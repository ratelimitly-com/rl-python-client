"""Blocking and asyncio adapters for the C-compatible RateLimitly protocol."""

import asyncio
import os
import select
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from .auth import AuthKeyInfo, parse_auth_key
from .discovery import ServerEndpoint, discover_server_endpoints
from .policy import RequestPolicy, default_request_policy
from .protocol import (
    R_PDU_LATENCY_REPORT,
    build_authenticated_packet,
    build_latency_report_body,
    build_pdu,
    build_rate_request_body,
    build_rate_request_pdu,
    parse_rate_response_packet,
)
from .steering import (
    bind_next_steering_socket,
    create_bound_udp_socket,
    next_steering_port,
)
from .types import (
    LatencyGuard,
    RateLimitResult,
    ResourceRequest,
    ServiceLatencyReport,
    RCLIENT_ERR_CONFIG,
    RCLIENT_ERR_DNS,
    RCLIENT_ERR_AUTH,
    RCLIENT_ERR_IO,
    RCLIENT_ERR_PROTOCOL,
    RCLIENT_ERR_TIMEOUT,
    RCLIENT_OK,
)


Resolver = Callable[[str], List[ServerEndpoint]]
Clock = Callable[[], int]
SocketFactory = Callable[[int, int], socket.socket]


def _wall_time_ms() -> int:
    # Match r_runtime_wall_time_ms(): the wire timestamp and policy deadlines
    # use Unix wall time in the reference C runtime.
    return time.time_ns() // 1_000_000


def _request_id() -> bytes:
    value = bytearray(os.urandom(16))
    value[6] = (value[6] & 0x0F) | 0x40
    value[8] = (value[8] & 0x3F) | 0x80
    return bytes(value)


class RateLimitlyClient:
    """Serialized blocking client implementing rl-c-client's request policy."""

    def __init__(
        self,
        auth_key: str,
        dns_srv: Optional[str] = None,
        policy: Optional[RequestPolicy] = None,
        *,
        resolver: Resolver = discover_server_endpoints,
        clock_ms: Clock = _wall_time_ms,
        socket_factory: SocketFactory = socket.socket,
        dns_refresh_interval_ms: int = 300_000,
    ) -> None:
        self.auth_info: AuthKeyInfo = parse_auth_key(auth_key)
        self.dns_srv = dns_srv or self.auth_info.default_dns_srv
        self.policy = policy or default_request_policy()
        self.policy.calculate_horizon_ms(self.auth_info.dedup_ttl_ms_max)
        self._resolver = resolver
        self._clock_ms = clock_ms
        self._socket_factory = socket_factory
        if dns_refresh_interval_ms <= 0:
            raise ValueError("dns_refresh_interval_ms must be positive")
        self._dns_refresh_interval_ms = dns_refresh_interval_ms
        self._last_dns_refresh_ms = 0
        self._dns_refresh_ttl_ms = 0
        self._endpoints: List[ServerEndpoint] = []
        self._sockets: Dict[int, socket.socket] = {}
        self._next_steering_ports: Dict[int, int] = {}
        self._closed = False

    def _ensure_endpoints(self) -> Tuple[int, List[ServerEndpoint]]:
        now_ms = self._clock_ms()
        refresh_interval_ms = self._dns_refresh_interval_ms
        if 0 < self._dns_refresh_ttl_ms < refresh_interval_ms:
            refresh_interval_ms = self._dns_refresh_ttl_ms
        if self._endpoints and now_ms - self._last_dns_refresh_ms < refresh_interval_ms:
            return RCLIENT_OK, list(self._endpoints)
        try:
            endpoints = self._resolver(self.dns_srv)
        except Exception:
            if self._endpoints:
                return RCLIENT_OK, list(self._endpoints)
            return RCLIENT_ERR_DNS, []
        if not endpoints:
            if self._endpoints:
                return RCLIENT_OK, list(self._endpoints)
            return RCLIENT_ERR_DNS, []
        self._endpoints = list(endpoints)
        self._last_dns_refresh_ms = now_ms
        positive_ttls = [endpoint.ttl_ms for endpoint in endpoints if endpoint.ttl_ms > 0]
        self._dns_refresh_ttl_ms = min(positive_ttls) if positive_ttls else 0
        return RCLIENT_OK, list(self._endpoints)

    def _socket_for_family(self, family: int) -> socket.socket:
        current = self._sockets.get(family)
        if current is not None:
            return current
        current = create_bound_udp_socket(family, 0, self._socket_factory)
        self._sockets[family] = current
        return current

    def _close_sockets(self) -> None:
        for current in self._sockets.values():
            try:
                current.close()
            except OSError:
                pass
        self._sockets.clear()
        self._next_steering_ports.clear()

    def _apply_steering(self) -> bool:
        replacements: Dict[int, socket.socket] = {}
        following_ports: Dict[int, int] = {}
        try:
            for family, previous in self._sockets.items():
                current_port = previous.getsockname()[1]
                first_port = self._next_steering_ports.get(
                    family, next_steering_port(current_port)
                )
                replacement, _selected, following = bind_next_steering_socket(
                    family,
                    first_port,
                    self._socket_factory,
                )
                replacements[family] = replacement
                following_ports[family] = following
        except (OSError, ValueError):
            for replacement in replacements.values():
                replacement.close()
            return False

        previous_sockets = self._sockets
        self._sockets = replacements
        self._next_steering_ports.update(following_ports)
        for previous in previous_sockets.values():
            try:
                previous.close()
            except OSError:
                pass
        return True

    @staticmethod
    def _target_responded(
        target: ServerEndpoint,
        seen_server_ids: Set[int],
        seen_addresses: Set[Tuple[int, Tuple]],
    ) -> bool:
        if target.server_id is not None:
            return target.server_id in seen_server_ids
        return (target.family, target.address) in seen_addresses

    def _send_request(
        self,
        endpoints: Sequence[ServerEndpoint],
        request_id: bytes,
        pdu: bytes,
        seen_server_ids: Set[int],
        seen_addresses: Set[Tuple[int, Tuple]],
        *,
        missing_only: bool,
        best_effort: bool,
    ) -> int:
        try:
            packet = build_authenticated_packet(
                pdu,
                self.auth_info,
                request_id=request_id,
                timestamp_ms=self._clock_ms(),
            )
        except (TypeError, ValueError):
            return RCLIENT_ERR_PROTOCOL
        except Exception:
            return RCLIENT_ERR_AUTH
        for target in endpoints:
            if missing_only and self._target_responded(target, seen_server_ids, seen_addresses):
                continue
            try:
                self._socket_for_family(target.family).sendto(packet, target.address)
            except OSError:
                if not best_effort:
                    return RCLIENT_ERR_IO
        return RCLIENT_OK

    def _receive_until(
        self,
        deadline_ms: int,
        request_id: bytes,
        allowed_server_ids: Set[int],
        oldest_server_id: Optional[int],
        preference_deadline_ms: int,
        best: Optional[RateLimitResult],
        seen_server_ids: Set[int],
        seen_addresses: Set[Tuple[int, Tuple]],
    ) -> Tuple[Optional[RateLimitResult], bool, bool, int]:
        """Return (best, selected, rebind_requested, status)."""
        rebind_requested = False
        while True:
            now_ms = self._clock_ms()
            if best is not None and now_ms >= preference_deadline_ms:
                return best, True, rebind_requested, RCLIENT_OK
            if now_ms >= deadline_ms:
                return best, False, rebind_requested, RCLIENT_OK

            sockets = list(self._sockets.values())
            if not sockets:
                return best, False, rebind_requested, RCLIENT_ERR_IO
            wait_deadline_ms = preference_deadline_ms if best is not None else deadline_ms
            timeout = max(0.0, (wait_deadline_ms - now_ms) / 1000.0)
            try:
                readable, _, _ = select.select(sockets, [], [], timeout)
            except (OSError, ValueError):
                return best, False, rebind_requested, RCLIENT_ERR_IO
            if not readable:
                continue

            consumed = 0
            for current in readable:
                while consumed < 32:
                    try:
                        packet, source = current.recvfrom(2048)
                    except BlockingIOError:
                        break
                    except OSError:
                        return best, False, rebind_requested, RCLIENT_ERR_IO
                    consumed += 1
                    try:
                        response_request_id, result = parse_rate_response_packet(
                            packet, self.auth_info
                        )
                    except (TypeError, ValueError):
                        continue
                    if response_request_id != request_id:
                        continue
                    if allowed_server_ids and result.server_id not in allowed_server_ids:
                        continue

                    family = current.family
                    seen_addresses.add((family, source))
                    seen_server_ids.add(result.server_id)
                    if not result.steering_feedback:
                        rebind_requested = True
                    if best is None or result.server_id < best.server_id:
                        best = result

                    now_ms = self._clock_ms()
                    if oldest_server_id is None or best.server_id == oldest_server_id:
                        return best, True, rebind_requested, RCLIENT_OK
                    if now_ms >= preference_deadline_ms:
                        return best, True, rebind_requested, RCLIENT_OK
                if consumed >= 32:
                    break

    def check_rate_limit(
        self,
        resources: Optional[Sequence[ResourceRequest]] = None,
        guards: Optional[Sequence[LatencyGuard]] = None,
        metrics_label: Optional[str] = None,
    ) -> Tuple[int, Optional[RateLimitResult]]:
        """Evaluate one logical request using the unified C-client policy."""
        if self._closed:
            return RCLIENT_ERR_CONFIG, None
        exact_resources = tuple(resources or ())
        exact_guards = tuple(guards or ())

        if not exact_resources and not exact_guards:
            return RCLIENT_OK, RateLimitResult(True, 0, False, (), ())
        try:
            oversized_window = any(
                resource.window_size_ms > self.auth_info.rate_window_size_ms_max
                for resource in exact_resources
            )
        except (AttributeError, TypeError):
            return RCLIENT_ERR_PROTOCOL, None
        if oversized_window:
            return RCLIENT_ERR_PROTOCOL, None

        try:
            horizon_ms = self.policy.calculate_horizon_ms(
                self.auth_info.dedup_ttl_ms_max
            )
            body = build_rate_request_body(
                exact_resources, exact_guards, metrics_label
            )
            pdu = build_rate_request_pdu(horizon_ms, body)
        except (TypeError, ValueError):
            return RCLIENT_ERR_PROTOCOL, None

        status, endpoints = self._ensure_endpoints()
        if status != RCLIENT_OK:
            return status, None

        try:
            request_id = _request_id()
        except Exception:
            return RCLIENT_ERR_AUTH, None
        allowed_server_ids = {
            target.server_id for target in endpoints if target.server_id is not None
        }
        if len(allowed_server_ids) != len({target.server_id for target in endpoints}):
            # At least one target lacked an ID: match C and accept any responder.
            allowed_server_ids.clear()
        oldest_server_id = min(allowed_server_ids) if allowed_server_ids else None
        seen_server_ids: Set[int] = set()
        seen_addresses: Set[Tuple[int, Tuple]] = set()
        best: Optional[RateLimitResult] = None
        rebind_requested = False
        start_ms = self._clock_ms()
        round_start_ms = start_ms

        for round_index in range(self.policy.replay_count + 1):
            duration_ms = self.policy.unit_ms * self.policy.replay_gap.get_gap(round_index)
            round_deadline_ms = round_start_ms + duration_ms
            preference_deadline_ms = round_deadline_ms if round_index == 0 else round_start_ms
            status = self._send_request(
                endpoints,
                request_id,
                pdu,
                seen_server_ids,
                seen_addresses,
                missing_only=round_index > 0,
                best_effort=False,
            )
            if status != RCLIENT_OK:
                if rebind_requested:
                    self._apply_steering()
                return status, None

            best, selected, phase_rebind, phase_status = self._receive_until(
                round_deadline_ms,
                request_id,
                allowed_server_ids,
                oldest_server_id,
                preference_deadline_ms,
                best,
                seen_server_ids,
                seen_addresses,
            )
            rebind_requested = rebind_requested or phase_rebind
            if phase_status != RCLIENT_OK:
                if rebind_requested:
                    self._apply_steering()
                return phase_status, None
            if selected and best is not None:
                break
            if best is not None:
                # The first round's preference deadline expired.
                break
            round_start_ms = round_deadline_ms
        if best is None and self.policy.final_receive_units > 0:
            final_deadline_ms = (
                round_deadline_ms
                + self.policy.unit_ms * self.policy.final_receive_units
            )
            best, selected, phase_rebind, phase_status = self._receive_until(
                final_deadline_ms,
                request_id,
                allowed_server_ids,
                oldest_server_id,
                round_deadline_ms,
                best,
                seen_server_ids,
                seen_addresses,
            )
            rebind_requested = rebind_requested or phase_rebind
            if phase_status != RCLIENT_OK:
                if rebind_requested:
                    self._apply_steering()
                return phase_status, None

        if best is None:
            if rebind_requested:
                self._apply_steering()
            return RCLIENT_ERR_TIMEOUT, None

        if self.policy.completion_delivery and self._clock_ms() < start_ms + horizon_ms:
            self._send_request(
                endpoints,
                request_id,
                pdu,
                seen_server_ids,
                seen_addresses,
                missing_only=True,
                best_effort=True,
            )
        if rebind_requested:
            self._apply_steering()
        return RCLIENT_OK, best

    def report_latency(self, reports: Sequence[ServiceLatencyReport]) -> int:
        """Send one fire-and-forget report packet to every discovered server."""
        if self._closed or not reports:
            return RCLIENT_ERR_CONFIG
        try:
            body = build_latency_report_body(reports)
            pdu = build_pdu(R_PDU_LATENCY_REPORT, body)
            request_id = _request_id()
            packet = build_authenticated_packet(
                pdu,
                self.auth_info,
                request_id=request_id,
                timestamp_ms=self._clock_ms(),
            )
        except (TypeError, ValueError):
            return RCLIENT_ERR_PROTOCOL
        except Exception:
            return RCLIENT_ERR_AUTH

        status, endpoints = self._ensure_endpoints()
        if status != RCLIENT_OK:
            return status
        for target in endpoints:
            try:
                self._socket_for_family(target.family).sendto(packet, target.address)
            except OSError:
                return RCLIENT_ERR_IO
        return RCLIENT_OK

    def close(self) -> None:
        self._close_sockets()
        self._endpoints.clear()
        self._closed = True

    def __enter__(self) -> "RateLimitlyClient":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


class AsyncRateLimitlyClient:
    """Asyncio adapter preserving the same serialized blocking state machine."""

    def __init__(self, *args, **kwargs) -> None:
        self._client = RateLimitlyClient(*args, **kwargs)
        self.auth_info = self._client.auth_info
        self.dns_srv = self._client.dns_srv
        self.policy = self._client.policy
        self._lock: Optional[asyncio.Lock] = None

    async def _run_blocking(self, function, *args):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def set_result(result) -> None:
            if not future.done():
                future.set_result(result)

        def set_exception(error: BaseException) -> None:
            if not future.done():
                future.set_exception(error)

        def run() -> None:
            try:
                result = function(*args)
            except BaseException as error:
                loop.call_soon_threadsafe(set_exception, error)
            else:
                loop.call_soon_threadsafe(set_result, result)

        threading.Thread(target=run, daemon=True).start()
        return await future

    def _serialization_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def check_rate_limit(
        self,
        resources: Optional[Sequence[ResourceRequest]] = None,
        guards: Optional[Sequence[LatencyGuard]] = None,
        metrics_label: Optional[str] = None,
    ) -> Tuple[int, Optional[RateLimitResult]]:
        async with self._serialization_lock():
            return await self._run_blocking(
                self._client.check_rate_limit,
                resources,
                guards,
                metrics_label,
            )

    async def report_latency(self, reports: Sequence[ServiceLatencyReport]) -> int:
        async with self._serialization_lock():
            return await self._run_blocking(self._client.report_latency, reports)

    def close(self) -> None:
        self._client.close()

    async def __aenter__(self) -> "AsyncRateLimitlyClient":
        return self

    async def __aexit__(self, _type, _value, _traceback) -> None:
        self.close()
