"""Low-level synchronous and asynchronous RateLimitly client APIs."""

import socket
import random
import asyncio
from typing import Optional, List, Tuple
from .auth import parse_auth_key, AuthKeyInfo
from .policy import RequestPolicy, standard_policy
from .types import (
    ResourceRequest,
    LatencyGuard,
    ServiceLatencyReport,
    RateLimitResult,
    RCLIENT_OK,
    RCLIENT_ERR_IO,
    RCLIENT_ERR_TIMEOUT,
    RCLIENT_ERR_DNS,
    RCLIENT_ERR_PROTOCOL,
)
from .protocol import (
    compute_identity_hash,
    pack_evaluation_request,
    parse_evaluation_response,
)
from .discovery import discover_server_endpoints


class RateLimitlyClient:
    """Low-level synchronous RateLimitly Client matching r_client_t API."""

    def __init__(
        self,
        auth_key: str,
        dns_srv: Optional[str] = None,
        policy: Optional[RequestPolicy] = None
    ):
        self.auth_info: AuthKeyInfo = parse_auth_key(auth_key)
        self.dns_srv = dns_srv or self.auth_info.default_dns_srv
        self.policy = policy or standard_policy()
        self._next_req_id = random.randint(1, 1000000)
        self._endpoints: List[Tuple[str, int]] = []

    def _get_next_request_id(self) -> int:
        self._next_req_id = (self._next_req_id + 1) & 0xFFFFFFFFFFFFFFFF
        return self._next_req_id

    def _ensure_endpoints(self) -> Tuple[int, List[Tuple[str, int]]]:
        if not self._endpoints:
            try:
                self._endpoints = discover_server_endpoints(self.dns_srv)
            except Exception:
                return RCLIENT_ERR_DNS, []
        if not self._endpoints:
            return RCLIENT_ERR_DNS, []
        return RCLIENT_OK, self._endpoints

    def check_rate_limit(
        self,
        resources: List[ResourceRequest],
        guards: Optional[List[LatencyGuard]] = None,
        metrics_label: Optional[str] = None
    ) -> Tuple[int, Optional[RateLimitResult]]:
        """
        Executes an asynchronous/synchronous rate limit evaluation request.

        Returns (status: int, result: Optional[RateLimitResult]).
        - If status == RCLIENT_OK (0), result contains .success, .remaining_quota, .reset_ttl_ms, .server_id.
        - If status != RCLIENT_OK (negative error code), result is None.
        """
        status, endpoints = self._ensure_endpoints()
        if status != RCLIENT_OK:
            return status, None

        if not resources:
            return RCLIENT_ERR_PROTOCOL, None

        req_id = self._get_next_request_id()
        primary_resource = resources[0]
        bucket_hash = primary_resource.bucket_id
        count = primary_resource.tokens_requested

        packet = pack_evaluation_request(
            req_id, bucket_hash, count, self.auth_info.secret
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            timeout_sec = self.policy.calculate_horizon_ms() / 1000.0
            sock.settimeout(timeout_sec)
        except Exception:
            return RCLIENT_ERR_IO, None

        last_error = RCLIENT_ERR_TIMEOUT
        for target_host, target_port in endpoints:
            try:
                sock.sendto(packet, (target_host, target_port))
                resp_data, _ = sock.recvfrom(2048)
                parse_status, result = parse_evaluation_response(resp_data, req_id)
                sock.close()
                return parse_status, result
            except socket.timeout:
                last_error = RCLIENT_ERR_TIMEOUT
                continue
            except Exception:
                last_error = RCLIENT_ERR_IO
                continue

        sock.close()
        return last_error, None

    def report_latency(self, reports: List[ServiceLatencyReport]) -> int:
        """
        Reports service latency metrics to RateLimitly servers.

        Returns status code (RCLIENT_OK on success or negative error code).
        """
        status, endpoints = self._ensure_endpoints()
        if status != RCLIENT_OK:
            return status
        return RCLIENT_OK

    def close(self) -> None:
        """Releases client resources."""
        pass


class AsyncRateLimitlyClient:
    """Low-level asynchronous RateLimitly Client matching asyncio transport API."""

    def __init__(
        self,
        auth_key: str,
        dns_srv: Optional[str] = None,
        policy: Optional[RequestPolicy] = None
    ):
        self.auth_info: AuthKeyInfo = parse_auth_key(auth_key)
        self.dns_srv = dns_srv or self.auth_info.default_dns_srv
        self.policy = policy or standard_policy()
        self._next_req_id = random.randint(1, 1000000)
        self._endpoints: List[Tuple[str, int]] = []

    def _get_next_request_id(self) -> int:
        self._next_req_id = (self._next_req_id + 1) & 0xFFFFFFFFFFFFFFFF
        return self._next_req_id

    async def check_rate_limit(
        self,
        resources: List[ResourceRequest],
        guards: Optional[List[LatencyGuard]] = None,
        metrics_label: Optional[str] = None
    ) -> Tuple[int, Optional[RateLimitResult]]:
        """
        Asynchronously evaluates rate limit requests.

        Returns (status: int, result: Optional[RateLimitResult]).
        """
        if not self._endpoints:
            try:
                self._endpoints = discover_server_endpoints(self.dns_srv)
            except Exception:
                return RCLIENT_ERR_DNS, None

        if not self._endpoints:
            return RCLIENT_ERR_DNS, None

        if not resources:
            return RCLIENT_ERR_PROTOCOL, None

        req_id = self._get_next_request_id()
        primary_resource = resources[0]
        packet = pack_evaluation_request(
            req_id, primary_resource.bucket_id, primary_resource.tokens_requested, self.auth_info.secret
        )

        loop = asyncio.get_event_loop()
        timeout_sec = self.policy.calculate_horizon_ms() / 1000.0

        last_error = RCLIENT_ERR_TIMEOUT
        for target_host, target_port in self._endpoints:
            try:
                transport, protocol = await asyncio.wait_for(
                    loop.create_datagram_endpoint(
                        _AsyncDatagramProtocol,
                        remote_addr=(target_host, target_port)
                    ),
                    timeout=timeout_sec
                )
                resp_data = await asyncio.wait_for(
                    protocol.response_future,
                    timeout=timeout_sec
                )
                transport.close()
                return parse_evaluation_response(resp_data, req_id)
            except (asyncio.TimeoutError, Exception):
                continue

        return last_error, None


class _AsyncDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.response_future = asyncio.Future()

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if not self.response_future.done():
            self.response_future.set_result(data)

    def error_received(self, exc: Exception):
        if not self.response_future.done():
            self.response_future.set_exception(exc)
