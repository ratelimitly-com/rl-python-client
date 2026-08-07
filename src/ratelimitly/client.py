"""Synchronous and Asynchronous RateLimitly clients."""

import socket
import random
import time
import asyncio
from typing import Optional, List, Tuple
from .auth import parse_auth_key, AuthKeyInfo
from .policy import RequestPolicy, standard_policy
from .protocol import (
    Verdict,
    EvaluationResult,
    compute_identity_hash,
    pack_evaluation_request,
    parse_evaluation_response,
)
from .discovery import discover_server_endpoints


class RateLimitlyClient:
    """Synchronous high-performance RateLimitly Client."""

    def __init__(
        self,
        auth_key: str,
        dns_srv: Optional[str] = None,
        policy: Optional[RequestPolicy] = None,
        fail_open: bool = True
    ):
        self.auth_info: AuthKeyInfo = parse_auth_key(auth_key)
        self.dns_srv = dns_srv or self.auth_info.default_dns_srv
        self.policy = policy or standard_policy()
        self.fail_open = fail_open
        self._next_req_id = random.randint(1, 1000000)
        self._endpoints: List[Tuple[str, int]] = []

    def _get_next_request_id(self) -> int:
        self._next_req_id = (self._next_req_id + 1) & 0xFFFFFFFFFFFFFFFF
        return self._next_req_id

    def _ensure_endpoints(self) -> List[Tuple[str, int]]:
        if not self._endpoints:
            self._endpoints = discover_server_endpoints(self.dns_srv)
        return self._endpoints

    def eval(self, bucket_identity: str, count: int = 1) -> Verdict:
        """
        Evaluates a rate limit bucket identity (e.g., "bucket=v1|scope=api|ip=1.2.3.4").

        Returns Verdict.ALLOW or Verdict.DENY.
        """
        try:
            endpoints = self._ensure_endpoints()
            req_id = self._get_next_request_id()
            bucket_hash = compute_identity_hash(bucket_identity)
            packet = pack_evaluation_request(
                req_id, bucket_hash, count, self.auth_info.secret
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            timeout_sec = self.policy.calculate_horizon_ms() / 1000.0
            sock.settimeout(timeout_sec)

            for target_host, target_port in endpoints:
                try:
                    sock.sendto(packet, (target_host, target_port))
                    resp_data, _ = sock.recvfrom(2048)
                    result = parse_evaluation_response(resp_data, req_id)
                    sock.close()
                    return result.verdict
                except socket.timeout:
                    continue
                except Exception:
                    continue

            sock.close()
            # If all servers time out or fail
            return Verdict.ALLOW if self.fail_open else Verdict.FAIL
        except Exception:
            return Verdict.ALLOW if self.fail_open else Verdict.FAIL

    def close(self):
        """Releases underlying resources."""
        pass


class AsyncRateLimitlyClient:
    """Asynchronous (asyncio) RateLimitly Client."""

    def __init__(
        self,
        auth_key: str,
        dns_srv: Optional[str] = None,
        policy: Optional[RequestPolicy] = None,
        fail_open: bool = True
    ):
        self.auth_info: AuthKeyInfo = parse_auth_key(auth_key)
        self.dns_srv = dns_srv or self.auth_info.default_dns_srv
        self.policy = policy or standard_policy()
        self.fail_open = fail_open
        self._next_req_id = random.randint(1, 1000000)
        self._endpoints: List[Tuple[str, int]] = []

    def _get_next_request_id(self) -> int:
        self._next_req_id = (self._next_req_id + 1) & 0xFFFFFFFFFFFFFFFF
        return self._next_req_id

    async def eval(self, bucket_identity: str, count: int = 1) -> Verdict:
        """Asynchronously evaluates a rate limit bucket identity."""
        try:
            if not self._endpoints:
                self._endpoints = discover_server_endpoints(self.dns_srv)

            req_id = self._get_next_request_id()
            bucket_hash = compute_identity_hash(bucket_identity)
            packet = pack_evaluation_request(
                req_id, bucket_hash, count, self.auth_info.secret
            )

            loop = asyncio.get_event_loop()
            timeout_sec = self.policy.calculate_horizon_ms() / 1000.0

            for target_host, target_port in self._endpoints:
                try:
                    # UDP datagram send/recv via asyncio
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
                    result = parse_evaluation_response(resp_data, req_id)
                    return result.verdict
                except (asyncio.TimeoutError, Exception):
                    continue

            return Verdict.ALLOW if self.fail_open else Verdict.FAIL
        except Exception:
            return Verdict.ALLOW if self.fail_open else Verdict.FAIL


class _AsyncDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.response_future = asyncio.Future()

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if not self.response_future.done():
            self.response_future.set_result(data)

    def error_received(self, exc: Exception):
        if not self.response_future.done():
            self.response_future.set_exception(exc)
