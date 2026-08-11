"""DNS SRV discovery for RateLimitly r-servers."""

import re
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple


_SERVER_TARGET = re.compile(r"^s-([0-9]+)\.", re.IGNORECASE)


@dataclass(frozen=True)
class ServerEndpoint:
    family: int
    address: Tuple
    server_id: Optional[int]
    target: str
    ttl_ms: int = 0


def server_id_from_target(target: str) -> Optional[int]:
    match = _SERVER_TARGET.match(target.rstrip(".") + ".")
    if not match:
        return None
    value = int(match.group(1), 10)
    return value if value <= 0xFFFFFFFFFFFFFFFF else None


def discover_server_endpoints(dns_srv_domain: str) -> List[ServerEndpoint]:
    """Resolve `_ratelimitly._udp.<tenant>` without inventing fallback servers."""
    if not isinstance(dns_srv_domain, str) or not dns_srv_domain:
        raise ValueError("dns_srv_domain must be a non-empty string")

    import dns.resolver

    srv_name = f"_ratelimitly._udp.{dns_srv_domain.rstrip('.')}"
    answers = dns.resolver.resolve(srv_name, "SRV")
    endpoints = []
    seen = set()
    for record in answers:
        target = str(record.target).rstrip(".")
        port = int(record.port)
        server_id = server_id_from_target(target)
        if server_id is None:
            continue
        ttl_ms = int(getattr(getattr(answers, "rrset", None), "ttl", 0)) * 1000
        addresses = socket.getaddrinfo(
            target,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
        )
        for family, socktype, protocol, _canonical, address in addresses:
            if socktype != socket.SOCK_DGRAM:
                continue
            key = (family, protocol, address, server_id)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(ServerEndpoint(family, address, server_id, target, ttl_ms))

    if not endpoints:
        raise LookupError(f"no usable SRV endpoints for {srv_name}")
    return endpoints
