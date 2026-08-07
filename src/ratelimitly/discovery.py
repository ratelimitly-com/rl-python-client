"""DNS SRV and socket address discovery for RateLimitly servers."""

import socket
from typing import List, Tuple

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def discover_server_endpoints(dns_srv_domain: str) -> List[Tuple[str, int]]:
    """
    Discovers RateLimitly server endpoints via DNS SRV record: `_ratelimitly._udp.<dns_srv_domain>`.
    
    Returns a list of (host, port) tuples.
    """
    endpoints = []
    srv_name = f"_ratelimitly._udp.{dns_srv_domain}"

    if HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(srv_name, "SRV")
            for rdata in answers:
                target = str(rdata.target).rstrip(".")
                port = rdata.port
                endpoints.append((target, port))
        except Exception:
            pass

    if not endpoints:
        # Fallback to standard host resolution on default port 9000
        endpoints.append((dns_srv_domain, 9000))

    return endpoints
