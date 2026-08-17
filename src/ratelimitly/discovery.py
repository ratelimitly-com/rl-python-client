"""DNS SRV discovery for RateLimitly r-servers."""

import os
import random
import re
import socket
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    import dns.resolver as _dns_resolver
except ImportError:  # The native path keeps the low-level client usable without extras.
    _dns_resolver = None


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


def _parse_dns_server(value: str) -> Tuple[str, int]:
    value = value.strip()
    if not value:
        raise ValueError("RCLIENT_DNS_SERVER must not be empty")
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            raise ValueError("invalid bracketed RCLIENT_DNS_SERVER")
        host = value[1:closing]
        suffix = value[closing + 1 :]
        if not suffix:
            port = 53
        elif suffix.startswith(":"):
            port = int(suffix[1:], 10)
        else:
            raise ValueError("invalid bracketed RCLIENT_DNS_SERVER")
    elif value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
        port = int(raw_port, 10)
    else:
        host = value
        port = 53
    if not host or not 1 <= port <= 65535:
        raise ValueError("RCLIENT_DNS_SERVER must be host[:port]")
    return host, port


def _encode_dns_name(name: str) -> bytes:
    encoded = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError("invalid DNS label")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def _decode_dns_name(message: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    next_offset = offset
    jumped = False
    visited = set()
    while True:
        if offset >= len(message) or offset in visited:
            raise ValueError("invalid compressed DNS name")
        visited.add(offset)
        length = message[offset]
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            return ".".join(labels), next_offset
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS compression pointer")
            if not jumped:
                next_offset = offset + 2
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            jumped = True
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label length")
        offset += 1
        end = offset + length
        if end > len(message):
            raise ValueError("truncated DNS label")
        labels.append(message[offset:end].decode("ascii"))
        offset = end


def _system_dns_server() -> Tuple[str, int]:
    try:
        with open("/etc/resolv.conf", "r", encoding="ascii") as resolv_conf:
            for line in resolv_conf:
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "nameserver":
                    return fields[1], 53
    except OSError:
        pass
    return "127.0.0.1", 53


def _query_srv_native(srv_name: str, dns_host: str, dns_port: int) -> List[Tuple[str, int, int]]:
    transaction_id = random.randint(0, 0xFFFF)
    query = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    query += _encode_dns_name(srv_name)
    query += struct.pack("!HH", 33, 1)

    response = None
    for family, socktype, protocol, _canonical, address in socket.getaddrinfo(
        dns_host, dns_port, type=socket.SOCK_DGRAM
    ):
        current = socket.socket(family, socktype, protocol)
        try:
            current.settimeout(2.0)
            current.sendto(query, address)
            response, _source = current.recvfrom(65535)
            break
        except OSError:
            continue
        finally:
            current.close()
    if response is None or len(response) < 12:
        raise LookupError(f"DNS SRV query failed for {srv_name}")

    reply_id, flags, question_count, answer_count, _authority_count, _additional_count = (
        struct.unpack_from("!HHHHHH", response, 0)
    )
    if reply_id != transaction_id or not flags & 0x8000 or flags & 0x000F:
        raise LookupError(f"invalid DNS SRV response for {srv_name}")

    offset = 12
    for _ in range(question_count):
        _name, offset = _decode_dns_name(response, offset)
        offset += 4

    records = []
    for _ in range(answer_count):
        _name, offset = _decode_dns_name(response, offset)
        if offset + 10 > len(response):
            raise ValueError("truncated DNS resource record")
        record_type, record_class, ttl, data_length = struct.unpack_from(
            "!HHIH", response, offset
        )
        offset += 10
        data_end = offset + data_length
        if data_end > len(response):
            raise ValueError("truncated DNS resource data")
        if record_type == 33 and record_class == 1 and data_length >= 7:
            _priority, _weight, port = struct.unpack_from("!HHH", response, offset)
            target, _unused = _decode_dns_name(response, offset + 6)
            records.append((target, port, ttl))
        offset = data_end
    return records


def discover_server_endpoints(dns_srv_domain: str) -> List[ServerEndpoint]:
    """Resolve `_ratelimitly._udp.<tenant>` without inventing fallback servers."""
    if not isinstance(dns_srv_domain, str) or not dns_srv_domain:
        raise ValueError("dns_srv_domain must be a non-empty string")

    srv_name = f"_ratelimitly._udp.{dns_srv_domain.rstrip('.')}"
    override = os.environ.get("RCLIENT_DNS_SERVER")
    dns_host, dns_port = _parse_dns_server(override) if override else _system_dns_server()

    records = []
    if _dns_resolver is not None:
        if override:
            resolver = _dns_resolver.Resolver(configure=False)
            resolver.nameservers = [dns_host]
            resolver.port = dns_port
            answers = resolver.resolve(srv_name, "SRV")
        else:
            answers = _dns_resolver.resolve(srv_name, "SRV")
        answer_ttl = int(getattr(getattr(answers, "rrset", None), "ttl", 0))
        records = [
            (str(record.target).rstrip("."), int(record.port), answer_ttl)
            for record in answers
        ]
    else:
        records = _query_srv_native(srv_name, dns_host, dns_port)

    endpoints = []
    seen = set()
    for target, port, ttl in records:
        server_id = server_id_from_target(target)
        if server_id is None:
            continue
        ttl_ms = ttl * 1000
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
