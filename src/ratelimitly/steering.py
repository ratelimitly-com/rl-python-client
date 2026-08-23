"""Portable source-port steering primitives."""

import errno
import os
import socket


STEERING_PORT_MIN = 49_152
STEERING_PORT_COUNT = 65_535 - STEERING_PORT_MIN + 1


def next_steering_port(port: int) -> int:
    """Advance once through the IANA dynamic/private port range."""
    if port < STEERING_PORT_MIN or port >= 65_535:
        return STEERING_PORT_MIN
    return port + 1


def _wildcard_address(family: int, port: int):
    if family == socket.AF_INET:
        return ("0.0.0.0", port)
    if family == socket.AF_INET6:
        return ("::", port)
    raise ValueError("source-port steering supports only AF_INET and AF_INET6")


def _is_occupied(error: OSError) -> bool:
    return error.errno in (errno.EADDRINUSE, errno.EACCES) or getattr(
        error, "winerror", None
    ) in (10013, 10048)


def create_bound_udp_socket(family: int, port: int, socket_factory=socket.socket):
    """Create a nonblocking wildcard UDP socket, exclusive on Windows."""
    current = socket_factory(family, socket.SOCK_DGRAM)
    try:
        if os.name == "nt":
            current.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
            current.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        current.bind(_wildcard_address(family, port))
        current.setblocking(False)
        return current
    except BaseException:
        current.close()
        raise


def bind_next_steering_socket(
    family: int,
    first_port: int,
    socket_factory=socket.socket,
):
    """Bind the first available monotonic candidate without a port-zero fallback."""
    candidate = first_port if first_port >= STEERING_PORT_MIN else STEERING_PORT_MIN
    for _ in range(STEERING_PORT_COUNT):
        try:
            current = create_bound_udp_socket(family, candidate, socket_factory)
        except OSError as error:
            if not _is_occupied(error):
                raise
            candidate = next_steering_port(candidate)
            continue
        return current, candidate, next_steering_port(candidate)
    raise OSError(errno.EADDRINUSE, "no UDP source port is available for steering")
