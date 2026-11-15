"""Lifetime physical UDP counters; no logical-request estimates."""
from dataclasses import dataclass
import ipaddress
import socket
import threading

MAX_COUNTER = (1 << 64) - 1


@dataclass(frozen=True)
class TrafficDirection:
    datagrams: int = 0
    payload_bytes: int = 0
    ip_bytes: int = 0


@dataclass(frozen=True)
class TrafficStats:
    sent: TrafficDirection
    received: TrafficDirection
    send_failures: int = 0
    incomplete: bool = False


class _TrafficCounters:
    def __init__(self):
        self._lock = threading.Lock()
        self._values = {"sent": [0, 0, 0], "received": [0, 0, 0]}
        self._failures = 0
        self._incomplete = False

    def _add(self, old, amount):
        total = old + amount
        if total > MAX_COUNTER:
            self._incomplete = True
            return MAX_COUNTER
        return total

    def record(self, direction, payload_bytes, family, address):
        overhead = None
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
            if family == socket.AF_INET and parsed.version == 4:
                overhead = 28
            elif family == socket.AF_INET6 and parsed.version == 6:
                overhead = 28 if parsed.ipv4_mapped is not None else 48
        except ValueError:
            pass
        with self._lock:
            values = self._values[direction]
            values[0] = self._add(values[0], 1)
            values[1] = self._add(values[1], payload_bytes)
            if overhead is None:
                self._incomplete = True
            else:
                values[2] = self._add(values[2], payload_bytes + overhead)

    def failed_send(self):
        with self._lock:
            self._failures = self._add(self._failures, 1)

    def snapshot(self):
        with self._lock:
            return TrafficStats(TrafficDirection(*self._values["sent"]),
                                TrafficDirection(*self._values["received"]),
                                self._failures, self._incomplete)
