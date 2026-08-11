"""Bech32 authentication key parser for RateLimitly credentials."""

from dataclasses import dataclass
from typing import List, Literal, Tuple

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_REV = {c: i for i, c in enumerate(BECH32_CHARSET)}


@dataclass(frozen=True)
class AuthKeyInfo:
    auth_type: Literal["aes", "cookie"]
    key_id: int
    secret: bytes
    rate_buckets_max: int
    latency_services_max: int
    metrics_labels_max: int
    latency_buffer_size_max: int
    dedup_ttl_ms_max: int

    @property
    def default_dns_srv(self) -> str:
        """Constructs default tenant SRV domain string: c-${key_id}.p0.ratelimitly.com"""
        return f"c-{self.key_id}.p0.ratelimitly.com"


def _bech32_polymod(values: List[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _bech32_decode(bech_str: str) -> Tuple[str, List[int]]:
    """Decodes a Bech32 string into HRP and 5-bit data values."""
    if not bech_str or any(ord(char) < 33 or ord(char) > 126 for char in bech_str):
        raise ValueError("Invalid Bech32 length")
    if bech_str.lower() != bech_str and bech_str.upper() != bech_str:
        raise ValueError("Mixed case Bech32 string")

    bech_str = bech_str.lower()
    pos = bech_str.rfind("1")
    if pos < 1 or pos + 7 > len(bech_str):
        raise ValueError("Invalid separator position in Bech32 string")

    hrp = bech_str[:pos]
    data = []
    for c in bech_str[pos + 1:]:
        if c not in BECH32_REV:
            raise ValueError(f"Invalid character in Bech32 string: '{c}'")
        data.append(BECH32_REV[c])

    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise ValueError("Invalid Bech32 checksum")

    return hrp, data


def _convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> bytes:
    """Converts a bit array from one representation to another (5-bit to 8-bit)."""
    acc = 0
    bits = 0
    ret = bytearray()
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("Invalid bit value")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding in bit conversion")
    return bytes(ret)


def parse_auth_key(key_str: str) -> AuthKeyInfo:
    """
    Parses a RateLimitly Bech32 authentication key (rl-aes1... or rl-cookie1...).

    Extracts:
    - Auth Type ('aes' or 'cookie')
    - Key ID (uint64)
    - Secret payload bytes (32 bytes)
    """
    if not isinstance(key_str, str):
        raise TypeError("Authentication key must be a string")

    hrp, data_5bit = _bech32_decode(key_str)
    if hrp == "rl-aes":
        auth_type = "aes"
    elif hrp == "rl-cookie":
        auth_type = "cookie"
    else:
        raise ValueError("Invalid auth key HRP; expected 'rl-aes' or 'rl-cookie'")

    # Remove 6-character checksum at the end
    payload_5bit = data_5bit[:-6]
    raw_bytes = _convertbits(payload_5bit, 5, 8, pad=False)

    if len(raw_bytes) != 60:
        raise ValueError(f"Invalid auth key payload length: {len(raw_bytes)} bytes (expected 60)")

    key_id = int.from_bytes(raw_bytes[:8], byteorder="little")
    secret = raw_bytes[8:40]
    quotas = tuple(
        int.from_bytes(raw_bytes[offset:offset + 4], byteorder="little")
        for offset in range(40, 60, 4)
    )

    return AuthKeyInfo(
        auth_type=auth_type,
        key_id=key_id,
        secret=secret,
        rate_buckets_max=quotas[0],
        latency_services_max=quotas[1],
        metrics_labels_max=quotas[2],
        latency_buffer_size_max=quotas[3],
        dedup_ttl_ms_max=quotas[4],
    )
