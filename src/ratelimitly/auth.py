"""Bech32 authentication key parser for RateLimitly credentials."""

from dataclasses import dataclass
from typing import Literal, Tuple

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_REV = {c: i for i, c in enumerate(BECH32_CHARSET)}


@dataclass(frozen=True)
class AuthKeyInfo:
    auth_type: Literal["aes", "cookie"]
    key_id: int
    secret: bytes
    dedup_ttl_ms_max: int = 300
    latency_buffer_size_max: int = 32

    @property
    def default_dns_srv(self) -> str:
        """Constructs default tenant SRV domain string: c-${key_id}.p0.ratelimitly.com"""
        return f"c-{self.key_id}.p0.ratelimitly.com"


def _bech32_decode(bech_str: str) -> Tuple[str, list[int]]:
    """Decodes a Bech32 string into HRP and 5-bit data values."""
    if not (1 <= len(bech_str) <= 128):
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

    return hrp, data


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool = True) -> bytes:
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

    key_str = key_str.strip()
    if key_str.startswith("rl-aes1"):
        auth_type = "aes"
    elif key_str.startswith("rl-cookie1"):
        auth_type = "cookie"
    else:
        raise ValueError("Invalid auth key prefix; expected 'rl-aes1' or 'rl-cookie1'")

    hrp, data_5bit = _bech32_decode(key_str)
    # Remove 6-character checksum at the end
    payload_5bit = data_5bit[:-6]
    raw_bytes = _convertbits(payload_5bit, 5, 8, pad=False)

    if len(raw_bytes) < 40:
        raise ValueError(f"Auth key payload too short: {len(raw_bytes)} bytes (expected >= 40)")

    # Key ID: 8-byte big-endian uint64
    key_id = int.from_bytes(raw_bytes[:8], byteorder="big")
    secret = raw_bytes[8:40]

    return AuthKeyInfo(
        auth_type=auth_type,
        key_id=key_id,
        secret=secret,
        dedup_ttl_ms_max=300,
        latency_buffer_size_max=32
    )
