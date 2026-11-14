"""Bech32 authentication key parser for RateLimitly credentials."""

from dataclasses import dataclass
from typing import List, Literal, Optional, Tuple

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_REV = {c: i for i, c in enumerate(BECH32_CHARSET)}
TENANT_KEY_FORMAT_VERSION = 2

NAMED_RATE_WINDOW_MS: Tuple[int, ...] = (
    1_000,
    5_000,
    10_000,
    15_000,
    30_000,
    60_000,
    120_000,
    180_000,
    300_000,
    600_000,
    900_000,
    1_800_000,
    2_700_000,
    3_600_000,
    7_200_000,
    10_800_000,
    18_000_000,
    21_600_000,
    28_800_000,
    43_200_000,
    86_400_000,
    172_800_000,
    432_000_000,
    604_800_000,
    1_209_600_000,
    2_419_200_000,
    2_592_000_000,
    7_776_000_000,
    15_724_800_000,
    31_536_000_000,
)


@dataclass(frozen=True)
class AuthKeyInfo:
    auth_type: Literal["aes", "cookie"]
    format_version: int
    key_id: int
    secret: bytes
    rate_buckets_max: int
    latency_services_max: int
    metrics_labels_max: int
    latency_buffer_size_max: int
    dedup_ttl_ms_max: int
    rate_window_size_ms_max: Optional[int]

    @property
    def rate_window_unlimited(self) -> bool:
        """Whether this credential allows any protocol-valid rate window."""
        return self.rate_window_size_ms_max is None

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


def _decode_quota_word(word: int) -> Tuple[int, int, int, int, int, Optional[int]]:
    rate_exp = word & 0x1F
    latency_exp = (word >> 5) & 0x1F
    labels_exp = (word >> 10) & 0x1F
    buffer_exp = (word >> 15) & 0x0F
    dedup_units = (word >> 19) & 0xFF
    window_code = (word >> 27) & 0x1F

    if rate_exp > 24:
        raise ValueError("Invalid packed rate_buckets_max quota")
    if latency_exp > 24:
        raise ValueError("Invalid packed latency_services_max quota")
    if not 1 <= dedup_units <= 200:
        raise ValueError("Invalid packed dedup_ttl_ms_max quota")
    if window_code == 0:
        raise ValueError("Invalid packed rate_window_size_ms_max quota")

    return (
        1 << rate_exp,
        1 << latency_exp,
        1 << labels_exp,
        1 << buffer_exp,
        dedup_units * 10,
        None if window_code == 31 else NAMED_RATE_WINDOW_MS[window_code - 1],
    )


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

    if len(raw_bytes) != 45:
        raise ValueError(f"Invalid auth key payload length: {len(raw_bytes)} bytes (expected 45)")

    format_version = raw_bytes[0]
    if format_version != TENANT_KEY_FORMAT_VERSION:
        raise ValueError(f"Unsupported auth key format version: {format_version}")

    key_id = int.from_bytes(raw_bytes[1:9], byteorder="little")
    secret = raw_bytes[9:41]
    quotas = _decode_quota_word(int.from_bytes(raw_bytes[41:45], byteorder="little"))

    return AuthKeyInfo(
        auth_type=auth_type,
        format_version=format_version,
        key_id=key_id,
        secret=secret,
        rate_buckets_max=quotas[0],
        latency_services_max=quotas[1],
        metrics_labels_max=quotas[2],
        latency_buffer_size_max=quotas[3],
        dedup_ttl_ms_max=quotas[4],
        rate_window_size_ms_max=quotas[5],
    )
