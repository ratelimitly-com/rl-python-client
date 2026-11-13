import unittest
from ratelimitly.auth import parse_auth_key

def check_v2_annual_cap():
    info = parse_auth_key("rl-cookie1qgqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz8scfwu4f")
    assert info.format_version == 2
    assert info.rate_window_size_ms_max == 31536000000

class TestV2Annual(unittest.TestCase):
    test_v2_annual_cap = staticmethod(check_v2_annual_cap)
