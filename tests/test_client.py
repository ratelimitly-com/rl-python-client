"""Unit tests for Sync and Async RateLimitly clients."""

import unittest
import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly import RateLimitlyClient, AsyncRateLimitlyClient, Verdict

SYNTHETIC_KEY = "rl-aes1qyqqqqqqqqqqq6uxkfel7d8uuxwkhqzwladr74684kjw4g30r4yuq8jjmkmcwk6tqqqqzqqqqsqqqqqsqqqyqqqqqqkqzqqq0n6jux"


class TestClient(unittest.TestCase):
    def test_client_init_and_fail_open(self):
        client = RateLimitlyClient(
            auth_key=SYNTHETIC_KEY,
            fail_open=True
        )
        verdict = client.eval("bucket=v1|scope=test", count=1)
        self.assertEqual(verdict, Verdict.ALLOW)
        client.close()

    def test_async_client_init_and_fail_open(self):
        async def run_test():
            client = AsyncRateLimitlyClient(
                auth_key=SYNTHETIC_KEY,
                fail_open=True
            )
            return await client.eval("bucket=v1|scope=test", count=1)

        verdict = asyncio.run(run_test())
        self.assertEqual(verdict, Verdict.ALLOW)


if __name__ == "__main__":
    unittest.main()
