"""Unit tests for low-level Sync and Async RateLimitly clients."""

import unittest
import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly import (
    RateLimitlyClient,
    AsyncRateLimitlyClient,
    ResourceRequest,
    RCLIENT_OK,
    r_client_derive_bucket_id,
)

SYNTHETIC_KEY = "rl-aes1qyqqqqqqqqqqq6uxkfel7d8uuxwkhqzwladr74684kjw4g30r4yuq8jjmkmcwk6tqqqqzqqqqsqqqqqsqqqyqqqqqqkqzqqq0n6jux"


class TestClient(unittest.TestCase):
    def test_client_init_and_timeout(self):
        client = RateLimitlyClient(
            auth_key=SYNTHETIC_KEY
        )
        bucket_id = r_client_derive_bucket_id("test_bucket", 60000, 100)
        req = ResourceRequest(bucket_id=bucket_id, tokens_requested=1)

        # In test env with no running server, returns negative error status
        status, result = client.check_rate_limit([req])
        self.assertNotEqual(status, RCLIENT_OK)
        self.assertIsNone(result)
        client.close()

    def test_async_client_init_and_timeout(self):
        async def run_test():
            client = AsyncRateLimitlyClient(
                auth_key=SYNTHETIC_KEY
            )
            bucket_id = r_client_derive_bucket_id("test_bucket", 60000, 100)
            req = ResourceRequest(bucket_id=bucket_id, tokens_requested=1)
            return await client.check_rate_limit([req])

        status, result = asyncio.run(run_test())
        self.assertNotEqual(status, RCLIENT_OK)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
