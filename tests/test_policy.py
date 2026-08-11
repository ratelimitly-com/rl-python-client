"""Conformance tests for the unified rl-c-client HA request policy."""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly.policy import (
    RequestPolicy,
    FixedSchedule,
    LinearSchedule,
    ExponentialSchedule,
    default_request_policy,
)


class TestPolicy(unittest.TestCase):
    def test_default_policy_matches_c_client(self):
        policy = default_request_policy()
        self.assertEqual(policy.unit_ms, 20)
        self.assertEqual(policy.replay_count, 1)
        self.assertEqual(policy.replay_gap.get_gap(0), 1)
        self.assertEqual(policy.replay_gap.get_gap(1), 1)
        self.assertEqual(policy.final_receive_units, 1)
        self.assertTrue(policy.completion_delivery)
        self.assertEqual(policy.calculate_horizon_ms(), 60)

    def test_zero_replays_and_no_final_receive_is_one_round(self):
        policy = RequestPolicy(
            unit_ms=25,
            replay_count=0,
            replay_gap=FixedSchedule(1),
            final_receive_units=0,
            completion_delivery=False,
        )
        self.assertEqual(policy.calculate_horizon_ms(), 25)

    def test_horizon_includes_initial_round_all_replays_and_final_receive(self):
        policy = RequestPolicy(
            unit_ms=10,
            replay_count=3,
            replay_gap=FixedSchedule(2),
            final_receive_units=2,
        )
        self.assertEqual(policy.calculate_horizon_ms(), 100)

    def test_linear_schedule(self):
        schedule = LinearSchedule(initial_units=1, step_units=2, maximum_units=5)
        self.assertEqual([schedule.get_gap(index) for index in range(4)], [1, 3, 5, 5])

    def test_exponential_schedule(self):
        schedule = ExponentialSchedule(initial_units=1, factor=2, maximum_units=10)
        self.assertEqual([schedule.get_gap(index) for index in range(5)], [1, 2, 4, 8, 10])

    def test_credential_dedup_limit_is_enforced(self):
        with self.assertRaises(ValueError):
            default_request_policy(unit_ms=101).calculate_horizon_ms(
                dedup_ttl_ms_max=300
            )


if __name__ == "__main__":
    unittest.main()
