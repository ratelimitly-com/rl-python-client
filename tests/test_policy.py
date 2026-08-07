"""Unit tests for HA Request Policy calculations."""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly.policy import (
    standard_policy,
    single_round_policy,
    custom_policy,
    FixedSchedule,
    LinearSchedule,
    ExponentialSchedule,
)


class TestPolicy(unittest.TestCase):
    def test_standard_policy_horizon(self):
        pol = standard_policy(unit_ms=20)
        self.assertEqual(pol.kind, "standard")
        self.assertEqual(pol.calculate_horizon_ms(), 60)

    def test_single_round_policy_horizon(self):
        pol = single_round_policy(unit_ms=50)
        self.assertEqual(pol.kind, "single_round")
        self.assertEqual(pol.calculate_horizon_ms(), 50)

    def test_custom_policy_fixed_schedule(self):
        pol = custom_policy(
            unit_ms=10,
            replays=3,
            replay_gap=FixedSchedule(2),
            final_wait_units=2
        )
        self.assertEqual(pol.calculate_horizon_ms(), 80)

    def test_linear_schedule_gap(self):
        sched = LinearSchedule(initial_units=1, step_units=2, maximum_units=5)
        self.assertEqual(sched.get_gap(0), 1)
        self.assertEqual(sched.get_gap(1), 3)
        self.assertEqual(sched.get_gap(2), 5)
        self.assertEqual(sched.get_gap(3), 5)

    def test_exponential_schedule_gap(self):
        sched = ExponentialSchedule(initial_units=1, factor=2, maximum_units=10)
        self.assertEqual(sched.get_gap(0), 1)
        self.assertEqual(sched.get_gap(1), 2)
        self.assertEqual(sched.get_gap(2), 4)
        self.assertEqual(sched.get_gap(3), 8)
        self.assertEqual(sched.get_gap(4), 10)


if __name__ == "__main__":
    unittest.main()
