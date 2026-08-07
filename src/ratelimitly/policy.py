"""HA Request Policy definitions matching rl-c-client v0.5.1."""

import math
from dataclasses import dataclass
from typing import Literal, Union


class Schedule:
    """Base class for replay gap schedules."""
    def get_gap(self, round_index: int) -> int:
        raise NotImplementedError


@dataclass(frozen=True)
class FixedSchedule(Schedule):
    units: int

    def get_gap(self, round_index: int) -> int:
        return self.units


@dataclass(frozen=True)
class LinearSchedule(Schedule):
    initial_units: int
    step_units: int
    maximum_units: int

    def get_gap(self, round_index: int) -> int:
        gap = self.initial_units + round_index * self.step_units
        return min(gap, self.maximum_units)


@dataclass(frozen=True)
class ExponentialSchedule(Schedule):
    initial_units: int
    factor: int
    maximum_units: int

    def get_gap(self, round_index: int) -> int:
        gap = self.initial_units * (self.factor ** round_index)
        return min(gap, self.maximum_units)


@dataclass(frozen=True)
class RequestPolicy:
    kind: Literal["standard", "single_round", "custom"]
    unit_ms: int = 20
    replays: int = 0
    replay_gap: Schedule = FixedSchedule(1)
    final_wait_units: int = 1
    completion_delivery: bool = True

    def calculate_horizon_ms(self) -> int:
        """Calculates total decision horizon in milliseconds."""
        if self.kind == "single_round":
            return self.unit_ms
        elif self.kind == "standard":
            return self.unit_ms * 3
        
        # Custom schedule calculation
        total_units = 0
        for k in range(self.replays):
            total_units += self.replay_gap.get_gap(k)
        total_units += self.final_wait_units
        return self.unit_ms * total_units


def standard_policy(unit_ms: int = 20) -> RequestPolicy:
    """Default standard three-transmission policy."""
    return RequestPolicy(
        kind="standard",
        unit_ms=unit_ms,
        replays=2,
        replay_gap=FixedSchedule(1),
        final_wait_units=1,
        completion_delivery=True
    )


def single_round_policy(unit_ms: int = 20) -> RequestPolicy:
    """Single-round single-transmission policy."""
    return RequestPolicy(
        kind="single_round",
        unit_ms=unit_ms,
        replays=0,
        replay_gap=FixedSchedule(1),
        final_wait_units=1,
        completion_delivery=False
    )


def custom_policy(
    unit_ms: int,
    replays: int,
    replay_gap: Schedule,
    final_wait_units: int = 1,
    completion_delivery: bool = True
) -> RequestPolicy:
    """Custom high-availability policy."""
    if not (0 <= replays <= 65535):
        raise ValueError("replays must be in range 0..65535")
    if unit_ms <= 0:
        raise ValueError("unit_ms must be positive")
    return RequestPolicy(
        kind="custom",
        unit_ms=unit_ms,
        replays=replays,
        replay_gap=replay_gap,
        final_wait_units=final_wait_units,
        completion_delivery=completion_delivery
    )
