"""The unified high-availability request policy shared with rl-c-client."""

from dataclasses import dataclass


R_CLIENT_HA_MAX_REPLAY_COUNT = 65535
UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF


def _plain_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return value


class Schedule:
    """Base class for a round duration B(k), expressed in policy units."""

    def get_gap(self, round_index: int) -> int:
        raise NotImplementedError


@dataclass(frozen=True)
class FixedSchedule(Schedule):
    units: int

    def __post_init__(self) -> None:
        units = _plain_int(self.units, "units")
        if not 1 <= units <= UINT32_MAX:
            raise ValueError("units must be in range 1..4294967295")

    def get_gap(self, round_index: int) -> int:
        _validate_round_index(round_index)
        return self.units


@dataclass(frozen=True)
class LinearSchedule(Schedule):
    initial_units: int
    step_units: int
    maximum_units: int

    def __post_init__(self) -> None:
        initial = _plain_int(self.initial_units, "initial_units")
        step = _plain_int(self.step_units, "step_units")
        maximum = _plain_int(self.maximum_units, "maximum_units")
        if not 1 <= initial <= maximum <= UINT32_MAX:
            raise ValueError("linear units must satisfy 1 <= initial <= maximum <= UINT32_MAX")
        if not 1 <= step <= UINT32_MAX:
            raise ValueError("step_units must be in range 1..UINT32_MAX")

    def get_gap(self, round_index: int) -> int:
        _validate_round_index(round_index)
        room = self.maximum_units - self.initial_units
        if round_index > room // self.step_units:
            return self.maximum_units
        return self.initial_units + round_index * self.step_units


@dataclass(frozen=True)
class ExponentialSchedule(Schedule):
    initial_units: int
    factor: int
    maximum_units: int

    def __post_init__(self) -> None:
        initial = _plain_int(self.initial_units, "initial_units")
        factor = _plain_int(self.factor, "factor")
        maximum = _plain_int(self.maximum_units, "maximum_units")
        if not 1 <= initial <= maximum <= UINT32_MAX:
            raise ValueError(
                "exponential units must satisfy "
                "1 <= initial <= maximum <= UINT32_MAX"
            )
        if not 2 <= factor <= UINT32_MAX:
            raise ValueError("factor must be in range 2..UINT32_MAX")

    def get_gap(self, round_index: int) -> int:
        _validate_round_index(round_index)
        value = self.initial_units
        for _ in range(round_index):
            if value >= self.maximum_units or value > self.maximum_units // self.factor:
                return self.maximum_units
            value *= self.factor
        return min(value, self.maximum_units)


def _validate_round_index(round_index: int) -> None:
    index = _plain_int(round_index, "round_index")
    if not 0 <= index <= UINT32_MAX:
        raise ValueError("round_index must be in range 0..UINT32_MAX")


@dataclass(frozen=True)
class RequestPolicy:
    """One parametrized policy; every non-empty request follows this model."""

    unit_ms: int
    replay_count: int
    replay_gap: Schedule
    final_receive_units: int = 1
    completion_delivery: bool = True

    def __post_init__(self) -> None:
        unit_ms = _plain_int(self.unit_ms, "unit_ms")
        replay_count = _plain_int(self.replay_count, "replay_count")
        final_units = _plain_int(self.final_receive_units, "final_receive_units")
        if not 1 <= unit_ms <= UINT64_MAX:
            raise ValueError("unit_ms must be in range 1..UINT64_MAX")
        if not 0 <= replay_count <= R_CLIENT_HA_MAX_REPLAY_COUNT:
            raise ValueError("replay_count must be in range 0..65535")
        if not isinstance(self.replay_gap, Schedule):
            raise TypeError("replay_gap must be a Schedule")
        if not 0 <= final_units <= UINT32_MAX:
            raise ValueError("final_receive_units must be in range 0..UINT32_MAX")
        if not isinstance(self.completion_delivery, bool):
            raise TypeError("completion_delivery must be bool")

    def calculate_horizon_ms(self, dedup_ttl_ms_max: int = UINT32_MAX) -> int:
        """Return the C-compatible deduplication TTL/decision horizon."""
        maximum = _plain_int(dedup_ttl_ms_max, "dedup_ttl_ms_max")
        if maximum == 0:
            maximum = UINT32_MAX
        if not 1 <= maximum <= UINT32_MAX:
            raise ValueError("dedup_ttl_ms_max must be in range 0..UINT32_MAX")
        if self.unit_ms > maximum:
            raise ValueError("unit_ms exceeds the credential deduplication limit")

        total_units = sum(
            self.replay_gap.get_gap(round_index)
            for round_index in range(self.replay_count + 1)
        )
        total_units += self.final_receive_units
        horizon = total_units * self.unit_ms
        if total_units == 0 or horizon > UINT32_MAX or horizon > maximum:
            raise ValueError("request policy horizon exceeds the deduplication limit")
        return horizon


def default_request_policy(unit_ms: int = 20) -> RequestPolicy:
    """Return the exact default produced by r_client_default_request_policy."""
    return RequestPolicy(
        unit_ms=unit_ms,
        replay_count=1,
        replay_gap=FixedSchedule(1),
        final_receive_units=1,
        completion_delivery=True,
    )
