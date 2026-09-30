"""PRO-136 reference-profile arithmetic; no production scheduler admission."""
import copy
import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "kernel_scheduler_metrics", Path(__file__).parents[1] / "payload/serein_stage1/kernel_operations.py")
operations = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(operations)
IDENTITY = ("kernel", "boot-fixture", "reference-profile", "1", "profile-digest",
            "policy-head", "authority-head", "lease-head")


def tasks(count, state="READY"):
    return [dict(task_id=str(i), owner_domain="KERNEL", lifecycle_state=state,
                 authority_digest="a"*64, policy_digest="b"*64, dependency_digest="c"*64,
                 dedupe_key=str(i), runnable_reason="VALID_DEMAND") for i in range(count)]


def slots(count):
    return [dict(slot_id=str(i), platform_capability_digest="d"*64, health=True,
                 qualification=True, isolation=True, reservation=True,
                 compatible_lease=True, freshness=True) for i in range(count)]


def cycle(metrics, number, demand=9, capacity=10, **overrides):
    kwargs = dict(sequence=number, monotonic_ns=number*1_000_000_000, identity=IDENTITY,
                  members=tasks(demand), slots=slots(capacity), complete=True,
                  dispatch_observed=False, snapshot_epoch="snapshot-fixture",
                  page_plan_digest="e"*64)
    kwargs.update(overrides)
    return metrics.observe(**kwargs)


def metric():
    return operations.SchedulerMetrics(floor_bpm=60, window_length=10)


@pytest.mark.parametrize("floor", [59, 0, -1, True, 60.0])
def test_floor_cannot_be_lowered_or_coerced(floor):
    with pytest.raises(operations.OperationsDenied, match="FLOOR"):
        operations.SchedulerMetrics(floor_bpm=floor, window_length=10)


def test_one_second_ceiling_and_first_sample_not_proof():
    result = cycle(metric(), 1)
    assert result["decision_interval_ceiling_ns"] == 1_000_000_000
    assert result["heartbeat_state"] == "UNKNOWN"
    assert result["evaluation_state"] == "INELIGIBLE"
    assert result["work_proof"] is False and result["authority_effect"] == "NONE"


@pytest.mark.parametrize("demand,capacity,state", [
    (8, 9, "BELOW_90"), (9, 10, "AT_OR_ABOVE_90"),
    (0, 0, "UNDEFINED_IDLE"), (1, 0, "ZERO_CAPACITY_DEMAND")])
def test_exact_pressure_and_zero_capacity(demand, capacity, state):
    result = cycle(metric(), 1, demand=demand, capacity=capacity)
    assert result["pressure_state"] == state


def test_sustained_window_is_evaluation_only_and_single_spike_is_not():
    evaluator = metric()
    cycle(evaluator, 1)
    for number in range(2, 11):
        result = cycle(evaluator, number)
        assert result["evaluation_state"] == "INELIGIBLE"
    result = cycle(evaluator, 11)
    assert result["evaluation_state"] == "ELIGIBLE_FOR_EVALUATION"
    assert result["lane_count_delta"] == 0 and result["dispatch_effect"] == "NONE"
    assert result["authority_effect"] == "NONE" and result["work_proof"] is False
    result = cycle(evaluator, 12, demand=0)
    assert result["qualifying_observations"] == 0
    assert cycle(evaluator, 13)["evaluation_state"] == "INELIGIBLE"


def test_exclusion_duplicate_and_queued_state_preservation():
    members = tasks(9)
    for index, state in enumerate(sorted(operations.EXCLUDED_TASK_STATES), 100):
        row = tasks(1, state)[0]
        row.update(task_id=str(index), dedupe_key=str(index))
        members.append(row)
    members.append(copy.deepcopy(members[0]))
    members.append({**tasks(1, "QUEUED_CURRENT")[0], "task_id":"queued", "dedupe_key":"queued"})
    before = copy.deepcopy(members)
    result = cycle(metric(), 1, members=members)
    assert result["eligible_runnable_count"] == 9
    assert result["excluded_count_by_reason"]["DUPLICATE"] == 1
    assert result["excluded_count_by_reason"]["QUEUED_CURRENT"] == 1
    assert members == before


def test_conflicting_duplicate_is_unknown():
    members = tasks(1)
    members.append({**members[0], "authority_digest":"e"*64})
    result = cycle(metric(), 1, members=members)
    assert result["pressure_state"] == "UNKNOWN"
    assert result["eligible_runnable_count"] is None


@pytest.mark.parametrize("changed", ["identity", "complete", "late", "missing"])
def test_epoch_incomplete_or_bad_cadence_resets_window(changed):
    evaluator = metric()
    for number in range(1, 11):
        cycle(evaluator, number)
    kwargs = {}
    if changed == "identity":
        kwargs["identity"] = (*IDENTITY[:-1], "new-lease")
    elif changed == "complete":
        kwargs["complete"] = False
    elif changed == "late":
        kwargs["monotonic_ns"] = 12_000_000_000
    else:
        kwargs.update(sequence=12, monotonic_ns=12_000_000_000)
    result = cycle(evaluator, 11, **kwargs)
    assert result["qualifying_observations"] == 0
    assert result["evaluation_state"] != "ELIGIBLE_FOR_EVALUATION"
    if changed in {"late", "missing"}:
        assert result["health_event"] == "SCHEDULER_DEGRADED"


def test_remeasure_discards_pre_expansion_window():
    evaluator = metric()
    for number in range(1, 12):
        result = cycle(evaluator, number)
    assert result["evaluation_state"] == "ELIGIBLE_FOR_EVALUATION"
    evaluator.remeasure()
    result = cycle(evaluator, 12)
    assert result["evaluation_state"] == "INELIGIBLE"
    assert result["qualifying_observations"] == 0


def test_under_dispatch_distinct_from_idle():
    assert cycle(metric(), 1, demand=1)["disposition"] == "UNDER_DISPATCH"
    assert cycle(metric(), 1, demand=0)["disposition"] == "HEALTHY_IDLE"


def test_unknown_capacity_and_untrusted_flags_fail_closed():
    capacity = slots(1)
    capacity[0]["isolation"] = "True"
    result = cycle(metric(), 1, slots=capacity)
    assert result["pressure_state"] == "UNKNOWN"
    with pytest.raises(operations.OperationsDenied, match="SNAPSHOT"):
        cycle(metric(), 1, complete=1)


def test_fixed_capacity_pressure_monotonic_and_failed_slots_excluded():
    values = [cycle(metric(), 1, demand=n)["pressure_numerator"] for n in range(11)]
    assert values == list(range(11))
    capacity = slots(10)
    capacity[0]["health"] = False
    result = cycle(metric(), 1, slots=capacity)
    assert result["admitted_available_capacity"] == 9
    assert result["excluded_count_by_reason"]["UNAVAILABLE_CAPACITY"] == 1


def test_changing_membership_with_same_pressure_never_accumulates_window():
    evaluator = metric()
    for number in range(1, 12):
        members = tasks(9)
        for row in members:
            row["task_id"] = str(number) + "-" + row["task_id"]
            row["dedupe_key"] = row["task_id"]
        result = cycle(evaluator, number, members=members)
        assert result["qualifying_observations"] == 0
        assert result["evaluation_state"] == "INELIGIBLE"


@pytest.mark.parametrize("change", ["snapshot_epoch", "page_plan_digest", "capacity", "authority"])
def test_snapshot_and_member_facts_reset_window(change):
    evaluator = metric()
    for number in range(1, 11):
        cycle(evaluator, number)
    kwargs = {}
    if change == "snapshot_epoch":
        kwargs[change] = "new-snapshot"
    elif change == "page_plan_digest":
        kwargs[change] = "f"*64
    elif change == "capacity":
        capacity = slots(10)
        capacity[0]["slot_id"] = "replacement-slot"
        kwargs["slots"] = capacity
    else:
        members = tasks(9)
        members[0]["authority_digest"] = "f"*64
        kwargs["members"] = members
    result = cycle(evaluator, 11, **kwargs)
    assert result["qualifying_observations"] == 0
    assert result["evaluation_state"] == "INELIGIBLE"


def test_member_reordering_does_not_change_identity():
    evaluator = metric()
    for number in range(1, 12):
        result = cycle(evaluator, number, members=tasks(9)[::1 if number % 2 else -1])
    assert result["evaluation_state"] == "ELIGIBLE_FOR_EVALUATION"


def test_membership_change_cannot_hide_clock_regression():
    evaluator = metric()
    cycle(evaluator, 1)
    with pytest.raises(operations.OperationsDenied, match="MONOTONICITY"):
        cycle(evaluator, 2, demand=8, monotonic_ns=1)


def test_noncanonical_exclusion_reason_cannot_break_observation():
    members = tasks(1, "HELD")
    members[0]["exclusion_reason"] = object()
    assert cycle(metric(), 1, members=members)["pressure_state"] == "UNKNOWN"
