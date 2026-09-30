"""Evidence semantics only: a replay observer is not a proven scheduler."""
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "kernel_operations_evidence", Path(__file__).parents[1] / "payload/serein_stage1/kernel_operations.py")
operations = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(operations)


def inputs(tmp_path):
    boot = tmp_path / "boot"
    boot.write_text("11111111-2222-3333-8444-555555555555\n")
    descriptor = tmp_path / "descriptor"
    descriptor.write_text(json.dumps({"body": {"trusted_key_receipt": "fixture-only"}}))
    key = tmp_path / "key"
    key.write_bytes(b"x" * 32)
    database = tmp_path / "replay.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE receipts(chain_id TEXT,revision INTEGER,canonical_json BLOB)")
    return dict(boot_id_path=boot, descriptor_path=descriptor, key_path=key,
                database_path=database, observed_at="2026-09-30T12:00:00Z")


def test_first_observation_does_not_claim_measured_cadence(tmp_path):
    value = operations.observe(**inputs(tmp_path), sequence=1, monotonic_ns=1_000_000_000)
    assert value["bpm"] == 0
    assert value["cadence_state"] == "UNPROVEN"
    assert value["heartbeat_scope"] == "REPLAY_OBSERVER_ONLY"


@pytest.mark.parametrize("seconds,expected_bpm,missed", [(1, 60, 0), (2, 30, 1), (3, 20, 2)])
def test_measured_cadence_and_missed_event(tmp_path, seconds, expected_bpm, missed):
    kwargs = inputs(tmp_path)
    first = operations.observe(**kwargs, sequence=1, monotonic_ns=1_000_000_000)
    value = operations.observe(**kwargs, sequence=2,
                               monotonic_ns=(seconds+1)*1_000_000_000, previous=first)
    assert value["bpm"] == expected_bpm
    assert value["missed_heartbeats_current"] == missed
    assert value["event"] == ("MISSED_HEARTBEAT" if missed else "HEARTBEAT")
    assert value["cadence_state"] == ("DEGRADED" if expected_bpm < 60 else "OBSERVED")
    assert value["authority_effect"] == "NONE"


def test_replay_integrity_does_not_prove_queues_leases_or_recovery(tmp_path):
    value = operations.observe(**inputs(tmp_path), sequence=1, monotonic_ns=1_000_000_000)
    assert value["replay_inputs"]["database_integrity"] == "ok"
    assert value["queues"] == "UNKNOWN"
    assert value["queue_depth"] is None
    assert value["leases"] == "UNKNOWN"
    assert value["recovery"] == "UNKNOWN"
    assert value["scheduler_state"] == "UNPROVEN"
    assert set(value["unproven"]) == {"task_queues", "lease_authenticity", "recovery_controls", "scheduler_decisions"}


@pytest.mark.parametrize("monotonic_ns", [True, -1, 0.5])
def test_invalid_clock_cannot_produce_heartbeat(tmp_path, monotonic_ns):
    with pytest.raises(operations.OperationsDenied, match="CLOCK"):
        operations.observe(**inputs(tmp_path), sequence=1, monotonic_ns=monotonic_ns)


def test_same_tick_does_not_prove_sixty_bpm(tmp_path):
    kwargs = inputs(tmp_path)
    first = operations.observe(**kwargs, sequence=1, monotonic_ns=1_000_000_000)
    with pytest.raises(operations.OperationsDenied, match="PREDECESSOR"):
        operations.observe(**kwargs, sequence=2, monotonic_ns=1_000_000_000, previous=first)
