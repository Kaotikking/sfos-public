"""Boot-bound replay observations for Kernel OPERATIONS.

Adapted from public 0dca6bd7. These observations do not establish scheduler
decisions, task-queue health, authenticated lease validity or recovery readiness.
Those responsibilities require their own evidence before Operations can pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import sqlite3
import stat
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "SEREIN/KernelOperationsHeartbeat/v1"
INTERVAL_SECONDS = 1.0
MAX_RECEIPTS = 4096

# PRO-136 / 4ae7de33: the evaluator produces telemetry only. The window is an
# explicit profile input, not a silently selected production default.
EXCLUDED_TASK_STATES = frozenset({
    "BLOCKED", "UNAUTHORIZED", "REVOKED", "STALE", "HELD", "SUPERSEDED",
    "DEPENDENCY_UNSATISFIED",
})


class SchedulerMetrics:
    """Bounded, non-mutating interpretation of an attributable queue snapshot.

    No task transitions, leases, dispatches or lanes are created here.
    Caller-provided snapshots require their own Authority/source verification;
    this metric cannot turn them into work or authority evidence.
    """

    def __init__(self, *, floor_bpm: int, window_length: int):
        if type(floor_bpm) is not int or floor_bpm < 60:
            raise OperationsDenied("SCHEDULER_FLOOR_DENIED")
        if type(window_length) is not int or not 1 <= window_length <= 4096:
            raise OperationsDenied("SCHEDULER_WINDOW_DENIED")
        self.floor_bpm = floor_bpm
        self.ceiling_ns = 60_000_000_000 // floor_bpm
        if self.ceiling_ns < 1:
            raise OperationsDenied("SCHEDULER_FLOOR_DENIED")
        self.window_length = window_length
        self._previous = None
        self._window = []

    def remeasure(self) -> None:
        """A separately authorized capacity change invalidates all old samples."""
        self._previous = None
        self._window.clear()

    def observe(self, *, sequence: int, monotonic_ns: int, identity: tuple[str, ...],
                members: list[dict], slots: list[dict], complete: bool,
                dispatch_observed: bool, snapshot_epoch: str, page_plan_digest: str) -> dict:
        if (type(sequence) is not int or sequence < 1 or type(monotonic_ns) is not int
                or monotonic_ns < 0 or type(complete) is not bool
                or type(dispatch_observed) is not bool):
            self.remeasure()
            raise OperationsDenied("SCHEDULER_SNAPSHOT_DENIED")
        # lane, boot, profile/version/digest, policy, authorization, lease heads.
        if (not isinstance(identity, tuple) or len(identity) != 8
                or any(not isinstance(item, str) or not item for item in identity)):
            self.remeasure()
            raise OperationsDenied("SCHEDULER_IDENTITY_DENIED")
        if (not isinstance(snapshot_epoch, str) or not snapshot_epoch
                or not isinstance(page_plan_digest, str) or len(page_plan_digest) != 64
                or any(char not in "0123456789abcdef" for char in page_plan_digest)):
            self.remeasure()
            raise OperationsDenied("SCHEDULER_SNAPSHOT_IDENTITY_DENIED")
        demand, capacity, exclusions, valid = self._population(members, slots)
        valid = valid and complete

        def population_digest(rows):
            # Input ordering is not membership identity. Bind all exact member
            # facts (including authority/state), not merely demand/capacity counts.
            encoded = sorted(json.dumps(row, sort_keys=True, separators=(",", ":"),
                                        allow_nan=False) for row in rows)
            return hashlib.sha256(json.dumps(encoded, separators=(",", ":")).encode()).hexdigest()

        member_digest = population_digest(members) if valid else None
        capacity_digest = population_digest(slots) if valid else None
        window_identity = (identity, snapshot_epoch, page_plan_digest, member_digest, capacity_digest)
        interval = None
        heartbeat = "UNKNOWN"
        if self._previous is not None:
            old_identity, old_sequence, old_ns = self._previous
            if identity == old_identity[0] and (monotonic_ns <= old_ns or sequence <= old_sequence):
                self.remeasure()
                raise OperationsDenied("SCHEDULER_MONOTONICITY_DENIED")
            if window_identity == old_identity:
                interval = monotonic_ns - old_ns
                if interval <= 0 or sequence <= old_sequence:
                    self.remeasure()
                    raise OperationsDenied("SCHEDULER_MONOTONICITY_DENIED")
                if sequence != old_sequence + 1:
                    heartbeat = "MISSING"
                else:
                    heartbeat = "ON_TIME" if interval <= self.ceiling_ns else "LATE"
            else:
                self._window.clear()
        self._previous = (window_identity, sequence, monotonic_ns)
        if not valid:
            pressure, disposition = "UNKNOWN", "UNKNOWN"
        elif capacity == 0:
            pressure = "ZERO_CAPACITY_DEMAND" if demand else "UNDEFINED_IDLE"
            disposition = "CONGESTED" if demand else "HEALTHY_IDLE"
        else:
            high = 10 * demand >= 9 * capacity
            pressure = "AT_OR_ABOVE_90" if high else "BELOW_90"
            disposition = ("CONGESTED" if high else
                           "UNDER_DISPATCH" if demand and not dispatch_observed else
                           "OBSERVED" if demand else "HEALTHY_IDLE")
        if heartbeat != "ON_TIME" or not valid:
            self._window.clear()
        elif pressure == "AT_OR_ABOVE_90":
            self._window.append((window_identity, sequence))
            self._window = self._window[-self.window_length:]
        else:
            self._window.clear()
        evaluation = ("UNKNOWN" if not valid else "ELIGIBLE_FOR_EVALUATION"
                      if len(self._window) == self.window_length else "INELIGIBLE")
        return {
            "contract_reference": "serein.scheduler-vital-sign-observation.v1",
            "classification": "LOCAL_METRIC_COMPONENT_NOT_ADMITTED_TELEMETRY",
            "sequence": sequence,
            "observed_monotonic_ns": monotonic_ns,
            "identity": list(identity),
            "snapshot_epoch": snapshot_epoch,
            "page_plan_digest": page_plan_digest,
            "member_set_digest": member_digest,
            "capacity_set_digest": capacity_digest,
            "configured_floor_bpm": self.floor_bpm,
            "decision_interval_ceiling_ns": self.ceiling_ns,
            "observed_interval_ns": interval,
            "heartbeat_state": heartbeat,
            "health_event": "SCHEDULER_DEGRADED" if heartbeat in {"LATE", "MISSING"} else None,
            "eligible_runnable_count": demand if valid else None,
            "admitted_available_capacity": capacity if valid else None,
            "excluded_count_by_reason": exclusions,
            "pressure_numerator": demand if valid else None,
            "pressure_denominator": capacity if valid else None,
            "pressure_state": pressure,
            "disposition": disposition,
            "evaluation_state": evaluation,
            "qualifying_observations": len(self._window),
            "window_length": self.window_length,
            "authority_effect": "NONE",
            "dispatch_effect": "NONE",
            "lane_count_delta": 0,
            "work_proof": False,
        }

    @staticmethod
    def _population(members, slots):
        if (not isinstance(members, list) or not isinstance(slots, list)
                or len(members) > 4096 or len(slots) > 4096):
            return 0, 0, {}, False
        member_fields = {"task_id", "owner_domain", "lifecycle_state", "authority_digest",
                         "policy_digest", "dependency_digest", "dedupe_key", "runnable_reason"}
        slot_fields = {"slot_id", "platform_capability_digest", "health", "qualification",
                       "isolation", "reservation", "compatible_lease", "freshness"}
        tasks, dedupe, capacities, exclusions = {}, {}, {}, {}
        demand = capacity = 0
        valid = True

        def excluded(reason):
            exclusions[reason] = exclusions.get(reason, 0) + 1

        def text_fields(row, fields):
            return all(isinstance(row.get(name), str) and row[name] for name in fields)

        def digest(value):
            return (isinstance(value, str) and len(value) == 64
                    and all(char in "0123456789abcdef" for char in value))

        for row in members:
            if (not isinstance(row, dict) or not member_fields <= set(row)
                    or set(row) - member_fields - {"exclusion_reason"}
                    or not text_fields(row, member_fields)
                    or ("exclusion_reason" in row and not isinstance(row["exclusion_reason"], str))):
                valid = False
                continue
            if any(not digest(row[name]) for name in
                   ("authority_digest", "policy_digest", "dependency_digest")):
                valid = False
                continue
            previous = tasks.get(row["task_id"]) or dedupe.get(row["dedupe_key"])
            if previous is not None:
                if previous != row:
                    valid = False
                excluded("DUPLICATE")
                continue
            tasks[row["task_id"]] = row
            dedupe[row["dedupe_key"]] = row
            state = row["lifecycle_state"]
            if state in EXCLUDED_TASK_STATES:
                excluded(state)
            elif state in {"READY", "RUNNABLE"} and not row.get("exclusion_reason"):
                demand += 1
            elif state == "QUEUED_CURRENT":
                excluded("QUEUED_CURRENT")
            else:
                valid = False
        for row in slots:
            if (not isinstance(row, dict) or set(row) != slot_fields
                    or not text_fields(row, {"slot_id", "platform_capability_digest"})
                    or not digest(row["platform_capability_digest"])):
                valid = False
                continue
            if row["slot_id"] in capacities:
                if capacities[row["slot_id"]] != row:
                    valid = False
                excluded("DUPLICATE_CAPACITY")
                continue
            capacities[row["slot_id"]] = row
            checks = [row[name] for name in slot_fields - {"slot_id", "platform_capability_digest"}]
            if any(type(value) is not bool for value in checks):
                valid = False
            elif all(checks):
                capacity += 1
            else:
                excluded("UNAVAILABLE_CAPACITY")
        return demand, capacity, exclusions, valid


class OperationsDenied(RuntimeError):
    pass


def _regular_bytes(path: Path, *, expected_size: int | None = None) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise OperationsDenied("IMMUTABLE_REPLAY_INPUT_DENIED")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or (expected_size is not None and info.st_size != expected_size):
        raise OperationsDenied("IMMUTABLE_REPLAY_INPUT_DENIED")
    return path.read_bytes()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def observe(*, boot_id_path: Path, descriptor_path: Path, key_path: Path,
            database_path: Path, sequence: int, monotonic_ns: int | None = None,
            observed_at: str | None = None, previous: dict[str, object] | None = None) -> dict[str, object]:
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise OperationsDenied("HEARTBEAT_SEQUENCE_DENIED")
    boot_id = _regular_bytes(boot_id_path).decode("ascii").strip()
    descriptor_raw = _regular_bytes(descriptor_path)
    key = _regular_bytes(key_path, expected_size=32)
    try:
        descriptor = json.loads(descriptor_raw)
        trusted_key_receipt = descriptor["body"]["trusted_key_receipt"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise OperationsDenied("IMMUTABLE_REPLAY_INPUT_DENIED") from exc
    if not isinstance(trusted_key_receipt, str) or not trusted_key_receipt:
        raise OperationsDenied("IMMUTABLE_REPLAY_INPUT_DENIED")
    if database_path.is_symlink() or not database_path.is_file():
        raise OperationsDenied("REPLAY_DATABASE_DENIED")
    effective_observed_at = observed_at or _utc_now()
    try:
        uri = f"file:{database_path.as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            receipt_count = int(connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
            latest = connection.execute(
                "SELECT canonical_json FROM receipts r WHERE revision="
                "(SELECT MAX(revision) FROM receipts WHERE chain_id=r.chain_id)"
            ).fetchall()
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise OperationsDenied("REPLAY_DATABASE_DENIED") from exc
    try:
        lease_bodies = [json.loads(bytes(row[0]))["body"] for row in latest]
        reserved = [body for body in lease_bodies if body.get("state") == "RESERVED"]
        now = datetime.fromisoformat(effective_observed_at.replace("Z", "+00:00"))
        if any(datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00")) <= now
               for body in reserved):
            raise OperationsDenied("EXPIRED_REPLAY_LEASE_DENIED")
        active_leases = len(reserved)
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise OperationsDenied("REPLAY_LEASE_STATE_DENIED") from exc
    healthy = integrity == "ok" and 0 <= receipt_count < MAX_RECEIPTS
    if not healthy:
        raise OperationsDenied("OPERATIONS_RECOVERY_DENIED")
    current_ns = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    if type(current_ns) is not int or current_ns < 0:
        raise OperationsDenied("HEARTBEAT_CLOCK_DENIED")
    bpm = 0
    cadence_state = "UNPROVEN"
    missed = 0
    missed_total = 0
    last_missed = None
    previous_sequence = None
    if previous is not None and previous.get("schema") == SCHEMA and previous.get("boot_id") == boot_id:
        try:
            previous_ns = int(previous["monotonic_ns"])
            previous_sequence = int(previous["sequence"])
            if sequence != previous_sequence + 1:
                raise ValueError("heartbeat sequence is not monotonic and contiguous")
            missed_total = int(previous.get("missed_heartbeats_total", 0))
            last_missed = previous.get("last_missed_heartbeat_at")
            gap = current_ns - previous_ns
            if gap <= 0:
                raise ValueError("monotonic clock did not advance")
            bpm = 60_000_000_000 / gap
            cadence_state = "OBSERVED" if bpm >= 60 else "DEGRADED"
            missed = max(0, gap // int(INTERVAL_SECONDS * 1_000_000_000) - 1)
            if missed:
                missed_total += missed
                last_missed = effective_observed_at
        except (KeyError, TypeError, ValueError) as exc:
            raise OperationsDenied("HEARTBEAT_PREDECESSOR_DENIED") from exc
    return {
        "schema": SCHEMA,
        "boot_id": boot_id,
        "sequence": sequence,
        "observed_at": effective_observed_at,
        "monotonic_ns": current_ns,
        "bpm": bpm,
        "cadence_state": cadence_state,
        "heartbeat_scope": "REPLAY_OBSERVER_ONLY",
        "scheduler_state": "UNPROVEN",
        "queues": "UNKNOWN",
        "queue_depth": None,
        "replay_receipts": receipt_count,
        "leases": "UNKNOWN",
        "active_leases": active_leases,
        "recovery": "UNKNOWN",
        "unproven": ["task_queues", "lease_authenticity", "recovery_controls", "scheduler_decisions"],
        "event": "MISSED_HEARTBEAT" if missed else ("BOOT_BOUND_START" if previous_sequence is None else "HEARTBEAT"),
        "previous_sequence": previous_sequence,
        "missed_heartbeats_current": missed,
        "missed_heartbeats_total": missed_total,
        "last_missed_heartbeat_at": last_missed,
        "replay_inputs": {
            "descriptor_sha256": hashlib.sha256(descriptor_raw).hexdigest(),
            "key_sha256": hashlib.sha256(key).hexdigest(),
            "trusted_key_receipt": trusted_key_receipt,
            "database_integrity": integrity,
        },
        "authority_effect": "NONE",
    }


def atomic_write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".kernel-operations-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)


def serve(*, output_path: Path, boot_id_path: Path, descriptor_path: Path,
          key_path: Path, database_path: Path, stop: threading.Event | None = None) -> None:
    stopped = stop or threading.Event()
    if stop is None:
        signal.signal(signal.SIGTERM, lambda *_: stopped.set())
        signal.signal(signal.SIGINT, lambda *_: stopped.set())
    previous = None
    if output_path.is_file() and not output_path.is_symlink():
        try:
            candidate = json.loads(output_path.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                previous = candidate
        except (OSError, UnicodeError, json.JSONDecodeError):
            previous = None
    current_boot = _regular_bytes(boot_id_path).decode("ascii").strip()
    if previous is not None and previous.get("boot_id") != current_boot:
        previous = None
    sequence = int(previous.get("sequence", 0)) if previous else 0
    deadline = time.monotonic()
    while not stopped.is_set():
        sequence += 1
        atomic_write(output_path, observe(
            boot_id_path=boot_id_path, descriptor_path=descriptor_path,
            key_path=key_path, database_path=database_path, sequence=sequence,
            previous=previous,
        ))
        previous = json.loads(output_path.read_text(encoding="utf-8"))
        deadline += INTERVAL_SECONDS
        stopped.wait(max(0.0, deadline - time.monotonic()))
