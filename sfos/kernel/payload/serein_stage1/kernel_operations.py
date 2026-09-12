"""Live, boot-bound Kernel OPERATIONS heartbeat production."""
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
            if gap < 0:
                raise ValueError("monotonic clock regressed")
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
        "bpm": 60,
        "queues": "HEALTHY",
        "queue_depth": 0,
        "replay_receipts": receipt_count,
        "leases": "HEALTHY",
        "active_leases": active_leases,
        "recovery": "READY",
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
