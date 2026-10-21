"""Observation-only reboot classification and hash-chained Serein Vitals chronology."""
from __future__ import annotations

import hashlib
import copy
import fcntl
import json
import math
import os
import re
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
WITNESS_MODES = {"POST_BOOT_INFERRED_REBOOT", "EXTERNAL_OUTAGE_WITNESS", "SUBJECT_REPORTED_REBOOT"}


class RebootVitalityError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError, UnicodeError) as error:
        raise RebootVitalityError("VITALITY_JSON_VALUE_DENIED") from error


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RebootVitalityError("VITALITY_JSON_DUPLICATE_KEY_DENIED")
        result[key] = value
    return result


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _timestamp(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def classify_reboot(observation: Mapping[str, Any], intent: Mapping[str, Any] | None = None) -> dict[str, Any]:
    required = {"schema", "event_id", "subject", "outpost_identity", "previous_boot_id", "new_boot_id", "last_observed_at", "first_post_boot_at", "observed_at", "witness_mode", "post_boot", "evidence_ref", "evidence_digest", "policy_version"}
    if not isinstance(observation, Mapping) or set(observation) != required or observation.get("schema") != "SereinOutpostRebootObservation/v1":
        raise RebootVitalityError("REBOOT_OBSERVATION_SHAPE_DENIED")
    if not all(_text(observation.get(key)) for key in ("event_id", "subject", "outpost_identity", "witness_mode", "evidence_ref", "policy_version")):
        raise RebootVitalityError("REBOOT_OBSERVATION_IDENTITY_DENIED")
    if observation["witness_mode"] not in WITNESS_MODES:
        raise RebootVitalityError("REBOOT_WITNESS_MODE_DENIED")
    if any(not BOOT.fullmatch(str(observation.get(key))) for key in ("previous_boot_id", "new_boot_id")):
        raise RebootVitalityError("REBOOT_BOOT_ID_DENIED")
    if any(not _timestamp(observation.get(key)) for key in ("last_observed_at", "first_post_boot_at", "observed_at")):
        raise RebootVitalityError("REBOOT_TIME_DENIED")
    if not observation["last_observed_at"] <= observation["first_post_boot_at"] <= observation["observed_at"]:
        raise RebootVitalityError("REBOOT_TIME_ORDER_DENIED")
    post = observation["post_boot"]
    if not isinstance(post, Mapping) or set(post) != {"readiness", "failed_components", "trust_changes", "capability_changes"}:
        raise RebootVitalityError("REBOOT_RECOVERY_SHAPE_DENIED")
    if post["readiness"] not in {"VERIFIED", "DEGRADED", "UNKNOWN"} or any(not isinstance(post[k], list) for k in ("failed_components", "trust_changes", "capability_changes")):
        raise RebootVitalityError("REBOOT_RECOVERY_VALUE_DENIED")
    if post["readiness"] == "VERIFIED" and post["failed_components"]:
        raise RebootVitalityError("REBOOT_RECOVERY_VALUE_DENIED")
    if post["readiness"] == "VERIFIED":
        # This generation has no admitted mode/profile required-component
        # denominator. An empty failure list cannot establish global recovery.
        raise RebootVitalityError("REBOOT_RECOVERY_DENOMINATOR_UNAVAILABLE")
    body = {k: v for k, v in observation.items() if k != "evidence_digest"}
    if not HEX64.fullmatch(str(observation["evidence_digest"])) or observation["evidence_digest"] != _digest(body):
        raise RebootVitalityError("REBOOT_EVIDENCE_DIGEST_DENIED")
    changed = observation["previous_boot_id"] != observation["new_boot_id"]
    cause, match, intent_id = "REBOOT_CAUSE_UNKNOWN", "NONE", None
    intent_evidence = None
    if changed and intent is not None:
        expected = {"schema", "intent_id", "subject", "actor", "requested_at", "not_before", "not_after", "action", "authorization_ref", "completion_evidence_ref", "consumed"}
        if not isinstance(intent, Mapping) or set(intent) != expected or intent.get("schema") != "SereinAuthorizedPowerIntent/v1":
            match = "CONTRADICTORY"
        else:
            intent_evidence = dict(intent)
            intent_id = intent.get("intent_id")
            # PRO-135 d0ec013c: this legacy subject-local envelope has no
            # independently verified issuer or boot-bound single-use ledger.
            # Retain it as evidence only. Neither its presence nor its absence
            # establishes whether the transition was authorized.
            match = "UNVERIFIED_GOVERNANCE_EVIDENCE"
    elif not changed:
        match = "NOT_APPLICABLE"
    recovery = {"VERIFIED": "BOOT_RECOVERY_VERIFIED", "DEGRADED": "BOOT_RECOVERY_DEGRADED", "UNKNOWN": "BOOT_RECOVERY_UNKNOWN"}[post["readiness"]]
    alert = changed and (cause in {"UNEXPECTED_REBOOT", "REBOOT_CAUSE_UNKNOWN"} or recovery == "BOOT_RECOVERY_DEGRADED")
    result = {"schema": "SereinOutpostRebootClassification/v1", "event_id": observation["event_id"], "subject": observation["subject"], "outpost_identity": observation["outpost_identity"], "previous_boot_id": observation["previous_boot_id"], "new_boot_id": observation["new_boot_id"], "boot_changed": changed, "cause": cause, "recovery": recovery, "intent_id": intent_id, "intent_match": match, "witness_mode": observation["witness_mode"], "last_observed_at": observation["last_observed_at"], "first_post_boot_at": observation["first_post_boot_at"], "observed_at": observation["observed_at"], "post_boot": dict(post), "evidence_ref": observation["evidence_ref"], "evidence_digest": observation["evidence_digest"], "policy_version": observation["policy_version"], "alert_required": alert, "authority_effect": "NONE", "mutation_effect": "NONE", "recommended_action": "SEPARATELY_GOVERNED_RECOVERY_REVIEW" if alert else "NONE"}
    # No trusted ledger is connected to this observation-only implementation.
    # Expected/unexpected classification remains incomplete, never inferred
    # from a local envelope, unkeyed digest, or missing intent.
    result["intent_evidence"] = intent_evidence
    return {**result, "classification_digest": _digest(result)}


def validate_classification(value: Mapping[str, Any], intent: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Check persisted observation/derived-state integrity; grant no authority."""
    if not isinstance(value, Mapping) or value.get("schema") != "SereinOutpostRebootClassification/v1":
        raise RebootVitalityError("REBOOT_CLASSIFICATION_SHAPE_DENIED")
    body = {key: item for key, item in value.items() if key != "classification_digest"}
    if value.get("classification_digest") != _digest(body):
        raise RebootVitalityError("REBOOT_CLASSIFICATION_DIGEST_DENIED")
    fields = ("event_id", "subject", "outpost_identity", "previous_boot_id", "new_boot_id", "last_observed_at", "first_post_boot_at", "observed_at", "witness_mode", "post_boot", "evidence_ref", "evidence_digest", "policy_version")
    try:
        observed = {key: value[key] for key in fields}
    except KeyError as error:
        raise RebootVitalityError("REBOOT_CLASSIFICATION_SHAPE_DENIED") from error
    # An intent-dependent cause must be re-derived from that intent, never
    # accepted from its label or an unkeyed digest alone.
    retained_intent = value.get("intent_evidence")
    if retained_intent is not None and not isinstance(retained_intent, Mapping):
        raise RebootVitalityError("REBOOT_INTENT_EVIDENCE_DENIED")
    if intent is not None and retained_intent != intent:
        raise RebootVitalityError("REBOOT_INTENT_EVIDENCE_DENIED")
    derived = classify_reboot({"schema": "SereinOutpostRebootObservation/v1", **observed}, retained_intent if intent is None else intent)
    if dict(value) != derived or type(value.get("boot_changed")) is not bool or type(value.get("alert_required")) is not bool:
        raise RebootVitalityError("REBOOT_CLASSIFICATION_DERIVATION_DENIED")
    return dict(value)


class VitalityChronology:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._summary_cache = None
        self._summary_failure = None
        self._summary_lock = threading.Lock()
        self._append_cache = None

    def _open(self, *, writing: bool):
        if self.path.is_symlink() or any(parent.is_symlink() for parent in self.path.parents):
            raise RebootVitalityError("VITALITY_CHRONOLOGY_CUSTODY_DENIED")
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT if writing else os.O_RDONLY
        path = self.path.absolute()
        directories, fd = [], None
        try:
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            directories.append((parent, None, None))
            for part in path.parent.parts[1:]:
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                except FileNotFoundError:
                    if not writing:
                        raise
                    try:
                        os.mkdir(part, dir_fd=parent)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                directories.append((child, parent, part))
                parent = child
            fd = os.open(path.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RebootVitalityError("VITALITY_CHRONOLOGY_CUSTODY_DENIED")
            fcntl.flock(fd, (fcntl.LOCK_EX if writing else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            self._check_names(fd, directories)
        except BlockingIOError as error:
            if fd is not None: os.close(fd)
            for directory, _, _ in reversed(directories): os.close(directory)
            raise RebootVitalityError("VITALITY_CHRONOLOGY_BUSY") from error
        except BaseException:
            if fd is not None: os.close(fd)
            for directory, _, _ in reversed(directories): os.close(directory)
            raise
        return fd, directories

    @staticmethod
    def _read_locked(fd: int, verified_prefix=None, digest_state=None) -> list[dict[str, Any]]:
        rows = list(verified_prefix) if verified_prefix is not None else []
        previous = rows[-1]["event_hash"] if rows else "GENESIS"
        seen = {row["event_id"] for row in rows}
        try:
            with os.fdopen(os.dup(fd), "rb") as stream:
                for raw in stream:
                    if digest_state is not None:
                        digest_state.update(raw)
                    if not raw.endswith(b"\n"):
                        raise RebootVitalityError("VITALITY_CHRONOLOGY_INCOMPLETE_RECORD")
                    record = json.loads(raw, object_pairs_hook=_unique_object)
                    if not isinstance(record, dict):
                        raise RebootVitalityError("VITALITY_CHRONOLOGY_SHAPE_DENIED")
                    body = {k: v for k, v in record.items() if k != "event_hash"}
                    if set(record) != {"schema", "sequence", "event_id", "event_kind", "subject", "observed_at", "payload", "previous_hash", "event_hash"} or record["schema"] != "SereinVitalityChronologyEvent/v1" or type(record["sequence"]) is not int or record["sequence"] != len(rows) + 1 or record["previous_hash"] != previous or record["event_hash"] != _digest(body):
                        raise RebootVitalityError("VITALITY_CHRONOLOGY_CHAIN_DENIED")
                    if not all(_text(record[key]) for key in ("event_id", "event_kind", "subject")) or not _timestamp(record["observed_at"]) or not isinstance(record["payload"], dict):
                        raise RebootVitalityError("VITALITY_CHRONOLOGY_INPUT_DENIED")
                    if record["event_id"] in seen: raise RebootVitalityError("VITALITY_CHRONOLOGY_DUPLICATE_DENIED")
                    seen.add(record["event_id"]); rows.append(record); previous = record["event_hash"]
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RebootVitalityError("VITALITY_CHRONOLOGY_READ_DENIED") from exc
        return rows

    def read(self) -> list[dict[str, Any]]:
        try:
            fd, directories = self._open(writing=False)
        except FileNotFoundError:
            return []
        try:
            return self._read_locked(fd)
        finally:
            os.close(fd)
            for directory, _, _ in reversed(directories): os.close(directory)

    @contextmanager
    def _summary_access(self, verified_prefix_only):
        if not self._summary_lock.acquire(blocking=not verified_prefix_only):
            raise RebootVitalityError("VITALITY_CHRONOLOGY_BUSY")
        try:
            if (verified_prefix_only and self._summary_cache is None
                    and self._summary_failure is None):
                raise RebootVitalityError("VITALITY_CHRONOLOGY_NOT_YET_VERIFIED")
            yield
        finally:
            self._summary_lock.release()

    def read_summary(self, *, verified_prefix_only=False) -> dict[str, Any]:
        return self._read_verified(verified_prefix_only=verified_prefix_only)

    def read_verified(self) -> list[dict[str, Any]]:
        """Return isolated rows through the same full-byte verification road."""
        return self._read_verified(include_rows=True)

    def _read_verified(self, *, verified_prefix_only=False, include_rows=False):
        """Validate all current bytes; reuse parsing only for a matching prefix.

        The prefix hash is recomputed from the open file on EVERY read. This
        is not a stat-only/tail cache and does not discard or trust history.
        Cold reads still validate the complete chain. No admission is granted.
        """
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                    info.st_uid, info.st_gid, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns)

        def hash_bytes(fd, count):
            result = hashlib.sha256()
            while count:
                block = os.read(fd, min(count, 1024 * 1024))
                if not block:
                    raise RebootVitalityError("VITALITY_CHRONOLOGY_CHANGED_DURING_READ")
                result.update(block)
                count -= len(block)
            return result.hexdigest()

        with self._summary_access(verified_prefix_only):
            try:
                fd, directories = self._open(writing=False)
            except FileNotFoundError:
                self._summary_cache = None
                self._summary_failure = None
                return [] if include_rows else {"event_count": 0, "latest_event": None}
            reused_failure = False
            try:
                initial = identity(os.fstat(fd))
                size = initial[6]
                failed = self._summary_failure
                if failed is not None and size == failed[0]:
                    if hash_bytes(fd, size) == failed[1]:
                        if identity(os.fstat(fd)) != initial:
                            raise RebootVitalityError("VITALITY_CHRONOLOGY_CHANGED_DURING_READ")
                        self._check_names(fd, directories)
                        reused_failure = True
                        raise RebootVitalityError(failed[2])
                    os.lseek(fd, 0, os.SEEK_SET)
                self._summary_failure = None
                cached = self._summary_cache
                prefix = None
                complete_digest = hashlib.sha256()
                if cached is not None and size >= cached[0]:
                    prefix_digest = hashlib.sha256()
                    prefix_bytes = cached[0]
                    while prefix_bytes:
                        block = os.read(fd, min(prefix_bytes, 1024 * 1024))
                        if not block:
                            raise RebootVitalityError("VITALITY_CHRONOLOGY_CHANGED_DURING_READ")
                        prefix_digest.update(block)
                        prefix_bytes -= len(block)
                    if prefix_digest.hexdigest() == cached[1]:
                        complete_digest = prefix_digest.copy(); prefix = cached[2]
                if prefix is None:
                    if verified_prefix_only:
                        # A changed/shrunk prefix or changed rejected content
                        # needs cold validation too. Report no history claim;
                        # the bounded presentation worker performs the same
                        # full reader after flushing unavailable evidence.
                        raise RebootVitalityError("VITALITY_CHRONOLOGY_NOT_YET_VERIFIED")
                    os.lseek(fd, 0, os.SEEK_SET)
                    complete_digest = hashlib.sha256()
                rows = self._read_locked(fd, prefix, complete_digest)
                # Bind the new cache to the exact complete current bytes, not
                # to a producer claim or filesystem timestamps alone.
                complete_hash = complete_digest.hexdigest()
                if identity(os.fstat(fd)) != initial:
                    raise RebootVitalityError("VITALITY_CHRONOLOGY_CHANGED_DURING_READ")
                self._check_names(fd, directories)
                self._summary_cache = (size, complete_hash, rows)
                if include_rows:
                    # Copy while holding the reader lock: callers may not
                    # mutate the parsed prefix that later byte checks reuse.
                    return json.loads(canonical(rows))
                return {"event_count": len(rows),
                        "latest_event": copy.deepcopy(rows[-1]) if rows else None}
            except BaseException as error:
                self._summary_cache = None
                self._summary_failure = None
                # Invalid history must not turn the recovery page into repeated
                # full JSON/chain scans. Reuse only a stable CONTENT rejection,
                # never a lock, I/O, race or custody failure, and rehash all its
                # bytes on every later attempt before reusing that verdict.
                content_errors = {
                    "VITALITY_CHRONOLOGY_CHAIN_DENIED", "VITALITY_CHRONOLOGY_INPUT_DENIED",
                    "VITALITY_CHRONOLOGY_INCOMPLETE_RECORD", "VITALITY_CHRONOLOGY_DUPLICATE_DENIED",
                    "VITALITY_CHRONOLOGY_SHAPE_DENIED", "VITALITY_JSON_DUPLICATE_KEY_DENIED",
                    "VITALITY_JSON_VALUE_DENIED",
                }
                invalid_content = isinstance(error, RebootVitalityError) and (
                    reused_failure or str(error) in content_errors or
                    str(error) == "VITALITY_CHRONOLOGY_READ_DENIED" and
                    isinstance(error.__cause__, (UnicodeError, json.JSONDecodeError)))
                if invalid_content:
                    os.lseek(fd, 0, os.SEEK_SET)
                    rejected_hash = hash_bytes(fd, size)
                    if identity(os.fstat(fd)) != initial:
                        raise RebootVitalityError("VITALITY_CHRONOLOGY_CHANGED_DURING_READ") from error
                    self._check_names(fd, directories)
                    self._summary_failure = (size, rejected_hash, str(error))
                raise
            finally:
                os.close(fd)
                for directory, _, _ in reversed(directories): os.close(directory)

    def _check_names(self, fd, directories):
        for opened, ancestor, name in directories[1:]:
            actual = os.fstat(opened)
            named = os.stat(name, dir_fd=ancestor, follow_symlinks=False)
            if (actual.st_dev, actual.st_ino, actual.st_mode) != (named.st_dev, named.st_ino, named.st_mode):
                raise RebootVitalityError("VITALITY_CHRONOLOGY_CUSTODY_DENIED")
        actual = os.fstat(fd)
        named = os.stat(self.path.name, dir_fd=directories[-1][0], follow_symlinks=False)
        if actual.st_nlink != 1 or (actual.st_dev, actual.st_ino, actual.st_mode) != (named.st_dev, named.st_ino, named.st_mode):
            raise RebootVitalityError("VITALITY_CHRONOLOGY_CUSTODY_DENIED")

    def _sync_locked(self, fd: int, directories) -> None:
        """Persist bytes and their directory names before acknowledging a record.

        Reuse the file-then-directory flush contract of watchdog/service. Walk
        to the root because a previous failed attempt may have created parents
        without persisting them; mere existence on retry is not durability.
        """
        self._check_names(fd, directories)
        os.fsync(fd)
        for directory, _, _ in reversed(directories):
            os.fsync(directory)
        self._check_names(fd, directories)

    def append(self, event_id: str, event_kind: str, subject: str, observed_at: float, payload: Mapping[str, Any]) -> dict[str, Any]:
        event, _ = self._append(event_id, event_kind, subject, observed_at, payload)
        return event

    def append_with_snapshot(self, event_id: str, event_kind: str, subject: str, observed_at: float, payload: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Return the durable event and full history validated under its write lock."""
        return self._append(event_id, event_kind, subject, observed_at, payload, snapshot=True)

    def append_watchdog(self, event_id: str, observed_at: float, payload: Mapping[str, Any]):
        """Return detached boot/history facts, never the private parsed history."""
        if not isinstance(payload, Mapping) or not BOOT.fullmatch(str(payload.get("boot_id"))):
            raise RebootVitalityError("VITALITY_CHRONOLOGY_INPUT_DENIED")
        return self._append(event_id, "OUTPOST_WATCHDOG", "SEREIN_HOST", observed_at,
                            payload, watchdog_boot=payload["boot_id"])

    def _append(self, event_id, event_kind, subject, observed_at, payload, *,
                snapshot=False, watchdog_boot=None):
        def detached_result(event, rows):
            event = copy.deepcopy(event)
            if snapshot:
                return event, copy.deepcopy(rows)
            if watchdog_boot is None:
                return event, None
            previous, first_post_boot_at = None, observed_at
            for row in reversed(rows):
                if row["event_id"] == event_id:
                    continue
                prior = row["payload"]
                if prior["boot_id"] != watchdog_boot:
                    previous = prior
                    break
                first_post_boot_at = prior["observed_at"]
            return event, {
                "event_count": len(rows), "latest_event": copy.deepcopy(rows[-1]),
                "previous": copy.deepcopy(previous), "first_post_boot_at": first_post_boot_at,
            }

        if not all(_text(v) for v in (event_id, event_kind, subject)) or not _timestamp(observed_at) or not isinstance(payload, Mapping): raise RebootVitalityError("VITALITY_CHRONOLOGY_INPUT_DENIED")
        candidate = json.loads(canonical(dict(payload)))
        if self.path.parent.is_symlink() or any(parent.is_symlink() for parent in self.path.parents):
            raise RebootVitalityError("VITALITY_CHRONOLOGY_CUSTODY_DENIED")
        fd, directories = self._open(writing=True)
        try:
            # Reuse parsing only after rehashing every byte of the retained
            # prefix under the existing exclusive chronology lock. A new
            # process, changed prefix or truncation still validates cold.
            initial = os.fstat(fd)
            cached = self._append_cache
            digest_state = hashlib.sha256()
            prefix = None
            if cached is not None and initial.st_size >= cached[0]:
                remaining_bytes = cached[0]
                while remaining_bytes:
                    block = os.read(fd, min(remaining_bytes, 1024 * 1024))
                    if not block:
                        raise RebootVitalityError("VITALITY_CHRONOLOGY_CHANGED_DURING_READ")
                    digest_state.update(block)
                    remaining_bytes -= len(block)
                if digest_state.hexdigest() == cached[1]:
                    prefix = cached[2]
            if prefix is None:
                os.lseek(fd, 0, os.SEEK_SET)
                digest_state = hashlib.sha256()
            rows = self._read_locked(fd, prefix, digest_state)
            after = os.fstat(fd)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_mode,
                                     info.st_nlink, info.st_uid, info.st_gid,
                                     info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if identity(after) != identity(initial):
                raise RebootVitalityError("VITALITY_CHRONOLOGY_CHANGED_DURING_READ")
            self._check_names(fd, directories)
            prior = next((row for row in rows if row["event_id"] == event_id), None)
            if prior:
                if prior["event_kind"] == event_kind and prior["subject"] == subject and prior["observed_at"] == observed_at and prior["payload"] == candidate:
                    self._sync_locked(fd, directories)
                    self._append_cache = (initial.st_size, digest_state.hexdigest(), rows)
                    return detached_result({**prior, "append_disposition": "IDEMPOTENT_REPLAY"}, rows)
                raise RebootVitalityError("VITALITY_CHRONOLOGY_CONTRADICTION_HOLD")
            body = {"schema": "SereinVitalityChronologyEvent/v1", "sequence": len(rows) + 1, "event_id": event_id, "event_kind": event_kind, "subject": subject, "observed_at": observed_at, "payload": candidate, "previous_hash": rows[-1]["event_hash"] if rows else "GENESIS"}
            record = {**body, "event_hash": _digest(body)}
            encoded = canonical(record)
            remaining = memoryview(encoded)
            self._check_names(fd, directories)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise RebootVitalityError("VITALITY_CHRONOLOGY_WRITE_DENIED")
                remaining = remaining[written:]
            self._sync_locked(fd, directories)
            digest_state.update(encoded)
            rows.append(record)
            # Parsed history remains private. Only callers explicitly requesting
            # a full snapshot pay its copy cost; the watchdog receives detached
            # facts. Every retained byte is still hashed on every append.
            self._append_cache = (initial.st_size + len(encoded), digest_state.hexdigest(), rows)
            result = detached_result({**record, "append_disposition": "APPENDED"}, rows)
        except BaseException:
            self._append_cache = None
            raise
        finally:
            os.close(fd)
            for directory, _, _ in reversed(directories): os.close(directory)
        return result
