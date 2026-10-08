"""Observation-only reboot classification and hash-chained Serein Vitals chronology."""
from __future__ import annotations

import hashlib
import fcntl
import json
import math
import os
import re
import stat
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
    def __init__(self, path: Path): self.path = Path(path)

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
    def _read_locked(fd: int) -> list[dict[str, Any]]:
        previous, seen, rows = "GENESIS", set(), []
        try:
            with os.fdopen(os.dup(fd), "rb") as stream:
                for raw in stream:
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
        event, _ = self.append_with_snapshot(event_id, event_kind, subject, observed_at, payload)
        return event

    def append_with_snapshot(self, event_id: str, event_kind: str, subject: str, observed_at: float, payload: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Return the durable event and full history validated under its write lock."""
        if not all(_text(v) for v in (event_id, event_kind, subject)) or not _timestamp(observed_at) or not isinstance(payload, Mapping): raise RebootVitalityError("VITALITY_CHRONOLOGY_INPUT_DENIED")
        candidate = json.loads(canonical(dict(payload)))
        if self.path.parent.is_symlink() or any(parent.is_symlink() for parent in self.path.parents):
            raise RebootVitalityError("VITALITY_CHRONOLOGY_CUSTODY_DENIED")
        fd, directories = self._open(writing=True)
        try:
            rows = self._read_locked(fd)
            prior = next((row for row in rows if row["event_id"] == event_id), None)
            if prior:
                if prior["event_kind"] == event_kind and prior["subject"] == subject and prior["observed_at"] == observed_at and prior["payload"] == candidate:
                    self._sync_locked(fd, directories)
                    return {**prior, "append_disposition": "IDEMPOTENT_REPLAY"}, rows
                raise RebootVitalityError("VITALITY_CHRONOLOGY_CONTRADICTION_HOLD")
            body = {"schema": "SereinVitalityChronologyEvent/v1", "sequence": len(rows) + 1, "event_id": event_id, "event_kind": event_kind, "subject": subject, "observed_at": observed_at, "payload": candidate, "previous_hash": rows[-1]["event_hash"] if rows else "GENESIS"}
            record = {**body, "event_hash": _digest(body)}
            remaining = memoryview(canonical(record))
            self._check_names(fd, directories)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise RebootVitalityError("VITALITY_CHRONOLOGY_WRITE_DENIED")
                remaining = remaining[written:]
            self._sync_locked(fd, directories)
        finally:
            os.close(fd)
            for directory, _, _ in reversed(directories): os.close(directory)
        rows.append(record)
        return {**record, "append_disposition": "APPENDED"}, rows
