"""Observation-only reboot classification and hash-chained Serein Vitals chronology."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
INDEPENDENT_WITNESSES = {"OUTPOST_BOOT_ID_CHANGE", "EXTERNAL_OUTAGE_WITNESS"}


class RebootVitalityError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def classify_reboot(observation: Mapping[str, Any], intent: Mapping[str, Any] | None = None) -> dict[str, Any]:
    required = {"schema", "event_id", "subject", "outpost_identity", "previous_boot_id", "new_boot_id", "last_observed_at", "first_post_boot_at", "observed_at", "witness_mode", "post_boot", "evidence_ref", "evidence_digest", "policy_version"}
    if not isinstance(observation, Mapping) or set(observation) != required or observation.get("schema") != "SereinOutpostRebootObservation/v1":
        raise RebootVitalityError("REBOOT_OBSERVATION_SHAPE_DENIED")
    if not all(_text(observation.get(key)) for key in ("event_id", "subject", "outpost_identity", "witness_mode", "evidence_ref", "policy_version")):
        raise RebootVitalityError("REBOOT_OBSERVATION_IDENTITY_DENIED")
    if any(not BOOT.fullmatch(str(observation.get(key))) for key in ("previous_boot_id", "new_boot_id")):
        raise RebootVitalityError("REBOOT_BOOT_ID_DENIED")
    if any(not isinstance(observation.get(key), (int, float)) for key in ("last_observed_at", "first_post_boot_at", "observed_at")):
        raise RebootVitalityError("REBOOT_TIME_DENIED")
    if not observation["last_observed_at"] <= observation["first_post_boot_at"] <= observation["observed_at"]:
        raise RebootVitalityError("REBOOT_TIME_ORDER_DENIED")
    post = observation["post_boot"]
    if not isinstance(post, Mapping) or set(post) != {"readiness", "failed_components", "trust_changes", "capability_changes"}:
        raise RebootVitalityError("REBOOT_RECOVERY_SHAPE_DENIED")
    if post["readiness"] not in {"VERIFIED", "DEGRADED", "UNKNOWN"} or any(not isinstance(post[k], list) for k in ("failed_components", "trust_changes", "capability_changes")):
        raise RebootVitalityError("REBOOT_RECOVERY_VALUE_DENIED")
    body = {k: v for k, v in observation.items() if k != "evidence_digest"}
    if not HEX64.fullmatch(str(observation["evidence_digest"])) or observation["evidence_digest"] != _digest(body):
        raise RebootVitalityError("REBOOT_EVIDENCE_DIGEST_DENIED")
    changed = observation["previous_boot_id"] != observation["new_boot_id"]
    cause, match, intent_id = "REBOOT_CAUSE_UNKNOWN", "NONE", None
    if changed and intent is not None:
        expected = {"schema", "intent_id", "subject", "actor", "requested_at", "not_before", "not_after", "action", "authorization_ref", "completion_evidence_ref", "consumed"}
        if not isinstance(intent, Mapping) or set(intent) != expected or intent.get("schema") != "SereinAuthorizedPowerIntent/v1":
            match = "CONTRADICTORY"
        else:
            intent_id = intent.get("intent_id")
            exact = all(_text(intent.get(k)) for k in ("intent_id", "subject", "actor", "action", "authorization_ref")) and intent["action"] in {"REBOOT", "SHUTDOWN_THEN_BOOT"} and all(isinstance(intent[k], (int, float)) for k in ("requested_at", "not_before", "not_after")) and intent["not_before"] <= observation["first_post_boot_at"] <= intent["not_after"] and intent["subject"] == observation["subject"] and intent["consumed"] is False and (intent["action"] != "SHUTDOWN_THEN_BOOT" or _text(intent["completion_evidence_ref"]))
            cause, match = ("EXPECTED_REBOOT", "EXACT") if exact else (cause, "STALE_MISMATCHED_OR_INCOMPLETE")
    elif changed and observation["witness_mode"] in INDEPENDENT_WITNESSES:
        cause = "UNEXPECTED_REBOOT"
    elif not changed:
        match = "NOT_APPLICABLE"
    recovery = {"VERIFIED": "BOOT_RECOVERY_VERIFIED", "DEGRADED": "BOOT_RECOVERY_DEGRADED", "UNKNOWN": "BOOT_RECOVERY_UNKNOWN"}[post["readiness"]]
    alert = changed and (cause in {"UNEXPECTED_REBOOT", "REBOOT_CAUSE_UNKNOWN"} or recovery == "BOOT_RECOVERY_DEGRADED")
    result = {"schema": "SereinOutpostRebootClassification/v1", "event_id": observation["event_id"], "subject": observation["subject"], "outpost_identity": observation["outpost_identity"], "previous_boot_id": observation["previous_boot_id"], "new_boot_id": observation["new_boot_id"], "boot_changed": changed, "cause": cause, "recovery": recovery, "intent_id": intent_id, "intent_match": match, "witness_mode": observation["witness_mode"], "last_observed_at": observation["last_observed_at"], "first_post_boot_at": observation["first_post_boot_at"], "observed_at": observation["observed_at"], "post_boot": dict(post), "evidence_ref": observation["evidence_ref"], "evidence_digest": observation["evidence_digest"], "policy_version": observation["policy_version"], "alert_required": alert, "authority_effect": "NONE", "mutation_effect": "NONE", "recommended_action": "SEPARATELY_GOVERNED_RECOVERY_REVIEW" if alert else "NONE"}
    return {**result, "classification_digest": _digest(result)}


class VitalityChronology:
    def __init__(self, path: Path): self.path = Path(path)

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists(): return []
        if self.path.is_symlink() or not self.path.is_file(): raise RebootVitalityError("VITALITY_CHRONOLOGY_CUSTODY_DENIED")
        previous, seen, rows = "GENESIS", set(), []
        try:
            for raw in self.path.read_bytes().splitlines():
                record = json.loads(raw); body = {k: v for k, v in record.items() if k != "event_hash"}
                if set(record) != {"schema", "sequence", "event_id", "event_kind", "subject", "observed_at", "payload", "previous_hash", "event_hash"} or record["schema"] != "SereinVitalityChronologyEvent/v1" or record["sequence"] != len(rows) + 1 or record["previous_hash"] != previous or record["event_hash"] != _digest(body):
                    raise RebootVitalityError("VITALITY_CHRONOLOGY_CHAIN_DENIED")
                if record["event_id"] in seen: raise RebootVitalityError("VITALITY_CHRONOLOGY_DUPLICATE_DENIED")
                seen.add(record["event_id"]); rows.append(record); previous = record["event_hash"]
        except (OSError, json.JSONDecodeError) as exc:
            raise RebootVitalityError("VITALITY_CHRONOLOGY_READ_DENIED") from exc
        return rows

    def append(self, event_id: str, event_kind: str, subject: str, observed_at: float, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not all(_text(v) for v in (event_id, event_kind, subject)) or not isinstance(observed_at, (int, float)) or not isinstance(payload, Mapping): raise RebootVitalityError("VITALITY_CHRONOLOGY_INPUT_DENIED")
        rows = self.read(); prior = next((row for row in rows if row["event_id"] == event_id), None); candidate = dict(payload)
        if prior:
            if prior["event_kind"] == event_kind and prior["subject"] == subject and prior["observed_at"] == observed_at and prior["payload"] == candidate: return {**prior, "append_disposition": "IDEMPOTENT_REPLAY"}
            raise RebootVitalityError("VITALITY_CHRONOLOGY_CONTRADICTION_HOLD")
        body = {"schema": "SereinVitalityChronologyEvent/v1", "sequence": len(rows) + 1, "event_id": event_id, "event_kind": event_kind, "subject": subject, "observed_at": observed_at, "payload": candidate, "previous_hash": rows[-1]["event_hash"] if rows else "GENESIS"}
        record = {**body, "event_hash": _digest(body)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink(): raise RebootVitalityError("VITALITY_CHRONOLOGY_CUSTODY_DENIED")
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try: os.write(fd, canonical(record)); os.fsync(fd)
        finally: os.close(fd)
        return {**record, "append_disposition": "APPENDED"}
