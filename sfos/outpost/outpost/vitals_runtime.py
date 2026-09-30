"""Aggregate Outpost-owned, read-only Serein Vitals evidence."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .constitutional_registry import registry_snapshot
from .host_vitality import BOOT, JOINED_SCHEMA, RECIPE_SCHEMA, HostVitalityStore, HostCollectionAttempts, host_attempt_matches
from .reboot_vitality import VitalityChronology, validate_classification
from .vitals_aggregation import aggregate_vitals, producer_observation, validate_producer
from .service import validate_coordinator_witness, held_domain_boot_view


class VitalsRuntimeError(ValueError):
    pass

MAX_SOURCE_BYTES = 2 * 1024 * 1024


class VitalsRuntimeStore:
    def __init__(self, host_root: Path, producer_root: Path, domain_state_path: Path, recovery_path: Path, *, expected_subject: str = "SEREIN_HOST", expected_outpost_identity: str = "OUTPOST/SEREIN_HOST"):
        if not all(isinstance(value, str) and value for value in (expected_subject, expected_outpost_identity)):
            raise VitalsRuntimeError("VITALS_TARGET_IDENTITY_DENIED")
        self.expected_subject = expected_subject
        self.expected_outpost_identity = expected_outpost_identity
        self.host = HostVitalityStore(host_root)
        self.host_attempts = HostCollectionAttempts(host_root)
        self.producer_root = Path(producer_root)
        self.coordinator_path = self.producer_root.parent / "coordinator/current.json"
        self.domain_state_path = Path(domain_state_path)
        self.recovery_path = Path(recovery_path)

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise VitalsRuntimeError("VITALS_SOURCE_CUSTODY_DENIED")
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_SOURCE_BYTES + 1)
            if len(raw) > MAX_SOURCE_BYTES:
                raise VitalsRuntimeError("VITALS_SOURCE_SIZE_DENIED")
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise VitalsRuntimeError("VITALS_SOURCE_READ_DENIED") from error
        if not isinstance(value, dict):
            raise VitalsRuntimeError("VITALS_SOURCE_SHAPE_DENIED")
        return value

    @staticmethod
    def _unavailable(perspective: str, producer: str, claim: str, boot_id: str, now: float) -> dict[str, Any]:
        # This is the reader's failure evidence, never a substitute subject PASS.
        return producer_observation(
            perspective=perspective, producer=producer, claim=claim,
            observed_at=now, boot_id=boot_id, evidence_ref="outpost-reader:" + producer,
            payload={"status": "UNAVAILABLE"},
        )

    def _producers(self, boot_id: str, now: float) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        if self.producer_root.is_symlink() or (self.producer_root.exists() and not self.producer_root.is_dir()):
            raise VitalsRuntimeError("VITALS_PRODUCER_ROOT_DENIED")
        bindings = {
            "outpost-watchdog.json": "OUTPOST_WATCHDOG",
            "outpost-chronology.json": "OUTPOST_VITALITY_CHRONOLOGY",
        }
        for filename in bindings:
            path = self.producer_root / filename
            try:
                value = validate_producer(self._read_json(path))
                # Only the two producers implemented by this generation may
                # enter this directory. Host/registry/recovery identities are
                # constructed from their native readers, never supplied here.
                if value["producer"] != bindings.get(path.name) or value["perspective"] != "outpost":
                    raise VitalsRuntimeError("VITALS_PRODUCER_BINDING_DENIED")
                watchdog_root = self.producer_root.parent / "watchdog"
                if watchdog_root.is_symlink():
                    raise VitalsRuntimeError("VITALS_SOURCE_CUSTODY_DENIED")
                if path.name == "outpost-watchdog.json":
                    native = self._read_json(watchdog_root / "current.json")
                    required = {"schema", "boot_id", "previous_boot_id", "observed_at", "host_witness", "registry_state", "watchdog_state", "authority_effect", "admission_effect", "mutation_effect"}
                    if (set(native) != required or native["schema"] != "SereinOutpostWatchdogWitness/v1"
                            or native["boot_id"] != value["boot_id"] or native["observed_at"] != value["observed_at"]
                            or native["watchdog_state"] not in {"CURRENT_BOOT_WITNESS", "DEGRADED"}
                            or native["host_witness"] not in {"CURRENT", "STALE_OR_UNAVAILABLE"}
                            or native["registry_state"] != "HOLD_INTENTIONAL"
                            or any(native[key] != "NONE" for key in ("authority_effect", "admission_effect", "mutation_effect"))
                            or value["payload"] != native or value["claim"] != native["watchdog_state"]):
                        raise VitalsRuntimeError("VITALS_NATIVE_WITNESS_DENIED")
                elif value["claim"] == "CHRONOLOGY_OBSERVED":
                    rows = VitalityChronology(watchdog_root / "chronology.jsonl").read()
                    # The writer durably appends before publishing its producer
                    # checkpoint. A valid append can therefore occur between
                    # these reads. Bind the original checkpoint to the fully
                    # verified chain, never relabel it as the current tail.
                    count = value["payload"].get("event_count")
                    if type(count) is not int or not 1 <= count <= len(rows):
                        raise VitalsRuntimeError("VITALS_NATIVE_WITNESS_DENIED")
                    checkpoint = rows[count - 1]
                    if (value["payload"] != {"event_count": count, "latest_event": checkpoint}
                            or value["evidence_ref"] != "chronology:" + checkpoint["event_hash"]
                            or checkpoint["event_kind"] != "OUTPOST_WATCHDOG"
                            or checkpoint["subject"] != self.expected_subject
                            or value["boot_id"] != checkpoint["payload"].get("boot_id")
                            or value["observed_at"] != checkpoint["observed_at"]
                            or value["observed_at"] != checkpoint["payload"].get("observed_at")):
                        raise VitalsRuntimeError("VITALS_NATIVE_WITNESS_DENIED")
                elif value["claim"] != "CHRONOLOGY_UNAVAILABLE" or value["payload"] != {"status": "UNAVAILABLE"}:
                    raise VitalsRuntimeError("VITALS_NATIVE_WITNESS_DENIED")
            except (OSError, ValueError, TypeError):
                value = self._unavailable("outpost", bindings[filename], "PRODUCER_EVIDENCE_UNAVAILABLE", boot_id, now)
            result.setdefault(value["perspective"], []).append(value)
        return result

    def snapshot(self, *, current_boot_id: str | None = None) -> dict[str, Any]:
        try:
            host = self.host.snapshot()
        except (OSError, ValueError, TypeError):
            host = {"status": "NO_OBSERVATION"}
        # Production presentation supplies the independently read current boot;
        # a historical Host record cannot make its old boot current again.
        boot_id = current_boot_id if current_boot_id is not None else host.get("current_boot_id")
        latest = host.get("latest")
        if not isinstance(boot_id, str) or not BOOT.fullmatch(boot_id):
            raise VitalsRuntimeError("VITALS_HOST_IDENTITY_DENIED")
        now = time.time()
        try:
            sources = self._producers(boot_id, now)
        except (OSError, ValueError, TypeError):
            sources = {"outpost": [self._unavailable("outpost", "OUTPOST_PRODUCER_READER", "PRODUCER_EVIDENCE_UNAVAILABLE", boot_id, now)]}
        attempt = None
        attempt_error = False
        try:
            attempt = self.host_attempts.latest()
        except (OSError, ValueError, TypeError):
            attempt_error = True
        terminal = attempt.get("terminal") if attempt else None
        start = attempt.get("start") if attempt else None
        current_attempt = (start is not None and start["payload"]["boot_id"] == boot_id
                           and start["observed_at"] <= now)
        completed = host_attempt_matches(host, attempt, boot_id, now)
        if isinstance(latest, dict) and completed:
            sources.setdefault("host", []).append(producer_observation(
                perspective="host", producer="OUTPOST_HOST_WITNESS",
                claim=str(host.get("classification", "UNKNOWN")) if latest.get("schema") in {JOINED_SCHEMA, RECIPE_SCHEMA} else "HISTORICAL_HOST_OBSERVATION", observed_at=float(latest.get("observed_at", 0)),
                boot_id=latest["boot_id"], evidence_ref="host-vitality:" + str(host.get("projection_digest", "UNKNOWN")),
                payload=host,
            ))
        else:
            claim = "HOST_WITNESS_UNAVAILABLE"
            if attempt_error:
                claim = "HOST_ATTEMPT_EVIDENCE_UNAVAILABLE"
            elif current_attempt:
                claim = "HOST_COLLECTION_INCOMPLETE" if terminal is None else "HOST_COLLECTION_FAILED" if terminal["event_kind"] == "HOST_COLLECTION_FAILED" else "HOST_ATTEMPT_RESULT_UNBOUND"
            # Historical success remains evidence, but cannot stand in for the
            # latest unfinished/failed attempt or unavailable attempt history.
            sources.setdefault("host", []).append(producer_observation(
                perspective="host", producer="OUTPOST_HOST_WITNESS", claim=claim,
                observed_at=now, boot_id=boot_id, evidence_ref="outpost-reader:host-collection-attempts",
                payload={"status":"UNAVAILABLE", "collection_attempt":attempt,
                         "last_successful_observation":host if isinstance(latest, dict) else None},
            ))
        registry = registry_snapshot(boot_id=boot_id, observed_at=now)
        sources.setdefault("outpost", []).append(producer_observation(
            perspective="outpost", producer="OUTPOST_CONSTITUTIONAL_REGISTRY",
            claim=str(registry["registry_state"]), observed_at=now, boot_id=boot_id,
            evidence_ref="registry:" + registry["registry_digest"], payload=registry,
        ))
        try:
            coordinator=validate_coordinator_witness(self._read_json(self.coordinator_path),boot_id=boot_id,observed_at=now)
            if (coordinator["host_gate"] != ("CURRENT_BOOT_OBSERVED" if completed else "HOST_GATE_UNAVAILABLE")
                    or coordinator["previous_boot_id"] != host.get("previous_boot_id")):
                raise VitalsRuntimeError("VITALS_COORDINATOR_BINDING_DENIED")
            sources.setdefault("domains", []).append(producer_observation(
                perspective="domains",producer="OUTPOST_DOMAIN_COORDINATOR",
                claim=coordinator["downstream_activation"],observed_at=coordinator["observed_at"],
                boot_id=boot_id,evidence_ref="outpost-native:coordinator/current.json",
                payload={"coordinator":coordinator,"registry":registry,
                         "boot_verification":held_domain_boot_view(boot_id=boot_id,observed_at=now)},
            ))
        except (OSError,ValueError,TypeError):
            sources.setdefault("domains", []).append(self._unavailable("domains","OUTPOST_DOMAIN_COORDINATOR","DOMAIN_STATE_UNAVAILABLE",boot_id,now))
        if self.domain_state_path.exists():
            # No native admitted domain-state validator is installed in this
            # Outpost-only candidate. A file/dict cannot stand in for one.
            observation = self._unavailable("domains", "OUTPOST_DOMAIN_INSTALLER", "DOMAIN_STATE_UNAVAILABLE", boot_id, now)
            sources.setdefault("domains", []).append(observation)
        if self.recovery_path.exists():
            try:
                recovery = validate_classification(self._read_json(self.recovery_path))
                if recovery["subject"] != self.expected_subject or recovery["outpost_identity"] != self.expected_outpost_identity:
                    raise VitalsRuntimeError("VITALS_RECOVERY_TARGET_DENIED")
                observation = producer_observation(
                    perspective="recovery", producer="OUTPOST_RECOVERY_WITNESS",
                    claim=str(recovery.get("recovery", "UNKNOWN")), observed_at=float(recovery.get("observed_at", now)),
                    boot_id=str(recovery.get("new_boot_id", "UNKNOWN")), evidence_ref="recovery:" + str(recovery.get("classification_digest", "UNKNOWN")),
                    payload=recovery,
                )
            except (OSError, ValueError, TypeError):
                observation = self._unavailable("recovery", "OUTPOST_RECOVERY_WITNESS", "RECOVERY_EVIDENCE_UNAVAILABLE", boot_id, now)
            sources.setdefault("recovery", []).append(observation)
        return aggregate_vitals(sources, current_boot_id=boot_id, generated_at=now)
