"""Aggregate Outpost-owned, read-only Serein Vitals evidence."""
from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from .constitutional_registry import registry_snapshot
from .host_vitality import BOOT, JOINED_SCHEMA, RECIPE_SCHEMA, HostVitalityStore, HostVitalityError, HostCollectionAttempts, host_attempt_matches
from .reboot_vitality import VitalityChronology, validate_classification
from .vitals_aggregation import PERSPECTIVES, aggregate_vitals, producer_observation, validate_producer
from .service import validate_coordinator_witness, held_domain_boot_view, _validate_generation_identity
from install.transaction import strict_json, TransactionError, canonical


class VitalsRuntimeError(ValueError):
    pass

MAX_SOURCE_BYTES = 2 * 1024 * 1024

GENERATION_ROOT = Path("/usr/share/serein/outpost-generations")


def _evidence_bytes(path, *, custody=None):
    """Bound one read to open directory/file identities; never repair custody."""
    path = Path(path).absolute()
    if ".." in path.parts:
        raise VitalsRuntimeError("VITALS_SOURCE_CUSTODY_DENIED")
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_uid, info.st_gid, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    with ExitStack() as opened:
        def acquire(name, flags, parent=None):
            descriptor = os.open(name, flags, dir_fd=parent)
            opened.callback(os.close, descriptor)
            return descriptor
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent = acquire(path.anchor, directory_flags)
        ancestry = []
        for name in path.parts[1:-1]:
            child = acquire(name, directory_flags, parent)
            ancestry.append((parent, name, child))
            parent = child
        leaf = acquire(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, parent)
        initial = os.fstat(leaf)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise VitalsRuntimeError("VITALS_SOURCE_CUSTODY_DENIED")
        if custody is not None and (initial.st_uid, initial.st_gid, stat.S_IMODE(initial.st_mode)) != custody:
            raise VitalsRuntimeError("VITALS_SOURCE_CUSTODY_DENIED")
        if initial.st_size > MAX_SOURCE_BYTES:
            raise VitalsRuntimeError("VITALS_SOURCE_SIZE_DENIED")
        data = bytearray()
        while len(data) <= MAX_SOURCE_BYTES:
            block = os.read(leaf, min(65536, MAX_SOURCE_BYTES + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) > MAX_SOURCE_BYTES:
            raise VitalsRuntimeError("VITALS_SOURCE_SIZE_DENIED")
        final = os.fstat(leaf)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if fingerprint(initial) != fingerprint(final) or fingerprint(final) != fingerprint(named):
            raise VitalsRuntimeError("VITALS_SOURCE_CHANGED_DURING_READ")
        for owner, name, descriptor in ancestry:
            actual = os.fstat(descriptor)
            named = os.stat(name, dir_fd=owner, follow_symlinks=False)
            if (actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_gid) != (
                    named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid):
                raise VitalsRuntimeError("VITALS_SOURCE_CHANGED_DURING_READ")
        return bytes(data)


def _running_generation():
    """Verify the complete public payload, not only this reader's own file.

    No private selector or key is read. This identifies running source bytes;
    it does not select a generation or admit a domain.
    """
    module = Path(__file__).absolute()
    root = module.parent.parent
    try:
        if root.parent != GENERATION_ROOT or not re.fullmatch(r"[0-9a-f]{64}", root.name):
            return None
        manifest_path = root / "release-manifest.json"
        raw = _evidence_bytes(manifest_path, custody=(0, 0, 0o644))
        manifest = strict_json(raw)
        if not isinstance(manifest, dict):
            return None
        body = dict(manifest)
        claimed = body.pop("self_digest", None)
        if claimed != "sha256:" + root.name or hashlib.sha256(canonical(body)).hexdigest() != root.name:
            return None
        payload = body.get("payload")
        if not isinstance(payload, list) or not payload:
            return None
        names = set()
        for row in payload:
            if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
                return None
            name = row["path"]
            if (not isinstance(name, str) or not name or "\\" in name
                    or name.startswith("/") or any(part in {"", ".", ".."} for part in name.split("/"))
                    or name in names or type(row["bytes"]) is not int
                    or not 0 <= row["bytes"] <= MAX_SOURCE_BYTES
                    or not isinstance(row["sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
                return None
            names.add(name)
            content = _evidence_bytes(root / name, custody=(0, 0, 0o644))
            if len(content) != row["bytes"] or hashlib.sha256(content).hexdigest() != row["sha256"]:
                return None
        if module != root / "outpost/vitals_runtime.py" or "outpost/vitals_runtime.py" not in names:
            return None
        if _evidence_bytes(manifest_path, custody=(0, 0, 0o644)) != raw:
            return None
        return root.name
    except (OSError, ValueError, TypeError, TransactionError):
        return None


def validate_kernel_vitals_projection(value, *, generation_identity, boot_id, observed_at):
    """Check bounded supporting/candidate evidence; neither grants admission."""
    projection = validate_producer(value)
    _validate_generation_identity(generation_identity)
    details = projection["payload"]
    hex_fields = {
        "kernel_generation": 64, "source_commit": 40, "source_tree": 40,
        "canonical_manifest_digest": 64, "host_projection_digest": 64,
        "installed_evidence_sha256": 64, "observation_digest": 64,
    }
    constants = {"domain": "KERNEL", "outpost_generation": generation_identity["generation"],
                 "stage1": "NOT_READY", "admission": "UNADMITTED"}
    allowed = set(hex_fields) | set(constants)
    candidate = projection["claim"] == "STAGE1_READY_CANDIDATE"
    if candidate:
        constants.update(stage1="READY_CANDIDATE", independent_validation="REQUIRED")
        allowed = set(hex_fields) | set(constants) | {"predicate_evidence_digests"}
    valid = (projection["producer"] == "OUTPOST_DOMAIN_OBSERVER"
             and projection["perspective"] == "serein"
             and projection["claim"] in {"STAGE1_SUPPORTING_EVIDENCE_AGGREGATED", "STAGE1_READY_CANDIDATE"}
             and projection["boot_id"] == boot_id
             and 0 <= observed_at - projection["observed_at"] <= 30
             and isinstance(details, dict) and set(details) == allowed)
    if valid:
        valid = all(details[key] == expected for key, expected in constants.items())
        valid = valid and all(isinstance(details[key], str) and
                              re.fullmatch("[0-9a-f]{" + str(width) + "}", details[key])
                              for key, width in hex_fields.items())
        valid = valid and projection["evidence_ref"] == "outpost-native:stage1:" + details["observation_digest"]
        if valid and candidate:
            from .kernel_direct_witness import STAGE1_PREDICATES
            predicates = details["predicate_evidence_digests"]
            valid = (isinstance(predicates, dict) and set(predicates) == set(STAGE1_PREDICATES)
                     and all(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value)
                             for value in predicates.values()))
    if not valid:
        raise VitalsRuntimeError("VITALS_KERNEL_PROJECTION_DENIED")
    return projection


class VitalsRuntimeStore:
    def __init__(self, host_root: Path, producer_root: Path, domain_state_path: Path, recovery_path: Path, *, expected_subject: str = "SEREIN_HOST", expected_outpost_identity: str = "OUTPOST/SEREIN_HOST"):
        if not all(isinstance(value, str) and value for value in (expected_subject, expected_outpost_identity)):
            raise VitalsRuntimeError("VITALS_TARGET_IDENTITY_DENIED")
        self.expected_subject = expected_subject
        self.expected_outpost_identity = expected_outpost_identity
        # One full-history acquisition at a time in this shared presentation
        # store. Other page callers receive truthful unavailable evidence;
        # they never wait for it or reuse a prior positive Host verdict.
        self.host = HostVitalityStore(host_root, max_readers=1)
        self.host_attempts = HostCollectionAttempts(host_root)
        self.producer_root = Path(producer_root)
        self.coordinator_path = self.producer_root.parent / "coordinator/current.json"
        self.install_observation_path = self.producer_root.parent / "generation-state/install-observation.json"
        self.domain_state_path = Path(domain_state_path)
        self.recovery_path = Path(recovery_path)
        self.chronology = VitalityChronology(self.producer_root.parent / "watchdog/chronology.jsonl")
        # Only the presentation server enables cold-producer deferral after its
        # startup validation attempt. Other readers retain synchronous proof.
        self.defer_cold_chronology = False
        self._presentation_acquisition = threading.Lock()

    def snapshot_for_presentation(self, *, current_boot_id: str, timeout: float):
        """Bound observer waiting, never verification or an install lifetime.

        A request owns its result. Late results are discarded, not offered to
        subsequent callers. One worker may finish the complete synchronous
        reader; its ownership remains held until that reader actually exits.
        """
        if not isinstance(current_boot_id, str) or not BOOT.fullmatch(current_boot_id):
            raise VitalsRuntimeError("VITALS_HOST_IDENTITY_DENIED")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout < 0:
            raise VitalsRuntimeError("VITALS_READ_BUDGET_DENIED")
        deadline = time.monotonic() + timeout

        def unavailable():
            now = time.time()
            return aggregate_vitals({perspective: [self._unavailable(
                perspective, "OUTPOST_PRESENTATION_READER", "VITALS_EVIDENCE_UNAVAILABLE",
                current_boot_id, now)] for perspective in PERSPECTIVES},
                current_boot_id=current_boot_id, generated_at=now)

        if timeout <= 0 or not self._presentation_acquisition.acquire(blocking=False):
            return unavailable()
        completed = threading.Event()
        result = []
        finished = []

        def acquire():
            try:
                result.append(self.snapshot(current_boot_id=current_boot_id))
            except (OSError, ValueError, TypeError):
                pass  # No partial evidence or prior positive result is reused.
            finally:
                finished.append(time.monotonic())
                self._presentation_acquisition.release()
                completed.set()

        try:
            worker = threading.Thread(target=acquire, name="outpost-presentation-read", daemon=True)
            worker.start()
        except Exception:
            self._presentation_acquisition.release()
            return unavailable()
        if (not completed.wait(max(0.0, deadline - time.monotonic())) or not result
                or finished[0] > deadline):
            return unavailable()
        return result[0]

    def chronology_needs_validation(self):
        # This is not a verdict. A prefix/rejection only selects the normal
        # reader, which still hashes current bytes and validates custody.
        return (self.chronology._summary_cache is None
                and self.chronology._summary_failure is None)

    @staticmethod
    def _read_json(path: Path, *, expected_custody=None) -> dict[str, Any]:
        try:
            value = strict_json(_evidence_bytes(path, custody=expected_custody))
        except (OSError, UnicodeError, TransactionError) as error:
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

    def _producers_once(self, boot_id: str, now: float) -> dict[str, list[dict[str, Any]]]:
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
                    history = self.chronology.read_summary(
                        verified_prefix_only=self.defer_cold_chronology)
                    if not history["event_count"] or value["payload"] != history or value["evidence_ref"] != "chronology:" + history["latest_event"]["event_hash"]:
                        raise VitalsRuntimeError("VITALS_NATIVE_WITNESS_DENIED")
                elif value["claim"] != "CHRONOLOGY_UNAVAILABLE" or value["payload"] != {"status": "UNAVAILABLE"}:
                    raise VitalsRuntimeError("VITALS_NATIVE_WITNESS_DENIED")
            except (OSError, ValueError, TypeError):
                value = self._unavailable("outpost", bindings[filename], "PRODUCER_EVIDENCE_UNAVAILABLE", boot_id, now)
            result.setdefault(value["perspective"], []).append(value)
        return result

    def _producers(self, boot_id: str, now: float) -> dict[str, list[dict[str, Any]]]:
        sample = self._producers_once(boot_id, now)
        if any(row["claim"] == "PRODUCER_EVIDENCE_UNAVAILABLE"
               for rows in sample.values() for row in rows):
            # Reacquire the entire canonical pair once; do not combine old
            # native history with a newer producer projection.
            sample = self._producers_once(boot_id, now)
        return sample

    def _domain_observation(self, *, coordinator, boot_id, host, completed):
        if coordinator is None:
            raise VitalsRuntimeError("VITALS_KERNEL_GENERATION_UNAVAILABLE")
        selected = coordinator["generation_identity"]
        if selected is None or _running_generation() != selected["generation"]:
            raise VitalsRuntimeError("VITALS_KERNEL_GENERATION_UNAVAILABLE")
        evidence = self._read_json(self.domain_state_path, expected_custody=(0, 0, 0o644))
        observed = validate_kernel_vitals_projection(evidence,
            generation_identity=selected, boot_id=boot_id, observed_at=time.time())
        if not completed or observed["payload"]["host_projection_digest"] != host.get("projection_digest"):
            raise VitalsRuntimeError("VITALS_KERNEL_HOST_BINDING_DENIED")
        return observed

    def snapshot(self, *, current_boot_id: str | None = None) -> dict[str, Any]:
        host_read_error = None
        try:
            host = self.host.snapshot()
        except HostVitalityError as error:
            host_read_error = str(error)
            host = {"status": "UNAVAILABLE"}
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
        now = time.time()
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
            claim = ("HOST_HISTORY_BUSY" if host_read_error == "HOST_VITALITY_HISTORY_BUSY" else
                     "HOST_HISTORY_UNVALIDATED" if host_read_error == "HOST_VITALITY_HISTORY_UNVALIDATED" else
                     "HOST_WITNESS_UNAVAILABLE")
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
                         "reader_error":host_read_error,
                         "last_successful_observation":host if isinstance(latest, dict) else None},
            ))
        registry = registry_snapshot(boot_id=boot_id, observed_at=now)
        sources.setdefault("outpost", []).append(producer_observation(
            perspective="outpost", producer="OUTPOST_CONSTITUTIONAL_REGISTRY",
            claim=str(registry["registry_state"]), observed_at=now, boot_id=boot_id,
            evidence_ref="registry:" + registry["registry_digest"], payload=registry,
        ))
        coordinator = None
        try:
            coordinator_sample = self._read_json(self.coordinator_path)
            # The coordinator can atomically publish while earlier producers
            # are being read. Bound it to its actual completed acquisition,
            # not the earlier snapshot timestamp. Future claims still fail;
            # the producer timestamp and Host/boot checks remain unchanged.
            coordinator=validate_coordinator_witness(coordinator_sample,boot_id=boot_id,observed_at=time.time())
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
            coordinator = None
            sources.setdefault("domains", []).append(self._unavailable("domains","OUTPOST_DOMAIN_COORDINATOR","DOMAIN_STATE_UNAVAILABLE",boot_id,now))
        if self.domain_state_path.exists():
            try:
                projected = self._domain_observation(coordinator=coordinator,
                    boot_id=boot_id, host=host, completed=completed)
                sources.setdefault("serein", []).append(projected)
            except (OSError, ValueError, TypeError):
                group, producer, claim = (
                    ("domains", "OUTPOST_DOMAIN_INSTALLER", "DOMAIN_STATE_UNAVAILABLE")
                    if coordinator is None else
                    ("serein", "OUTPOST_DOMAIN_OBSERVER", "STAGE1_OBSERVATION_UNAVAILABLE"))
                sources.setdefault(group, []).append(self._unavailable(group, producer, claim, boot_id, now))
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
        install_failed = False
        if self.install_observation_path.exists():
            install_failed = True  # Corrupt failure evidence cannot admit Stage 1.
            try:
                installed = self._read_json(self.install_observation_path, expected_custody=(0,0,0o644))
                keys = {'schema','boot_id','generation','observed_at','state','failure_code',
                        'last_completed_phase','last_completed_step','authority_effect',
                        'admission_effect','observation_digest'}
                if (set(installed)!=keys or installed['schema']!='SereinOutpostInstallObservation/v1'
                        or installed['state']!='FAILED_INSTALL'
                        or not isinstance(installed['boot_id'],str) or not BOOT.fullmatch(installed['boot_id'])
                        or not isinstance(installed['generation'],str)
                        or not re.fullmatch('[0-9a-f]{64}',installed['generation'])
                        or installed['authority_effect']!='NONE' or installed['admission_effect']!='NONE'
                        or installed['observation_digest']!=hashlib.sha256(canonical(
                            {k:v for k,v in installed.items() if k!='observation_digest'})).hexdigest()
                        or type(installed['last_completed_step']) is not int
                        or any(not isinstance(installed[key],str) or not re.fullmatch('[A-Z_]{1,96}',installed[key])
                               for key in ('failure_code','last_completed_phase'))):
                    raise VitalsRuntimeError('VITALS_INSTALL_OBSERVATION_DENIED')
                running_generation = _running_generation()
                if running_generation is None:
                    raise VitalsRuntimeError('VITALS_INSTALL_OBSERVATION_DENIED')
                current_failure = (installed['boot_id']==boot_id
                                   and installed['generation']==running_generation)
                observation = producer_observation(perspective='recovery',producer='OUTPOST_INSTALLER',
                    claim='FAILED_INSTALL' if current_failure else 'HISTORICAL_FAILED_INSTALL',
                    observed_at=installed['observed_at'],boot_id=installed['boot_id'],
                    evidence_ref='outpost-install:'+installed['observation_digest'],payload=installed)
                # Historical failure remains attributable, never deleted or
                # relabelled as the current generation. It grants no admission;
                # normal current coordinator/Kernel checks still run below.
                install_failed = current_failure
            except (OSError,ValueError,TypeError):
                observation = self._unavailable('recovery','OUTPOST_INSTALLER',
                    'INSTALL_OBSERVATION_UNAVAILABLE',boot_id,now)
            sources.setdefault('recovery',[]).append(observation)
        finished = time.time()
        for index, item in enumerate(sources.get("serein", [])):
            if item["claim"] not in {"STAGE1_SUPPORTING_EVIDENCE_AGGREGATED", "STAGE1_READY_CANDIDATE"}:
                continue
            try:
                if install_failed:
                    raise VitalsRuntimeError('VITALS_INSTALL_FAILED_UNADMITTED')
                selected = coordinator["generation_identity"]
                if _running_generation() != selected["generation"]:
                    raise VitalsRuntimeError("VITALS_KERNEL_GENERATION_UNAVAILABLE")
                finished = time.time()
                validate_kernel_vitals_projection(item, generation_identity=selected,
                    boot_id=boot_id, observed_at=finished)
            except (ValueError, TypeError):
                finished = time.time()
                sources["serein"][index] = self._unavailable("serein", "OUTPOST_DOMAIN_OBSERVER",
                    "STAGE1_OBSERVATION_UNAVAILABLE", boot_id, finished)
        return aggregate_vitals(sources, current_boot_id=boot_id, generated_at=finished)
