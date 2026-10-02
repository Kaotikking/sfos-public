"""Outpost watchdog and current/previous-boot witness; no domain authority."""
from __future__ import annotations

import json
import os
import socket
import tempfile
import time
from pathlib import Path
from typing import Any

from .constitutional_registry import registry_snapshot
from .host_vitality import BOOT, JOINED_SCHEMA, RECIPE_SCHEMA, HostVitalityStore, HostCollectionAttempts, host_attempt_matches, digest
from .reboot_vitality import VitalityChronology, classify_reboot
from .vitals_aggregation import producer_observation


STATE_ROOT = Path("/var/lib/serein-outpost/watchdog")
HOST_ROOT = Path("/var/lib/serein-outpost/host-vitality")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


class WatchdogError(ValueError):
    pass


def _write_atomic(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise WatchdogError("WATCHDOG_CUSTODY_DENIED")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".watchdog-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def witness_once(*, state_root: Path = STATE_ROOT, host_root: Path = HOST_ROOT, boot_id_path: Path = BOOT_ID_PATH, observed_at: float | None = None) -> dict[str, Any]:
    now = time.time() if observed_at is None else observed_at
    try:
        boot_id = boot_id_path.read_text(encoding="ascii").strip()
        if not BOOT.fullmatch(boot_id):
            raise WatchdogError("WATCHDOG_SOURCE_UNAVAILABLE")
        registry = registry_snapshot(boot_id=boot_id, observed_at=now)
    except (OSError, UnicodeError, ValueError) as error:
        raise WatchdogError("WATCHDOG_SOURCE_UNAVAILABLE") from error
    try:
        host = HostVitalityStore(host_root).snapshot()
    except (OSError, UnicodeError, ValueError, TypeError):
        host = {"status": "NO_OBSERVATION"}
    try:
        current = host_attempt_matches(host, HostCollectionAttempts(host_root).latest(), boot_id, now)
    except (OSError, ValueError, TypeError):
        current = False
    healthy = current and host.get("latest", {}).get("schema") in {JOINED_SCHEMA, RECIPE_SCHEMA} and host.get("classification") in {"FIRST_BOOT_OBSERVED", "CURRENT_BOOT_STABLE", "RECOVERED_AFTER_BOOT_CHANGE"}
    state = {
        "schema": "SereinOutpostWatchdogWitness/v1",
        "boot_id": boot_id,
        "previous_boot_id": host.get("previous_boot_id"),
        "observed_at": now,
        "host_witness": "CURRENT" if current else "STALE_OR_UNAVAILABLE",
        "registry_state": registry["registry_state"],
        "watchdog_state": "CURRENT_BOOT_WITNESS" if healthy else "DEGRADED",
        "authority_effect": "NONE",
        "admission_effect": "NONE",
        "mutation_effect": "NONE",
    }
    state_root = Path(state_root)
    producer_root = state_root.parent / "vitals-producers"
    chronology = VitalityChronology(state_root / "chronology.jsonl")
    try:
        prior_rows = chronology.read()
        previous, first_post_boot_at = None, now
        for row in reversed(prior_rows):
            prior = row["payload"]
            if prior["boot_id"] != boot_id:
                previous = prior
                break
            first_post_boot_at = prior["observed_at"]
        if previous and current:
            latest = host["latest"]
            # Observe the changed boot; this does not request a power action or
            # infer an Operator intent. Scope is the Host gate, not Stage 1.
            observation = {
                "schema": "SereinOutpostRebootObservation/v1",
                "event_id": "watchdog-boot:" + previous["boot_id"] + ":" + boot_id,
                "subject": "SEREIN_HOST", "outpost_identity": "OUTPOST/SEREIN_HOST",
                "previous_boot_id": previous["boot_id"], "new_boot_id": boot_id,
                "last_observed_at": previous["observed_at"], "first_post_boot_at": first_post_boot_at, "observed_at": now,
                "witness_mode": "POST_BOOT_INFERRED_REBOOT",
                # Host recovery alone does not prove Outpost startup, its edge,
                # or the complete installation recovery set.
                "post_boot": {"readiness": "UNKNOWN" if healthy else "DEGRADED", "failed_components": [] if healthy else ["HOST_GATE"], "trust_changes": [], "capability_changes": []},
                "evidence_ref": "host-vitality:" + host["projection_digest"],
                "policy_version": latest["public_base"]["manifest_sha256" if latest["schema"] == RECIPE_SCHEMA else "policy_sha256"],
            }
            recovery = classify_reboot({**observation, "evidence_digest": digest(observation)})
            _write_atomic(state_root.parent / "recovery" / "current.json", recovery)
        event = chronology.append("watchdog:" + digest(state), "OUTPOST_WATCHDOG", "SEREIN_HOST", now, state)
        # append() has validated the full chain and durably committed this
        # exact event under its exclusive lock. A later read may observe a
        # different writer's event; never attribute that event to this sample.
        checkpoint = {key: value for key, value in event.items()
                      if key != "append_disposition"}
        history_claim = "CHRONOLOGY_OBSERVED"
        history_payload = {"event_count": checkpoint["sequence"], "latest_event": checkpoint}
        history_ref = "chronology:" + event["event_hash"]
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        state["watchdog_state"] = "DEGRADED"
        history_claim = "CHRONOLOGY_UNAVAILABLE"
        history_payload = {"status": "UNAVAILABLE"}
        history_ref = "outpost-reader:watchdog-chronology"
    _write_atomic(state_root / "current.json", state)
    _write_atomic(producer_root / "outpost-watchdog.json", producer_observation(
        perspective="outpost", producer="OUTPOST_WATCHDOG", claim=state["watchdog_state"],
        observed_at=now, boot_id=boot_id, evidence_ref="watchdog:" + digest(state), payload=state,
    ))
    _write_atomic(producer_root / "outpost-chronology.json", producer_observation(
        perspective="outpost", producer="OUTPOST_VITALITY_CHRONOLOGY", claim=history_claim,
        observed_at=now, boot_id=boot_id, evidence_ref=history_ref, payload=history_payload,
    ))
    return state


def _notify(message: str) -> None:
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        client.connect(address)
        client.sendall(message.encode("utf-8"))


def serve() -> None:
    first = witness_once()
    _notify("READY=1\nSTATUS=" + first["watchdog_state"])
    interval = 5.0
    while True:
        state = witness_once()
        _notify("WATCHDOG=1\nSTATUS=" + state["watchdog_state"])
        time.sleep(interval)


if __name__ == "__main__":
    serve()
