"""Observation-only Outpost coordinator, adapted from archive191c017.

Extends the existing coordinator witness to v2 with exact selected-generation
identity. This adds no listener, activation, privilege change or downstream
installer. An unbound observer is evidence, never generation acceptance.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from .constitutional_registry import DOMAIN_ORDER, registry_snapshot
from .host_vitality import BOOT, HostVitalityStore, HostCollectionAttempts, host_attempt_matches
from .vitals_aggregation import validate_producer

# Observation grammar from canonical domain_postinstall.py; no installer,
# service-start, rollback or self-admission behavior is imported.
DOMAIN_GATE_ORDER=("LOAD_SEED_CONSTITUTION","VERIFY_DOMAIN_IDENTITY","LOAD_LOCAL_BLUEPRINT_POLICY",
                   "START_PRIVATE_STATE_SERVICES","VERIFY_DEPENDENCIES","EXPOSE_VERSIONED_API",
                   "SELF_TEST_HEALTH","KERNEL_AUTHORITY_CHECK","ADMIT")
BLUEPRINT_ISSUES=dict(zip(DOMAIN_ORDER,("PRO-180","PRO-182","PRO-181","PRO-184","PRO-185",
                                      "PRO-186","PRO-187","PRO-188","PRO-189","PRO-183")))
UNADMITTED_OBSERVATION_STATES={"PENDING","LAGGING","TIMED_OUT","RETRYING","RECOVERY","FAILED","HELD"}


class OutpostServiceError(ValueError):
    pass


def current_generation_identity(*, module_path=None, selector_path=None, generation_root=None):
    """Read the existing selector contract and bind it to this running module.

    An unbound/degraded observer may still publish evidence, but that evidence
    cannot prove generation acceptance. Never select LKG or change custody.
    Constitutional admission remains a separate prerequisite.
    """
    from install.generation_launcher import read_selector, LaunchDenied
    module = Path(__file__) if module_path is None else Path(module_path)
    selector = (Path('/var/lib/serein-outpost/generation-state/current.json')
                if selector_path is None else Path(selector_path))
    root = (Path('/usr/share/serein/outpost-generations')
            if generation_root is None else Path(generation_root))
    try:
        identity, generation = read_selector(selector, root)
        if module.absolute() != generation.absolute() / 'outpost/service.py':
            return None
        _validate_generation_identity(identity)
        return identity
    except (OSError, ValueError, TypeError, KeyError, LaunchDenied, OutpostServiceError):
        return None


def _validate_generation_identity(value):
    from install.generation_launcher import _digest
    required = {'schema', 'generation', 'release_digest', 'predecessor_receipt_sha256',
                'inventory_digest', 'selector_digest'}
    if (not isinstance(value, dict) or set(value) != required
            or value['schema'] != 'SereinOutpostGenerationSelector/v1'
            or any(not isinstance(value[key], str) or not re.fullmatch(r'[0-9a-f]{64}', value[key])
                   for key in ('generation', 'predecessor_receipt_sha256', 'inventory_digest', 'selector_digest'))
            or value['release_digest'] != 'sha256:' + value['generation']
            or value['selector_digest'] != _digest(value)):
        raise OutpostServiceError('OUTPOST_COORDINATOR_GENERATION_DENIED')


def held_domain_boot_view(*,boot_id:str,observed_at:float,observations=()):
    """Every-boot fail-closed projection while PRO-116 material is held.

    Supporting lag/failure observations remain attributable and separate from
    Seed/blueprint verification. This function cannot produce PASS or admit.
    No file producer or service observation road is enabled by this projection.
    """
    registry_snapshot(boot_id=boot_id,observed_at=observed_at)
    current={};historical={}
    for item in observations:
        value=validate_producer(item)
        payload=value["payload"]
        required={"domain","step","state","started_at"}
        if (value["producer"]!="OUTPOST_DOMAIN_OBSERVER" or value["perspective"]!="domains"
                or set(payload)!=required or payload["domain"] not in DOMAIN_ORDER
                or payload["step"] not in DOMAIN_GATE_ORDER
                or payload["state"] not in UNADMITTED_OBSERVATION_STATES
                or value["claim"]!=payload["state"]
                or type(payload["started_at"]) not in (int,float)
                or not math.isfinite(payload["started_at"])
                or not 0<=payload["started_at"]<=value["observed_at"]<=observed_at):
            raise OutpostServiceError("DOMAIN_BOOT_OBSERVATION_DENIED")
        target=current if value["boot_id"]==boot_id else historical
        domain=payload["domain"]
        prior=target.get(domain)
        if prior is not None and prior["observed_at"]==value["observed_at"] and prior!=value:
            raise OutpostServiceError("DOMAIN_BOOT_OBSERVATION_CONFLICT")
        if prior is None or prior["observed_at"]<value["observed_at"]:target[domain]=value
    domains=[]
    for index,domain in enumerate(DOMAIN_ORDER):
        item=current.get(domain)
        domains.append({"domain":domain,"current_boot_id":boot_id,
          "current_gate":DOMAIN_GATE_ORDER[0],"verification":"DENIED_HELD_SEED_CONTENT",
          "seed":{"reference":"PRO-116","state":"HOLD_INTENTIONAL","digest":None},
          "blueprint":{"reference":BLUEPRINT_ISSUES[domain],"state":"UNADMITTED","digest":None},
          "installed_generation":"UNPROVEN","gate_order":list(DOMAIN_GATE_ORDER),
          "dependencies":list(DOMAIN_ORDER[:index]),"downstream_hold":list(DOMAIN_ORDER[index+1:]),
          "observation":item,"observation_elapsed":None if item is None else item["observed_at"]-item["payload"]["started_at"],
          "historical_observation":historical.get(domain),"admission_effect":"NONE"})
    return {"current_boot_id":boot_id,"observed_at":observed_at,
            "earliest_unproven_domain":"KERNEL","earliest_unproven_gate":DOMAIN_GATE_ORDER[0],
            "domains":domains,"authority_effect":"NONE","admission_effect":"NONE","mutation_effect":"NONE"}


def validate_coordinator_witness(value, *, boot_id: str, observed_at: float,
                                 expected_generation=None) -> dict[str, Any]:
    required={"schema","boot_id","previous_boot_id","observed_at","host_gate","registry_state","downstream_activation","authority_effect","admission_effect","mutation_effect","generation_identity"}
    if not isinstance(value,dict) or set(value)!=required or value["schema"]!="SereinOutpostCoordinatorWitness/v2":
        raise OutpostServiceError("OUTPOST_COORDINATOR_SHAPE_DENIED")
    if value['generation_identity'] is not None:
        _validate_generation_identity(value['generation_identity'])
    if expected_generation is not None:
        _validate_generation_identity(expected_generation)
        if value['generation_identity'] != expected_generation:
            raise OutpostServiceError('OUTPOST_COORDINATOR_GENERATION_DENIED')
    if (not isinstance(boot_id,str) or not BOOT.fullmatch(boot_id) or value["boot_id"]!=boot_id
            or type(value["observed_at"]) not in (int,float) or not math.isfinite(value["observed_at"])
            or not 0<=value["observed_at"]<=observed_at
            or (value["previous_boot_id"] is not None and not BOOT.fullmatch(str(value["previous_boot_id"])))):
        raise OutpostServiceError("OUTPOST_COORDINATOR_IDENTITY_DENIED")
    if (value["host_gate"] not in {"CURRENT_BOOT_OBSERVED","HOST_GATE_UNAVAILABLE"}
            or value["registry_state"]!="HOLD_INTENTIONAL"
            or value["downstream_activation"]!="DENIED_HELD_SEED_CONTENT"
            or any(value[key]!="NONE" for key in ("authority_effect","admission_effect","mutation_effect"))):
        raise OutpostServiceError("OUTPOST_COORDINATOR_EFFECT_DENIED")
    return dict(value)


def _atomic(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise OutpostServiceError("OUTPOST_SERVICE_CUSTODY_DENIED")
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,temporary=tempfile.mkstemp(prefix=".outpost-service-",dir=path.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as handle:
            json.dump(value,handle,sort_keys=True,separators=(",",":"),allow_nan=False)
            handle.write("\n");handle.flush();os.fsync(handle.fileno())
        os.replace(temporary,path)
        # File fsync alone does not persist the directory entry installed by
        # rename. Do not return an attributable current witness until both
        # the bytes and the directory update have reached the filesystem.
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def coordinator_witness(*,host_root:Path,state_path:Path,boot_id_path:Path,observed_at:float|None=None)->dict[str,Any]:
    now=time.time() if observed_at is None else observed_at
    if boot_id_path.is_symlink():raise OutpostServiceError("OUTPOST_COORDINATOR_SOURCE_DENIED")
    boot_id=boot_id_path.read_text(encoding="ascii").strip()
    registry=registry_snapshot(boot_id=boot_id,observed_at=now)
    try:
        host=HostVitalityStore(host_root).snapshot()
        current=host_attempt_matches(host,HostCollectionAttempts(host_root).latest(),boot_id,now)
    except (OSError,ValueError,TypeError):
        host={};current=False
    value={"schema":"SereinOutpostCoordinatorWitness/v2","boot_id":boot_id,
           "generation_identity":current_generation_identity(),
           "previous_boot_id":host.get("previous_boot_id"),"observed_at":now,
           "host_gate":"CURRENT_BOOT_OBSERVED" if current else "HOST_GATE_UNAVAILABLE",
           "registry_state":registry["registry_state"],"downstream_activation":"DENIED_HELD_SEED_CONTENT",
           "authority_effect":"NONE","admission_effect":"NONE","mutation_effect":"NONE"}
    validate_coordinator_witness(value,boot_id=boot_id,observed_at=now)
    _atomic(state_path,value)
    return value


def _notify(message: str) -> None:
    """Existing systemd notification road; not a listener or admission."""
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        client.connect(address)
        client.sendall(message.encode("utf-8"))


def run_coordinator(*, host_root: Path, state_path: Path, boot_id_path: Path,
                    stop: threading.Event | None = None) -> None:
    """Publish observation every five seconds using the attributed donor loop.

    READY is service-protocol readiness only; STATUS preserves Host unknown or
    observed state. A failed write/read raises before notification. No domain
    activation, signing, token access or predecessor fallback is performed.
    """
    stop = threading.Event() if stop is None else stop
    while not stop.is_set():
        state = coordinator_witness(host_root=host_root, state_path=state_path,
                                    boot_id_path=boot_id_path)
        _notify("READY=1\nWATCHDOG=1\nSTATUS=" + state["host_gate"])
        stop.wait(5.0)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-vitality-root", required=True)
    args = parser.parse_args(argv)
    run_coordinator(host_root=Path(args.host_vitality_root),
                    state_path=Path("/var/lib/serein-outpost/coordinator/current.json"),
                    boot_id_path=Path("/proc/sys/kernel/random/boot_id"))


if __name__ == "__main__":
    main()
