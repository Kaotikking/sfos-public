"""Outpost's independent Authority-v2 observation; existing private socket only.

A trusted installation binding and public registry are explicit inputs from
the governed installer handoff, never supplied by the responding Kernel.
This initial-admission reader does not grant authority or start any service.
"""
from __future__ import annotations
from datetime import datetime, timezone
import copy
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import stat
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from install.transaction import strict_json, TransactionError
from install.kernel_first_install_runner import regular, current_host_gate, HOST_STATE
from install.public_generation_transaction import CANONICAL_AUTHORITY_SHA256

SOCKET = Path("/run/serein/stage1/kernel-authority-v1.sock")
BOOT = Path("/proc/sys/kernel/random/boot_id")
ANCHOR = Path("/usr/share/serein/outpost/cognition-verification.pem")
PHASE_A_CHECKS = ("implementation-identity", "blueprint-policy-integrity", "frame-identity",
                  "contract-containment", "authority-admission-policy", "unknown-trust-safe-recovery")


class KernelWitnessError(ValueError):
    mode = "SAFE_RECOVERY"
    privileged_execution = False
    branch_advance = False


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def record_bytes(value):
    return canonical(value) + b"\n"


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(value, reason):
    if not value:
        raise KernelWitnessError(reason)


def expected_identity(identity, anchor, source):
    """Independently verify initial registry signatures; never execute Kernel code."""
    try:
        require(hashlib.sha256(anchor).hexdigest() == CANONICAL_AUTHORITY_SHA256,
                "KERNEL_INSTALLER_ANCHOR_DENIED")
        require(isinstance(identity, dict) and set(identity) == {"binding", "registry"},
                "KERNEL_EXPECTED_IDENTITY_DENIED")
        binding, registry = identity["binding"], identity["registry"]
        require(isinstance(binding, dict) and set(binding) == {
            "schema", "instance_id", "checkpoint", "registry_sha256", "private_sha256",
            "public_key", "transaction_context"} and binding["schema"] == "SereinKernelNativeIdentityMaterial/v1",
            "KERNEL_EXPECTED_IDENTITY_DENIED")
        require(isinstance(registry, dict) and set(registry) == {"schema", "records"}
                and registry["schema"] == "SereinDomainIdentityRegistry/v1"
                and hashlib.sha256(record_bytes(registry)).hexdigest() == binding["registry_sha256"],
                "KERNEL_EXPECTED_REGISTRY_DENIED")
        records = registry["records"]
        require(isinstance(records, list) and len(records) == 1
                and hashlib.sha256(record_bytes(records)).hexdigest() == binding["checkpoint"],
                "KERNEL_EXPECTED_CHECKPOINT_DENIED")
        record = records[0]
        require(isinstance(record, dict) and set(record) == {
            "body", "installer_signature", "domain_signature", "prior_key_signature"}
            and record["prior_key_signature"] is None, "KERNEL_EXPECTED_RECORD_DENIED")
        body = record["body"]
        require(re.fullmatch(r"[0-9a-f]{16}", binding["instance_id"])
                and all(re.fullmatch(r"[0-9a-f]{64}", binding[key]) for key in (
                    "checkpoint", "registry_sha256", "private_sha256", "public_key", "transaction_context")),
                "KERNEL_EXPECTED_IDENTITY_DENIED")
        expected = {"schema": "SereinDomainIdentityRecord/v1", "domain": "KERNEL",
                    "instance_id": binding["instance_id"], "operation": "INSTALL", "revision": 0,
                    "prior_record": None, "replaces_instance_id": None, "public_key": binding["public_key"],
                    "key_fingerprint": hashlib.sha256(bytes.fromhex(binding["public_key"])).hexdigest(),
                    "source_commit": source["source_commit"], "governance_receipt": binding["transaction_context"],
                    "authority_effect": "NONE", "admission_effect": "NONE"}
        require(body == expected and type(body["revision"]) is int, "KERNEL_EXPECTED_RECORD_DENIED")
        load_pem_public_key(anchor).verify(bytes.fromhex(record["installer_signature"]), record_bytes(body))
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(body["public_key"])).verify(
            bytes.fromhex(record["domain_signature"]), record_bytes(body))
    except KernelWitnessError:
        raise
    except Exception as exc:
        raise KernelWitnessError("KERNEL_EXPECTED_IDENTITY_CRYPTO_DENIED") from exc
    return body


def validate_authority_response(value, *, request, source, boot_id, observed_at, identity, anchor, host_machine_id):
    required = {"schema", "domain", "branch", "verdict", "issuer", "issued_at", "request_id", "nonce",
                "previous_evidence_digest", "source_commit", "source_tree", "canonical_manifest_digest",
                "boot_id", "facts_digest", "phase_a", "api_health", "uncertainty", "authority_effect",
                "native_identity_proof", "boot_decision", "frame_identity", "evidence_digest"}
    require(isinstance(value, dict) and set(value) == required, "KERNEL_RESPONSE_SHAPE_DENIED")
    require(all(isinstance(value[key], str) for key in required - {"phase_a", "native_identity_proof", "boot_decision", "frame_identity"}),
            "KERNEL_RESPONSE_SHAPE_DENIED")
    body = {key: item for key, item in value.items() if key != "evidence_digest"}
    require(value["schema"] == "SEREIN/KernelBranchDirectWitness/v2" and value["domain"] == "KERNEL"
            and value["branch"] == "AUTHORITY" and value["verdict"] in {"PASS", "FAIL", "UNKNOWN"}
            and value["issuer"] == "KERNEL_AUTHORITY_API" and value["boot_id"] == boot_id
            and value["previous_evidence_digest"] == request["previous_evidence_digest"] == "GENESIS"
            and value["request_id"] == request["request_id"] and value["nonce"] == request["nonce"]
            and all(value[key] == source[key] for key in source)
            and re.fullmatch(r"[0-9a-f]{64}", str(value["facts_digest"]))
            and value["authority_effect"] == "NONE" and value["evidence_digest"] == digest(body),
            "KERNEL_AUTHORITY_RESPONSE_DENIED")
    try:
        frame = value["frame_identity"]
        require(isinstance(host_machine_id, str) and re.fullmatch(r"[0-9a-f]{32}", host_machine_id)
                and host_machine_id != "0"*32 and isinstance(frame, dict)
                and set(frame) == {"machine_id", "boot_id", "host_projection_digest"}
                and frame["machine_id"] == host_machine_id and frame["boot_id"] == boot_id
                and isinstance(frame["host_projection_digest"], str)
                and re.fullmatch(r"[0-9a-f]{64}", frame["host_projection_digest"]),
                "KERNEL_FRAME_IDENTITY_DENIED")
        decision = value["boot_decision"]
        require(decision == {"schema": "SereinAuthorityBootDecision/v1",
                "mode": "PRIVATE_VALIDATION_ONLY", "allowed_effects": ["OBSERVE_AUTHORITY"],
                "privileged_execution": False, "branch_advance": False,
                "authority_effect": "NONE", "admission_effect": "NONE"}
                and decision["privileged_execution"] is False and decision["branch_advance"] is False,
                "KERNEL_BOOT_DECISION_DENIED")
        issued = datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00"))
        require(issued.tzinfo is not None and 0 <= (observed_at-issued).total_seconds() <= 30,
                "KERNEL_AUTHORITY_STALE")
        checks = value["phase_a"]
        require(isinstance(checks, list) and len(checks) == len(PHASE_A_CHECKS)
                and all(isinstance(row, dict) and set(row) == {"name", "verdict"} and row["name"] == name
                        and row["verdict"] in {"PASS", "FAIL", "UNKNOWN"}
                        for row, name in zip(checks, PHASE_A_CHECKS)), "KERNEL_PHASE_A_SHAPE_DENIED")
        complete = value["api_health"] == "READY" and all(row["verdict"] == "PASS" for row in checks)
        verdict = "PASS" if complete else ("FAIL" if any(row["verdict"] == "FAIL" for row in checks) else "UNKNOWN")
        require(value["api_health"] in {"READY", "UNKNOWN", "DENIED"}
                and value["verdict"] == verdict
                and value["uncertainty"] == ("NONE" if complete else "PHASE_A_UNPROVEN"),
                "KERNEL_PHASE_A_VERDICT_DENIED")
        admitted = expected_identity(identity, anchor, source)
        native = value["native_identity_proof"]
        require(isinstance(native, dict) and set(native) == {
            "schema", "instance_id", "checkpoint", "key_fingerprint", "possession_signature"}
            and native["schema"] == "SereinNativeIdentityPossession/v1"
            and native["instance_id"] == admitted["instance_id"]
            and native["checkpoint"] == identity["binding"]["checkpoint"]
            and native["key_fingerprint"] == admitted["key_fingerprint"],
            "KERNEL_POSSESSION_BINDING_DENIED")
        unsigned = {**body, "native_identity_proof": {
            key: item for key, item in native.items() if key != "possession_signature"}}
        challenge = hashlib.sha256(canonical({"request": request, "witness": unsigned})).digest()
        envelope = {"domain": "KERNEL", "instance_id": native["instance_id"],
                    "checkpoint": native["checkpoint"], "challenge": challenge.hex()}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(admitted["public_key"])).verify(
            bytes.fromhex(native["possession_signature"]), record_bytes(envelope))
    except KernelWitnessError:
        raise
    except Exception as exc:
        raise KernelWitnessError("KERNEL_AUTHORITY_PROOF_DENIED") from exc
    return value


def observe_authority(*, source, identity, socket_path=SOCKET, boot_path=BOOT, anchor_path=ANCHOR, host_path=HOST_STATE, request=None):
    source, identity = copy.deepcopy(source), copy.deepcopy(identity)
    require(isinstance(source, dict) and set(source) == {"source_commit", "source_tree", "canonical_manifest_digest"}
            and all(re.fullmatch(r"[0-9a-f]{40}", str(source[key])) for key in ("source_commit", "source_tree"))
            and re.fullmatch(r"[0-9a-f]{64}", str(source["canonical_manifest_digest"])), "KERNEL_EXPECTED_SOURCE_DENIED")
    anchor = regular(Path(anchor_path))
    expected_identity(identity, anchor, source)
    account = pwd.getpwnam("serein-outpost")
    require(os.geteuid() == account.pw_uid, "OUTPOST_OBSERVER_IDENTITY_DENIED")
    path, boot_path = Path(socket_path), Path(boot_path)
    require(not path.is_symlink() and all(not parent.is_symlink() for parent in path.parents), "KERNEL_SOCKET_PATH_DENIED")
    info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            == (account.pw_uid, account.pw_gid, 0o600), "KERNEL_SOCKET_CUSTODY_DENIED")
    boot_id = boot_path.read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id), "KERNEL_BOOT_IDENTITY_DENIED")
    host = current_host_gate(Path(host_path), boot_id)
    host_machine_id = host["latest"]["host"]["machine_id"]
    request = copy.deepcopy(request) if request is not None else {
        "schema": "SEREIN/KernelBranchWitnessRequest/v1", "branch": "AUTHORITY",
        "request_id": "kernel-authority-"+secrets.token_hex(16), "nonce": secrets.token_hex(32),
        "previous_evidence_digest": "GENESIS"}
    require(isinstance(request, dict) and set(request) == {"schema", "branch", "request_id", "nonce", "previous_evidence_digest"}
            and request["schema"] == "SEREIN/KernelBranchWitnessRequest/v1" and request["branch"] == "AUTHORITY"
            and request["previous_evidence_digest"] == "GENESIS"
            and all(isinstance(request[key], str) and 0 < len(request[key]) <= 128
                    for key in ("request_id", "nonce")), "KERNEL_REQUEST_DENIED")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(str(path))
            server_uid = struct.unpack("3i", client.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
            require(server_uid == 0, "KERNEL_SERVER_IDENTITY_DENIED")
            after = path.lstat()
            require((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) ==
                    (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid), "KERNEL_SOCKET_CHANGED")
            client.sendall(canonical(request)+b"\n")
            raw = b""
            while not raw.endswith(b"\n") and len(raw) <= 65536:
                chunk = client.recv(min(4096, 65537-len(raw)))
                if not chunk:
                    break
                raw += chunk
    except OSError as exc:
        raise KernelWitnessError("KERNEL_TRANSPORT_UNAVAILABLE") from exc
    require(raw.endswith(b"\n") and len(raw) <= 65536, "KERNEL_RESPONSE_FRAMING_DENIED")
    try:
        value = strict_json(raw)
    except TransactionError as exc:
        raise KernelWitnessError("KERNEL_RESPONSE_JSON_DENIED") from exc
    observed = datetime.now(timezone.utc)
    validate_authority_response(value, request=request, source=source, boot_id=boot_id,
                                observed_at=observed, identity=identity, anchor=anchor,
                                host_machine_id=host_machine_id)
    require(boot_path.read_text(encoding="ascii").strip() == boot_id
            and regular(Path(anchor_path)) == anchor, "KERNEL_OBSERVATION_CHANGED")
    require(current_host_gate(Path(host_path), boot_id)["latest"]["host"]["machine_id"] == host_machine_id,
            "KERNEL_FRAME_IDENTITY_CHANGED")
    body = {"schema": "SereinOutpostKernelAuthorityObservation/v2", "issuer": "OUTPOST_DIRECT_WITNESS",
            "subject_issuer": "KERNEL_AUTHORITY_API", "branch": "AUTHORITY", "boot_id": boot_id,
            "source": source, "request": request, "observed_at": observed.isoformat(),
            "subject_evidence": value, "identity_possession": "VERIFIED",
            "result": "AUTHORITY_PHASE_A_OBSERVED" if value["verdict"] == "PASS" else "AUTHORITY_IDENTITY_OBSERVED",
            "admission": "INDEPENDENT_VALIDATION_PENDING" if value["verdict"] == "PASS" else "UNADMITTED",
            "stage1": "NOT_READY", "authority_effect": "NONE"}
    return {**body, "observation_digest": digest(body)}


def main():
    """Existing read-only observer entry; handoff contains public data only."""
    require(len(sys.argv) == 2, "KERNEL_EXPECTED_SOURCE_REQUIRED")
    try:
        envelope = strict_json(sys.argv[1].encode("utf-8"))
    except TransactionError as exc:
        raise KernelWitnessError("KERNEL_EXPECTED_SOURCE_DENIED") from exc
    require(isinstance(envelope, dict) and set(envelope) == {"source", "request", "identity"},
            "KERNEL_EXPECTED_SOURCE_DENIED")
    result = observe_authority(source=envelope["source"], request=envelope["request"],
                               identity=envelope["identity"])
    sys.stdout.buffer.write(canonical(result) + b"\n")


if __name__ == "__main__":
    main()

