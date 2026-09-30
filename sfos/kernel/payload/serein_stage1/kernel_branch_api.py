"""Private Authority identity witness, adapted from canonical branch API v1.

Same AF_UNIX/peer boundary. Response v2 adds request/source/boot-bound native
key possession. An answered API or identity proof never implies Phase-A PASS.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import pwd
import socket
import struct

from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
if __package__:
    from .authority_boot import collect_authority_facts, authority_boot_decision, AuthorityDenied, PHASE_A_CHECKS, strict_json, regular, NATIVE_REGISTRY
else:
    from authority_boot import collect_authority_facts, authority_boot_decision, AuthorityDenied, PHASE_A_CHECKS, strict_json, regular, NATIVE_REGISTRY

NATIVE_KEY = "/var/lib/serein/kernel/authority/domain-identity.pem"
SCHEMA = "SEREIN/KernelBranchDirectWitness/v2"


class BranchDenied(ValueError):
    # Errors cannot produce a signed healthy witness or advance a branch.
    mode = "SAFE_RECOVERY"
    privileged_execution = False
    branch_advance = False

    def __init__(self, message):
        super().__init__(message)
        self.decision = authority_boot_decision(None, requested_effect="OBSERVE_AUTHORITY")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def record_bytes(value):
    return canonical(value) + b"\n"


def require(value, reason):
    if not value:
        raise BranchDenied(reason)


def validate_request(request):
    require(isinstance(request, dict) and set(request) == {
        "schema", "branch", "request_id", "nonce", "previous_evidence_digest"}
        and request["schema"] == "SEREIN/KernelBranchWitnessRequest/v1"
        and request["branch"] == "AUTHORITY"
        and request["previous_evidence_digest"] == "GENESIS"
        and all(isinstance(request[key], str) and 0 < len(request[key]) <= 128
                for key in ("request_id", "nonce")), "REQUEST_SCHEMA_DENIED")


def answer(*args, **kwargs):
    raise BranchDenied("AUTHORITY_REQUIRES_VERIFIED_TRANSPORT")


def _answer(*args, **kwargs):
    raise BranchDenied("AUTHORITY_REQUIRES_VERIFIED_TRANSPORT")


def serve_authority(connection, *, root=Path("/")):
    """Get peer from the kernel, facts from installed source, key from custody."""
    require(connection.family == socket.AF_UNIX, "AUTHORITY_PRIVATE_TRANSPORT_REQUIRED")
    peer = struct.unpack("3i", connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
    require(peer == pwd.getpwnam("serein-outpost").pw_uid, "OUTPOST_PEER_IDENTITY_DENIED")
    connection.settimeout(3)
    raw = b""
    while not raw.endswith(b"\n") and len(raw) <= 16384:
        chunk = connection.recv(min(4096, 16385-len(raw)))
        if not chunk:
            break
        raw += chunk
    require(raw.endswith(b"\n") and len(raw) <= 16384, "REQUEST_FRAMING_DENIED")
    try:
        request = strict_json(raw)
        validate_request(request)
        root = Path(root)
        facts = collect_authority_facts(root)
        decision = authority_boot_decision(facts, requested_effect="OBSERVE_AUTHORITY")
        require(decision["mode"] == "PRIVATE_VALIDATION_ONLY"
                and decision["allowed_effects"] == ["OBSERVE_AUTHORITY"],
                "AUTHORITY_SAFE_RECOVERY_REQUIRED")
        proof = facts["proof"]["native_identity"]
        require(proof["registry_integrity"] == "VERIFIED"
                and proof["authority_effect"] == proof["admission_effect"] == "NONE",
                "NATIVE_IDENTITY_UNPROVEN")
        registry_path = root / NATIVE_REGISTRY.lstrip("/")
        key_path = root / NATIVE_KEY.lstrip("/")
        registry_raw = regular(registry_path, root=root, expected_custody=(0, 0, 0o644))
        registry = strict_json(registry_raw)
        require(record_bytes(registry) == registry_raw
                and hashlib.sha256(record_bytes(registry["records"])).hexdigest() == proof["checkpoint"],
                "NATIVE_REGISTRY_CHANGED")
        body = registry["records"][-1]["body"]
        require(body["domain"] == "KERNEL" and body["instance_id"] == proof["instance_id"],
                "NATIVE_IDENTITY_CHANGED")
        private_raw = regular(key_path, root=root, expected_custody=(0, 0, 0o600))
        private = load_pem_private_key(private_raw, password=None)
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        require(public == body["public_key"], "NATIVE_KEY_MISMATCH")
        checks = facts["self_tests"]
        require(isinstance(checks, list) and len(checks) == len(PHASE_A_CHECKS)
                and all(isinstance(row, dict) and set(row) == {"name", "verdict"}
                        and row["name"] == name and row["verdict"] in {"PASS", "FAIL", "UNKNOWN"}
                        for row, name in zip(checks, PHASE_A_CHECKS)), "PHASE_A_SHAPE_DENIED")
        complete = facts["api_health"] == "READY" and all(row["verdict"] == "PASS" for row in checks)
        verdict = "PASS" if complete else ("FAIL" if any(row["verdict"] == "FAIL" for row in checks) else "UNKNOWN")
        native = {"schema": "SereinNativeIdentityPossession/v1", "instance_id": proof["instance_id"],
                  "checkpoint": proof["checkpoint"], "key_fingerprint": hashlib.sha256(bytes.fromhex(public)).hexdigest()}
        response = {"schema": SCHEMA, "domain": "KERNEL", "branch": "AUTHORITY",
                    "verdict": verdict, "issuer": "KERNEL_AUTHORITY_API",
                    "issued_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                    "request_id": request["request_id"], "nonce": request["nonce"],
                    "previous_evidence_digest": "GENESIS",
                    **{key: facts[key] for key in ("source_commit", "source_tree", "canonical_manifest_digest", "boot_id")},
                    "facts_digest": hashlib.sha256(canonical(facts)).hexdigest(),
                    "phase_a": checks, "api_health": facts["api_health"],
                    "uncertainty": "NONE" if complete else "PHASE_A_UNPROVEN",
                    "authority_effect": "NONE", "native_identity_proof": native,
                    "boot_decision": decision, "frame_identity": facts["proof"]["frame_identity"]}
        # Sign the complete response meaning, not only the nonce: altering a
        # verdict, phase result, timestamp or source invalidates possession.
        challenge = hashlib.sha256(canonical({"request": request, "witness": response})).digest()
        envelope = {"domain": "KERNEL", "instance_id": proof["instance_id"],
                    "checkpoint": proof["checkpoint"], "challenge": challenge.hex()}
        signature = private.sign(record_bytes(envelope)).hex()
        require(collect_authority_facts(root) == facts, "AUTHORITY_FACTS_CHANGED")
        require(regular(registry_path, root=root, expected_custody=(0, 0, 0o644)) == registry_raw
                and regular(key_path, root=root, expected_custody=(0, 0, 0o600)) == private_raw,
                "NATIVE_IDENTITY_CHANGED")
        response["native_identity_proof"] = {**native, "possession_signature": signature}
        response["evidence_digest"] = hashlib.sha256(canonical(response)).hexdigest()
    except BranchDenied:
        raise
    except (AuthorityDenied, ValueError, KeyError, TypeError, OSError) as exc:
        raise BranchDenied("AUTHORITY_WITNESS_DENIED") from exc
    connection.sendall(canonical(response) + b"\n")
    return response

