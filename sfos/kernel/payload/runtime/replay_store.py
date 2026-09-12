#!/usr/bin/env python3
"""Offline reference contract for VM4010 HTTPS telemetry replay state."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from datetime import datetime, timezone

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp is not canonical UTC")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("timestamp is not canonical UTC") from error
    if result.tzinfo != timezone.utc:
        raise ValueError("timestamp is not canonical UTC")
    return result


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def signature(body: dict, key: bytes) -> str:
    return hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()


def signed(body: dict, key: bytes) -> dict:
    return {"body": body, "signature": signature(body, key)}


def receipt_hash(receipt: dict) -> str:
    return digest(receipt)


def make_descriptor(*, store_id: str, backend_identity: str, issuer: str, observer: str,
                    key: bytes, key_receipt: str, vm_id: str, boot_id: str,
                    parent: str, commit: str, tree: str) -> dict:
    body = {"schema": "VM4010HttpsReplayStoreDescriptor/v1", "store_id": store_id,
            "backend_identity": backend_identity, "issuer": issuer, "observer": observer,
            "signature_algorithm": "HMAC-SHA256",
            "trusted_key_fingerprint": hashlib.sha256(key).hexdigest(),
            "trusted_key_receipt": key_receipt,
            "target": {"vm_id": vm_id, "boot_id": boot_id},
            "source_generation": {"parent": parent, "commit": commit, "tree": tree},
            "telemetry_schema": "VM4010HttpsAdapterTelemetry/v2",
            "authority_effect": "NONE"}
    return signed(body, key)


def _verify_signed(value: object, key: bytes, label: str) -> dict:
    if not isinstance(value, dict) or set(value) != {"body", "signature"}:
        raise ValueError(f"{label} envelope is malformed")
    body = value["body"]
    supplied = value["signature"]
    if not isinstance(body, dict) or not isinstance(supplied, str) or not HEX64.fullmatch(supplied):
        raise ValueError(f"{label} signature is malformed")
    if not hmac.compare_digest(supplied, signature(body, key)):
        raise ValueError(f"{label} signature verification failed")
    return body


def verify_descriptor(descriptor: object, *, key: bytes, expected_store_id: str,
                      expected_backend_identity: str, expected_issuer: str,
                      expected_observer: str, expected_key_fingerprint: str,
                      expected_key_receipt: str, expected_target: dict,
                      expected_generation: dict) -> dict:
    body = _verify_signed(descriptor, key, "descriptor")
    required = {"schema", "store_id", "backend_identity", "issuer", "observer",
                "signature_algorithm", "trusted_key_fingerprint", "trusted_key_receipt",
                "target", "source_generation", "telemetry_schema", "authority_effect"}
    if set(body) != required:
        raise ValueError("descriptor fields are missing or unknown")
    expected = {"store_id": expected_store_id, "backend_identity": expected_backend_identity,
                "issuer": expected_issuer, "observer": expected_observer,
                "trusted_key_fingerprint": expected_key_fingerprint,
                "trusted_key_receipt": expected_key_receipt, "target": expected_target,
                "source_generation": expected_generation}
    if any(body[field] != value for field, value in expected.items()):
        raise ValueError("descriptor identity or scope mismatch")
    if (body["schema"] != "VM4010HttpsReplayStoreDescriptor/v1"
            or body["signature_algorithm"] != "HMAC-SHA256"
            or body["telemetry_schema"] != "VM4010HttpsAdapterTelemetry/v2"
            or body["authority_effect"] != "NONE"
            or body["trusted_key_fingerprint"] != hashlib.sha256(key).hexdigest()):
        raise ValueError("descriptor policy mismatch")
    if not UUID.fullmatch(body["store_id"]) or not UUID.fullmatch(body["trusted_key_receipt"]):
        raise ValueError("descriptor identifiers are malformed")
    generation = body["source_generation"]
    if set(generation) != {"parent", "commit", "tree"} or any(
            not isinstance(generation[field], str) or not HEX40.fullmatch(generation[field])
            for field in generation):
        raise ValueError("descriptor generation is malformed")
    return body


def make_unused(descriptor: dict, *, key: bytes, receipt_id: str, run_id: str,
                action_nonce: str, observed_at: str, expires_at: str) -> dict:
    scope = descriptor["body"]
    body = {"schema": "VM4010HttpsReplayStoreReceipt/v1", "receipt_id": receipt_id,
            "store_id": scope["store_id"], "issuer": scope["issuer"],
            "observer": scope["observer"], "revision": 0, "prior_revision": None,
            "prior_receipt_sha256": None, "state": "UNUSED", "operation": "WITNESS",
            "result": "UNUSED", "run_id": run_id, "action_nonce": action_nonce,
            "target": scope["target"], "source_generation": scope["source_generation"],
            "observed_at": observed_at, "expires_at": expires_at, "revoked": False,
            "transition_effect": "NONE"}
    return signed(body, key)


def transition(current: dict, *, expected_hash: str, operation: str, receipt_id: str,
               at: str, key: bytes) -> dict:
    body = _verify_signed(current, key, "current receipt")
    if receipt_hash(current) != expected_hash:
        raise ValueError("CAS expected hash conflict")
    mapping = {("UNUSED", "RESERVE"): ("RESERVED", "RESERVATION"),
               ("RESERVED", "CONSUME"): ("CONSUMED", "CONSUMPTION")}
    if (body.get("state"), operation) not in mapping:
        raise ValueError("duplicate or invalid replay transition")
    if receipt_id == body.get("receipt_id"):
        raise ValueError("replay receipt UUID is reused")
    if utc(at) <= utc(body["observed_at"]):
        raise ValueError("transition timestamp is not strictly monotonic")
    next_state, effect = mapping[(body["state"], operation)]
    next_body = {**body, "receipt_id": receipt_id, "revision": body["revision"] + 1,
                 "prior_revision": body["revision"], "prior_receipt_sha256": expected_hash,
                 "state": next_state, "operation": operation, "result": next_state,
                 "observed_at": at, "transition_effect": effect}
    return signed(next_body, key)


def verify_lifecycle(receipts: list[dict], *, descriptor: dict, key: bytes,
                     current_time: str, require_consumed: bool = True) -> dict:
    if not isinstance(receipts, list) or not receipts:
        raise ValueError("replay receipt chain is omitted")
    expected_states = ["UNUSED", "RESERVED", "CONSUMED"] if require_consumed else None
    if expected_states and len(receipts) != 3:
        raise ValueError("replay receipt chain is partial")
    scope = descriptor["body"]
    now = utc(current_time)
    previous = None
    required = {"schema", "receipt_id", "store_id", "issuer", "observer", "revision",
                "prior_revision", "prior_receipt_sha256", "state", "operation", "result",
                "run_id", "action_nonce", "target", "source_generation", "observed_at",
                "expires_at", "revoked", "transition_effect"}
    operations = ["WITNESS", "RESERVE", "CONSUME"]
    effects = ["NONE", "RESERVATION", "CONSUMPTION"]
    receipt_ids = set()
    for index, receipt in enumerate(receipts):
        body = _verify_signed(receipt, key, "replay receipt")
        if set(body) != required or body.get("schema") != "VM4010HttpsReplayStoreReceipt/v1":
            raise ValueError("replay receipt fields are missing or unknown")
        if (body.get("store_id") != scope["store_id"] or body.get("issuer") != scope["issuer"]
                or body.get("observer") != scope["observer"] or body.get("target") != scope["target"]
                or body.get("source_generation") != scope["source_generation"]):
            raise ValueError("receipt store identity, target, or generation mismatch")
        for field in ("receipt_id", "run_id", "action_nonce"):
            if not isinstance(body.get(field), str) or not UUID.fullmatch(body[field]):
                raise ValueError("receipt identifier is malformed")
        if body["receipt_id"] in receipt_ids:
            raise ValueError("replay receipt UUID is duplicated")
        receipt_ids.add(body["receipt_id"])
        observed, expires = utc(body["observed_at"]), utc(body["expires_at"])
        if observed > now or expires <= now or observed >= expires or body.get("revoked") is not False:
            raise ValueError("receipt is stale, future, expired, or revoked")
        if body.get("revision") != index:
            raise ValueError("receipt revision is non-monotonic")
        if previous is None:
            if body.get("prior_revision") is not None or body.get("prior_receipt_sha256") is not None:
                raise ValueError("genesis linkage is invalid")
        else:
            if observed <= utc(previous["body"]["observed_at"]):
                raise ValueError("transition timestamps are not strictly monotonic")
            if (body.get("prior_revision") != previous["body"]["revision"]
                    or body.get("prior_receipt_sha256") != receipt_hash(previous)):
                raise ValueError("receipt hash or revision continuity is broken")
            if (body.get("run_id"), body.get("action_nonce")) != (
                    previous["body"]["run_id"], previous["body"]["action_nonce"]):
                raise ValueError("receipt run or nonce changed")
        if expected_states and body.get("state") != expected_states[index]:
            raise ValueError("receipt state sequence is invalid")
        if expected_states and (body.get("operation") != operations[index]
                                or body.get("result") != expected_states[index]
                                or body.get("transition_effect") != effects[index]):
            raise ValueError("receipt operation or effect sequence is invalid")
        previous = receipt
    return {"verdict": "PASS", "state": receipts[-1]["body"]["state"],
            "revision": receipts[-1]["body"]["revision"],
            "receipt_sha256": receipt_hash(receipts[-1]), "authority_effect": "NONE"}


def telemetry_projection(receipt: dict, *, descriptor: dict, key: bytes,
                         projection_receipt_id: str, observed_at: str) -> dict:
    body = _verify_signed(receipt, key, "replay receipt")
    consumed = [body["run_id"]] if body["state"] == "CONSUMED" else []
    return {"schema": "VM4010HttpsAdapterReplayState/v1",
            "receipt_id": projection_receipt_id, "issuer": descriptor["body"]["issuer"],
            "observer": descriptor["body"]["observer"], "observed_at": observed_at,
            "target": descriptor["body"]["target"], "scope": "COMPLETE_FOR_TARGET_BOOT",
            "consumed_run_ids": consumed, "authority_effect": "NONE"}


class AtomicReplayStore:
    """In-memory reference CAS; external persistence and keys remain Root-owned."""

    def __init__(self, initial: dict):
        self._current = initial
        self._lock = threading.Lock()

    def current(self) -> dict:
        with self._lock:
            return self._current

    def cas(self, *, expected_hash: str, operation: str, receipt_id: str,
            at: str, key: bytes) -> dict:
        with self._lock:
            if receipt_hash(self._current) != expected_hash:
                raise ValueError("CAS expected hash conflict")
            self._current = transition(self._current, expected_hash=expected_hash,
                                       operation=operation, receipt_id=receipt_id,
                                       at=at, key=key)
            return self._current


class VersionedKeyLifecycle:
    """Bounded active/verify-only/revoked HMAC key policy; key bytes never enter receipts."""

    def __init__(self, *, version: int, key: bytes, receipt_id: str):
        if version < 1 or len(key) != 32 or not UUID.fullmatch(receipt_id):
            raise ValueError("key generation is malformed")
        self._keys = {version: key}
        self._receipts = {version: receipt_id}
        self._active = version
        self._revoked: set[int] = set()

    def receipt(self, version: int) -> dict:
        if version not in self._keys:
            raise ValueError("key version is unknown")
        return {"version": version, "fingerprint_sha256": hashlib.sha256(
            self._keys[version]).hexdigest(), "receipt_id": self._receipts[version],
            "state": "REVOKED" if version in self._revoked else (
                "ACTIVE" if version == self._active else "VERIFY_ONLY")}

    def rotate(self, *, version: int, key: bytes, receipt_id: str) -> dict:
        if version != self._active + 1 or version in self._keys or len(key) != 32:
            raise ValueError("key rotation is non-monotonic or malformed")
        if not UUID.fullmatch(receipt_id):
            raise ValueError("key receipt is malformed")
        self._keys[version] = key
        self._receipts[version] = receipt_id
        self._active = version
        return self.receipt(version)

    def sign(self, body: dict, *, version: int | None = None) -> str:
        selected = self._active if version is None else version
        if selected != self._active or selected in self._revoked:
            raise ValueError("key version is not active for signing")
        return signature(body, self._keys[selected])

    def verify(self, body: dict, supplied: str, *, version: int) -> bool:
        if version not in self._keys or version in self._revoked:
            raise ValueError("key version is revoked or unknown")
        return hmac.compare_digest(supplied, signature(body, self._keys[version]))

    def revoke(self, *, version: int, retention_closed: bool) -> dict:
        if version == self._active or version not in self._keys or not retention_closed:
            raise ValueError("key revocation boundary is invalid")
        self._revoked.add(version)
        return self.receipt(version)

    def rollback(self, *, version: int, expected_fingerprint: str) -> dict:
        if version not in self._keys or version in self._revoked:
            raise ValueError("rollback key is revoked or unknown")
        if hashlib.sha256(self._keys[version]).hexdigest() != expected_fingerprint:
            raise ValueError("rollback key fingerprint mismatch")
        self._active = version
        return self.receipt(version)
