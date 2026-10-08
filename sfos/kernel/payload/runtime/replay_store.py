#!/usr/bin/env python3
"""Offline reference contract for VM4010 HTTPS telemetry replay state."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

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
                action_nonce: str, observed_at: str, expires_at: str,
                binding_sha256: str | None = None) -> dict:
    scope = descriptor["body"]
    body = {"schema": "VM4010HttpsReplayStoreReceipt/v1", "receipt_id": receipt_id,
            "store_id": scope["store_id"], "issuer": scope["issuer"],
            "observer": scope["observer"], "revision": 0, "prior_revision": None,
            "prior_receipt_sha256": None, "state": "UNUSED", "operation": "WITNESS",
            "result": "UNUSED", "run_id": run_id, "action_nonce": action_nonce,
            "target": scope["target"], "source_generation": scope["source_generation"],
            "observed_at": observed_at, "expires_at": expires_at, "revoked": False,
            "transition_effect": "NONE"}
    if binding_sha256 is not None:
        if not isinstance(binding_sha256, str) or not HEX64.fullmatch(binding_sha256):
            raise ValueError("dispatch binding digest is malformed")
        body.update(schema="SereinKernelDispatchReplayReceipt/v1", binding_sha256=binding_sha256)
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
    expected_states = ["UNUSED", "RESERVED", "CONSUMED"]
    if (require_consumed and len(receipts) != 3) or len(receipts) > 3:
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
    first = _verify_signed(receipts[0], key, "replay receipt")
    schema = first.get("schema")
    binding_hash = first.get("binding_sha256")
    if schema == "SereinKernelDispatchReplayReceipt/v1":
        if not isinstance(binding_hash, str) or not HEX64.fullmatch(binding_hash):
            raise ValueError("dispatch binding digest is malformed")
        required = required | {"binding_sha256"}
    elif schema != "VM4010HttpsReplayStoreReceipt/v1":
        raise ValueError("replay receipt schema is unknown")
    for index, receipt in enumerate(receipts):
        body = _verify_signed(receipt, key, "replay receipt")
        if set(body) != required or body.get("schema") != schema:
            raise ValueError("replay receipt fields are missing or unknown")
        if body.get("binding_sha256") != binding_hash:
            raise ValueError("dispatch binding digest continuity is broken")
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
        if body.get("state") != expected_states[index]:
            raise ValueError("receipt state sequence is invalid")
        if (body.get("operation") != operations[index]
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


def verify_stored_history(chains: list[list[dict]], *, descriptor: dict, key: bytes,
                          current_time: str) -> dict:
    """Authenticate stored lifecycle prefixes without reviving expired work.

    The caller must independently verify the descriptor and read a coherent
    database snapshot. Historical completed chains remain evidence after their
    expiry; only a current RESERVED head counts as an active replay reservation.
    This is replay integrity, not a scheduler/work lease or admission witness.
    """
    now = utc(current_time)
    _verify_signed(descriptor, key, "stored replay descriptor")
    if (not isinstance(chains, list) or len(chains) > 4096
            or any(not isinstance(chain, list) or not 1 <= len(chain) <= 3 for chain in chains)
            or sum(map(len, chains)) >= 4096):
        raise ValueError("stored replay history is unbounded or malformed")
    runs, nonces, receipt_ids = set(), set(), set()
    active = expired = consumed = 0
    for chain in chains:
        # Authenticate before using head timestamps to evaluate its history.
        head = _verify_signed(chain[-1], key, "stored replay head")
        observed = utc(head["observed_at"])
        if observed > now:
            raise ValueError("stored replay history is from the future")
        result = verify_lifecycle(chain, descriptor=descriptor, key=key,
                                  current_time=head["observed_at"], require_consumed=False)
        if head["run_id"] in runs or head["action_nonce"] in nonces:
            raise ValueError("stored replay run or nonce is duplicated")
        runs.add(head["run_id"]); nonces.add(head["action_nonce"])
        for receipt in chain:
            identifier = receipt["body"]["receipt_id"]
            if identifier in receipt_ids:
                raise ValueError("stored replay receipt is duplicated")
            receipt_ids.add(identifier)
        if result["state"] == "CONSUMED":
            consumed += 1
        elif result["state"] == "RESERVED":
            if utc(head["expires_at"]) <= now:
                expired += 1
            else:
                active += 1
    return {"integrity": "AUTHENTICATED_REPLAY_HISTORY" if chains else "EMPTY_NO_AUTHENTICATED_RECEIPTS", "chains": len(chains),
            "receipts": len(receipt_ids), "active_reservations": active,
            "expired_reservations": expired, "consumed_chains": consumed,
            "authority_effect": "NONE", "work_proof": False}


DISPATCH_BINDING_FIELDS = frozenset({'request_id','conversation_id','route','owner','plane',
    'request_sha256','payload_sha256','contract_sha256','registered_route_sha256',
    'identity_checkpoint','kernel_instance','boot_id','source_generation','capacity',
    'external_active_count','policy_digest','policy_version','ump_sha256',
    'trust_identity','predecessor_evidence_digest'})


CONVERSATION_BINDING_SCHEMA = 'SereinStage1ConversationReplayBinding/v1'
CONVERSATION_BINDING_FIELDS = frozenset({'schema','request_id','conversation_id',
    'request_sha256','payload_sha256','caller','requested_operation','route',
    'policy_sha256','plan_sha256','canonical_manifest_digest','boot_id',
    'source_generation','kernel_instance','identity_checkpoint','observed_at',
    'authority_effect','admission_effect'})


def verify_conversation_binding(binding, chain_id, *, descriptor, expected_generation=None):
    """Closed attempt record for installed policy, never an execution grant.

    No generic route contract, UMP, lease or capacity evidence is fabricated.
    The owning Authority must authenticate policy/current gates separately.
    """
    if not isinstance(binding, dict) or set(binding) != CONVERSATION_BINDING_FIELDS:
        raise ValueError('conversation replay fields denied')
    fixed = {'schema': CONVERSATION_BINDING_SCHEMA, 'caller': 'HAOS',
             'route': '/run/serein/kernel/conversation.sock',
             'authority_effect': 'NONE', 'admission_effect': 'NONE'}
    if any(binding[name] != value for name, value in fixed.items()):
        raise ValueError('conversation replay scope denied')
    if binding['requested_operation'] not in ('conversation_only','conversation_tools'):
        raise ValueError('conversation replay operation denied')
    request_id = binding['request_id']
    if (not isinstance(request_id, str) or not 1 <= len(request_id) <= 128
            or request_id != request_id.strip()
            or any(ord(char) < 32 or ord(char) > 126 for char in request_id)
            or str(uuid5(NAMESPACE_URL, f'{request_id}:action')) != chain_id):
        raise ValueError('conversation replay request denied')
    conversation = binding['conversation_id']
    if (not isinstance(conversation, str) or not conversation.strip()
            or len(conversation) > 256 or '\x00' in conversation):
        raise ValueError('conversation replay correlation denied')
    for name in ('request_sha256','payload_sha256','policy_sha256','plan_sha256',
                 'canonical_manifest_digest','identity_checkpoint'):
        if not isinstance(binding[name], str) or not HEX64.fullmatch(binding[name]):
            raise ValueError('conversation replay digest denied')
    if (not isinstance(binding['kernel_instance'], str)
            or not re.fullmatch('[0-9a-f]{16}', binding['kernel_instance'])):
        raise ValueError('conversation replay identity denied')
    generation = binding['source_generation']
    if (not isinstance(generation,dict) or set(generation)!={'commit','tree'}
            or any(not isinstance(v,str) or not re.fullmatch(r'[0-9a-f]{40}',v)
                   for v in generation.values())):
        raise ValueError('conversation replay generation denied')
    expected = descriptor['body']
    generation_scope = (expected_generation if expected_generation is not None else
                        {k: expected['source_generation'][k] for k in ('commit','tree')})
    if (binding['boot_id'] != expected['target']['boot_id']
            or generation != generation_scope):
        raise ValueError('conversation replay generation denied')
    utc(binding['observed_at'])
    return binding


def verify_dispatch_binding(binding, chain_id, *, descriptor):
    if isinstance(binding, dict) and binding.get('schema') == CONVERSATION_BINDING_SCHEMA:
        return verify_conversation_binding(binding, chain_id, descriptor=descriptor)
    if not isinstance(binding, dict) or set(binding) != DISPATCH_BINDING_FIELDS:
        raise ValueError('dispatch binding fields denied')
    request_id = binding['request_id']
    if (not isinstance(request_id, str) or not request_id or len(request_id) > 128
            or request_id != request_id.strip()
            or any(ord(char) < 0x20 or ord(char) > 0x7e for char in request_id)):
        raise ValueError('dispatch binding request denied')
    if str(uuid5(NAMESPACE_URL, f'{request_id}:action')) != chain_id:
        raise ValueError('dispatch binding request denied')
    if (type(binding['capacity']) is not int or binding['capacity'] < 1
            or type(binding['external_active_count']) is not int or binding['external_active_count'] < 0):
        raise ValueError('dispatch binding capacity denied')
    for field in DISPATCH_BINDING_FIELDS - {'capacity','external_active_count','source_generation'}:
        value = binding[field]
        if not isinstance(value, str) or not value or len(value) > 256 or '\x00' in value:
            raise ValueError('dispatch binding value denied')
        if (field.endswith('_sha256') or field.endswith('_digest') or field == 'identity_checkpoint'):
            if len(value) != 64 or any(char not in '0123456789abcdef' for char in value):
                raise ValueError('dispatch binding digest denied')
    expected = descriptor['body']
    if (binding['boot_id'] != expected['target']['boot_id']
            or binding['source_generation'] != {k:expected['source_generation'][k] for k in ('commit','tree')}):
        raise ValueError('dispatch binding scope denied')
    return binding

def verify_dispatch_bindings(rows, chains, *, descriptor, key, allow_conversation_history=False):
    """Verify a coherent read-only snapshot after its replay lifecycle checks."""
    if len(rows) >= 4096:
        raise ValueError('dispatch binding capacity exceeded')
    bindings = {}; used = 0
    for chain_id, raw, outcome_raw in rows:
        if not isinstance(raw, bytes) or len(raw) > 16384:
            raise ValueError('dispatch binding encoding denied')
        envelope = json.loads(raw)
        body = _verify_signed(envelope, key, 'dispatch binding')
        if (canonical_bytes(envelope) != raw
                or set(body) != {'schema','chain_id','binding','authority_effect'}
                or body['schema'] != 'SereinKernelDispatchBinding/v1'
                or body['chain_id'] != chain_id or body['authority_effect'] != 'NONE'):
            raise ValueError('dispatch binding integrity denied')
        if (allow_conversation_history
                and isinstance(body['binding'],dict)
                and body['binding'].get('schema') == CONVERSATION_BINDING_SCHEMA):
            # Historical source is authenticated by the existing MAC and
            # receipt anchor below, not asserted as current installation.
            bindings[chain_id] = verify_conversation_binding(body['binding'], chain_id,
                descriptor=descriptor, expected_generation=body['binding'].get('source_generation'))
        else:
            bindings[chain_id] = verify_dispatch_binding(body['binding'], chain_id, descriptor=descriptor)
        values = chains.get(chain_id, [])
        if (len(values) not in (2,3) or values[0]['body']['run_id'] !=
                str(uuid5(NAMESPACE_URL, f"{body['binding']['request_id']}:run"))):
            raise ValueError('dispatch binding lifecycle denied')
        if any(receipt['body'].get('schema') != 'SereinKernelDispatchReplayReceipt/v1'
               or receipt['body'].get('binding_sha256') != hashlib.sha256(raw).hexdigest()
               for receipt in values):
            raise ValueError('dispatch binding receipt anchor denied')
        if (len(values) == 3) != (outcome_raw is not None):
            raise ValueError('dispatch outcome lifecycle denied')
        used += len(raw)
        if outcome_raw is not None:
            if not isinstance(outcome_raw, bytes) or len(outcome_raw) > 4096:
                raise ValueError('dispatch outcome encoding denied')
            outcome = json.loads(outcome_raw)
            result = _verify_signed(outcome, key, 'dispatch outcome')
            if (canonical_bytes(outcome) != outcome_raw
                    or set(result) != {'schema','chain_id','binding_sha256','result_sha256',
                                      'completed_at','authority_effect','physical_effect'}
                    or result['schema'] != 'SereinKernelDispatchOutcome/v1'
                    or result['chain_id'] != chain_id
                    or result['binding_sha256'] != hashlib.sha256(raw).hexdigest()
                    or result['completed_at'] != values[-1]['body']['observed_at']
                    or result['authority_effect'] != 'NONE' or result['physical_effect'] != 'UNVERIFIED'
                    or not isinstance(result['result_sha256'],str)
                    or not HEX64.fullmatch(result['result_sha256'])):
                raise ValueError('dispatch outcome integrity denied')
            used += len(outcome_raw)
    expected = {chain_id for chain_id, values in chains.items()
                if values[0]['body']['schema'] == 'SereinKernelDispatchReplayReceipt/v1'}
    if set(bindings) != expected:
        raise ValueError('dispatch binding receipt anchor missing')
    return bindings, used


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

