"""Candidate-only Kernel identity records for PRO-116/65b12aad.

Pure offline record construction/verification, not a registry service, installer,
authorization mechanism or admission API. No filesystem, network or key creation.
Installation authority must independently admit the exact registry checkpoint.
The caller supplies governed installer/domain keys and installation-only entropy.
"""
from __future__ import annotations

import hashlib
import base64
import json
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCHEMA = "SereinDomainIdentityRecord/v1"
DOMAINS = frozenset(("KERNEL", "PLATFORM", "ROOT", "MEMORY", "KNOWLEDGE",
                    "UI", "AUDIO", "PERSONALITY", "MODULAR", "CLOUD"))
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class IdentityDenied(ValueError):
    pass


def require(value, reason):
    if not value:
        raise IdentityDenied(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def public_hex(private):
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def verify_signature(public, signature, raw):
    try:
        require(isinstance(public, str) and HEX64.fullmatch(public), "IDENTITY_KEY_DENIED")
        require(isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{128}", signature),
                "IDENTITY_SIGNATURE_DENIED")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(bytes.fromhex(signature), raw)
    except Exception as exc:
        raise IdentityDenied("IDENTITY_SIGNATURE_DENIED") from exc


def installation_id(used_ids, random_bytes):
    """Only the governed installer may call this; runtime must never mint IDs."""
    require(isinstance(used_ids, (set, frozenset)) and
            all(isinstance(x, str) and HEX16.fullmatch(x) for x in used_ids),
            "IDENTITY_REGISTRY_DENIED")
    for _ in range(16):
        raw = random_bytes(8)
        require(type(raw) is bytes and len(raw) == 8, "IDENTITY_ENTROPY_DENIED")
        value = raw.hex()
        if value not in used_ids:
            return value
    raise IdentityDenied("IDENTITY_COLLISION_DENIED")


def verify_installation_origin(plan, *, installer_public, native_identity,
                               host_identity_file, boot_id):
    """Authenticate the unchanged identity/replay birth plan across updates.

    An update has new payload provenance, not a new identity or replay store.
    The governing successor must already have independently verified current
    installed state before retaining this signed original plan. This pure
    reader creates no key, installation, authority or admission.
    """
    try:
        require(isinstance(plan,dict) and len(canonical(plan))<=1024*1024
                and plan.get('schema')=='SereinPublicKernelFirstInstallPlan/v1'
                and plan.get('target_vm_id')=='VM4010'
                and 'installation_origin' not in plan
                and plan.get('current_boot_id')==boot_id,
                'IDENTITY_ORIGIN_PLAN_DENIED')
        signature=plan['signature']
        require(isinstance(signature,str) and re.fullmatch(r'[A-Za-z0-9_-]{86}',signature),
                'IDENTITY_ORIGIN_SIGNATURE_DENIED')
        raw_signature=base64.b64decode(signature+'==',altchars=b'-_',validate=True)
        require(base64.urlsafe_b64encode(raw_signature).decode().rstrip('=')==signature,
                'IDENTITY_ORIGIN_SIGNATURE_DENIED')
        verify_signature(installer_public,raw_signature.hex(),
                         canonical({k:v for k,v in plan.items() if k!='signature'}))
        binding=plan['native_identity']
        require(isinstance(binding,dict) and set(binding)=={
            'schema','instance_id','checkpoint','registry_sha256','private_sha256',
            'public_key','transaction_context'}
            and binding['schema']=='SereinKernelNativeIdentityMaterial/v1'
            and isinstance(native_identity,dict)
            and set(native_identity) in ({'instance_id','checkpoint','registry_sha256','transaction_context'},set(binding))
            and all(binding[k]==v for k,v in native_identity.items())
            and HEX16.fullmatch(binding['instance_id'])
            and all(HEX64.fullmatch(binding[k]) for k in
                ('checkpoint','registry_sha256','private_sha256','public_key','transaction_context')),
                'IDENTITY_ORIGIN_NATIVE_DENIED')
        context=digest({k:v for k,v in plan.items() if k not in {'signature','native_identity'}})
        require(context==binding['transaction_context']
                and plan['host_identity']['file']==host_identity_file,
                'IDENTITY_ORIGIN_CONTEXT_DENIED')
        generation={name:plan['source_'+name] for name in ('parent','commit','tree')}
        reserved=plan['reserved_domain_ids']
        require(all(isinstance(v,str) and HEX40.fullmatch(v) for v in generation.values())
                and isinstance(reserved,list) and reserved==sorted(set(reserved))
                and all(isinstance(v,str) and HEX16.fullmatch(v) for v in reserved)
                and binding['instance_id'] not in reserved,
                'IDENTITY_ORIGIN_LINEAGE_DENIED')
        return {'plan_sha256':digest(plan),'source_generation':generation,
                'transaction_context':context,'reserved_domain_ids':list(reserved),
                'authority_effect':'NONE','admission_effect':'NONE'}
    except IdentityDenied:
        raise
    except Exception as exc:
        raise IdentityDenied('IDENTITY_ORIGIN_DENIED') from exc


def _record(body, installer_key, domain_key, previous_key=None):
    raw = canonical(body)
    return {"body": body, "installer_signature": installer_key.sign(raw).hex(),
            "domain_signature": domain_key.sign(raw).hex(),
            "prior_key_signature": None if previous_key is None else previous_key.sign(raw).hex()}


def candidate(domain, *, source_commit, governance_receipt, installer_key,
              domain_key, used_ids, random_bytes, previous=None,
              previous_key=None, replacement=False):
    """Produce unadmitted bytes; no persistence or live identity is granted.

    Existing history must be independently verified before it is passed here.
    A new instance (initial or explicit replacement) gets installation entropy;
    rotation uses the prior immutable ID and requires proof from both keys.
    """
    require(domain in DOMAINS and isinstance(source_commit, str) and HEX40.fullmatch(source_commit)
            and isinstance(governance_receipt, str) and HEX64.fullmatch(governance_receipt),
            "IDENTITY_SOURCE_DENIED")
    require(type(replacement) is bool, "IDENTITY_OPERATION_DENIED")
    if previous is None:
        require(not replacement and previous_key is None, "IDENTITY_PREDECESSOR_DENIED")
        instance = installation_id(used_ids, random_bytes)
        operation, revision, prior, replaced = "INSTALL", 0, None, None
    else:
        old = previous["body"]
        require(old["domain"] == domain and old["instance_id"] in used_ids,
                "IDENTITY_PREDECESSOR_DENIED")
        prior, revision = digest(previous), old["revision"] + 1
        if replacement:
            require(previous_key is None, "IDENTITY_REPLACEMENT_DENIED")
            instance = installation_id(used_ids, random_bytes)
            operation, replaced = "REPLACE", old["instance_id"]
        else:
            require(previous_key is not None and public_hex(previous_key) == old["public_key"]
                    and public_hex(domain_key) != old["public_key"], "IDENTITY_ROTATION_DENIED")
            instance, operation, replaced = old["instance_id"], "ROTATE", None
    key = public_hex(domain_key)
    body = {"schema": SCHEMA, "domain": domain, "instance_id": instance,
            "operation": operation, "revision": revision, "prior_record": prior,
            "replaces_instance_id": replaced, "public_key": key,
            "key_fingerprint": hashlib.sha256(bytes.fromhex(key)).hexdigest(),
            "source_commit": source_commit, "governance_receipt": governance_receipt,
            "authority_effect": "NONE", "admission_effect": "NONE"}
    return _record(body, installer_key, domain_key, previous_key)


def verify_lineage(records, *, installer_public, expected_checkpoint, expected_domain,
                   reserved_ids=frozenset()):
    """Verify against an independently admitted exact integrity checkpoint.

    A record's own digest or copied ID cannot supply expected_checkpoint.
    This is identity integrity only, never API, freshness or action authority.
    """
    require(isinstance(records, list) and 0 < len(records) <= 4096,
            "IDENTITY_HISTORY_DENIED")
    require(isinstance(expected_checkpoint, str) and HEX64.fullmatch(expected_checkpoint)
            and digest(records) == expected_checkpoint, "IDENTITY_CHECKPOINT_DENIED")
    require(expected_domain in DOMAINS and isinstance(reserved_ids, (set, frozenset))
            and all(isinstance(x, str) and HEX16.fullmatch(x) for x in reserved_ids),
            "IDENTITY_REGISTRY_DENIED")
    fields = {"schema", "domain", "instance_id", "operation", "revision", "prior_record",
              "replaces_instance_id", "public_key", "key_fingerprint", "source_commit",
              "governance_receipt", "authority_effect", "admission_effect"}
    instances = set(reserved_ids)
    previous = None
    for index, record in enumerate(records):
        require(isinstance(record, dict) and set(record) ==
                {"body", "installer_signature", "domain_signature", "prior_key_signature"},
                "IDENTITY_RECORD_DENIED")
        body = record["body"]
        require(isinstance(body, dict) and set(body) == fields
                and body["schema"] == SCHEMA and body["domain"] == expected_domain
                and type(body["revision"]) is int and body["revision"] == index
                and isinstance(body["instance_id"], str) and HEX16.fullmatch(body["instance_id"])
                and isinstance(body["source_commit"], str) and HEX40.fullmatch(body["source_commit"])
                and isinstance(body["governance_receipt"], str) and HEX64.fullmatch(body["governance_receipt"])
                and body["authority_effect"] == body["admission_effect"] == "NONE",
                "IDENTITY_RECORD_DENIED")
        raw = canonical(body)
        verify_signature(installer_public, record["installer_signature"], raw)
        verify_signature(body["public_key"], record["domain_signature"], raw)
        require(body["key_fingerprint"] == hashlib.sha256(bytes.fromhex(body["public_key"])).hexdigest(),
                "IDENTITY_KEY_BINDING_DENIED")
        require(body["prior_record"] == (None if previous is None else digest(previous)),
                "IDENTITY_PREDECESSOR_DENIED")
        if previous is None:
            require(body["operation"] == "INSTALL" and body["replaces_instance_id"] is None
                    and record["prior_key_signature"] is None, "IDENTITY_INSTALL_DENIED")
            require(body["instance_id"] not in instances, "IDENTITY_COLLISION_DENIED")
            instances.add(body["instance_id"])
        elif body["operation"] == "ROTATE":
            old = previous["body"]
            require(body["instance_id"] == old["instance_id"] and
                    body["public_key"] != old["public_key"] and body["replaces_instance_id"] is None,
                    "IDENTITY_ROTATION_DENIED")
            verify_signature(old["public_key"], record["prior_key_signature"], raw)
        elif body["operation"] == "REPLACE":
            require(body["replaces_instance_id"] == previous["body"]["instance_id"]
                    and body["instance_id"] not in instances and record["prior_key_signature"] is None,
                    "IDENTITY_REPLACEMENT_DENIED")
            instances.add(body["instance_id"])
        else:
            raise IdentityDenied("IDENTITY_OPERATION_DENIED")
        previous = record
    return {"domain": expected_domain, "instance_id": previous["body"]["instance_id"],
            "public_key": previous["body"]["public_key"], "checkpoint": expected_checkpoint,
            "authority_effect": "NONE", "admission_effect": "NONE"}


def verify_possession(records, *, installer_public, expected_checkpoint,
                      expected_domain, challenge, signature, reserved_ids=frozenset()):
    """Caller must bind an externally issued fresh challenge; no freshness claim here."""
    identity = verify_lineage(records, installer_public=installer_public,
                              expected_checkpoint=expected_checkpoint,
                              expected_domain=expected_domain, reserved_ids=reserved_ids)
    require(type(challenge) is bytes and 32 <= len(challenge) <= 4096, "IDENTITY_CHALLENGE_DENIED")
    envelope = {"domain": identity["domain"], "instance_id": identity["instance_id"],
                "checkpoint": identity["checkpoint"], "challenge": challenge.hex()}
    verify_signature(identity["public_key"], signature, canonical(envelope))
    return {"identity_proof": "VERIFIED", "freshness": "CALLER_MUST_VERIFY",
            "authority_effect": "NONE", "admission_effect": "NONE"}
