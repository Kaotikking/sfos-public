"""Domain-1 Authority contract validation; validation only, never signs."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json

SCHEMA = "SEREIN/KernelAuthorityRouteContract/v1"
FIELDS = {"schema","action","object","intent","scope","conditions","policy_version",
          "policy_digest","issuer","subject","trust_identity","issued_at","expires_at",
          "nonce","expected_result","boot_id","source_generation",
          "predecessor_evidence_digest","authority_effect"}
HEX64 = __import__("re").compile(r"[0-9a-f]{64}\Z")
HEX40 = __import__("re").compile(r"[0-9a-f]{40}\Z")


class AuthorityDenied(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def validate(value, *, action, route, boot_id, caller=None, now=None,
             intent=None, scope=None, conditions=None, policy_version=None,
             policy_digest=None, expected_result=None, source_generation=None):
    if not isinstance(value, dict) or set(value) != FIELDS or value.get("schema") != SCHEMA:
        raise AuthorityDenied("AUTHORITY_CONTRACT_SHAPE_DENIED")
    if value["action"] != action:
        raise AuthorityDenied("AUTHORITY_ACTION_DENIED")
    if value["object"] != route:
        raise AuthorityDenied("AUTHORITY_OBJECT_DENIED")
    if value["boot_id"] != boot_id:
        raise AuthorityDenied("AUTHORITY_BOOT_DENIED")
    if value["issuer"] != "KERNEL_AUTHORITY" or value["subject"] != "KERNEL" or value["authority_effect"] != "NONE":
        raise AuthorityDenied("AUTHORITY_TRUST_IDENTITY_DENIED")
    if caller is not None and value["trust_identity"] != caller:
        raise AuthorityDenied("AUTHORITY_CALLER_DENIED")
    if any(not isinstance(value[k], str) or not value[k] or value[k] == "UNKNOWN"
           for k in ("intent","policy_version","nonce","expected_result",
                     "predecessor_evidence_digest","trust_identity")):
        raise AuthorityDenied("AUTHORITY_UNKNOWN_DENIED")
    if not isinstance(value["scope"], dict) or value["scope"].get("route") != route:
        raise AuthorityDenied("AUTHORITY_SCOPE_DENIED")
    if (not isinstance(value["conditions"], list) or not value["conditions"] or
            any(not isinstance(item, str) or not item or item == "UNKNOWN" for item in value["conditions"])):
        raise AuthorityDenied("AUTHORITY_CONDITIONS_DENIED")
    generation=value["source_generation"]
    if not isinstance(generation,dict) or set(generation)!={"commit","tree"}:
        raise AuthorityDenied("AUTHORITY_GENERATION_DENIED")
    if any(not isinstance(generation[k],str) or not HEX40.fullmatch(generation[k]) for k in ("commit","tree")):
        raise AuthorityDenied("AUTHORITY_GENERATION_DENIED")
    if not isinstance(value["predecessor_evidence_digest"],str) or not HEX64.fullmatch(value["predecessor_evidence_digest"]):
        raise AuthorityDenied("AUTHORITY_PREDECESSOR_DENIED")
    if not isinstance(value["policy_digest"],str) or not HEX64.fullmatch(value["policy_digest"]):
        raise AuthorityDenied("AUTHORITY_POLICY_DENIED")
    try:
        issued=datetime.fromisoformat(value["issued_at"].replace("Z","+00:00"))
        expires=datetime.fromisoformat(value["expires_at"].replace("Z","+00:00"))
    except Exception as error:
        raise AuthorityDenied("AUTHORITY_FRESHNESS_DENIED") from error
    observed=now or datetime.now(timezone.utc)
    if issued.tzinfo is None or expires.tzinfo is None or observed.tzinfo is None:
        raise AuthorityDenied("AUTHORITY_FRESHNESS_DENIED")
    if not issued <= observed < expires or (expires-issued).total_seconds()>30:
        raise AuthorityDenied("AUTHORITY_FRESHNESS_DENIED")
    expected = {
        "intent": intent, "scope": scope, "conditions": conditions,
        "policy_version": policy_version, "policy_digest": policy_digest,
        "expected_result": expected_result, "source_generation": source_generation,
    }
    for field, wanted in expected.items():
        if wanted is not None and value[field] != wanted:
            raise AuthorityDenied("AUTHORITY_%s_DENIED" % field.upper())
    return dict(value)
