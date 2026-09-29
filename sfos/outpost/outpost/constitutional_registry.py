"""Fail-closed constitutional and Domain-Seed registry for Outpost.

The registry records the ten canonical Domain-Seed slots and the Outpost
constitution without manufacturing Seed content.  Until governing Seed
material is admitted, every slot remains intentionally held and no domain can
be admitted from this registry.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping

from .host_vitality import BOOT


SCHEMA = "SereinOutpostConstitutionRegistry/v1"
HOLD = "HOLD_INTENTIONAL"
# Exact candidate transcription of PRO-132's controlling Sep26 execution and
# atomic-promotion clauses. Changing policy requires an attributable revision,
# not merely rehashing arbitrary prose inside a release.
BOOTSTRAP_CONSTITUTION_SHA256 = '5c98df0e7101572b7748bef10585714588814b107ee637acff470d2201d1e3c9'
DOMAIN_ORDER = (
    "KERNEL", "PLATFORM", "ROOT", "MEMORY", "KNOWLEDGE",
    "UI", "AUDIO", "PERSONALITY", "MODULAR", "CLOUD",
)


class ConstitutionalRegistryError(ValueError):
    pass


def bootstrap_constitution_binding(raw: bytes, expected_sha256: str) -> dict[str, Any]:
    """Bind the candidate's canonical clauses without admitting the candidate.

    The independent installer supplies the digest from its verified release;
    neither these bytes nor the registry grant mutation/admission authority.
    Future-domain Seeds remain outside this bootstrap-only predicate.
    """
    from install.transaction import strict_json, TransactionError
    if (not isinstance(raw,bytes) or hashlib.sha256(raw).hexdigest()!=expected_sha256
            or expected_sha256!=BOOTSTRAP_CONSTITUTION_SHA256):
        raise ConstitutionalRegistryError('BOOTSTRAP_CONSTITUTION_DIGEST_DENIED')
    try: value=strict_json(raw)
    except TransactionError:
        raise ConstitutionalRegistryError('BOOTSTRAP_CONSTITUTION_ENCODING_DENIED') from None
    if (set(value)!={'schema','identity','version','status','source','clauses','authority_effect','admission_effect'}
            or value['schema']!='SereinOutpostBootstrapConstitution/v1'
            or value['identity']!='OUTPOST' or value['version']!='g0-candidate.1'
            or value['status']!='CANDIDATE_UNADMITTED'
            or value['authority_effect']!='NONE' or value['admission_effect']!='NONE'
            or not isinstance(value['source'],dict) or value['source'].get('issue')!='PRO-132'
            or value['source'].get('controlling_date')!='2026-09-26'
            or not isinstance(value['clauses'],list) or len(value['clauses'])!=2
            or any(not isinstance(clause,str) or not clause for clause in value['clauses'])):
        raise ConstitutionalRegistryError('BOOTSTRAP_CONSTITUTION_IDENTITY_DENIED')
    return {'identity':value['identity'],'version':value['version'],'sha256':expected_sha256,
            'source':value['source'],'status':'CANDIDATE_BOUND_UNADMITTED',
            'authority_effect':'NONE','admission_effect':'NONE'}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def registry_snapshot(*, boot_id: str, observed_at: float) -> dict[str, Any]:
    """Return the immutable registry shape without admitting held content."""
    if not isinstance(boot_id, str) or not BOOT.fullmatch(boot_id) or type(observed_at) not in (int, float) or not math.isfinite(observed_at) or observed_at < 0:
        raise ConstitutionalRegistryError("REGISTRY_IDENTITY_DENIED")
    constitutions = (
        {"id": "OUTPOST", "kind": "OUTPOST", "status": "CONSTITUTION_SLOT"},
        *({"id": domain, "kind": "DOMAIN", "status": "CONSTITUTION_SLOT"} for domain in DOMAIN_ORDER),
    )
    seeds = tuple(
        {
            "domain": domain,
            "status": HOLD,
            "content": "UNAVAILABLE",
            "admission": "DENIED_HELD_SEED_CONTENT",
            "drift": "UNAVAILABLE_HELD_SEED_CONTENT",
            "recovery": "UNAVAILABLE_HELD_SEED_CONTENT",
        }
        for domain in DOMAIN_ORDER
    )
    body = {
        "schema": SCHEMA,
        "boot_id": boot_id,
        "observed_at": observed_at,
        "constitutions": constitutions,
        "seeds": seeds,
        "registry_state": HOLD,
        "authority_effect": "NONE",
        "admission_effect": "NONE",
        "mutation_effect": "NONE",
    }
    return {**body, "registry_digest": _digest(body)}


def validate_registry(value: Mapping[str, Any]) -> dict[str, Any]:
    """Reject any registry that claims held Seed content has been admitted."""
    if not isinstance(value, Mapping) or "registry_digest" not in value:
        raise ConstitutionalRegistryError("REGISTRY_SHAPE_DENIED")
    body = {key: child for key, child in value.items() if key != "registry_digest"}
    required = {
        "schema", "boot_id", "observed_at", "constitutions", "seeds", "registry_state",
        "authority_effect", "admission_effect", "mutation_effect",
    }
    if set(body) != required or body.get("schema") != SCHEMA or body.get("registry_state") != HOLD:
        raise ConstitutionalRegistryError("REGISTRY_SHAPE_DENIED")
    # This implementation has no admitted constitutional/Seed artifacts. A
    # self-consistent digest cannot turn a slot into installed or verified truth.
    expected = registry_snapshot(boot_id=body["boot_id"], observed_at=body["observed_at"])
    for field in ("constitutions", "seeds"):
        if not isinstance(body[field], (list, tuple)) or any(not isinstance(row, Mapping) for row in body[field]):
            raise ConstitutionalRegistryError("REGISTRY_ROWS_DENIED")
    if tuple(row.get("id") for row in body["constitutions"]) != ("OUTPOST", *DOMAIN_ORDER):
        raise ConstitutionalRegistryError("CONSTITUTION_ORDER_DENIED")
    if tuple(row.get("domain") for row in body["seeds"]) != DOMAIN_ORDER:
        raise ConstitutionalRegistryError("SEED_ORDER_DENIED")
    if tuple(body["constitutions"]) != expected["constitutions"]:
        raise ConstitutionalRegistryError("UNADMITTED_CONSTITUTION_DENIED")
    for row in body["seeds"]:
        if row.get("status") != HOLD or row.get("content") != "UNAVAILABLE" or row.get("admission") != "DENIED_HELD_SEED_CONTENT":
            raise ConstitutionalRegistryError("HELD_SEED_ADMISSION_DENIED")
    if tuple(body["seeds"]) != expected["seeds"]:
        raise ConstitutionalRegistryError("HELD_SEED_CLAIM_DENIED")
    if any(body.get(key) != "NONE" for key in ("authority_effect", "admission_effect", "mutation_effect")):
        raise ConstitutionalRegistryError("REGISTRY_EFFECT_DENIED")
    if value.get("registry_digest") != _digest(body):
        raise ConstitutionalRegistryError("REGISTRY_DIGEST_DENIED")
    return dict(value)
