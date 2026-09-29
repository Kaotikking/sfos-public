import copy
import json

import pytest

from outpost.constitutional_registry import (
    ConstitutionalRegistryError,
    DOMAIN_ORDER,
    registry_snapshot,
    validate_registry,
    _digest,
)


BOOT = "11111111-2222-4333-8444-555555555555"


def test_held_registry_exposes_all_canonical_slots_without_seed_content():
    registry = registry_snapshot(boot_id=BOOT, observed_at=1.0)
    assert [row["id"] for row in registry["constitutions"]] == ["OUTPOST", *DOMAIN_ORDER]
    assert [row["domain"] for row in registry["seeds"]] == list(DOMAIN_ORDER)
    assert all(row["admission"] == "DENIED_HELD_SEED_CONTENT" for row in registry["seeds"])
    assert validate_registry(registry) == registry


def test_held_registry_rejects_fixture_promotion_or_digest_drift():
    registry = registry_snapshot(boot_id=BOOT, observed_at=1.0)
    promoted = copy.deepcopy(registry)
    promoted["seeds"][0]["content"] = {"fixture": "not-admitted"}
    with pytest.raises(ConstitutionalRegistryError, match="HELD_SEED_ADMISSION_DENIED"):
        validate_registry(promoted)
    tampered = copy.deepcopy(registry)
    tampered["registry_digest"] = "0" * 64
    with pytest.raises(ConstitutionalRegistryError, match="REGISTRY_DIGEST_DENIED"):
        validate_registry(tampered)


def test_registry_never_claims_an_active_constitution_without_installed_content():
    registry=registry_snapshot(boot_id=BOOT,observed_at=1.0)
    assert all(row["status"]=="CONSTITUTION_SLOT" for row in registry["constitutions"])
    assert validate_registry(json.loads(json.dumps(registry)))["registry_state"]=="HOLD_INTENTIONAL"


@pytest.mark.parametrize("fault",["constitution-promoted","constitution-owner","seed-drift","seed-recovery","seed-extra-field","malformed-row","bad-boot","nonfinite-time"])
def test_rehashed_registry_cannot_promote_or_reinterpret_held_slots(fault):
    value=json.loads(json.dumps(registry_snapshot(boot_id=BOOT,observed_at=1.0)))
    if fault=="constitution-promoted":value["constitutions"][0]["status"]="ACTIVE_CONSTITUTION"
    elif fault=="constitution-owner":value["constitutions"][1]["kind"]="OUTPOST"
    elif fault=="seed-drift":value["seeds"][0]["drift"]="PASS"
    elif fault=="seed-recovery":value["seeds"][0]["recovery"]="READY"
    elif fault=="seed-extra-field":value["seeds"][0]["admitted_version"]="invented"
    elif fault=="malformed-row":value["constitutions"][0]=None
    elif fault=="bad-boot":value["boot_id"]="invented"
    elif fault=="nonfinite-time":value["observed_at"]=float("nan")
    value["registry_digest"]=_digest({key:child for key,child in value.items() if key!="registry_digest"})
    with pytest.raises(ConstitutionalRegistryError):validate_registry(value)
