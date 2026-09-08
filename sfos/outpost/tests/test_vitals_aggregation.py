import pytest
from outpost.vitals_aggregation import VitalsAggregationError, aggregate_vitals, producer_observation

BOOT = "11111111-2222-4333-8444-555555555555"

def source(perspective="host", producer="OUTPOST", claim="PASS", boot_id=BOOT, **payload):
    return producer_observation(perspective=perspective, producer=producer, claim=claim, observed_at=1.0, boot_id=boot_id, evidence_ref=f"evidence:{producer}", payload=payload or {"status": claim})

def test_unknowns_and_effects_are_explicit():
    result = aggregate_vitals({}, current_boot_id=BOOT, generated_at=2.0)
    assert all(section["state"] == "UNKNOWN" for section in result["sections"].values())
    assert result["authority_effect"] == result["admission_effect"] == result["mutation_effect"] == "NONE"

def test_multiple_producers_and_disagreement_are_preserved():
    agreed = aggregate_vitals({"host": [source(producer="OUTPOST"), source(producer="HOST_OS")]}, current_boot_id=BOOT, generated_at=2.0)
    assert agreed["sections"]["host"]["state"] == "OBSERVED"
    conflict = aggregate_vitals({"host": [source(producer="OUTPOST"), source(producer="HOST_OS", claim="FAIL")]}, current_boot_id=BOOT, generated_at=2.0)
    assert conflict["sections"]["host"]["state"] == "DISAGREEMENT"

def test_budget_is_a_real_producer_slot_and_stale_claims_do_not_project():
    stale = source("budget", "BUDGET_LEDGER", "GREEN", boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    section = aggregate_vitals({"budget": [stale]}, current_boot_id=BOOT, generated_at=2.0)["sections"]["budget"]
    assert section["state"] == "UNKNOWN" and section["perspectives"][0]["freshness"] == "STALE"

def test_tamper_binding_and_credentials_fail_closed():
    tampered = source(); tampered["claim"] = "FAIL"
    with pytest.raises(VitalsAggregationError, match="DIGEST"): aggregate_vitals({"host": [tampered]}, current_boot_id=BOOT, generated_at=2.0)
    with pytest.raises(VitalsAggregationError, match="BINDING"): aggregate_vitals({"budget": [source()]}, current_boot_id=BOOT, generated_at=2.0)
    with pytest.raises(VitalsAggregationError, match="CREDENTIAL"): source(password="secret")
