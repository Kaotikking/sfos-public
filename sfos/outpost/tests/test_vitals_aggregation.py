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


def test_matching_claim_labels_cannot_hide_different_current_payloads():
    values=[source(producer="OUTPOST", gpu={"devices":1}),
            source(producer="HOST_OS", gpu={"devices":0})]
    section=aggregate_vitals({"host":values},current_boot_id=BOOT,generated_at=2.0)["sections"]["host"]
    assert section["state"]=="DISAGREEMENT" and section["claim"] is None
    assert [row["payload"] for row in section["perspectives"]]==[row["payload"] for row in values]

def test_budget_is_a_real_producer_slot_and_stale_claims_do_not_project():
    stale = source("budget", "BUDGET_LEDGER", "GREEN", boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    section = aggregate_vitals({"budget": [stale]}, current_boot_id=BOOT, generated_at=2.0)["sections"]["budget"]
    assert section["state"] == "UNKNOWN" and section["perspectives"][0]["freshness"] == "STALE"

def test_tamper_binding_and_credentials_fail_closed():
    tampered = source(); tampered["claim"] = "FAIL"
    with pytest.raises(VitalsAggregationError, match="DIGEST"): aggregate_vitals({"host": [tampered]}, current_boot_id=BOOT, generated_at=2.0)
    with pytest.raises(VitalsAggregationError, match="BINDING"): aggregate_vitals({"budget": [source()]}, current_boot_id=BOOT, generated_at=2.0)
    with pytest.raises(VitalsAggregationError, match="CREDENTIAL"): source(password="secret")


@pytest.mark.parametrize("timestamp", [True, -1, float("inf"), float("nan")])
def test_invalid_producer_and_projection_times_are_rejected(timestamp):
    with pytest.raises(VitalsAggregationError, match="VALUE_DENIED"):
        producer_observation(perspective="host", producer="OUTPOST", claim="UNKNOWN",
                             observed_at=timestamp, boot_id=BOOT, evidence_ref="evidence:test", payload={})
    with pytest.raises(VitalsAggregationError, match="IDENTITY_DENIED"):
        aggregate_vitals({}, current_boot_id=BOOT, generated_at=timestamp)


def test_non_boot_identifier_cannot_make_a_projection_current():
    with pytest.raises(VitalsAggregationError, match="IDENTITY_DENIED"):
        source(boot_id="not-a-boot")
    with pytest.raises(VitalsAggregationError, match="IDENTITY_DENIED"):
        aggregate_vitals({}, current_boot_id="not-a-boot", generated_at=1.0)


def test_future_observation_cannot_contribute_a_current_claim():
    value=source()
    section=aggregate_vitals({"host":[value]},current_boot_id=BOOT,generated_at=0.0)["sections"]["host"]
    assert section["state"]=="UNKNOWN"
    assert section["perspectives"][0]["freshness"]=="INVALID_FUTURE"


def test_same_boot_evidence_does_not_claim_an_unspecified_time_freshness_sla():
    value=source()
    section=aggregate_vitals({"host":[value]},current_boot_id=BOOT,generated_at=86400.0)["sections"]["host"]
    assert section["perspectives"][0]["freshness"]=="CURRENT_BOOT_ATTRIBUTABLE"
    assert section["perspectives"][0]["observed_at"]==1.0


@pytest.mark.parametrize("number", [float("nan"), float("inf"), -float("inf")])
def test_nested_nonfinite_evidence_cannot_be_hashed_as_canonical_api_json(number):
    with pytest.raises(VitalsAggregationError, match="VALUE_DENIED"):
        source(metrics={"samples": [{"value": number}]})
