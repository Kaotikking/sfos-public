import hashlib
import json
import pytest
from outpost.reboot_vitality import RebootVitalityError, VitalityChronology, canonical, classify_reboot

def observation(readiness="VERIFIED", witness="OUTPOST_BOOT_ID_CHANGE", new_boot="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"):
    value={"schema":"SereinOutpostRebootObservation/v1","event_id":"reboot-1","subject":"SEREIN_HOST","outpost_identity":"OUTPOST/SEREIN_HOST","previous_boot_id":"11111111-2222-4333-8444-555555555555","new_boot_id":new_boot,"last_observed_at":10.0,"first_post_boot_at":20.0,"observed_at":21.0,"witness_mode":witness,"post_boot":{"readiness":readiness,"failed_components":[] if readiness=="VERIFIED" else ["host-gate"],"trust_changes":[],"capability_changes":[]},"evidence_ref":"outpost://events/reboot-1","policy_version":"public-v1"}
    return {**value,"evidence_digest":hashlib.sha256(canonical(value)).hexdigest()}

def intent(subject="SEREIN_HOST", consumed=False):
    return {"schema":"SereinAuthorizedPowerIntent/v1","intent_id":"intent-1","subject":subject,"actor":"OPERATOR","requested_at":9.0,"not_before":19.0,"not_after":25.0,"action":"REBOOT","authorization_ref":"operator://intent-1","completion_evidence_ref":"done","consumed":consumed}

def test_expected_cause_and_recovery_are_independent():
    value=classify_reboot(observation(readiness="DEGRADED"),intent())
    assert value["cause"]=="EXPECTED_REBOOT" and value["recovery"]=="BOOT_RECOVERY_DEGRADED" and value["alert_required"]

def test_unexpected_and_unknown_remain_distinct():
    assert classify_reboot(observation(),None)["cause"]=="UNEXPECTED_REBOOT"
    assert classify_reboot(observation(witness="SUBJECT_SELF_REPORT_ONLY"),None)["cause"]=="REBOOT_CAUSE_UNKNOWN"

def test_chronology_is_durable_idempotent_and_detects_conflicts(tmp_path):
    path=tmp_path/"chronology.jsonl"; log=VitalityChronology(path)
    first=log.append("host-1","OUTPOST_HOST_VITAL","SEREIN_HOST",1.0,{"state":"PASS"})
    assert VitalityChronology(path).read()[0]["event_hash"]==first["event_hash"]
    assert log.append("host-1","OUTPOST_HOST_VITAL","SEREIN_HOST",1.0,{"state":"PASS"})["append_disposition"]=="IDEMPOTENT_REPLAY"
    with pytest.raises(RebootVitalityError,match="CONTRADICTION_HOLD"): log.append("host-1","OUTPOST_HOST_VITAL","SEREIN_HOST",1.0,{"state":"FAIL"})

def test_chronology_tamper_fails_before_append(tmp_path):
    path=tmp_path/"chronology.jsonl"; log=VitalityChronology(path); log.append("e1","OUTPOST_HOST_VITAL","SEREIN_HOST",1.0,{"state":"PASS"})
    row=json.loads(path.read_text()); row["payload"]["state"]="FAIL"; path.write_text(json.dumps(row)+"\n")
    with pytest.raises(RebootVitalityError,match="CHAIN_DENIED"): log.append("e2","OUTPOST_HOST_VITAL","SEREIN_HOST",2.0,{})
