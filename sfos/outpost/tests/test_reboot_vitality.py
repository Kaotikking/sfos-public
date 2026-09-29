import hashlib
import json
import pytest
from outpost.reboot_vitality import RebootVitalityError, VitalityChronology, canonical, classify_reboot
from outpost import reboot_vitality

def observation(readiness="UNKNOWN", witness="POST_BOOT_INFERRED_REBOOT", new_boot="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"):
    value={"schema":"SereinOutpostRebootObservation/v1","event_id":"reboot-1","subject":"SEREIN_HOST","outpost_identity":"OUTPOST/SEREIN_HOST","previous_boot_id":"11111111-2222-4333-8444-555555555555","new_boot_id":new_boot,"last_observed_at":10.0,"first_post_boot_at":20.0,"observed_at":21.0,"witness_mode":witness,"post_boot":{"readiness":readiness,"failed_components":[] if readiness=="VERIFIED" else ["host-gate"],"trust_changes":[],"capability_changes":[]},"evidence_ref":"outpost://events/reboot-1","policy_version":"public-v1"}
    return {**value,"evidence_digest":hashlib.sha256(canonical(value)).hexdigest()}

def intent(subject="SEREIN_HOST", consumed=False):
    return {"schema":"SereinAuthorizedPowerIntent/v1","intent_id":"intent-1","subject":subject,"actor":"OPERATOR","requested_at":9.0,"not_before":19.0,"not_after":25.0,"action":"REBOOT","authorization_ref":"operator://intent-1","completion_evidence_ref":"done","consumed":consumed}

def test_untrusted_intent_cannot_authorize_and_recovery_is_independent():
    value=classify_reboot(observation(readiness="DEGRADED"),intent())
    assert value["cause"]=="REBOOT_CAUSE_UNKNOWN" and value["recovery"]=="BOOT_RECOVERY_DEGRADED" and value["alert_required"]

@pytest.mark.parametrize("mode", sorted(reboot_vitality.WITNESS_MODES))
def test_missing_ledger_is_unknown_even_with_a_proven_transition(mode):
    value = classify_reboot(observation(witness=mode), None)
    assert value["cause"] == "REBOOT_CAUSE_UNKNOWN"
    assert value["witness_mode"] == mode


@pytest.mark.parametrize("reported_intent", [intent(), intent(consumed=True), intent(subject="OTHER_HOST"), dict(intent(), not_after=19)])
def test_local_replayed_expired_or_wrong_subject_intent_never_authorizes(reported_intent):
    assert classify_reboot(observation(), reported_intent)["cause"] == "REBOOT_CAUSE_UNKNOWN"


def test_noncanonical_witness_mode_is_rejected():
    with pytest.raises(RebootVitalityError, match="WITNESS_MODE_DENIED"):
        classify_reboot(observation(witness="OUTPOST_BOOT_ID_CHANGE"))

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


def test_chronology_completes_short_writes(monkeypatch, tmp_path):
    original_write = reboot_vitality.os.write
    monkeypatch.setattr(reboot_vitality.os, "write", lambda fd, data: original_write(fd, data[:max(1, len(data)//2)]))
    log = VitalityChronology(tmp_path/"chronology.jsonl")
    event = log.append("e1", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1.0, {"watchdog_state": "DEGRADED"})
    assert log.read()[0]["event_hash"] == event["event_hash"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_chronology_nonfinite_payload_is_denied_before_creation(tmp_path, value):
    path = tmp_path / "not-created" / "chronology.jsonl"
    with pytest.raises(RebootVitalityError):
        VitalityChronology(path).append("event", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {"nested": [value]})
    assert not path.parent.exists()


@pytest.mark.parametrize("nested", [False, True])
def test_chronology_duplicate_json_keys_preserved_and_denied(tmp_path, nested):
    path = tmp_path / "chronology.jsonl"
    log = VitalityChronology(path)
    log.append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {"state": "UNKNOWN"})
    original = path.read_bytes()
    if nested:
        changed = original.replace(b'"state":"UNKNOWN"', b'"state":"PASS","state":"UNKNOWN"')
    else:
        changed = original.replace(b'"event_id":"first"', b'"event_id":"other","event_id":"first"')
    assert changed != original
    # The permissive parser sees the same surviving values and original hash.
    assert json.loads(changed) == json.loads(original)
    path.write_bytes(changed)
    with pytest.raises(RebootVitalityError):
        log.read()
    with pytest.raises(RebootVitalityError):
        log.append("second", "OUTPOST_WATCHDOG", "SEREIN_HOST", 2, {})
    assert path.read_bytes() == changed


def test_persisted_unknown_reboot_retains_untrusted_intent_evidence():
    original_intent = intent()
    value = classify_reboot(observation(), original_intent)
    assert value["intent_evidence"] == original_intent
    assert reboot_vitality.validate_classification(json.loads(json.dumps(value))) == value
    assert reboot_vitality.validate_classification(value, original_intent) == value
    without_intent = dict(value, intent_evidence=None)
    without_intent["classification_digest"] = reboot_vitality._digest({k:v for k,v in without_intent.items() if k!="classification_digest"})
    with pytest.raises(RebootVitalityError, match="DERIVATION_DENIED"):
        reboot_vitality.validate_classification(without_intent)


@pytest.mark.parametrize("timestamp", [True, -1, float("inf"), float("nan")])
def test_invalid_chronology_time_is_rejected_without_file_write(tmp_path, timestamp):
    path=tmp_path/"chronology.jsonl"
    with pytest.raises(RebootVitalityError, match="INPUT_DENIED"):
        VitalityChronology(path).append("event", "OUTPOST_WATCHDOG", "SEREIN_HOST", timestamp, {})
    assert not path.exists()


def test_recovery_verified_label_cannot_hide_failed_components():
    value=observation(readiness="VERIFIED")
    value["post_boot"]["failed_components"]=["HOST_GATE"]
    value["evidence_digest"]=hashlib.sha256(canonical({k:v for k,v in value.items() if k!="evidence_digest"})).hexdigest()
    with pytest.raises(RebootVitalityError, match="RECOVERY_VALUE_DENIED"):
        classify_reboot(value)


def test_empty_failure_list_does_not_prove_complete_recovery():
    with pytest.raises(RebootVitalityError, match="RECOVERY_DENOMINATOR_UNAVAILABLE"):
        classify_reboot(observation(readiness="VERIFIED"))


def test_chronology_busy_never_appends_around_an_existing_writer(tmp_path):
    import fcntl
    path = tmp_path/"chronology.jsonl"
    log = VitalityChronology(path)
    log.append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {})
    before = path.read_bytes()
    with path.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RebootVitalityError, match="CHRONOLOGY_BUSY"):
            log.append("second", "OUTPOST_WATCHDOG", "SEREIN_HOST", 2, {})
        with pytest.raises(RebootVitalityError, match="CHRONOLOGY_BUSY"):
            log.read()
    assert path.read_bytes() == before
    assert log.append("second", "OUTPOST_WATCHDOG", "SEREIN_HOST", 2, {})["sequence"] == 2


@pytest.mark.parametrize("redirect", ["symlink", "hardlink", "parent_symlink"])
def test_chronology_rejects_redirected_files_without_modifying_target(tmp_path, redirect):
    import os
    real = tmp_path/"real"
    real.mkdir()
    target = real/"chronology.jsonl"
    VitalityChronology(target).append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {})
    before = target.read_bytes()
    alias = tmp_path/"alias"
    if redirect == "symlink": alias.symlink_to(target)
    elif redirect == "hardlink": os.link(target, alias)
    else:
        alias.symlink_to(real, target_is_directory=True)
        alias = alias/"chronology.jsonl"
    with pytest.raises(RebootVitalityError, match="CUSTODY_DENIED"):
        VitalityChronology(alias).append("second", "OUTPOST_WATCHDOG", "SEREIN_HOST", 2, {})
    assert target.read_bytes() == before


def test_chronology_partial_record_is_preserved_and_append_is_denied(tmp_path):
    path = tmp_path/"chronology.jsonl"
    log = VitalityChronology(path)
    log.append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {})
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    before = path.read_bytes()
    with pytest.raises(RebootVitalityError, match="INCOMPLETE_RECORD"):
        log.append("second", "OUTPOST_WATCHDOG", "SEREIN_HOST", 2, {})
    assert path.read_bytes() == before


@pytest.mark.parametrize("field,value", [("sequence", True), ("observed_at", -1), ("event_id", []), ("payload", [])])
def test_valid_digest_does_not_make_malformed_chronology_valid(tmp_path, field, value):
    path = tmp_path/"chronology.jsonl"
    log = VitalityChronology(path)
    log.append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {})
    record = json.loads(path.read_text())
    record[field] = value
    record["event_hash"] = reboot_vitality._digest({k:v for k,v in record.items() if k != "event_hash"})
    path.write_bytes(canonical(record))
    before = path.read_bytes()
    with pytest.raises(RebootVitalityError):
        log.append("second", "OUTPOST_WATCHDOG", "SEREIN_HOST", 2, {})
    assert path.read_bytes() == before


def test_chronology_flushes_file_then_new_directory_chain_before_ack(monkeypatch, tmp_path):
    import os
    import stat
    path = tmp_path / "new" / "nested" / "chronology.jsonl"
    flushed = []
    original = os.fsync
    def observe(fd):
        info = os.fstat(fd)
        flushed.append((stat.S_ISDIR(info.st_mode), info.st_dev, info.st_ino))
        original(fd)
    monkeypatch.setattr(reboot_vitality.os, "fsync", observe)
    result = VitalityChronology(path).append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {})
    assert result["append_disposition"] == "APPENDED"
    assert flushed[0][0] is False
    expected = [(True, parent.stat().st_dev, parent.stat().st_ino)
                for parent in (path.parent, path.parent.parent, tmp_path)]
    assert flushed[1:4] == expected


def test_chronology_failed_directory_flush_is_not_acknowledged_even_on_replay(monkeypatch, tmp_path):
    import os
    import stat
    path = tmp_path / "new" / "chronology.jsonl"
    log = VitalityChronology(path)
    original = os.fsync
    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected directory flush failure")
        original(fd)
    monkeypatch.setattr(reboot_vitality.os, "fsync", fail_directory)
    with pytest.raises(OSError, match="injected directory flush"):
        log.append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {})
    evidence = path.read_bytes()
    with pytest.raises(OSError, match="injected directory flush"):
        log.append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {})
    assert path.read_bytes() == evidence
    monkeypatch.setattr(reboot_vitality.os, "fsync", original)
    result = log.append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1, {})
    assert result["append_disposition"] == "IDEMPOTENT_REPLAY"
    assert len(log.read()) == 1 and path.read_bytes() == evidence


def test_chronology_ancestor_swap_never_appends_to_redirected_target(monkeypatch, tmp_path):
    import os
    directory = tmp_path / "history"
    directory.mkdir()
    path = directory / "chronology.jsonl"
    outside = tmp_path / "unrelated"
    outside.mkdir()
    foreign = outside / path.name
    foreign_log = VitalityChronology(foreign)
    foreign_log.append("foreign", "OUTPOST_WATCHDOG", "OTHER_HOST", 1, {})
    before = foreign.read_bytes()
    original_open = os.open
    swapped = False
    def swap_before_log_open(name, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.fspath(name).endswith("chronology.jsonl") and flags & os.O_APPEND:
            swapped = True
            directory.rename(tmp_path / "retained-history")
            directory.symlink_to(outside, target_is_directory=True)
        return original_open(name, flags, *args, **kwargs)
    monkeypatch.setattr(reboot_vitality.os, "open", swap_before_log_open)
    with pytest.raises((RebootVitalityError, OSError)):
        VitalityChronology(path).append("new", "OUTPOST_WATCHDOG", "SEREIN_HOST", 2, {})
    assert swapped and foreign.read_bytes() == before
