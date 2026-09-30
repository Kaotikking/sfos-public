import json
import pytest

from outpost.host_vitality import HostVitalityStore, HostCollectionAttempts, digest
from outpost.http_readonly import present
from outpost.vitals_edge import _ready
from outpost import vitals_edge
from outpost.vitals_runtime import VitalsRuntimeStore
from outpost.reboot_vitality import classify_reboot, _digest, VitalityChronology
from outpost.vitals_aggregation import producer_observation
from tests.active_host import active_host
from tests.test_reboot_vitality import observation as reboot_observation
from tests.test_reboot_vitality import intent as reboot_intent


BOOT = "11111111-2222-4333-8444-555555555555"


def chronology_checkpoint(tmp_path, *, advance=False, corruption=None):
    producers = tmp_path / "vitals-producers"
    producers.mkdir()
    chronology = VitalityChronology(tmp_path / "watchdog/chronology.jsonl")
    chronology.append("first", "OUTPOST_WATCHDOG", "SEREIN_HOST", 1.0,
                      {"boot_id": BOOT, "observed_at": 1.0})
    checkpoint = chronology.read()[0]
    payload = {"event_count": 1, "latest_event": checkpoint}
    boot, observed, reference = BOOT, 1.0, "chronology:" + checkpoint["event_hash"]
    if advance:
        chronology.append("second", "OUTPOST_WATCHDOG", "SEREIN_HOST", 2.0,
                          {"boot_id": BOOT, "observed_at": 2.0})
    if corruption == "zero": payload["event_count"] = 0
    elif corruption == "bool": payload["event_count"] = True
    elif corruption == "forward": payload["event_count"] = 3
    elif corruption == "event": payload["latest_event"] = {**checkpoint, "event_id": "forged"}
    elif corruption == "reference": reference = "chronology:" + "0" * 64
    elif corruption == "boot": boot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    elif corruption == "time": observed = 2.0
    elif corruption == "tail":
        with chronology.path.open("ab") as stream: stream.write(b"broken")
    value = producer_observation(perspective="outpost", producer="OUTPOST_VITALITY_CHRONOLOGY",
        claim="CHRONOLOGY_OBSERVED", observed_at=observed, boot_id=boot,
        evidence_ref=reference, payload=payload)
    (producers / "outpost-chronology.json").write_text(json.dumps(value))
    runtime = VitalsRuntimeStore(tmp_path / "host", producers, tmp_path / "domains", tmp_path / "recovery")
    return runtime, value


@pytest.mark.parametrize("advance", [False, True])
def test_chronology_checkpoint_survives_concurrent_append(tmp_path, advance):
    runtime, expected = chronology_checkpoint(tmp_path, advance=advance)
    actual = next(row for row in runtime._producers(BOOT, 3.0)["outpost"]
                  if row["producer"] == "OUTPOST_VITALITY_CHRONOLOGY")
    assert actual == expected
    assert actual["payload"]["event_count"] == 1
    assert actual["observed_at"] == 1.0


@pytest.mark.parametrize("corruption", ["zero", "bool", "forward", "event", "reference", "boot", "time", "tail"])
@pytest.mark.parametrize("advance", [False, True])
def test_chronology_checkpoint_rejects_invalid_binding(tmp_path, corruption, advance):
    runtime, _ = chronology_checkpoint(tmp_path, advance=advance, corruption=corruption)
    actual = next(row for row in runtime._producers(BOOT, 3.0)["outpost"]
                  if row["producer"] == "OUTPOST_VITALITY_CHRONOLOGY")
    assert actual["claim"] == "PRODUCER_EVIDENCE_UNAVAILABLE"


def test_file_producer_cannot_impersonate_reserved_host_witness(tmp_path):
    producers=tmp_path/"producers";producers.mkdir()
    forged=producer_observation(perspective="host",producer="OUTPOST_HOST_WITNESS",
        claim="PASS",observed_at=1.0,boot_id=BOOT,evidence_ref="invented",payload={})
    (producers/"pretend-host.json").write_text(json.dumps(forged))
    runtime=VitalsRuntimeStore(tmp_path/"host",producers,tmp_path/"domains.json",tmp_path/"recovery.json")
    snapshot=runtime.snapshot(current_boot_id=BOOT)
    host=snapshot["sections"]["host"]["perspectives"]
    assert len(host)==1 and host[0]["claim"]=="HOST_WITNESS_UNAVAILABLE"
    assert any(row["claim"]=="PRODUCER_EVIDENCE_UNAVAILABLE" for row in snapshot["sections"]["outpost"]["perspectives"])


def test_empty_domain_dict_is_not_native_domain_evidence(tmp_path):
    domains=tmp_path/"domains.json";domains.write_text("{}")
    runtime=VitalsRuntimeStore(tmp_path/"host",tmp_path/"producers",domains,tmp_path/"recovery.json")
    assert runtime.snapshot(current_boot_id=BOOT)["sections"]["domains"]["claim"]=="DOMAIN_STATE_UNAVAILABLE"


def test_unknown_producer_files_cannot_expand_intake(tmp_path):
    producers=tmp_path/"producers";producers.mkdir()
    for index in range(20):(producers/f"unknown-{index}.json").write_text("{}")
    runtime=VitalsRuntimeStore(tmp_path/"host",producers,tmp_path/"domains.json",tmp_path/"recovery.json")
    sources=runtime._producers(BOOT,1.0)
    assert len(sources["outpost"])==2


@pytest.mark.parametrize("failure",["absent","corrupt","stale"])
def test_vitals_remains_readable_when_host_witness_is_unavailable(tmp_path,failure,monkeypatch):
    host=tmp_path/"host";host.mkdir()
    if failure=="corrupt":(host/"state.json").write_text("{}")
    if failure=="stale":
        body={"target":"SEREIN_HOST","boot_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","observed_at":1.0,"host":{"hostname":"host","os_id":"debian","os_version_id":"13","machine_id":"m","status":"PASS"},"gpu":{"pci_present":True,"driver_loaded":True,"device_count":1,"driver_packages":{"nvidia-driver":"x"},"status":"PASS"}}
        HostVitalityStore(host).record(active_host(body))
    runtime=VitalsRuntimeStore(host,tmp_path/"producers",tmp_path/"domains.json",tmp_path/"recovery.json")
    page=present(runtime,"GET","/v1/runtime/status","text/html",BOOT)
    api=present(runtime,"GET","/v1/runtime/status","application/json",BOOT)
    assert page.status==api.status==200
    assert not _ready(api.body)
    monkeypatch.setattr(vitals_edge,"_presentation",lambda *_:(api.status,api.content_type,[],api.body))
    assert vitals_edge.edge_response("GET","/health/ready","application/json")[0]==200
    state=json.loads(api.body)
    assert state["current_boot_id"]==BOOT
    assert "Serein Vitals" in page.body.decode() and "HOLD_INTENTIONAL" in page.body.decode()
    assert "Conflicting Host evidence: NONE OBSERVED" in page.body.decode()
    assert "CONFLICT — DO NOT ACT" not in page.body.decode()
    assert state["sections"]["host"]["claim"] not in {"FIRST_BOOT_OBSERVED","CURRENT_BOOT_STABLE","RECOVERED_AFTER_BOOT_CHANGE"}
    if failure=="stale":assert state["sections"]["host"]["perspectives"][0]["payload"]["last_successful_observation"]["current_boot_id"]!=BOOT
    assert state["authority_effect"]==state["admission_effect"]==state["mutation_effect"]=="NONE"


def test_broken_downstream_evidence_does_not_disable_vitals(tmp_path):
    producers=tmp_path/"producers";producers.mkdir();(producers/"gateway.json").write_text("not JSON")
    domains=tmp_path/"domains.json";domains.write_text("not JSON")
    runtime=VitalsRuntimeStore(tmp_path/"host",producers,domains,tmp_path/"recovery.json")
    response=present(runtime,"GET","/v1/runtime/status","application/json",BOOT)
    assert response.status==200
    state=json.loads(response.body)
    assert state["sections"]["domains"]["claim"]=="DOMAIN_STATE_UNAVAILABLE"
    assert any(row["claim"]=="PRODUCER_EVIDENCE_UNAVAILABLE" for row in state["sections"]["outpost"]["perspectives"])


@pytest.mark.parametrize("gateway_evidence", ["absent", "corrupt"])
def test_edge_readback_survives_missing_or_invalid_gateway_evidence(tmp_path,monkeypatch,gateway_evidence):
    producers=tmp_path/"producers";producers.mkdir()
    if gateway_evidence=="corrupt":
        (producers/"gateway.json").write_text("not JSON")
    runtime=VitalsRuntimeStore(tmp_path/"host",producers,tmp_path/"domains.json",tmp_path/"recovery.json")
    def presentation(method,path,accept):
        response=present(runtime,method,path,accept,BOOT)
        return response.status,response.content_type,list(response.headers),response.body
    monkeypatch.setattr(vitals_edge,"_presentation",presentation)
    assert vitals_edge.edge_response("GET","/health/ready","application/json")[0]==200
    status,_,_,body=vitals_edge.edge_response("GET","/v1/runtime/status","application/json")
    assert status==200 and not _ready(body)
    state=json.loads(body)
    assert state["sections"]["serein"]["state"]=="UNKNOWN"
    assert state["admission_effect"]==state["mutation_effect"]=="NONE"
    status,content_type,_,page=vitals_edge.edge_response("GET","/v1/runtime/status","text/html")
    assert status==200 and content_type.startswith("text/html") and b"Serein Vitals" in page
    assert vitals_edge.edge_response("POST","/v1/voice/conversation","application/json")[0]==405


def test_recovery_evidence_retains_its_observed_boot(tmp_path):
    recovery=tmp_path/"recovery.json"
    recovery.write_text(json.dumps(classify_reboot(reboot_observation())))
    runtime=VitalsRuntimeStore(tmp_path/"host",tmp_path/"producers",tmp_path/"domains.json",recovery)
    section=runtime.snapshot(current_boot_id=BOOT)["sections"]["recovery"]
    assert section["claim"] is None and section["perspectives"][0]["freshness"]=="STALE"


def test_untrusted_reboot_evidence_roundtrips_through_vitals_as_unknown(tmp_path):
    recovery=tmp_path/"recovery.json"
    value=classify_reboot(reboot_observation(), reboot_intent())
    recovery.write_text(json.dumps(value))
    runtime=VitalsRuntimeStore(tmp_path/"host",tmp_path/"producers",tmp_path/"domains.json",recovery)
    section=runtime.snapshot(current_boot_id=value["new_boot_id"])["sections"]["recovery"]
    assert section["perspectives"][0]["payload"]["cause"]=="REBOOT_CAUSE_UNKNOWN"
    assert section["perspectives"][0]["payload"]["intent_evidence"]==reboot_intent()
    assert section["perspectives"][0]["payload"]["mutation_effect"]=="NONE"


def test_operator_sees_boot_recovery_facts_without_opening_raw_logs(tmp_path):
    recovery=tmp_path/"recovery.json"
    value=classify_reboot(reboot_observation(readiness="DEGRADED"),reboot_intent())
    recovery.write_text(json.dumps(value))
    runtime=VitalsRuntimeStore(tmp_path/"host",tmp_path/"producers",tmp_path/"domains.json",recovery)
    response=present(runtime,"GET","/v1/runtime/status","text/html",value["new_boot_id"])
    assert response.status==200
    page=response.body.decode()
    for expected in ("Subject: SEREIN_HOST", "Cause: REBOOT_CAUSE_UNKNOWN", "Recovery: BOOT_RECOVERY_DEGRADED",
                     "Last seen: 1970-01-01T00:00:10Z", "Returned: 1970-01-01T00:00:20Z",
                     "Intent match: UNVERIFIED_GOVERNANCE_EVIDENCE", "Failed to return: host-gate", "Observation only; no repair is authorized"):
        assert expected in page


@pytest.mark.parametrize("corruption", ["digest", "derived_recovery", "shape"])
def test_vitals_rejects_invalid_recovery_classification_without_hiding_page(tmp_path, corruption):
    value = classify_reboot(reboot_observation(readiness="DEGRADED", new_boot=BOOT))
    if corruption == "digest":
        value["classification_digest"] = "0" * 64
    elif corruption == "derived_recovery":
        value["recovery"] = "BOOT_RECOVERY_VERIFIED"
        value["classification_digest"] = _digest({k:v for k,v in value.items() if k != "classification_digest"})
    else:
        value = {"new_boot_id": BOOT, "recovery": "BOOT_RECOVERY_VERIFIED"}
    recovery = tmp_path / "recovery.json"
    recovery.write_text(json.dumps(value))
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"producers", tmp_path/"domains.json", recovery)
    response = present(runtime, "GET", "/v1/runtime/status", "application/json", BOOT)
    assert response.status == 200
    section = json.loads(response.body)["sections"]["recovery"]
    assert section["claim"] == "RECOVERY_EVIDENCE_UNAVAILABLE"


def test_vitals_runtime_reports_registry_hold_without_seed_admission(tmp_path):
    body = {
        "schema": "SereinOutpostHostVitalityObservation/v2", "target": "VM4010", "boot_id": BOOT,
        "observed_at": 1.0,
        "host": {"hostname": "serein-vm4010", "os_id": "debian", "os_version_id": "13", "machine_id": "m", "status": "PASS"},
        "gpu": {"pci_present": True, "driver_loaded": True, "device_count": 1, "driver_packages": {}, "status": "PASS"},
        "public_base": {"repository":"Kaotikking/sfos-public","commit":"a"*40,"tree":"b"*40,"lock_path":"sfos/base/packages.lock","lock_sha256":"a"*64,"policy_path":"sfos/base/installer/base-policy.json","policy_sha256":"b"*64,"expected_packages":{},"observed_packages":{},"exact_diff":[],"unknowns":[],"status":"PASS"},
    }
    attempts=HostCollectionAttempts(tmp_path/"host")
    attempt=attempts.start(BOOT,0.0)
    saved=HostVitalityStore(tmp_path / "host").record(active_host(body))
    attempts.finish(attempt,2.0,state=saved)
    runtime = VitalsRuntimeStore(tmp_path / "host", tmp_path / "producers", tmp_path / "domains.json", tmp_path / "recovery.json")
    snapshot = runtime.snapshot()
    registry = next(row["payload"] for row in snapshot["sections"]["outpost"]["perspectives"] if row["producer"] == "OUTPOST_CONSTITUTIONAL_REGISTRY")
    assert registry["registry_state"] == "HOLD_INTENTIONAL"
    assert all(row["admission"] == "DENIED_HELD_SEED_CONTENT" for row in registry["seeds"])
    page = present(runtime, "GET", "/v1/runtime/status", "text/html", BOOT)
    assert page.status == 200 and "HOLD_INTENTIONAL" in page.body.decode()
    rendered=page.body.decode()
    assert "Host: PASS" in rendered and "GPU: PASS" in rendered
    assert "Classification: FIRST_BOOT_OBSERVED" in rendered
    assert "OUTPOST_CONSTITUTIONAL_REGISTRY" in rendered
    assert "OUTPOST_WATCHDOG" in rendered and "PRODUCER_EVIDENCE_UNAVAILABLE" in rendered


def test_missing_producer_directory_names_both_missing_native_witnesses(tmp_path):
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"absent", tmp_path/"domains", tmp_path/"recovery")
    rows = runtime.snapshot(current_boot_id=BOOT)["sections"]["outpost"]["perspectives"]
    missing = {row["producer"] for row in rows if row["claim"] == "PRODUCER_EVIDENCE_UNAVAILABLE"}
    assert missing == {"OUTPOST_WATCHDOG", "OUTPOST_VITALITY_CHRONOLOGY"}


@pytest.mark.parametrize("field,replacement", [("subject", "OTHER_HOST"), ("outpost_identity", "OTHER_OUTPOST")])
def test_recovery_for_another_identity_is_not_this_runtime_evidence(tmp_path, field, replacement):
    observed = reboot_observation(new_boot=BOOT)
    observed[field] = replacement
    observed["evidence_digest"] = _digest({k:v for k,v in observed.items() if k != "evidence_digest"})
    recovery = tmp_path/"recovery.json"
    recovery.write_text(json.dumps(classify_reboot(observed)))
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"producers", tmp_path/"domains", recovery)
    assert runtime.snapshot(current_boot_id=BOOT)["sections"]["recovery"]["claim"] == "RECOVERY_EVIDENCE_UNAVAILABLE"


def test_persisted_verified_recovery_without_profile_is_unavailable(tmp_path):
    value = classify_reboot(reboot_observation(new_boot=BOOT))
    value["post_boot"].update(readiness="VERIFIED", failed_components=[])
    value["recovery"] = "BOOT_RECOVERY_VERIFIED"
    fields = ("event_id", "subject", "outpost_identity", "previous_boot_id", "new_boot_id", "last_observed_at", "first_post_boot_at", "observed_at", "witness_mode", "post_boot", "evidence_ref", "policy_version")
    value["evidence_digest"] = _digest({"schema":"SereinOutpostRebootObservation/v1", **{k:value[k] for k in fields}})
    value["classification_digest"] = _digest({k:v for k,v in value.items() if k != "classification_digest"})
    recovery = tmp_path/"recovery.json"
    recovery.write_text(json.dumps(value))
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"producers", tmp_path/"domains", recovery)
    response = present(runtime, "GET", "/v1/runtime/status", "application/json", BOOT)
    assert response.status == 200
    assert json.loads(response.body)["sections"]["recovery"]["claim"] == "RECOVERY_EVIDENCE_UNAVAILABLE"


@pytest.mark.parametrize("failure", ["failed", "incomplete", "corrupt"])
def test_html_separates_latest_failed_attempt_from_historical_success(tmp_path, failure):
    from tests.test_host_vitality import observation
    host=tmp_path/"host"
    saved=HostVitalityStore(host).record(observation())
    attempts=HostCollectionAttempts(host)
    identifier=attempts.start(BOOT,2.0)
    if failure=="failed":
        attempts.finish(identifier,3.0,error_code="DEBIAN_INRELEASE_SIGNATURE_DENIED")
    elif failure=="corrupt":
        with (host/"collection-attempts.jsonl").open("ab") as stream:stream.write(b"broken")
    runtime=VitalsRuntimeStore(host,tmp_path/"producers",tmp_path/"domain",tmp_path/"recovery")
    response=present(runtime,"GET","/v1/runtime/status","text/html",BOOT)
    assert response.status==200
    page=response.body.decode()
    assert {"failed":"HOST_COLLECTION_FAILED","incomplete":"HOST_COLLECTION_INCOMPLETE","corrupt":"HOST_ATTEMPT_EVIDENCE_UNAVAILABLE"}[failure] in page
    assert "Last successful observation — HISTORICAL ONLY" in page
    assert "not current Host verification" in page
    assert "Historical classification: FIRST_BOOT_OBSERVED" in page
    assert "1970-01-01T00:00:01Z" in page and saved["projection_digest"] in page
    assert "<p>Host: UNKNOWN</p>" in page and "<p>GPU: UNKNOWN</p>" in page
    assert "Outpost observes no current Host-gate degradation" not in page
    if failure=="failed":assert "Failure code: DEBIAN_INRELEASE_SIGNATURE_DENIED" in page
