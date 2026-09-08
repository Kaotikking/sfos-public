import html,json
from outpost.host_vitality import HostVitalityStore,digest
from outpost.http_readonly import present
def obs():
 body={"schema":"SereinOutpostHostVitalityObservation/v1","target":"SEREIN_HOST","boot_id":"11111111-2222-4333-8444-555555555555","observed_at":1.0,"host":{"hostname":"serein-host","os_id":"debian","os_version_id":"13","machine_id":"m","status":"PASS"},"gpu":{"pci_present":True,"driver_loaded":True,"device_count":1,"driver_packages":{"nvidia-driver":"x"},"status":"PASS"},"debian":{"release":"trixie","release_sha256":"a"*64,"signer_fingerprint":"b"*64,"repositories":["deb.debian.org"],"installed_identity":{"source":"dpkg-status"},"installed_packages":{"base-files":"13.6"},"repository_packages":{"base-files":"13.6"},"exact_diff":[],"pins":[],"exceptions":[],"unknowns":[],"correction_result":"NOT_REQUIRED","status":"PASS"}}
 return {**body,"evidence_digest":digest(body)}
def test_page_and_api_share_exact_canonical_snapshot_and_are_read_only(tmp_path):
 store=HostVitalityStore(tmp_path);snapshot=store.record(obs());boot=snapshot["current_boot_id"];api=present(store,"GET","/v1/runtime/status","application/json",boot);page=present(store,"GET","/v1/runtime/status","text/html",boot)
 assert api.status==page.status==200 and json.loads(api.body)==snapshot and html.escape(api.body.decode().strip()) in page.body.decode()
 assert snapshot["projection_digest"] in page.body.decode() and ("X-Content-Type-Options","nosniff") in api.headers
 rendered=page.body.decode()
 assert "<title>Serein Vitals</title>" in rendered and "<h1>Serein Vitals</h1>" in rendered
 for section in ("home","observed","identity","health","rescue","resume","domains","hardware","sereinnet","memory","evidence","controls"):
  assert f"id='{section}'" in rendered
 assert "Outpost Host observation" in rendered and "This is not Host self-report" in rendered
 assert "Recommendation is not authorization" in rendered and "No mutation controls are exposed" in rendered
 for heading in ("1. STATE","2. PERSPECTIVES","3. SAFE PATH","4. DECISION","5. STOP/WAKE"):
  assert heading in rendered
 assert "Evidence maturity: OBSERVED" in rendered and "Black-box event chronology: UNKNOWN" in rendered
 assert "Starting credit: UNKNOWN" in rendered and "Last-known-good reference: UNKNOWN" in rendered
 assert "Mission Control" not in rendered and "no source supplied" in rendered
 before=(tmp_path/"state.json").read_bytes()
 for method in ("POST","PUT","PATCH","DELETE"):assert present(store,method,"/v1/runtime/status","application/json",boot).status==405
 assert (tmp_path/"state.json").read_bytes()==before
def test_outpost_degraded_state_is_explained_without_authority(tmp_path):
 store=HostVitalityStore(tmp_path);value=obs();value["host"]["status"]="FAIL";body={k:v for k,v in value.items() if k!="evidence_digest"};value["evidence_digest"]=digest(body)
 snapshot=store.record(value);page=present(store,"GET","/v1/runtime/status","text/html",snapshot["current_boot_id"]);rendered=page.body.decode()
 assert snapshot["classification"]=="DRIFT_DETECTED" and "Conflicting Vitals: PRESENT" in rendered
 assert "separately authorized owning recovery road" in rendered and "cannot execute recovery" in rendered
def test_unavailable_unknown_and_no_listener_fail_closed(tmp_path):
 store=HostVitalityStore(tmp_path);boot="11111111-2222-4333-8444-555555555555";assert present(store,"GET","/v1/runtime/status","application/json",boot).status==503;assert present(store,"GET","/","application/json",boot).status==404;assert present(store,"GET","/other","application/json",boot).status==404
 import outpost.http_readonly as module
 assert not hasattr(module,"serve") and not hasattr(module,"HTTPServer")
def test_old_boot_snapshot_fails_closed(tmp_path):
 store=HostVitalityStore(tmp_path);snapshot=store.record(obs())
 result=present(store,"GET","/v1/runtime/status","application/json","aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
 assert result.status==503 and json.loads(result.body)=={"error":"VITALITY_STALE_BOOT"}
def test_serein_vitals_escapes_hostile_observation_fields(tmp_path):
 store=HostVitalityStore(tmp_path);value=obs();value["host"]["hostname"]="<script>alert(1)</script>";body={k:v for k,v in value.items() if k!="evidence_digest"};value["evidence_digest"]=digest(body)
 snapshot=store.record(value);rendered=present(store,"GET","/v1/runtime/status","text/html",snapshot["current_boot_id"]).body.decode()
 assert "<script>alert(1)</script>" not in rendered and "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
