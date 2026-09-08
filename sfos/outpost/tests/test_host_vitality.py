import json
import pytest
from outpost.host_vitality import HostVitalityError,HostVitalityStore,apply_debian_plan,build_debian_plan,digest

def observation(boot="11111111-2222-4333-8444-555555555555",gpu=True):
 body={"schema":"SereinOutpostHostVitalityObservation/v1","target":"SEREIN_HOST","boot_id":boot,"observed_at":1.0,"host":{"hostname":"serein-host","os_id":"debian","os_version_id":"13","machine_id":"machine","status":"PASS"},"gpu":{"pci_present":gpu,"driver_loaded":gpu,"device_count":1 if gpu else 0,"driver_packages":{"nvidia-driver":"x"},"status":"PASS" if gpu else "FAIL"},"debian":{"release":"trixie","release_sha256":"a"*64,"signer_fingerprint":"b"*64,"repositories":["deb.debian.org","security.debian.org"],"installed_identity":{"source":"dpkg-status"},"installed_packages":{"base-files":"13.6"},"repository_packages":{"base-files":"13.7"},"exact_diff":[{"package":"base-files","installed":"13.6","candidate":"13.7"}],"pins":[],"exceptions":[],"unknowns":[],"correction_result":"PENDING","status":"PASS"}}
 return {**body,"evidence_digest":digest(body)}
def test_persists_current_previous_boot_and_ecg(tmp_path):
 store=HostVitalityStore(tmp_path);first=store.record(observation());assert first["classification"]=="FIRST_BOOT_OBSERVED"
 same=store.record(observation());assert same["classification"]=="CURRENT_BOOT_STABLE"
 changed=store.record(observation("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"));assert changed["classification"]=="RECOVERED_AFTER_BOOT_CHANGE" and changed["previous_boot_id"]==first["current_boot_id"]
 assert len((tmp_path/"ecg.jsonl").read_text().splitlines())==3 and store.snapshot()==changed
def test_drift_and_malformed_state_fail_closed(tmp_path):
 store=HostVitalityStore(tmp_path);assert store.record(observation(gpu=False))["classification"]=="DRIFT_DETECTED"
 (tmp_path/"state.json").write_text("{}");
 with pytest.raises(HostVitalityError,match="STATE_DENIED"):store.snapshot()
def test_forged_observation_has_no_persistent_effect(tmp_path):
 value=observation();value["gpu"]["device_count"]=9;store=HostVitalityStore(tmp_path)
 with pytest.raises(HostVitalityError,match="DIGEST_DENIED"):store.record(value)
 assert list(tmp_path.iterdir())==[]
def test_signed_debian_plan_is_allowlisted_transactional_and_gpu_preserving():
 current=observation();plan=build_debian_plan(current,{"base-files":"13.7"},{"base-files":"13.7","libc6":"2.41"},"req-1")
 class Adapter:
  def __init__(self):self.calls=[]
  def prepare(self,p):self.calls.append("prepare");return {"before":"exact"}
  def apply(self,p):self.calls.append("apply")
  def observe(self):
   self.calls.append("observe");value=observation();value["debian"]["installed_packages"]={"base-files":"13.7","libc6":"2.41"};value["debian"]["exact_diff"]=[];value["debian"]["correction_result"]="VERIFIED";body={k:v for k,v in value.items() if k!="evidence_digest"};value["evidence_digest"]=digest(body);return value
  def rollback(self,p):self.calls.append("rollback")
 adapter=Adapter();assert apply_debian_plan(plan,current,adapter)["status"]=="VERIFIED";assert adapter.calls==["prepare","apply","observe"]
 bad=dict(plan);bad["repository_hosts"]=["example.com"];bad["plan_digest"]=digest({k:v for k,v in bad.items() if k!="plan_digest"})
 with pytest.raises(HostVitalityError):apply_debian_plan(bad,current,adapter)
 assert adapter.calls==["prepare","apply","observe"]
def test_debian_postchange_drift_rolls_back():
 current=observation();plan=build_debian_plan(current,{"base-files":"13.7"},{"base-files":"13.7"},"req-2")
 class Adapter:
  def __init__(self):self.rolled=False
  def prepare(self,p):return {"before":"exact"}
  def apply(self,p):pass
  def observe(self):return observation(gpu=False)
  def rollback(self,p):self.rolled=True
 adapter=Adapter()
 with pytest.raises(HostVitalityError,match="POSTCHANGE"):apply_debian_plan(plan,current,adapter)
 assert adapter.rolled
