import json
import pytest
from outpost.host_vitality import HostVitalityError,HostVitalityStore,HostCollectionAttempts,apply_debian_plan,build_debian_plan,digest,validate,validate_state,ADMITTED_PUBLIC_BASE_COMMIT,ADMITTED_PUBLIC_BASE_TREE

def observation(boot="11111111-2222-4333-8444-555555555555",gpu=True):
 body={"schema":"SereinOutpostHostVitalityObservation/v3","target":"SEREIN_HOST","boot_id":boot,"observed_at":1.0,"host":{"hostname":"serein-host","os_id":"debian","os_version_id":"13","machine_id":"machine","status":"PASS"},"gpu":{"pci_present":gpu,"driver_loaded":gpu,"device_count":1 if gpu else 0,"driver_packages":{"nvidia-driver":"x"},"status":"PASS" if gpu else "FAIL"},"debian":{"release":"trixie","release_sha256":"a"*64,"signer_fingerprint":"b"*64,"repositories":["deb.debian.org","security.debian.org"],"installed_identity":{"id":"debian","version_id":"13","pretty_name":"Debian GNU/Linux 13 (trixie)"},"installed_packages":{"base-files":"13.6"},"repository_packages":{"base-files":"13.7"},"exact_diff":[{"package":"base-files","installed":"13.6","candidate":"13.7"}],"pins":[],"exceptions":[],"unknowns":[],"correction_result":"PENDING","status":"PASS"},"public_base":{"repository":"Kaotikking/sfos-public","commit":"0dca6bd7a22b83b04ddf353df901d2c7ea15c294","tree":"8c56a80487f25150ffec90316a946ac89f64fb92","lock_path":"sfos/base/packages.lock","lock_sha256":"c"*64,"policy_path":"sfos/base/installer/base-policy.json","policy_sha256":"d"*64,"expected_packages":{"base-files":"13.6"},"observed_packages":{"base-files":"13.6"},"exact_diff":[],"unknowns":[],"status":"PASS"}}
 body["public_base"].update(commit=ADMITTED_PUBLIC_BASE_COMMIT,tree=ADMITTED_PUBLIC_BASE_TREE)
 body["debian"].update(repository_packages={"base-files":"13.6"},exact_diff=[],correction_result="NOT_REQUIRED")
 return {**body,"evidence_digest":digest(body)}


def test_older_terminal_does_not_mask_newer_started_attempt(tmp_path):
 attempts=HostCollectionAttempts(tmp_path)
 boot=observation()["boot_id"]
 older=attempts.start(boot,1.0)
 newer=attempts.start(boot,2.0)
 attempts.finish(older,3.0,error_code="DEBIAN_SOURCE_SET_DENIED")
 assert attempts.latest()["start"]["payload"]["attempt_id"]==newer
 assert attempts.latest()["terminal"] is None


def test_attempt_cannot_accept_stale_or_other_boot_success(tmp_path):
 attempts=HostCollectionAttempts(tmp_path)
 state=HostVitalityStore(tmp_path).record(observation())
 identifier=attempts.start(state["current_boot_id"],2.0)
 with pytest.raises(HostVitalityError,match="HOST_ATTEMPT_RESULT_DENIED"):
  attempts.finish(identifier,3.0,state=state)
 assert attempts.latest()["terminal"] is None


def test_attempt_cannot_be_completed_twice_or_accept_arbitrary_error_text(tmp_path):
 attempts=HostCollectionAttempts(tmp_path)
 identifier=attempts.start(observation()["boot_id"],0.0)
 with pytest.raises(HostVitalityError,match="HOST_ATTEMPT_RESULT_DENIED"):
  attempts.finish(identifier,1.0,error_code="private details here")
 attempts.finish(identifier,2.0,error_code="HOST_COLLECTION_UNAVAILABLE")
 with pytest.raises(HostVitalityError,match="HOST_ATTEMPT_SEQUENCE_DENIED"):
  attempts.finish(identifier,3.0,error_code="HOST_COLLECTION_UNAVAILABLE")

@pytest.mark.parametrize("contradiction", ["public_diff", "public_unknown", "public_package", "debian_diff", "debian_unknown", "pending", "installed_package", "empty_contract"])
def test_claimed_pass_cannot_override_contradictory_host_data(tmp_path, contradiction):
 value=observation();public=value["public_base"];debian=value["debian"]
 if contradiction=="public_diff":public["exact_diff"]=[{"package":"base-files","observed":"wrong"}]
 elif contradiction=="public_unknown":public["unknowns"]=["UNPROVEN"]
 elif contradiction=="public_package":public["observed_packages"]["base-files"]="wrong"
 elif contradiction=="debian_diff":debian["exact_diff"]=[{"package":"base-files","installed":"wrong"}]
 elif contradiction=="debian_unknown":debian["unknowns"]=["UNPROVEN"]
 elif contradiction=="pending":debian["correction_result"]="PENDING"
 elif contradiction=="installed_package":debian["installed_packages"]["base-files"]="wrong"
 elif contradiction=="empty_contract":public["expected_packages"]={};public["observed_packages"]={}
 value["evidence_digest"]=digest({key:item for key,item in value.items() if key!="evidence_digest"})
 result=HostVitalityStore(tmp_path).record(value)
 assert result["classification"]=="DRIFT_DETECTED"
 assert result["latest"]==value  # Preserve the disagreement as evidence.
@pytest.mark.parametrize("identity", [{}, {"id":"ubuntu","version_id":"13"},
 {"id":"debian","version_id":"12"}, {"id":"debian"},
 {"id":"debian","version_id":13}])
def test_claimed_pass_cannot_override_missing_or_conflicting_debian_identity(tmp_path, identity):
 value=observation();value["debian"]["installed_identity"]=identity
 value["evidence_digest"]=digest({key:item for key,item in value.items() if key!="evidence_digest"})
 result=HostVitalityStore(tmp_path).record(value)
 assert result["classification"]=="DRIFT_DETECTED"
 assert result["latest"]==value

def test_persists_current_previous_boot_and_ecg(tmp_path):
 store=HostVitalityStore(tmp_path);first=store.record(observation());assert first["classification"]=="FIRST_BOOT_OBSERVED"
 same=store.record(observation());assert same["classification"]=="CURRENT_BOOT_STABLE"
 changed=store.record(observation("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"));assert changed["classification"]=="RECOVERED_AFTER_BOOT_CHANGE" and changed["previous_boot_id"]==first["current_boot_id"]
 assert len((tmp_path/"ecg.jsonl").read_text().splitlines())==3 and store.snapshot()==changed
def test_admits_existing_vm4010_host_witness_without_rewriting_identity(tmp_path):
 value=observation();value["target"]="VM4010";body={key:item for key,item in value.items() if key!="evidence_digest"};value["evidence_digest"]=digest(body)
 saved=HostVitalityStore(tmp_path).record(value)
 assert saved["latest"]["target"]=="VM4010" and saved["classification"]=="FIRST_BOOT_OBSERVED"
def test_drift_and_malformed_state_fail_closed(tmp_path):
 store=HostVitalityStore(tmp_path);assert store.record(observation(gpu=False))["classification"]=="DRIFT_DETECTED"
 (tmp_path/"state.json").write_text("{}");
 with pytest.raises(HostVitalityError,match="STATE_DENIED"):store.snapshot()
def test_forged_observation_has_no_persistent_effect(tmp_path):
 value=observation();value["gpu"]["device_count"]=9;store=HostVitalityStore(tmp_path)
 with pytest.raises(HostVitalityError,match="DIGEST_DENIED"):store.record(value)
 assert list(tmp_path.iterdir())==[]

@pytest.mark.parametrize("observed_at", [True, False, -1, float("nan"), float("inf"), -float("inf"), "1"])
def test_invalid_observation_time_has_no_persistent_effect(tmp_path, observed_at):
 value=observation();value["observed_at"]=observed_at
 value["evidence_digest"]=digest({key:item for key,item in value.items() if key!="evidence_digest"})
 with pytest.raises(HostVitalityError,match="IDENTITY_DENIED"):
  HostVitalityStore(tmp_path).record(value)
 assert list(tmp_path.iterdir())==[]

def test_coherent_projection_history_rewrite_disagrees_with_recorded_ecg(tmp_path):
 store=HostVitalityStore(tmp_path);state=store.record(observation())
 state.update(previous_boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",sample_count=2,classification="RECOVERED_AFTER_BOOT_CHANGE")
 store.state.write_text(json.dumps(state))
 with pytest.raises(HostVitalityError,match="HISTORY_DENIED"):store.snapshot()

@pytest.mark.parametrize("has_predecessor",[False,True])
def test_durable_observation_survives_projection_replace_failure(tmp_path,monkeypatch,has_predecessor):
 import outpost.host_vitality as subject
 store=HostVitalityStore(tmp_path)
 if has_predecessor:store.record(observation())
 before=store.state.read_bytes() if store.state.exists() else None
 with monkeypatch.context() as patch:
  def fail_replace(*_):raise OSError("injected projection replacement failure")
  patch.setattr(subject.os,"replace",fail_replace)
  with pytest.raises(OSError,match="injected"):store.record(observation())
 recovered=store.snapshot()
 assert recovered["sample_count"]==1+int(has_predecessor)
 assert (store.state.read_bytes() if store.state.exists() else None)==before
 assert store.record(observation())["sample_count"]==2+int(has_predecessor)
def test_joined_observation_rejects_a_substituted_public_generation():
 value=observation();value["schema"]="SereinOutpostHostVitalityObservation/v3";value["public_base"]={"repository":"Kaotikking/sfos-public","commit":"f"*40,"tree":"8c56a80487f25150ffec90316a946ac89f64fb92","lock_path":"sfos/base/packages.lock","lock_sha256":"a"*64,"policy_path":"sfos/base/installer/base-policy.json","policy_sha256":"b"*64,"expected_packages":{},"observed_packages":{},"exact_diff":[],"unknowns":[],"status":"PASS"};value["evidence_digest"]=digest({k:v for k,v in value.items() if k!="evidence_digest"})
 with pytest.raises(HostVitalityError,match="PUBLIC_BASE_DENIED"):validate(value)

def test_historical_manifest_remains_evidence_but_cannot_be_active(tmp_path):
 value=observation()
 value["public_base"].update(commit="0dca6bd7a22b83b04ddf353df901d2c7ea15c294",tree="8c56a80487f25150ffec90316a946ac89f64fb92")
 value["evidence_digest"]=digest({k:v for k,v in value.items() if k!="evidence_digest"})
 assert validate(value)==value
 state=HostVitalityStore._projection(value,None,1)
 assert validate_state(state)==state
 with pytest.raises(HostVitalityError,match="ACTIVE_MANIFEST_DENIED"):
  validate_state(state,active=True)
 with pytest.raises(HostVitalityError,match="ACTIVE_MANIFEST_DENIED"):
  HostVitalityStore(tmp_path).record(value)
 assert list(tmp_path.iterdir())==[]

def test_public_selection_matches_published_minimum_recipe():
 assert ADMITTED_PUBLIC_BASE_COMMIT=="a16852781005884d0c08a757a7173dbcdc030dfd"
 assert ADMITTED_PUBLIC_BASE_TREE=="235acf6175fc181286d512865ac345dfb7e88509"

def recipe_witness(defect=None):
 from tests.test_public_tree_host import _existing_recipe_inputs
 from outpost.public_tree_host import inspect_existing_host_manifest
 recipe,inputs=_existing_recipe_inputs()
 if defect=="package":inputs["installed"].pop(next(iter(inputs["installed"])))
 elif defect=="artifact":inputs["authenticated"][next(iter(inputs["authenticated"]))]["sha256"]="0"*64
 elif defect=="source":inputs["sources"]=[]
 elif defect=="gpu":inputs["gpu"]["driver_loaded"]=False
 comparison=inspect_existing_host_manifest(recipe,**inputs)
 body={"schema":"SFOSPublicHostRecipeWitness/v1","source":{"schema":"SereinOutpostPublicSource/v1","repository":"Kaotikking/sfos-public","commit":"a"*40,"tree":"b"*40,"archive_sha256":"c"*64,"release_digest":"sha256:"+"d"*64,"source_plan_sha256":"e"*64},"manifest_path":"sfos/base/host-manifest.json","manifest_sha256":"f"*64,"manifest_git_blob":"1"*40,"comparison":comparison,"admission_effect":"NONE","downstream_activation":"NONE"}
 return {**body,"evidence_digest":digest(body)}

def test_recipe_state_preserves_history_and_binds_active_source(tmp_path,monkeypatch):
 from outpost import host_vitality as subject,public_tree_host
 store=HostVitalityStore(tmp_path)
 old=store.record(observation())
 recipe=recipe_witness()
 monkeypatch.setattr(public_tree_host,"installed_public_source",lambda:dict(recipe["source"]))
 current=store.record(subject.recipe_observation(recipe,2.0))
 assert current["sample_count"]==2 and current["classification"]=="CURRENT_BOOT_STABLE"
 assert validate_state(current,active=True)==current
 assert store.snapshot()==current
 assert json.loads(store.samples.read_text().splitlines()[0])==old["latest"]
 monkeypatch.setattr(public_tree_host,"installed_public_source",lambda:{**recipe["source"],"commit":"0"*40})
 assert store.snapshot()==current  # History remains readable after successor selection.
 with pytest.raises(HostVitalityError,match="ACTIVE_SOURCE_DENIED"):validate_state(current,active=True)

@pytest.mark.parametrize("defect",["package","artifact","source","gpu"])
def test_recipe_drift_remains_observable_without_health_or_admission(tmp_path,monkeypatch,defect):
 from outpost import host_vitality as subject,public_tree_host
 recipe=recipe_witness(defect)
 monkeypatch.setattr(public_tree_host,"installed_public_source",lambda:recipe["source"])
 state=HostVitalityStore(tmp_path).record(subject.recipe_observation(recipe,2.0))
 assert state["classification"]=="DRIFT_DETECTED"
 assert state["latest"]["recipe"]["admission_effect"]==state["authority_effect"]=="NONE"

def test_recipe_hash_and_projection_tampering_denied(monkeypatch):
 from outpost import host_vitality as subject
 recipe=recipe_witness();recipe["comparison"]["boot_id"]="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
 recipe["evidence_digest"]=digest({k:v for k,v in recipe.items() if k!="evidence_digest"})
 with pytest.raises(HostVitalityError,match="COMPARISON_DENIED"):subject.recipe_observation(recipe,2.0)
 value=subject.recipe_observation(recipe_witness(),2.0)
 value["public_base"]["status"]="DRIFT"
 value["evidence_digest"]=digest({k:v for k,v in value.items() if k!="evidence_digest"})
 with pytest.raises(HostVitalityError,match="PROJECTION_DENIED"):validate(value)

def test_legacy_active_state_does_not_bypass_selected_recipe(monkeypatch):
 from outpost import host_vitality as subject
 state=HostVitalityStore._projection(observation(),None,1)
 monkeypatch.setattr(subject,"installed_recipe_required",lambda:True)
 assert validate_state(state)==state
 with pytest.raises(HostVitalityError,match="ACTIVE_SOURCE_DENIED"):validate_state(state,active=True)
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
