"""Persistent, observation-only Host OS/GPU first-install witness."""
from __future__ import annotations
import hashlib,json,os,re,tempfile
from pathlib import Path
from typing import Mapping,Any

SCHEMA="SereinOutpostHostVitalityObservation/v1"
BOOT=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
DEBIAN_PLAN_SCHEMA="SereinOutpostDebianBasePlan/v1"
DEBIAN_HOSTS={"deb.debian.org","security.debian.org"}
class HostVitalityError(ValueError):pass
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def validate(observation:Mapping[str,Any])->dict:
 required={"schema","target","boot_id","observed_at","host","gpu","debian","evidence_digest"}
 if not isinstance(observation,Mapping) or set(observation)!=required or observation.get("schema")!=SCHEMA or observation.get("target") not in {"SEREIN_HOST","VM4010"}:raise HostVitalityError("HOST_VITALITY_SHAPE_DENIED")
 if not BOOT.fullmatch(str(observation.get("boot_id"))) or not isinstance(observation.get("observed_at"),(int,float)):raise HostVitalityError("HOST_VITALITY_IDENTITY_DENIED")
 host=observation.get("host");gpu=observation.get("gpu")
 if (not isinstance(host,Mapping) or set(host)!={"hostname","os_id","os_version_id","machine_id","status"}
  or not isinstance(gpu,Mapping) or set(gpu)!={"pci_present","driver_loaded","device_count","driver_packages","status"} or not isinstance(gpu.get("driver_packages"),dict)):raise HostVitalityError("HOST_VITALITY_DENOMINATOR_DENIED")
 debian=observation.get("debian")
 if (not isinstance(debian,Mapping) or set(debian)!={"release","release_sha256","signer_fingerprint","repositories","installed_identity","installed_packages","repository_packages","exact_diff","pins","exceptions","unknowns","correction_result","status"}
  or debian.get("status") not in {"PASS","DRIFT"} or not HEX64.fullmatch(str(debian.get("release_sha256")))
  or not HEX64.fullmatch(str(debian.get("signer_fingerprint"))) or not isinstance(debian.get("repositories"),list)
  or any(repo not in DEBIAN_HOSTS for repo in debian["repositories"]) or not debian["repositories"]
  or not isinstance(debian.get("installed_identity"),dict) or any(not isinstance(debian.get(k),t) for k,t in (("installed_packages",dict),("repository_packages",dict),("exact_diff",list),("pins",list),("exceptions",list),("unknowns",list)))
  or debian.get("correction_result") not in {"NOT_REQUIRED","PENDING","VERIFIED","FAILED"}):raise HostVitalityError("HOST_VITALITY_DEBIAN_DENIED")
 body={k:v for k,v in observation.items() if k!="evidence_digest"}
 if not HEX64.fullmatch(str(observation.get("evidence_digest"))) or observation["evidence_digest"]!=digest(body):raise HostVitalityError("HOST_VITALITY_DIGEST_DENIED")
 return dict(observation)

def classify(current:dict,previous:dict|None)->str:
 host=current["host"];gpu=current["gpu"]
 healthy=(host["status"]=="PASS" and host["os_id"]=="debian" and host["os_version_id"]=="13" and current["debian"]["status"]=="PASS" and gpu["status"]=="PASS" and gpu["pci_present"] is True and gpu["driver_loaded"] is True and isinstance(gpu["device_count"],int) and gpu["device_count"]>0)
 if not healthy:return "DRIFT_DETECTED"
 if previous is None:return "FIRST_BOOT_OBSERVED"
 if current["boot_id"]==previous["boot_id"]:return "CURRENT_BOOT_STABLE"
 return "RECOVERED_AFTER_BOOT_CHANGE"

class HostVitalityStore:
 def __init__(self,root:Path):self.root=Path(root);self.state=self.root/"state.json";self.samples=self.root/"ecg.jsonl"
 def _read_state(self):
  if not self.state.exists():return None
  if self.state.is_symlink() or not self.state.is_file():raise HostVitalityError("HOST_VITALITY_STATE_CUSTODY_DENIED")
  try:value=json.loads(self.state.read_text())
  except (OSError,json.JSONDecodeError) as exc:raise HostVitalityError("HOST_VITALITY_STATE_DENIED") from exc
  if set(value)!={"schema","projection_revision","projection_digest","previous_boot_id","current_boot_id","sample_count","latest","classification","authority_effect","mutation_effect"} or value["schema"]!="SereinOutpostHostVitalityState/v1" or value["projection_revision"]!=1 or value["projection_digest"]!=digest(value["latest"]):raise HostVitalityError("HOST_VITALITY_STATE_DENIED")
  validate(value["latest"]);return value
 def snapshot(self):
  value=self._read_state()
  if value is None:return {"schema":"SereinOutpostHostVitalityState/v1","status":"NO_OBSERVATION","authority_effect":"NONE","mutation_effect":"NONE"}
  return value
 def record(self,observation:Mapping[str,Any]):
  current=validate(observation);old=self._read_state();previous=old["latest"] if old else None
  self.root.mkdir(parents=True,exist_ok=True)
  if self.root.is_symlink():raise HostVitalityError("HOST_VITALITY_ROOT_CUSTODY_DENIED")
  line=canonical(current)
  with self.samples.open("ab") as stream:stream.write(line);stream.flush();os.fsync(stream.fileno())
  value={"schema":"SereinOutpostHostVitalityState/v1","projection_revision":1,"projection_digest":digest(current),"previous_boot_id":previous["boot_id"] if previous else None,"current_boot_id":current["boot_id"],"sample_count":1+(old["sample_count"] if old else 0),"latest":current,"classification":classify(current,previous),"authority_effect":"NONE","mutation_effect":"NONE"}
  fd,tmp=tempfile.mkstemp(prefix=".host-vitality-",dir=self.root)
  try:
   with os.fdopen(fd,"wb") as stream:fd=-1;stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
   os.chmod(tmp,0o600);os.replace(tmp,self.state)
  finally:
   if fd!=-1:os.close(fd)
   if os.path.exists(tmp):os.unlink(tmp)
  return value

def build_debian_plan(observation:Mapping[str,Any],desired_packages:Mapping[str,str],dependency_closure:Mapping[str,str],request_id:str)->dict:
 current=validate(observation);debian=current["debian"]
 if not request_id or not isinstance(desired_packages,Mapping) or not isinstance(dependency_closure,Mapping) or any(not isinstance(k,str) or not isinstance(v,str) for k,v in {**desired_packages,**dependency_closure}.items()) or not set(desired_packages)<=set(dependency_closure):raise HostVitalityError("DEBIAN_PLAN_INPUT_DENIED")
 body={"schema":DEBIAN_PLAN_SCHEMA,"target":"SEREIN_HOST","request_id":request_id,"boot_id":current["boot_id"],"repository_hosts":sorted(debian["repositories"]),"release":debian["release"],"release_sha256":debian["release_sha256"],"signer_fingerprint":debian["signer_fingerprint"],"before_packages":dict(sorted(debian["installed_packages"].items())),"desired_packages":dict(sorted(desired_packages.items())),"dependency_closure":dict(sorted(dependency_closure.items())),"gpu_before":current["gpu"],"authority_effect":"NONE"}
 return {**body,"plan_digest":digest(body)}

def validate_debian_plan(plan:Mapping[str,Any],current:Mapping[str,Any])->dict:
 expected={"schema","target","request_id","boot_id","repository_hosts","release","release_sha256","signer_fingerprint","before_packages","desired_packages","dependency_closure","gpu_before","authority_effect","plan_digest"}
 if not isinstance(plan,Mapping) or set(plan)!=expected or plan.get("schema")!=DEBIAN_PLAN_SCHEMA or plan.get("target")!="SEREIN_HOST" or plan.get("authority_effect")!="NONE":raise HostVitalityError("DEBIAN_PLAN_SHAPE_DENIED")
 body={k:v for k,v in plan.items() if k!="plan_digest"}
 if plan.get("plan_digest")!=digest(body) or plan.get("boot_id")!=current.get("boot_id") or plan.get("repository_hosts")!=sorted(current["debian"]["repositories"]) or any(x not in DEBIAN_HOSTS for x in plan["repository_hosts"]):raise HostVitalityError("DEBIAN_PLAN_BINDING_DENIED")
 if plan.get("release_sha256")!=current["debian"]["release_sha256"] or plan.get("signer_fingerprint")!=current["debian"]["signer_fingerprint"] or plan.get("before_packages")!=current["debian"]["installed_packages"] or plan.get("gpu_before")!=current["gpu"] or not set(plan.get("desired_packages",{}))<=set(plan.get("dependency_closure",{})):raise HostVitalityError("DEBIAN_PLAN_BINDING_DENIED")
 return dict(plan)

def apply_debian_plan(plan:Mapping[str,Any],current:Mapping[str,Any],adapter)->dict:
 """Governed boundary: adapter must provide prepare/apply/observe/rollback; no shell or URL execution occurs here."""
 bound=validate_debian_plan(plan,validate(current));rollback=adapter.prepare(bound)
 try:
  adapter.apply(bound);after=validate(adapter.observe())
  expected=dict(bound["before_packages"]);expected.update(bound["dependency_closure"])
  if after["boot_id"]!=bound["boot_id"] or after["gpu"]!=bound["gpu_before"] or after["debian"]["installed_packages"]!=expected or after["debian"]["exact_diff"] or after["debian"]["unknowns"] or after["debian"]["correction_result"]!="VERIFIED" or after["debian"]["status"]!="PASS":raise HostVitalityError("DEBIAN_POSTCHANGE_DENIED")
  return {"status":"VERIFIED","plan_digest":bound["plan_digest"],"rollback_digest":digest(rollback),"authority_effect":"NONE"}
 except Exception:
  adapter.rollback(rollback)
  raise

