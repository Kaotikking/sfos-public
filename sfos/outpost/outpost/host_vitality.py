"""Persistent, observation-only Host OS/GPU first-install witness."""
from __future__ import annotations
import hashlib,json,math,os,re,tempfile
from urllib.parse import urlsplit
from pathlib import Path
from typing import Mapping,Any

SCHEMA="SereinOutpostHostVitalityObservation/v1"
PUBLIC_SCHEMA="SereinOutpostHostVitalityObservation/v2"
JOINED_SCHEMA="SereinOutpostHostVitalityObservation/v3"
RECIPE_SCHEMA="SereinOutpostHostVitalityObservation/v4"
BOOT=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
DEBIAN_PLAN_SCHEMA="SereinOutpostDebianBasePlan/v1"
DEBIAN_HOSTS={"deb.debian.org","security.debian.org"}
ADMITTED_PUBLIC_BASE_COMMIT="a16852781005884d0c08a757a7173dbcdc030dfd"
ADMITTED_PUBLIC_BASE_TREE="235acf6175fc181286d512865ac345dfb7e88509"
# Earlier observations remain readable evidence, never the active manifest.
HISTORICAL_PUBLIC_BASES={
 ("0dca6bd7a22b83b04ddf353df901d2c7ea15c294","8c56a80487f25150ffec90316a946ac89f64fb92"),
}
PUBLIC_BASES=HISTORICAL_PUBLIC_BASES|{(ADMITTED_PUBLIC_BASE_COMMIT,ADMITTED_PUBLIC_BASE_TREE)}
class HostVitalityError(ValueError):pass
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def _recipe_projection(recipe):
 """Validate the nested read-only witness and project its actual evidence."""
 if (not isinstance(recipe,Mapping) or set(recipe)!={"schema","source","manifest_path","manifest_sha256","manifest_git_blob","comparison","admission_effect","downstream_activation","evidence_digest"}
  or recipe.get("schema")!="SFOSPublicHostRecipeWitness/v1" or recipe.get("manifest_path")!="sfos/base/host-manifest.json"
  or not HEX64.fullmatch(str(recipe.get("manifest_sha256"))) or not re.fullmatch(r"[0-9a-f]{40}",str(recipe.get("manifest_git_blob")))
  or recipe.get("admission_effect")!="NONE" or recipe.get("downstream_activation")!="NONE"
  or recipe.get("evidence_digest")!=digest({k:v for k,v in recipe.items() if k!="evidence_digest"})):
  raise HostVitalityError("HOST_RECIPE_WITNESS_DENIED")
 source=recipe["source"]
 if (not isinstance(source,Mapping) or set(source)!={"schema","repository","commit","tree","archive_sha256","release_digest","source_plan_sha256"}
  or source.get("schema")!="SereinOutpostPublicSource/v1" or source.get("repository")!="Kaotikking/sfos-public"
  or any(not re.fullmatch(r"[0-9a-f]{40}",str(source.get(k))) for k in ("commit","tree"))
  or any(not HEX64.fullmatch(str(source.get(k))) for k in ("archive_sha256","source_plan_sha256"))
  or not re.fullmatch(r"sha256:[0-9a-f]{64}",str(source.get("release_digest")))):
  raise HostVitalityError("HOST_RECIPE_SOURCE_DENIED")
 comparison=recipe["comparison"]
 required={"schema","boot_id","host","gpu","debian","manifest_sha256","package_count","exact_diff","unknowns","result","package_mutation","identity_mutation","downstream_activation","outpost_generation_acceptance","admission_effect","evidence_digest"}
 if (not isinstance(comparison,Mapping) or set(comparison)!=required
  or comparison.get("schema")!="SFOSExistingDebianHostComparison/v1"
  or not BOOT.fullmatch(str(comparison.get("boot_id"))) or not HEX64.fullmatch(str(comparison.get("manifest_sha256")))
  or type(comparison.get("package_count")) is not int or comparison["package_count"]<1
  or any(comparison.get(k)!="NONE" for k in ("package_mutation","identity_mutation","downstream_activation","admission_effect"))
  or comparison.get("outpost_generation_acceptance")!="SEPARATE_REQUIRED"
  or not isinstance(comparison.get("exact_diff"),list) or not isinstance(comparison.get("unknowns"),list)
  or comparison.get("result") not in {"EXACT_EXISTING_RECIPE_MATCH","HOST_RECIPE_UNPROVEN"}
  or comparison.get("evidence_digest")!=digest({k:v for k,v in comparison.items() if k!="evidence_digest"})):
  raise HostVitalityError("HOST_RECIPE_COMPARISON_DENIED")
 evidence=comparison["debian"]
 if not isinstance(evidence,Mapping) or set(evidence)!={"authenticated_release","authenticated_indexes","installed","authenticated","expected","sources","preferences"}:
  raise HostVitalityError("HOST_RECIPE_EVIDENCE_DENIED")
 release=evidence["authenticated_release"];expected=evidence["expected"];installed=evidence["installed"];authenticated=evidence["authenticated"]
 if (not isinstance(release,Mapping) or not HEX64.fullmatch(str(release.get("sha256")))
  or not isinstance(release.get("signers"),list) or not release["signers"]
  or any(not re.fullmatch(r"[A-Fa-f0-9]{40}",str(x)) for x in release["signers"])
  or not isinstance(evidence["authenticated_indexes"],list) or not evidence["authenticated_indexes"]
  or not isinstance(expected,Mapping) or len(expected)!=comparison["package_count"]
  or not isinstance(installed,Mapping) or not isinstance(authenticated,Mapping)
  or not isinstance(evidence["sources"],list) or not isinstance(evidence["preferences"],list)):
  raise HostVitalityError("HOST_RECIPE_EVIDENCE_DENIED")
 for index in evidence["authenticated_indexes"]:
  if not isinstance(index,Mapping) or set(index)!={"path","sha256","bytes"} or not HEX64.fullmatch(str(index["sha256"])) or type(index["bytes"]) is not int or index["bytes"]<1:raise HostVitalityError("HOST_RECIPE_EVIDENCE_DENIED")
 for name,row in expected.items():
  if (not isinstance(row,Mapping) or set(row)!={"package","version","architecture","sha256","component"}
   or row["package"]!=name or not isinstance(row["version"],str) or not row["version"]
   or row["architecture"] not in {"amd64","all"} or not HEX64.fullmatch(str(row["sha256"]))):raise HostVitalityError("HOST_RECIPE_EVIDENCE_DENIED")
 for rows in (installed,authenticated):
  if any(not isinstance(row,Mapping) or not isinstance(row.get("version"),str) or not row["version"] for row in rows.values()):raise HostVitalityError("HOST_RECIPE_EVIDENCE_DENIED")
 host=comparison["host"];gpu=comparison["gpu"]
 if not isinstance(host,Mapping) or not isinstance(gpu,Mapping):raise HostVitalityError("HOST_RECIPE_EVIDENCE_DENIED")
 healthy=(not comparison["exact_diff"] and not comparison["unknowns"]
  and all(authenticated.get(name)==row and installed.get(name)=={"version":row["version"],"architecture":row["architecture"]} for name,row in expected.items())
  and set(installed)==set(expected)|{"serein-outpost"}
  and installed.get("serein-outpost")=={"version":"1.0.31+1fa5603","architecture":"all"}
  and host.get("os_id")=="debian" and host.get("os_version_id")=="13" and host.get("architecture")=="amd64"
  and bool(host.get("hostname")) and bool(re.fullmatch(r"[0-9a-f]{32}",str(host.get("machine_id"))))
  and gpu.get("status")=="PASS" and gpu.get("pci_present") is True and gpu.get("driver_loaded") is True and type(gpu.get("device_count")) is int and gpu["device_count"]>0)
 if (comparison["result"]=="EXACT_EXISTING_RECIPE_MATCH")!=healthy:raise HostVitalityError("HOST_RECIPE_RESULT_DENIED")
 status="PASS" if healthy else "DRIFT"
 host={k:host.get(k) for k in ("hostname","os_id","os_version_id","machine_id")}|{"status":status}
 gpu={k:gpu.get(k) for k in ("pci_present","driver_loaded","device_count","status")}|{"driver_packages":dict(gpu.get("driver_packages",{}))}
 public={k:source[k] for k in ("repository","commit","tree")}|{k:recipe[k] for k in ("manifest_path","manifest_sha256","manifest_git_blob")}
 public.update(expected_packages={k:v["version"] for k,v in expected.items()},observed_packages={k:installed.get(k,{}).get("version") for k in expected},exact_diff=comparison["exact_diff"],unknowns=comparison["unknowns"],status=status)
 debian={"release":release.get("codename",""),"release_sha256":release["sha256"],"signer_fingerprint":hashlib.sha256("\n".join(sorted({s.lower() for s in release["signers"]})).encode()).hexdigest(),
  "repositories":sorted({urlsplit(row["uri"]).hostname for row in evidence["sources"]}),
  "installed_identity":{"id":host["os_id"],"version_id":host["os_version_id"]},"installed_packages":{k:v["version"] for k,v in installed.items()},"repository_packages":{k:v["version"] for k,v in authenticated.items()},
  "exact_diff":comparison["exact_diff"],"pins":[{"sources":evidence["sources"],"preferences":evidence["preferences"]}],"exceptions":["serein-outpost"],"unknowns":comparison["unknowns"],"correction_result":"NOT_REQUIRED" if healthy else "PENDING","status":status}
 return host,gpu,public,debian

def recipe_observation(recipe,observed_at):
 host,gpu,public,debian=_recipe_projection(recipe)
 body={"schema":RECIPE_SCHEMA,"target":"VM4010","boot_id":recipe["comparison"]["boot_id"],"observed_at":observed_at,"host":host,"gpu":gpu,"public_base":public,"debian":debian,"recipe":recipe}
 return validate({**body,"evidence_digest":digest(body)})

def installed_recipe_required():
 """A selected generation must not fall back after missing/invalid metadata."""
 return os.path.lexists('/var/lib/serein-outpost/generation-state/current.json')

def _validate_active(current):
 if current["schema"]==RECIPE_SCHEMA:
  from .public_tree_host import installed_public_source
  try: source=installed_public_source()
  except Exception as exc:raise HostVitalityError("HOST_RECIPE_ACTIVE_SOURCE_DENIED") from exc
  if current["recipe"]["source"]!=source:raise HostVitalityError("HOST_RECIPE_ACTIVE_SOURCE_DENIED")
 elif installed_recipe_required():raise HostVitalityError("HOST_RECIPE_ACTIVE_SOURCE_DENIED")
 elif current["schema"]!=JOINED_SCHEMA:raise HostVitalityError("HOST_VITALITY_ACTIVE_SCHEMA_DENIED")
 elif (current["public_base"]["commit"],current["public_base"]["tree"])!=(ADMITTED_PUBLIC_BASE_COMMIT,ADMITTED_PUBLIC_BASE_TREE):raise HostVitalityError("HOST_VITALITY_ACTIVE_MANIFEST_DENIED")


class HostCollectionAttempts:
 """Observation chronology only; never fabricates signed Host metadata."""
 def __init__(self,root:Path):
  from .reboot_vitality import VitalityChronology
  self.log=VitalityChronology(Path(root)/"collection-attempts.jsonl")
 def _attempts(self):
  attempts={};latest=None
  for row in self.log.read():
   value=row["payload"]
   if row["subject"]!="SEREIN_HOST" or not isinstance(value.get("attempt_id"),str) or not BOOT.fullmatch(value["attempt_id"]) or not isinstance(value.get("boot_id"),str) or not BOOT.fullmatch(value["boot_id"]):raise HostVitalityError("HOST_ATTEMPT_IDENTITY_DENIED")
   identifier=value["attempt_id"]
   if row["event_kind"]=="HOST_COLLECTION_STARTED":
    if set(value)!={"attempt_id","boot_id"} or identifier in attempts:raise HostVitalityError("HOST_ATTEMPT_SEQUENCE_DENIED")
    attempts[identifier]={"start":row,"terminal":None};latest=identifier
   elif row["event_kind"] in {"HOST_COLLECTION_SUCCEEDED","HOST_COLLECTION_FAILED"}:
    prior=attempts.get(identifier)
    if not prior or prior["terminal"] is not None or value["boot_id"]!=prior["start"]["payload"]["boot_id"] or row["observed_at"]<prior["start"]["observed_at"]:raise HostVitalityError("HOST_ATTEMPT_SEQUENCE_DENIED")
    if row["event_kind"]=="HOST_COLLECTION_SUCCEEDED":
     if set(value)!={"attempt_id","boot_id","projection_digest"} or not HEX64.fullmatch(str(value["projection_digest"])):raise HostVitalityError("HOST_ATTEMPT_RESULT_DENIED")
    elif set(value)!={"attempt_id","boot_id","error_code"} or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}",str(value["error_code"])):raise HostVitalityError("HOST_ATTEMPT_RESULT_DENIED")
    prior["terminal"]=row
   else:raise HostVitalityError("HOST_ATTEMPT_KIND_DENIED")
  return attempts,latest
 def latest(self):
  attempts,latest=self._attempts()
  return attempts[latest] if latest else None
 def start(self,boot_id:str,observed_at:float)->str:
  import uuid
  if not isinstance(boot_id,str) or not BOOT.fullmatch(boot_id):raise HostVitalityError("HOST_ATTEMPT_IDENTITY_DENIED")
  self._attempts()
  identifier=str(uuid.uuid4())
  self.log.append(identifier+":start","HOST_COLLECTION_STARTED","SEREIN_HOST",observed_at,{"attempt_id":identifier,"boot_id":boot_id})
  return identifier
 def finish(self,identifier:str,observed_at:float,*,state=None,error_code=None):
  attempts,_=self._attempts();prior=attempts.get(identifier)
  if not prior or prior["terminal"] is not None or observed_at<prior["start"]["observed_at"]:raise HostVitalityError("HOST_ATTEMPT_SEQUENCE_DENIED")
  payload=dict(prior["start"]["payload"])
  if state is not None and error_code is None:
   checked=validate_state(state,active=True)
   if checked["current_boot_id"]!=payload["boot_id"] or not prior["start"]["observed_at"]<=checked["latest"]["observed_at"]<=observed_at:raise HostVitalityError("HOST_ATTEMPT_RESULT_DENIED")
   payload["projection_digest"]=checked["projection_digest"];kind="HOST_COLLECTION_SUCCEEDED"
  elif state is None and isinstance(error_code,str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}",error_code):
   payload["error_code"]=error_code;kind="HOST_COLLECTION_FAILED"
  else:raise HostVitalityError("HOST_ATTEMPT_RESULT_DENIED")
  return self.log.append(identifier+":terminal",kind,"SEREIN_HOST",observed_at,payload)


def host_attempt_matches(host,attempt,boot_id,observed_at):
 """One read-only completion predicate shared by all Outpost observers."""
 try:
  checked=validate_state(host,active=True)
  start=attempt["start"];terminal=attempt["terminal"]
  return (type(observed_at) in (int,float) and math.isfinite(observed_at)
   and start["payload"]["boot_id"]==boot_id==checked["current_boot_id"]
   and terminal is not None and terminal["event_kind"]=="HOST_COLLECTION_SUCCEEDED"
   and terminal["payload"]["boot_id"]==boot_id
   and terminal["payload"]["attempt_id"]==start["payload"]["attempt_id"]
   and start["observed_at"]<=checked["latest"]["observed_at"]<=terminal["observed_at"]<=observed_at
   and terminal["payload"]["projection_digest"]==checked["projection_digest"])
 except (ValueError,TypeError,KeyError):return False

def _validate_public_base(source:Mapping[str,Any],*,admitted:bool=False)->None:
 expected={"repository","commit","tree","lock_path","lock_sha256","policy_path","policy_sha256","expected_packages","observed_packages","exact_diff","unknowns","status"}
 if (not isinstance(source,Mapping) or set(source)!=expected or source.get("repository")!="Kaotikking/sfos-public" or (admitted and not any(source.get("commit")==commit and source.get("tree")==tree for commit,tree in PUBLIC_BASES)) or not re.fullmatch(r"[0-9a-f]{40}",str(source.get("commit"))) or not re.fullmatch(r"[0-9a-f]{40}",str(source.get("tree"))) or source.get("lock_path")!="sfos/base/packages.lock" or source.get("policy_path")!="sfos/base/installer/base-policy.json" or not HEX64.fullmatch(str(source.get("lock_sha256"))) or not HEX64.fullmatch(str(source.get("policy_sha256"))) or not isinstance(source.get("expected_packages"),dict) or not isinstance(source.get("observed_packages"),dict) or not isinstance(source.get("exact_diff"),list) or not isinstance(source.get("unknowns"),list) or source.get("status") not in {"PASS","DRIFT"}):raise HostVitalityError("HOST_VITALITY_PUBLIC_BASE_DENIED")

def _validate_debian(debian:Mapping[str,Any])->None:
 expected={"release","release_sha256","signer_fingerprint","repositories","installed_identity","installed_packages","repository_packages","exact_diff","pins","exceptions","unknowns","correction_result","status"}
 if (not isinstance(debian,Mapping) or set(debian)!=expected or debian.get("status") not in {"PASS","DRIFT"} or not HEX64.fullmatch(str(debian.get("release_sha256"))) or not HEX64.fullmatch(str(debian.get("signer_fingerprint"))) or not isinstance(debian.get("repositories"),list) or any(repo not in DEBIAN_HOSTS for repo in debian["repositories"]) or not debian["repositories"] or not isinstance(debian.get("installed_identity"),dict) or any(not isinstance(debian.get(k),t) for k,t in (("installed_packages",dict),("repository_packages",dict),("exact_diff",list),("pins",list),("exceptions",list),("unknowns",list))) or debian.get("correction_result") not in {"NOT_REQUIRED","PENDING","VERIFIED","FAILED"}):raise HostVitalityError("HOST_VITALITY_DEBIAN_DENIED")

def validate(observation:Mapping[str,Any])->dict:
 required={"schema","target","boot_id","observed_at","host","gpu","evidence_digest"}
 if not isinstance(observation,Mapping) or observation.get("target") not in {"SEREIN_HOST","VM4010"}:raise HostVitalityError("HOST_VITALITY_SHAPE_DENIED")
 schema=observation.get("schema")
 expected_keys={SCHEMA:required|{"debian"},PUBLIC_SCHEMA:required|{"public_base"},JOINED_SCHEMA:required|{"public_base","debian"},RECIPE_SCHEMA:required|{"public_base","debian","recipe"}}
 if schema not in expected_keys or set(observation)!=expected_keys[schema]:raise HostVitalityError("HOST_VITALITY_SHAPE_DENIED")
 observed_at=observation.get("observed_at")
 if not isinstance(observation.get("boot_id"),str) or not BOOT.fullmatch(observation["boot_id"]) or type(observed_at) not in (int,float) or not math.isfinite(observed_at) or observed_at<0:raise HostVitalityError("HOST_VITALITY_IDENTITY_DENIED")
 host=observation.get("host");gpu=observation.get("gpu")
 if (not isinstance(host,Mapping) or set(host)!={"hostname","os_id","os_version_id","machine_id","status"}
  or not isinstance(gpu,Mapping) or set(gpu)!={"pci_present","driver_loaded","device_count","driver_packages","status"} or not isinstance(gpu.get("driver_packages"),dict)):raise HostVitalityError("HOST_VITALITY_DENOMINATOR_DENIED")
 if schema in {PUBLIC_SCHEMA,JOINED_SCHEMA}:_validate_public_base(observation["public_base"],admitted=schema==JOINED_SCHEMA)
 if schema in {SCHEMA,JOINED_SCHEMA}:_validate_debian(observation["debian"])
 if schema==RECIPE_SCHEMA:
  projected=_recipe_projection(observation["recipe"])
  if observation["boot_id"]!=observation["recipe"]["comparison"]["boot_id"] or any(observation[k]!=v for k,v in zip(("host","gpu","public_base","debian"),projected)):raise HostVitalityError("HOST_RECIPE_PROJECTION_DENIED")
 body={k:v for k,v in observation.items() if k!="evidence_digest"}
 if not HEX64.fullmatch(str(observation.get("evidence_digest"))) or observation["evidence_digest"]!=digest(body):raise HostVitalityError("HOST_VITALITY_DIGEST_DENIED")
 return dict(observation)

def classify(current:dict,previous:dict|None)->str:
 host=current["host"];gpu=current["gpu"]
 public=current.get("public_base",{})
 debian=current.get("debian",{})
 expected=public.get("expected_packages",{})
 installed=debian.get("installed_packages",{})
 repository=debian.get("repository_packages",{})
 # Verdict labels cannot override the observed facts. Retain contradictions in
 # the witness, but never classify them as a healthy current-boot Host gate.
 denominators_agree=(current.get("schema") in {JOINED_SCHEMA,RECIPE_SCHEMA} and bool(expected)
  and debian.get("installed_identity",{}).get("id")==host.get("os_id")
  and debian.get("installed_identity",{}).get("version_id")==host.get("os_version_id")
  and public.get("status")=="PASS" and debian.get("status")=="PASS"
  and not public.get("exact_diff") and not public.get("unknowns")
  and not debian.get("exact_diff") and not debian.get("unknowns")
  and debian.get("correction_result") in {"NOT_REQUIRED","VERIFIED"}
  and public.get("observed_packages")==expected
  and all(isinstance(version,str) and bool(version) and installed.get(name)==version and repository.get(name)==version for name,version in expected.items())
  and all(repository.get(name)==version for name,version in installed.items() if name not in debian.get("exceptions",[])))
 healthy=(denominators_agree and host["status"]=="PASS" and host["os_id"]=="debian" and host["os_version_id"]=="13" and gpu["status"]=="PASS" and gpu["pci_present"] is True and gpu["driver_loaded"] is True and type(gpu["device_count"]) is int and gpu["device_count"]>0)
 if not healthy:return "DRIFT_DETECTED"
 if previous is None:return "FIRST_BOOT_OBSERVED"
 if current["boot_id"]==previous["boot_id"]:return "CURRENT_BOOT_STABLE"
 return "RECOVERED_AFTER_BOOT_CHANGE"

def validate_state(value:Mapping[str,Any],*,active:bool=False)->dict:
 required={"schema","projection_revision","projection_digest","previous_boot_id","current_boot_id","sample_count","latest","classification","authority_effect","mutation_effect"}
 if not isinstance(value,Mapping) or set(value)!=required or value["schema"]!="SereinOutpostHostVitalityState/v1" or value["projection_revision"]!=1 or value["projection_digest"]!=digest(value["latest"]):raise HostVitalityError("HOST_VITALITY_STATE_DENIED")
 current=validate(value["latest"])
 previous=value["previous_boot_id"];count=value["sample_count"]
 if value["current_boot_id"]!=current["boot_id"] or type(count) is not int or count<1 or (count==1 and previous is not None) or (count>1 and not BOOT.fullmatch(str(previous))) or value["authority_effect"]!="NONE" or value["mutation_effect"]!="NONE":raise HostVitalityError("HOST_VITALITY_STATE_DENIED")
 if active:_validate_active(current)
 if current["schema"] in {JOINED_SCHEMA,RECIPE_SCHEMA} and value["classification"]!=classify(current,None if previous is None else {"boot_id":previous}):raise HostVitalityError("HOST_VITALITY_HISTORY_DENIED")
 return dict(value)

class HostVitalityStore:
 def __init__(self,root:Path):self.root=Path(root);self.state=self.root/"state.json";self.samples=self.root/"ecg.jsonl"
 @staticmethod
 def _projection(current,previous,count):
  return {"schema":"SereinOutpostHostVitalityState/v1","projection_revision":1,"projection_digest":digest(current),"previous_boot_id":previous["boot_id"] if previous else None,"current_boot_id":current["boot_id"],"sample_count":count,"latest":current,"classification":classify(current,previous),"authority_effect":"NONE","mutation_effect":"NONE"}
 def _read_state(self):
  value=None
  if self.state.is_symlink():raise HostVitalityError("HOST_VITALITY_STATE_CUSTODY_DENIED")
  if self.state.exists():
   if not self.state.is_file():raise HostVitalityError("HOST_VITALITY_STATE_CUSTODY_DENIED")
   try:value=validate_state(json.loads(self.state.read_text()))
   except (OSError,json.JSONDecodeError) as exc:raise HostVitalityError("HOST_VITALITY_STATE_DENIED") from exc
  if self.samples.is_symlink():raise HostVitalityError("HOST_VITALITY_HISTORY_DENIED")
  if not self.samples.exists() and value is None:return None
  if not self.samples.is_file():raise HostVitalityError("HOST_VITALITY_HISTORY_DENIED")
  try:rows=[validate(json.loads(line)) for line in self.samples.read_bytes().splitlines()]
  except (OSError,ValueError,TypeError) as exc:raise HostVitalityError("HOST_VITALITY_HISTORY_DENIED") from exc
  if not rows:
   if value is None:return None
   raise HostVitalityError("HOST_VITALITY_HISTORY_DENIED")
  if value is not None:
   count=value["sample_count"]
   if count>len(rows) or rows[count-1]!=value["latest"] or (rows[count-2]["boot_id"] if count>1 else None)!=value["previous_boot_id"]:raise HostVitalityError("HOST_VITALITY_HISTORY_DENIED")
   if count==len(rows):return value
  # The fsynced ECG is the observation journal. A crash may leave the cache
  # absent or behind a validated prefix; reconstruct without mutating on read.
  return self._projection(rows[-1],rows[-2] if len(rows)>1 else None,len(rows))
 def snapshot(self):
  value=self._read_state()
  if value is None:return {"schema":"SereinOutpostHostVitalityState/v1","status":"NO_OBSERVATION","authority_effect":"NONE","mutation_effect":"NONE"}
  return value
 def record(self,observation:Mapping[str,Any]):
  current=validate(observation)
  _validate_active(current)
  old=self._read_state();previous=old["latest"] if old else None
  self.root.mkdir(parents=True,exist_ok=True)
  if self.root.is_symlink():raise HostVitalityError("HOST_VITALITY_ROOT_CUSTODY_DENIED")
  if self.samples.is_symlink() or (self.samples.exists() and not self.samples.is_file()):raise HostVitalityError("HOST_VITALITY_HISTORY_DENIED")
  line=canonical(current)
  with self.samples.open("ab") as stream:stream.write(line);stream.flush();os.fsync(stream.fileno())
  value=self._projection(current,previous,1+(old["sample_count"] if old else 0))
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
