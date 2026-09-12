"""Three private, read-only Kernel branch witness APIs."""
from __future__ import annotations
import hashlib,json,re,stat
from datetime import datetime,timezone
from pathlib import Path
BRANCHES=("AUTHORITY","OPERATIONS","INTERFACE")
SCHEMA="SEREIN/KernelBranchDirectWitness/v1";HEX=re.compile(r"[0-9a-f]{40,64}\Z")
class BranchDenied(ValueError):pass
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def live_facts(branch,root=Path("/")):
 def rooted(path):return root/path.lstrip("/")
 generation=json.loads(rooted("/var/lib/serein-outpost/stage1/source-generation.json").read_text())
 manifest=rooted("/usr/share/serein/outpost/installed-manifest.json").read_bytes();boot=rooted("/proc/sys/kernel/random/boot_id").read_text().strip()
 base={"source_commit":generation["commit"],"source_tree":generation["tree"],"canonical_manifest_digest":hashlib.sha256(manifest).hexdigest(),"boot_id":boot,"api_health":"READY"}
 if branch=="AUTHORITY":
  proof={"identity":"KERNEL","policy":"DEFAULT_DENY","containment":"PRIVATE_ONLY","self_admission":False};checks=[("identity",generation.get("commit")),("default-deny",True),("private-only",True)]
 elif branch=="OPERATIONS":
  heartbeat=json.loads(rooted("/var/lib/serein/kernel/replay/lifecycle-heartbeat.json").read_text());required=("/run/serein/kernel/replay-store.sock","/run/serein/stage1/audit.sock")
  healthy=heartbeat.get("boot_id")==boot and heartbeat.get("bpm",0)>=60 and heartbeat.get("missed_heartbeats_current")==0 and all(rooted(x).is_socket() for x in required) and heartbeat.get("queues")=="HEALTHY" and heartbeat.get("leases")=="HEALTHY" and heartbeat.get("recovery")=="READY"
  proof={"minimum_bpm":60 if heartbeat.get("bpm",0)>=60 else heartbeat.get("bpm"),"lifecycle":"READY" if healthy else "DENIED","queues":heartbeat.get("queues"),"leases":heartbeat.get("leases"),"replay":"HEALTHY" if rooted(required[0]).is_socket() else "DENIED","audit":"HEALTHY" if rooted(required[1]).is_socket() else "DENIED","recovery":heartbeat.get("recovery")};checks=[("heartbeat",healthy)]
 elif branch=="INTERFACE":
  interface=rooted("/run/serein/stage1/kernel-interface-v1.sock");private=interface.is_socket()
  proof={"api_transport":"AF_UNIX_PRIVATE","api_version":"v1","socket":"/run/serein/stage1/kernel-interface-v1.sock","downstream_domains":"NOT_STARTED"};checks=[("kernel-interface-private-af-unix",private)]
 else:raise BranchDenied("BRANCH_IDENTITY_DENIED")
 return {**base,"self_tests":[{"name":name,"verdict":"PASS" if value else "FAIL"} for name,value in checks],"proof":proof}
def answer(branch,request,facts,*,peer_uid,expected_outpost_uid,now=None):
 if branch not in BRANCHES:raise BranchDenied("BRANCH_IDENTITY_DENIED")
 if peer_uid!=expected_outpost_uid:raise BranchDenied("OUTPOST_PEER_IDENTITY_DENIED")
 if set(request)!={"schema","branch","request_id","nonce","previous_evidence_digest"} or request.get("schema")!="SEREIN/KernelBranchWitnessRequest/v1" or request.get("branch")!=branch:raise BranchDenied("REQUEST_SCHEMA_DENIED")
 if not all(isinstance(request.get(k),str) and request[k] for k in ("request_id","nonce")):raise BranchDenied("REQUEST_BINDING_DENIED")
 previous=request["previous_evidence_digest"]
 if branch=="AUTHORITY" and previous!="GENESIS" or branch!="AUTHORITY" and not re.fullmatch(r"[0-9a-f]{64}",str(previous)):raise BranchDenied("CHAIN_BINDING_DENIED")
 common={"source_commit","source_tree","canonical_manifest_digest","boot_id","api_health","self_tests"}
 if not isinstance(facts,dict) or set(facts)!=common|{"proof"}:raise BranchDenied("FACT_DENOMINATOR_DENIED")
 if not re.fullmatch(r"[0-9a-f]{40}",str(facts["source_commit"])) or not re.fullmatch(r"[0-9a-f]{40}",str(facts["source_tree"])) or not re.fullmatch(r"[0-9a-f]{64}",str(facts["canonical_manifest_digest"])):raise BranchDenied("SOURCE_BINDING_DENIED")
 if facts["api_health"]!="READY" or not isinstance(facts["self_tests"],list) or not facts["self_tests"] or any(x.get("verdict")!="PASS" for x in facts["self_tests"] if isinstance(x,dict)) or any(not isinstance(x,dict) for x in facts["self_tests"]):raise BranchDenied("SELF_TEST_DENIED")
 proof=facts["proof"]
 exact={"AUTHORITY":{"identity":"KERNEL","policy":"DEFAULT_DENY","containment":"PRIVATE_ONLY","self_admission":False},"OPERATIONS":{"minimum_bpm":60,"lifecycle":"READY","queues":"HEALTHY","leases":"HEALTHY","replay":"HEALTHY","audit":"HEALTHY","recovery":"READY"},"INTERFACE":{"api_transport":"AF_UNIX_PRIVATE","api_version":"v1","socket":"/run/serein/stage1/kernel-interface-v1.sock","downstream_domains":"NOT_STARTED"}}
 if proof!=exact[branch]:raise BranchDenied("BRANCH_PROOF_DENIED")
 issued=(now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
 body={"schema":SCHEMA,"domain":"KERNEL","branch":branch,"verdict":"PASS","issuer":"OUTPOST_DIRECT_WITNESS","issued_at":issued,"request_id":request["request_id"],"nonce":request["nonce"],"previous_evidence_digest":previous,"source_commit":facts["source_commit"],"source_tree":facts["source_tree"],"canonical_manifest_digest":facts["canonical_manifest_digest"],"boot_id":facts["boot_id"],"facts_digest":hashlib.sha256(canonical(facts)).hexdigest(),"uncertainty":"NONE","authority_effect":"NONE"}
 return {**body,"evidence_digest":hashlib.sha256(canonical(body)).hexdigest()}

def domain_authority_answer(request,*,peer_uid,expected_outpost_uid,boot_id,admitted_domains,now=None):
 if peer_uid!=expected_outpost_uid:raise BranchDenied("OUTPOST_PEER_IDENTITY_DENIED")
 required={"schema","domain","request_id","nonce","boot_id","source_commit","source_tree","previous_evidence_digest","issued_at"}
 if not isinstance(request,dict) or set(request)!=required or request.get("schema")!="SEREIN/OutpostDomainAuthorityCheck/v1":raise BranchDenied("DOMAIN_AUTHORITY_REQUEST_DENIED")
 order=("KERNEL","PLATFORM","ROOT","MEMORY","KNOWLEDGE","UI","AUDIO","PERSONALITY","MODULAR","CLOUD");domain=request.get("domain")
 if domain not in order[1:] or admitted_domains!=list(order[:order.index(domain)]) or request.get("boot_id")!=boot_id:raise BranchDenied("DOMAIN_AUTHORITY_ORDER_DENIED")
 observed=(now or datetime.now(timezone.utc)).timestamp();issued=request.get("issued_at")
 if not isinstance(issued,(int,float)) or not 0<=observed-issued<=30:raise BranchDenied("DOMAIN_AUTHORITY_FRESHNESS_DENIED")
 return {"schema":"SEREIN/KernelDomainAuthorityResponse/v1","status":"PASS","api_identity":"KERNEL_AUTHORITY","api_version":"v1","domain":domain,"request_id":request["request_id"],"nonce":request["nonce"],"boot_id":boot_id,"source_commit":request["source_commit"],"source_tree":request["source_tree"],"admitted_prefix":admitted_domains,"self_admission":False,"authority_effect":"NONE"}
