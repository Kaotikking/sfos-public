"""Canonical Kernel compute road: Authority lease -> Operations -> GPU runtime."""
from __future__ import annotations
import hashlib,hmac,json,sqlite3,time
from pathlib import Path
from .companion_provider import infer
from . import gpu_control
from .kernel_router import Router

CLIENTS=frozenset({"HAOS","ANDROID","ESP32","INTERNAL"});ROUTE="companion.generate";MIN_BPM=60
class ComputeDenied(RuntimeError):pass
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def _key(path):
 p=Path(path);value=p.read_bytes()
 if p.is_symlink() or len(value)!=32:raise ComputeDenied("COMPUTE_AUTHORITY_KEY_DENIED")
 return value
def _signature(key,body):return hmac.new(key,canonical(body),hashlib.sha256).hexdigest()
def operations_health(path="/var/lib/serein/kernel/replay/lifecycle-heartbeat.json"):
 row=json.loads(Path(path).read_bytes());return {"bpm":row.get("bpm"),"queues":row.get("queues"),"leases":row.get("leases"),"capacity_available":max(0,1-int(row.get("active_leases",0)))}
def gpu_probe():return gpu_control.verify(gpu_control.collect())

def issue_lease(request,*,key_path="/var/lib/serein/kernel/authority/replay.key",now=None,ttl=30):
 current=int(time.time() if now is None else now)
 required={"schema","request_id","conversation_id","client","route","prompt","ump"}
 if not isinstance(request,dict) or set(request)!=required or request.get("schema")!="SEREIN/KernelComputeRequest/v1" or request.get("client") not in CLIENTS or request.get("route")!=ROUTE:raise ComputeDenied("COMPUTE_ROUTE_DENIED")
 if any(not isinstance(request.get(k),str) or not request[k] for k in ("request_id","conversation_id","prompt")):raise ComputeDenied("COMPUTE_REQUEST_DENIED")
 body={"schema":"SEREIN/KernelAuthorityLease/v1","request_id":request["request_id"],"conversation_id":request["conversation_id"],"client":request["client"],"route":ROUTE,"issued_at":current,"expires_at":current+ttl,"nonce":hashlib.sha256(canonical(request)).hexdigest(),"policy":"OFFLINE_GPU_ONLY","authority_effect":"NONE"}
 return {"body":body,"signature":_signature(_key(key_path),body)}

def consume(request,lease,*,operations_health=operations_health,gpu_probe=gpu_probe,runtime=infer,key_path="/var/lib/serein/kernel/authority/replay.key",journal_path="/var/lib/serein/kernel/operations/compute.sqlite3",now=None,route_decision=None):
 current=int(time.time() if now is None else now);body=lease.get("body",{}) if isinstance(lease,dict) else {}
 if not hmac.compare_digest(_signature(_key(key_path),body),str(lease.get("signature",""))):raise ComputeDenied("COMPUTE_LEASE_SIGNATURE_DENIED")
 if body.get("expires_at",0)<current or body.get("issued_at",current)>current:raise ComputeDenied("COMPUTE_LEASE_EXPIRED")
 if any(body.get(k)!=request.get(k) for k in ("request_id","conversation_id","client","route")) or body.get("policy")!="OFFLINE_GPU_ONLY":raise ComputeDenied("COMPUTE_LEASE_BINDING_DENIED")
 health=operations_health()
 if not isinstance(health,dict) or health.get("bpm",0)<MIN_BPM or health.get("queues")!="HEALTHY" or health.get("leases")!="HEALTHY" or not isinstance(health.get("capacity_available"),int) or health["capacity_available"]<1:raise ComputeDenied("COMPUTE_CAPACITY_DENIED")
 gpu=gpu_probe()
 if gpu.get("status")!="READY" or gpu.get("owner")!="KERNEL":raise ComputeDenied("COMPUTE_GPU_DENIED")
 path=Path(journal_path);path.parent.mkdir(parents=True,exist_ok=True);database=sqlite3.connect(path,timeout=10,isolation_level=None)
 try:
  database.execute("PRAGMA journal_mode=WAL");database.execute("PRAGMA synchronous=FULL");database.execute("CREATE TABLE IF NOT EXISTS compute_receipts(nonce TEXT PRIMARY KEY,request_id TEXT UNIQUE NOT NULL,receipt TEXT NOT NULL)");database.execute("BEGIN IMMEDIATE")
  if database.execute("SELECT 1 FROM compute_receipts WHERE nonce=? OR request_id=?",(body["nonce"],request["request_id"])).fetchone():database.execute("ROLLBACK");raise ComputeDenied("COMPUTE_REPLAY_DENIED")
  answer=runtime(request["prompt"])
  receipt={"schema":"SEREIN/KernelOperationsComputeReceipt/v1","request_id":request["request_id"],"conversation_id":request["conversation_id"],"client":request["client"],"route":ROUTE,"routed_decision_sha256":hashlib.sha256(canonical(route_decision)).hexdigest() if route_decision else None,"lease_nonce":body["nonce"],"operations_bpm":health["bpm"],"gpu_boot_id":gpu["boot_id"],"status":"ANSWERED","authority_effect":"NONE"}
  database.execute("INSERT INTO compute_receipts VALUES(?,?,?)",(body["nonce"],request["request_id"],canonical(receipt).decode()));database.execute("COMMIT")
 except Exception:
  if database.in_transaction:database.execute("ROLLBACK")
  raise
 finally:database.close()
 return answer,receipt

def dispatch(request,**kwargs):
 key_path=kwargs.get("key_path","/var/lib/serein/kernel/authority/replay.key");router_call=kwargs.pop("router_dispatch",None);authority_contract=kwargs.pop("authority_contract",None)
 if not isinstance(authority_contract,dict):raise ComputeDenied("COMPUTE_ROUTE_AUTHORITY_DENIED")
 if router_call is None:
  boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip();router=Router("/var/lib/serein/kernel/operations/router.sqlite3",key_path,boot)
  router_call=lambda value:router.dispatch(value)
 routed=router_call({"schema":"kernel.route.dispatch.v1/request","request_id":request.get("request_id"),"conversation_id":request.get("conversation_id"),"route":"kernel.companion.generate.v1","plane":"COGNITIVE","caller":request.get("client"),"ump":request.get("ump"),"authority_contract":authority_contract})
 lease=issue_lease(request,key_path=key_path,now=kwargs.get("now"));return consume(request,lease,route_decision=routed,**kwargs)
