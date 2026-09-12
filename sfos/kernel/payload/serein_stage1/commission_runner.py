"""Outpost-owned installed Domain-1 commission transaction."""
from __future__ import annotations
import base64,hashlib,json,os,socket,stat,sys
from datetime import datetime,timezone
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from . import conversation_runtime,domain1_runner,kernel_branch_api,stage1_witness
from .kernel_router import Router
PLAN="/var/lib/serein/kernel/commission-plan.json";AUTHORITY="/usr/share/serein/outpost/cognition-verification.pem";ROUTER_SOCKET="/run/serein/kernel/router.sock"
class CommissionDenied(RuntimeError):pass
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def validate(plan,authority_path=AUTHORITY,boot_path="/proc/sys/kernel/random/boot_id"):
 required={"schema","target","boot_id","conversation_id","request_id","offline_receipt","audit","authority_contract","signature"}
 audit=plan.get("audit") if isinstance(plan,dict) else None
 if not isinstance(plan,dict) or set(plan)!=required or plan.get("schema")!="SEREIN/OutpostKernelCommissionPlan/v1" or plan.get("target")!="VM4010" or not isinstance(audit,dict) or audit.get("schema")!="SEREIN/IndependentRouteAudit/v1" or audit.get("route")!="kernel.companion.generate.v1" or audit.get("status")!="PASS" or audit.get("auditor") in {None,"","OUTPOST"}:raise CommissionDenied("INDEPENDENT_AUDIT_PENDING")
 if plan["boot_id"]!=Path(boot_path).read_text().strip():raise CommissionDenied("COMMISSION_BOOT_DENIED")
 body={k:v for k,v in plan.items() if k!="signature"}
 try:load_pem_public_key(Path(authority_path).read_bytes()).verify(base64.urlsafe_b64decode(plan["signature"]+"="*(-len(plan["signature"])%4)),canonical(body))
 except Exception as error:raise CommissionDenied("COMMISSION_SIGNATURE_DENIED") from error
 return plan
class RouterClient:
 def __init__(self,path=ROUTER_SOCKET):self.path=path
 def register(self,request):
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:client.settimeout(15);client.connect(self.path);client.sendall(canonical({"operation":"REGISTER","request":request}));raw=client.recv(65537)
  value=json.loads(raw)
  if value.get("status")!="OK":raise CommissionDenied("COMMISSION_ROUTER_DENIED")
  return value["receipt"]
 def withdraw(self,route,reason,authority_contract):
  packet={"operation":"WITHDRAW","route":route,"reason":reason,"authority_contract":authority_contract}
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:client.settimeout(15);client.connect(self.path);client.sendall(canonical(packet));raw=client.recv(65537)
  value=json.loads(raw)
  if value.get("status")!="OK":raise CommissionDenied("COMMISSION_ROUTE_COMPENSATION_DENIED")
  return value["receipt"]
def _compensation_authority(authority):
 value=json.loads(json.dumps(authority));value["action"]="kernel.route.withdraw.v1";value["nonce"]=hashlib.sha256((authority["nonce"]+":commission-compensation").encode()).hexdigest();value["expected_result"]="ROUTE_WITHDRAWN_INELIGIBLE";return value
def execute(plan,*,router,branch_probe,gpu_probe,offline_probe,companion_probe,gateway_probe,witness_write):
 validate_result=plan
 route={"schema":"kernel.route.register.v1/request","route":"kernel.companion.generate.v1","owner":"KERNEL","plane":"COGNITIVE","version":"v1","posture":"ELIGIBLE","qos":{"priority":1,"capacity":1,"backpressure":"REJECT"},"failover":[],"ump":{"schema":"SEREIN/UMP/v1","state":"KNOWN","claims":[{"source":"OUTPOST_COMMISSION"}],"authority_effect":"NONE"},"audit":plan["audit"],"authority_contract":plan["authority_contract"]}
 registration=router.register(route)
 try:
  return domain1_runner.run(branch_probe=branch_probe,router_commission=lambda:{"status":"COMMISSIONED","audit":plan["audit"],"receipt":registration},gpu_probe=gpu_probe,offline_install=offline_probe,companion_probe=companion_probe,gateway_probe=gateway_probe,witness_write=witness_write)
 except Exception:
  router.withdraw(route["route"],"commission_post_registration_failure",_compensation_authority(plan["authority_contract"]))
  raise
def main(plan_path=PLAN):
 plan_file=Path(plan_path);info=plan_file.lstat()
 if plan_file.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600:raise CommissionDenied("COMMISSION_PLAN_CUSTODY_DENIED")
 plan=validate(json.loads(plan_file.read_bytes()));router=RouterClient()
 def branch(name):
  facts=kernel_branch_api.live_facts(name);return {"branch":name,"status":"READY","facts":facts}
 def offline():
  path=Path(plan["offline_receipt"]);value=json.loads(path.read_bytes());acceptance=value.get("acceptance") if isinstance(value,dict) else None
  if path.is_symlink() or value.get("actor")!="OUTPOST" or value.get("boot_id")!=plan["boot_id"] or not isinstance(acceptance,dict) or acceptance.get("boot_id")!=plan["boot_id"]:raise CommissionDenied("COMMISSION_OFFLINE_RECEIPT_DENIED")
  return {"status":"INSTALLED","network_effect":"NONE","receipt_digest":value.get("receipt_digest")}
 def companion():
  now=datetime.now(timezone.utc);request={"schema":"SereinStage1ConversationRuntimeRequest/v1","request_id":plan["request_id"],"conversation_id":plan["conversation_id"],"machine_identity":"INTERNAL_VM4010","requested_operation":"conversation_only","utterance":"Return a bounded Stage 1 readiness response.","observed_at":now.isoformat()};response=json.loads(conversation_runtime.handle_payload(canonical(request),now=now))
  if response.get("status")!="ANSWERED" or not response.get("compute_receipt"):raise CommissionDenied("COMMISSION_COMPANION_DENIED")
  return response
 def gateways(companion):
  result={};correlation={"request_id":companion["request_id"],"conversation_id":companion["conversation_id"]}
  for client in stage1_witness.CLIENTS:
   path=Path("/run/serein/kernel/gateway-%s.sock"%client.lower())
   if not path.exists() or not stat.S_ISSOCK(path.stat().st_mode):raise CommissionDenied("COMMISSION_GATEWAY_DENIED")
   result[client]={"client":client,"process_isolation":"DEDICATED",**correlation}
  return result
 from .gpu_control import collect
 result=execute(plan,router=router,branch_probe=branch,gpu_probe=collect,offline_probe=offline,companion_probe=companion,gateway_probe=gateways,witness_write=stage1_witness.persist);print(json.dumps(result,sort_keys=True,separators=(",",":")))
if __name__=="__main__":main(sys.argv[1] if len(sys.argv)==2 else PLAN)
