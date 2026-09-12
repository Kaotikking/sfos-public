"""Outpost-invoked Domain 1 gate runner; construction equals validation order."""
from __future__ import annotations
from . import core_attachments,gpu_control,stage1_witness
ORDER=("AUTHORITY","OPERATIONS","INTERFACE","GPU_CONTROL","OFFLINE_COMPANION","COGNITIVE_GATEWAY","OUTPOST_STAGE1_WITNESS")
class Domain1Denied(RuntimeError):pass
def run(*,branch_probe,router_commission,gpu_probe=gpu_control.collect,offline_install,companion_probe,gateway_probe,witness_write=stage1_witness.persist):
 branches=[]
 for branch in ORDER[:3]:
  row=branch_probe(branch)
  if not isinstance(row,dict) or row.get("branch")!=branch or row.get("status")!="READY":raise Domain1Denied("DOMAIN1_%s_DENIED"%branch)
  branches.append(row)
 route=router_commission()
 audit=route.get("audit") if isinstance(route,dict) else None
 if not isinstance(route,dict) or route.get("status")!="COMMISSIONED" or not isinstance(audit,dict) or audit.get("schema")!="SEREIN/IndependentRouteAudit/v1" or audit.get("status")!="PASS" or audit.get("auditor") in {None,"","OUTPOST"}:raise Domain1Denied("DOMAIN1_ROUTER_COMMISSION_DENIED")
 gpu=gpu_control.verify(gpu_probe())
 offline=offline_install()
 if not isinstance(offline,dict) or offline.get("status") not in {"INSTALLED","ALREADY_EXACT"} or offline.get("network_effect") not in {None,"NONE"}:raise Domain1Denied("DOMAIN1_OFFLINE_INSTALL_DENIED")
 companion=companion_probe()
 if not isinstance(companion,dict) or companion.get("status")!="ANSWERED":raise Domain1Denied("DOMAIN1_COMPANION_DENIED")
 gateways=gateway_probe(companion)
 witness={"schema":"SEREIN/OutpostKernelStage1Witness/v1","boot_id":gpu["boot_id"],"branch_order":list(ORDER[:3]),"gpu":gpu,"companion":companion,"gateways":gateways,"attachments":core_attachments.contracts(),"observer":"OUTPOST","authority_effect":"NONE"}
 durable=witness_write(witness)
 return {"status":"STAGE1_READY","order":list(ORDER),"branches":branches,"router":route,"offline":offline,"witness":durable,"authority_effect":"NONE"}
