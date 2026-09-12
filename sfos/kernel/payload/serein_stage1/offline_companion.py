"""Offline-only Kernel companion contract; model material is never fetched here."""
from __future__ import annotations
class CompanionDenied(ValueError):pass
def request(value,infer):
 if not isinstance(value,dict) or set(value)!={"schema","conversation_id","prompt","model_digest","network_policy"} or value.get("schema")!="SEREIN/KernelCompanionRequest/v1" or value.get("network_policy")!="OFFLINE_ONLY" or not all(isinstance(value.get(k),str) and value[k] for k in ("conversation_id","prompt","model_digest")):raise CompanionDenied("COMPANION_REQUEST_DENIED")
 result=infer(value["prompt"],value["model_digest"])
 if not isinstance(result,str) or not result:raise CompanionDenied("COMPANION_RESULT_DENIED")
 return {"schema":"SEREIN/KernelCompanionResponse/v1","conversation_id":value["conversation_id"],"answer":result,"model_digest":value["model_digest"],"network_effect":"NONE","authority_effect":"NONE"}
