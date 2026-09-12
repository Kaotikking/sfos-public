"""Production verifier for an Operator-selected independent route audit."""
from __future__ import annotations
import base64,json
from datetime import datetime,timezone
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key

FIELDS={"schema","route","status","verdict","auditor","selected_by","boot_id","source_generation","issued_at","expires_at","nonce","evidence_sha256","signature"}
HEX64=__import__("re").compile(r"[0-9a-f]{64}\Z");HEX40=__import__("re").compile(r"[0-9a-f]{40}\Z")
class AuditDenied(ValueError):pass
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()

def verifier(public_key_path):
 path=Path(public_key_path);info=path.lstat()
 if path.is_symlink() or not path.is_file() or info.st_mode&0o022:raise AuditDenied("INDEPENDENT_AUDIT_KEY_CUSTODY_DENIED")
 key=load_pem_public_key(path.read_bytes())
 def verify(value,*,route=None,boot_id=None,source_generation=None,now=None):
  if not isinstance(value,dict) or set(value)!=FIELDS or value.get("schema")!="SEREIN/IndependentRouteAudit/v1":raise AuditDenied("INDEPENDENT_AUDIT_SHAPE_DENIED")
  if value.get("status")!="PASS" or value.get("verdict")!="PASS — SECURITY ROUTE INDEPENDENTLY VERIFIED" or value.get("selected_by")!="OPERATOR" or value.get("auditor") in {None,"","OUTPOST"}:raise AuditDenied("INDEPENDENT_AUDIT_VERDICT_DENIED")
  generation=value.get("source_generation")
  if not isinstance(generation,dict) or set(generation)!={"commit","tree"} or any(not HEX40.fullmatch(str(generation.get(k,""))) for k in ("commit","tree")):raise AuditDenied("INDEPENDENT_AUDIT_GENERATION_DENIED")
  if not HEX64.fullmatch(str(value.get("evidence_sha256",""))) or not isinstance(value.get("nonce"),str) or not value["nonce"]:raise AuditDenied("INDEPENDENT_AUDIT_EVIDENCE_DENIED")
  try:issued=datetime.fromisoformat(value["issued_at"].replace("Z","+00:00"));expires=datetime.fromisoformat(value["expires_at"].replace("Z","+00:00"));observed=now or datetime.now(timezone.utc)
  except Exception as error:raise AuditDenied("INDEPENDENT_AUDIT_FRESHNESS_DENIED") from error
  if issued.tzinfo is None or expires.tzinfo is None or observed.tzinfo is None or not issued<=observed<expires:raise AuditDenied("INDEPENDENT_AUDIT_FRESHNESS_DENIED")
  if route is not None and value["route"]!=route:raise AuditDenied("INDEPENDENT_AUDIT_ROUTE_DENIED")
  if boot_id is not None and value["boot_id"]!=boot_id:raise AuditDenied("INDEPENDENT_AUDIT_BOOT_DENIED")
  if source_generation is not None and generation!=source_generation:raise AuditDenied("INDEPENDENT_AUDIT_GENERATION_DENIED")
  body={k:v for k,v in value.items() if k!="signature"}
  try:key.verify(base64.urlsafe_b64decode(value["signature"]+"="*(-len(value["signature"])%4)),canonical(body))
  except Exception as error:raise AuditDenied("INDEPENDENT_AUDIT_SIGNATURE_DENIED") from error
  return True
 return verify
