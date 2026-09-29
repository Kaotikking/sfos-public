"""Outpost-owned read-only Host-gate presentation producer; opens no listener."""
from __future__ import annotations
import html
from datetime import datetime,timezone
from dataclasses import dataclass
from .host_vitality import HostVitalityError,HostVitalityStore,canonical,digest
from .vitals_runtime import VitalsRuntimeStore

@dataclass(frozen=True)
class ReadOnlyPresentation:
 status:int
 content_type:str
 body:bytes
 headers:tuple[tuple[str,str],...]

SAFE_HEADERS=(("Cache-Control","no-store"),("X-Content-Type-Options","nosniff"),("Content-Security-Policy","default-src 'none'; style-src 'none'; script-src 'none'"))
def json_body(snapshot):return canonical(snapshot)
def _status(value):
 return html.escape(str(value if value is not None else "UNKNOWN"))
def _when(value):
 try:return datetime.fromtimestamp(float(value),timezone.utc).isoformat().replace("+00:00","Z")
 except (TypeError,ValueError,OverflowError):return "UNKNOWN"
def _producer_evidence(snapshot,perspectives,missing,producers=None):
 sections=snapshot.get("sections",{})
 rows=[]
 for perspective in perspectives:
  section=sections.get(perspective,{})
  for item in section.get("perspectives",[]):
   if producers is not None and item.get("producer") not in producers:continue
   rows.append("<p>Perspective: "+_status(perspective)+". Source: "+_status(item.get("producer"))+". State: "+_status(section.get("state"))+". Claim: "+_status(item.get("claim"))+". Freshness: "+_status(item.get("freshness"))+". Observed: "+_status(_when(item.get("observed_at")))+". Evidence: "+_status(item.get("evidence_ref"))+".</p>")
 return "".join(rows) if rows else missing

def _recovery_summary(snapshot):
 rows=[]
 for source in snapshot.get("sections",{}).get("recovery",{}).get("perspectives",[]):
  value=source.get("payload",{})
  if value.get("schema")!="SereinOutpostRebootClassification/v1":continue
  post=value.get("post_boot",{})
  failed=post.get("failed_components",[])
  rows.append("<article aria-label='Boot recovery observation'><h3>Boot recovery observation</h3>"
   "<p>Subject: "+_status(value.get("subject"))+". Cause: "+_status(value.get("cause"))+". Recovery: "+_status(value.get("recovery"))+".</p>"
   "<p>Last seen: "+_status(_when(value.get("last_observed_at")))+". Returned: "+_status(_when(value.get("first_post_boot_at")))+". Observed: "+_status(_when(value.get("observed_at")))+".</p>"
   "<p>Previous boot: "+_status(value.get("previous_boot_id"))+". New boot: "+_status(value.get("new_boot_id"))+".</p>"
   "<p>Intent match: "+_status(value.get("intent_match"))+". Intent: "+_status(value.get("intent_id"))+". Evidence age: "+_status(source.get("freshness"))+".</p>"
   "<p>Failed to return: "+_status(", ".join(str(item) for item in failed) if failed else "NONE REPORTED — complete recovery is not implied")+".</p>"
   "<p>Recommended path: "+_status(value.get("recommended_action"))+". Observation only; no repair is authorized.</p></article>")
 return "".join(rows)

def _collection_attempt_summary(snapshot):
 rows=[]
 for source in snapshot.get("sections",{}).get("host",{}).get("perspectives",[]):
  payload=source.get("payload",{})
  if source.get("producer")!="OUTPOST_HOST_WITNESS" or "collection_attempt" not in payload:continue
  attempt=payload.get("collection_attempt") or {}
  start=attempt.get("start") or {};terminal=attempt.get("terminal") or {}
  rows.append("<article aria-label='Host verification attempt'><h3>Current Host verification attempt</h3>"
   "<p>Current result: "+_status(source.get("claim"))+". Failure code: "+_status(terminal.get("payload",{}).get("error_code"))+".</p>"
   "<p>Started: "+_status(_when(start.get("observed_at")))+". Completed: "+_status(_when(terminal.get("observed_at")))+".</p>")
  historical=payload.get("last_successful_observation")
  if isinstance(historical,dict):
   old=historical.get("latest",{})
   rows.append("<h3>Last successful observation — HISTORICAL ONLY</h3>"
    "<p>This retained observation is not current Host verification and does not pass the current gate.</p>"
    "<p>Historical classification: "+_status(historical.get("classification"))+". Observed: "+_status(_when(old.get("observed_at")))+".</p>"
    "<p>Historical boot: "+_status(historical.get("current_boot_id"))+". Projection digest: "+_status(historical.get("projection_digest"))+".</p>"
    "<p>Historical Host: "+_status(old.get("host",{}).get("status"))+". Historical GPU: "+_status(old.get("gpu",{}).get("status"))+". Historical Debian: "+_status(old.get("debian",{}).get("status"))+".</p>")
  else:rows.append("<p>Last successful observation: UNAVAILABLE.</p>")
  rows.append("</article>")
 return "".join(rows)

def _domain_registry_summary(snapshot):
 rows=[]
 for source in snapshot.get("sections",{}).get("domains",{}).get("perspectives",[]):
  payload=source.get("payload",{})
  if source.get("producer")!="OUTPOST_DOMAIN_COORDINATOR" or "registry" not in payload:continue
  rows.append("<h3>Canonical domain order — held, not admitted</h3>"
   "<p>Outpost owns installation and verification. This record permits no downstream activation.</p><ol>")
  for seed in payload["registry"]["seeds"]:
   rows.append("<li>"+_status(seed["domain"])+": "+_status(seed["status"])+"; "+_status(seed["admission"])+".</li>")
  rows.append("</ol><p>Kernel must be independently verified as the complete Companion foundation before Stage 1; Cloud remains last.</p>")
  view=payload.get("boot_verification",{})
  if view:
   rows.append("<h3>Every-boot verification</h3><p>Earliest unproven domain: "+_status(view.get("earliest_unproven_domain"))+". Gate: "+_status(view.get("earliest_unproven_gate"))+". Prior admission never proves this boot.</p><ol>")
   for domain in view.get("domains",[]):
    rows.append("<li>"+_status(domain.get("domain"))+": "+_status(domain.get("verification"))+". Current gate: "+_status(domain.get("current_gate"))+". Blueprint reference: "+_status(domain.get("blueprint",{}).get("reference"))+" (unadmitted). Installed generation: "+_status(domain.get("installed_generation"))+".")
    observation=domain.get("observation")
    if observation:
     rows.append(" Supporting observation only: "+_status(observation.get("claim"))+" at "+_status(observation.get("payload",{}).get("step"))+". Observed elapsed seconds: "+_status(domain.get("observation_elapsed"))+". Evidence: "+_status(observation.get("evidence_ref"))+".")
    if domain.get("historical_observation"):
     rows.append(" Prior-boot observation: HISTORICAL ONLY; not current verification.")
    rows.append(" Downstream hold: "+_status(", ".join(domain.get("downstream_hold",[])) or "NONE — Cloud is last")+".</li>")
   rows.append("</ol>")
 return "".join(rows)

def _outpost_operator_page(snapshot):
 latest=snapshot.get("latest",{}) if isinstance(snapshot,dict) else {}
 classification=snapshot.get("classification","UNKNOWN")
 conflicting_host=False
 if snapshot.get("schema")=="SereinVitalsAggregation/v1":
  section=snapshot.get("sections",{}).get("host",{})
  conflicting_host=section.get("state")=="DISAGREEMENT"
  witnessed=[item for item in section.get("perspectives",[]) if item.get("producer")=="OUTPOST_HOST_WITNESS" and item.get("freshness")=="CURRENT_BOOT_ATTRIBUTABLE"]
  host_state=witnessed[0].get("payload",{}) if len(witnessed)==1 else {}
  latest=host_state.get("latest",{})
  classification=section.get("claim") if section.get("state")=="OBSERVED" and len(witnessed)==1 else section.get("state","UNKNOWN")
 host=latest.get("host",{}) if isinstance(latest,dict) else {}
 gpu=latest.get("gpu",{}) if isinstance(latest,dict) else {}
 debian=latest.get("debian",{}) if isinstance(latest,dict) else {}
 degraded=classification not in {"CURRENT_BOOT_STABLE","FIRST_BOOT_OBSERVED","RECOVERED_AFTER_BOOT_CHANGE"}
 recovery=(
  "Outpost observes a degraded, unavailable or conflicting Host gate. Review the evidence below; "
  "any repair requires a separately authorized owning recovery road."
  if degraded else
  "Outpost observes no current Host-gate degradation. No recovery action is authorized by this page."
 )
 return (
  "<header id='home'><h1>Serein Vitals</h1>"
  "<p>Independent Outpost witness data. This surface is read-only and grants no authority.</p>"
  "<nav aria-label='Serein Vitals Home'>"
  "<a href='#observed'>Observed</a> | <a href='#identity'>Identity/Auth</a> | "
  "<a href='#health'>Health</a> | <a href='#rescue'>Rescue Chat</a> | "
  "<a href='#resume'>Resume</a> | <a href='#domains'>Domains</a> | <a href='#hardware'>Hardware/Frame</a> | "
  "<a href='#sereinnet'>SereinNet</a> | <a href='#memory'>Memory/Knowledge</a> | "
  "<a href='#evidence'>Evidence/Logs</a> | <a href='#controls'>Operator controls</a>"
  "</nav></header><main>"
  "<section id='observed'><h2>Observed</h2>"
  "<h3>Outpost Host observation</h3><p>Source: OUTPOST / host-vitality observation. Observed: "+_status(_when(latest.get("observed_at")))+". Host value: "+_status(host.get("status"))+".</p>"
  "<p>Persisted current-boot projection sequence: "+_status((host_state if snapshot.get("schema")=="SereinVitalsAggregation/v1" else snapshot).get("sample_count"))+". Classification: "+_status(classification)+".</p>"
  "<p>This is not Host self-report, domain admission, or recovery authority.</p>"+_collection_attempt_summary(snapshot)+_producer_evidence(snapshot,("host","serein","outpost"),"")+"</section>"
  "<section id='identity'><h2>Identity/Auth</h2><p>Target: "+_status(latest.get("target"))+"</p>"
  "<p>Boot: "+_status(snapshot.get("current_boot_id"))+"</p><p>Authority effect: NONE</p></section>"
  "<section id='health'><h2>Health</h2><p>Evidence maturity: OBSERVED. Admission: NOT PROVEN.</p><p>Host: "+_status(host.get("status"))+"</p>"
  "<p>GPU: "+_status(gpu.get("status"))+"</p><p>Debian: "+_status(debian.get("status"))+"</p>"
  "<p>Conflicting Host evidence: "+("PRESENT" if conflicting_host else "NONE OBSERVED")+"</p></section>"
  "<section id='rescue'><h2>Rescue Chat</h2>"
  "<h3>1. STATE</h3><p>"+_status(classification)+"</p>"
  "<h3>2. PERSPECTIVES</h3><p>The Host field inside the Outpost observation is "+_status(host.get("status"))+". Outpost classifies the projection as "+_status(classification)+". "+("CONFLICT — DO NOT ACT." if conflicting_host else "No disagreement between current Host observations is evidenced. Missing or degraded evidence is not agreement or admission.")+"</p>"
  "<h3>3. SAFE PATH</h3><p>"+html.escape(recovery)+"</p>"
  "<h3>4. DECISION</h3><p>OPERATOR_REQUIRED only for a separately prepared consequential action; none is requested by this page.</p>"
  "<h3>5. STOP/WAKE</h3><p>Stop on UNKNOWN, STALE, REVOKED, or CONFLICT. Wake on fresh attributable evidence through the governed owning road.</p>"
  "<p>Recommendation is not authorization. This page cannot execute recovery.</p></section>"
  "<section id='resume'><h2>Resume</h2>"+_recovery_summary(snapshot)+_producer_evidence(snapshot,("recovery",),"<p>Last-known-good reference: UNKNOWN — no source supplied in this Outpost dataset. Recovery execution: NOT AUTHORIZED.</p>")+"</section>"
  "<section id='domains'><h2>Domains</h2>"+_domain_registry_summary(snapshot)+_producer_evidence(snapshot,("domains",),"<p>Domain admission: UNKNOWN — no domain producer supplied in this Host-gate dataset.</p>")+"</section>"
  "<section id='hardware'><h2>Hardware/Frame</h2><p>GPU witness: "+_status(gpu.get("status"))+"; devices: "+_status(gpu.get("device_count"))+".</p></section>"
  "<section id='sereinnet'><h2>SereinNet</h2>"+_producer_evidence(snapshot,("serein",),"<p>Kernel and Gateway admission: UNKNOWN — no SereinNet producer supplied in this Host-gate dataset.</p>")+"</section>"
  "<section id='memory'><h2>Memory/Knowledge</h2><p>State: UNKNOWN — no Memory or Knowledge producer supplied in this Host-gate dataset.</p></section>"
  "<section id='evidence'><h2>Evidence/Logs</h2>"+_producer_evidence(snapshot,("outpost",),"<p>Black-box event chronology: UNKNOWN — no event-log producer supplied in this Host-gate dataset.</p>",{"OUTPOST_VITALITY_CHRONOLOGY"})+"<p>Projection digest: "+_status(snapshot.get("projection_digest"))+"</p>"
  "<p>Observed at: "+_status(_when(latest.get("observed_at")))+"; monotonic sample sequence: "+_status(snapshot.get("sample_count"))+".</p>"
  "<details><summary>Deep evidence</summary><pre id='vitality'>"+html.escape(json_body(snapshot).decode().strip())+"</pre></details>"
  "</section><section id='controls'><h2>Operator controls</h2><h3>Budget</h3>"+_producer_evidence(snapshot,("budget",),"<p>Starting credit: UNKNOWN. Attributable spend: UNKNOWN. Estimated remaining: UNKNOWN. Unreconciled usage: UNKNOWN. Budget state: UNKNOWN — no budget producer supplied.</p>")+"<p>No mutation controls are exposed. Consequential actions require their governed owning path and explicit authority.</p></section>"
  "</main><footer><a href='#home'>Serein Vitals Home</a></footer>"
 )
def html_body(snapshot):
 projection=snapshot.get("projection_digest",digest(snapshot))
 return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Serein Vitals</title></head><body><p id='projection-digest'>"+html.escape(projection)+"</p>"+_outpost_operator_page(snapshot)+"</body></html>").encode()
def present(store:HostVitalityStore,method:str,path:str,accept:str,current_boot_id:str)->ReadOnlyPresentation:
 if method!="GET":return ReadOnlyPresentation(405,"application/json",canonical({"error":"READ_ONLY"}),SAFE_HEADERS)
 if path!="/v1/runtime/status":return ReadOnlyPresentation(404,"application/json",canonical({"error":"NOT_FOUND"}),SAFE_HEADERS)
 try:snapshot=store.snapshot(current_boot_id=current_boot_id) if isinstance(store,VitalsRuntimeStore) else store.snapshot()
 except (HostVitalityError,OSError,ValueError):return ReadOnlyPresentation(503,"application/json",canonical({"error":"VITALITY_UNAVAILABLE"}),SAFE_HEADERS)
 if snapshot.get("status")=="NO_OBSERVATION":return ReadOnlyPresentation(503,"application/json",canonical({"error":"VITALITY_UNAVAILABLE"}),SAFE_HEADERS)
 if not current_boot_id or snapshot.get("current_boot_id")!=current_boot_id:
  return ReadOnlyPresentation(503,"application/json",canonical({"error":"VITALITY_STALE_BOOT"}),SAFE_HEADERS)
 if "text/html" not in accept:return ReadOnlyPresentation(200,"application/json",json_body(snapshot),SAFE_HEADERS)
 return ReadOnlyPresentation(200,"text/html; charset=utf-8",html_body(snapshot),SAFE_HEADERS)
