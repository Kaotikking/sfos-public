"""Outpost-owned read-only Host-gate presentation producer; opens no listener."""
from __future__ import annotations
import html
from datetime import datetime,timezone
from dataclasses import dataclass
from .host_vitality import HostVitalityError,HostVitalityStore,canonical,digest

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
def _outpost_operator_page(snapshot):
 latest=snapshot.get("latest",{}) if isinstance(snapshot,dict) else {}
 host=latest.get("host",{}) if isinstance(latest,dict) else {}
 gpu=latest.get("gpu",{}) if isinstance(latest,dict) else {}
 debian=latest.get("debian",{}) if isinstance(latest,dict) else {}
 classification=snapshot.get("classification","UNKNOWN")
 degraded=classification not in {"CURRENT_BOOT_STABLE","FIRST_BOOT_OBSERVED","RECOVERED_AFTER_BOOT_CHANGE"}
 recovery=(
  "Outpost observes a degraded or conflicting Host gate. Review the evidence below; "
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
  "<p>Persisted current-boot projection sequence: "+_status(snapshot.get("sample_count"))+". Classification: "+_status(classification)+".</p>"
  "<p>This is not Host self-report, domain admission, or recovery authority.</p></section>"
  "<section id='identity'><h2>Identity/Auth</h2><p>Target: "+_status(latest.get("target"))+"</p>"
  "<p>Boot: "+_status(snapshot.get("current_boot_id"))+"</p><p>Authority effect: NONE</p></section>"
  "<section id='health'><h2>Health</h2><p>Evidence maturity: OBSERVED. Admission: NOT PROVEN.</p><p>Host: "+_status(host.get("status"))+"</p>"
  "<p>GPU: "+_status(gpu.get("status"))+"</p><p>Debian: "+_status(debian.get("status"))+"</p>"
  "<p>Conflicting Vitals: "+("PRESENT" if degraded else "NONE OBSERVED")+"</p></section>"
  "<section id='rescue'><h2>Rescue Chat</h2>"
  "<h3>1. STATE</h3><p>"+_status(classification)+"</p>"
  "<h3>2. PERSPECTIVES</h3><p>The Host field inside the Outpost observation is "+_status(host.get("status"))+". Outpost classifies the projection as "+_status(classification)+". "+("CONFLICT — DO NOT ACT." if degraded else "No conflict is evidenced inside this Outpost dataset.")+"</p>"
  "<h3>3. SAFE PATH</h3><p>"+html.escape(recovery)+"</p>"
  "<h3>4. DECISION</h3><p>OPERATOR_REQUIRED only for a separately prepared consequential action; none is requested by this page.</p>"
  "<h3>5. STOP/WAKE</h3><p>Stop on UNKNOWN, STALE, REVOKED, or CONFLICT. Wake on fresh attributable evidence through the governed owning road.</p>"
  "<p>Recommendation is not authorization. This page cannot execute recovery.</p></section>"
  "<section id='resume'><h2>Resume</h2><p>Last-known-good reference: UNKNOWN — no source supplied in this Outpost dataset. Recovery execution: NOT AUTHORIZED.</p></section>"
  "<section id='domains'><h2>Domains</h2><p>Domain admission: UNKNOWN — no domain producer supplied in this Host-gate dataset.</p></section>"
  "<section id='hardware'><h2>Hardware/Frame</h2><p>GPU witness: "+_status(gpu.get("status"))+"; devices: "+_status(gpu.get("device_count"))+".</p></section>"
  "<section id='sereinnet'><h2>SereinNet</h2><p>Kernel and Gateway admission: UNKNOWN — no SereinNet producer supplied in this Host-gate dataset.</p></section>"
  "<section id='memory'><h2>Memory/Knowledge</h2><p>State: UNKNOWN — no Memory or Knowledge producer supplied in this Host-gate dataset.</p></section>"
  "<section id='evidence'><h2>Evidence/Logs</h2><p>Black-box event chronology: UNKNOWN — no event-log producer supplied in this Host-gate dataset.</p><p>Projection digest: "+_status(snapshot.get("projection_digest"))+"</p>"
  "<p>Observed at: "+_status(_when(latest.get("observed_at")))+"; monotonic sample sequence: "+_status(snapshot.get("sample_count"))+".</p>"
  "<details><summary>Deep evidence</summary><pre id='vitality'>"+html.escape(json_body(snapshot).decode().strip())+"</pre></details>"
  "</section><section id='controls'><h2>Operator controls</h2><h3>Budget</h3><p>Starting credit: UNKNOWN. Attributable spend: UNKNOWN. Estimated remaining: UNKNOWN. Unreconciled usage: UNKNOWN. Budget state: UNKNOWN — no budget producer supplied.</p><p>No mutation controls are exposed. Consequential actions require their governed owning path and explicit authority.</p></section>"
  "</main><footer><a href='#home'>Serein Vitals Home</a></footer>"
 )
def html_body(snapshot):
 projection=snapshot.get("projection_digest",digest(snapshot))
 return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Serein Vitals</title></head><body><p id='projection-digest'>"+html.escape(projection)+"</p>"+_outpost_operator_page(snapshot)+"</body></html>").encode()
def present(store:HostVitalityStore,method:str,path:str,accept:str,current_boot_id:str)->ReadOnlyPresentation:
 if method!="GET":return ReadOnlyPresentation(405,"application/json",canonical({"error":"READ_ONLY"}),SAFE_HEADERS)
 if path!="/v1/runtime/status":return ReadOnlyPresentation(404,"application/json",canonical({"error":"NOT_FOUND"}),SAFE_HEADERS)
 try:snapshot=store.snapshot()
 except (HostVitalityError,OSError,ValueError):return ReadOnlyPresentation(503,"application/json",canonical({"error":"VITALITY_UNAVAILABLE"}),SAFE_HEADERS)
 if snapshot.get("status")=="NO_OBSERVATION":return ReadOnlyPresentation(503,"application/json",canonical({"error":"VITALITY_UNAVAILABLE"}),SAFE_HEADERS)
 if not current_boot_id or snapshot.get("current_boot_id")!=current_boot_id:
  return ReadOnlyPresentation(503,"application/json",canonical({"error":"VITALITY_STALE_BOOT"}),SAFE_HEADERS)
 if "text/html" not in accept:return ReadOnlyPresentation(200,"application/json",json_body(snapshot),SAFE_HEADERS)
 return ReadOnlyPresentation(200,"text/html; charset=utf-8",html_body(snapshot),SAFE_HEADERS)
