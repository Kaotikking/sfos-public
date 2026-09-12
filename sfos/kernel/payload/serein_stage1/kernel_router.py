"""PRO-180 Kernel API/router foundation with reconstructable signed state."""
from __future__ import annotations
import hashlib,hmac,json,os,socket,sqlite3,struct,time
from pathlib import Path
from .supervision import inherited_systemd_socket,ready_and_watch
from .authority_contract import AuthorityDenied,validate as validate_authority
from .independent_audit import AuditDenied,verifier as independent_audit_verifier
ABILITIES=("kernel.route.register.v1","kernel.route.discover.v1","kernel.route.dispatch.v1","kernel.route.policy.evaluate.v1","kernel.route.status.query.v1","kernel.route.withdraw.v1","kernel.failover.select.v1","kernel.ingress.classify.v1","kernel.route.reconstruct.v1")
PLANES=frozenset({"ADMIN","COGNITIVE","RECOVERY"});POSTURES=frozenset({"ELIGIBLE","DEGRADED","INELIGIBLE"});UMP_STATES=frozenset({"KNOWN","UNKNOWN","CONFLICT"})
PLANE_CALLERS={"ADMIN":frozenset({"OUTPOST"}),"COGNITIVE":frozenset({"HAOS","ANDROID","ESP32","INTERNAL"}),"RECOVERY":frozenset({"OUTPOST"})}
POLICY_VERSION="KERNEL_ROUTE_POLICY_V1"
POLICY_DIGEST=hashlib.sha256(b"SEREIN_KERNEL_ROUTE_POLICY_V1\n").hexdigest()
class RouterDenied(RuntimeError):pass
def pending_independent_audit(_):raise RouterDenied("INDEPENDENT_AUDIT_PENDING")
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def _key(path):
 p=Path(path);value=p.read_bytes()
 if p.is_symlink() or len(value)!=32:raise RouterDenied("ROUTER_KEY_DENIED")
 return value
def ump(value):
 required={"schema","state","claims","authority_effect"}
 if not isinstance(value,dict) or set(value)!=required or value.get("schema")!="SEREIN/UMP/v1" or value.get("state") not in UMP_STATES or value.get("authority_effect")!="NONE" or not isinstance(value.get("claims"),list):raise RouterDenied("UMP_DENIED")
 if value["state"]!="KNOWN":raise RouterDenied("UMP_%s_DENIED"%value["state"])
 return value
class Router:
 def __init__(self,database,key_path,boot_id,clock=time.time,audit_verifier=pending_independent_audit):
  self.database=Path(database);self.key_path=key_path;self.boot_id=boot_id;self.clock=clock;self.audit_verifier=audit_verifier;self.database.parent.mkdir(parents=True,exist_ok=True);self._init()
 def _connect(self):return sqlite3.connect(self.database,timeout=10,isolation_level=None)
 def _init(self):
  with self._connect() as db:
   db.execute("PRAGMA journal_mode=WAL");db.execute("PRAGMA synchronous=FULL");db.execute("CREATE TABLE IF NOT EXISTS routes(route TEXT PRIMARY KEY,document TEXT NOT NULL)");db.execute("CREATE TABLE IF NOT EXISTS ledger(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL)");db.execute("CREATE TABLE IF NOT EXISTS authority_nonces(nonce TEXT PRIMARY KEY,route TEXT NOT NULL,action TEXT NOT NULL,boot_id TEXT NOT NULL)");db.execute("CREATE TABLE IF NOT EXISTS audit_nonces(nonce TEXT PRIMARY KEY,route TEXT NOT NULL,boot_id TEXT NOT NULL)")
 def _signed(self,body):return {"body":body,"signature":hmac.new(_key(self.key_path),canonical(body),hashlib.sha256).hexdigest()}
 def _append(self,db,event,details):
  previous=db.execute("SELECT event FROM ledger ORDER BY sequence DESC LIMIT 1").fetchone();prior=hashlib.sha256(previous[0].encode()).hexdigest() if previous else "0"*64
  body={"schema":"SEREIN/KernelRoutedDecision/v1","event":event,"details":details,"boot_id":self.boot_id,"observed_at":int(self.clock()),"previous_sha256":prior,"authority_effect":"NONE"};document=self._signed(body);db.execute("INSERT INTO ledger(event) VALUES(?)",(canonical(document).decode(),));return document
 def register(self,request):
  required={"schema","route","owner","plane","version","posture","qos","failover","ump","audit","authority_contract"}
  if not isinstance(request,dict) or set(request)!=required or request.get("schema")!="kernel.route.register.v1/request" or not request.get("route"," ").endswith(".v1") or request.get("plane") not in PLANES or request.get("posture")!="ELIGIBLE":raise RouterDenied("ROUTE_REGISTRATION_DENIED")
  audit=request.get("audit")
  if audit=={"gate":"PRO-174","status":"PASS"}:raise RouterDenied("OUTPOST_AUDIT_SUBSTITUTION_DENIED")
  if not isinstance(audit,dict) or audit.get("schema")!="SEREIN/IndependentRouteAudit/v1" or audit.get("route")!=request.get("route") or audit.get("status")!="PASS" or audit.get("auditor") in {None,"","OUTPOST"}:raise RouterDenied("INDEPENDENT_AUDIT_PENDING")
  observed=__import__("datetime").datetime.fromtimestamp(self.clock(),__import__("datetime").timezone.utc)
  try: authority=validate_authority(request["authority_contract"],action="kernel.route.register.v1",route=request["route"],boot_id=self.boot_id,caller="OUTPOST",now=observed,intent="COMMISSION_KERNEL_ROUTE",scope={"route":request["route"],"plane":request["plane"],"owner":request["owner"]},conditions=["INDEPENDENT_AUDIT_PASS","UMP_KNOWN","ROUTE_UNIQUE"],policy_version=POLICY_VERSION,policy_digest=POLICY_DIGEST,expected_result="ROUTE_REGISTERED")
  except AuthorityDenied as error: raise RouterDenied(str(error)) from error
  try: verified=self.audit_verifier(audit,route=request["route"],boot_id=self.boot_id,source_generation=authority["source_generation"],now=observed)
  except (AuditDenied,TypeError) as error:raise RouterDenied(str(error)) from error
  if verified is not True:raise RouterDenied("INDEPENDENT_AUDIT_SIGNATURE_DENIED")
  ump(request["ump"]);qos=request.get("qos")
  if not isinstance(qos,dict) or set(qos)!={"priority","capacity","backpressure"} or not isinstance(qos["capacity"],int) or qos["capacity"]<1 or qos["backpressure"] not in {"REJECT","QUEUE"}:raise RouterDenied("ROUTE_QOS_DENIED")
  if not isinstance(request.get("owner"),str) or not request["owner"] or not isinstance(request.get("failover"),list):raise RouterDenied("ROUTE_OWNER_DENIED")
  document={"schema":"SEREIN/KernelRouteRecord/v1",**{k:request[k] for k in ("route","owner","plane","version","posture","qos","failover")},"source_generation":authority["source_generation"],"registration_authority_sha256":hashlib.sha256(canonical(authority)).hexdigest(),"authority_contract":authority,"state":"ACTIVE","boot_id":self.boot_id,"authority_effect":"NONE"}
  with self._connect() as db:
   db.execute("BEGIN IMMEDIATE")
   if db.execute("SELECT 1 FROM routes WHERE route=?",(request["route"],)).fetchone():db.execute("ROLLBACK");raise RouterDenied("ROUTE_COLLISION_DENIED")
   if db.execute("SELECT 1 FROM authority_nonces WHERE nonce=?",(authority["nonce"],)).fetchone():db.execute("ROLLBACK");raise RouterDenied("AUTHORITY_REPLAY_DENIED")
   if not isinstance(audit.get("nonce"),str) or not audit["nonce"] or db.execute("SELECT 1 FROM audit_nonces WHERE nonce=?",(audit["nonce"],)).fetchone():db.execute("ROLLBACK");raise RouterDenied("INDEPENDENT_AUDIT_REPLAY_DENIED")
   db.execute("INSERT INTO authority_nonces VALUES(?,?,?,?)",(authority["nonce"],request["route"],authority["action"],self.boot_id));db.execute("INSERT INTO audit_nonces VALUES(?,?,?)",(audit["nonce"],request["route"],self.boot_id))
   db.execute("INSERT INTO routes VALUES(?,?)",(request["route"],canonical(document).decode()));receipt=self._append(db,"REGISTER",{"record":document,"authority_contract":authority});db.execute("COMMIT")
  return receipt
 def withdraw(self,route,reason,authority_contract,caller="OUTPOST"):
  observed=__import__("datetime").datetime.fromtimestamp(self.clock(),__import__("datetime").timezone.utc)
  try: authority=validate_authority(authority_contract,action="kernel.route.withdraw.v1",route=route,boot_id=self.boot_id,caller=caller,now=observed)
  except AuthorityDenied as error: raise RouterDenied(str(error)) from error
  with self._connect() as db:
   db.execute("BEGIN IMMEDIATE");row=db.execute("SELECT document FROM routes WHERE route=?",(route,)).fetchone()
   if not row:db.execute("ROLLBACK");raise RouterDenied("ROUTE_UNKNOWN_DENIED")
   if db.execute("SELECT 1 FROM authority_nonces WHERE nonce=?",(authority["nonce"],)).fetchone():db.execute("ROLLBACK");raise RouterDenied("AUTHORITY_REPLAY_DENIED")
   db.execute("INSERT INTO authority_nonces VALUES(?,?,?,?)",(authority["nonce"],route,authority["action"],self.boot_id))
   record=json.loads(row[0]);record["state"]="WITHDRAWN";record["posture"]="INELIGIBLE";db.execute("UPDATE routes SET document=? WHERE route=?",(canonical(record).decode(),route));receipt=self._append(db,"WITHDRAW",{"route":route,"reason":reason,"authority_contract_sha256":hashlib.sha256(canonical(authority)).hexdigest()});db.execute("COMMIT");return receipt
 def dispatch(self,request,active=0,pressure=None):
  required={"schema","request_id","conversation_id","route","plane","caller","ump","authority_contract"}
  if not isinstance(request,dict) or set(request)!=required or request.get("schema")!="kernel.route.dispatch.v1/request" or not request.get("request_id") or not request.get("conversation_id") or request.get("plane") not in PLANES:raise RouterDenied("INGRESS_DEFAULT_DENY")
  ump(request["ump"])
  if request.get("caller") not in PLANE_CALLERS[request["plane"]]:raise RouterDenied("INGRESS_CALLER_DENIED")
  observed=__import__("datetime").datetime.fromtimestamp(self.clock(),__import__("datetime").timezone.utc)
  with self._connect() as db:
   db.execute("BEGIN IMMEDIATE");row=db.execute("SELECT document FROM routes WHERE route=?",(request["route"],)).fetchone()
   if not row:db.execute("ROLLBACK");raise RouterDenied("ROUTE_UNKNOWN_DENIED")
   route=json.loads(row[0])
   try: authority=validate_authority(request["authority_contract"],action="kernel.route.dispatch.v1",route=request["route"],boot_id=self.boot_id,caller=request["caller"],now=observed,intent="DISPATCH_KERNEL_COMPUTE",scope={"route":request["route"],"plane":request["plane"],"caller":request["caller"]},conditions=["ROUTE_ACTIVE","UMP_KNOWN","CAPACITY_ENFORCED"],policy_version=POLICY_VERSION,policy_digest=POLICY_DIGEST,expected_result="ROUTE_DISPATCHED",source_generation=route.get("source_generation"))
   except AuthorityDenied as error:db.execute("ROLLBACK");raise RouterDenied(str(error)) from error
   if db.execute("SELECT 1 FROM authority_nonces WHERE nonce=?",(authority["nonce"],)).fetchone():db.execute("ROLLBACK");raise RouterDenied("AUTHORITY_REPLAY_DENIED")
   if route["state"]!="ACTIVE" or route["posture"]!="ELIGIBLE" or route["plane"]!=request["plane"]:db.execute("ROLLBACK");raise RouterDenied("ROUTE_POSTURE_DENIED")
   capacity=route["qos"]["capacity"]
   if active>=capacity:
    if route["qos"]["backpressure"]=="REJECT":db.execute("ROLLBACK");raise RouterDenied("ROUTE_BACKPRESSURE")
    db.execute("INSERT INTO authority_nonces VALUES(?,?,?,?)",(authority["nonce"],route["route"],authority["action"],self.boot_id));queued=self._append(db,"QUEUED",{"request_id":request["request_id"],"conversation_id":request["conversation_id"],"route":route["route"],"owner":route["owner"],"plane":route["plane"],"authority_contract":authority});db.execute("COMMIT");return queued
   evaluation={"required":bool(pressure and len(pressure)>=60 and all(float(x)>=0.90 for x in pressure[-60:])),"authority":"INHERITED_EXACT","automatic_expansion":False}
   db.execute("INSERT INTO authority_nonces VALUES(?,?,?,?)",(authority["nonce"],route["route"],authority["action"],self.boot_id))
   decision={"request_id":request["request_id"],"conversation_id":request["conversation_id"],"route":route["route"],"owner":route["owner"],"plane":route["plane"],"qos":route["qos"],"authority_contract":authority,"authority_contract_sha256":hashlib.sha256(canonical(authority)).hexdigest(),"expansion_evaluation":evaluation}
   receipt=self._append(db,"DISPATCH",decision);db.execute("COMMIT");return receipt
 def failover(self,route,authority_contract,caller):
  observed=__import__("datetime").datetime.fromtimestamp(self.clock(),__import__("datetime").timezone.utc)
  try: authority=validate_authority(authority_contract,action="kernel.failover.select.v1",route=route,boot_id=self.boot_id,caller=caller,now=observed)
  except AuthorityDenied as error: raise RouterDenied(str(error)) from error
  with self._connect() as db:
   db.execute("BEGIN IMMEDIATE")
   row=db.execute("SELECT document FROM routes WHERE route=?",(route,)).fetchone()
   if not row:db.execute("ROLLBACK");raise RouterDenied("ROUTE_UNKNOWN_DENIED")
   if db.execute("SELECT 1 FROM authority_nonces WHERE nonce=?",(authority["nonce"],)).fetchone():db.execute("ROLLBACK");raise RouterDenied("AUTHORITY_REPLAY_DENIED")
   record=json.loads(row[0])
   for candidate in record["failover"]:
    found=db.execute("SELECT document FROM routes WHERE route=?",(candidate,)).fetchone()
    if found:
     alternate=json.loads(found[0])
     compatible=all(alternate.get(k)==record.get(k) for k in ("owner","plane","version","qos"))
     if alternate["state"]=="ACTIVE" and alternate["posture"]=="ELIGIBLE" and compatible:
      db.execute("INSERT INTO authority_nonces VALUES(?,?,?,?)",(authority["nonce"],route,authority["action"],self.boot_id));receipt=self._append(db,"FAILOVER_SELECT",{"source_route":route,"selected_route":alternate["route"],"authority_contract_sha256":hashlib.sha256(canonical(authority)).hexdigest()});db.execute("COMMIT");return {"route":alternate,"receipt":receipt}
   db.execute("ROLLBACK")
  raise RouterDenied("ROUTE_FAILOVER_DENIED")
 def reconstruct(self):
  with self._connect() as db:routes=[json.loads(row[0]) for row in db.execute("SELECT document FROM routes ORDER BY route")];ledger=[json.loads(row[0]) for row in db.execute("SELECT event FROM ledger ORDER BY sequence")]
  key=_key(self.key_path);previous="0"*64;rebuilt={}
  for event in ledger:
   if event.get("body",{}).get("previous_sha256")!=previous or not hmac.compare_digest(event.get("signature",""),hmac.new(key,canonical(event["body"]),hashlib.sha256).hexdigest()):raise RouterDenied("ROUTE_RECONSTRUCTION_DENIED")
   previous=hashlib.sha256(canonical(event)).hexdigest();kind=event["body"]["event"];details=event["body"]["details"]
   if kind=="REGISTER":rebuilt[details["record"]["route"]]=details["record"]
   elif kind=="WITHDRAW" and details["route"] in rebuilt:rebuilt[details["route"]]={**rebuilt[details["route"]],"state":"WITHDRAWN","posture":"INELIGIBLE"}
  if [rebuilt[name] for name in sorted(rebuilt)]!=routes:raise RouterDenied("ROUTE_RECONSTRUCTION_STATE_DENIED")
  return {"schema":"kernel.route.reconstruct.v1/response","boot_id":self.boot_id,"routes":routes,"ledger":ledger,"posture":"DEGRADED" if any(x["state"]!="ACTIVE" for x in routes) else "ELIGIBLE","authority_effect":"NONE"}
def serve(database="/var/lib/serein/kernel/operations/router.sqlite3",key_path="/var/lib/serein/kernel/authority/replay.key",boot_path="/proc/sys/kernel/random/boot_id"):
 credential=Path(os.environ.get("CREDENTIALS_DIRECTORY","/run/credentials/serein-kernel-router.service"))/"independent-route-audit.pem";router=Router(database,key_path,Path(boot_path).read_text().strip(),audit_verifier=independent_audit_verifier(credential));expected=int(os.environ["SEREIN_OUTPOST_UID"])
 with inherited_systemd_socket() as server:
  ready_and_watch()
  while True:
   connection,_=server.accept()
   with connection:
    try:
     _,uid,_=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
     if uid!=expected:raise RouterDenied("ROUTER_PEER_DENIED")
     packet=json.loads(connection.recv(65537));response=_handle_packet(router,packet)
    except Exception as error:response={"status":"DENIED","reason":str(error),"authority_effect":"NONE"}
    connection.sendall(canonical(response))

def _handle_packet(router,packet):
 operation=packet.get("operation") if isinstance(packet,dict) else None
 if operation=="REGISTER" and set(packet)=={"operation","request"}:return {"status":"OK","receipt":router.register(packet["request"])}
 if operation=="WITHDRAW" and set(packet)=={"operation","route","reason","authority_contract"}:return {"status":"OK","receipt":router.withdraw(packet["route"],packet["reason"],packet["authority_contract"],caller="OUTPOST")}
 raise RouterDenied("ROUTER_OPERATION_DENIED")
