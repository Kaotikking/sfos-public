"""Canonical HAOS-only HTTPS edge for the private Kernel Gateway."""
from __future__ import annotations
import hmac,json,os,socket,ssl
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from uuid import UUID

PATH="/v1/voice/conversation";SOCKET=Path("/run/serein/kernel/gateway-haos.sock")
MAX_REQUEST=128*1024;MAX_RESPONSE=64*1024;MAX_TEXT=1024
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def credential(directory,name):
 path=Path(directory)/name
 if path.is_symlink() or not path.is_file():raise RuntimeError("credential_unavailable")
 value=path.read_bytes()
 if name=="haos-companion-token" and (not 32<=len(value)<=4096 or b"\n" in value or b"\r" in value):raise RuntimeError("credential_invalid")
 return value
def bearer(value):
 if not isinstance(value,str) or not value.startswith("Bearer ") or value.count(" ")!=1 or not value[7:]:raise ValueError("conversation_token_invalid")
 return value[7:]
def validate(payload,authorization,token,now=None):
 if not payload or len(payload)>MAX_REQUEST:raise ValueError("conversation_request_size_invalid")
 supplied=bearer(authorization).encode()
 if not hmac.compare_digest(supplied,token):raise ValueError("conversation_token_invalid")
 try:value=json.loads(payload.decode())
 except Exception as error:raise ValueError("conversation_json_invalid") from error
 fields={"conversation_id","request_id","machine_identity","requested_operation","utterance","observed_at"}
 if not isinstance(value,dict) or set(value)!=fields:raise ValueError("conversation_envelope_invalid")
 try:UUID(value["request_id"])
 except Exception as error:raise ValueError("conversation_request_id_invalid") from error
 if any(not isinstance(value[x],str) or not value[x].strip() for x in ("conversation_id","machine_identity")):raise ValueError("conversation_identity_invalid")
 if value["requested_operation"]!="conversation_only":raise ValueError("conversation_operation_not_admitted")
 text=value["utterance"]
 if not isinstance(text,str) or not text.strip() or len(text)>MAX_TEXT or "\0" in text:raise ValueError("conversation_utterance_invalid")
 try:observed=datetime.fromisoformat(str(value["observed_at"]).replace("Z","+00:00"))
 except Exception as error:raise ValueError("conversation_observed_at_invalid") from error
 if observed.tzinfo is None:raise ValueError("conversation_observed_at_invalid")
 age=((now or datetime.now(timezone.utc))-observed.astimezone(timezone.utc)).total_seconds()
 if age>120:raise ValueError("conversation_observation_stale")
 if age < -5:raise ValueError("conversation_observation_future")
 return value
def forward(request,socket_path=SOCKET):
 packet={"schema":"SereinStage1Request/v1","request_id":request["request_id"],"authority":"local-operator","action":"companion","conversation":{k:request[k] for k in ("conversation_id","machine_identity","requested_operation","utterance","observed_at")}}
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
  client.settimeout(18);client.connect(str(socket_path));client.sendall(canonical(packet));raw=client.recv(MAX_RESPONSE+1)
 if not raw or len(raw)>MAX_RESPONSE:raise RuntimeError("gateway_response_size_invalid")
 response=json.loads(raw.decode());result=response.get("result") if isinstance(response,dict) else None
 if response.get("schema")!="SereinStage1Response/v1" or response.get("request_id")!=request["request_id"]:raise RuntimeError("gateway_response_invalid")
 if response.get("status")!="ANSWERED" or not isinstance(result,dict) or result.get("state")!="READY" or result.get("conversation_id")!=request["conversation_id"] or result.get("scope")!="stage1-bounded-companion" or result.get("authority_effect")!="NONE" or result.get("effects")!=[] or not isinstance(result.get("response"),str) or not result["response"].strip():raise RuntimeError("inference_unavailable")
 return {"status":"ANSWERED","request_id":request["request_id"],"conversation_id":request["conversation_id"],"response":result["response"],"continue_conversation":False,"authority_effect":"NONE","effects":[]}
class Handler(BaseHTTPRequestHandler):
 server_version="SereinGateway/1";sys_version=""
 def reply(self,status,value,request_id=None):
  body=canonical(value);self.send_response(status);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)));self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff")
  if request_id:self.send_header("X-Serein-Request-ID",request_id)
  self.end_headers();self.wfile.write(body)
 def do_POST(self):
  if self.path!=PATH:self.reply(405,{"status":"DENIED","reason":"method_not_admitted"});return
  if self.headers.get_content_type()!="application/json":self.reply(415,{"status":"DENIED","reason":"conversation_content_type_invalid"});return
  values=self.headers.get_all("Content-Length",[])
  try:length=int(values[0]) if len(values)==1 else -1
  except ValueError:length=-1
  if not 1<=length<=MAX_REQUEST:self.reply(400,{"status":"DENIED","reason":"conversation_request_size_invalid"});return
  payload=self.rfile.read(length)
  if len(payload)!=length:self.reply(400,{"status":"DENIED","reason":"conversation_request_size_invalid"});return
  try:
   request=self.server.validate(payload,self.headers.get("Authorization"));result=self.server.gateway(request)
  except ValueError as error:self.reply(403,{"status":"DENIED","reason":str(error)});return
  except Exception:self.reply(503,{"status":"UNAVAILABLE","reason":"gateway_unavailable"});return
  self.reply(200,result,request["request_id"])
 def do_GET(self):self.reply(405,{"status":"DENIED","reason":"method_not_admitted"})
 def log_message(self,*_):return
class Server(ThreadingHTTPServer):
 def __init__(self,address,credential_value,**kwargs):super().__init__(address,Handler,**kwargs);self.companion_credential=credential_value
 def validate(self,payload,authorization):return validate(payload,authorization,self.companion_credential)
 gateway=staticmethod(forward)
def tls_context(directory):
 cert=Path(directory)/"serein-backend-cert.pem";key=Path(directory)/"serein-backend-key.pem"
 if cert.is_symlink() or key.is_symlink() or not cert.is_file() or not key.is_file():raise RuntimeError("tls_credential_unavailable")
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(cert,key);return context
def serve():
 directory=os.environ.get("CREDENTIALS_DIRECTORY")
 if not directory:raise RuntimeError("systemd_credentials_directory_required")
 address=os.environ.get("SEREIN_HAOS_BIND_ADDRESS","127.0.0.1");port=int(os.environ.get("SEREIN_HAOS_BIND_PORT","8444"))
 server=Server((address,port),credential(directory,"haos-companion-token"));server.socket=tls_context(directory).wrap_socket(server.socket,server_side=True);server.serve_forever()
