"""Outpost-owned join verifier for the complete portable Kernel Stage-1 object."""
from __future__ import annotations
import hashlib,hmac,json,os,tempfile
from pathlib import Path
CLIENTS=("HAOS","ANDROID","ESP32","INTERNAL")
ORDER=("AUTHORITY","OPERATIONS","INTERFACE","GPU_CONTROL","OFFLINE_COMPANION","COGNITIVE_GATEWAY","OUTPOST_STAGE1_WITNESS")
class Stage1Denied(ValueError):pass
def _canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def verify(value):
 required={"schema","boot_id","branch_order","gpu","companion","gateways","attachments","observer","authority_effect"}
 if not isinstance(value,dict) or set(value)!=required or value.get("schema")!="SEREIN/OutpostKernelStage1Witness/v1" or value.get("observer")!="OUTPOST" or value.get("authority_effect")!="NONE":raise Stage1Denied("STAGE1_WITNESS_DENIED")
 if value.get("branch_order")!=list(ORDER[:3]) or value.get("gpu",{}).get("status")!="READY":raise Stage1Denied("STAGE1_PREREQUISITE_DENIED")
 companion=value.get("companion");gateways=value.get("gateways")
 if not isinstance(companion,dict) or companion.get("status")!="ANSWERED" or not companion.get("request_id") or not companion.get("conversation_id"):raise Stage1Denied("STAGE1_COMPANION_DENIED")
 if not isinstance(gateways,dict) or set(gateways)!=set(CLIENTS):raise Stage1Denied("STAGE1_GATEWAY_DENIED")
 for client,row in gateways.items():
  if not isinstance(row,dict) or row.get("client")!=client or row.get("process_isolation")!="DEDICATED" or row.get("request_id")!=companion["request_id"] or row.get("conversation_id")!=companion["conversation_id"]:raise Stage1Denied("STAGE1_GATEWAY_DENIED")
 attachments=value.get("attachments")
 if not isinstance(attachments,list) or len(attachments)!=9 or any(row.get("state")!="INERT" or row.get("activation")!="OUTPOST_ONLY" for row in attachments):raise Stage1Denied("STAGE1_ATTACHMENT_DENIED")
 return {"status":"STAGE1_READY","observer":"OUTPOST","boot_id":value["boot_id"],"order":list(ORDER),"request_id":companion["request_id"],"conversation_id":companion["conversation_id"],"authority_effect":"NONE"}

def persist(value,key_path="/var/lib/serein/kernel/authority/replay.key",state_path="/var/lib/serein/kernel/witness/stage1-current.json",boot_path="/proc/sys/kernel/random/boot_id"):
 result=verify(value);boot=Path(boot_path).read_text().strip()
 if value["boot_id"]!=boot:raise Stage1Denied("STAGE1_CURRENT_BOOT_DENIED")
 key_file=Path(key_path);key=key_file.read_bytes()
 if key_file.is_symlink() or len(key)!=32:raise Stage1Denied("STAGE1_KEY_CUSTODY_DENIED")
 body={"schema":"SEREIN/OutpostKernelStage1SignedWitness/v1","witness":value,"verification":result,"boot_id":boot,"authority_effect":"NONE"}
 document={"body":body,"signature":hmac.new(key,_canonical(body),hashlib.sha256).hexdigest()};document["digest"]=hashlib.sha256(_canonical(document)).hexdigest()
 destination=Path(state_path);destination.parent.mkdir(parents=True,exist_ok=True)
 fd,name=tempfile.mkstemp(prefix=".stage1-",dir=destination.parent)
 try:
  with os.fdopen(fd,"wb") as stream:fd=-1;stream.write(_canonical(document));stream.flush();os.fsync(stream.fileno())
  os.chmod(name,0o640);os.replace(name,destination);directory=os.open(destination.parent,os.O_RDONLY);os.fsync(directory);os.close(directory)
 finally:
  if fd!=-1:os.close(fd)
  if os.path.exists(name):os.unlink(name)
 return {"status":"WITNESS_DURABLE","path":str(destination),"digest":document["digest"],"boot_id":boot}

def read_current(key_path="/var/lib/serein/kernel/authority/replay.key",state_path="/var/lib/serein/kernel/witness/stage1-current.json",boot_path="/proc/sys/kernel/random/boot_id"):
 path=Path(state_path)
 if path.is_symlink() or not path.is_file():raise Stage1Denied("STAGE1_WITNESS_CUSTODY_DENIED")
 document=json.loads(path.read_bytes());digest=document.pop("digest",None)
 if digest!=hashlib.sha256(_canonical(document)).hexdigest():raise Stage1Denied("STAGE1_WITNESS_DIGEST_DENIED")
 body=document.get("body",{});key=Path(key_path).read_bytes();expected=hmac.new(key,_canonical(body),hashlib.sha256).hexdigest()
 if not hmac.compare_digest(expected,str(document.get("signature",""))):raise Stage1Denied("STAGE1_WITNESS_SIGNATURE_DENIED")
 if body.get("boot_id")!=Path(boot_path).read_text().strip():raise Stage1Denied("STAGE1_CURRENT_BOOT_DENIED")
 verify(body.get("witness"));return {**document,"digest":digest}
