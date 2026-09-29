#!/usr/bin/env python3
"""Outpost-owned inactive Kernel installer; no domain admission or startup.

ADAPT: sfos-public 0dca6bd7a22b83b04ddf353df901d2c7ea15c294,
blob addf2e86cc9dca49ef3a268e523a801cbf3f7d68. This capability is inert
until its exact signed source, current Host gate and root-owned bounded
request exist. It does not install a privileged unit or grant the running
unprivileged coordinator new privileges. Future payload placement never
admits Authority, Operations, Interface or Stage 1.
"""
from __future__ import annotations
import base64,hashlib,hmac,json,os,pwd,grp,re,stat,tempfile
from contextlib import contextmanager
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key
from .transaction import strict_json
from .public_generation_transaction import CANONICAL_AUTHORITY_SHA256,IMMUTABLE_POLICY,public_generation_lock
from outpost.host_vitality import validate_state

STATE=Path("/var/lib/serein-outpost/kernel")
SOURCE=STATE/"source/sfos/kernel"
REQUEST=STATE/"install-request.json"
HOST_STATE=Path("/var/lib/serein-outpost/host-vitality/state.json")
SIGNING_KEY=Path("/etc/serein-outpost/cognition-signing.pem")
VERIFY_KEY=Path("/usr/share/serein/outpost/cognition-verification.pem")
SOURCE_RECEIPT=STATE/"source-receipt.json"
ORDER=("AUTHORITY","OPERATIONS","INTERFACE")
HEX40=re.compile(r"[0-9a-f]{40}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES=16*1024*1024

class RunnerDenied(RuntimeError):pass
def deny(value,message):
 if value:raise RunnerDenied(message)
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def decode(value):return base64.urlsafe_b64decode(value+"="*(-len(value)%4))
def regular(path,*,fact=False):
 """Read existing custody without changing accounts, keys or permissions."""
 path=Path(path);deny(not path.is_absolute() or ".." in path.parts,"KERNEL_RUNNER_PATH_DENIED")
 descriptors=[]
 try:
  parent=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);descriptors.append((parent,None,None))
  for part in path.parts[1:-1]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);descriptors.append((child,parent,part));parent=child
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
  with os.fdopen(fd,"rb") as stream:
   before=os.fstat(stream.fileno());mode=stat.S_IMODE(before.st_mode)
   owner=identity("serein-outpost") if path==HOST_STATE else {"uid":0,"gid":0}
   modes={0o600} if path in {REQUEST,HOST_STATE,SOURCE_RECEIPT} else ({0o640} if path==SIGNING_KEY else {int(IMMUTABLE_POLICY[str(path)],8)} if str(path) in IMMUTABLE_POLICY else {0o600,0o644,0o755})
   deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE_BYTES or before.st_uid!=owner["uid"] or mode not in modes,"KERNEL_RUNNER_CUSTODY_DENIED")
   if path==HOST_STATE:deny(before.st_gid!=owner["gid"],"KERNEL_RUNNER_CUSTODY_DENIED")
   data=stream.read(MAX_FILE_BYTES+1);after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
   fingerprint=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
   deny(len(data)!=before.st_size or fingerprint(before)!=fingerprint(after) or fingerprint(after)!=fingerprint(named),"KERNEL_RUNNER_FILE_CHANGED")
  for fd,parent_fd,name in descriptors[1:]:
   opened=os.fstat(fd);named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
   deny((opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_gid)!=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid),"KERNEL_RUNNER_FILE_CHANGED")
  return (sha(data),before.st_uid,before.st_gid,mode,len(data)) if fact else data
 except OSError as exc:raise RunnerDenied("KERNEL_RUNNER_FILE_DENIED") from exc
 finally:
  for fd,_,_ in reversed(descriptors):os.close(fd)
def read_json(path):
 try:value=strict_json(regular(path))
 except Exception as exc:raise RunnerDenied("KERNEL_RUNNER_JSON_DENIED") from exc
 deny(not isinstance(value,dict),"KERNEL_RUNNER_JSON_DENIED");return value
def safe_tree(root):
 root=Path(root);cursor=Path(root.anchor);enforce_owner=root==SOURCE
 for part in root.parts[1:]:
  cursor/=part;deny(cursor.is_symlink() or not cursor.is_dir(),"KERNEL_SOURCE_ANCESTOR_DENIED")
  if enforce_owner:
   info=cursor.stat();service=identity("serein-outpost") if cursor==Path("/var/lib/serein-outpost") else None
   expected=(service["uid"],service["gid"],0o750) if service else None
   deny((info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=expected if expected else info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022,"KERNEL_SOURCE_CUSTODY_DENIED")
 rows=[]
 for path in sorted(root.rglob("*")):
  deny(path.is_symlink(),"KERNEL_SOURCE_SYMLINK_DENIED")
  if path.is_dir():
   info=path.stat();deny(enforce_owner and (info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022),"KERNEL_SOURCE_CUSTODY_DENIED");continue
  deny(not path.is_file(),"KERNEL_SOURCE_TYPE_DENIED");data=regular(path);rows.append({"path":path.relative_to(root).as_posix(),"bytes":len(data),"sha256":sha(data)})
 return rows
def source_receipt(source,path,verify_path):
 value=read_json(path);required={"schema","repository","ref","source_parent","source_commit","source_tree","archive_sha256","release_digest","inventory_digest","signature"}
 deny(set(value)!=required or value["schema"]!="SereinOutpostKernelSourceReceipt/v1" or value["repository"]!="Kaotikking/sfos-public" or value["ref"]!="refs/heads/main","KERNEL_SOURCE_RECEIPT_DENIED")
 deny(any(not HEX40.fullmatch(str(value[x])) for x in ("source_parent","source_commit","source_tree")) or not HEX64.fullmatch(str(value["archive_sha256"])) or not re.fullmatch(r"sha256:[0-9a-f]{64}",str(value["release_digest"])) or not re.fullmatch(r"sha256:[0-9a-f]{64}",str(value["inventory_digest"])),"KERNEL_SOURCE_RECEIPT_LINEAGE_DENIED")
 try:load_pem_public_key(regular(verify_path)).verify(decode(value["signature"]),canonical({k:v for k,v in value.items() if k!="signature"}))
 except Exception as exc:raise RunnerDenied("KERNEL_SOURCE_RECEIPT_SIGNATURE_DENIED") from exc
 inventory=safe_tree(source);deny(value["inventory_digest"]!="sha256:"+sha(canonical(inventory)),"KERNEL_SOURCE_INVENTORY_DENIED");return value,sha(canonical(value))
def identity(user):
 account=pwd.getpwnam(user);group=grp.getgrnam(user)
 return {"user":user,"group":user,"uid":account.pw_uid,"gid":group.gr_gid,"primary_gid":account.pw_gid,"members":sorted(group.gr_mem)}
@contextmanager
def witness_directory(path):
 """Existing root-private request/witness directory; never create/repair it."""
 handles=[]
 try:
  fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);handles.append((fd,None,None))
  for part in Path(path).parts[1:]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);handles.append((child,fd,part));fd=child
  info=os.fstat(fd);deny((info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o700),"KERNEL_WITNESS_PARENT_DENIED")
  custody=lambda item:(item.st_dev,item.st_ino,item.st_uid,item.st_gid,item.st_mode)
  captured={child:custody(os.fstat(child)) for child,_,_ in handles}
  def unchanged():
   for child,parent,name in handles[1:]:
    opened=os.fstat(child);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
    deny(custody(opened)!=captured[child] or custody(named)!=captured[child],"KERNEL_WITNESS_PARENT_CHANGED")
  unchanged();yield fd,unchanged;unchanged()
 except OSError as exc:raise RunnerDenied("KERNEL_WITNESS_PARENT_DENIED") from exc
 finally:
  for fd,_,_ in reversed(handles):os.close(fd)

def atomic(path,value,directory_fd,check_parent):
 """Publish once via link-at: a concurrent witness is never overwritten."""
 name=".kernel-witness-"+os.urandom(16).hex();fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory_fd)
 try:
  with os.fdopen(fd,"wb") as stream:fd=-1;stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
  check_parent()
  try:os.link(name,path.name,src_dir_fd=directory_fd,dst_dir_fd=directory_fd,follow_symlinks=False)
  except FileExistsError:raise RunnerDenied("KERNEL_WITNESS_COLLISION_DENIED") from None
  os.fsync(directory_fd)
 finally:
  if fd!=-1:os.close(fd)
  os.unlink(name,dir_fd=directory_fd);os.fsync(directory_fd)
def payload_rows(source,manifest,layout):
 roots=layout.get("payload_roots");deny(not isinstance(roots,dict),"KERNEL_LAYOUT_DENIED");rows=[]
 for item in manifest.get("payload",[]):
  deny(not isinstance(item,list) or len(item)!=4,"KERNEL_MANIFEST_DENIED");relative,size,digest,mode=item
  prefix=next((p for p in roots if relative==p or relative.startswith(p+"/")),None);deny(prefix is None,"KERNEL_LAYOUT_DENIED")
  suffix=relative[len(prefix):].lstrip("/");target=roots[prefix].rstrip("/")+"/"+suffix;name=Path(relative).name
  branch="INTERFACE" if "interface" in name else ("OPERATIONS" if "operations" in name else "AUTHORITY")
  rows.append({"branch":branch,"source":relative,"target":target,"bytes":size,"sha256":digest,"mode":mode})
 rows.sort(key=lambda row:(ORDER.index(row["branch"]),row["target"]));return rows

def current_host_gate(host_path,boot_id):
 """Consume the canonical data-derived Host witness, not verdict labels."""
 try:host=validate_state(read_json(host_path),active=True)
 except (ValueError,TypeError,KeyError) as exc:raise RunnerDenied("KERNEL_HOST_GATE_DENIED") from exc
 deny(host["current_boot_id"]!=boot_id or host["classification"] not in {"CURRENT_BOOT_STABLE","FIRST_BOOT_OBSERVED","RECOVERED_AFTER_BOOT_CHANGE"},"KERNEL_HOST_GATE_DENIED")
 return host

def current_boot():
 return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
def build_plan(source=SOURCE,request_path=REQUEST,host_path=HOST_STATE,verify_path=VERIFY_KEY,source_receipt_path=SOURCE_RECEIPT):
 request=read_json(request_path);required={"schema","target_vm_id","repository","source_parent","source_commit","source_tree","archive_sha256","rollback_selector"}
 deny(set(request)!=required or request["schema"]!="SereinOutpostKernelInstallRequest/v1" or request["target_vm_id"]!="VM4010" or request["repository"]!="Kaotikking/sfos-public","KERNEL_REQUEST_DENIED")
 deny(any(not HEX40.fullmatch(str(request[x])) for x in ("source_parent","source_commit","source_tree")) or not HEX64.fullmatch(str(request["archive_sha256"])),"KERNEL_REQUEST_LINEAGE_DENIED")
 receipt,receipt_digest=source_receipt(source,source_receipt_path,verify_path);deny(any(request[x]!=receipt[x] for x in ("repository","source_parent","source_commit","source_tree","archive_sha256")),"KERNEL_REQUEST_SOURCE_BINDING_DENIED")
 host=current_host_gate(host_path,current_boot())
 manifest=read_json(source/"release-manifest.json");unsigned={k:v for k,v in manifest.items() if k!="self_digest"};deny(manifest.get("self_digest")!="sha256:"+sha(canonical(unsigned)) or receipt["release_digest"]!=manifest.get("self_digest"),"KERNEL_MANIFEST_DENIED")
 installer=regular(source/"install/kernel_first_install.py");installer_rows=manifest.get("installer_files",[]);deny(not any(row==["install/kernel_first_install.py",len(installer),sha(installer),"0755"] for row in installer_rows),"KERNEL_INSTALLER_DENOMINATOR_DENIED")
 layout=read_json(source/"install-layout.json");rows=payload_rows(source,manifest,layout);deny(manifest.get("install_denominator_digest")!="sha256:"+sha(canonical(rows)),"KERNEL_DENOMINATOR_DENIED")
 plan={"schema":"SereinPublicKernelFirstInstallPlan/v1","target_vm_id":"VM4010","source_parent":request["source_parent"],"source_commit":request["source_commit"],"source_tree":request["source_tree"],"release_digest":manifest["self_digest"],"current_boot_id":host["current_boot_id"],"outpost_identity":identity("serein-outpost"),"replay_identity":identity("serein-stage1"),"payload":rows,"rollback_selector":request["rollback_selector"],"authority_sha256":sha(regular(verify_path)),"archive_sha256":request["archive_sha256"],"source_receipt_sha256":receipt_digest,"source_inventory_digest":receipt["inventory_digest"]}
 return plan
def verify_install(root,plan,receipt):
 receipt_path=Path(root).joinpath(*Path(receipt["receipt"]).parts[1:]);value=read_json(receipt_path);required={"schema","plan_sha256","boot_id","branch_order","prestate","replacements","rollback_selector","rollback_auth_sha256","receipt_signature","receipt_digest"};deny(set(value)!=required or value.get("schema")!="SereinPublicKernelFirstInstallReceipt/v1","KERNEL_INSTALL_RECEIPT_SCHEMA_DENIED");digest=value.pop("receipt_digest",None);deny(digest!=sha(canonical(value)) or value.get("plan_sha256")!=sha(canonical(plan)) or value.get("boot_id")!=plan["current_boot_id"] or value.get("rollback_selector")!=plan["rollback_selector"] or value.get("branch_order")!=list(ORDER),"KERNEL_INSTALL_RECEIPT_DENIED")
 signature=value.pop("receipt_signature",None);auth=regular(receipt_path.parent/"rollback-auth.key");deny(sha(auth)!=value.get("rollback_auth_sha256") or not hmac.compare_digest(base64.urlsafe_b64encode(hmac.new(auth,canonical(value),hashlib.sha256).digest()).decode().rstrip("="),str(signature)),"KERNEL_INSTALL_RECEIPT_SIGNATURE_DENIED")
 replacements=value.get("replacements");generated={"/var/lib/serein/kernel/authority/replay.key","/var/lib/serein/kernel/authority/replay-descriptor.json","/etc/serein/kernel/replay-peer.env"};expected_payload=[{**{key:row[key] for key in ("target","bytes","sha256","mode","branch")},"uid":0,"gid":0} for row in plan["payload"]];payload_rows=[row for row in replacements if row.get("target") not in generated] if isinstance(replacements,list) else []
 deny(not isinstance(replacements,list) or len(replacements)!=len(expected_payload)+len(generated) or payload_rows!=expected_payload or {row.get("target") for row in replacements if row.get("target") in generated}!=generated or any(set(row)!={"target","bytes","sha256","mode","uid","gid","branch"} for row in replacements),"KERNEL_INSTALL_INVENTORY_DENIED")
 generated_rows={row["target"]:row for row in replacements if row["target"] in generated};replay=plan["replay_identity"]
 deny((generated_rows["/var/lib/serein/kernel/authority/replay.key"]["mode"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["uid"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["gid"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["branch"])!=("0600",replay["uid"],replay["gid"],"AUTHORITY"),"KERNEL_REPLAY_KEY_CUSTODY_DENIED")
 for target,mode in (("/var/lib/serein/kernel/authority/replay-descriptor.json","0644"),("/etc/serein/kernel/replay-peer.env","0600")):deny((generated_rows[target]["mode"],generated_rows[target]["uid"],generated_rows[target]["gid"],generated_rows[target]["branch"])!=(mode,0,0,"AUTHORITY"),"KERNEL_GENERATED_CUSTODY_DENIED")
 deny(value.get("prestate")!= [{"target":row["target"],"state":"ABSENT"} for row in replacements],"KERNEL_INSTALL_PRESTATE_DENIED")
 for row in replacements:
  path=Path(root).joinpath(*Path(row["target"]).parts[1:]);info=path.lstat();data=path.read_bytes();deny(path.is_symlink() or not stat.S_ISREG(info.st_mode) or len(data)!=row["bytes"] or sha(data)!=row["sha256"] or stat.S_IMODE(info.st_mode)!=int(row["mode"],8) or (os.name!="nt" and (info.st_uid!=row["uid"] or info.st_gid!=row["gid"])),"KERNEL_INSTALL_INVENTORY_DENIED")
 journal=read_json(receipt_path.parent/"phase-journal.json");deny(journal.get("receipt_digest")!=digest or journal.get("state")!="INSTALLED_INACTIVE" or journal.get("completed")!=[row["target"] for row in replacements],"KERNEL_INSTALL_JOURNAL_DENIED")
 return digest
def run(root=Path("/"),source=SOURCE,request_path=REQUEST,host_path=HOST_STATE,signing_path=SIGNING_KEY,verify_path=VERIFY_KEY,source_receipt_path=SOURCE_RECEIPT,installer=None,rollback_installer=None):
 # Serialize with Outpost promotion using its already-proven root-private lock.
 # Do not introduce a service-owned privileged lock or a new root service.
 boot=current_boot();request_raw=regular(request_path)
 with public_generation_lock(root,sha(request_raw),boot),witness_directory(STATE) as (witness_fd,check_parent):
  deny(os.path.lexists(STATE/"kernel-install-witness.json"),"KERNEL_WITNESS_COLLISION_DENIED")
  plan=build_plan(source,request_path,host_path,verify_path,source_receipt_path);deny(plan["current_boot_id"]!=boot or regular(request_path)!=request_raw,"KERNEL_REQUEST_CHANGED")
  immutable={path:regular(Path(root)/path.lstrip("/"),fact=True) for path in IMMUTABLE_POLICY}
  deny(sha(regular(verify_path))!=CANONICAL_AUTHORITY_SHA256,"KERNEL_CANONICAL_ANCHOR_DENIED")
  private=load_pem_private_key(regular(signing_path),password=None);plan["signature"]=base64.urlsafe_b64encode(private.sign(canonical(plan))).decode().rstrip("=")
  def boundary():
   check_parent();deny(current_boot()!=boot or regular(request_path)!=request_raw,"KERNEL_REQUEST_CHANGED")
   current_host_gate(host_path,boot)
   deny(any(regular(Path(root)/path.lstrip("/"),fact=True)!=fact for path,fact in immutable.items()),"KERNEL_IMMUTABLE_CHANGED")
   deny("sha256:"+sha(canonical(safe_tree(source)))!=plan["source_inventory_digest"],"KERNEL_SOURCE_CHANGED_DURING_INSTALL")
  boundary()
  if installer is None:
   import importlib.util
   module_path=source/"install/kernel_first_install.py";module_bytes=regular(module_path);manifest=read_json(source/"release-manifest.json")
   deny(manifest.get("self_digest")!="sha256:"+sha(canonical({k:v for k,v in manifest.items() if k!="self_digest"})) or manifest["self_digest"]!=plan["release_digest"] or not any(row==["install/kernel_first_install.py",len(module_bytes),sha(module_bytes),"0755"] for row in manifest["installer_files"]),"KERNEL_INSTALLER_DENOMINATOR_DENIED")
   spec=importlib.util.spec_from_file_location("_serein_kernel_first_install",module_path);deny(spec is None or spec.loader is None,"KERNEL_INSTALLER_DENIED");module=importlib.util.module_from_spec(spec);exec(compile(module_bytes,str(module_path),"exec"),module.__dict__);installer=module.install;rollback_installer=module.rollback
  boundary()
  receipt=installer(root,source,plan,boundary=boundary);canonical_receipt=Path(root).joinpath(*Path(plan["rollback_selector"]+"/receipt.json").parts[1:])
  try:
   deny(receipt.get("status")!="INSTALLED_INACTIVE" or receipt.get("receipt")!=plan["rollback_selector"]+"/receipt.json","KERNEL_INSTALL_RECEIPT_DENIED");deny("sha256:"+sha(canonical(safe_tree(source)))!=plan["source_inventory_digest"],"KERNEL_SOURCE_CHANGED_DURING_INSTALL");receipt_digest=verify_install(root,plan,receipt)
   witness={"schema":"SereinOutpostKernelInstallWitness/v1","target":"VM4010","boot_id":plan["current_boot_id"],"source_commit":plan["source_commit"],"source_tree":plan["source_tree"],"archive_sha256":plan["archive_sha256"],"source_receipt_sha256":plan["source_receipt_sha256"],"release_digest":plan["release_digest"],"installer_receipt_sha256":receipt_digest,"branch_order":list(ORDER),"install_status":receipt["status"],"admission":"INDEPENDENT_AUDIT_PENDING","stage1":"NOT_READY","rollback_selector":plan["rollback_selector"],"authority_effect":"NONE"};witness["witness_digest"]=sha(canonical(witness));boundary();atomic(STATE/"kernel-install-witness.json",witness,witness_fd,check_parent)
  except Exception:
   deny(rollback_installer is None,"KERNEL_POSTINSTALL_ROLLBACK_UNAVAILABLE");rollback_installer(root,canonical_receipt,boundary=boundary);raise
  return witness
if __name__=="__main__":
 deny(os.geteuid()!=0,"KERNEL_INSTALLER_ROOT_REQUIRED")
 run()
