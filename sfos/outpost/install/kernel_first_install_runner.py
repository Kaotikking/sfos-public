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
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key,Encoding,PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
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
NATIVE_KEY="/var/lib/serein/kernel/authority/domain-identity.pem"
NATIVE_REGISTRY="/var/lib/serein/kernel/authority/domain-identity.json"
GENERATED=("/var/lib/serein/kernel/authority/replay.key","/var/lib/serein/kernel/authority/replay-descriptor.json","/etc/serein/kernel/replay-peer.env",NATIVE_KEY,NATIVE_REGISTRY)
HEX40=re.compile(r"[0-9a-f]{40}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES=16*1024*1024

class RunnerDenied(RuntimeError):pass
def deny(value,message):
 if value:raise RunnerDenied(message)
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def decode(value):return base64.urlsafe_b64decode(value+"="*(-len(value)%4))
def regular(path,*,fact=False,host_capture=False):
 """Read existing custody without changing accounts, keys or permissions."""
 path=Path(path);deny(not path.is_absolute() or ".." in path.parts,"KERNEL_RUNNER_PATH_DENIED")
 deny(host_capture and path.parts[-2:]!=("etc","machine-id"),"KERNEL_HOST_IDENTITY_PATH_DENIED")
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
   if host_capture:modes={mode} if not mode & 0o022 and before.st_gid==0 else set()
   deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE_BYTES or before.st_uid!=owner["uid"] or mode not in modes,"KERNEL_RUNNER_CUSTODY_DENIED")
   if path==HOST_STATE:deny(before.st_gid!=owner["gid"],"KERNEL_RUNNER_CUSTODY_DENIED")
   data=stream.read(MAX_FILE_BYTES+1);after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
   if host_capture:
    stream.seek(0);deny(stream.read(MAX_FILE_BYTES+1)!=data,"KERNEL_HOST_IDENTITY_CHANGED")
    after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
   fingerprint=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
   deny(len(data)!=before.st_size or fingerprint(before)!=fingerprint(after) or fingerprint(after)!=fingerprint(named),"KERNEL_RUNNER_FILE_CHANGED")
  for fd,parent_fd,name in descriptors[1:]:
   opened=os.fstat(fd);named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
   deny((opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_gid)!=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid),"KERNEL_RUNNER_FILE_CHANGED")
  if host_capture:return data,{"target":"/etc/machine-id","state":"PRESENT_PRESERVED","bytes":len(data),"sha256":sha(data),"mode":format(mode,"04o"),"uid":before.st_uid,"gid":before.st_gid,"device":before.st_dev,"inode":before.st_ino,"nlink":before.st_nlink}
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
 payload=manifest.get("payload");deny(not isinstance(payload,list),"KERNEL_MANIFEST_DENIED")
 deny(any(not isinstance(item,list) or len(item)!=4 or not isinstance(item[0],str) for item in payload),"KERNEL_MANIFEST_DENIED")
 branches=layout.get("payload_branches");paths=[item[0] for item in payload]
 # Exact signed mapping, not a filename guess or a runtime ownership claim.
 deny(not isinstance(branches,dict) or len(paths)!=len(set(paths)) or set(branches)!=set(paths) or any(not isinstance(branch,str) or branch not in ORDER for branch in branches.values()),"KERNEL_BRANCH_MAP_DENIED")
 deny(set(branches.values())!=set(ORDER),"KERNEL_COMPLETE_BRANCH_SET_REQUIRED")
 for relative,size,digest,mode in payload:
  matches=[p for p in roots if relative==p or relative.startswith(p+"/")];deny(len(matches)!=1,"KERNEL_LAYOUT_DENIED");prefix=matches[0]
  suffix=relative[len(prefix):].lstrip("/");target=roots[prefix].rstrip("/")+"/"+suffix
  rows.append({"branch":branches[relative],"source":relative,"target":target,"bytes":size,"sha256":digest,"mode":mode})
 rows.sort(key=lambda row:(ORDER.index(row["branch"]),row["target"]));return rows


def target_prestate(root, row, *, generated=False, expected_owner=(0,0)):
 """Capture exact retained bytes/custody without following links or writing."""
 name=row["target"];relative=Path(name)
 deny(not relative.is_absolute() or ".." in relative.parts,"KERNEL_TARGET_PRESTATE_PATH_DENIED")
 path=Path(root).joinpath(*relative.parts[1:]);handles=[]
 fingerprint=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 try:
  parent=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);handles.append((parent,None,None))
  for part in path.parts[1:-1]:
   try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   except FileNotFoundError:return {"target":name,"state":"ABSENT"}
   handles.append((child,parent,part));parent=child
  try:fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
  except FileNotFoundError:return {"target":name,"state":"ABSENT"}
  with os.fdopen(fd,"rb") as stream:
   before=os.fstat(stream.fileno())
   deny(generated,"KERNEL_GENERATED_PRESTATE_COLLISION_DENIED")
   deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or (before.st_uid,before.st_gid)!=expected_owner
        or stat.S_IMODE(before.st_mode)!=int(row["mode"],8) or before.st_size!=row["bytes"],
        "KERNEL_TARGET_PRESTATE_CUSTODY_DENIED")
   data=stream.read(row["bytes"]+1);stream.seek(0);second=stream.read(row["bytes"]+1)
   after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
   deny(fingerprint(before)!=fingerprint(after) or fingerprint(after)!=fingerprint(named)
        or data!=second or len(data)!=row["bytes"] or sha(data)!=row["sha256"],
        "KERNEL_TARGET_PRESTATE_CONTENT_DENIED")
  for child,parent_fd,part in handles[1:]:
   opened=os.fstat(child);named=os.stat(part,dir_fd=parent_fd,follow_symlinks=False)
   deny((opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_gid)!=
        (named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid),"KERNEL_TARGET_PRESTATE_ANCESTOR_CHANGED")
  return {"target":name,"state":"PRESENT_PRESERVED","bytes":len(data),"sha256":sha(data),
          "mode":row["mode"],"uid":before.st_uid,"gid":before.st_gid,
          "device":before.st_dev,"inode":before.st_ino,"nlink":before.st_nlink}
 except OSError as exc:raise RunnerDenied("KERNEL_TARGET_PRESTATE_CUSTODY_DENIED") from exc
 finally:
  for fd,_,_ in reversed(handles):os.close(fd)

def capture_target_prestate(root, rows):
 ordered=[row for branch in ORDER for row in rows if row["branch"]==branch]
 deny(len({row["target"] for row in rows})!=len(rows),"KERNEL_TARGET_PRESTATE_DUPLICATE")
 return [target_prestate(root,{"target":name},generated=True) for name in GENERATED]+[target_prestate(root,row) for row in ordered]

def current_host_gate(host_path,boot_id):
 """Consume the canonical data-derived Host witness, not verdict labels."""
 try:host=validate_state(read_json(host_path),active=True)
 except (ValueError,TypeError,KeyError) as exc:raise RunnerDenied("KERNEL_HOST_GATE_DENIED") from exc
 deny(host["current_boot_id"]!=boot_id or host["classification"] not in {"CURRENT_BOOT_STABLE","FIRST_BOOT_OBSERVED","RECOVERED_AFTER_BOOT_CHANGE"},"KERNEL_HOST_GATE_DENIED")
 return host

def current_boot():
 return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
def capture_host_identity(root,expected_machine_id):
 """Bind existing Host identity without creating or rewriting it."""
 deny(not isinstance(expected_machine_id,str) or not re.fullmatch(r"[0-9a-f]{32}",expected_machine_id) or expected_machine_id=="0"*32,"KERNEL_HOST_IDENTITY_DENIED")
 raw,custody=regular(Path(root)/"etc/machine-id",host_capture=True)
 deny(not 0<len(raw)<=4096,"KERNEL_HOST_IDENTITY_DENIED")
 try:actual=raw.decode("ascii").strip()
 except UnicodeError as exc:raise RunnerDenied("KERNEL_HOST_IDENTITY_DENIED") from exc
 deny(actual!=expected_machine_id,"KERNEL_HOST_IDENTITY_MISMATCH")
 return {"machine_id":actual,"file":custody}

def build_plan(source=SOURCE,request_path=REQUEST,host_path=HOST_STATE,verify_path=VERIFY_KEY,source_receipt_path=SOURCE_RECEIPT,*,root=Path("/")):
 request=read_json(request_path);required={"schema","target_vm_id","repository","source_parent","source_commit","source_tree","archive_sha256","rollback_selector","reserved_domain_ids"}
 deny(set(request)!=required or request["schema"]!="SereinOutpostKernelInstallRequest/v1" or request["target_vm_id"]!="VM4010" or request["repository"]!="Kaotikking/sfos-public","KERNEL_REQUEST_DENIED")
 reserved=request['reserved_domain_ids']
 deny(not isinstance(reserved,list) or any(not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{16}',value) for value in reserved) or reserved!=sorted(set(reserved)),"KERNEL_NATIVE_IDENTITY_RESERVED_DENIED")
 deny(any(not HEX40.fullmatch(str(request[x])) for x in ("source_parent","source_commit","source_tree")) or not HEX64.fullmatch(str(request["archive_sha256"])),"KERNEL_REQUEST_LINEAGE_DENIED")
 receipt,receipt_digest=source_receipt(source,source_receipt_path,verify_path);deny(any(request[x]!=receipt[x] for x in ("repository","source_parent","source_commit","source_tree","archive_sha256")),"KERNEL_REQUEST_SOURCE_BINDING_DENIED")
 host=current_host_gate(host_path,current_boot())
 manifest=read_json(source/"release-manifest.json");unsigned={k:v for k,v in manifest.items() if k!="self_digest"};deny(manifest.get("self_digest")!="sha256:"+sha(canonical(unsigned)) or receipt["release_digest"]!=manifest.get("self_digest"),"KERNEL_MANIFEST_DENIED")
 deny(manifest.get('schema')!='SereinPortableKernelRelease/v1' or manifest.get('branch_order')!=list(ORDER)
      or manifest.get('activation')!='OUTPOST_ONLY_AFTER_INACTIVE_PROOF' or manifest.get('gate')=='KERNEL_AUTHORITY',
      'KERNEL_MANIFEST_POLICY_DENIED')
 installer=regular(source/"install/kernel_first_install.py");installer_rows=manifest.get("installer_files",[]);deny(not any(row==["install/kernel_first_install.py",len(installer),sha(installer),"0755"] for row in installer_rows),"KERNEL_INSTALLER_DENOMINATOR_DENIED")
 layout=read_json(source/"install-layout.json");rows=payload_rows(source,manifest,layout);deny(manifest.get("install_denominator_digest")!="sha256:"+sha(canonical(rows)),"KERNEL_DENOMINATOR_DENIED")
 plan={"schema":"SereinPublicKernelFirstInstallPlan/v1","target_vm_id":"VM4010","source_parent":request["source_parent"],"source_commit":request["source_commit"],"source_tree":request["source_tree"],"release_digest":manifest["self_digest"],"current_boot_id":host["current_boot_id"],"outpost_identity":identity("serein-outpost"),"replay_identity":identity("serein-stage1"),"payload":rows,"rollback_selector":request["rollback_selector"],"authority_sha256":sha(regular(verify_path)),"archive_sha256":request["archive_sha256"],"source_receipt_sha256":receipt_digest,"source_inventory_digest":receipt["inventory_digest"]}
 plan["target_prestate"]=capture_target_prestate(root,rows)
 plan["host_identity"]=capture_host_identity(root,host["latest"]["host"]["machine_id"])
 plan["host_projection_digest"]=host["projection_digest"]
 plan['reserved_domain_ids']=list(reserved)
 return plan

def verify_native_installed(root,plan):
 """Independent readback of one signed installation identity; no admission.

 Do not call the installer's verifier or trust a registry's own checkpoint.
 The independently preserved Outpost key verifies the complete signed plan,
 including its public identity binding, before the installed bytes are used.
 """
 def installed(name):return Path(root).joinpath(*Path(name).parts[1:])
 try:
  binding=plan['native_identity']
  deny(not isinstance(binding,dict) or set(binding)!={'schema','instance_id','checkpoint','registry_sha256','private_sha256','public_key','transaction_context'} or binding['schema']!='SereinKernelNativeIdentityMaterial/v1',"KERNEL_NATIVE_IDENTITY_BINDING_DENIED")
  anchor=regular(installed('/usr/share/serein/outpost/cognition-verification.pem'))
  deny(sha(anchor)!=CANONICAL_AUTHORITY_SHA256 or sha(anchor)!=plan['authority_sha256'],"KERNEL_NATIVE_IDENTITY_ANCHOR_DENIED")
  public=load_pem_public_key(anchor)
  public.verify(base64.b64decode(plan['signature']+'='*(-len(plan['signature'])%4),altchars=b'-_',validate=True),canonical({k:v for k,v in plan.items() if k!='signature'}))
  registry_raw=regular(installed(NATIVE_REGISTRY));private_raw=regular(installed(NATIVE_KEY))
  deny(sha(registry_raw)!=binding['registry_sha256'] or sha(private_raw)!=binding['private_sha256'],"KERNEL_NATIVE_IDENTITY_BYTES_DENIED")
  for name,raw,mode in ((NATIVE_KEY,private_raw,'0600'),(NATIVE_REGISTRY,registry_raw,'0644')):
   target_prestate(root,{'target':name,'bytes':len(raw),'sha256':sha(raw),'mode':mode})
  registry=strict_json(registry_raw)
  deny(not isinstance(registry,dict) or set(registry)!={'schema','records'} or registry['schema']!='SereinDomainIdentityRegistry/v1' or canonical(registry)!=registry_raw,"KERNEL_NATIVE_IDENTITY_REGISTRY_DENIED")
  records=registry['records']
  deny(not isinstance(records,list) or len(records)!=1 or sha(canonical(records))!=binding['checkpoint'],"KERNEL_NATIVE_IDENTITY_CHECKPOINT_DENIED")
  record=records[0]
  deny(not isinstance(record,dict) or set(record)!={'body','installer_signature','domain_signature','prior_key_signature'} or record['prior_key_signature'] is not None,"KERNEL_NATIVE_IDENTITY_RECORD_DENIED")
  body=record['body'];context=sha(canonical({k:v for k,v in plan.items() if k not in {'signature','native_identity'}}))
  expected={'schema':'SereinDomainIdentityRecord/v1','domain':'KERNEL','instance_id':binding['instance_id'],'operation':'INSTALL','revision':0,'prior_record':None,'replaces_instance_id':None,'public_key':binding['public_key'],'key_fingerprint':sha(bytes.fromhex(binding['public_key'])),'source_commit':plan['source_commit'],'governance_receipt':context,'authority_effect':'NONE','admission_effect':'NONE'}
  reserved=plan['reserved_domain_ids']
  deny(not isinstance(reserved,list) or any(not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{16}',value) for value in reserved) or reserved!=sorted(set(reserved)),"KERNEL_NATIVE_IDENTITY_RESERVED_DENIED")
  deny(body!=expected or type(body['revision']) is not int or binding['transaction_context']!=context or not re.fullmatch(r'[0-9a-f]{16}',binding['instance_id']) or binding['instance_id'] in reserved,"KERNEL_NATIVE_IDENTITY_CONTEXT_DENIED")
  public.verify(bytes.fromhex(record['installer_signature']),canonical(body))
  Ed25519PublicKey.from_public_bytes(bytes.fromhex(body['public_key'])).verify(bytes.fromhex(record['domain_signature']),canonical(body))
  loaded=load_pem_private_key(private_raw,password=None)
  deny(loaded.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()!=body['public_key'],"KERNEL_NATIVE_IDENTITY_KEY_DENIED")
 except RunnerDenied:raise
 except Exception as exc:raise RunnerDenied('KERNEL_NATIVE_IDENTITY_VERIFICATION_DENIED') from exc
 return dict(binding)

def verify_install(root,plan,receipt):
 deny(capture_host_identity(root,plan["host_identity"]["machine_id"])!=plan["host_identity"],"KERNEL_HOST_IDENTITY_CHANGED")
 receipt_path=Path(root).joinpath(*Path(receipt["receipt"]).parts[1:]);value=read_json(receipt_path);required={"schema","plan_sha256","boot_id","branch_order","prestate","replacements","rollback_selector","rollback_auth_sha256","receipt_signature","receipt_digest"};deny(set(value)!=required or value.get("schema")!="SereinPublicKernelFirstInstallReceipt/v1","KERNEL_INSTALL_RECEIPT_SCHEMA_DENIED");digest=value.pop("receipt_digest",None);deny(digest!=sha(canonical(value)) or value.get("plan_sha256")!=sha(canonical(plan)) or value.get("boot_id")!=plan["current_boot_id"] or value.get("rollback_selector")!=plan["rollback_selector"] or value.get("branch_order")!=list(ORDER),"KERNEL_INSTALL_RECEIPT_DENIED")
 signature=value.pop("receipt_signature",None);auth=regular(receipt_path.parent/"rollback-auth.key");deny(sha(auth)!=value.get("rollback_auth_sha256") or not hmac.compare_digest(base64.urlsafe_b64encode(hmac.new(auth,canonical(value),hashlib.sha256).digest()).decode().rstrip("="),str(signature)),"KERNEL_INSTALL_RECEIPT_SIGNATURE_DENIED")
 plan_path=receipt_path.parent/'plan.json';plan_raw=regular(plan_path)
 deny(plan_raw!=canonical(plan),"KERNEL_INSTALL_PLAN_READBACK_DENIED")
 target_prestate(root,{'target':'/'+plan_path.relative_to(root).as_posix(),'bytes':len(plan_raw),'sha256':sha(plan_raw),'mode':'0600'})
 replacements=value.get("replacements");generated=set(GENERATED);expected_payload=[{**{key:row[key] for key in ("target","bytes","sha256","mode","branch")},"uid":0,"gid":0} for row in plan["payload"]];payload_rows=[row for row in replacements if row.get("target") not in generated] if isinstance(replacements,list) else []
 deny(not isinstance(replacements,list) or len(replacements)!=len(expected_payload)+len(generated) or payload_rows!=expected_payload or {row.get("target") for row in replacements if row.get("target") in generated}!=generated or any(set(row)!={"target","bytes","sha256","mode","uid","gid","branch"} for row in replacements),"KERNEL_INSTALL_INVENTORY_DENIED")
 generated_rows={row["target"]:row for row in replacements if row["target"] in generated};replay=plan["replay_identity"]
 deny((generated_rows["/var/lib/serein/kernel/authority/replay.key"]["mode"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["uid"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["gid"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["branch"])!=("0600",replay["uid"],replay["gid"],"AUTHORITY"),"KERNEL_REPLAY_KEY_CUSTODY_DENIED")
 for target,mode in (("/var/lib/serein/kernel/authority/replay-descriptor.json","0644"),("/etc/serein/kernel/replay-peer.env","0600"),(NATIVE_KEY,"0600"),(NATIVE_REGISTRY,"0644")):deny((generated_rows[target]["mode"],generated_rows[target]["uid"],generated_rows[target]["gid"],generated_rows[target]["branch"])!=(mode,0,0,"AUTHORITY"),"KERNEL_GENERATED_CUSTODY_DENIED")
 deny(value.get("prestate")!=plan["target_prestate"],"KERNEL_INSTALL_PRESTATE_DENIED")
 for before in plan["target_prestate"]:
  if before["state"]=="PRESENT_PRESERVED":
   row=next(row for row in plan["payload"] if row["target"]==before["target"])
   deny(target_prestate(root,row)!=before,"KERNEL_PRESERVED_PRESTATE_CHANGED")
 installed_identity={}
 for row in replacements:
  fact=target_prestate(root,row,expected_owner=(row["uid"],row["gid"]))
  deny(fact["state"]!="PRESENT_PRESERVED","KERNEL_INSTALL_INVENTORY_DENIED")
  installed_identity[row["target"]]=(fact["device"],fact["inode"])
 journal=read_json(receipt_path.parent/"phase-journal.json");deny(journal.get("receipt_digest")!=digest or journal.get("state")!="INSTALLED_INACTIVE" or journal.get("completed")!=[row["target"] for row in plan["target_prestate"] if row["state"]=="ABSENT"],"KERNEL_INSTALL_JOURNAL_DENIED")
 deny(set(journal)!={"schema","receipt_digest","state","completed","ownership"} or journal.get("schema")!="SereinKernelRollbackJournal/v1","KERNEL_INSTALL_OWNERSHIP_DENIED")
 ownership=journal.get("ownership");created=[row["target"] for row in plan["target_prestate"] if row["state"]=="ABSENT"]
 deny(not isinstance(ownership,list) or any(not isinstance(item,dict) or set(item)!={"target","device","inode","temporary"} for item in ownership),"KERNEL_INSTALL_OWNERSHIP_DENIED")
 deny([item["target"] for item in ownership]!=created,"KERNEL_INSTALL_OWNERSHIP_DENIED")
 for item in ownership:
  deny(type(item["device"]) is not int or type(item["inode"]) is not int or item["device"]<0 or item["inode"]<=0 or not re.fullmatch(r"\.kernel-[0-9a-f]{32}",str(item["temporary"])) or installed_identity[item["target"]]!=(item["device"],item["inode"]),"KERNEL_INSTALL_OWNERSHIP_DENIED")
 verify_native_installed(root,plan)
 return digest
def read_authority_handoff(*,expected_witness_sha256,root=Path('/'),source=SOURCE,
                           host_path=HOST_STATE,verify_path=VERIFY_KEY,source_receipt_path=SOURCE_RECEIPT):
 """Read an existing signed install into the observer's public input shape.

 This is read-only reconciliation, not the held service-control transaction:
 no process/service calls, signing, identity creation, file writes or dispatch.
 It cannot turn an inactive install into a runtime observation or admission.
 """
 deny(not isinstance(expected_witness_sha256,str) or not HEX64.fullmatch(expected_witness_sha256),
      'KERNEL_HANDOFF_WITNESS_BINDING_DENIED')
 captured={}
 def capture(path,*,private=False):
  path=Path(path);raw=regular(path)
  if private:deny(regular(path,fact=True)[1:4]!=(0,0,0o600),'KERNEL_HANDOFF_CUSTODY_DENIED')
  captured[path]=raw
  return raw
 boot=current_boot();host=current_host_gate(host_path,boot)
 raw=capture(STATE/'kernel-install-witness.json',private=True);installed=strict_json(raw)
 deny(sha(raw)!=expected_witness_sha256 or not isinstance(installed,dict)
      or installed.get('schema')!='SereinOutpostKernelInstallWitness/v1'
      or installed.get('witness_digest')!=sha(canonical({k:v for k,v in installed.items() if k!='witness_digest'}))
      or installed.get('target')!='VM4010' or installed.get('boot_id')!=boot
      or installed.get('install_status')!='INSTALLED_INACTIVE'
      or installed.get('admission')!='INDEPENDENT_AUDIT_PENDING'
      or installed.get('stage1')!='NOT_READY' or installed.get('authority_effect')!='NONE',
      'KERNEL_HANDOFF_WITNESS_DENIED')
 selector=installed.get('rollback_selector')
 deny(not isinstance(selector,str) or not re.fullmatch(
      r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',selector),
      'KERNEL_HANDOFF_SELECTOR_DENIED')
 plan_raw=capture(Path(root)/selector.lstrip('/')/'plan.json',private=True);plan=strict_json(plan_raw)
 deny(not isinstance(plan,dict) or canonical(plan)!=plan_raw or plan.get('rollback_selector')!=selector
      or plan.get('current_boot_id')!=boot or plan.get('target_vm_id')!='VM4010',
      'KERNEL_HANDOFF_PLAN_DENIED')
 anchor=capture(verify_path)
 deny(sha(anchor)!=CANONICAL_AUTHORITY_SHA256,'KERNEL_CANONICAL_ANCHOR_DENIED')
 capture(source_receipt_path)
 source_record,source_digest=source_receipt(source,source_receipt_path,verify_path)
 deny(plan.get('source_receipt_sha256')!=source_digest or installed.get('source_receipt_sha256')!=source_digest
      or any(plan.get(k)!=source_record.get(k) for k in ('source_parent','source_commit','source_tree','archive_sha256','release_digest'))
      or any(installed.get(k)!=plan.get(k) for k in ('source_commit','source_tree','archive_sha256','release_digest')),
      'KERNEL_HANDOFF_SOURCE_DENIED')
 manifest_raw=capture(source/'release-manifest.json');manifest=strict_json(manifest_raw)
 layout=strict_json(capture(source/'install-layout.json'))
 deny(manifest.get('self_digest')!='sha256:'+sha(canonical({k:v for k,v in manifest.items() if k!='self_digest'}))
      or manifest.get('self_digest')!=plan['release_digest']
      or manifest.get('branch_order')!=list(ORDER) or installed.get('branch_order')!=list(ORDER)
      or manifest.get('activation')!='OUTPOST_ONLY_AFTER_INACTIVE_PROOF'
      or payload_rows(source,manifest,layout)!=plan.get('payload'),'KERNEL_HANDOFF_PACKAGE_DENIED')
 receipt={'receipt':selector+'/receipt.json'}
 deny(verify_install(root,plan,receipt)!=installed.get('installer_receipt_sha256'),'KERNEL_HANDOFF_RECEIPT_DENIED')
 native=verify_native_installed(root,plan)
 deny(native!=installed.get('native_identity'),'KERNEL_HANDOFF_IDENTITY_DENIED')
 registry=strict_json(capture(Path(root)/NATIVE_REGISTRY.lstrip('/')))
 deny(capture_host_identity(root,host['latest']['host']['machine_id'])!=plan['host_identity'],
      'KERNEL_HOST_IDENTITY_CHANGED')
 # Read-only stability check. No lock acquisition or new transaction record.
 deny(any(regular(path)!=value for path,value in captured.items()),'KERNEL_HANDOFF_CHANGED')
 deny(source_receipt(source,source_receipt_path,verify_path)!=(source_record,source_digest)
      or verify_install(root,plan,receipt)!=installed['installer_receipt_sha256'],
      'KERNEL_HANDOFF_CHANGED')
 fresh_host=current_host_gate(host_path,boot)
 deny(current_boot()!=boot or capture_host_identity(root,fresh_host['latest']['host']['machine_id'])!=plan['host_identity'],
      'KERNEL_HANDOFF_BOOT_CHANGED')
 return {'source':{'source_commit':plan['source_commit'],'source_tree':plan['source_tree'],
                   'canonical_manifest_digest':sha(manifest_raw)},
         'identity':{'binding':native,'registry':registry}}

def run(root=Path("/"),source=SOURCE,request_path=REQUEST,host_path=HOST_STATE,signing_path=SIGNING_KEY,verify_path=VERIFY_KEY,source_receipt_path=SOURCE_RECEIPT,installer=None,rollback_installer=None):
 # Serialize with Outpost promotion using its already-proven root-private lock.
 # Do not introduce a service-owned privileged lock or a new root service.
 boot=current_boot();request_raw=regular(request_path)
 with public_generation_lock(root,sha(request_raw),boot),witness_directory(STATE) as (witness_fd,check_parent):
  deny(os.path.lexists(STATE/"kernel-install-witness.json"),"KERNEL_WITNESS_COLLISION_DENIED")
  plan=build_plan(source,request_path,host_path,verify_path,source_receipt_path,root=root);deny(plan["current_boot_id"]!=boot or regular(request_path)!=request_raw,"KERNEL_REQUEST_CHANGED")
  immutable={path:regular(Path(root)/path.lstrip("/"),fact=True) for path in IMMUTABLE_POLICY}
  deny(sha(regular(verify_path))!=CANONICAL_AUTHORITY_SHA256,"KERNEL_CANONICAL_ANCHOR_DENIED")
  private=load_pem_private_key(regular(signing_path),password=None)
  def boundary():
   check_parent();deny(current_boot()!=boot or regular(request_path)!=request_raw,"KERNEL_REQUEST_CHANGED")
   current_host=current_host_gate(host_path,boot)
   deny(capture_host_identity(root,current_host["latest"]["host"]["machine_id"])!=plan["host_identity"],"KERNEL_HOST_IDENTITY_CHANGED")
   deny(any(regular(Path(root)/path.lstrip("/"),fact=True)!=fact for path,fact in immutable.items()),"KERNEL_IMMUTABLE_CHANGED")
   deny("sha256:"+sha(canonical(safe_tree(source)))!=plan["source_inventory_digest"],"KERNEL_SOURCE_CHANGED_DURING_INSTALL")
  boundary()
  import importlib.util
  module_path=source/"install/kernel_first_install.py";module_bytes=regular(module_path);manifest=read_json(source/"release-manifest.json")
  deny(manifest.get("self_digest")!="sha256:"+sha(canonical({k:v for k,v in manifest.items() if k!="self_digest"})) or manifest["self_digest"]!=plan["release_digest"] or not any(row==["install/kernel_first_install.py",len(module_bytes),sha(module_bytes),"0755"] for row in manifest["installer_files"]),"KERNEL_INSTALLER_DENOMINATOR_DENIED")
  spec=importlib.util.spec_from_file_location("_serein_kernel_first_install",module_path);deny(spec is None or spec.loader is None,"KERNEL_INSTALLER_DENIED");module=importlib.util.module_from_spec(spec);exec(compile(module_bytes,str(module_path),"exec"),module.__dict__)
  deny(not callable(getattr(module,'prepare_native_identity',None)),"KERNEL_NATIVE_IDENTITY_IMPLEMENTATION_DENIED")
  if installer is None:installer=module.install;rollback_installer=module.rollback
  boundary()
  native_material=module.prepare_native_identity(source,plan,private,reserved_ids=set(plan['reserved_domain_ids']))
  plan['native_identity']=dict(native_material['binding'])
  plan["signature"]=base64.urlsafe_b64encode(private.sign(canonical(plan))).decode().rstrip("=")
  boundary()
  deny(capture_target_prestate(root,plan["payload"])!=plan["target_prestate"],"KERNEL_TARGET_PRESTATE_CHANGED")
  receipt=installer(root,source,plan,boundary=boundary,native_material=native_material);canonical_receipt=Path(root).joinpath(*Path(plan["rollback_selector"]+"/receipt.json").parts[1:])
  try:
   deny(receipt.get("status")!="INSTALLED_INACTIVE" or receipt.get("receipt")!=plan["rollback_selector"]+"/receipt.json","KERNEL_INSTALL_RECEIPT_DENIED");deny("sha256:"+sha(canonical(safe_tree(source)))!=plan["source_inventory_digest"],"KERNEL_SOURCE_CHANGED_DURING_INSTALL");receipt_digest=verify_install(root,plan,receipt)
   witness={"schema":"SereinOutpostKernelInstallWitness/v1","target":"VM4010","boot_id":plan["current_boot_id"],"source_commit":plan["source_commit"],"source_tree":plan["source_tree"],"archive_sha256":plan["archive_sha256"],"source_receipt_sha256":plan["source_receipt_sha256"],"release_digest":plan["release_digest"],"installer_receipt_sha256":receipt_digest,"branch_order":list(ORDER),"install_status":receipt["status"],"admission":"INDEPENDENT_AUDIT_PENDING","stage1":"NOT_READY","rollback_selector":plan["rollback_selector"],"native_identity":verify_native_installed(root,plan),"authority_effect":"NONE"};witness["witness_digest"]=sha(canonical(witness))
   def publication_boundary():
    boundary()
    deny(verify_install(root,plan,receipt)!=receipt_digest,"KERNEL_INSTALL_RECEIPT_CHANGED")
   witness["host_identity"]=plan["host_identity"]
   witness["host_projection_digest"]=plan["host_projection_digest"]
   witness["witness_digest"]=sha(canonical({key:value for key,value in witness.items() if key!="witness_digest"}))
   publication_boundary();atomic(STATE/"kernel-install-witness.json",witness,witness_fd,publication_boundary)
  except Exception:
   deny(rollback_installer is None,"KERNEL_POSTINSTALL_ROLLBACK_UNAVAILABLE");rollback_installer(root,canonical_receipt,boundary=boundary);raise
  return witness
if __name__=="__main__":
 deny(os.geteuid()!=0,"KERNEL_INSTALLER_ROOT_REQUIRED")
 run()
