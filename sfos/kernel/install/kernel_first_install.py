"""Inactive complete-branch Kernel transaction owned by the installed Outpost.

ADAPT public 0dca6bd7 installer plus preserved Authority-donor exclusive
publication/write-ahead inode custody. No existing target is overwritten.
Mechanical package proof is not complete Kernel behavior or admission proof.
"""
from __future__ import annotations
import base64,grp,hashlib,hmac,json,os,pwd,re,stat,tempfile
from pathlib import Path,PurePosixPath
from uuid import NAMESPACE_URL,uuid5
from cryptography.hazmat.primitives.serialization import load_pem_public_key,load_pem_private_key,Encoding,PrivateFormat,PublicFormat,NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ORDER=("AUTHORITY","OPERATIONS","INTERFACE")
SCHEMA="SereinPublicKernelFirstInstallPlan/v1"
KEY="/var/lib/serein/kernel/authority/replay.key"
DESCRIPTOR="/var/lib/serein/kernel/authority/replay-descriptor.json"
PEER_ENV="/etc/serein/kernel/replay-peer.env"
NATIVE_KEY="/var/lib/serein/kernel/authority/domain-identity.pem"
NATIVE_REGISTRY="/var/lib/serein/kernel/authority/domain-identity.json"
GENERATED=(KEY,DESCRIPTOR,PEER_ENV,NATIVE_KEY,NATIVE_REGISTRY)
AUTHORITY="/usr/share/serein/outpost/cognition-verification.pem"
ROLLBACK_AUTH="rollback-auth.key"
ROLLBACK_JOURNAL="phase-journal.json"
ROOTS=("/usr/lib/serein/kernel/","/usr/lib/python3/dist-packages/serein_stage1/","/usr/libexec/serein/serein-kernel-","/etc/systemd/system/serein-kernel-","/usr/libexec/serein/serein-observation-audit","/etc/systemd/system/serein-observation-audit.","/usr/libexec/serein/serein-conversation-runtime","/etc/systemd/system/serein-conversation-runtime.")
class Denied(RuntimeError):pass
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def deny(c,m):
 if c:raise Denied(m)
def target(root,name):
 p=PurePosixPath(name);deny(not p.is_absolute() or ".." in p.parts,"KERNEL_TARGET_DENIED");result=root.joinpath(*p.parts[1:]);cursor=root
 for part in p.parts[1:-1]:
  cursor=cursor/part
  if os.path.lexists(cursor):deny(cursor.is_symlink() or not cursor.is_dir(),"KERNEL_ANCESTOR_CUSTODY_DENIED")
 return result
def atomic(path,data,mode,boundary,uid=0,gid=0,*,create_only=False,on_intent=None):
 path.parent.mkdir(parents=True,exist_ok=True);deny(path.parent.is_symlink(),"KERNEL_PARENT_DENIED")
 parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 custody=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
 before=custody(os.fstat(parent));name='.kernel-'+os.urandom(16).hex();fd=-1
 def unchanged():
  deny(custody(os.fstat(parent))!=before or custody(path.parent.lstat())!=before,"KERNEL_PARENT_CHANGED")
 try:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
  with os.fdopen(fd,"wb") as out:
   fd=-1;out.write(data);out.flush();os.fchmod(out.fileno(),int(mode,8));os.fchown(out.fileno(),uid,gid);os.fsync(out.fileno())
  if on_intent is not None:
   staged=os.stat(name,dir_fd=parent,follow_symlinks=False)
   on_intent({'device':staged.st_dev,'inode':staged.st_ino,'temporary':name})
  boundary();unchanged()
  if create_only:
   try:os.link(name,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
   except FileExistsError:raise Denied("KERNEL_FIRST_INSTALL_COLLISION_DENIED") from None
  else:os.replace(name,path.name,src_dir_fd=parent,dst_dir_fd=parent)
  os.fsync(parent);unchanged()
 finally:
  if fd!=-1:os.close(fd)
  try:os.unlink(name,dir_fd=parent);os.fsync(parent)
  except FileNotFoundError:pass
  os.close(parent)
def exact(path,data,mode,uid=0,gid=0):
 i=path.lstat();deny(path.is_symlink() or not stat.S_ISREG(i.st_mode) or path.read_bytes()!=data or stat.S_IMODE(i.st_mode)!=int(mode,8) or (os.name!="nt" and (i.st_uid!=uid or i.st_gid!=gid)),"KERNEL_FILE_CAS_DENIED")
def exact_row(path,row):
 i=path.lstat();data=path.read_bytes();deny(path.is_symlink() or not stat.S_ISREG(i.st_mode) or len(data)!=row["bytes"] or sha(data)!=row["sha256"] or stat.S_IMODE(i.st_mode)!=int(row["mode"],8) or (os.name!="nt" and (i.st_uid!=row.get("uid",0) or i.st_gid!=row.get("gid",0))),"KERNEL_FILE_CAS_DENIED")
def sync_parent(path):
 d=os.open(path.parent,os.O_RDONLY);os.fsync(d);os.close(d)
def journal_write(rollback,receipt_digest,state,completed,boundary,ownership=()):
 body={"schema":"SereinKernelRollbackJournal/v1","receipt_digest":receipt_digest,"state":state,"completed":completed,"ownership":list(ownership)}
 atomic(rollback/ROLLBACK_JOURNAL,canonical(body),"0600",boundary)
def journal_read(rollback,receipt_digest):
 info=rollback.lstat();deny(rollback.is_symlink() or not rollback.is_dir() or stat.S_IMODE(info.st_mode)!=0o700 or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0)),"KERNEL_ROLLBACK_DIR_CUSTODY_DENIED");path=rollback/ROLLBACK_JOURNAL;info=path.lstat();deny(path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0)),"KERNEL_JOURNAL_CUSTODY_DENIED")
 value=json.loads(path.read_text());deny(value.get("schema")!="SereinKernelRollbackJournal/v1" or value.get("receipt_digest")!=receipt_digest or value.get("state") not in {"INSTALLING","INSTALLED_INACTIVE","ROLLING_BACK","ROLLBACK_COMPLETE"} or not isinstance(value.get("completed"),list),"KERNEL_JOURNAL_DENIED");return value

def source_data(source,row):
 name=row.get("source")
 deny(not isinstance(name,str) or not name or "\\" in name,"KERNEL_SOURCE_PATH_DENIED")
 relative=PurePosixPath(name)
 deny(relative.is_absolute() or ".." in relative.parts or relative.as_posix()!=name,"KERNEL_SOURCE_PATH_DENIED")
 path=source
 deny(source.is_symlink() or not source.is_dir(),"KERNEL_SOURCE_PATH_DENIED")
 for part in relative.parts:
  path=path/part
  deny(path.is_symlink(),"KERNEL_SOURCE_PATH_DENIED")
 deny(not path.is_file(),"KERNEL_SOURCE_DENIED")
 data=path.read_bytes()
 deny(len(data)!=row["bytes"] or sha(data)!=row["sha256"],"KERNEL_SOURCE_HASH_DENIED")
 return data


def target_prestate(root, row, *, generated=False, include_bytes=False):
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
   deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or (before.st_uid,before.st_gid)!=(0,0)
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
  fact={"target":name,"state":"PRESENT_PRESERVED","bytes":len(data),"sha256":sha(data),
          "mode":row["mode"],"uid":before.st_uid,"gid":before.st_gid,
          "device":before.st_dev,"inode":before.st_ino,"nlink":before.st_nlink}
  return (fact,data) if include_bytes else fact
 except OSError as exc:raise Denied("KERNEL_TARGET_PRESTATE_CUSTODY_DENIED") from exc
 finally:
  for fd,_,_ in reversed(handles):os.close(fd)

def capture_target_prestate(root, rows):
 ordered=[row for branch in ORDER for row in rows if row["branch"]==branch]
 deny(len({row["target"] for row in rows})!=len(rows),"KERNEL_TARGET_PRESTATE_DUPLICATE")
 return [target_prestate(root,{"target":name},generated=True) for name in GENERATED]+[target_prestate(root,row) for row in ordered]

def verify_host_identity(root,plan):
 """Existing Host identity is a preserved input, never Kernel payload."""
 identity=plan.get("host_identity")
 deny(not isinstance(identity,dict) or set(identity)!={"machine_id","file"},"KERNEL_HOST_IDENTITY_DENIED")
 machine=identity["machine_id"];row=identity["file"]
 deny(not isinstance(machine,str) or not re.fullmatch(r"[0-9a-f]{32}",machine) or machine=="0"*32,"KERNEL_HOST_IDENTITY_DENIED")
 deny(not isinstance(row,dict) or set(row)!={"target","state","bytes","sha256","mode","uid","gid","device","inode","nlink"}
      or row.get("target")!="/etc/machine-id" or row.get("state")!="PRESENT_PRESERVED"
      or type(row.get("bytes")) is not int or not 0<row["bytes"]<=4096
      or not isinstance(row.get("mode"),str) or not re.fullmatch(r"[0-7]{4}",row["mode"])
      or int(row["mode"],8)&0o022,"KERNEL_HOST_IDENTITY_CUSTODY_DENIED")
 captured=target_prestate(root,row,include_bytes=True)
 deny(not isinstance(captured,tuple) or captured[0]!=row,"KERNEL_HOST_IDENTITY_CHANGED")
 try:actual=captured[1].decode("ascii").strip()
 except UnicodeError as exc:raise Denied("KERNEL_HOST_IDENTITY_DENIED") from exc
 deny(actual!=machine,"KERNEL_HOST_IDENTITY_MISMATCH")
 deny(not isinstance(plan.get("host_projection_digest"),str) or not re.fullmatch(r"[0-9a-f]{64}",plan["host_projection_digest"]),"KERNEL_HOST_PROVENANCE_DENIED")

def system_identity(user,group):
 account=pwd.getpwnam(user);group_row=grp.getgrnam(group);return {"user":user,"group":group,"uid":account.pw_uid,"gid":group_row.gr_gid,"primary_gid":account.pw_gid,"members":sorted(group_row.gr_mem)}

def native_identity_module(source,plan):
 """Reuse only the exact identity implementation in the signed source set."""
 import types
 relative="payload/serein_stage1/domain_identity.py"
 rows=[row for row in plan['payload'] if row['source']==relative]
 deny(len(rows)!=1 or rows[0]['branch']!='AUTHORITY',"KERNEL_NATIVE_IDENTITY_SOURCE_DENIED")
 raw=source_data(Path(source),rows[0]);module=types.ModuleType('_serein_native_identity')
 exec(compile(raw,str(Path(source)/relative),'exec'),module.__dict__)
 return module

def prepare_native_identity(source,plan,installer_key,*,reserved_ids,random_bytes=os.urandom):
 """Memory-only candidate material for the governed installer, never a receipt.

 No persistence, live admission or key replacement. The eventual installer
 must place the private bytes create-only and sign the public binding in its
 complete plan. Never log/serialize this whole return value into evidence.
 """
 module=native_identity_module(source,plan)
 private=Ed25519PrivateKey.generate()
 context=sha(canonical({k:v for k,v in plan.items() if k not in {'signature','native_identity'}}))
 record=module.candidate('KERNEL',source_commit=plan['source_commit'],
                         governance_receipt=context,installer_key=installer_key,
                         domain_key=private,used_ids=reserved_ids,random_bytes=random_bytes)
 records=[record];checkpoint=module.digest(records)
 registry=canonical({'schema':'SereinDomainIdentityRegistry/v1','records':records})
 private_bytes=private.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
 binding={'schema':'SereinKernelNativeIdentityMaterial/v1','instance_id':record['body']['instance_id'],
          'checkpoint':checkpoint,'registry_sha256':sha(registry),'private_sha256':sha(private_bytes),
          'public_key':module.public_hex(private),'transaction_context':context}
 return {'binding':binding,'registry':registry,'private':private_bytes}

def verify_native_identity_material(source,plan,material,installer_public,*,reserved_ids):
 """Verify prospective generated bytes; does not write or admit an identity."""
 module=native_identity_module(source,plan)
 deny(not isinstance(material,dict) or set(material)!={'binding','registry','private'},"KERNEL_NATIVE_IDENTITY_MATERIAL_DENIED")
 binding=material['binding']
 deny(not isinstance(binding,dict) or set(binding)!={'schema','instance_id','checkpoint','registry_sha256','private_sha256','public_key','transaction_context'} or binding['schema']!='SereinKernelNativeIdentityMaterial/v1',"KERNEL_NATIVE_IDENTITY_BINDING_DENIED")
 deny(type(material['registry']) is not bytes or type(material['private']) is not bytes or sha(material['registry'])!=binding['registry_sha256'] or sha(material['private'])!=binding['private_sha256'],"KERNEL_NATIVE_IDENTITY_BYTES_DENIED")
 try:
  document=json.loads(material['registry']);private=load_pem_private_key(material['private'],password=None)
  deny(not isinstance(document,dict) or set(document)!={'schema','records'} or document['schema']!='SereinDomainIdentityRegistry/v1' or canonical(document)!=material['registry'],"KERNEL_NATIVE_IDENTITY_REGISTRY_DENIED")
  result=module.verify_lineage(document['records'],installer_public=installer_public,
                               expected_checkpoint=binding['checkpoint'],expected_domain='KERNEL',reserved_ids=reserved_ids)
  context=sha(canonical({k:v for k,v in plan.items() if k not in {'signature','native_identity'}}))
  deny(len(document['records'])!=1 or document['records'][0]['body']['source_commit']!=plan['source_commit'] or document['records'][0]['body']['governance_receipt']!=context or binding['transaction_context']!=context,"KERNEL_NATIVE_IDENTITY_CONTEXT_DENIED")
  deny(result['instance_id']!=binding['instance_id'] or result['public_key']!=binding['public_key'] or module.public_hex(private)!=result['public_key'],"KERNEL_NATIVE_IDENTITY_KEY_DENIED")
 except Denied:raise
 except Exception as exc:raise Denied("KERNEL_NATIVE_IDENTITY_VERIFICATION_DENIED") from exc
 return binding

def validate(source,root,plan,identity_lookup=None):
 identity_lookup=identity_lookup or system_identity
 required={"schema","target_vm_id","source_parent","source_commit","source_tree","release_digest","current_boot_id","outpost_identity","replay_identity","payload","target_prestate","rollback_selector","authority_sha256","archive_sha256","source_receipt_sha256","source_inventory_digest","reserved_domain_ids","native_identity","signature"}
 required|={"host_identity","host_projection_digest"}
 deny(not isinstance(plan,dict) or set(plan)!=required or plan["schema"]!=SCHEMA,"KERNEL_PLAN_DENIED")
 reserved=plan['reserved_domain_ids']
 deny(not isinstance(reserved,list) or any(not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{16}',value) for value in reserved) or reserved!=sorted(set(reserved)),"KERNEL_NATIVE_IDENTITY_RESERVED_DENIED")
 deny(any(not re.fullmatch(r"[0-9a-f]{40}",str(plan[x])) for x in ("source_parent","source_commit","source_tree")) or not re.fullmatch(r"sha256:[0-9a-f]{64}",str(plan["release_digest"])) or not re.fullmatch(r"[0-9a-f]{64}",str(plan["archive_sha256"])) or not re.fullmatch(r"[0-9a-f]{64}",str(plan["source_receipt_sha256"])) or not re.fullmatch(r"sha256:[0-9a-f]{64}",str(plan["source_inventory_digest"])),"KERNEL_LINEAGE_DENIED")
 deny(plan["target_vm_id"]!="VM4010","KERNEL_TARGET_IDENTITY_DENIED")
 for field,user,group in (("outpost_identity","serein-outpost","serein-outpost"),("replay_identity","serein-stage1","serein-stage1")):
  value=plan[field];deny(not isinstance(value,dict) or value!=identity_lookup(user,group),"KERNEL_IDENTITY_DENIED")
 anchor=target(root,AUTHORITY);deny(anchor.is_symlink() or not anchor.is_file() or sha(anchor.read_bytes())!=plan["authority_sha256"],"KERNEL_AUTHORITY_DENIED")
 try:load_pem_public_key(anchor.read_bytes()).verify(base64.urlsafe_b64decode(plan["signature"]+"="*(-len(plan["signature"])%4)),canonical({k:v for k,v in plan.items() if k!="signature"}))
 except Exception as exc:raise Denied("KERNEL_PLAN_SIGNATURE_DENIED") from exc
 rows=plan["payload"];deny(not isinstance(rows,list) or not rows,"KERNEL_PAYLOAD_DENIED");seen=set()
 verify_host_identity(root,plan)
 for row in rows:
  deny(not isinstance(row,dict) or set(row)!={"branch","source","target","bytes","sha256","mode"} or row["branch"] not in ORDER,"KERNEL_PAYLOAD_DENIED")
  deny(not any(row["target"].startswith(x) for x in ROOTS) or row["target"] in seen or row["mode"] not in {"0644","0755"},"KERNEL_PAYLOAD_TARGET_DENIED");seen.add(row["target"])
  source_data(source,row)
 deny([b for b in ORDER if any(r["branch"]==b for r in rows)]!=list(ORDER),"KERNEL_BRANCH_ORDER_DENIED")
 manifest_path=source/"release-manifest.json";deny(manifest_path.is_symlink() or not manifest_path.is_file(),"KERNEL_RELEASE_MANIFEST_DENIED");manifest=json.loads(manifest_path.read_text());unsigned={k:v for k,v in manifest.items() if k!="self_digest"}
 deny(manifest.get("self_digest")!="sha256:"+sha(canonical(unsigned)) or plan["release_digest"]!=manifest.get("self_digest"),"KERNEL_RELEASE_DIGEST_DENIED")
 deny(manifest.get("schema")!="SereinPortableKernelRelease/v1" or manifest.get("branch_order")!=list(ORDER) or manifest.get("activation")!="OUTPOST_ONLY_AFTER_INACTIVE_PROOF" or manifest.get("gate")=="KERNEL_AUTHORITY","KERNEL_COMPLETE_PACKAGE_DENIED")
 declared=manifest.get("payload");deny(not isinstance(declared,list) or manifest.get("payload_digest")!="sha256:"+sha(canonical(declared)) or manifest.get("install_denominator_digest")!="sha256:"+sha(canonical(rows)),"KERNEL_RELEASE_DENOMINATOR_DENIED")
 deny(sorted((r["source"],r["bytes"],r["sha256"],r["mode"]) for r in rows)!=sorted(tuple(x) for x in declared),"KERNEL_RELEASE_DENOMINATOR_DENIED")
 deny(target(root,"/proc/sys/kernel/random/boot_id").read_text().strip()!=plan["current_boot_id"],"KERNEL_BOOT_DENIED")
 rollback=target(root,plan["rollback_selector"]);deny(rollback.parent!=target(root,"/var/lib/serein/rollback") or not re.fullmatch(r"kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}",rollback.name),"KERNEL_ROLLBACK_DENIED")
 return [r for branch in ORDER for r in rows if r["branch"]==branch],rollback

def install(root,source,plan,boundary=lambda:None,random_bytes=os.urandom,identity_lookup=None,*,native_material=None):
 root,source=Path(root),Path(source);rows,rollback=validate(source,root,plan,identity_lookup)
 external_boundary=boundary
 def boundary():
  external_boundary()
  verify_host_identity(root,plan)
 deny(not isinstance(native_material,dict) or native_material.get('binding')!=plan['native_identity'],"KERNEL_NATIVE_IDENTITY_PLAN_BINDING_DENIED")
 native_material={**native_material,'binding':dict(native_material['binding'])}
 anchor=load_pem_public_key(target(root,AUTHORITY).read_bytes()).public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
 verify_native_identity_material(source,plan,native_material,anchor,reserved_ids=set(plan['reserved_domain_ids']))
 boundary()
 deny(capture_target_prestate(root,rows)!=plan["target_prestate"],"KERNEL_TARGET_PRESTATE_COLLISION_CHANGED")
 deny(os.path.lexists(rollback),"KERNEL_ROLLBACK_COLLISION_DENIED")
 preserved={row["target"]:row for row in plan["target_prestate"] if row["state"]=="PRESENT_PRESERVED"}
 def preserved_unchanged():
  verify_host_identity(root,plan)
  for row in rows:
   if row["target"] in preserved:
    deny(target_prestate(root,row)!=preserved[row["target"]],"KERNEL_PRESERVED_PRESTATE_CHANGED")
 key=random_bytes(32);deny(type(key) is not bytes or len(key)!=32,"KERNEL_REPLAY_KEY_DENIED")
 peer=(f"SEREIN_OUTPOST_UID={plan['outpost_identity']['uid']}\n"
       f"SEREIN_OUTPOST_GID={plan['outpost_identity']['gid']}\n"
       f"SEREIN_GATEWAY_UID={plan['replay_identity']['uid']}\n"
       f"SEREIN_GATEWAY_GID={plan['replay_identity']['gid']}\n").encode()
 identity=sha(canonical(plan));store_id=str(uuid5(NAMESPACE_URL,"serein-kernel-store:"+identity));key_receipt=str(uuid5(NAMESPACE_URL,"serein-kernel-key:"+identity))
 body={"schema":"VM4010HttpsReplayStoreDescriptor/v1","store_id":store_id,"backend_identity":"SEREIN_KERNEL_REPLAY","issuer":"KERNEL_AUTHORITY","observer":"OUTPOST","signature_algorithm":"HMAC-SHA256","trusted_key_fingerprint":sha(key),"trusted_key_receipt":key_receipt,"target":{"vm_id":plan["target_vm_id"],"boot_id":plan["current_boot_id"]},"source_generation":{"parent":plan["source_parent"],"commit":plan["source_commit"],"tree":plan["source_tree"]},"telemetry_schema":"VM4010HttpsAdapterTelemetry/v2","authority_effect":"NONE"};descriptor=canonical({"body":body,"signature":hmac.new(key,canonical(body),hashlib.sha256).hexdigest()})
 generated={KEY:(key,"0600",plan["replay_identity"]["uid"],plan["replay_identity"]["gid"]),DESCRIPTOR:(descriptor,"0644",0,0),PEER_ENV:(peer,"0600",0,0),NATIVE_KEY:(native_material['private'],"0600",0,0),NATIVE_REGISTRY:(native_material['registry'],"0644",0,0)}
 replacements=[{"target":n,"bytes":len(v),"sha256":sha(v),"mode":m,"uid":u,"gid":g,"branch":"AUTHORITY"} for n,(v,m,u,g) in generated.items()]+[{**{k:r[k] for k in ("target","bytes","sha256","mode","branch")},"uid":0,"gid":0} for r in rows]
 rollback_key=random_bytes(32);deny(type(rollback_key) is not bytes or len(rollback_key)!=32,"KERNEL_ROLLBACK_KEY_DENIED")
 receipt_body={"schema":"SereinPublicKernelFirstInstallReceipt/v1","plan_sha256":sha(canonical(plan)),"boot_id":plan["current_boot_id"],"branch_order":list(ORDER),"prestate":plan["target_prestate"],"replacements":replacements,"rollback_selector":plan["rollback_selector"],"rollback_auth_sha256":sha(rollback_key)}
 receipt={**receipt_body,"receipt_signature":base64.urlsafe_b64encode(hmac.new(rollback_key,canonical(receipt_body),hashlib.sha256).digest()).decode().rstrip("=")};receipt["receipt_digest"]=sha(canonical(receipt));receipt_digest=receipt["receipt_digest"]
 boundary();preserved_unchanged()
 rollback.mkdir(mode=0o700);receipt_bytes=canonical(receipt);plan_bytes=canonical(plan);journal_bytes=canonical({"schema":"SereinKernelRollbackJournal/v1","receipt_digest":receipt_digest,"state":"INSTALLING","completed":[],"ownership":[]})
 try:
  atomic(rollback/ROLLBACK_AUTH,rollback_key,"0600",boundary,create_only=True);atomic(rollback/"receipt.json",receipt_bytes,"0600",boundary,create_only=True);atomic(rollback/"plan.json",plan_bytes,"0600",boundary,create_only=True);journal_write(rollback,receipt_digest,"INSTALLING",[],boundary)
 except Exception:
  for path,data in ((rollback/ROLLBACK_JOURNAL,journal_bytes),(rollback/"plan.json",plan_bytes),(rollback/"receipt.json",receipt_bytes),(rollback/ROLLBACK_AUTH,rollback_key)):
   if os.path.lexists(path):exact(path,data,"0600");path.unlink();sync_parent(path)
  rollback.rmdir();sync_parent(rollback)
  raise
 written=[];ownership=[]
 def install_new(name,data,mode,uid=0,gid=0):
  preserved_unchanged()
  def intent(identity):
   ownership.append({'target':name,**identity})
   # Write-ahead inode identity distinguishes our pending publication from
   # any byte-identical competing file after interruption or exclusive denial.
   journal_write(rollback,receipt_digest,'INSTALLING',written,boundary,ownership)
  atomic(target(root,name),data,mode,boundary,uid,gid,create_only=True,on_intent=intent)
  written.append(name);journal_write(rollback,receipt_digest,'INSTALLING',written,boundary,ownership)
 try:
  for branch in ORDER:
   if branch=="AUTHORITY":
    for name,(data,mode,uid,gid) in generated.items():install_new(name,data,mode,uid,gid)
   for row in (r for r in rows if r["branch"]==branch):
    if row["target"] not in preserved:install_new(row["target"],source_data(source,row),row["mode"])
  preserved_unchanged()
  for row in replacements:
   data=generated[row["target"]][0] if row["target"] in generated else source_data(source,next(r for r in rows if r["target"]==row["target"]));exact(target(root,row["target"]),data,row["mode"],row["uid"],row["gid"])
  def completion_boundary():
   boundary();preserved_unchanged();exact(rollback/"plan.json",plan_bytes,"0600")
  completion_boundary()
  journal_write(rollback,receipt_digest,"INSTALLED_INACTIVE",written,completion_boundary,ownership)
  preserved_unchanged()
  return {"status":"INSTALLED_INACTIVE","branch_order":list(ORDER),"receipt":plan["rollback_selector"]+"/receipt.json","secret_exported":False}
 except Exception:
  rollback_transaction(root,rollback/"receipt.json",boundary)
  raise

def rollback_transaction(root,receipt_path,boundary=lambda:None):
 root=Path(root);receipt_path=Path(receipt_path);deny(receipt_path.name!="receipt.json" or receipt_path.parent.parent!=target(root,"/var/lib/serein/rollback"),"KERNEL_RECEIPT_PATH_DENIED");info=receipt_path.lstat();deny(receipt_path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600,"KERNEL_RECEIPT_CUSTODY_DENIED");receipt=json.loads(receipt_path.read_text());digest=receipt.pop("receipt_digest",None);deny(digest!=sha(canonical(receipt)),"KERNEL_RECEIPT_DIGEST_DENIED");body={k:v for k,v in receipt.items() if k!="receipt_signature"}
 rollback_dir=receipt_path.parent;dir_info=rollback_dir.lstat();deny(rollback_dir.is_symlink() or not rollback_dir.is_dir() or stat.S_IMODE(dir_info.st_mode)!=0o700 or (os.name!="nt" and (dir_info.st_uid!=0 or dir_info.st_gid!=0)),"KERNEL_ROLLBACK_DIR_CUSTODY_DENIED");auth=rollback_dir/ROLLBACK_AUTH;auth_info=auth.lstat();deny(auth.is_symlink() or not stat.S_ISREG(auth_info.st_mode) or stat.S_IMODE(auth_info.st_mode)!=0o600 or (os.name!="nt" and (auth_info.st_uid!=0 or auth_info.st_gid!=0)),"KERNEL_ROLLBACK_AUTH_CUSTODY_DENIED");key=auth.read_bytes();deny(sha(key)!=receipt.get("rollback_auth_sha256"),"KERNEL_ROLLBACK_AUTH_DENIED")
 expected=base64.urlsafe_b64encode(hmac.new(key,canonical(body),hashlib.sha256).digest()).decode().rstrip("=");deny(not hmac.compare_digest(expected,receipt.get("receipt_signature","")),"KERNEL_RECEIPT_SIGNATURE_DENIED")
 deny(receipt.get("branch_order")!=list(ORDER) or any(row.get("target") not in GENERATED and not any(row.get("target","").startswith(prefix) for prefix in ROOTS) for row in receipt.get("replacements",[])),"KERNEL_RECEIPT_TARGET_DENIED")
 journal=journal_read(rollback_dir,digest);completed=list(journal['completed']);ownership=journal.get('ownership')
 rows={row['target']:row for row in receipt['replacements']}
 prestate=receipt.get('prestate');deny(not isinstance(prestate,list) or any(not isinstance(row,dict) for row in prestate) or [row.get('target') for row in prestate]!=list(rows) or any(row.get('state') not in {'ABSENT','PRESENT_PRESERVED'} for row in prestate),"KERNEL_RECEIPT_PRESTATE_DENIED")
 for before in prestate:
  if before['state']=='ABSENT':deny(set(before)!={'target','state'},"KERNEL_RECEIPT_PRESTATE_DENIED")
  else:
   deny(set(before)!={'target','state','bytes','sha256','mode','uid','gid','device','inode','nlink'} or before['target'] in GENERATED,"KERNEL_RECEIPT_PRESTATE_DENIED")
   row=rows[before['target']]
   deny(any(before[field]!=row[field] for field in ('bytes','sha256','mode','uid','gid')) or (before['uid'],before['gid'],before['nlink'])!=(0,0,1) or type(before['device']) is not int or type(before['inode']) is not int or before['device']<0 or before['inode']<=0,"KERNEL_RECEIPT_PRESTATE_DENIED")
 install_order=[row['target'] for row in prestate if row['state']=='ABSENT']
 deny(not isinstance(ownership,list),"KERNEL_PUBLICATION_OWNERSHIP_UNPROVEN")
 deny(any(not isinstance(item,dict) or set(item)!={'target','device','inode','temporary'}
          or item['target'] not in rows or type(item['device']) is not int or type(item['inode']) is not int
          or item['device']<0 or item['inode']<=0 or not re.fullmatch(r'\.kernel-[0-9a-f]{32}',str(item['temporary'])) for item in ownership),"KERNEL_PUBLICATION_OWNERSHIP_DENIED")
 names=[item['target'] for item in ownership]
 deny(names!=install_order[:len(names)] or len(set(names))!=len(names),"KERNEL_PUBLICATION_ORDER_DENIED")
 reverse=list(reversed(ownership));reverse_names=list(reversed(names))
 if journal['state'] in {'INSTALLING','INSTALLED_INACTIVE'}:
  deny(completed!=names[:len(completed)] or len(names)-len(completed)>1,"KERNEL_JOURNAL_ORDER_DENIED");completed=[]
 else:deny(completed!=reverse_names[:len(completed)],"KERNEL_JOURNAL_ORDER_DENIED")
 foreign=[]
 journal_write(rollback_dir,digest,'ROLLING_BACK',completed,boundary,ownership)
 for item in reverse:
  row=rows[item['target']];path=target(root,item['target'])
  # Content parity is never proof that this transaction created a file.
  # Recover only the write-ahead inode; preserve every different owner.
  for candidate in (path,path.parent/item['temporary']):
   if not os.path.lexists(candidate):continue
   info=candidate.lstat()
   if (info.st_dev,info.st_ino)!=(item['device'],item['inode']):
    foreign.append(str(candidate.relative_to(root)));continue
   exact_row(candidate,row);boundary()
   current=candidate.lstat()
   deny((current.st_dev,current.st_ino)!=(item['device'],item['inode']),"KERNEL_ROLLBACK_OWNERSHIP_CHANGED")
   exact_row(candidate,row)
   candidate.unlink();sync_parent(candidate)
  if item['target'] not in completed:completed.append(item['target']);journal_write(rollback_dir,digest,'ROLLING_BACK',completed,boundary,ownership)
 for item in ownership:
  path=target(root,item['target'])
  for candidate in (path,path.parent/item['temporary']):
   if os.path.lexists(candidate):
    info=candidate.lstat();deny((info.st_dev,info.st_ino)==(item['device'],item['inode']),"KERNEL_ROLLBACK_RESIDUE_DENIED")
 journal_write(rollback_dir,digest,'ROLLBACK_COMPLETE',completed,boundary,ownership)
 return {'status':'ROLLBACK_COMPLETE','branch_order':receipt['branch_order'],'foreign_targets_preserved':sorted(set(foreign))}
def rollback(root,receipt_path,boundary=lambda:None):return rollback_transaction(root,receipt_path,boundary)
