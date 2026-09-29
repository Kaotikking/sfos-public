"""Portable inactive Kernel first-install transaction (Authority -> Operations -> Interface)."""
from __future__ import annotations
import base64,grp,hashlib,hmac,json,os,pwd,re,stat,tempfile
from pathlib import Path,PurePosixPath
from uuid import NAMESPACE_URL,uuid5
from cryptography.hazmat.primitives.serialization import load_pem_public_key

ORDER=("AUTHORITY","OPERATIONS","INTERFACE")
SCHEMA="SereinPublicKernelFirstInstallPlan/v1"
KEY="/var/lib/serein/kernel/authority/replay.key"
DESCRIPTOR="/var/lib/serein/kernel/authority/replay-descriptor.json"
PEER_ENV="/etc/serein/kernel/replay-peer.env"
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
def atomic(path,data,mode,boundary,uid=0,gid=0):
 path.parent.mkdir(parents=True,exist_ok=True);deny(path.parent.is_symlink(),"KERNEL_PARENT_DENIED")
 fd,tmp=tempfile.mkstemp(prefix=".kernel-",dir=path.parent)
 try:
  with os.fdopen(fd,"wb") as out:fd=-1;out.write(data);out.flush();os.fsync(out.fileno())
  os.chmod(tmp,int(mode,8));
  if os.name!="nt":os.chown(tmp,uid,gid)
  boundary();os.replace(tmp,path)
  d=os.open(path.parent,os.O_RDONLY);os.fsync(d);os.close(d)
 finally:
  if fd!=-1:os.close(fd)
  if os.path.exists(tmp):os.unlink(tmp)
def exact(path,data,mode,uid=0,gid=0):
 i=path.lstat();deny(path.is_symlink() or not stat.S_ISREG(i.st_mode) or path.read_bytes()!=data or stat.S_IMODE(i.st_mode)!=int(mode,8) or (os.name!="nt" and (i.st_uid!=uid or i.st_gid!=gid)),"KERNEL_FILE_CAS_DENIED")
def exact_row(path,row):
 i=path.lstat();data=path.read_bytes();deny(path.is_symlink() or not stat.S_ISREG(i.st_mode) or len(data)!=row["bytes"] or sha(data)!=row["sha256"] or stat.S_IMODE(i.st_mode)!=int(row["mode"],8) or (os.name!="nt" and (i.st_uid!=row.get("uid",0) or i.st_gid!=row.get("gid",0))),"KERNEL_FILE_CAS_DENIED")
def sync_parent(path):
 d=os.open(path.parent,os.O_RDONLY);os.fsync(d);os.close(d)
def journal_write(rollback,receipt_digest,state,completed,boundary):
 body={"schema":"SereinKernelRollbackJournal/v1","receipt_digest":receipt_digest,"state":state,"completed":completed}
 atomic(rollback/ROLLBACK_JOURNAL,canonical(body),"0600",boundary)
def journal_read(rollback,receipt_digest):
 info=rollback.lstat();deny(rollback.is_symlink() or not rollback.is_dir() or stat.S_IMODE(info.st_mode)!=0o700 or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0)),"KERNEL_ROLLBACK_DIR_CUSTODY_DENIED");path=rollback/ROLLBACK_JOURNAL;info=path.lstat();deny(path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0)),"KERNEL_JOURNAL_CUSTODY_DENIED")
 value=json.loads(path.read_text());deny(value.get("schema")!="SereinKernelRollbackJournal/v1" or value.get("receipt_digest")!=receipt_digest or value.get("state") not in {"INSTALLING","INSTALLED_INACTIVE","ROLLING_BACK","ROLLBACK_COMPLETE"} or not isinstance(value.get("completed"),list),"KERNEL_JOURNAL_DENIED");return value

def system_identity(user,group):
 account=pwd.getpwnam(user);group_row=grp.getgrnam(group);return {"user":user,"group":group,"uid":account.pw_uid,"gid":group_row.gr_gid,"primary_gid":account.pw_gid,"members":sorted(group_row.gr_mem)}
def validate(source,root,plan,identity_lookup=None):
 identity_lookup=identity_lookup or system_identity
 required={"schema","target_vm_id","source_parent","source_commit","source_tree","release_digest","current_boot_id","outpost_identity","replay_identity","payload","rollback_selector","authority_sha256","archive_sha256","source_receipt_sha256","source_inventory_digest","signature"}
 deny(not isinstance(plan,dict) or set(plan)!=required or plan["schema"]!=SCHEMA,"KERNEL_PLAN_DENIED")
 deny(any(not re.fullmatch(r"[0-9a-f]{40}",str(plan[x])) for x in ("source_parent","source_commit","source_tree")) or not re.fullmatch(r"sha256:[0-9a-f]{64}",str(plan["release_digest"])) or not re.fullmatch(r"[0-9a-f]{64}",str(plan["archive_sha256"])) or not re.fullmatch(r"[0-9a-f]{64}",str(plan["source_receipt_sha256"])) or not re.fullmatch(r"sha256:[0-9a-f]{64}",str(plan["source_inventory_digest"])),"KERNEL_LINEAGE_DENIED")
 deny(plan["target_vm_id"]!="VM4010","KERNEL_TARGET_IDENTITY_DENIED")
 for field,user,group in (("outpost_identity","serein-outpost","serein-outpost"),("replay_identity","serein-stage1","serein-stage1")):
  value=plan[field];deny(not isinstance(value,dict) or value!=identity_lookup(user,group),"KERNEL_IDENTITY_DENIED")
 anchor=target(root,AUTHORITY);deny(anchor.is_symlink() or not anchor.is_file() or sha(anchor.read_bytes())!=plan["authority_sha256"],"KERNEL_AUTHORITY_DENIED")
 try:load_pem_public_key(anchor.read_bytes()).verify(base64.urlsafe_b64decode(plan["signature"]+"="*(-len(plan["signature"])%4)),canonical({k:v for k,v in plan.items() if k!="signature"}))
 except Exception as exc:raise Denied("KERNEL_PLAN_SIGNATURE_DENIED") from exc
 rows=plan["payload"];deny(not isinstance(rows,list) or not rows,"KERNEL_PAYLOAD_DENIED");seen=set()
 for row in rows:
  deny(not isinstance(row,dict) or set(row)!={"branch","source","target","bytes","sha256","mode"} or row["branch"] not in ORDER,"KERNEL_PAYLOAD_DENIED")
  deny(not any(row["target"].startswith(x) for x in ROOTS) or row["target"] in seen or row["mode"] not in {"0644","0755"},"KERNEL_PAYLOAD_TARGET_DENIED");seen.add(row["target"])
  path=source/row["source"];deny(path.is_symlink() or not path.is_file(),"KERNEL_SOURCE_DENIED");data=path.read_bytes();deny(len(data)!=row["bytes"] or sha(data)!=row["sha256"],"KERNEL_SOURCE_HASH_DENIED")
 deny([b for b in ORDER if any(r["branch"]==b for r in rows)]!=list(ORDER),"KERNEL_BRANCH_ORDER_DENIED")
 manifest_path=source/"release-manifest.json";deny(manifest_path.is_symlink() or not manifest_path.is_file(),"KERNEL_RELEASE_MANIFEST_DENIED");manifest=json.loads(manifest_path.read_text());unsigned={k:v for k,v in manifest.items() if k!="self_digest"}
 deny(manifest.get("self_digest")!="sha256:"+sha(canonical(unsigned)) or plan["release_digest"]!=manifest.get("self_digest"),"KERNEL_RELEASE_DIGEST_DENIED")
 declared=manifest.get("payload");deny(not isinstance(declared,list) or manifest.get("payload_digest")!="sha256:"+sha(canonical(declared)) or manifest.get("install_denominator_digest")!="sha256:"+sha(canonical(rows)),"KERNEL_RELEASE_DENOMINATOR_DENIED")
 deny(sorted((r["source"],r["bytes"],r["sha256"],r["mode"]) for r in rows)!=sorted(tuple(x) for x in declared),"KERNEL_RELEASE_DENOMINATOR_DENIED")
 deny(target(root,"/proc/sys/kernel/random/boot_id").read_text().strip()!=plan["current_boot_id"],"KERNEL_BOOT_DENIED")
 rollback=target(root,plan["rollback_selector"]);deny(rollback.parent!=target(root,"/var/lib/serein/rollback") or not re.fullmatch(r"kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}",rollback.name),"KERNEL_ROLLBACK_DENIED")
 return rows,rollback

def install(root,source,plan,boundary=lambda:None,random_bytes=os.urandom,identity_lookup=None):
 root,source=Path(root),Path(source);rows,rollback=validate(source,root,plan,identity_lookup)
 names=[KEY,DESCRIPTOR,PEER_ENV,*[r["target"] for r in rows]]
 deny(any(os.path.lexists(target(root,x)) for x in names),"KERNEL_FIRST_INSTALL_COLLISION_DENIED");deny(os.path.lexists(rollback),"KERNEL_ROLLBACK_COLLISION_DENIED")
 key=random_bytes(32);deny(type(key) is not bytes or len(key)!=32,"KERNEL_REPLAY_KEY_DENIED")
 peer=(f"SEREIN_OUTPOST_UID={plan['outpost_identity']['uid']}\n"
       f"SEREIN_OUTPOST_GID={plan['outpost_identity']['gid']}\n"
       f"SEREIN_GATEWAY_UID={plan['replay_identity']['uid']}\n"
       f"SEREIN_GATEWAY_GID={plan['replay_identity']['gid']}\n").encode()
 identity=sha(canonical(plan));store_id=str(uuid5(NAMESPACE_URL,"serein-kernel-store:"+identity));key_receipt=str(uuid5(NAMESPACE_URL,"serein-kernel-key:"+identity))
 body={"schema":"VM4010HttpsReplayStoreDescriptor/v1","store_id":store_id,"backend_identity":"SEREIN_KERNEL_REPLAY","issuer":"KERNEL_AUTHORITY","observer":"OUTPOST","signature_algorithm":"HMAC-SHA256","trusted_key_fingerprint":sha(key),"trusted_key_receipt":key_receipt,"target":{"vm_id":plan["target_vm_id"],"boot_id":plan["current_boot_id"]},"source_generation":{"parent":plan["source_parent"],"commit":plan["source_commit"],"tree":plan["source_tree"]},"telemetry_schema":"VM4010HttpsAdapterTelemetry/v2","authority_effect":"NONE"};descriptor=canonical({"body":body,"signature":hmac.new(key,canonical(body),hashlib.sha256).hexdigest()})
 generated={KEY:(key,"0600",plan["replay_identity"]["uid"],plan["replay_identity"]["gid"]),DESCRIPTOR:(descriptor,"0644",0,0),PEER_ENV:(peer,"0600",0,0)}
 replacements=[{"target":n,"bytes":len(v),"sha256":sha(v),"mode":m,"uid":u,"gid":g,"branch":"AUTHORITY"} for n,(v,m,u,g) in generated.items()]+[{**{k:r[k] for k in ("target","bytes","sha256","mode","branch")},"uid":0,"gid":0} for r in rows]
 rollback_key=random_bytes(32);deny(type(rollback_key) is not bytes or len(rollback_key)!=32,"KERNEL_ROLLBACK_KEY_DENIED")
 receipt_body={"schema":"SereinPublicKernelFirstInstallReceipt/v1","plan_sha256":sha(canonical(plan)),"boot_id":plan["current_boot_id"],"branch_order":list(ORDER),"prestate":[{"target":x,"state":"ABSENT"} for x in names],"replacements":replacements,"rollback_selector":plan["rollback_selector"],"rollback_auth_sha256":sha(rollback_key)}
 receipt={**receipt_body,"receipt_signature":base64.urlsafe_b64encode(hmac.new(rollback_key,canonical(receipt_body),hashlib.sha256).digest()).decode().rstrip("=")};receipt["receipt_digest"]=sha(canonical(receipt));receipt_digest=receipt["receipt_digest"]
 rollback.mkdir(mode=0o700);receipt_bytes=canonical(receipt);journal_bytes=canonical({"schema":"SereinKernelRollbackJournal/v1","receipt_digest":receipt_digest,"state":"INSTALLING","completed":[]})
 try:
  atomic(rollback/ROLLBACK_AUTH,rollback_key,"0600",boundary);atomic(rollback/"receipt.json",receipt_bytes,"0600",boundary);journal_write(rollback,receipt_digest,"INSTALLING",[],boundary)
 except Exception:
  for path,data in ((rollback/ROLLBACK_JOURNAL,journal_bytes),(rollback/"receipt.json",receipt_bytes),(rollback/ROLLBACK_AUTH,rollback_key)):
   if os.path.lexists(path):exact(path,data,"0600");path.unlink();sync_parent(path)
  rollback.rmdir();sync_parent(rollback)
  raise
 written=[]
 try:
  for branch in ORDER:
   if branch=="AUTHORITY":
    for name,(data,mode,uid,gid) in generated.items():atomic(target(root,name),data,mode,boundary,uid,gid);written.append(name);journal_write(rollback,receipt_digest,"INSTALLING",written,boundary)
   for row in (r for r in rows if r["branch"]==branch):atomic(target(root,row["target"]),(source/row["source"]).read_bytes(),row["mode"],boundary);written.append(row["target"]);journal_write(rollback,receipt_digest,"INSTALLING",written,boundary)
  for row in replacements:
   data=generated[row["target"]][0] if row["target"] in generated else (source/next(r["source"] for r in rows if r["target"]==row["target"])).read_bytes();exact(target(root,row["target"]),data,row["mode"],row["uid"],row["gid"])
  journal_write(rollback,receipt_digest,"INSTALLED_INACTIVE",written,boundary)
  return {"status":"INSTALLED_INACTIVE","branch_order":list(ORDER),"receipt":plan["rollback_selector"]+"/receipt.json","secret_exported":False}
 except Exception:
  rollback_transaction(root,rollback/"receipt.json",boundary)
  raise

def rollback_transaction(root,receipt_path,boundary=lambda:None):
 root=Path(root);receipt_path=Path(receipt_path);deny(receipt_path.name!="receipt.json" or receipt_path.parent.parent!=target(root,"/var/lib/serein/rollback"),"KERNEL_RECEIPT_PATH_DENIED");info=receipt_path.lstat();deny(receipt_path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600,"KERNEL_RECEIPT_CUSTODY_DENIED");receipt=json.loads(receipt_path.read_text());digest=receipt.pop("receipt_digest",None);deny(digest!=sha(canonical(receipt)),"KERNEL_RECEIPT_DIGEST_DENIED");body={k:v for k,v in receipt.items() if k!="receipt_signature"}
 rollback_dir=receipt_path.parent;dir_info=rollback_dir.lstat();deny(rollback_dir.is_symlink() or not rollback_dir.is_dir() or stat.S_IMODE(dir_info.st_mode)!=0o700 or (os.name!="nt" and (dir_info.st_uid!=0 or dir_info.st_gid!=0)),"KERNEL_ROLLBACK_DIR_CUSTODY_DENIED");auth=rollback_dir/ROLLBACK_AUTH;auth_info=auth.lstat();deny(auth.is_symlink() or not stat.S_ISREG(auth_info.st_mode) or stat.S_IMODE(auth_info.st_mode)!=0o600 or (os.name!="nt" and (auth_info.st_uid!=0 or auth_info.st_gid!=0)),"KERNEL_ROLLBACK_AUTH_CUSTODY_DENIED");key=auth.read_bytes();deny(sha(key)!=receipt.get("rollback_auth_sha256"),"KERNEL_ROLLBACK_AUTH_DENIED")
 expected=base64.urlsafe_b64encode(hmac.new(key,canonical(body),hashlib.sha256).digest()).decode().rstrip("=");deny(not hmac.compare_digest(expected,receipt.get("receipt_signature","")),"KERNEL_RECEIPT_SIGNATURE_DENIED")
 deny(receipt.get("branch_order")!=list(ORDER) or any(row.get("target") not in {KEY,DESCRIPTOR,PEER_ENV} and not any(row.get("target","").startswith(prefix) for prefix in ROOTS) for row in receipt.get("replacements",[])),"KERNEL_RECEIPT_TARGET_DENIED")
 journal=journal_read(rollback_dir,digest);completed=list(journal["completed"]);ordered=list(reversed(receipt["replacements"]));allowed=[r["target"] for r in ordered];install_order=list(reversed(allowed));deny(len(completed)!=len(set(completed)),"KERNEL_JOURNAL_ORDER_DENIED")
 if journal["state"] in {"INSTALLING","INSTALLED_INACTIVE"}:deny(completed!=install_order[:len(completed)],"KERNEL_JOURNAL_ORDER_DENIED");completed=[]
 else:deny(completed!=allowed[:len(completed)],"KERNEL_JOURNAL_ORDER_DENIED")
 if journal["state"]=="ROLLBACK_COMPLETE":
  deny(any(os.path.lexists(target(root,row["target"])) for row in ordered),"KERNEL_ROLLBACK_RESIDUE_DENIED");return {"status":"ROLLBACK_COMPLETE","branch_order":receipt["branch_order"]}
 journal_write(rollback_dir,digest,"ROLLING_BACK",completed,boundary)
 for row in ordered:
  path=target(root,row["target"])
  if os.path.lexists(path):exact_row(path,row);boundary();path.unlink();sync_parent(path)
  if row["target"] not in completed:completed.append(row["target"]);journal_write(rollback_dir,digest,"ROLLING_BACK",completed,boundary)
 deny(any(os.path.lexists(target(root,row["target"])) for row in ordered),"KERNEL_ROLLBACK_RESIDUE_DENIED");journal_write(rollback_dir,digest,"ROLLBACK_COMPLETE",completed,boundary)
 return {"status":"ROLLBACK_COMPLETE","branch_order":receipt["branch_order"]}
def rollback(root,receipt_path,boundary=lambda:None):return rollback_transaction(root,receipt_path,boundary)
