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
# Existing public release/layout declarations are mandatory as a whole.
# Checking these declarations is not behavioral verification or admission.
STAGE1_ORDER=ORDER+("GPU_CONTROL","OFFLINE_COMPANION","COGNITIVE_GATEWAY","OUTPOST_STAGE1_WITNESS")
LATER_CORES=("PLATFORM","ROOT","MEMORY","KNOWLEDGE","UI","AUDIO","PERSONALITY","MODULAR","CLOUD")
# Mechanical closure of the existing private Companion destination. These
# paths do not prove authenticated Gateway ingress or whole-Kernel readiness.
COMPANION_PACKAGE={
 "payload/runtime/kernel-observer-access.conf":("AUTHORITY","/usr/lib/serein/kernel/kernel-observer-access.conf","0644"),
 "payload/runtime/replay_store.py":("OPERATIONS","/usr/lib/serein/kernel/replay_store.py","0644"),
 "payload/runtime/persistent_replay_store.py":("OPERATIONS","/usr/lib/serein/kernel/persistent_replay_store.py","0644"),
 "payload/serein_stage1/kernel_operations.py":("OPERATIONS","/usr/lib/python3/dist-packages/serein_stage1/kernel_operations.py","0644"),
 "payload/serein_stage1/audit.py":("OPERATIONS","/usr/lib/python3/dist-packages/serein_stage1/audit.py","0644"),
 "payload/bin/serein-kernel-operations-heartbeat":("OPERATIONS","/usr/libexec/serein/serein-kernel-operations-heartbeat","0755"),
 "payload/systemd/serein-kernel-operations-heartbeat.service":("OPERATIONS","/etc/systemd/system/serein-kernel-operations-heartbeat.service","0644"),
 "payload/systemd/serein-kernel-operations-api.service":("OPERATIONS","/etc/systemd/system/serein-kernel-operations-api.service","0644"),
 "payload/systemd/serein-kernel-operations-api.socket":("OPERATIONS","/etc/systemd/system/serein-kernel-operations-api.socket","0644"),
 "payload/serein_stage1/outpost_evidence/__init__.py":("OPERATIONS","/usr/lib/python3/dist-packages/serein_stage1/outpost_evidence/__init__.py","0644"),
 "payload/serein_stage1/outpost_evidence/host_vitality.py":("OPERATIONS","/usr/lib/python3/dist-packages/serein_stage1/outpost_evidence/host_vitality.py","0644"),
 "payload/serein_stage1/outpost_evidence/vitals_aggregation.py":("OPERATIONS","/usr/lib/python3/dist-packages/serein_stage1/outpost_evidence/vitals_aggregation.py","0644"),
 "payload/serein_stage1/outpost_evidence/vitals_edge.py":("OPERATIONS","/usr/lib/python3/dist-packages/serein_stage1/outpost_evidence/vitals_edge.py","0644"),
 "payload/serein_stage1/authority_contract.py":("AUTHORITY","/usr/lib/python3/dist-packages/serein_stage1/authority_contract.py","0644"),
 "payload/serein_stage1/kernel_branch_api.py":("AUTHORITY","/usr/lib/python3/dist-packages/serein_stage1/kernel_branch_api.py","0644"),
 "payload/serein_stage1/stage1-conversation-policy.v1.json":("AUTHORITY","/usr/lib/python3/dist-packages/serein_stage1/stage1-conversation-policy.v1.json","0644"),
 "payload/systemd/serein-conversation-runtime.service":("INTERFACE","/etc/systemd/system/serein-conversation-runtime.service","0644"),
 "payload/systemd/serein-conversation-runtime.socket":("INTERFACE","/etc/systemd/system/serein-conversation-runtime.socket","0644"),
 "payload/bin/serein-conversation-runtime":("INTERFACE","/usr/libexec/serein/serein-conversation-runtime","0755"),
 "payload/bin/serein-kernel-client-gateway":("INTERFACE","/usr/libexec/serein/serein-kernel-client-gateway","0755"),
 "payload/systemd/serein-kernel-client-gateway-haos.socket":("INTERFACE","/etc/systemd/system/serein-kernel-client-gateway-haos.socket","0644"),
 "payload/systemd/serein-kernel-client-gateway@.service":("INTERFACE","/etc/systemd/system/serein-kernel-client-gateway@.service","0644"),
 "payload/serein_stage1/kernel.py":("INTERFACE","/usr/lib/python3/dist-packages/serein_stage1/kernel.py","0644"),
 "payload/serein_stage1/serein_https_gateway_adapter.py":("INTERFACE","/usr/lib/python3/dist-packages/serein_stage1/serein_https_gateway_adapter.py","0644"),
 "payload/serein_stage1/conversation_runtime.py":("INTERFACE","/usr/lib/python3/dist-packages/serein_stage1/conversation_runtime.py","0644"),
 "payload/serein_stage1/__init__.py":("INTERFACE","/usr/lib/python3/dist-packages/serein_stage1/__init__.py","0644"),
 "payload/serein_stage1/companion_provider.py":("INTERFACE","/usr/lib/python3/dist-packages/serein_stage1/companion_provider.py","0644"),
 "payload/serein_stage1/gpu_control.py":("INTERFACE","/usr/lib/python3/dist-packages/serein_stage1/gpu_control.py","0644"),
 "payload/serein_stage1/supervision.py":("OPERATIONS","/usr/lib/python3/dist-packages/serein_stage1/supervision.py","0644"),
}
SCHEMA="SereinPublicKernelFirstInstallPlan/v1"
KEY="/var/lib/serein/kernel/authority/replay.key"
DESCRIPTOR="/var/lib/serein/kernel/authority/replay-descriptor.json"
PEER_ENV="/etc/serein/kernel/replay-peer.env"
NATIVE_KEY="/var/lib/serein/kernel/authority/domain-identity.pem"
NATIVE_REGISTRY="/var/lib/serein/kernel/authority/domain-identity.json"
POLICY_EVIDENCE="/var/lib/serein/kernel/authority/installed-policy-evidence.json"
GENERATED=(KEY,DESCRIPTOR,PEER_ENV,NATIVE_KEY,NATIVE_REGISTRY,POLICY_EVIDENCE)
AUTHORITY="/usr/share/serein/outpost/cognition-verification.pem"
ROLLBACK_AUTH="rollback-auth.key"
ROLLBACK_JOURNAL="phase-journal.json"
ROOTS=("/usr/lib/serein/kernel/","/usr/lib/python3/dist-packages/serein_stage1/","/usr/libexec/serein/serein-kernel-","/etc/systemd/system/serein-kernel-","/usr/libexec/serein/serein-observation-audit","/etc/systemd/system/serein-observation-audit.","/usr/libexec/serein/serein-conversation-runtime","/etc/systemd/system/serein-conversation-runtime.")
class Denied(RuntimeError):pass

RUNTIME_DIRECTORY='/run/serein/stage1'
RUNTIME_ACCESS_SOURCE='payload/runtime/kernel-observer-access.conf'
RUNTIME_ACCESS_TARGET='/usr/lib/serein/kernel/kernel-observer-access.conf'
RUNTIME_ACCESS_RULE=(b'# Whole Kernel construction: only Outpost may traverse to its private sockets.\n'
 b'# Preserve the Base directory owner/group/mode; no listing, write or default ACL.\n'
 b'a+ /run/serein/stage1 - - - - u:serein-outpost:--x\n')


def observer_access_acl(uid):
 """Exact Linux UAPI access ACL: owner rwx, named observer x, group rx."""
 import struct
 deny(type(uid) is not int or not 0<uid<2**32-1,'KERNEL_RUNTIME_ACCESS_IDENTITY_DENIED')
 return (struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,who) for tag,perm,who in
     ((1,7,2**32-1),(2,1,uid),(4,5,2**32-1),(16,5,2**32-1),(32,0,2**32-1))))


def _runtime_access_read(root,plan):
 """No-follow, inode-bound read of the single pre-existing Base directory."""
 import errno
 root=Path(root);descriptors=[]
 try:
  parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  descriptors.append((parent,None,None))
  for part in ('run','serein','stage1'):
   prior=os.fstat(parent)
   deny(prior.st_uid!=0 or stat.S_IMODE(prior.st_mode)&0o022,
        'KERNEL_RUNTIME_ACCESS_ANCESTOR_DENIED')
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   descriptors.append((child,parent,part));parent=child
  before=os.fstat(parent)
  replay=plan['replay_identity'];observer=plan['outpost_identity']
  deny(before.st_uid!=replay['uid'] or before.st_gid!=replay['gid']
       or replay['uid']==observer['uid'] or stat.S_IMODE(before.st_mode)!=0o750,
       'KERNEL_RUNTIME_ACCESS_CUSTODY_DENIED')
  values={}
  for kind in ('access','default'):
   try:raw=os.getxattr(parent,'system.posix_acl_'+kind)
   except OSError as exc:
    if exc.errno!=errno.ENODATA:raise
    raw=None
   values[kind]=raw
  deny(values['default'] is not None or values['access'] not in (None,observer_access_acl(observer['uid'])),
       'KERNEL_RUNTIME_ACCESS_ACL_DENIED')
  for fd,parent_fd,name in descriptors[1:]:
   opened=os.fstat(fd);named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
   deny((opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_gid)!=
        (named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid),
        'KERNEL_RUNTIME_ACCESS_CHANGED')
  after=os.fstat(parent)
  deny((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_ctime_ns)!=
       (after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid,after.st_ctime_ns),
       'KERNEL_RUNTIME_ACCESS_CHANGED')
  return {'path':RUNTIME_DIRECTORY,'dev':before.st_dev,'ino':before.st_ino,
      'uid':before.st_uid,'gid':before.st_gid,'mode':'0750',
      'access_acl_hex':None if values['access'] is None else values['access'].hex(),
      'default_acl_hex':None}
 except (OSError,KeyError,TypeError) as exc:
  raise Denied('KERNEL_RUNTIME_ACCESS_READ_DENIED') from exc
 finally:
  for fd,_,_ in reversed(descriptors):os.close(fd)


def capture_runtime_access(root,plan):
 return _runtime_access_read(root,plan)


def apply_runtime_access(root,plan,boundary=lambda:None):
 """Only called by the complete Outpost owner before its first socket start."""
 import subprocess
 before=plan['runtime_access_prestate'];boundary()
 deny(capture_runtime_access(root,plan)!=before,'KERNEL_RUNTIME_ACCESS_PRESTATE_CHANGED')
 rule=target(Path(root),RUNTIME_ACCESS_TARGET)
 deny(rule.is_symlink() or rule.read_bytes()!=RUNTIME_ACCESS_RULE
      or (rule.stat().st_uid,rule.stat().st_gid,stat.S_IMODE(rule.stat().st_mode))!=(0,0,0o644),
      'KERNEL_RUNTIME_ACCESS_RULE_DENIED')
 # Native tmpfiles applies this one exact additive entry, never the full host
 # configuration. No recursive/default ACL, chmod, group or service change.
 argv=['/usr/bin/systemd-tmpfiles','--create']
 if Path(root)!=Path('/'):argv.append('--root='+str(root))
 argv.append(str(rule))
 try:
  subprocess.run(argv,check=True,timeout=15,stdin=subprocess.DEVNULL,
      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,
      env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
 except (OSError,subprocess.SubprocessError) as exc:
  raise Denied('KERNEL_RUNTIME_ACCESS_APPLY_DENIED') from exc
 expected={**before,'access_acl_hex':observer_access_acl(plan['outpost_identity']['uid']).hex()}
 deny(capture_runtime_access(root,plan)!=expected,'KERNEL_RUNTIME_ACCESS_POSTSTATE_DENIED')
 boundary()
 return expected


def restore_runtime_access(root,plan,boundary=lambda:None):
 """Restore only the exact ACL delta after all transaction-owned units stop."""
 before=plan['runtime_access_prestate'];boundary()
 observed=capture_runtime_access(root,plan)
 expected={**before,'access_acl_hex':observer_access_acl(plan['outpost_identity']['uid']).hex()}
 deny(observed not in (before,expected),'KERNEL_RUNTIME_ACCESS_COMPENSATION_DENIED')
 if observed!=before:
  path=target(Path(root),RUNTIME_DIRECTORY)
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   info=os.fstat(fd)
   deny((info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=
        (observed['dev'],observed['ino'],observed['uid'],observed['gid'],int(observed['mode'],8)),
        'KERNEL_RUNTIME_ACCESS_CHANGED')
   deny(capture_runtime_access(root,plan)!=observed,'KERNEL_RUNTIME_ACCESS_CHANGED')
   import errno
   for kind in ('access','default'):
    try:current=os.getxattr(fd,'system.posix_acl_'+kind).hex()
    except OSError as exc:
     if exc.errno!=errno.ENODATA:raise
     current=None
    deny(current!=observed[kind+'_acl_hex'],'KERNEL_RUNTIME_ACCESS_CHANGED')
   named=path.lstat();final=os.fstat(fd)
   fingerprint=lambda i:(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_ctime_ns)
   deny(fingerprint(info)!=fingerprint(final) or fingerprint(final)!=fingerprint(named),
        'KERNEL_RUNTIME_ACCESS_CHANGED')
   if before['access_acl_hex'] is None:os.removexattr(fd,'system.posix_acl_access')
   else:os.setxattr(fd,'system.posix_acl_access',bytes.fromhex(before['access_acl_hex']))
  finally:os.close(fd)
 deny(capture_runtime_access(root,plan)!=before,'KERNEL_RUNTIME_ACCESS_RESTORATION_UNPROVEN')
 boundary()
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


def target_prestate(root, row, *, generated=False, include_bytes=False,expected_nlink=1):
 """Capture exact retained bytes/custody without following links or writing."""
 name=row["target"];relative=Path(name)
 deny(expected_nlink not in (1,2),'KERNEL_TARGET_LINK_COUNT_DENIED')
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
   deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=expected_nlink or (before.st_uid,before.st_gid)!=(0,0)
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

def capture_install_prestate(root,rows,prior=None):
 """Exact signed recovered public preimages; generated identity stays absent."""
 if prior is None:return capture_target_prestate(root,rows)
 ordered=[r for branch in ORDER for r in rows if r['branch']==branch]
 deny(not isinstance(prior,list) or any(not isinstance(r,dict) for r in prior)
      or [r.get('target') for r in prior]!=list(GENERATED)+[r['target'] for r in ordered],
      'KERNEL_RECOVERED_PRESTATE_DENIED')
 result=[]
 for previous in prior:
  name=previous['target']
  if previous.get('state')=='PRESENT_REPLACE':
   deny(name in GENERATED or set(previous)!={'target','state','bytes','sha256','mode','uid','gid','device','inode','nlink'},
        'KERNEL_RECOVERED_PRESTATE_DENIED')
   row=next(r for r in ordered if r['target']==name)
   deny(previous['mode'] not in {'0644','0755'} or type(previous['bytes']) is not int
        or not 0<=previous['bytes']<=16*1024*1024 or not isinstance(previous['sha256'],str)
        or not re.fullmatch(r'[0-9a-f]{64}',previous['sha256'])
        or all(previous[k]==row[k] for k in ('bytes','sha256','mode')),
        'KERNEL_RECOVERED_PRESTATE_DENIED')
   expected={**previous,'state':'PRESENT_PRESERVED'}
   observed=target_prestate(root,previous)
   deny(observed!=expected,'KERNEL_RECOVERED_PRESTATE_CHANGED')
   result.append(dict(previous))
  else:
   row={'target':name} if name in GENERATED else next(r for r in ordered if r['target']==name)
   observed=target_prestate(root,row,generated=name in GENERATED)
   deny(observed!=previous,'KERNEL_RECOVERED_PRESTATE_CHANGED');result.append(observed)
 return result

def capture_successor_payload(root,rows):
 """Read exact public predecessor bytes for later governed compensation.

 The caller must authenticate its original signed plan before this primitive.
 This is not a plan, authorization, installation or rollback implementation.
 Generated identity/replay state is excluded, never backed up or regenerated
 through this public-payload reader. The original first-install rollback must
 not be reused to compensate a successor: it removes first-created identity.
 """
 deny(not isinstance(rows,list) or not rows,'KERNEL_SUCCESSOR_PAYLOAD_DENIED')
 names=set()
 for row in rows:
  deny(not isinstance(row,dict) or set(row)!={'branch','source','target','bytes','sha256','mode'},
       'KERNEL_SUCCESSOR_PAYLOAD_DENIED')
  name=row['target'];source=row['source']
  deny(not isinstance(name,str) or '\x00' in name or not Path(name).is_absolute() or '..' in Path(name).parts
       or Path(name).as_posix()!=name or name in names or name in GENERATED
       or not any(name.startswith(prefix) for prefix in ROOTS)
       or not isinstance(source,str) or not source or source=='.' or '\\' in source or '\x00' in source
       or Path(source).is_absolute() or '..' in Path(source).parts or Path(source).as_posix()!=source
       or not isinstance(row['branch'],str) or row['branch'] not in ORDER
       or not isinstance(row['mode'],str) or row['mode'] not in {'0644','0755'}
       or type(row['bytes']) is not int or not 0<=row['bytes']<=16*1024*1024
       or not isinstance(row['sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',row['sha256']),
       'KERNEL_SUCCESSOR_PAYLOAD_DENIED')
  names.add(name)
 deny({row['branch'] for row in rows}!=set(ORDER),'KERNEL_SUCCESSOR_BRANCH_SET_DENIED')
 captured={}
 for row in rows:
  value=target_prestate(root,row,include_bytes=True)
  deny(not isinstance(value,tuple),'KERNEL_SUCCESSOR_PREDECESSOR_MISSING')
  fact,data=value
  deny(fact['state']!='PRESENT_PRESERVED','KERNEL_SUCCESSOR_PREDECESSOR_MISSING')
  captured[row['target']]={'prestate':fact,'content':data}
 for row in rows:
  fact=captured[row['target']]
  deny(target_prestate(root,row,include_bytes=True)!=(fact['prestate'],fact['content']),
       'KERNEL_SUCCESSOR_PRESTATE_CHANGED')
 return captured

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

def verify_gateway_credential(root):
 """Preflight the existing LoadCredential source, never provision or disclose it.

 Same fixed name/32..4096-byte/no-CRLF contract as load_companion_token.
 This checks root custody before systemd projects the secret to the service;
 it does not prove that HAOS holds the matching value or grant admission.
 """
 path=Path(root)/'etc/serein/haos-companion-token';handles=[]
 identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
 fingerprint=lambda s:(*identity(s),s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 try:
  parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  handles.append((parent,None,'/',identity(os.fstat(parent))))
  for part in path.parts[1:-1]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   handles.append((child,parent,part,identity(os.fstat(child))));parent=child
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
  with os.fdopen(fd,'rb') as stream:
   before=os.fstat(stream.fileno())
   deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=0
        or stat.S_IMODE(before.st_mode)&0o077 or not 32<=before.st_size<=4096,
        'KERNEL_GATEWAY_CREDENTIAL_CUSTODY_DENIED')
   data=stream.read(4097);stream.seek(0);second=stream.read(4097)
   deny(len(data)!=before.st_size or not 32<=len(data)<=4096 or b'\r' in data or b'\n' in data,
        'KERNEL_GATEWAY_CREDENTIAL_FORMAT_DENIED')
   deny(data!=second or fingerprint(before)!=fingerprint(os.fstat(stream.fileno()))
        or fingerprint(before)!=fingerprint(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
        'KERNEL_GATEWAY_CREDENTIAL_CHANGED')
  for child,parent_fd,name,before in handles:
   deny(identity(os.fstat(child))!=before
        or identity(os.stat(name,dir_fd=parent_fd,follow_symlinks=False))!=before,
        'KERNEL_GATEWAY_CREDENTIAL_ANCESTOR_CHANGED')
 except FileNotFoundError:raise Denied('KERNEL_GATEWAY_CREDENTIAL_MISSING') from None
 except OSError:raise Denied('KERNEL_GATEWAY_CREDENTIAL_CUSTODY_DENIED') from None
 finally:
  for fd,_,_,_ in reversed(handles):os.close(fd)


def validate(source,root,plan,identity_lookup=None):
 identity_lookup=identity_lookup or system_identity
 required={"schema","target_vm_id","source_parent","source_commit","source_tree","release_digest","current_boot_id","outpost_identity","replay_identity","payload","target_prestate","rollback_selector","authority_sha256","archive_sha256","source_receipt_sha256","source_inventory_digest","reserved_domain_ids","native_identity","signature"}
 required|={"host_identity","host_projection_digest","outpost_generation"}
 if isinstance(plan,dict) and 'runtime_access_prestate' in plan:required.add('runtime_access_prestate')
 if isinstance(plan,dict) and 'recovered_predecessor' in plan:
  required.add('recovered_predecessor')
  prior=plan['recovered_predecessor']
  deny(not isinstance(prior,dict) or set(prior)!={'rollback_selector','plan_sha256','receipt_sha256',
       'journal_sha256','witness_sha256','current_boot_id','machine_id_sha256','reserved_domain_id'}
       or prior.get('rollback_selector')==plan.get('rollback_selector')
       or not re.fullmatch(r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',str(prior.get('rollback_selector')))
       or prior.get('current_boot_id')!=plan.get('current_boot_id')
       or any(not isinstance(prior.get(k),str) or not re.fullmatch(r'[0-9a-f]{64}',prior[k]) for k in
              ('plan_sha256','receipt_sha256','journal_sha256','witness_sha256','machine_id_sha256'))
       or prior.get('reserved_domain_id') not in plan.get('reserved_domain_ids',[]),
       'KERNEL_RECOVERED_BINDING_DENIED')
 deny(not isinstance(plan,dict) or set(plan)!=required or plan["schema"]!=SCHEMA,"KERNEL_PLAN_DENIED")
 generation=plan['outpost_generation']
 deny(not isinstance(generation,dict) or set(generation)!={'schema','generation','release_digest','predecessor_receipt_sha256','inventory_digest','selector_digest'}
      or generation['schema']!='SereinOutpostGenerationSelector/v1'
      or any(not isinstance(generation[k],str) or not re.fullmatch(r'[0-9a-f]{64}',generation[k]) for k in ('generation','predecessor_receipt_sha256','inventory_digest','selector_digest'))
      or generation['release_digest']!='sha256:'+generation['generation']
      or generation['selector_digest']!=sha(json.dumps({k:v for k,v in generation.items() if k!='selector_digest'},sort_keys=True,separators=(',',':')).encode()),'KERNEL_OUTPOST_GENERATION_DENIED')
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
 if 'recovered_predecessor' in plan:
  deny(plan['recovered_predecessor']['machine_id_sha256']!=plan['host_identity']['file']['sha256'],
       'KERNEL_RECOVERED_HOST_DENIED')
 for row in rows:
  deny(not isinstance(row,dict) or set(row)!={"branch","source","target","bytes","sha256","mode"} or row["branch"] not in ORDER,"KERNEL_PAYLOAD_DENIED")
  deny(not any(row["target"].startswith(x) for x in ROOTS) or row["target"] in seen or row["mode"] not in {"0644","0755"},"KERNEL_PAYLOAD_TARGET_DENIED");seen.add(row["target"])
  source_data(source,row)
 deny([b for b in ORDER if any(r["branch"]==b for r in rows)]!=list(ORDER),"KERNEL_BRANCH_ORDER_DENIED")
 for name,expected in COMPANION_PACKAGE.items():
  matches=[row for row in rows if row["source"]==name]
  deny(len(matches)!=1 or (matches[0]["branch"],matches[0]["target"],matches[0]["mode"])!=expected,"KERNEL_COMPANION_PACKAGE_DENIED")
 manifest_path=source/"release-manifest.json";deny(manifest_path.is_symlink() or not manifest_path.is_file(),"KERNEL_RELEASE_MANIFEST_DENIED");manifest=json.loads(manifest_path.read_text());unsigned={k:v for k,v in manifest.items() if k!="self_digest"}
 deny(manifest.get("self_digest")!="sha256:"+sha(canonical(unsigned)) or plan["release_digest"]!=manifest.get("self_digest"),"KERNEL_RELEASE_DIGEST_DENIED")
 deny(manifest.get("schema")!="SereinPortableKernelRelease/v1" or manifest.get("branch_order")!=list(ORDER) or manifest.get("activation")!="OUTPOST_ONLY_AFTER_INACTIVE_PROOF" or manifest.get("gate")=="KERNEL_AUTHORITY"
      or manifest.get("classification")!="PUBLIC_KERNEL_COMPANION_FOUNDATION_INACTIVE"
      or manifest.get("stage1_order")!=list(STAGE1_ORDER)
      or manifest.get("later_core_attachments")!=list(LATER_CORES)
      or manifest.get("admission_effect")!="NONE","KERNEL_COMPLETE_PACKAGE_DENIED")
 declared=manifest.get("payload");deny(not isinstance(declared,list) or manifest.get("payload_digest")!="sha256:"+sha(canonical(declared)) or manifest.get("install_denominator_digest")!="sha256:"+sha(canonical(rows)),"KERNEL_RELEASE_DENOMINATOR_DENIED")
 deny(sorted((r["source"],r["bytes"],r["sha256"],r["mode"]) for r in rows)!=sorted(tuple(x) for x in declared),"KERNEL_RELEASE_DENOMINATOR_DENIED")
 deny(target(root,"/proc/sys/kernel/random/boot_id").read_text().strip()!=plan["current_boot_id"],"KERNEL_BOOT_DENIED")
 rollback=target(root,plan["rollback_selector"]);deny(rollback.parent!=target(root,"/var/lib/serein/rollback") or not re.fullmatch(r"kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}",rollback.name),"KERNEL_ROLLBACK_DENIED")
 verify_gateway_credential(root)
 return [r for branch in ORDER for r in rows if r["branch"]==branch],rollback

def prepare_installed_policy_evidence(root,source,plan,installer_key,*,native_material,identity_lookup=None):
 """Prepare non-secret exact-install evidence with the existing installer key.

 Memory-only composition, not a new runtime grant or an installation result.
 The eventual whole-domain transaction must place and verify these bytes
 atomically. Private plan, source receipt, keys and witness stay private.
 No caller-provided READY field or extra input is copied into this envelope.
 """
 root,source=Path(root),Path(source)
 rows,_=validate(source,root,plan,identity_lookup)
 anchor=target(root,AUTHORITY).read_bytes()
 public=load_pem_public_key(anchor).public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
 deny(installer_key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)!=anchor,
      'KERNEL_POLICY_EVIDENCE_SIGNER_DENIED')
 native=verify_native_identity_material(source,plan,native_material,public,
                                      reserved_ids=set(plan['reserved_domain_ids']))
 body=installed_policy_evidence_body(plan,rows,native,sha((source/'release-manifest.json').read_bytes()))
 encoded=canonical(body)
 return canonical({'body':body,'signature':base64.urlsafe_b64encode(
     installer_key.sign(encoded)).decode().rstrip('=')})


def installed_policy_evidence_body(plan,rows,native,manifest_sha256):
 """Exact non-secret projection, shared by preparation and atomic placement."""
 policy_source='payload/serein_stage1/stage1-conversation-policy.v1.json'
 policy=[row for row in rows if row['source']==policy_source]
 deny(len(policy)!=1,'KERNEL_POLICY_EVIDENCE_CLOSURE_DENIED')
 body={'schema':'SereinKernelInstalledPolicyEvidence/v1','target':'VM4010',
       'boot_id':plan['current_boot_id'],
       'source_generation':{'parent':plan['source_parent'],'commit':plan['source_commit'],'tree':plan['source_tree']},
       'release_digest':plan['release_digest'],'plan_sha256':sha(canonical(plan)),
       'manifest_sha256':manifest_sha256,
       'source_receipt_sha256':plan['source_receipt_sha256'],
       'source_inventory_digest':plan['source_inventory_digest'],
       'native_identity':{key:native[key] for key in
          ('instance_id','checkpoint','registry_sha256','transaction_context')},
       'host_identity_sha256':sha(plan['host_identity']['machine_id'].encode('ascii')),
       'host_identity_file':dict(plan['host_identity']['file']),
       'host_projection_digest':plan['host_projection_digest'],
       'outpost_generation':dict(plan['outpost_generation']),
       'conversation_policy':dict(policy[0]),'payload':[dict(row) for row in rows],
       'state':'MATERIAL_BINDING_ONLY','authority_effect':'NONE','admission_effect':'NONE'}
 return body


def install(root,source,plan,boundary=lambda:None,random_bytes=os.urandom,identity_lookup=None,*,native_material=None,policy_evidence=None):
 root,source=Path(root),Path(source);rows,rollback=validate(source,root,plan,identity_lookup)
 external_boundary=boundary
 def boundary():
  external_boundary()
  verify_host_identity(root,plan)
 deny(not isinstance(native_material,dict) or native_material.get('binding')!=plan['native_identity'],"KERNEL_NATIVE_IDENTITY_PLAN_BINDING_DENIED")
 native_material={**native_material,'binding':dict(native_material['binding'])}
 anchor=load_pem_public_key(target(root,AUTHORITY).read_bytes()).public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
 verify_native_identity_material(source,plan,native_material,anchor,reserved_ids=set(plan['reserved_domain_ids']))
 try:
  deny(type(policy_evidence) is not bytes,'KERNEL_POLICY_EVIDENCE_REQUIRED')
  evidence=json.loads(policy_evidence)
  deny(not isinstance(evidence,dict) or set(evidence)!={'body','signature'}
       or canonical(evidence)!=policy_evidence
       or evidence['body']!=installed_policy_evidence_body(plan,rows,native_material['binding'],sha((source/'release-manifest.json').read_bytes())),
       'KERNEL_POLICY_EVIDENCE_BINDING_DENIED')
  signature=evidence['signature']
  deny(not isinstance(signature,str) or not re.fullmatch(r'[A-Za-z0-9_-]{86}',signature),
       'KERNEL_POLICY_EVIDENCE_SIGNATURE_DENIED')
  decoded=base64.b64decode(signature+'==',altchars=b'-_',validate=True)
  deny(base64.urlsafe_b64encode(decoded).decode().rstrip('=')!=signature,
       'KERNEL_POLICY_EVIDENCE_SIGNATURE_DENIED')
  load_pem_public_key(target(root,AUTHORITY).read_bytes()).verify(decoded,canonical(evidence['body']))
 except Denied:raise
 except Exception as exc:raise Denied('KERNEL_POLICY_EVIDENCE_DENIED') from exc
 boundary()
 deny(capture_install_prestate(root,rows,plan['target_prestate'] if 'recovered_predecessor' in plan else None)!=plan["target_prestate"],"KERNEL_TARGET_PRESTATE_COLLISION_CHANGED")
 deny(os.path.lexists(rollback),"KERNEL_ROLLBACK_COLLISION_DENIED")
 preserved={row["target"]:row for row in plan["target_prestate"] if row["state"]=="PRESENT_PRESERVED"}
 replacing={row['target']:row for row in plan['target_prestate'] if row['state']=='PRESENT_REPLACE'}
 preimages={name:target_prestate(root,row,include_bytes=True)[1] for name,row in replacing.items()}
 predecessor_witness=None
 if 'recovered_predecessor' in plan:
  name='/var/lib/serein-outpost/kernel/kernel-install-witness.json';path=target(root,name)
  row={'target':name,'mode':'0600','bytes':path.lstat().st_size,
       'sha256':plan['recovered_predecessor']['witness_sha256']}
  deny(not 0<row['bytes']<=16*1024*1024,'KERNEL_PREDECESSOR_WITNESS_DENIED')
  predecessor_witness=target_prestate(root,row,include_bytes=True)
 written=[];ownership=[]
 def preserved_unchanged():
  verify_host_identity(root,plan)
  if predecessor_witness is not None:
   deny(target_prestate(root,predecessor_witness[0],include_bytes=True)!=predecessor_witness,
        'KERNEL_PREDECESSOR_WITNESS_CHANGED')
  for row in rows:
   if row["target"] in preserved:
    deny(target_prestate(root,row)!=preserved[row["target"]],"KERNEL_PRESERVED_PRESTATE_CHANGED")
  for name,previous in replacing.items():
   if name not in written:
    held=rollback/('retained-inode-'+sha(name.encode()));links=2 if os.path.lexists(held) else 1
    if links==2:
     info=held.lstat();deny((info.st_dev,info.st_ino)!=(previous['device'],previous['inode']),
                            'KERNEL_RETAINED_INODE_CHANGED');exact_row(held,previous)
    deny(target_prestate(root,previous,expected_nlink=links)!={**previous,'state':'PRESENT_PRESERVED','nlink':links},
         'KERNEL_RECOVERED_PRESTATE_CHANGED')
   else:
    row=next(r for r in rows if r['target']==name);owned=next(r for r in ownership if r['target']==name)
    fact=target_prestate(root,row)
    deny((fact.get('device'),fact.get('inode'))!=(owned['device'],owned['inode']),
         'KERNEL_REPLACEMENT_OWNERSHIP_CHANGED')
 key=random_bytes(32);deny(type(key) is not bytes or len(key)!=32,"KERNEL_REPLAY_KEY_DENIED")
 peer=(f"SEREIN_OUTPOST_UID={plan['outpost_identity']['uid']}\n"
       f"SEREIN_OUTPOST_GID={plan['outpost_identity']['gid']}\n"
       f"SEREIN_GATEWAY_UID={plan['replay_identity']['uid']}\n"
       f"SEREIN_GATEWAY_GID={plan['replay_identity']['gid']}\n").encode()
 identity=sha(canonical(plan));store_id=str(uuid5(NAMESPACE_URL,"serein-kernel-store:"+identity));key_receipt=str(uuid5(NAMESPACE_URL,"serein-kernel-key:"+identity))
 body={"schema":"VM4010HttpsReplayStoreDescriptor/v1","store_id":store_id,"backend_identity":"SEREIN_KERNEL_REPLAY","issuer":"KERNEL_AUTHORITY","observer":"OUTPOST","signature_algorithm":"HMAC-SHA256","trusted_key_fingerprint":sha(key),"trusted_key_receipt":key_receipt,"target":{"vm_id":plan["target_vm_id"],"boot_id":plan["current_boot_id"]},"source_generation":{"parent":plan["source_parent"],"commit":plan["source_commit"],"tree":plan["source_tree"]},"telemetry_schema":"VM4010HttpsAdapterTelemetry/v2","authority_effect":"NONE"};descriptor=canonical({"body":body,"signature":hmac.new(key,canonical(body),hashlib.sha256).hexdigest()})
 generated={KEY:(key,"0600",plan["replay_identity"]["uid"],plan["replay_identity"]["gid"]),DESCRIPTOR:(descriptor,"0644",0,0),PEER_ENV:(peer,"0600",0,0),NATIVE_KEY:(native_material['private'],"0600",0,0),NATIVE_REGISTRY:(native_material['registry'],"0644",0,0)}
 generated[POLICY_EVIDENCE]=(policy_evidence,"0644",0,0)
 replacements=[{"target":n,"bytes":len(v),"sha256":sha(v),"mode":m,"uid":u,"gid":g,"branch":"AUTHORITY"} for n,(v,m,u,g) in generated.items()]+[{**{k:r[k] for k in ("target","bytes","sha256","mode","branch")},"uid":0,"gid":0} for r in rows]
 rollback_key=random_bytes(32);deny(type(rollback_key) is not bytes or len(rollback_key)!=32,"KERNEL_ROLLBACK_KEY_DENIED")
 receipt_body={"schema":"SereinPublicKernelFirstInstallReceipt/v1","plan_sha256":sha(canonical(plan)),"boot_id":plan["current_boot_id"],"branch_order":list(ORDER),"prestate":plan["target_prestate"],"replacements":replacements,"rollback_selector":plan["rollback_selector"],"rollback_auth_sha256":sha(rollback_key)}
 receipt={**receipt_body,"receipt_signature":base64.urlsafe_b64encode(hmac.new(rollback_key,canonical(receipt_body),hashlib.sha256).digest()).decode().rstrip("=")};receipt["receipt_digest"]=sha(canonical(receipt));receipt_digest=receipt["receipt_digest"]
 boundary();preserved_unchanged()
 rollback.mkdir(mode=0o700);receipt_bytes=canonical(receipt);plan_bytes=canonical(plan);journal_bytes=canonical({"schema":"SereinKernelRollbackJournal/v1","receipt_digest":receipt_digest,"state":"INSTALLING","completed":[],"ownership":[]})
 try:
  atomic(rollback/ROLLBACK_AUTH,rollback_key,"0600",boundary,create_only=True);atomic(rollback/"receipt.json",receipt_bytes,"0600",boundary,create_only=True);atomic(rollback/"plan.json",plan_bytes,"0600",boundary,create_only=True);journal_write(rollback,receipt_digest,"INSTALLING",[],boundary)
  for name,data in preimages.items():
   preserved_unchanged()
   atomic(rollback/('preimage-'+sha(name.encode())),data,'0600',boundary,create_only=True)
   boundary();preserved_unchanged()
   held=rollback/('retained-inode-'+sha(name.encode()))
   os.link(target(root,name),held,follow_symlinks=False);sync_parent(held)
   preserved_unchanged()
  if predecessor_witness is not None:
   preserved_unchanged()
   atomic(rollback/'predecessor-witness.json',predecessor_witness[1],'0600',boundary,create_only=True)
 except Exception:
  for name,previous in replacing.items():
   held=rollback/('retained-inode-'+sha(name.encode()))
   if os.path.lexists(held):
    info=held.lstat();deny((info.st_dev,info.st_ino)!=(previous['device'],previous['inode']),
                           'KERNEL_RETAINED_INODE_CHANGED');exact_row(held,previous)
    deny(target_prestate(root,previous,expected_nlink=2)!={**previous,'state':'PRESENT_PRESERVED','nlink':2},
         'KERNEL_RECOVERED_PRESTATE_CHANGED');held.unlink();sync_parent(held)
  if predecessor_witness is not None:
   path=rollback/'predecessor-witness.json'
   if os.path.lexists(path):exact(path,predecessor_witness[1],'0600');path.unlink();sync_parent(path)
  for name,data in preimages.items():
   path=rollback/('preimage-'+sha(name.encode()))
   if os.path.lexists(path):exact(path,data,'0600');path.unlink();sync_parent(path)
  for path,data in ((rollback/ROLLBACK_JOURNAL,journal_bytes),(rollback/"plan.json",plan_bytes),(rollback/"receipt.json",receipt_bytes),(rollback/ROLLBACK_AUTH,rollback_key)):
   if os.path.lexists(path):exact(path,data,"0600");path.unlink();sync_parent(path)
  rollback.rmdir();sync_parent(rollback)
  raise
 def install_new(name,data,mode,uid=0,gid=0):
  preserved_unchanged()
  def intent(identity):
   ownership.append({'target':name,**identity})
   # Write-ahead inode identity distinguishes our pending publication from
   # any byte-identical competing file after interruption or exclusive denial.
   journal_write(rollback,receipt_digest,'INSTALLING',written,boundary,ownership)
  def placement_boundary():
   boundary();preserved_unchanged()
  atomic(target(root,name),data,mode,placement_boundary,uid,gid,create_only=name not in replacing,on_intent=intent)
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
 prestate=receipt.get('prestate');deny(not isinstance(prestate,list) or any(not isinstance(row,dict) for row in prestate) or [row.get('target') for row in prestate]!=list(rows) or any(row.get('state') not in {'ABSENT','PRESENT_PRESERVED','PRESENT_REPLACE'} for row in prestate),"KERNEL_RECEIPT_PRESTATE_DENIED")
 replacing={r['target']:r for r in prestate if r['state']=='PRESENT_REPLACE'}
 if replacing or any(row['target']==RUNTIME_ACCESS_TARGET for row in receipt['replacements']):
  # Authenticate the signed preimage set, not merely an editable restore label.
  plan_path=rollback_dir/'plan.json';plan_info=plan_path.lstat()
  deny(plan_path.is_symlink() or not stat.S_ISREG(plan_info.st_mode)
       or stat.S_IMODE(plan_info.st_mode)!=0o600 or (plan_info.st_uid,plan_info.st_gid,plan_info.st_nlink)!=(0,0,1),
       'KERNEL_COMPENSATION_PLAN_DENIED')
  plan_raw=plan_path.read_bytes();plan=json.loads(plan_raw)
  deny(canonical(plan)!=plan_raw or sha(plan_raw)!=receipt['plan_sha256']
       or plan.get('target_prestate')!=prestate
       or (replacing and not isinstance(plan.get('recovered_predecessor'),dict)),
       'KERNEL_COMPENSATION_PLAN_DENIED')
  anchor=target(root,AUTHORITY).read_bytes()
  deny(sha(anchor)!=plan.get('authority_sha256'),'KERNEL_COMPENSATION_ANCHOR_DENIED')
  try:load_pem_public_key(anchor).verify(base64.urlsafe_b64decode(plan['signature']+'='*(-len(plan['signature'])%4)),canonical({k:v for k,v in plan.items() if k!='signature'}))
  except Exception as exc:raise Denied('KERNEL_COMPENSATION_PLAN_DENIED') from exc
  if 'runtime_access_prestate' in plan:
   # Durable signed prestate also covers interruption after ACL application.
   # The caller's quiescence/boot guard must pass before removing any files.
   restore_runtime_access(root,plan,boundary)
 for before in prestate:
  if before['state']=='ABSENT':deny(set(before)!={'target','state'},"KERNEL_RECEIPT_PRESTATE_DENIED")
  else:
   deny(set(before)!={'target','state','bytes','sha256','mode','uid','gid','device','inode','nlink'} or before['target'] in GENERATED,"KERNEL_RECEIPT_PRESTATE_DENIED")
   row=rows[before['target']]
   deny((before['state']=='PRESENT_PRESERVED' and any(before[field]!=row[field] for field in ('bytes','sha256','mode','uid','gid')))
        or (before['uid'],before['gid'],before['nlink'])!=(0,0,1) or type(before['device']) is not int or type(before['inode']) is not int or before['device']<0 or before['inode']<=0,"KERNEL_RECEIPT_PRESTATE_DENIED")
 install_order=[row['target'] for row in prestate if row['state']!='PRESENT_PRESERVED']
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
 def write_progress():journal_write(rollback_dir,digest,'ROLLING_BACK',completed,boundary,ownership)
 write_progress()
 for item in reverse:
  row=rows[item['target']];path=target(root,item['target'])
  if item['target'] in replacing:
   prior=replacing[item['target']];backup=rollback_dir/('preimage-'+sha(item['target'].encode()))
   exact_row(backup,{**prior,'mode':'0600'})
   held=rollback_dir/('retained-inode-'+sha(item['target'].encode()))
   def verify_held(links):
    exact_row(held,prior);info=held.lstat()
    deny((info.st_dev,info.st_ino,info.st_nlink)!=(prior['device'],prior['inode'],links),
         'KERNEL_COMPENSATION_RETAINED_INODE_CHANGED')
   deny(not os.path.lexists(path),'KERNEL_COMPENSATION_TARGET_MISSING')
   current=path.lstat();current_id=(current.st_dev,current.st_ino)
   if current_id==(prior['device'],prior['inode']):
    if os.path.lexists(held):
     verify_held(2);boundary();verify_held(2);held.unlink();sync_parent(held)
    deny(target_prestate(root,prior)!={**prior,'state':'PRESENT_PRESERVED'},'KERNEL_COMPENSATION_PRESTATE_CHANGED')
   else:
    deny(current_id!=(item['device'],item['inode']),'KERNEL_COMPENSATION_FOREIGN_TARGET')
    exact_row(path,row)
    verify_held(1);boundary();exact_row(backup,{**prior,'mode':'0600'});verify_held(1)
    info=path.lstat();deny((info.st_dev,info.st_ino)!=(item['device'],item['inode']),
                          'KERNEL_COMPENSATION_OWNERSHIP_CHANGED');exact_row(path,row)
    # Retain the original inode, not only equal bytes: the selected historical
    # packet remains usable for a new complete attempt after compensation.
    os.replace(held,path);sync_parent(path);sync_parent(held)
    deny(target_prestate(root,prior)!={**prior,'state':'PRESENT_PRESERVED'},'KERNEL_COMPENSATION_PRESTATE_CHANGED')
   temporary=path.parent/item['temporary']
   if os.path.lexists(temporary):
    info=temporary.lstat();deny((info.st_dev,info.st_ino)!=(item['device'],item['inode']),
                               'KERNEL_COMPENSATION_FOREIGN_TEMP')
    exact_row(temporary,row);temporary.unlink();sync_parent(temporary)
   if item['target'] not in completed:completed.append(item['target']);write_progress()
   continue
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
  if item['target'] not in completed:completed.append(item['target']);write_progress()
 for item in ownership:
  path=target(root,item['target'])
  for candidate in (path,path.parent/item['temporary']):
   if os.path.lexists(candidate):
    info=candidate.lstat();deny((info.st_dev,info.st_ino)==(item['device'],item['inode']),"KERNEL_ROLLBACK_RESIDUE_DENIED")
 for name,prior in replacing.items():
  held=rollback_dir/('retained-inode-'+sha(name.encode()))
  if os.path.lexists(held):
   info=held.lstat();deny((info.st_dev,info.st_ino,info.st_nlink)!=(prior['device'],prior['inode'],2),
                          'KERNEL_COMPENSATION_RETAINED_INODE_CHANGED');exact_row(held,prior)
   deny(target_prestate(root,prior,expected_nlink=2)!={**prior,'state':'PRESENT_PRESERVED','nlink':2},
        'KERNEL_COMPENSATION_PRESTATE_CHANGED');boundary();held.unlink();sync_parent(held)
  observed=target_prestate(root,prior)
  deny(observed!={**prior,'state':'PRESENT_PRESERVED'},'KERNEL_COMPENSATION_UNPROVEN')
 journal_write(rollback_dir,digest,'ROLLBACK_COMPLETE',completed,boundary,ownership)
 return {'status':'ROLLBACK_COMPLETE','branch_order':receipt['branch_order'],'foreign_targets_preserved':sorted(set(foreign))}
def rollback(root,receipt_path,boundary=lambda:None):return rollback_transaction(root,receipt_path,boundary)
