#!/usr/bin/env python3
"""Outpost-owned Kernel placement and ordered lifecycle constituents.

ADAPT: sfos-public 0dca6bd7a22b83b04ddf353df901d2c7ea15c294,
blob addf2e86cc9dca49ef3a268e523a801cbf3f7d68. This capability is inert
until its exact signed source, current Host gate and root-owned bounded
request exist. It does not install a privileged unit or grant the running
unprivileged coordinator new privileges. Future payload placement never
admits Authority, Operations, Interface or Stage 1.
The command entry selects complete construction, including when preserving an
existing runtime. Source-pinned model selectors are derived from the exact plan;
optional post-install compute input is not authentication or an install gate.
"""
from __future__ import annotations
import base64,hashlib,hmac,json,os,pwd,grp,re,stat,tempfile
from contextlib import contextmanager,ExitStack
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key
from .transaction import strict_json,TransactionError
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
AUTHORITY_UNITS=('serein-kernel-authority-api.service','serein-kernel-authority-api.socket')
RESIDENCY_UNITS=('serein-ollama-warmup.timer','serein-ollama-warmup.service')
# Exact historical b8760b4 payload; only these omitted public artifacts may be
# incorporated into an already-installed Kernel. No arbitrary file adoption.
RESIDENCY_PREDECESSORS={
 '/usr/libexec/serein/serein-ollama-warmup':(1634,'4a8971d72739c161d2f082a67814ad3646065a3a77011fd978311ffdf98cc89e','0755'),
 '/etc/systemd/system/serein-ollama-warmup.service':(401,'888747ad8cb0d0979f7e5d37c1f293bd4a84bcc16e6b4c94a09af409b708a1c9','0644'),
 '/etc/systemd/system/serein-ollama-warmup.timer':(271,'2ae487882607a7d0468ec074d144f0d1fd805dbca1002ccea0c80be57a28ad6c','0644')}
OTHER_KERNEL_UNITS=('serein-observation-audit.service','serein-observation-audit.socket',
                    'serein-conversation-runtime.service','serein-conversation-runtime.socket',
                    'serein-kernel-client-gateway@haos.service','serein-kernel-client-gateway-haos.socket',
                    'serein-kernel-operations-heartbeat.service',
                    'serein-kernel-operations-api.service','serein-kernel-operations-api.socket')+RESIDENCY_UNITS
OPERATIONS_SERVICES=('serein-kernel-operations-heartbeat.service','serein-observation-audit.service')
OPERATIONS_ENDPOINT=('serein-kernel-operations-api.service','serein-kernel-operations-api.socket')
SUCCESSOR_FAILURE_UNITS=(AUTHORITY_UNITS[0],)+OPERATIONS_SERVICES+OPERATIONS_ENDPOINT+RESIDENCY_UNITS
OPERATIONS_UNITS=('serein-kernel-operations-api.socket','serein-kernel-operations-api.service',
                  'serein-kernel-operations-heartbeat.service',
                  'serein-observation-audit.socket','serein-observation-audit.service')
INTERFACE_UNITS=('serein-kernel-client-gateway-haos.socket','serein-kernel-client-gateway@haos.service',
                 'serein-conversation-runtime.socket','serein-conversation-runtime.service')
HEX40=re.compile(r"[0-9a-f]{40}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES=16*1024*1024
# A Host observation is already rejected as stale after 30 seconds by the
# installed observer contracts below.  Give an in-flight, same-boot collector
# that full existing freshness budget; this is an absolute deadline and never
# turns a pending attempt into evidence.
HOST_SETTLE_DEADLINE_SECONDS=30.0

class RunnerDenied(RuntimeError):pass
class WitnessPublicationUncertain(RunnerDenied):pass
class RuntimeCompensationUncertain(RunnerDenied):pass
def deny(value,message):
 if value:raise RunnerDenied(message)
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def decode(value):return base64.urlsafe_b64decode(value+"="*(-len(value)%4))
def regular(path,*,fact=False,expected_custody=None,include_identity=False):
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
   if expected_custody is not None:
    uid,gid,expected_mode=expected_custody;owner={"uid":uid,"gid":gid};modes={expected_mode}
   deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE_BYTES or before.st_uid!=owner["uid"] or mode not in modes,"KERNEL_RUNNER_CUSTODY_DENIED")
   if path==HOST_STATE or expected_custody is not None:deny(before.st_gid!=owner["gid"],"KERNEL_RUNNER_CUSTODY_DENIED")
   data=stream.read(MAX_FILE_BYTES+1);after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
   fingerprint=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
   deny(len(data)!=before.st_size or fingerprint(before)!=fingerprint(after) or fingerprint(after)!=fingerprint(named),"KERNEL_RUNNER_FILE_CHANGED")
  for fd,parent_fd,name in descriptors[1:]:
   opened=os.fstat(fd);named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
   deny((opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_gid)!=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid),"KERNEL_RUNNER_FILE_CHANGED")
  result=(sha(data),before.st_uid,before.st_gid,mode,len(data))
  if include_identity:result+=(before.st_dev,before.st_ino,before.st_nlink)
  return result if fact else data
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
def witness_directory(path,publication=None):
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
  unchanged();yield fd,unchanged
  try:unchanged()
  except BaseException as exc:
   if publication is not None and publication.get('completed'):
    raise WitnessPublicationUncertain('KERNEL_WITNESS_PUBLICATION_UNCERTAIN') from exc
   raise
 except BaseException as exc:
  # This owner encloses the transaction lock as well as the publisher. A
  # failed lock-release fsync must not erase post-publication disposition.
  if publication is not None and publication.get('completed'):
   if isinstance(exc,WitnessPublicationUncertain):raise
   raise WitnessPublicationUncertain('KERNEL_WITNESS_PUBLICATION_UNCERTAIN') from exc
  if isinstance(exc,OSError):raise RunnerDenied("KERNEL_WITNESS_PARENT_DENIED") from exc
  raise
 finally:
  for fd,_,_ in reversed(handles):os.close(fd)

def atomic(path,value,directory_fd,check_parent,*,predecessor=None):
 """Publish once via link-at: a concurrent witness is never overwritten."""
 expected=canonical(value)
 name=".kernel-witness-"+os.urandom(16).hex();fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory_fd)
 linked=False;renamed=False
 try:
  try:
   with os.fdopen(fd,"wb") as stream:
    fd=-1;stream.write(expected);stream.flush();os.fsync(stream.fileno())
    created=os.fstat(stream.fileno())
   check_parent()
   if predecessor is None:
    try:os.link(name,path.name,src_dir_fd=directory_fd,dst_dir_fd=directory_fd,follow_symlinks=False)
    except FileExistsError:raise RunnerDenied("KERNEL_WITNESS_COLLISION_DENIED") from None
   else:
    raw,fact=predecessor
    deny(regular(path,expected_custody=(0,0,0o600))!=raw
         or regular(path,fact=True,expected_custody=(0,0,0o600),include_identity=True)!=fact,
         'KERNEL_WITNESS_PREDECESSOR_CHANGED')
    os.replace(name,path.name,src_dir_fd=directory_fd,dst_dir_fd=directory_fd);renamed=True
   linked=True
   os.fsync(directory_fd)
  finally:
   if fd!=-1:os.close(fd)
   if not renamed:os.unlink(name,dir_fd=directory_fd)
   os.fsync(directory_fd)
  # Link/fsync success alone is not installed witness readback. Bind the named
  # result to our exact inode and bytes through the already-owned directory.
  # A post-link discrepancy is uncertain publication, never permission to
  # compensate files underneath a potentially visible witness.
  check_parent()
  read_fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
  with os.fdopen(read_fd,'rb') as stream:
   before=os.fstat(stream.fileno())
   identity=lambda row:(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_size)
   deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
        or identity(before)!=identity(created),'KERNEL_WITNESS_READBACK_CHANGED')
   observed=stream.read(len(expected)+1)
   after=os.fstat(stream.fileno())
   named=os.stat(path.name,dir_fd=directory_fd,follow_symlinks=False)
   fingerprint=lambda row:(identity(row),row.st_nlink,row.st_mtime_ns,row.st_ctime_ns)
   deny(observed!=expected or fingerprint(before)!=fingerprint(after)
        or fingerprint(after)!=fingerprint(named),'KERNEL_WITNESS_READBACK_CHANGED')
  check_parent()
 except Exception as exc:
  # The final name can already be visible even when durability/cleanup failed.
  # Preserve installed bytes for reconciliation; never compensate underneath
  # a published witness or silently treat this outcome as successful admission.
  if linked:raise WitnessPublicationUncertain('KERNEL_WITNESS_PUBLICATION_UNCERTAIN') from exc
  raise
def payload_rows(source,manifest,layout):
 roots=layout.get("payload_roots");deny(not isinstance(roots,dict) or not roots,"KERNEL_LAYOUT_DENIED");rows=[]
 payload=manifest.get("payload");branches=layout.get("payload_branches")
 deny(not isinstance(payload,list) or not payload or any(not isinstance(item,list) or len(item)!=4 or not isinstance(item[0],str) for item in payload),"KERNEL_MANIFEST_DENIED")
 names=[item[0] for item in payload]
 # Use the signed package's explicit phase map, exactly as refresh_manifest.
 # Filenames are not branch ownership: supervision, runtime and audit files
 # may lack a branch name even though their installation phase is explicit.
 deny(not isinstance(branches,dict) or len(set(names))!=len(names) or set(branches)!=set(names)
      or any(not isinstance(branch,str) or branch not in ORDER for branch in branches.values()),"KERNEL_BRANCH_MAP_DENIED")
 for item in payload:
  deny(not isinstance(item,list) or len(item)!=4,"KERNEL_MANIFEST_DENIED");relative,size,digest,mode=item
  deny(any(not isinstance(p,str) or not isinstance(destination,str) for p,destination in roots.items()),"KERNEL_LAYOUT_DENIED")
  prefixes=[p for p in roots if relative==p or relative.startswith(p+"/")];deny(len(prefixes)!=1,"KERNEL_LAYOUT_DENIED");prefix=prefixes[0]
  suffix=relative[len(prefix):].lstrip("/");target=roots[prefix].rstrip("/")+"/"+suffix
  branch=branches[relative]
  rows.append({"branch":branch,"source":relative,"target":target,"bytes":size,"sha256":digest,"mode":mode})
 deny({row["branch"] for row in rows}!=set(ORDER),"KERNEL_COMPLETE_BRANCH_SET_REQUIRED")
 rows.sort(key=lambda row:(ORDER.index(row["branch"]),row["target"]));return rows

def retirement_payload_selection(plan,manifest,layout):
 """Select complete public program material, never private state or authority.

 This pure check is one prerequisite of whole-generation retirement, not an
 executable retirement command. The caller must separately authenticate the
 historical plan and current successor, prove exclusive ownership, and bind
 fresh file/service custody. No historical request is admitted for replay.
 """
 deny(not isinstance(plan,dict) or not isinstance(manifest,dict)
      or not isinstance(layout,dict),'KERNEL_RETIREMENT_INPUT_DENIED')
 rows=payload_rows(None,manifest,layout)
 deny(plan.get('schema')!='SereinPublicKernelFirstInstallPlan/v1'
      or plan.get('target_vm_id')!='VM4010'
      or not isinstance(manifest.get('self_digest'),str)
      or not re.fullmatch(r'sha256:[0-9a-f]{64}',manifest['self_digest'])
      or plan.get('release_digest')!=manifest['self_digest']
      or plan.get('payload')!=rows,'KERNEL_RETIREMENT_INVENTORY_DENIED')
 prefixes=('/usr/lib/serein/kernel/',
           '/usr/lib/python3/dist-packages/serein_stage1/',
           '/usr/libexec/serein/serein-kernel-',
           '/etc/systemd/system/serein-kernel-')
 exact={ '/usr/libexec/serein/'+name for name in
         ('serein-observation-audit','serein-conversation-runtime','serein-ollama-warmup') }
 exact.update('/etc/systemd/system/'+name+suffix for name,suffixes in
      (('serein-observation-audit',('.service','.socket')),
       ('serein-conversation-runtime',('.service','.socket')),
       ('serein-ollama-warmup',('.service','.timer'))) for suffix in suffixes)
 seen=set()
 for row in rows:
  target=row['target']
  deny(not target.startswith('/') or str(Path(target))!=target
       or '..' in Path(target).parts or target in seen
       or target in IMMUTABLE_POLICY
       or not (target in exact or any(target.startswith(p) and target!=p for p in prefixes)),
       'KERNEL_RETIREMENT_TARGET_DENIED')
  deny(type(row['bytes']) is not int or row['bytes']<0
       or not isinstance(row['sha256'],str) or not HEX64.fullmatch(row['sha256'])
       or row['mode'] not in ('0644','0755'),'KERNEL_RETIREMENT_ROW_DENIED')
  seen.add(target)
 # Return an isolated copy: later caller mutation cannot change source truth.
 return strict_json(canonical({'payload':rows}))['payload']

def retirement_preservation_paths(plan):
 """Closed preservation set from the existing Kernel and Outpost contracts."""
 selector=plan.get('rollback_selector') if isinstance(plan,dict) else None
 deny(not isinstance(selector,str) or not re.fullmatch(
      r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',selector),
      'KERNEL_RETIREMENT_HISTORY_DENIED')
 files={'/var/lib/serein/kernel/authority/'+name for name in (
  'replay.key','replay-descriptor.json','domain-identity.pem','domain-identity.json',
  'installed-policy-evidence.json')}
 files|=set(IMMUTABLE_POLICY)|{'/etc/serein/kernel/replay-peer.env','/etc/machine-id','/etc/hostname'}
 return files,{'/var/lib/serein/kernel/replay',str(STATE),'/var/lib/ollama/models',selector}


def collect_retirement_preserved_state(root,plan,*,current_boot_id):
 """Read complete protected inventories without copying contents or changing state.

 Native no-follow descriptor traversal and before/after identity checks reject
 changed files, changed directory membership, links and special objects. This
 is an observation, not a snapshot/quiescence or installation authorization.
 Streaming hashes have no installer-kill deadline and retain no private bytes.
 """
 files,directories=retirement_preservation_paths(plan)
 deny(not isinstance(current_boot_id,str) or not re.fullmatch(
      r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',current_boot_id),
      'KERNEL_RETIREMENT_BOOT_DENIED')
 flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
 fingerprint=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
                       s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 def common(s):
  return dict(uid=s.st_uid,gid=s.st_gid,mode=f'{stat.S_IMODE(s.st_mode):04o}',
              device=s.st_dev,inode=s.st_ino)
 def read_file(fd,*,virtual=False):
  before=os.fstat(fd)
  deny(not stat.S_ISREG(before.st_mode) or before.st_nlink!=1,
       'KERNEL_RETIREMENT_COLLECTION_KIND_DENIED')
  digest=hashlib.sha256();size=0
  while True:
   chunk=os.read(fd,1024*1024)
   if not chunk:break
   digest.update(chunk);size+=len(chunk)
  deny((not virtual and size!=before.st_size) or fingerprint(before)!=fingerprint(os.fstat(fd)),
       'KERNEL_RETIREMENT_COLLECTION_CHANGED')
  return dict(state='FILE',sha256=digest.hexdigest(),bytes=size,nlink=before.st_nlink,**common(before))
 def read_directory(fd):
  before=os.fstat(fd);names=sorted(os.listdir(fd));entries=[]
  deny(not stat.S_ISDIR(before.st_mode),'KERNEL_RETIREMENT_COLLECTION_KIND_DENIED')
  for name in names:
   named=os.stat(name,dir_fd=fd,follow_symlinks=False)
   deny(not (stat.S_ISREG(named.st_mode) or stat.S_ISDIR(named.st_mode)),
        'KERNEL_RETIREMENT_COLLECTION_KIND_DENIED')
   child=os.open(name,flags|(os.O_DIRECTORY if stat.S_ISDIR(named.st_mode) else 0),dir_fd=fd)
   try:
    deny(fingerprint(named)!=fingerprint(os.fstat(child)),
         'KERNEL_RETIREMENT_COLLECTION_CHANGED')
    fact=read_directory(child) if stat.S_ISDIR(named.st_mode) else read_file(child)
    deny(fingerprint(named)!=fingerprint(os.stat(name,dir_fd=fd,follow_symlinks=False)),
         'KERNEL_RETIREMENT_COLLECTION_CHANGED')
    entries.append({'name':name,'fact':fact})
   finally:os.close(child)
  deny(names!=sorted(os.listdir(fd)) or fingerprint(before)!=fingerprint(os.fstat(fd)),
       'KERNEL_RETIREMENT_COLLECTION_CHANGED')
  return dict(state='DIRECTORY',inventory_sha256=sha(canonical({'entries':entries})),
              entry_count=sum(1+(row['fact'].get('entry_count',0)) for row in entries),**common(before))
 rootfd=os.open(root,flags|os.O_DIRECTORY)
 def collect(path,directory=False,optional=False):
  handles=[];parent=rootfd;chain=[]
  def verify_chain():
   for ancestor,name,opened,initial in chain:
    deny(initial!=fingerprint(os.fstat(opened)) or initial!=fingerprint(os.stat(name,dir_fd=ancestor,follow_symlinks=False)),
         'KERNEL_RETIREMENT_COLLECTION_CHANGED')
  try:
   parts=Path(path).parts[1:]
   for part in parts[:-1]:
    fd=os.open(part,flags|os.O_DIRECTORY,dir_fd=parent)
    handles.append(fd);chain.append((parent,part,fd,fingerprint(os.fstat(fd))));parent=fd
   try:fd=os.open(parts[-1],flags|(os.O_DIRECTORY if directory else 0),dir_fd=parent)
   except FileNotFoundError:
    if optional:
     # Absence is evidence about the named parent, not an orphaned descriptor.
     # Apply the same ancestor identity check used for present objects.
     verify_chain()
     try:os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
     except FileNotFoundError:pass
     else:raise RunnerDenied('KERNEL_RETIREMENT_COLLECTION_CHANGED')
     verify_chain()
     return {'state':'ABSENT'}
    raise
   handles.append(fd);before=os.fstat(fd)
   result=read_directory(fd) if directory else read_file(fd,virtual=path=='/proc/sys/kernel/random/boot_id')
   deny(fingerprint(before)!=fingerprint(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)),
        'KERNEL_RETIREMENT_COLLECTION_CHANGED')
   verify_chain()
   return result
  finally:
   for fd in reversed(handles):os.close(fd)
 try:
  before=collect('/proc/sys/kernel/random/boot_id')
  deny(before['sha256']!=sha((current_boot_id+'\n').encode('ascii')),
       'KERNEL_RETIREMENT_COLLECTION_BOOT_CHANGED')
  result={path:collect(path) for path in sorted(files)}
  result.update({path:collect(path,directory=True,optional=path=='/var/lib/serein/kernel/replay')
                 for path in sorted(directories)})
  # Large model/history reads must not hide a changed earlier identity/key.
  # This is still observation, not quiescence of the mutable directory trees.
  deny(any(result[path]!=collect(path) for path in sorted(files)),
       'KERNEL_RETIREMENT_COLLECTION_CHANGED')
  deny(before!=collect('/proc/sys/kernel/random/boot_id'),'KERNEL_RETIREMENT_COLLECTION_BOOT_CHANGED')
  return result
 except OSError as exc:raise RunnerDenied('KERNEL_RETIREMENT_COLLECTION_READ_DENIED') from exc
 finally:os.close(rootfd)


def read_retirement_dependencies():
 """Collect the reachable manager graph through the existing read-only road.

 No start/stop/reload/enable operation is available here. Missing or malformed
 manager output is UNKNOWN, never an empty graph or independence proof.
 """
 import shlex,subprocess
 properties=('Requires','Wants','BindsTo','PartOf','RequiredBy','WantedBy','Triggers','TriggeredBy',
             'BoundBy','ConsistsOf','PropagatesStopTo')
 forward=('Requires','Wants','BindsTo','PartOf','Triggers')
 pending=set(AUTHORITY_UNITS+OTHER_KERNEL_UNITS)|{
  'serein-outpost.target','serein-outpost.service','serein-outpost-presentation.service',
  'serein-https-gateway-adapter.service'}
 result={}
 while pending:
  name=min(pending);pending.remove(name)
  if name in result:continue
  try:
   reply=subprocess.run(['/usr/bin/systemctl','show','--all','--no-pager',
    '--property='+','.join(('Id','LoadState')+properties),'--',name],capture_output=True,text=True,
    timeout=15,check=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
    stdin=subprocess.DEVNULL,close_fds=True)
  except (OSError,subprocess.SubprocessError) as exc:
   raise RunnerDenied('KERNEL_RETIREMENT_DEPENDENCY_READ_DENIED') from exc
  deny(len(reply.stdout)>16384,'KERNEL_RETIREMENT_DEPENDENCY_READ_DENIED')
  fields={}
  for line in reply.stdout.splitlines():
   key,separator,value=line.partition('=')
   deny(not separator or key in fields,'KERNEL_RETIREMENT_DEPENDENCY_READ_DENIED')
   fields[key]=value
  missing_kernel=(name in AUTHORITY_UNITS+OTHER_KERNEL_UNITS and fields.get('LoadState')=='not-found')
  deny(set(fields)!=set(properties)|{'Id','LoadState'} or fields['Id']!=name
       or (fields['LoadState']!='loaded' and not missing_kernel)
       or (missing_kernel and any(fields[key] for key in properties)),
       'KERNEL_RETIREMENT_DEPENDENCY_READ_DENIED')
  row={}
  for key in properties:
   try:values=shlex.split(fields[key],posix=True)
   except ValueError as exc:raise RunnerDenied('KERNEL_RETIREMENT_DEPENDENCY_READ_DENIED') from exc
   deny(any(not value or any(c.isspace() or ord(c)<32 for c in value) or '/' in value
            for value in values) or len(values)!=len(set(values)),
        'KERNEL_RETIREMENT_DEPENDENCY_READ_DENIED')
   row[key]=sorted(values)
  result[name]=row
  pending.update(child for key in forward for child in row[key] if child not in result)
 return result


def capture_retirement_packet(root,plan,manifest,layout,*,current_boot_id,
                              read_dependencies,read_runtime_access):
 """Join native file/link observations with the owner's bounded read adapters.

 This does not authenticate a successor or acquire transaction ownership.
 The returned packet is capture-only and must be signed/bound and freshly
 rechecked by the complete installer before any retirement effect.
 """
 root=Path(root)
 rows=retirement_payload_selection(plan,manifest,layout)
 def public_facts():
  result=[]
  for row in rows:
   # A fresh generation may encounter a prior retirement interrupted after
   # some public program removals. Bind absence explicitly, through opened
   # ancestors; never infer it from a failed read or missing private state.
   path=root/row['target'].lstrip('/');handles=[]
   identity=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode)
   try:
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    handles.append((parent,None,None,identity(os.fstat(parent))))
    for name in path.parts[1:-1]:
     child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
     handles.append((child,parent,name,identity(os.fstat(child))));parent=child
    try:opened=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError:opened=None
    if opened is None:
     fact=None
     try:os.stat(path.name,dir_fd=parent,follow_symlinks=False)
     except FileNotFoundError:pass
     else:raise RunnerDenied('KERNEL_RETIREMENT_INSTALLED_PAYLOAD_CHANGED')
    else:
     fact=regular(path,fact=True,include_identity=True,expected_custody=(0,0,int(row['mode'],8)))
     deny((fact[0],fact[4])!=(row['sha256'],row['bytes'])
          or fact[5:7]!=(opened.st_dev,opened.st_ino),
          'KERNEL_RETIREMENT_INSTALLED_PAYLOAD_CHANGED')
    for fd,parent_fd,name,before in handles[1:]:
     deny(identity(os.fstat(fd))!=before
          or identity(os.stat(name,dir_fd=parent_fd,follow_symlinks=False))!=before,
          'KERNEL_RETIREMENT_CAPTURE_CHANGED')
   except OSError as exc:raise RunnerDenied('KERNEL_RETIREMENT_PUBLIC_READ_DENIED') from exc
   finally:
    for fd,_,_,_ in reversed(handles):os.close(fd)
   result.append(fact)
  return result
 before=public_facts()
 links=read_kernel_enablement_prestate(root)
 dependencies=read_dependencies()
 access=read_runtime_access()
 protected=collect_retirement_preserved_state(root,plan,current_boot_id=current_boot_id)
 # Do not let a file replacement, changed link or adapter result during a
 # long model-inventory read masquerade as one coherent prestate.
 deny(before!=public_facts() or links!=read_kernel_enablement_prestate(root)
      or dependencies!=read_dependencies() or access!=read_runtime_access(),
      'KERNEL_RETIREMENT_CAPTURE_CHANGED')
 packet={'boot_id':current_boot_id,'historical_plan_sha256':sha(canonical(plan)),
         'public_payload':rows,'public_state':{row['target']:'ABSENT' if fact is None else 'PRESENT'
                                             for row,fact in zip(rows,before)},
         'preserved':protected,'enablement_links':links,
         'dependencies':dependencies,'runtime_access':access}
 retirement_preservation_binding(plan,manifest,layout,packet,packet,current_boot_id=current_boot_id)
 return strict_json(canonical(packet))


def retirement_preservation_binding(plan,manifest,layout,expected,observed,*,current_boot_id):
 """Pure retirement prestate comparison; never an execution authorization.

 Expected facts must come from the separately authenticated successor packet;
 observed facts must be freshly collected by its owner. Equality here neither
 authenticates those inputs nor proves quiescence/exclusive ownership. This
 function cannot retire files, stop units, replay a request or alter a lock.
 Missing protected-state coverage fails closed, including absent-state facts.
 """
 rows=retirement_payload_selection(plan,manifest,layout)
 fields={'boot_id','historical_plan_sha256','public_payload','public_state','preserved',
         'enablement_links','dependencies','runtime_access'}
 deny(not isinstance(current_boot_id,str) or not re.fullmatch(
      r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',current_boot_id),
      'KERNEL_RETIREMENT_BOOT_DENIED')
 # These are preservation roots, never deletion roots. Directory facts bind
 # a complete collector inventory digest; this comparator cannot certify the
 # collector or turn a directory's stat into evidence for all its contents.
 files,directories=retirement_preservation_paths(plan)
 units=set(AUTHORITY_UNITS+OTHER_KERNEL_UNITS)
 observers={'serein-outpost.target','serein-outpost.service','serein-outpost-presentation.service',
            'serein-https-gateway-adapter.service'}
 for value in (expected,observed):
  deny(not isinstance(value,dict) or set(value)!=fields
       or value['boot_id']!=current_boot_id
       or value['historical_plan_sha256']!=sha(canonical(plan))
       or value['public_payload']!=rows,'KERNEL_RETIREMENT_PACKET_DENIED')
  deny(not isinstance(value['public_state'],dict)
       or set(value['public_state'])!={row['target'] for row in rows}
       or any(state not in ('PRESENT','ABSENT') for state in value['public_state'].values()),
       'KERNEL_RETIREMENT_PUBLIC_STATE_DENIED')
  facts=value['preserved']
  deny(not isinstance(facts,dict) or set(facts)!=files|directories,
       'KERNEL_RETIREMENT_PRESERVATION_COVERAGE_DENIED')
  for path,fact in facts.items():
   deny(not isinstance(fact,dict),'KERNEL_RETIREMENT_PRESERVATION_FACT_DENIED')
   if fact=={'state':'ABSENT'}:
    deny(path!='/var/lib/serein/kernel/replay','KERNEL_RETIREMENT_PRESERVATION_FACT_DENIED')
    continue
   keys={'state','sha256','bytes','uid','gid','mode','device','inode','nlink'}
   if path in directories:keys={'state','inventory_sha256','entry_count','uid','gid','mode','device','inode'}
   digest='inventory_sha256' if path in directories else 'sha256'
   deny(set(fact)!=keys or fact['state']!=('DIRECTORY' if path in directories else 'FILE')
        or not isinstance(fact[digest],str) or not HEX64.fullmatch(fact[digest])
        or not isinstance(fact['mode'],str) or not re.fullmatch(r'0[0-7]{3}',fact['mode'])
        or any(type(fact[k]) is not int or fact[k]<0 for k in keys-{'state',digest,'mode'})
        or fact['inode']==0 or (path in files and fact['nlink']!=1),
        'KERNEL_RETIREMENT_PRESERVATION_FACT_DENIED')
  links=value['enablement_links']
  deny(not isinstance(links,list),'KERNEL_RETIREMENT_LINK_DENIED');seen=set()
  for link in links:
   deny(not isinstance(link,dict) or set(link)!={'unit','path','target','fact'},
        'KERNEL_RETIREMENT_LINK_DENIED')
   name=link['unit'];path=link['path'];fact=link['fact']
   deny(name not in units or not isinstance(path,str) or path in seen
        or not re.fullmatch(r'/(?:etc|run)/systemd/system/[^/]+\.(?:wants|requires)/'+re.escape(name),path)
        or not isinstance(link['target'],str)
        or os.path.normpath(os.path.join(os.path.dirname(path),link['target']))!='/etc/systemd/system/'+name
        or not isinstance(fact,list) or len(fact)!=8
        or any(type(n) is not int or n<0 for n in fact)
        or fact[1]==0 or fact[2:4]!=[0,0] or fact[5]!=1
        or not stat.S_ISLNK(fact[4]),'KERNEL_RETIREMENT_LINK_DENIED')
   seen.add(path)
  dependencies=value['dependencies']
  deny(not isinstance(dependencies,dict) or not (units|observers)<=set(dependencies),
       'KERNEL_RETIREMENT_DEPENDENCY_COVERAGE_DENIED')
  for name,deps in dependencies.items():
   deny(not isinstance(deps,dict) or set(deps)!={'Requires','Wants','BindsTo','PartOf','RequiredBy','WantedBy','Triggers','TriggeredBy','BoundBy','ConsistsOf','PropagatesStopTo'}
        or any(not isinstance(v,list) or any(not isinstance(n,str) or not n for n in v)
               or len(v)!=len(set(v)) for v in deps.values()),
        'KERNEL_RETIREMENT_DEPENDENCY_DENIED')
  forward=('Requires','Wants','BindsTo','PartOf','Triggers')
  def closure(roots):
   seen=set();pending=list(roots)
   while pending:
    name=pending.pop()
    if name in seen:continue
    deny(name not in dependencies,'KERNEL_RETIREMENT_DEPENDENCY_COVERAGE_DENIED')
    seen.add(name)
    pending.extend(child for key in forward for child in dependencies[name][key])
   return seen
  # The whole reachable dependency graph is required, not just direct rows.
  # Cycles are ordinary systemd topology; a missing node remains UNKNOWN.
  deny(closure(units|observers)!=set(dependencies),
       'KERNEL_RETIREMENT_DEPENDENCY_COVERAGE_DENIED')
  deny(bool(closure(observers)&units),'KERNEL_RETIREMENT_OBSERVER_DEPENDENCY_DENIED')
  access=value['runtime_access']
  deny(not isinstance(access,dict) or set(access)!={'path','dev','ino','uid','gid','mode','access_acl_hex','default_acl_hex'}
       or access['path']!='/run/serein/stage1' or access['mode']!='0750'
       or any(type(access[k]) is not int or access[k]<0 for k in ('dev','ino','uid','gid'))
       or access['ino']==0 or access['default_acl_hex'] is not None
       or (access['access_acl_hex'] is not None and (not isinstance(access['access_acl_hex'],str)
           or not re.fullmatch(r'(?:[0-9a-f]{2})+',access['access_acl_hex']))),
       'KERNEL_RETIREMENT_RUNTIME_ACCESS_DENIED')
 deny(expected!=observed,'KERNEL_RETIREMENT_PRESTATE_CHANGED')
 return {'state':'RETIREMENT_PRESTATE_COMPARED_ONLY','boot_id':current_boot_id,
         'packet_sha256':sha(canonical(expected)),'authority_effect':'NONE',
         'exclusive_ownership':'UNPROVEN','mutable_private_state':'NOT_QUIESCED'}


def prepare_kernel_retirement(root,successor):
 """Authenticate historical source and fresh preservation inside Outpost.

 The old request/plan is evidence only; it is never executed or retimestamped.
 Only the separately verified fresh complete Outpost plan selects retirement.
 This preparation has no unit/file effects and cannot release a transaction.
 """
 from .public_generation_transaction import VerifiedSourcePlan,_retained_transaction_binding
 deny(type(successor) is not VerifiedSourcePlan or not successor.authority_custody_proven,
      'KERNEL_RETIREMENT_SUCCESSOR_REQUIRED')
 fields=successor.as_dict();binding=_retained_transaction_binding(fields)
 expected=fields.get('kernel_retirement')
 deny(not isinstance(expected,dict),'KERNEL_RETIREMENT_PACKET_DENIED')
 root=Path(root)
 history={path:regular(root/path.lstrip('/'),expected_custody=(0,0,0o600))
          for path in binding['history']}
 deny(any(sha(raw)!=binding['history'][path] for path,raw in history.items()),
      'KERNEL_RETIREMENT_HISTORY_CHANGED')
 plan_path=next(path for path in history if path.endswith('/plan.json'))
 historical=strict_json(history[plan_path])
 anchor=regular(root/str(VERIFY_KEY).lstrip('/'),expected_custody=(0,0,0o644))
 deny(sha(anchor)!=successor.authority_sha256 or historical.get('authority_sha256')!=sha(anchor),
      'KERNEL_RETIREMENT_ANCHOR_DENIED')
 try:
  load_pem_public_key(anchor).verify(decode(historical['signature']),
      canonical({k:v for k,v in historical.items() if k!='signature'}))
 except Exception as exc:raise RunnerDenied('KERNEL_RETIREMENT_SIGNATURE_DENIED') from exc
 deny(historical.get('current_boot_id')!=binding['prior_boot_id']
      or historical.get('rollback_selector')!=str(Path(plan_path).parent)
      or sha(canonical(historical))!=expected.get('historical_plan_sha256'),
      'KERNEL_RETIREMENT_HISTORY_BINDING_DENIED')
 source=root/str(SOURCE).lstrip('/')
 inventory=safe_tree(source)
 deny('sha256:'+sha(canonical(inventory))!=historical.get('source_inventory_digest'),
      'KERNEL_RETIREMENT_SOURCE_CHANGED')
 manifest=read_json(source/'release-manifest.json');layout=read_json(source/'install-layout.json')
 retirement_payload_selection(historical,manifest,layout)
 module=load_installer(source,manifest,expected_release=historical['release_digest'])
 def observe():
  return capture_retirement_packet(root,historical,manifest,layout,
      current_boot_id=fields['current_boot_id'],read_dependencies=read_retirement_dependencies,
      read_runtime_access=lambda:module.capture_runtime_access(root,historical))
 observed=observe()
 retirement_preservation_binding(historical,manifest,layout,expected,observed,
                                 current_boot_id=fields['current_boot_id'])
 def verify_source():
  deny(any(regular(root/path.lstrip('/'),expected_custody=(0,0,0o600))!=raw
           for path,raw in history.items()) or safe_tree(source)!=inventory
       or regular(root/str(VERIFY_KEY).lstrip('/'),expected_custody=(0,0,0o644))!=anchor,
       'KERNEL_RETIREMENT_SOURCE_CHANGED')
 verify_source()
 return {'plan':historical,'manifest':manifest,'layout':layout,'expected':expected,
         'observe':observe,'verify_source':verify_source,'runtime_access':lambda:module.capture_runtime_access(root,historical)}


def _retirement_stop_units(names):
 """Native fixed Kernel stop road; no start, timer, reboot or other unit."""
 import subprocess
 deny(not isinstance(names,tuple) or not names
      or len(set(names))!=len(names)
      or not set(names)<=set(AUTHORITY_UNITS+OTHER_KERNEL_UNITS),
      'KERNEL_RETIREMENT_UNIT_SET_DENIED')
 try:
  subprocess.run(['/usr/bin/systemctl','stop','--',*names],check=True,
      capture_output=True,stdin=subprocess.DEVNULL,close_fds=True,
      env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
 except (OSError,subprocess.SubprocessError) as exc:
  raise RunnerDenied('KERNEL_RETIREMENT_STOP_FAILED') from exc


def _retirement_quiescence():
 """Require stopped native jobs/process groups, not only an inactive label."""
 return {**_read_kernel_units(AUTHORITY_UNITS,retirement_controls=True),
         **_read_kernel_units(OTHER_KERNEL_UNITS,retirement_controls=True)}


def quiesce_kernel_retirement(root,successor,prepared,verify_ownership):
 """First constituent of the complete successor, never a standalone CLI.

 Close activation sockets/timer before their services. Exact protected state
 and runtime ACL must be unchanged after stop; a failed comparison keeps all
 program files in place and evidence intact. No predecessor is reactivated.
 """
 from .public_generation_transaction import VerifiedSourcePlan
 deny(type(successor) is not VerifiedSourcePlan or not successor.authority_custody_proven
      or not callable(verify_ownership),'KERNEL_RETIREMENT_SUCCESSOR_REQUIRED')
 fields=successor.as_dict();expected=fields.get('kernel_retirement')
 deny(expected!=prepared['expected'],'KERNEL_RETIREMENT_PACKET_DENIED')
 verify_ownership();prepared['verify_source']()
 retirement_preservation_binding(prepared['plan'],prepared['manifest'],prepared['layout'],
     expected,prepared['observe'](),current_boot_id=fields['current_boot_id'])
 names=AUTHORITY_UNITS+OTHER_KERNEL_UNITS
 units={**_read_kernel_units(AUTHORITY_UNITS,allow_transitional=True,retirement_prestate=True),
        **_read_kernel_units(OTHER_KERNEL_UNITS,allow_transitional=True,retirement_prestate=True)}
 # Stop propagation includes inverse BindsTo/PartOf and explicit stop edges,
 # not only inverse Requires. No unrelated dependent may be stopped.
 for name in names:
  deny(any(item not in names for key in ('RequiredBy','BoundBy','ConsistsOf','PropagatesStopTo')
           for item in expected['dependencies'][name][key]),
       'KERNEL_RETIREMENT_FOREIGN_DEPENDENT_DENIED')
 loaded={name for name,value in units.items() if value['LoadState']=='loaded'}
 groups=(tuple(name for name in names if name in loaded and name.endswith(('.socket','.timer'))),
         tuple(name for name in reversed(names) if name in loaded and name.endswith('.service')))
 for group in groups:
  verify_ownership();prepared['verify_source']()
  if group:_retirement_stop_units(group)
 after=_retirement_quiescence()
 deny(set(after)!=set(names) or any(value['ActiveState'] not in {'inactive','failed'}
      for value in after.values()),'KERNEL_RETIREMENT_QUIESCENCE_DENIED')
 verify_ownership()
 retirement_preservation_binding(prepared['plan'],prepared['manifest'],prepared['layout'],
     expected,prepared['observe'](),current_boot_id=fields['current_boot_id'])
 return {'state':'KERNEL_UNITS_QUIESCED','boot_id':fields['current_boot_id'],
         'source_plan_sha256':sha(successor.encoded),'before':units,'after':after,
         'preserved':expected['preserved'],'runtime_access':expected['runtime_access'],
         'stage1':'UNPROVEN','activation':'NONE'}


def retire_kernel_in_generation(root,successor,prepared,io,private,public,verify_ownership):
 """Retire only authenticated Kernel program/enablement in one Outpost install.

 Public program prestate and every write-ahead step remain signed in the new
 transaction directory. Identity, replay, models, source and old history are
 never removal targets. Failure retains evidence; there is no rollback or
 standalone unlock/retirement command.
 """
 from .public_generation_transaction import (_effect_row,_signed_transition_record,
                                             VerifiedSourcePlan)
 deny(type(successor) is not VerifiedSourcePlan or not successor.authority_custody_proven,
      'KERNEL_RETIREMENT_SUCCESSOR_REQUIRED')
 root=Path(root);fields=successor.as_dict();expected=fields.get('kernel_retirement')
 deny(expected!=prepared['expected'] or io.root!=root
      or io.receipt_directory!=fields['rollback_selector'],
      'KERNEL_RETIREMENT_PACKET_DENIED')
 rows=retirement_payload_selection(prepared['plan'],prepared['manifest'],prepared['layout'])
 targets={row['target'] for row in rows}
 prestate_path=io.receipt_directory+'/kernel-retirement-prestate.json'
 journal_path=io.receipt_directory+'/kernel-retirement-state.json'
 io.allowed.update(targets|{prestate_path,journal_path})
 verify_ownership();prepared['verify_source']()
 retirement_preservation_binding(prepared['plan'],prepared['manifest'],prepared['layout'],
     expected,prepared['observe'](),current_boot_id=fields['current_boot_id'])
 images={row['target']:io.read(row['target']) for row in rows}
 for row in rows:
  image=images[row['target']]
  deny(image.get('state')!=expected['public_state'][row['target']]
       or (image.get('state')=='PRESENT' and any(image.get(k)!=row[k] for k in ('bytes','sha256','mode'))),
       'KERNEL_RETIREMENT_INSTALLED_PAYLOAD_CHANGED')
 record={'schema':'SereinOutpostKernelRetirementPrestate/v1',
         'source_plan_sha256':sha(successor.encoded),'boot_id':fields['current_boot_id'],
         'packet':expected,'public_images':images}
 prestate=_effect_row(prestate_path,_signed_transition_record(record,private,public))
 io.replace(prestate_path,{'target':prestate_path,'state':'ABSENT'},prestate)
 journal={'target':journal_path,'state':'ABSENT'}
 def advance(phase,target=None):
  nonlocal journal
  verify_ownership();prepared['verify_source']()
  deny(io.read(prestate_path)!=prestate,'KERNEL_RETIREMENT_PRESTATE_CHANGED')
  body={'schema':'SereinOutpostKernelRetirementState/v1','source_plan_sha256':sha(successor.encoded),
        'boot_id':fields['current_boot_id'],'prestate_sha256':prestate['sha256'],
        'phase':phase,'target':target,'stage1':'UNPROVEN','activation':'NONE'}
  after=_effect_row(journal_path,_signed_transition_record(body,private,public))
  io.replace(journal_path,journal,after);journal=after
 advance('PREPARED')
 quiesced=quiesce_kernel_retirement(root,successor,prepared,verify_ownership)
 advance('QUIESCED')
 def preserved(*,full=False):
  verify_ownership();prepared['verify_source']()
  if full:
   deny(collect_retirement_preserved_state(root,prepared['plan'],current_boot_id=fields['current_boot_id'])
        !=expected['preserved'],'KERNEL_RETIREMENT_PRESERVED_STATE_CHANGED')
  else:
   files,_=retirement_preservation_paths(prepared['plan'])
   for path in files:
    fact=expected['preserved'][path]
    observed=regular(root/path.lstrip('/'),fact=True,include_identity=True,
        expected_custody=(fact['uid'],fact['gid'],int(fact['mode'],8)))
    deny(observed!=(fact['sha256'],fact['uid'],fact['gid'],int(fact['mode'],8),
                   fact['bytes'],fact['device'],fact['inode'],fact['nlink']),
         'KERNEL_RETIREMENT_PRESERVED_STATE_CHANGED')
  deny(prepared['runtime_access']()!=expected['runtime_access'],
       'KERNEL_RETIREMENT_PRESERVED_STATE_CHANGED')
  units=_retirement_quiescence()
  deny(any(value['ActiveState'] not in {'inactive','failed'} for value in units.values()),
       'KERNEL_RETIREMENT_QUIESCENCE_DENIED')
 def link_fact(parent,name):
  value=os.stat(name,dir_fd=parent,follow_symlinks=False)
  return [value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,value.st_nlink,
          value.st_mtime_ns,value.st_ctime_ns]
 for link in expected['enablement_links']:
  preserved();advance('LINK_INTENT',link['path'])
  io.allowed.add(link['path'])
  with io.parent(link['path']) as (parent,name,recheck):
   deny(link_fact(parent,name)!=link['fact'] or os.readlink(name,dir_fd=parent)!=link['target'],
        'KERNEL_RETIREMENT_ENABLEMENT_CHANGED')
   recheck();os.unlink(name,dir_fd=parent);os.fsync(parent);recheck()
  advance('LINK_RETIRED',link['path'])
 for row in rows:
  preserved();advance('PAYLOAD_INTENT',row['target'])
  if images[row['target']]['state']=='ABSENT':
   deny(io.read(row['target'])!=images[row['target']],'KERNEL_RETIREMENT_INSTALLED_PAYLOAD_CHANGED')
   advance('PAYLOAD_ALREADY_ABSENT',row['target'])
  else:
   io.replace(row['target'],images[row['target']],{'target':row['target'],'state':'ABSENT'})
   advance('PAYLOAD_RETIRED',row['target'])
 def terminal(*,full=False):
  preserved(full=full)
  deny(read_kernel_enablement_prestate(root)!=[]
       or any(io.read(row['target'])!={'target':row['target'],'state':'ABSENT'} for row in rows),
       'KERNEL_RETIREMENT_TERMINAL_DENIED')
  deny(io.read(prestate_path)!=prestate,'KERNEL_RETIREMENT_PRESTATE_CHANGED')
 terminal(full=True);advance('RETIRED')
 return {'result':'KERNEL_PROGRAM_RETIRED_PRIVATE_STATE_PRESERVED',
         'source_plan_sha256':sha(successor.encoded),'boot_id':fields['current_boot_id'],
         'prestate_sha256':prestate['sha256'],'journal_sha256':journal['sha256'],
         'payload_count':len(rows),'enablement_count':len(expected['enablement_links']),
         'removed_count':sum(image['state']=='PRESENT' for image in images.values()),
         'already_absent_count':sum(image['state']=='ABSENT' for image in images.values()),
         'quiescence':quiesced['state'],'stage1':'UNPROVEN','activation':'NONE'},terminal


def current_host_gate(host_path,boot_id):
 """Consume the canonical data-derived Host witness, not verdict labels."""
 import time
 from outpost.host_vitality import HostCollectionAttempts,host_attempt_matches
 try:
  host=validate_state(read_json(host_path),active=True)
  deny(host["current_boot_id"]!=boot_id or host["classification"] not in {"CURRENT_BOOT_STABLE","FIRST_BOOT_OBSERVED","RECOVERED_AFTER_BOOT_CHANGE"},"KERNEL_HOST_GATE_DENIED")
  attempts=HostCollectionAttempts(Path(host_path).parent)
  latest=attempts.latest()
  deny(not host_attempt_matches(host,latest,boot_id,time.time()),'KERNEL_HOST_ATTEMPT_DENIED')
  # A successful old state cannot override a newer pending/failed collection.
  # Use the same attempt predicate as Outpost/Vitals, with no invented TTL.
  deny(read_json(host_path)!=host or attempts.latest()!=latest,'KERNEL_HOST_OBSERVATION_CHANGED')
 except (ValueError,TypeError,KeyError) as exc:raise RunnerDenied("KERNEL_HOST_GATE_DENIED") from exc
 return host

def current_boot():
 return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()

def _settled_host_gate(host_path,boot_id):
 """Wait only for collection evidence; never execute using a pending sample.

 The recurring collector can begin between two installer boundaries. Keep the
 ordinary observer fail-closed, but let the transaction wait briefly for that
 exact attempt to finish. Failed, replaced, wrong-boot and abandoned attempts
 remain denials. No service action, old-sample fallback or timestamp rewrite.
 """
 import time
 from outpost.host_vitality import HostCollectionAttempts
 from outpost.reboot_vitality import RebootVitalityError
 deadline=time.monotonic()+HOST_SETTLE_DEADLINE_SECONDS
 def read_unlocked(reader):
  # The collector's exclusive flock is transient, not invalid evidence.
  # Retry only that exact lock result; every read still validates all bytes.
  # All reads share the original deadline and no cached state is returned.
  while True:
   deny(time.monotonic()>=deadline,'KERNEL_HOST_ATTEMPT_DENIED')
   try:
    value=reader()
   except (RunnerDenied,RebootVitalityError) as exc:
    cause=exc.__cause__ if isinstance(exc,RunnerDenied) else exc
    if (isinstance(exc,RunnerDenied) and str(exc)!='KERNEL_HOST_GATE_DENIED'
        or not isinstance(cause,RebootVitalityError)
        or str(cause)!='VITALITY_CHRONOLOGY_BUSY'):raise
    deny(time.monotonic()>=deadline,'KERNEL_HOST_ATTEMPT_DENIED')
    time.sleep(0.1)
   else:
    deny(time.monotonic()>=deadline,'KERNEL_HOST_ATTEMPT_DENIED')
    return value
 try:return read_unlocked(lambda:current_host_gate(host_path,boot_id))
 except RunnerDenied as exc:
  if str(exc)!='KERNEL_HOST_ATTEMPT_DENIED':raise
  attempts=HostCollectionAttempts(Path(host_path).parent)
  latest=read_unlocked(attempts.latest)
  if not latest:raise
  pinned=latest['start']
  while True:
   if (not latest or latest['start']!=pinned
       or pinned['payload']['boot_id']!=boot_id or pinned['observed_at']>time.time()):raise
   if time.monotonic()>=deadline:raise
   terminal=latest['terminal']
   if terminal is not None:
    if terminal['event_kind']!='HOST_COLLECTION_SUCCEEDED':raise
    # It completed after the failed read. The unchanged strict reader must
    # still prove the exact latest state; this is not a cached PASS.
    result=read_unlocked(lambda:current_host_gate(host_path,boot_id))
    deny(read_unlocked(attempts.latest)!=latest,'KERNEL_HOST_OBSERVATION_CHANGED')
    deny(time.monotonic()>=deadline,'KERNEL_HOST_ATTEMPT_DENIED')
    return result
   time.sleep(0.1)
   latest=read_unlocked(attempts.latest)
def load_installer(source,manifest,*,expected_release):
 """Compile only the exact installer bytes in the verified source manifest."""
 import types
 path=source/'install/kernel_first_install.py';raw=regular(path)
 deny(manifest.get('self_digest')!=expected_release or manifest.get('self_digest')!='sha256:'+sha(canonical({k:v for k,v in manifest.items() if k!='self_digest'}))
      or not any(row==['install/kernel_first_install.py',len(raw),sha(raw),'0755'] for row in manifest.get('installer_files',[])),
      'KERNEL_INSTALLER_DENOMINATOR_DENIED')
 module=types.ModuleType('_serein_kernel_first_install');exec(compile(raw,str(path),'exec'),module.__dict__)
 return module

def load_offline_installer(source,manifest,*,expected_release):
 """Reuse the exact public offline installer for planning and its later owner."""
 import types
 deny(manifest.get('self_digest')!=expected_release
      or manifest.get('self_digest')!='sha256:'+sha(canonical({k:v for k,v in manifest.items() if k!='self_digest'})),
      'KERNEL_MANIFEST_DENIED')
 layout=read_json(source/'install-layout.json');offline=layout.get('offline_model_transaction')
 relative='install/offline_ollama_transaction.py'
 deny(not isinstance(offline,dict) or set(offline)!={'executor','source','network',
      'runtime_archive_sha256','model_digest','blobs_in_public_archive'}
      or offline['executor']!='OUTPOST_ONLY' or offline['source']!=relative
      or offline['network']!='PROHIBIT_FETCH_AND_PULL' or offline['blobs_in_public_archive'] is not False,
      'KERNEL_OFFLINE_CONTRACT_DENIED')
 raw=regular(source/relative)
 deny(not any(row==[relative,len(raw),sha(raw),'0755'] for row in manifest.get('installer_files',[])),
      'KERNEL_OFFLINE_SOURCE_DENIED')
 module=types.ModuleType('_serein_outpost_offline_companion')
 exec(compile(raw,str(source/relative),'exec'),module.__dict__)
 deny(module.PINNED_ARCHIVE['sha256']!=offline['runtime_archive_sha256']
      or module.PINNED_MODEL['digest']!=offline['model_digest'],'KERNEL_OFFLINE_PIN_DENIED')
 return module


def prepare_offline_companion(source,bundle_root,expected_before,rollback_selector,request_id,*,
                             host_path=HOST_STATE,verify_path=VERIFY_KEY,
                             source_receipt_path=SOURCE_RECEIPT,adapter=None):
 """Source-bound read-only planning for the existing offline transaction.

 No signer, service action, installation, model download or admission is invoked.
 The later owning transaction must independently bind and revalidate this whole
 preparation, including its Host projection and source-receipt digest. Signing
 the nested plan alone does NOT bind those observations and is not sufficient
 authorization. No such authorization/composition is implemented here.
 """
 deny(sha(regular(verify_path))!=CANONICAL_AUTHORITY_SHA256,'KERNEL_CANONICAL_ANCHOR_DENIED')
 receipt,receipt_digest=source_receipt(source,source_receipt_path,verify_path)
 manifest=read_json(source/'release-manifest.json')
 boot=current_boot();host=_settled_host_gate(host_path,boot)
 module=load_offline_installer(source,manifest,expected_release=receipt['release_digest'])
 if adapter is None:adapter=module.OfflineOllamaRealAdapter()
 plan=module.classify(adapter,Path(bundle_root),expected_before,rollback_selector,boot_id=boot,
      source_generation={'commit':receipt['source_commit'],'tree':receipt['source_tree']},request_id=request_id)
 fresh=_settled_host_gate(host_path,boot)
 stable=lambda value:canonical({k:v for k,v in value['latest'].items() if k not in {'observed_at','evidence_digest'}})
 deny(current_boot()!=boot or stable(fresh)!=stable(host)
      or fresh['classification'] not in {host['classification'],'CURRENT_BOOT_STABLE'}
      or fresh['latest']['observed_at']<host['latest']['observed_at'], 'KERNEL_HOST_PRESTATE_CHANGED')
 deny(sha(regular(verify_path))!=CANONICAL_AUTHORITY_SHA256
      or source_receipt(source,source_receipt_path,verify_path)!=(receipt,receipt_digest),
      'KERNEL_OFFLINE_SOURCE_CHANGED')
 fixed={'schema':'SereinOfflineOllamaInstallPlan/v2','target':'VM4010',
        'method':'PVE_REST_QGA','delivery_actor':'SFOS_PROXY','executor':'OUTPOST',
        'network':'PROHIBIT_FETCH_AND_PULL','boot_id':boot,
        'source_generation':{'commit':receipt['source_commit'],'tree':receipt['source_tree']},
        'request_id':request_id,'rollback_selector':rollback_selector,
        'model':module.PINNED_MODEL,'signature_algorithm':'Ed25519',
        'signing_key_id':'outpost-cognition-v1','signature':None}
 archive={**module.PINNED_ARCHIVE,'target':'/usr/local/bin/ollama','mode':'0755',
          'uid':0,'gid':0,'format':'tar','original_zst':module.ORIGINAL_ARCHIVE_PROVENANCE,
          'denominator':{'source':module.ARCHIVE_DENOMINATOR_SOURCE,
                         'sha256':module.ARCHIVE_DENOMINATOR_SHA256}}
 required=set(fixed)|{'runtime_archive','unit_prestate','directories','immutable_inputs',
                      'runtime_objects','files','plan_sha256'}
 deny(not isinstance(plan,dict) or set(plan)!=required
      or any(plan[key]!=value for key,value in fixed.items())
      or plan['runtime_archive']!=archive,'KERNEL_OFFLINE_PLAN_DENIED')
 body={key:value for key,value in plan.items()
       if key not in {'plan_sha256','signature_algorithm','signing_key_id','signature'}}
 # The offline transaction's canonical encoding has no trailing LF.
 deny(plan['plan_sha256']!=sha(json.dumps(body,sort_keys=True,separators=(',',':'),
                                        allow_nan=False).encode()),'KERNEL_OFFLINE_PLAN_DENIED')
 return {'plan':plan,'host_projection_digest':host['projection_digest'],
         'source_receipt_sha256':receipt_digest,'status':'PREPARED_UNSIGNED_NOT_AUTHORIZED',
         'authority_effect':'NONE','admission_effect':'NONE'}

def prepare_native_companion(source,expected_before_sha256,rollback_selector,request_id,*,
                             host_path=HOST_STATE,verify_path=VERIFY_KEY,
                             source_receipt_path=SOURCE_RECEIPT,adapter=None):
 """Same Outpost-owned runtime constituent, with no binary/model replacement."""
 deny(sha(regular(verify_path))!=CANONICAL_AUTHORITY_SHA256,'KERNEL_CANONICAL_ANCHOR_DENIED')
 receipt,receipt_digest=source_receipt(source,source_receipt_path,verify_path)
 boot=current_boot();host=_settled_host_gate(host_path,boot)
 module=load_offline_installer(source,read_json(source/'release-manifest.json'),
      expected_release=receipt['release_digest'])
 if adapter is None:adapter=module.OfflineOllamaRealAdapter()
 deny(adapter.boot_id!=boot,'KERNEL_NATIVE_ALLOCATION_BOOT_DENIED')
 plan=module.prepare_native_allocation(adapter,source_generation={
      'commit':receipt['source_commit'],'tree':receipt['source_tree']},
      rollback_selector=rollback_selector,request_id=request_id)
 expected={key:plan[key] for key in ('runtime_prestate','unit_prestate','immutable_inputs')}
 deny(sha(module.canonical(expected))!=expected_before_sha256,'KERNEL_NATIVE_ALLOCATION_PRESTATE_CHANGED')
 fresh=_settled_host_gate(host_path,boot)
 stable=lambda value:canonical({k:v for k,v in value['latest'].items() if k not in {'observed_at','evidence_digest'}})
 deny(current_boot()!=boot or stable(fresh)!=stable(host)
      or fresh['classification'] not in {host['classification'],'CURRENT_BOOT_STABLE'}
      or fresh['latest']['observed_at']<host['latest']['observed_at'], 'KERNEL_HOST_PRESTATE_CHANGED')
 deny(source_receipt(source,source_receipt_path,verify_path)!=(receipt,receipt_digest)
      or sha(regular(verify_path))!=CANONICAL_AUTHORITY_SHA256,'KERNEL_OFFLINE_SOURCE_CHANGED')
 return {'plan':plan,'host_projection_digest':host['projection_digest'],
         'source_receipt_sha256':receipt_digest,'status':'PREPARED_UNSIGNED_NOT_AUTHORIZED',
         'authority_effect':'NONE','admission_effect':'NONE'}


def install_request(path):
 request=read_json(path)
 required={"schema","target_vm_id","repository","source_parent","source_commit","source_tree","archive_sha256","rollback_selector","reserved_domain_ids"}
 version=request.get('schema')
 deny(not isinstance(version,str) or version not in {'SereinOutpostKernelInstallRequest/v1','SereinOutpostKernelInstallRequest/v2','SereinOutpostKernelInstallRequest/v3'},'KERNEL_REQUEST_DENIED')
 if version.endswith('/v2'):required.add('offline_companion')
 if version.endswith('/v3'):required.add('native_allocation')
 if 'recovered_predecessor' in request:required.add('recovered_predecessor')
 if 'installed_predecessor' in request:
  required.add('installed_predecessor')
  previous=request['installed_predecessor']
  fields={'rollback_selector','plan_sha256','receipt_sha256','journal_sha256',
          'witness_sha256','current_boot_id','machine_id_sha256','source_root','source_receipt'}
  if isinstance(previous,dict) and 'failed_construction' in previous:
   fields.add('failed_construction')
   _failed_construction_descriptor(previous['failed_construction'])
   deny(version!='SereinOutpostKernelInstallRequest/v1','KERNEL_FAILED_SUCCESSOR_RUNTIME_EFFECT_DENIED')
  deny('recovered_predecessor' in request or not isinstance(previous,dict) or set(previous)!=fields,
       'KERNEL_SUCCESSOR_REQUEST_DENIED')
  for key in ('source_root','source_receipt'):
   location=previous[key]
   deny(not isinstance(location,str) or not location.startswith('/var/lib/serein/rollback/')
        or '\\' in location or '\x00' in location or str(Path(location))!=location
        or '..' in Path(location).parts,'KERNEL_SUCCESSOR_SOURCE_PATH_DENIED')
 deny(set(request)!=required or request['target_vm_id']!='VM4010' or request['repository']!='Kaotikking/sfos-public','KERNEL_REQUEST_DENIED')
 if 'native_allocation' in request:
  value=request['native_allocation']
  deny(type(value) is not dict or set(value)!={'expected_before_sha256','rollback_selector','request_id'}
       or type(value['expected_before_sha256']) is not str or not HEX64.fullmatch(value['expected_before_sha256'])
       or type(value['request_id']) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}',value['request_id'])
       or type(value['rollback_selector']) is not str
       or not re.fullmatch(r'/var/lib/serein/rollback/offline-ollama-\d{8}T\d{6}Z-[0-9a-f]{12}',value['rollback_selector'])
       or value['rollback_selector']==request['rollback_selector'],'KERNEL_NATIVE_ALLOCATION_REQUEST_DENIED')
 if 'offline_companion' in request:
  value=request['offline_companion']
  deny(not isinstance(value,dict) or set(value)!={'bundle_root','expected_before','rollback_selector','request_id'},'KERNEL_OFFLINE_REQUEST_DENIED')
  location=value['bundle_root']
  deny(not isinstance(location,str) or not location.startswith('/') or '\\' in location or '\x00' in location
       or str(Path(location))!=location or '..' in Path(location).parts or location=='/', 'KERNEL_OFFLINE_REQUEST_DENIED')
  deny(not isinstance(value['request_id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}',value['request_id'])
       or not isinstance(value['rollback_selector'],str)
       or not re.fullmatch(r'/var/lib/serein/rollback/offline-ollama-\d{8}T\d{6}Z-[0-9a-f]{12}',value['rollback_selector'])
       or value['rollback_selector']==request['rollback_selector'],'KERNEL_OFFLINE_REQUEST_DENIED')
  expected=value['expected_before']
  deny(not isinstance(expected,dict) or set(expected)!={'schema','unit','files','runtime_objects','directories','immutable_inputs'}
       or expected['schema']!='SereinOfflineOllamaExpectedBefore/v2' or not isinstance(expected['unit'],dict)
       or any(not isinstance(expected[key],list) for key in ('files','runtime_objects','directories','immutable_inputs')),'KERNEL_OFFLINE_REQUEST_DENIED')
 return request

def read_outpost_generation(root):
 """Read verified selected bytes; observation is not permission to execute them."""
 from .generation_launcher import read_selector
 from outpost.service import _validate_generation_identity
 root=Path(root)
 selector,generation=read_selector(root/'var/lib/serein-outpost/generation-state/current.json',
                                  root/'usr/share/serein/outpost-generations')
 _validate_generation_identity(selector)
 return selector,generation


def capture_outpost_generation(root):
 """Bind this executor to the existing selected generation."""
 root=Path(root)
 selector,generation=read_outpost_generation(root)
 executing=Path(__file__).absolute()
 expected=generation/'install/kernel_first_install_runner.py'
 deny(root==Path('/') and executing!=expected.absolute(),'KERNEL_OUTPOST_EXECUTOR_GENERATION_DENIED')
 deny(regular(executing)!=regular(expected),'KERNEL_OUTPOST_EXECUTOR_SOURCE_DENIED')
 return selector


def _failed_construction_descriptor(value):
 """Explicit failed-state input, never an invented successful witness."""
 fields={'schema','request_path','request_sha256','native_selector','native_receipt_sha256',
         'native_observation_sha256'}
 deny(type(value) is not dict or set(value)!=fields
      or value['schema']!='SereinFailedKernelConstruction/v1'
      or any(type(value[k]) is not str or not HEX64.fullmatch(value[k]) for k in
             ('request_sha256','native_receipt_sha256','native_observation_sha256')),
      'KERNEL_FAILED_PREDECESSOR_DESCRIPTOR_DENIED')
 for key in ('request_path','native_selector'):
  name=value[key]
  deny(type(name) is not str or not name.startswith('/var/lib/serein/rollback/')
       or '\\' in name or '\x00' in name or str(Path(name))!=name or '..' in Path(name).parts,
       'KERNEL_FAILED_PREDECESSOR_PATH_DENIED')
 deny(not re.fullmatch(r'/var/lib/serein/rollback/offline-ollama-\d{8}T\d{6}Z-[0-9a-f]{12}',
                      value['native_selector']),'KERNEL_FAILED_PREDECESSOR_PATH_DENIED')
 return strict_json(canonical(value))


def observe_failed_native_prestate(root,plan,failed,runtime_source,*,expected_release):
 """Read a failed v3 attempt as current UNADMITTED material, without effects.

 This never fills the legacy receipt's missing runtime ownership, restores a
 process, or claims the attempt succeeded. The successor explicitly retains
 the currently observed runtime and must prove the whole Kernel afresh.
 """
 root=Path(root);failed=_failed_construction_descriptor(failed)
 request_path=root/failed['request_path'].lstrip('/')
 request_raw=regular(request_path,expected_custody=(0,0,0o600))
 deny(sha(request_raw)!=failed['request_sha256'],'KERNEL_FAILED_REQUEST_CHANGED')
 request=install_request(request_path)
 deny(request['schema']!='SereinOutpostKernelInstallRequest/v3'
      or any(request[k]!=plan[k] for k in
             ('source_parent','source_commit','source_tree','archive_sha256','rollback_selector'))
      or request['native_allocation']['rollback_selector']!=failed['native_selector'],
      'KERNEL_FAILED_REQUEST_DENIED')
 runtime_source=Path(runtime_source)
 manifest=read_json(runtime_source/'release-manifest.json')
 module=load_offline_installer(runtime_source,manifest,expected_release=expected_release)
 adapter=module.OfflineOllamaRealAdapter()
 deny(Path(adapter.root)!=root or adapter.boot_id!=plan['current_boot_id'],
      'KERNEL_FAILED_RUNTIME_TARGET_DENIED')
 selector=root/failed['native_selector'].lstrip('/')
 raw=regular(selector/'receipt.json',expected_custody=(0,0,0o600))
 deny(sha(raw)!=failed['native_receipt_sha256'],'KERNEL_FAILED_RUNTIME_RECEIPT_CHANGED')
 receipt=module._native_allocation_receipt(adapter,selector)
 native=receipt['plan']
 deny(receipt['schema']!=module.NATIVE_ALLOCATION_RECEIPT or receipt['phase']!='START_REQUESTED'
      or receipt['runtime_after'] is not None or receipt['rollback_complete']
      or receipt['acceptance'] is not None or receipt['restoration'] is not None
      or native['source_generation']!={'commit':plan['source_commit'],'tree':plan['source_tree']}
      or native['request_id']!=request['native_allocation']['request_id']
      or module.digest(module.canonical({'unit_prestate':native['unit_prestate'],
          'runtime_prestate':native['runtime_prestate'],'immutable_inputs':native['immutable_inputs']}))
          !=request['native_allocation']['expected_before_sha256'],
      'KERNEL_FAILED_NATIVE_PHASE_DENIED')
 module._native_owned_configuration(adapter,receipt)
 incarnation=adapter.observe_native_incarnation()
 observed=adapter.observe_native_allocation()
 definition=adapter.read_native_allocation_definition()
 module.native_allocation_transition(native['runtime_prestate'],observed)
 deny(definition!=module._native_expected_definition(native,installed=True)
      or adapter.observe_native_incarnation()!=incarnation
      or any(observed['runtime'][k]!=incarnation[k] for k in ('boot_id','pid','start_time')),
      'KERNEL_FAILED_RUNTIME_CHANGED')
 captured={'runtime':observed,'incarnation':incarnation,'definition':definition}
 deny(sha(canonical(captured))!=failed['native_observation_sha256'],
      'KERNEL_FAILED_NATIVE_OBSERVATION_CHANGED')
 module._native_owned_configuration(adapter,receipt)
 deny(regular(selector/'receipt.json',expected_custody=(0,0,0o600))!=raw
      or regular(request_path,expected_custody=(0,0,0o600))!=request_raw,
      'KERNEL_FAILED_RUNTIME_RECORD_CHANGED')
 return {**captured,'native_plan':native}


def capture_installed_kernel_prestate(root,source,expected,*,verify_path=VERIFY_KEY,witness_path=None,
                                     observation_boot_id=None,runtime_source=None,runtime_release=None):
 """Authenticate exact predecessor material for a whole-domain successor.

 A failed construction is capture-only: its historical successful witness
 remains distinct and does not admit the failed generation.

 Read-only: retain birth/replay provenance and exact public preimages. This
 does not run the first-install rollback, generate identity, quiesce services,
 authorize replacement, or describe active mutable databases as frozen.
 """
 root=Path(root);source=Path(source)
 fields={'rollback_selector','plan_sha256','receipt_sha256','journal_sha256',
         'witness_sha256','current_boot_id','machine_id_sha256'}
 if isinstance(expected,dict) and 'failed_construction' in expected:
  fields.add('failed_construction')
  _failed_construction_descriptor(expected['failed_construction'])
 deny(not isinstance(expected,dict) or set(expected)!=fields
      or any(not isinstance(expected[k],str) or not HEX64.fullmatch(expected[k])
             for k in fields-{'rollback_selector','current_boot_id','failed_construction'}),
      'KERNEL_SUCCESSOR_EXPECTATION_DENIED')
 expected=strict_json(canonical(expected));selector=expected['rollback_selector']
 # A historical signed installation remains evidence after a boot change.
 # Explicit read-only observation never changes its signed boot or permits
 # installation/runtime execution. Existing executable callers retain their
 # same-boot default until the complete successor contract is proven.
 observed_boot=expected['current_boot_id'] if observation_boot_id is None else observation_boot_id
 deny(not isinstance(observed_boot,str) or not re.fullmatch(
      r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',observed_boot),
      'KERNEL_SUCCESSOR_OBSERVATION_BOOT_DENIED')
 deny(not isinstance(selector,str) or not re.fullmatch(
      r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',selector),
      'KERNEL_SUCCESSOR_SELECTOR_DENIED')
 directory=root/selector.lstrip('/')
 witness_path=Path(witness_path) if witness_path is not None else root/'var/lib/serein-outpost/kernel/kernel-install-witness.json'
 paths={directory/'plan.json':'plan_sha256',directory/'receipt.json':'receipt_sha256',
        directory/'phase-journal.json':'journal_sha256',witness_path:'witness_sha256'}
 captured={}
 for path,key in paths.items():
  raw=regular(path,expected_custody=(0,0,0o600))
  deny(sha(raw)!=expected[key],'KERNEL_SUCCESSOR_RECORD_DENIED')
  value=strict_json(raw)
  deny(canonical(value)!=raw,'KERNEL_SUCCESSOR_RECORD_DENIED')
  captured[path]=raw
 plan=strict_json(captured[directory/'plan.json']);witness=strict_json(captured[witness_path])
 failed=expected.get('failed_construction')
 anchor=regular(verify_path,expected_custody=(0,0,0o644))
 deny(sha(anchor)!=CANONICAL_AUTHORITY_SHA256 or plan.get('authority_sha256')!=sha(anchor),
      'KERNEL_SUCCESSOR_ANCHOR_DENIED')
 try:load_pem_public_key(anchor).verify(decode(plan['signature']),canonical({k:v for k,v in plan.items() if k!='signature'}))
 except Exception as exc:raise RunnerDenied('KERNEL_SUCCESSOR_SIGNATURE_DENIED') from exc
 deny(plan.get('schema')!='SereinPublicKernelFirstInstallPlan/v1'
      or plan.get('target_vm_id')!='VM4010' or plan.get('rollback_selector')!=selector
      or plan.get('current_boot_id')!=expected['current_boot_id']
      or witness.get('schema') not in {'SereinOutpostKernelInstallWitness/v1','SereinOutpostKernelInstallWitness/v2'}
      or witness.get('target')!='VM4010' or witness.get('boot_id')!=plan['current_boot_id']
      or witness.get('install_status') not in {'INSTALLED_INACTIVE','CONSTRUCTION_OBSERVED'}
      or witness.get('authority_effect')!='NONE'
      or witness.get('witness_digest')!=sha(canonical({k:v for k,v in witness.items() if k!='witness_digest'}))
      or (failed is None and any(witness.get(k)!=plan.get(k) for k in ('source_commit','source_tree','archive_sha256',
          'release_digest','source_receipt_sha256','rollback_selector','native_identity','host_identity','host_projection_digest'))),
      'KERNEL_SUCCESSOR_PREDECESSOR_DENIED')
 if failed is not None:
  prior=plan.get('installed_predecessor')
  deny(not isinstance(prior,dict) or prior.get('witness_sha256')!=expected['witness_sha256']
       or prior.get('rollback_selector')!=witness.get('rollback_selector')
       or plan['rollback_selector']==witness.get('rollback_selector')
       or plan['current_boot_id']!=observed_boot
       or plan['native_identity']!=witness['native_identity']
       or plan['host_identity']!=witness['host_identity'] or runtime_source is None or runtime_release is None,
       'KERNEL_FAILED_HISTORICAL_WITNESS_DENIED')
  observe_failed_native_prestate(root,plan,failed,runtime_source,expected_release=runtime_release)
 if witness['schema'].endswith('/v1'):
  deny(witness['install_status']!='INSTALLED_INACTIVE'
       or witness.get('admission')!='INDEPENDENT_AUDIT_PENDING'
       or witness.get('stage1')!='NOT_READY','KERNEL_SUCCESSOR_TERMINAL_DENIED')
 else:
  deny(witness['install_status']!='CONSTRUCTION_OBSERVED'
       or witness.get('admission')!='UNADMITTED' or witness.get('stage1')!='NOT_READY'
       or witness.get('admission_effect')!='NONE'
       or witness.get('temporal_scope')!='HISTORICAL_CONSTRUCTION_OBSERVATION'
       or witness.get('public_acceptance')!='UNPROVEN'
       or not isinstance(witness.get('observations'),dict)
       or witness.get('observations_sha256')!=sha(canonical(witness['observations'])),
       'KERNEL_SUCCESSOR_TERMINAL_DENIED')
 def currentness():
  machine_mode=stat.S_IMODE((root/'etc/machine-id').lstat().st_mode)
  deny(machine_mode not in {0o444,0o644},'KERNEL_SUCCESSOR_HOST_CUSTODY_DENIED')
  deny((root/'proc/sys/kernel/random/boot_id').read_text().strip()!=observed_boot
       or sha(regular(root/'etc/machine-id',expected_custody=(0,0,machine_mode)))!=expected['machine_id_sha256'],
       'KERNEL_SUCCESSOR_HOST_CHANGED')
  deny(any(regular(path,expected_custody=(0,0,0o600))!=raw for path,raw in captured.items())
       or regular(verify_path,expected_custody=(0,0,0o644))!=anchor,
       'KERNEL_SUCCESSOR_RECORD_CHANGED')
  deny('sha256:'+sha(canonical(safe_tree(source)))!=plan['source_inventory_digest'],
       'KERNEL_SUCCESSOR_SOURCE_CHANGED')
 currentness()
 manifest=read_json(source/'release-manifest.json')
 module=load_installer(source,manifest,expected_release=plan['release_digest'])
 module.verify_host_identity(root,plan)
 receipt={'status':'INSTALLED_INACTIVE','receipt':selector+'/receipt.json'}
 digest=_verify_install_material(root,plan,receipt,source=source)
 deny(module.journal_read(directory,digest)!=strict_json(captured[directory/'phase-journal.json']),
      'KERNEL_SUCCESSOR_JOURNAL_CHANGED')
 if failed is None:
  deny(witness.get('installer_receipt_sha256')!=digest,'KERNEL_SUCCESSOR_RECEIPT_DENIED')
 public=module.capture_successor_payload(root,plan['payload'])
 rows=strict_json(captured[directory/'receipt.json'])['replacements']
 generated={}
 for row in rows:
  if row['target'] in module.GENERATED:
   generated[row['target']]=regular(root/row['target'].lstrip('/'),fact=True,
       expected_custody=(row['uid'],row['gid'],int(row['mode'],8)),include_identity=True)
 deny(set(generated)!=set(module.GENERATED),'KERNEL_SUCCESSOR_GENERATED_SET_DENIED')
 currentness();module.verify_host_identity(root,plan)
 deny(_verify_install_material(root,plan,receipt,source=source)!=digest
      or module.capture_successor_payload(root,plan['payload'])!=public,
      'KERNEL_SUCCESSOR_PRESTATE_CHANGED')
 for row in rows:
  if row['target'] in generated:
   deny(regular(root/row['target'].lstrip('/'),fact=True,
       expected_custody=(row['uid'],row['gid'],int(row['mode'],8)),include_identity=True)!=generated[row['target']],
       'KERNEL_SUCCESSOR_IDENTITY_CHANGED')
 currentness()
 deny(module.journal_read(directory,digest)!=strict_json(captured[directory/'phase-journal.json']),
      'KERNEL_SUCCESSOR_JOURNAL_CHANGED')
 if failed is not None:
  observe_failed_native_prestate(root,plan,failed,runtime_source,expected_release=runtime_release)
 return {'state':'FAILED_PREDECESSOR_CAPTURE_ONLY' if failed is not None else 'INSTALLED_PREDECESSOR_CAPTURE_ONLY',
         'plan':plan,'receipt_digest':digest,
         'witness':witness,'expected':expected,'public_payload':public,
         'observation_boot_id':observed_boot,
         'generated_prestate':generated,'mutable_private_state':'NOT_QUIESCED',
         'authority_effect':'NONE','admission_effect':'NONE'}


def capture_recovered_kernel_prestate(root,module,expected,*,verify_path=VERIFY_KEY,witness_path=None):
 """Authenticate an already recovered transaction, without changing a file.

 A historical witness and ROLLBACK_COMPLETE label are not a clean target.
 Bind the signed original plan, authenticated receipt, exact retained public
 bytes and physical absence of every created target/temp. This observation
 grants neither installation nor admission; the whole installer must consume
 and recheck it before any eventual successor effect.
 """
 root=Path(root)
 expected=strict_json(canonical(expected))
 deny(not isinstance(expected,dict) or set(expected)!={'rollback_selector','plan_sha256','receipt_sha256',
      'journal_sha256','witness_sha256','current_boot_id','machine_id_sha256'}
      or any(not isinstance(expected[k],str) or not HEX64.fullmatch(expected[k]) for k in
             ('plan_sha256','receipt_sha256','journal_sha256','witness_sha256','machine_id_sha256')),
      'KERNEL_RECOVERED_EXPECTATION_DENIED')
 machine_fact=None
 def check_host():
  nonlocal machine_fact
  try:boot=(root/'proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
  except (OSError,UnicodeError) as exc:raise RunnerDenied('KERNEL_RECOVERED_BOOT_DENIED') from exc
  deny(not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',boot)
       or boot!=expected['current_boot_id'],'KERNEL_RECOVERED_BOOT_DENIED')
  machine_path=root/'etc/machine-id';mode=stat.S_IMODE(machine_path.lstat().st_mode)
  deny(mode not in {0o444,0o644},'KERNEL_RECOVERED_HOST_DENIED')
  raw=regular(machine_path,expected_custody=(0,0,mode))
  fact=regular(machine_path,fact=True,expected_custody=(0,0,mode),include_identity=True)
  deny(sha(raw)!=expected['machine_id_sha256'],'KERNEL_RECOVERED_HOST_DENIED')
  deny(fact[0]!=sha(raw) or (machine_fact is not None and machine_fact!=fact),'KERNEL_RECOVERED_HOST_CHANGED')
  machine_fact=fact
 check_host()
 witness_path=Path(witness_path) if witness_path is not None else root/str(STATE/'kernel-install-witness.json').lstrip('/')
 captured={}
 def read(path,mode=0o600):
  path=Path(path);raw=regular(path,expected_custody=(0,0,mode))
  fact=regular(path,fact=True,expected_custody=(0,0,mode),include_identity=True)
  deny((sha(raw),len(raw))!=(fact[0],fact[4]),'KERNEL_RECOVERED_RECORD_CHANGED')
  captured[path]=(raw,fact,mode)
  return raw
 def document(path):
  raw=read(path)
  try:value=strict_json(raw)
  except Exception as exc:raise RunnerDenied('KERNEL_RECOVERED_DOCUMENT_DENIED') from exc
  deny(not isinstance(value,dict) or canonical(value)!=raw,'KERNEL_RECOVERED_DOCUMENT_DENIED')
  return value
 witness=document(witness_path)
 deny(witness.get('schema')!='SereinOutpostKernelInstallWitness/v1'
      or witness.get('target')!='VM4010' or witness.get('install_status')!='INSTALLED_INACTIVE'
      or witness.get('stage1')!='NOT_READY' or witness.get('authority_effect')!='NONE'
      or witness.get('witness_digest')!=sha(canonical({k:v for k,v in witness.items() if k!='witness_digest'})),
      'KERNEL_RECOVERED_WITNESS_DENIED')
 selector=witness.get('rollback_selector')
 deny(selector!=expected['rollback_selector'] or not isinstance(selector,str) or not re.fullmatch(
      r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',selector),
      'KERNEL_RECOVERED_SELECTOR_DENIED')
 directory=root/selector.lstrip('/')
 with witness_directory(directory) as (_,check_directory):
  plan=document(directory/'plan.json');receipt=document(directory/'receipt.json')
  journal=document(directory/'phase-journal.json');auth=read(directory/'rollback-auth.key')
  for path,field in ((directory/'plan.json','plan_sha256'),(directory/'receipt.json','receipt_sha256'),
                     (directory/'phase-journal.json','journal_sha256'),(witness_path,'witness_sha256')):
   deny(sha(captured[path][0])!=expected[field],'KERNEL_RECOVERED_EXPECTATION_MISMATCH')
  anchor=read(verify_path,0o644)
  deny(sha(anchor)!=CANONICAL_AUTHORITY_SHA256 or plan.get('authority_sha256')!=sha(anchor),
       'KERNEL_CANONICAL_ANCHOR_DENIED')
  try:load_pem_public_key(anchor).verify(decode(plan['signature']),canonical({k:v for k,v in plan.items() if k!='signature'}))
  except Exception as exc:raise RunnerDenied('KERNEL_RECOVERED_PLAN_SIGNATURE_DENIED') from exc
  if 'host_identity' in plan:module.verify_host_identity(root,plan)
  deny(plan.get('schema')!='SereinPublicKernelFirstInstallPlan/v1' or plan.get('target_vm_id')!='VM4010'
       or plan.get('rollback_selector')!=selector
       or plan.get('current_boot_id')!=witness.get('boot_id')
       or any(plan.get(k)!=witness.get(k) for k in ('source_commit','source_tree','archive_sha256','source_receipt_sha256','release_digest')),
       'KERNEL_RECOVERED_PLAN_BINDING_DENIED')
  native=plan.get('native_identity')
  deny(not isinstance(native,dict) or not re.fullmatch(r'[0-9a-f]{16}',str(native.get('instance_id','')))
       or witness.get('native_identity')!=native,'KERNEL_RECOVERED_IDENTITY_DENIED')
  required={'schema','plan_sha256','boot_id','branch_order','prestate','replacements','rollback_selector',
            'rollback_auth_sha256','receipt_signature','receipt_digest'}
  unsigned={k:v for k,v in receipt.items() if k!='receipt_digest'}
  body={k:v for k,v in unsigned.items() if k!='receipt_signature'}
  signature=base64.urlsafe_b64encode(hmac.new(auth,canonical(body),hashlib.sha256).digest()).decode().rstrip('=')
  deny(set(receipt)!=required or receipt['schema']!='SereinPublicKernelFirstInstallReceipt/v1'
       or receipt['receipt_digest']!=sha(canonical(unsigned))
       or receipt['receipt_digest']!=witness.get('installer_receipt_sha256')
       or receipt['plan_sha256']!=sha(canonical(plan)) or receipt['boot_id']!=plan['current_boot_id']
       or receipt['branch_order']!=list(ORDER) or receipt['rollback_selector']!=selector
       or len(auth)!=32 or receipt['rollback_auth_sha256']!=sha(auth)
       or not isinstance(receipt['receipt_signature'],str) or not hmac.compare_digest(signature,receipt['receipt_signature']),
       'KERNEL_RECOVERED_RECEIPT_DENIED')
  rows=plan.get('payload');before=plan.get('target_prestate');replacements=receipt['replacements']
  deny(not isinstance(rows,list) or not rows or not isinstance(before,list) or not isinstance(replacements,list)
       or before!=receipt['prestate'],'KERNEL_RECOVERED_INVENTORY_DENIED')
  names=[]
  for row in rows:
   deny(not isinstance(row,dict) or set(row)!={'branch','source','target','bytes','sha256','mode'},
        'KERNEL_RECOVERED_INVENTORY_DENIED')
   name=row['target']
   deny(not isinstance(name,str) or '\x00' in name or not Path(name).is_absolute()
        or '..' in Path(name).parts or Path(name).as_posix()!=name or name in names or name in module.GENERATED
        or not (any(name.startswith(prefix) for prefix in module.ROOTS)
                or name in getattr(module,'RESIDENCY_TARGETS',()))
        or row['branch'] not in ORDER or row['mode'] not in {'0644','0755'}
        or type(row['bytes']) is not int or not 0<=row['bytes']<=MAX_FILE_BYTES
        or not isinstance(row['sha256'],str) or not HEX64.fullmatch(row['sha256']),
        'KERNEL_RECOVERED_INVENTORY_DENIED')
   names.append(name)
  deny([r['branch'] for r in rows]!=sorted((r['branch'] for r in rows),key=ORDER.index)
       or {r['branch'] for r in rows}!=set(ORDER),'KERNEL_RECOVERED_INVENTORY_DENIED')
  generated=list(module.GENERATED)
  expected_payload=[{**{k:r[k] for k in ('target','bytes','sha256','mode','branch')},'uid':0,'gid':0} for r in rows]
  deny(any(not isinstance(r,dict) for r in replacements)
       or [r for r in replacements if r.get('target') not in generated]!=expected_payload,
       'KERNEL_RECOVERED_INVENTORY_DENIED')
  generated_rows=[r for r in replacements if r.get('target') in generated]
  # The installed historical schema preceded policy-evidence.json. Both
  # exact old closure and today's closure still require ALL current paths absent.
  deny([r.get('target') for r in generated_rows] not in (generated,generated[:-1])
       or any(not isinstance(r,dict) or set(r)!={'target','bytes','sha256','mode','uid','gid','branch'} for r in replacements)
       or any(not isinstance(r,dict) for r in before)
       or [r.get('target') for r in before]!=[r['target'] for r in replacements],
       'KERNEL_RECOVERED_INVENTORY_DENIED')
  retained={};absent=[];by_name={r['target']:r for r in rows}
  def check_target(prior):
   name=prior['target']
   if prior.get('state')=='ABSENT':
    deny(set(prior)!={'target','state'},'KERNEL_RECOVERED_PRESTATE_DENIED')
    deny(module.target_prestate(root,{'target':name},generated=True)!=prior,'KERNEL_RECOVERED_RESIDUE_DENIED')
   else:
    deny(name not in by_name or set(prior)!={'target','state','bytes','sha256','mode','uid','gid','device','inode','nlink'}
         or prior.get('state')!='PRESENT_PRESERVED','KERNEL_RECOVERED_PRESTATE_DENIED')
    result=module.target_prestate(root,by_name[name],include_bytes=True)
    deny(not isinstance(result,tuple) or result[0]!=prior,'KERNEL_RECOVERED_PRESTATE_CHANGED')
    return result[1]
  for prior in before:
   raw=check_target(prior)
   if raw is not None:retained[prior['target']]={'prestate':dict(prior),'content':raw}
   else:absent.append(prior['target'])
  ownership=journal.get('ownership')
  deny(set(journal)!={'schema','receipt_digest','state','completed','ownership'}
       or journal['schema']!='SereinKernelRollbackJournal/v1' or journal['receipt_digest']!=receipt['receipt_digest']
       or journal['state']!='ROLLBACK_COMPLETE' or not isinstance(ownership,list),
       'KERNEL_RECOVERED_JOURNAL_DENIED')
  for item in ownership:
   deny(not isinstance(item,dict) or set(item)!={'target','device','inode','temporary'}
        or item['target'] not in absent or type(item['device']) is not int or item['device']<0
        or type(item['inode']) is not int or item['inode']<=0
        or not isinstance(item['temporary'],str) or not re.fullmatch(r'\.kernel-[0-9a-f]{32}',item['temporary']),
        'KERNEL_RECOVERED_OWNERSHIP_DENIED')
  deny([item['target'] for item in ownership]!=absent
       or journal['completed']!=list(reversed(absent)),'KERNEL_RECOVERED_JOURNAL_DENIED')
  def check_absence():
   for name in generated:
    module.target_prestate(root,{'target':name},generated=True)
   for item in ownership:
    name=str(Path(item['target']).parent/item['temporary'])
    module.target_prestate(root,{'target':name},generated=True)
  check_absence()
  for prior in before:
   raw=check_target(prior)
   if raw is not None:deny(raw!=retained[prior['target']]['content'],'KERNEL_RECOVERED_PRESTATE_CHANGED')
  check_absence();check_directory()
  for path,(raw,fact,mode) in captured.items():
   deny(regular(path,expected_custody=(0,0,mode))!=raw
        or regular(path,fact=True,expected_custody=(0,0,mode),include_identity=True)!=fact,
        'KERNEL_RECOVERED_RECORD_CHANGED')
  check_host()
  return {'rollback_selector':selector,'plan_sha256':receipt['plan_sha256'],
          'receipt_sha256':sha(captured[directory/'receipt.json'][0]),
          'receipt_digest':receipt['receipt_digest'],'journal_sha256':sha(captured[directory/'phase-journal.json'][0]),
          'witness_sha256':sha(captured[witness_path][0]),'reserved_domain_id':native['instance_id'],
          'retained':retained,'absent':absent,'state':'RECOVERED_PRESTATE_ONLY_NOT_ADMISSION'}

def build_plan(source=SOURCE,request_path=REQUEST,host_path=HOST_STATE,verify_path=VERIFY_KEY,source_receipt_path=SOURCE_RECEIPT,*,root=Path('/')):
 # Source code is loaded while collecting its native installer prestate.
 # Authenticate the canonical anchor before any such execution, not only
 # later when run() signs the finished plan.
 deny(sha(regular(verify_path))!=CANONICAL_AUTHORITY_SHA256,"KERNEL_CANONICAL_ANCHOR_DENIED")
 request=install_request(request_path)
 deny(any(not HEX40.fullmatch(str(request[x])) for x in ("source_parent","source_commit","source_tree")) or not HEX64.fullmatch(str(request["archive_sha256"])),"KERNEL_REQUEST_LINEAGE_DENIED")
 reserved=request['reserved_domain_ids']
 deny(not isinstance(reserved,list) or any(not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{16}',value) for value in reserved) or reserved!=sorted(set(reserved)),"KERNEL_NATIVE_IDENTITY_RESERVED_DENIED")
 receipt,receipt_digest=source_receipt(source,source_receipt_path,verify_path);deny(any(request[x]!=receipt[x] for x in ("repository","source_parent","source_commit","source_tree","archive_sha256")),"KERNEL_REQUEST_SOURCE_BINDING_DENIED")
 host=_settled_host_gate(host_path,current_boot())
 manifest=read_json(source/"release-manifest.json");unsigned={k:v for k,v in manifest.items() if k!="self_digest"};deny(manifest.get("self_digest")!="sha256:"+sha(canonical(unsigned)) or receipt["release_digest"]!=manifest.get("self_digest"),"KERNEL_MANIFEST_DENIED")
 installer=regular(source/"install/kernel_first_install.py");installer_rows=manifest.get("installer_files",[]);deny(not any(row==["install/kernel_first_install.py",len(installer),sha(installer),"0755"] for row in installer_rows),"KERNEL_INSTALLER_DENOMINATOR_DENIED")
 layout=read_json(source/"install-layout.json");rows=payload_rows(source,manifest,layout);deny(manifest.get("install_denominator_digest")!="sha256:"+sha(canonical(rows)),"KERNEL_DENOMINATOR_DENIED")
 plan={"schema":"SereinPublicKernelFirstInstallPlan/v1","target_vm_id":"VM4010","source_parent":request["source_parent"],"source_commit":request["source_commit"],"source_tree":request["source_tree"],"release_digest":manifest["self_digest"],"current_boot_id":host["current_boot_id"],"outpost_identity":identity("serein-outpost"),"replay_identity":identity("serein-stage1"),"payload":rows,"rollback_selector":request["rollback_selector"],"authority_sha256":sha(regular(verify_path)),"archive_sha256":request["archive_sha256"],"source_receipt_sha256":receipt_digest,"source_inventory_digest":receipt["inventory_digest"]}
 module=load_installer(source,manifest,expected_release=receipt['release_digest'])
 machine_path=Path(root)/'etc/machine-id';machine_stat=machine_path.lstat();mode=stat.S_IMODE(machine_stat.st_mode)
 deny(mode&0o022,'KERNEL_HOST_IDENTITY_CUSTODY_DENIED')
 machine_raw=regular(machine_path,expected_custody=(0,0,mode))
 try:machine_id=machine_raw.decode('ascii').strip()
 except UnicodeError as exc:raise RunnerDenied('KERNEL_HOST_IDENTITY_DENIED') from exc
 deny(not re.fullmatch(r'[0-9a-f]{32}',machine_id) or machine_id=='0'*32,'KERNEL_HOST_IDENTITY_DENIED')
 deny(machine_id!=host['latest']['host']['machine_id'],'KERNEL_HOST_IDENTITY_MISMATCH')
 machine_row={'target':'/etc/machine-id','bytes':len(machine_raw),'sha256':sha(machine_raw),'mode':format(mode,'04o')}
 plan['host_identity']={'machine_id':machine_id,'file':module.target_prestate(Path(root),machine_row,include_bytes=True)[0]}
 plan['host_projection_digest']=host['projection_digest'];plan['reserved_domain_ids']=list(reserved)
 plan['outpost_generation']=capture_outpost_generation(root)
 plan['runtime_access_prestate']=module.capture_runtime_access(root,plan)
 if 'installed_predecessor' in request:
  previous=request['installed_predecessor']
  prior_source=Path(root)/previous['source_root'].lstrip('/')
  bound={k:v for k,v in previous.items() if k not in {'source_root','source_receipt'}}
  installed=capture_installed_kernel_prestate(root,prior_source,bound,verify_path=verify_path,
      witness_path=STATE/'kernel-install-witness.json',observation_boot_id=plan['current_boot_id'],
      runtime_source=source,runtime_release=plan['release_digest'])
  prior_receipt,prior_receipt_digest=source_receipt(prior_source,
      Path(root)/previous['source_receipt'].lstrip('/'),verify_path)
  deny(prior_receipt_digest!=installed['plan']['source_receipt_sha256'],
       'KERNEL_SUCCESSOR_SOURCE_RECEIPT_DENIED')
  origin=installed['plan'].get('installation_origin',installed['plan'])
  deny(reserved!=origin['reserved_domain_ids'],'KERNEL_SUCCESSOR_RESERVED_CHANGED')
  old_targets=set(installed['public_payload']);new_targets={row['target'] for row in rows}
  deny(not old_targets<=new_targets or not new_targets-old_targets<=set(RESIDENCY_PREDECESSORS),
       'KERNEL_SUCCESSOR_PAYLOAD_SET_CHANGED')
  plan['installed_predecessor']=bound
  plan['installation_origin']=strict_json(canonical(origin))
  plan['native_identity']=dict(installed['plan']['native_identity'])
  prestate=[]
  for name in module.GENERATED:
   digest,uid,gid,mode,size,device,inode,nlink=installed['generated_prestate'][name]
   prestate.append({'target':name,'state':'PRESENT_REPLACE' if name==module.POLICY_EVIDENCE else 'PRESENT_PRESERVED',
       'sha256':digest,'uid':uid,'gid':gid,'mode':format(mode,'04o'),'bytes':size,
       'device':device,'inode':inode,'nlink':nlink})
  for row in rows:
   if row['target'] in installed['public_payload']:
    fact=installed['public_payload'][row['target']]['prestate']
    changed=any(fact[k]!=row[k] for k in ('bytes','sha256','mode'))
    prestate.append({**fact,'state':'PRESENT_REPLACE' if changed else 'PRESENT_PRESERVED'})
   else:prestate.append(_capture_added_residency_prestate(root,module,row))
  plan['target_prestate']=module.capture_install_prestate(root,rows,prestate,preserve_generated=True)
 elif 'recovered_predecessor' in request:
  recovered=capture_recovered_kernel_prestate(root,module,request['recovered_predecessor'],verify_path=verify_path,
      witness_path=STATE/'kernel-install-witness.json')
  deny(recovered['reserved_domain_id'] not in reserved,'KERNEL_RECOVERED_IDENTITY_NOT_RESERVED')
  deny(recovered['rollback_selector']==plan['rollback_selector'],'KERNEL_RECOVERED_SELECTOR_REUSE_DENIED')
  plan['recovered_predecessor']={**request['recovered_predecessor'],'reserved_domain_id':recovered['reserved_domain_id']}
  old=recovered['retained']
  deny(not set(old)<={r['target'] for r in rows},'KERNEL_RECOVERED_PAYLOAD_OMISSION_DENIED')
  prestate=[module.target_prestate(Path(root),{'target':name},generated=True) for name in module.GENERATED]
  for row in rows:
   if row['target'] in old:
    prior=old[row['target']]['prestate']
    changed=any(prior[k]!=row[k] for k in ('bytes','sha256','mode'))
    prestate.append({**prior,'state':'PRESENT_REPLACE' if changed else 'PRESENT_PRESERVED'})
   else:prestate.append(module.target_prestate(Path(root),row))
  plan['target_prestate']=module.capture_install_prestate(Path(root),rows,prestate)
 else:plan['target_prestate']=module.capture_target_prestate(Path(root),rows)
 deny(capture_outpost_generation(root)!=plan['outpost_generation'],'KERNEL_OUTPOST_GENERATION_CHANGED')
 return plan,host
def _capture_added_residency_prestate(root,module,row):
 """Absent or exact proven historical bytes only, before signing any effect."""
 name=row['target']
 deny(name not in RESIDENCY_PREDECESSORS or row['branch']!='INTERFACE',
      'KERNEL_RESIDENCY_ADOPTION_DENIED')
 size,digest,mode=RESIDENCY_PREDECESSORS[name]
 deny(row['mode']!=mode,'KERNEL_RESIDENCY_ADOPTION_DENIED')
 previous=module.target_prestate(Path(root),{'target':name,'bytes':size,'sha256':digest,'mode':mode})
 if previous['state']=='ABSENT':return previous
 changed=any(previous[key]!=row[key] for key in ('bytes','sha256','mode'))
 return {**previous,'state':'PRESENT_REPLACE' if changed else 'PRESENT_PRESERVED'}


def verify_install(root,plan,receipt,*,source):
 deny(capture_outpost_generation(root)!=plan['outpost_generation'],'KERNEL_OUTPOST_GENERATION_CHANGED')
 return _verify_install_material(root,plan,receipt,source=source)


def _verify_install_material(root,plan,receipt,*,source):
 # Read-only signed material verification, also used by exact failed-attempt
 # recovery. Normal construction separately requires its original Outpost.
 receipt_path=Path(root).joinpath(*Path(receipt["receipt"]).parts[1:]);value=read_json(receipt_path);required={"schema","plan_sha256","boot_id","branch_order","prestate","replacements","rollback_selector","rollback_auth_sha256","receipt_signature","receipt_digest"};deny(set(value)!=required or value.get("schema")!="SereinPublicKernelFirstInstallReceipt/v1","KERNEL_INSTALL_RECEIPT_SCHEMA_DENIED");digest=value.pop("receipt_digest",None);deny(digest!=sha(canonical(value)) or value.get("plan_sha256")!=sha(canonical(plan)) or value.get("boot_id")!=plan["current_boot_id"] or value.get("rollback_selector")!=plan["rollback_selector"] or value.get("branch_order")!=list(ORDER),"KERNEL_INSTALL_RECEIPT_DENIED")
 signature=value.pop("receipt_signature",None);auth=regular(receipt_path.parent/"rollback-auth.key");deny(sha(auth)!=value.get("rollback_auth_sha256") or not hmac.compare_digest(base64.urlsafe_b64encode(hmac.new(auth,canonical(value),hashlib.sha256).digest()).decode().rstrip("="),str(signature)),"KERNEL_INSTALL_RECEIPT_SIGNATURE_DENIED")
 replacements=value.get("replacements");generated={"/var/lib/serein/kernel/authority/replay.key","/var/lib/serein/kernel/authority/replay-descriptor.json","/etc/serein/kernel/replay-peer.env"}
 native=plan.get("native_identity")
 if native is not None:
  deny(not isinstance(native,dict) or any(not HEX64.fullmatch(str(native.get(key,""))) for key in ("private_sha256","registry_sha256")),"KERNEL_NATIVE_IDENTITY_BINDING_DENIED")
  generated|={"/var/lib/serein/kernel/authority/domain-identity.pem","/var/lib/serein/kernel/authority/domain-identity.json",
              "/var/lib/serein/kernel/authority/installed-policy-evidence.json"}
 expected_payload=[{**{key:row[key] for key in ("target","bytes","sha256","mode","branch")},"uid":0,"gid":0} for row in plan["payload"]];payload_rows=[row for row in replacements if isinstance(row,dict) and row.get("target") not in generated] if isinstance(replacements,list) else []
 deny(not isinstance(replacements,list) or any(not isinstance(row,dict) for row in replacements),"KERNEL_INSTALL_INVENTORY_DENIED")
 deny(not isinstance(replacements,list) or len(replacements)!=len(expected_payload)+len(generated) or payload_rows!=expected_payload or {row.get("target") for row in replacements if row.get("target") in generated}!=generated or any(set(row)!={"target","bytes","sha256","mode","uid","gid","branch"} for row in replacements),"KERNEL_INSTALL_INVENTORY_DENIED")
 generated_rows={row["target"]:row for row in replacements if row["target"] in generated};replay=plan["replay_identity"]
 deny((generated_rows["/var/lib/serein/kernel/authority/replay.key"]["mode"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["uid"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["gid"],generated_rows["/var/lib/serein/kernel/authority/replay.key"]["branch"])!=("0600",replay["uid"],replay["gid"],"AUTHORITY"),"KERNEL_REPLAY_KEY_CUSTODY_DENIED")
 for target,mode in (("/var/lib/serein/kernel/authority/replay-descriptor.json","0644"),("/etc/serein/kernel/replay-peer.env","0600")):deny((generated_rows[target]["mode"],generated_rows[target]["uid"],generated_rows[target]["gid"],generated_rows[target]["branch"])!=(mode,0,0,"AUTHORITY"),"KERNEL_GENERATED_CUSTODY_DENIED")
 if native is not None:
  for target,mode,key in (("/var/lib/serein/kernel/authority/domain-identity.pem","0600","private_sha256"),("/var/lib/serein/kernel/authority/domain-identity.json","0644","registry_sha256")):
   row=generated_rows[target]
   deny((row["mode"],row["uid"],row["gid"],row["branch"],row["sha256"])!=(mode,0,0,"AUTHORITY",native[key]),"KERNEL_NATIVE_IDENTITY_BINDING_DENIED")
  policy_target='/var/lib/serein/kernel/authority/installed-policy-evidence.json'
  row=generated_rows[policy_target]
  deny((row['mode'],row['uid'],row['gid'],row['branch'])!=('0644',0,0,'AUTHORITY'),
       'KERNEL_POLICY_EVIDENCE_CUSTODY_DENIED')
  raw=regular(Path(root)/policy_target.lstrip('/'),expected_custody=(0,0,0o644))
  document=strict_json(raw)
  policy_rows=[r for r in plan['payload'] if r['source']=='payload/serein_stage1/stage1-conversation-policy.v1.json']
  deny(len(policy_rows)!=1,'KERNEL_POLICY_EVIDENCE_BINDING_DENIED')
  expected={'schema':'SereinKernelInstalledPolicyEvidence/v1','target':'VM4010',
      'boot_id':plan['current_boot_id'],
      'source_generation':{'parent':plan['source_parent'],'commit':plan['source_commit'],'tree':plan['source_tree']},
      'release_digest':plan['release_digest'],'plan_sha256':sha(canonical(plan)),
      'manifest_sha256':sha(regular(Path(source)/'release-manifest.json')),
      'outpost_generation':plan['outpost_generation'],
      'source_receipt_sha256':plan['source_receipt_sha256'],'source_inventory_digest':plan['source_inventory_digest'],
      'native_identity':{key:native[key] for key in ('instance_id','checkpoint','registry_sha256','transaction_context')},
      'host_identity_sha256':sha(plan['host_identity']['machine_id'].encode('ascii')),
      'host_identity_file':plan['host_identity']['file'],'host_projection_digest':plan['host_projection_digest'],
      'conversation_policy':policy_rows[0],
      'payload':sorted(plan['payload'],key=lambda r:ORDER.index(r['branch'])),
      'state':'MATERIAL_BINDING_ONLY','authority_effect':'NONE','admission_effect':'NONE'}
  if 'installation_origin' in plan:
   origin=plan['installation_origin']
   expected['installation_origin']={'plan_sha256':sha(canonical(origin)),
       'source_generation':{k:origin['source_'+k] for k in ('parent','commit','tree')},
       'native_identity':{k:origin['native_identity'][k] for k in
           ('instance_id','checkpoint','registry_sha256','transaction_context')},
       'host_identity_file':dict(origin['host_identity']['file']),
       'boot_id':origin['current_boot_id']}
  deny(not isinstance(document,dict) or set(document)!={'body','signature'}
       or canonical(document)!=raw or document['body']!=expected,'KERNEL_POLICY_EVIDENCE_BINDING_DENIED')
  anchor=regular(Path(root)/'usr/share/serein/outpost/cognition-verification.pem',expected_custody=(0,0,0o644))
  deny(sha(anchor)!=plan['authority_sha256'],'KERNEL_POLICY_EVIDENCE_ANCHOR_DENIED')
  try:load_pem_public_key(anchor).verify(decode(document['signature']),canonical(expected))
  except Exception as exc:raise RunnerDenied('KERNEL_POLICY_EVIDENCE_SIGNATURE_DENIED') from exc
 prestate=plan.get("target_prestate",[{"target":row["target"],"state":"ABSENT"} for row in replacements])
 deny(not isinstance(prestate,list) or len(prestate)!=len(replacements)
      or any(not isinstance(row,dict) or row.get("target")!=replacement["target"] or row.get("state") not in {"ABSENT","PRESENT_PRESERVED","PRESENT_REPLACE"} for row,replacement in zip(prestate,replacements))
      or value.get("prestate")!=prestate,"KERNEL_INSTALL_PRESTATE_DENIED")
 preserved={row['target']:row for row in prestate if row['state']=='PRESENT_PRESERVED'}
 replaced={row['target']:row for row in prestate if row['state']=='PRESENT_REPLACE'}
 successor='installed_predecessor' in plan
 deny(bool(replaced) and not successor and 'recovered_predecessor' not in plan,'KERNEL_INSTALL_PRESTATE_DENIED')
 if successor:
  deny(set(preserved)&generated!=generated-{'/var/lib/serein/kernel/authority/installed-policy-evidence.json'}
       or set(replaced)&generated!={'/var/lib/serein/kernel/authority/installed-policy-evidence.json'},
       'KERNEL_SUCCESSOR_PRESERVATION_DENIED')
 else:
  deny(bool(set(preserved)&generated),"KERNEL_INSTALL_PRESTATE_DENIED")
  deny(bool(set(replaced)&generated),'KERNEL_INSTALL_PRESTATE_DENIED')
 for name,prior in replaced.items():
  backup=receipt_path.parent/('preimage-'+sha(name.encode()))
  raw=regular(backup,expected_custody=(0,0,0o600))
  deny((len(raw),sha(raw))!=(prior['bytes'],prior['sha256']),'KERNEL_COMPENSATION_MATERIAL_DENIED')
  held=receipt_path.parent/('retained-inode-'+sha(name.encode()))
  fact=regular(held,fact=True,expected_custody=(prior['uid'],prior['gid'],int(prior['mode'],8)),include_identity=True)
  deny(fact!=(prior['sha256'],prior['uid'],prior['gid'],int(prior['mode'],8),prior['bytes'],
              prior['device'],prior['inode'],1),'KERNEL_COMPENSATION_INODE_DENIED')
 previous=plan.get('installed_predecessor',plan.get('recovered_predecessor'))
 if previous is not None:
  raw=regular(receipt_path.parent/'predecessor-witness.json',expected_custody=(0,0,0o600))
  deny(sha(raw)!=previous['witness_sha256'],'KERNEL_COMPENSATION_WITNESS_DENIED')
  prior_selector=previous['rollback_selector']
  deny(not isinstance(prior_selector,str) or not re.fullmatch(
       r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',prior_selector),
       'KERNEL_RECOVERED_SELECTOR_DENIED')
  for filename,field in (('plan.json','plan_sha256'),('receipt.json','receipt_sha256'),('phase-journal.json','journal_sha256')):
   raw=regular(Path(root)/prior_selector.lstrip('/')/filename,expected_custody=(0,0,0o600))
   deny(sha(raw)!=previous[field],'KERNEL_RECOVERED_HISTORY_CHANGED')
 for row in replacements:
  path=Path(root).joinpath(*Path(row["target"]).parts[1:])
  # One descriptor-bound observation binds content, custody and final named
  # inode. A separate lstat/read can falsely accept a same-byte replacement.
  observed=regular(path,fact=True,expected_custody=(row['uid'],row['gid'],int(row['mode'],8)),include_identity=True)
  deny(observed[:5]!=(row['sha256'],row['uid'],row['gid'],int(row['mode'],8),row['bytes']),"KERNEL_INSTALL_INVENTORY_DENIED")
  if row['target'] in preserved:
   prior=preserved[row['target']]
   deny(any(prior.get(field)!=row[field] for field in ('bytes','sha256','mode','uid','gid'))
        or (prior.get('device'),prior.get('inode'),prior.get('nlink'))!=observed[5:],"KERNEL_PRESERVED_PRESTATE_CHANGED")
 journal=read_json(receipt_path.parent/"phase-journal.json");deny(journal.get("receipt_digest")!=digest or journal.get("state")!="INSTALLED_INACTIVE" or journal.get("completed")!=[row["target"] for row in replacements if row['target'] not in preserved],"KERNEL_INSTALL_JOURNAL_DENIED")
 return digest
def prepare_authority_observation(plan,receipt,request,*,root=Path('/'),source=SOURCE,
                                  host_path=HOST_STATE,verify_path=VERIFY_KEY,
                                  source_receipt_path=SOURCE_RECEIPT):
 """Public inputs for the existing independent observer; no start or admission.

 Reuse the signed installer plan and installed-file verifier. Do not ask the
 subject Kernel to choose its own expected source or identity. The returned
 envelope contains no private-key bytes and is consumed by the existing
 kernel_direct_witness entry only after separately governed socket startup.
 """
 from outpost.kernel_direct_witness import expected_identity
 # Snapshot caller-owned values before verification.
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt));request=strict_json(canonical(request))
 deny(not isinstance(request,dict) or set(request)!={'schema','branch','request_id','nonce','previous_evidence_digest'}
      or request['schema']!='SEREIN/KernelBranchWitnessRequest/v1'
      or request['branch']!='AUTHORITY' or request['previous_evidence_digest']!='GENESIS'
      or any(not isinstance(request[k],str) or not 0<len(request[k])<=128 for k in ('request_id','nonce')),
      'KERNEL_OBSERVATION_REQUEST_DENIED')
 anchor=regular(verify_path);boot=current_boot()
 deny(sha(anchor)!=CANONICAL_AUTHORITY_SHA256,'KERNEL_CANONICAL_ANCHOR_DENIED')
 deny(not isinstance(plan,dict) or plan.get('schema')!='SereinPublicKernelFirstInstallPlan/v1'
      or plan.get('target_vm_id')!='VM4010' or plan.get('current_boot_id')!=boot
      or plan.get('authority_sha256')!=sha(anchor),'KERNEL_OBSERVATION_PLAN_DENIED')
 try:load_pem_public_key(anchor).verify(decode(plan['signature']),canonical({k:v for k,v in plan.items() if k!='signature'}))
 except Exception as exc:raise RunnerDenied('KERNEL_PLAN_SIGNATURE_DENIED') from exc
 selector=plan.get('rollback_selector')
 deny(not isinstance(selector,str) or not re.fullmatch(r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',selector)
      or not isinstance(receipt,dict) or receipt.get('status')!='INSTALLED_INACTIVE'
      or receipt.get('receipt')!=selector+'/receipt.json','KERNEL_INSTALL_RECEIPT_DENIED')
 host=_settled_host_gate(host_path,boot)
 deny(plan.get('host_identity',{}).get('machine_id')!=host['latest']['host']['machine_id'],
      'KERNEL_HOST_IDENTITY_MISMATCH')
 def verify_machine_identity():
  binding=plan['host_identity'];row=binding.get('file')
  deny(not isinstance(row,dict) or row.get('target')!='/etc/machine-id'
       or row.get('state')!='PRESENT_PRESERVED'
       or not re.fullmatch(r'[0-9a-f]{32}',str(binding.get('machine_id','')))
       or binding['machine_id']=='0'*32,'KERNEL_HOST_IDENTITY_DENIED')
  try:
   custody=(row['uid'],row['gid'],int(row['mode'],8))
   observed=regular(Path(root)/'etc/machine-id',fact=True,
                    expected_custody=custody,include_identity=True)
   expected=(row['sha256'],*custody,row['bytes'],row['device'],row['inode'],row['nlink'])
   deny(observed!=expected,'KERNEL_HOST_IDENTITY_CHANGED')
   # The signed plan binds both the decoded identity and captured file bytes.
   # Check that relationship too; a valid signature alone is not its proof.
   raw=regular(Path(root)/'etc/machine-id',expected_custody=custody)
   deny(sha(raw)!=row['sha256'] or len(raw)!=row['bytes']
        or raw.decode('ascii').strip()!=binding['machine_id'],'KERNEL_HOST_IDENTITY_CHANGED')
  except (KeyError,TypeError,ValueError,UnicodeError) as exc:
   raise RunnerDenied('KERNEL_HOST_IDENTITY_DENIED') from exc
 verify_machine_identity()
 admitted,receipt_digest=source_receipt(source,source_receipt_path,verify_path)
 deny(any(plan.get(k)!=admitted[k] for k in ('source_commit','source_tree','archive_sha256','release_digest'))
      or plan.get('source_receipt_sha256')!=receipt_digest
      or plan.get('source_inventory_digest')!=admitted['inventory_digest'],'KERNEL_OBSERVATION_SOURCE_DENIED')
 manifest_raw=regular(source/'release-manifest.json');manifest=strict_json(manifest_raw)
 deny(manifest.get('self_digest')!=admitted['release_digest']
      or manifest['self_digest']!='sha256:'+sha(canonical({k:v for k,v in manifest.items() if k!='self_digest'})),
      'KERNEL_MANIFEST_DENIED')
 source_binding={'source_commit':plan['source_commit'],'source_tree':plan['source_tree'],
                 'canonical_manifest_digest':sha(manifest_raw)}
 installed_digest=verify_install(root,plan,receipt,source=source)
 policy_source='payload/serein_stage1/stage1-conversation-policy.v1.json'
 policy_target='/usr/lib/python3/dist-packages/serein_stage1/stage1-conversation-policy.v1.json'
 policy_rows=[row for row in plan['payload'] if row.get('source')==policy_source or row.get('target')==policy_target]
 deny(len(policy_rows)!=1,'KERNEL_OBSERVATION_POLICY_DENIED')
 policy_raw=regular(Path(root)/policy_target.lstrip('/'),expected_custody=(0,0,0o644))
 deny(policy_rows[0]!={'branch':'AUTHORITY','source':policy_source,'target':policy_target,
       'bytes':len(policy_raw),'sha256':sha(policy_raw),'mode':'0644'}
      or regular(source/policy_source)!=policy_raw,'KERNEL_OBSERVATION_POLICY_DENIED')
 source_binding['conversation_policy']={'path':policy_target,'source':policy_source,
      'sha256':sha(policy_raw),'plan_sha256':sha(canonical(plan)),
      'state':'SIGNED_INSTALLED_POLICY_NOT_RUNTIME_ADMISSION',
      'authority_effect':'NONE','admission_effect':'NONE'}
 registry_path=Path(root)/'var/lib/serein/kernel/authority/domain-identity.json'
 registry_raw=regular(registry_path,expected_custody=(0,0,0o644))
 registry=strict_json(registry_raw)
 deny(canonical(registry)!=registry_raw,'KERNEL_NATIVE_IDENTITY_BINDING_DENIED')
 identity_binding={'binding':plan.get('native_identity'),'registry':registry}
 if 'installation_origin' in plan:
  # verify_install above authenticated this exact installed policy projection.
  # Keep immutable birth identity separate from this successor's source binding.
  policy_evidence=read_json(Path(root)/'var/lib/serein/kernel/authority/installed-policy-evidence.json')
  origin=policy_evidence.get('body',{}).get('installation_origin')
  deny(not isinstance(origin,dict),'KERNEL_OBSERVATION_ORIGIN_DENIED')
  identity_binding['installation_origin']=strict_json(canonical(origin))
 expected_identity(identity_binding,anchor,source_binding)
 fresh=_settled_host_gate(host_path,boot)
 facts=lambda value:canonical({k:v for k,v in value['latest'].items() if k not in {'observed_at','evidence_digest'}})
 deny(current_boot()!=boot or regular(verify_path)!=anchor or facts(host)!=facts(fresh)
      or fresh['latest']['observed_at']<host['latest']['observed_at']
      or regular(registry_path,expected_custody=(0,0,0o644))!=registry_raw
      or source_receipt(source,source_receipt_path,verify_path)!=(admitted,receipt_digest)
      or verify_install(root,plan,receipt,source=source)!=installed_digest,'KERNEL_OBSERVATION_PRESTATE_CHANGED')
 verify_machine_identity()
 return {'source':source_binding,'identity':identity_binding,'request':request}


def consume_authority_observation(plan,receipt,request,raw,*,root=Path('/'),source=SOURCE,
                                  host_path=HOST_STATE,verify_path=VERIFY_KEY,
                                  source_receipt_path=SOURCE_RECEIPT):
 """Readback half of the installer/observer handoff; never start or sign.

 The caller must obtain raw from trusted Outpost observer execution. This
 consumer does not create that execution or upgrade untrusted uploaded bytes
 into proof of Outpost process identity. The independent observer's existing
 account and socket boundaries are unchanged.
 """
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import validate_authority_observation
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt));request=strict_json(canonical(request))
 arguments=dict(root=root,source=source,host_path=host_path,verify_path=verify_path,
                source_receipt_path=source_receipt_path)
 envelope=prepare_authority_observation(plan,receipt,request,**arguments)
 result=validate_authority_observation(raw,**envelope,boot_id=plan['current_boot_id'],
     observed_at=datetime.now(timezone.utc),anchor=regular(verify_path),
     host_machine_id=plan['host_identity']['machine_id'])
 deny(prepare_authority_observation(plan,receipt,request,**arguments)!=envelope,
      'KERNEL_OBSERVATION_PRESTATE_CHANGED')
 # Source/file revalidation may outlast the subject's freshness window.
 # Returning the initially valid result after that delay would renew evidence.
 return validate_authority_observation(raw,**envelope,boot_id=plan['current_boot_id'],
     observed_at=datetime.now(timezone.utc),anchor=regular(verify_path),
     host_machine_id=plan['host_identity']['machine_id'])


def prepare_operations_observation(plan,receipt,authority_observation,*,root=Path('/'),source=SOURCE,
                                  host_path=HOST_STATE,verify_path=VERIFY_KEY,
                                  source_receipt_path=SOURCE_RECEIPT):
 """Bind public observer input to installed files, not Operations self-report.

 Reuse the existing signed-plan/file/Host/identity handoff. The caller owns
 the actual prior Outpost execution; uploaded JSON is not process evidence.
 No service starts, signer, keys, mutable grant or domain admission here.
 """
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import validate_authority_observation
 deny(not isinstance(authority_observation,bytes) or not 0<len(authority_observation)<=131072,
      'KERNEL_AUTHORITY_PREDECESSOR_DENIED')
 prior=strict_json(authority_observation)
 deny(not isinstance(prior,dict) or not isinstance(prior.get('request'),dict),
      'KERNEL_AUTHORITY_PREDECESSOR_DENIED')
 arguments=dict(root=root,source=source,host_path=host_path,verify_path=verify_path,
                source_receipt_path=source_receipt_path)
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 path=Path(root)/'var/lib/serein/kernel/authority/installed-policy-evidence.json'
 before=regular(path,expected_custody=(0,0,0o644))
 # This handoff already performs the complete before/after installed-source
 # verification. Nesting the Authority consumer would repeat it three times
 # and can consume the signed predecessor's entire freshness window.
 envelope=prepare_authority_observation(plan,receipt,prior['request'],**arguments)
 # The shared handoff verifies the exact signed public evidence in the
 # install receipt. Re-read to bind the digest to those same verified bytes.
 deny(regular(path,expected_custody=(0,0,0o644))!=before,
      'KERNEL_OBSERVATION_PRESTATE_CHANGED')
 # Exact-file validation can outlast the predecessor's freshness window.
 # Never let the subsequent Operations observation renew signed Authority.
 observed=validate_authority_observation(authority_observation,**envelope,boot_id=plan['current_boot_id'],
     observed_at=datetime.now(timezone.utc),anchor=regular(verify_path),
     host_machine_id=plan['host_identity']['machine_id'])
 deny(observed['result']!='AUTHORITY_PHASE_A_OBSERVED','KERNEL_AUTHORITY_PREDECESSOR_DENIED')
 return {'source':envelope['source'],'identity':envelope['identity'],
         'installed_evidence_sha256':sha(before),'authority_observation':observed}


def consume_operations_observation(plan,receipt,authority_observation,raw,*,root=Path('/'),source=SOURCE,
                                  host_path=HOST_STATE,verify_path=VERIFY_KEY,
                                  source_receipt_path=SOURCE_RECEIPT):
 """Consume only the existing trusted observer's output, not uploaded proof.

 Recheck the installed closure and signed Authority predecessor on both sides.
 Operations remains unadmitted: a private listener and correlated heartbeat
 are not native identity possession or the complete Phase B contract.
 """
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import compare_operations_response
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 arguments=dict(root=root,source=source,host_path=host_path,verify_path=verify_path,
                source_receipt_path=source_receipt_path)
 envelope=prepare_operations_observation(plan,receipt,authority_observation,**arguments)
 deny(not isinstance(raw,bytes) or not 0<len(raw)<=65536,'KERNEL_OPERATIONS_OUTPUT_DENIED')
 value=strict_json(raw)
 required={'result','subject_evidence','evidence_authentication','phase_b','admission',
           'stage1','authority_effect','native_identity_possession','request','observed_at',
           'subject_bytes_sha256'}
 deny(not isinstance(value,dict) or set(value)!=required or canonical(value)!=raw,
      'KERNEL_OPERATIONS_OUTPUT_DENIED')
 request=value['request']
 deny(not isinstance(request,dict) or request.get('previous_evidence_digest')
      !=envelope['authority_observation']['observation_digest'],
      'KERNEL_OPERATIONS_PREDECESSOR_DENIED')
 def validate():
  now=datetime.now(timezone.utc)
  try:stamp=datetime.fromisoformat(value['observed_at'].replace('Z','+00:00'))
  except (ValueError,TypeError,AttributeError) as exc:
   raise RunnerDenied('KERNEL_OPERATIONS_CLOCK_DENIED') from exc
  deny(stamp.utcoffset() is None or not 0<=(now-stamp).total_seconds()<=30,
       'KERNEL_OPERATIONS_STALE')
  subject=canonical(value['subject_evidence'])
  for clock in (stamp,now):
   compared=compare_operations_response(subject,request=request,source=envelope['source'],
       boot_id=plan['current_boot_id'],installed_evidence_sha256=envelope['installed_evidence_sha256'],
       observed_at=clock)
  expected={**compared,'evidence_authentication':'ROOT_CREATED_PRIVATE_LISTENER',
            'native_identity_possession':'NOT_ESTABLISHED_BY_OPERATIONS','request':request,
            'observed_at':value['observed_at'],'subject_bytes_sha256':sha(subject)}
  deny(value!=expected,'KERNEL_OPERATIONS_OUTPUT_DENIED')
  return value
 validate()
 deny(prepare_operations_observation(plan,receipt,authority_observation,**arguments)!=envelope,
      'KERNEL_OBSERVATION_PRESTATE_CHANGED')
 return validate()


def prepare_interface_observation(plan,receipt,authority_observation,operations):
 """Same trusted handoff, bound to the original complete Operations window."""
 from datetime import datetime,timezone
 boot=current_boot();controls=operations.get('service_controls')
 deny(read_operations_service_controls()!=controls,'KERNEL_OPERATIONS_PROCESS_CHANGED')
 envelope=prepare_operations_observation(plan,receipt,authority_observation)
 # The shared handoff already brackets the complete source/installed closure.
 # Reuse its exact envelope for the original Operations samples instead of
 # repeating the same source scan inside validate_operations_lifecycle.
 deny(current_boot()!=boot or read_operations_service_controls()!=controls,
      'KERNEL_OPERATIONS_PROCESS_CHANGED')
 anchor=regular(VERIFY_KEY);now=datetime.now(timezone.utc)
 verified=_compare_operations_lifecycle(plan,authority_observation,
     operations.get('observations'),controls,envelope=envelope,boot=boot,anchor=anchor,now=now)
 deny(verified!=operations or verified['source']!=envelope['source']
      or verified['installed_evidence_sha256']!=envelope['installed_evidence_sha256'],
      'KERNEL_INTERFACE_OPERATIONS_PREDECESSOR_DENIED')
 return {**envelope,'interface_predecessor':sha(canonical(operations))}


def _compare_interface_observation(plan,envelope,raw):
 """Compare the original Interface sample after source preparation finishes."""
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import compare_interface_response
 deny(not isinstance(raw,bytes) or not 0<len(raw)<=65536,'KERNEL_INTERFACE_OUTPUT_DENIED')
 value=strict_json(raw)
 required={'result','subject_evidence','evidence_authentication','phase_c','admission',
           'stage1','authority_effect','native_identity_possession','request','observed_at','subject_bytes_sha256'}
 deny(set(value)!=required or canonical(value)!=raw,'KERNEL_INTERFACE_OUTPUT_DENIED')
 request=value['request']
 deny(not isinstance(request,dict) or request.get('previous_evidence_digest')!=envelope['interface_predecessor'],
      'KERNEL_INTERFACE_PREDECESSOR_DENIED')
 def validate():
  now=datetime.now(timezone.utc)
  try:stamp=datetime.fromisoformat(value['observed_at'].replace('Z','+00:00'))
  except (ValueError,TypeError,AttributeError) as exc:raise RunnerDenied('KERNEL_INTERFACE_CLOCK_DENIED') from exc
  deny(stamp.utcoffset() is None or not 0<=(now-stamp).total_seconds()<=30,'KERNEL_INTERFACE_STALE')
  subject=canonical(value['subject_evidence'])
  for clock in (stamp,now):
   compared=compare_interface_response(subject,request=request,source=envelope['source'],
       boot_id=plan['current_boot_id'],installed_evidence_sha256=envelope['installed_evidence_sha256'],observed_at=clock)
  expected={**compared,'evidence_authentication':'ROOT_CREATED_PRIVATE_LISTENER',
            'native_identity_possession':'NOT_ESTABLISHED_BY_INTERFACE','request':request,
            'observed_at':value['observed_at'],'subject_bytes_sha256':sha(subject)}
  deny(value!=expected,'KERNEL_INTERFACE_OUTPUT_DENIED')
  return value
 return validate()


def consume_interface_observation(plan,receipt,authority_observation,operations,raw):
 """Independent negative Interface witness, not Phase-C admission."""
 envelope=prepare_interface_observation(plan,receipt,authority_observation,operations)
 _compare_interface_observation(plan,envelope,raw)
 deny(prepare_interface_observation(plan,receipt,authority_observation,operations)!=envelope,
      'KERNEL_OBSERVATION_PRESTATE_CHANGED')
 return _compare_interface_observation(plan,envelope,raw)


def observe_installed_interface(plan,receipt,authority_observation,operations):
 return _observe_installed_branch(plan,receipt,(authority_observation,operations),branch='INTERFACE')


def _compute_expectation(expectation):
 """Copy the existing observation contract; it grants no caller authority."""
 deny(not isinstance(expectation,dict),'KERNEL_COMPUTE_EXPECTATION_REQUIRED')
 from outpost.kernel_direct_witness import validate_compute_inputs,KernelWitnessError
 try:
  expectation=strict_json(canonical(expectation))
  deny(set(expectation)!={'request','expected_provider_request_sha256','model','model_digest'},
       'KERNEL_COMPUTE_EXPECTATION_DENIED')
  validate_compute_inputs(**expectation)
 except (KernelWitnessError,TransactionError,ValueError,TypeError,OverflowError) as exc:
  raise RunnerDenied('KERNEL_COMPUTE_EXPECTATION_DENIED') from exc
 return expectation


def _compute_model(expectation):
 """Static pre-effect model selector; no request or timestamp is prebound."""
 deny(not isinstance(expectation,dict),'KERNEL_COMPUTE_EXPECTATION_REQUIRED')
 try:
  expectation=strict_json(canonical(expectation))
  deny(set(expectation)!={'model','model_digest'}
       or not isinstance(expectation['model'],str) or not expectation['model']
       or '\x00' in expectation['model'] or len(canonical(expectation))>65536
       or not isinstance(expectation['model_digest'],str)
       or re.fullmatch('[0-9a-f]{64}',expectation['model_digest']) is None,
       'KERNEL_COMPUTE_MODEL_EXPECTATION_DENIED')
 except (ValueError,TypeError,OverflowError) as exc:
  raise RunnerDenied('KERNEL_COMPUTE_MODEL_EXPECTATION_DENIED') from exc
 return expectation


def prepare_compute_observation(plan,receipt,authority_observation,operations,interface,expectation):
 """Same owner handoff after A/O/I; expectations belong to the enclosing probe.

 The complete owner must bind the request/model/provider recipe before its
 single conversation. Neither this reader nor its evidence performs inference.
 """
 expectation=_compute_expectation(expectation)
 envelope=prepare_interface_observation(plan,receipt,authority_observation,operations)
 verified=_compare_interface_observation(plan,envelope,canonical(interface))
 deny(verified!=interface,'KERNEL_COMPUTE_INTERFACE_PREDECESSOR_DENIED')
 return {**envelope,'interface_predecessor':sha(canonical(interface)),'compute_expectation':expectation}


def _bind_compute_model(plan,source,expectation=None):
 """Bind the observation's model to the existing exact source policy pre-effect.

 A syntactically valid arbitrary/oversized model cannot advance to installation
 and only then fail the observer envelope. This does not derive request facts
 from a response or grant authority to originate a conversation.
 """
 relative='payload/serein_stage1/stage1-conversation-policy.v1.json'
 raw=regular(Path(source)/relative)
 rows=[row for row in plan['payload'] if row.get('source')==relative]
 deny(len(rows)!=1 or rows[0].get('bytes')!=len(raw) or rows[0].get('sha256')!=sha(raw),
      'KERNEL_COMPUTE_POLICY_SOURCE_DENIED')
 policy=strict_json(raw)
 if expectation is None:
  deny(not isinstance(policy,dict),'KERNEL_COMPUTE_POLICY_MODEL_DENIED')
  expectation=_compute_model({key:policy.get(key) for key in ('model','model_digest')})
 deny(not isinstance(policy,dict) or policy.get('schema') not in ('SereinStage1ConversationPolicy/v1','SereinStage1ConversationPolicy/v2')
      or expectation['model']!=policy.get('model')
      or expectation['model_digest']!=policy.get('model_digest'),
      'KERNEL_COMPUTE_POLICY_MODEL_DENIED')
 # Reject inputs already too large for the fixed envelope before any start.
 # Unknown future signed observations are deliberately empty here: this is a
 # lower bound, never a fabricated observation or a guarantee of final size.
 # Keep the actual whole-envelope check at delivery as well.
 minimum={'source':{'source_commit':plan['source_commit'],'source_tree':plan['source_tree'],
     'canonical_manifest_digest':'0'*64,'conversation_policy':{
         'path':'/usr/lib/python3/dist-packages/serein_stage1/stage1-conversation-policy.v1.json',
         'source':relative,'sha256':sha(raw),'plan_sha256':'0'*64,
         'state':'SIGNED_INSTALLED_POLICY_NOT_RUNTIME_ADMISSION',
         'authority_effect':'NONE','admission_effect':'NONE'}},
     'identity':{},'installed_evidence_sha256':'0'*64,'authority_observation':{},
     'interface_predecessor':'0'*64,'compute_expectation':expectation}
 deny(len(canonical(minimum))>65536,'KERNEL_COMPUTE_PREFLIGHT_ENVELOPE_BOUND_DENIED')
 return expectation


def consume_compute_observation(plan,receipt,authority_observation,operations,interface,expectation,raw):
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import compare_retained_compute_response
 envelope=prepare_compute_observation(plan,receipt,authority_observation,operations,interface,expectation)
 deny(not isinstance(raw,bytes) or not 0<len(raw)<=65536,'KERNEL_COMPUTE_OUTPUT_DENIED')
 value=strict_json(raw)
 deny(not isinstance(value,dict) or canonical(value)!=raw,'KERNEL_COMPUTE_OUTPUT_DENIED')
 request=value.get('request')
 deny(not isinstance(request,dict) or request.get('previous_evidence_digest')!=envelope['interface_predecessor'],
      'KERNEL_COMPUTE_PREDECESSOR_DENIED')
 def validate():
  host=current_host_gate(HOST_STATE,plan['current_boot_id'])
  boot=current_boot();controls=read_operations_service_controls()
  deny(boot!=plan['current_boot_id'] or controls!=operations['service_controls'],
       'KERNEL_OPERATIONS_PROCESS_CHANGED')
  anchor=regular(VERIFY_KEY);now=datetime.now(timezone.utc)
  # Host collection can outlast the original A/O/I evidence. A newer compute
  # result never renews those prerequisites; compare their original bytes
  # after the last potentially blocking input read, without another scan.
  original_operations=_compare_operations_lifecycle(plan,authority_observation,
      operations['observations'],controls,envelope=envelope,boot=boot,anchor=anchor,now=now)
  deny(original_operations!=operations,'KERNEL_COMPUTE_OPERATIONS_PREDECESSOR_DENIED')
  original_interface=_compare_interface_observation(plan,
      {**envelope,'interface_predecessor':sha(canonical(operations))},canonical(interface))
  deny(original_interface!=interface,'KERNEL_COMPUTE_INTERFACE_PREDECESSOR_DENIED')
  try:stamp=datetime.fromisoformat(value['observed_at'].replace('Z','+00:00'))
  except (ValueError,TypeError,KeyError,AttributeError) as exc:raise RunnerDenied('KERNEL_COMPUTE_CLOCK_DENIED') from exc
  deny(stamp.utcoffset() is None or not 0<=(now-stamp).total_seconds()<=30,'KERNEL_COMPUTE_STALE')
  subject=canonical(value['subject_evidence'])
  compared=compare_retained_compute_response(subject,query=request,source=envelope['source'],
      installed_evidence_sha256=envelope['installed_evidence_sha256'],boot_id=plan['current_boot_id'],
      observed_at=now,host_state=host,**envelope['compute_expectation'])
  expected={**compared,'evidence_authentication':'ROOT_CREATED_PRIVATE_LISTENER',
      'native_identity_possession':'NOT_ESTABLISHED_BY_OPERATIONS','request':request,
      'observed_at':value['observed_at'],'subject_bytes_sha256':sha(subject)}
  deny(value!=expected,'KERNEL_COMPUTE_OUTPUT_DENIED')
  return value
 # prepare_compute_observation already verifies both sides of the complete
 # source/installed closure. This read-only comparison has no target effects;
 # a second identical full preparation only consumes the original witnesses'
 # time budget. Perform final live-input and original A/O/I checks once, after
 # that complete preparation; never reuse its result across observer calls.
 return validate()


def observe_installed_compute(plan,receipt,authority_observation,operations,interface,expectation):
 return _observe_installed_branch(plan,receipt,(authority_observation,operations,interface,expectation),branch='COMPUTE')


def prepare_gateway_observation(plan,receipt,authority_observation,operations,interface,expectation):
 """Same private observer, with metadata from the governed HAOS API proxy.

 No new signer or caller PASS. Native acquisition authentication is a separate
 required fact; this material alone cannot admit Stage 1.
 """
 expectation=strict_json(canonical(expectation))
 required={'compute_request_id','haos_event','haos_result','haos_manifest_sha256'}
 deny(not isinstance(expectation,dict) or set(expectation) not in
      (required,required|{'prior_compute_request_ids'}),'GATEWAY_EXPECTATION_DENIED')
 prior=expectation.get('prior_compute_request_ids',[])
 try:
  from uuid import UUID
  final=UUID(expectation['compute_request_id'])
  parsed=[UUID(value) for value in prior]
 except (ValueError,TypeError,AttributeError) as exc:
  raise RunnerDenied('GATEWAY_EXPECTATION_DENIED') from exc
 deny(not isinstance(prior,list) or len(prior)>9 or len(set(prior))!=len(prior)
      or str(final)!=expectation['compute_request_id'] or final.version!=4
      or any(not isinstance(value,str) or str(item)!=value or item.version!=4
             for value,item in zip(prior,parsed))
      or expectation['compute_request_id'] in prior
      or not isinstance(expectation['haos_event'],dict)
      or type(expectation['haos_event'].get('rounds')) is not int
      or expectation['haos_event']['rounds']!=len(prior)+1,
      'GATEWAY_EXPECTATION_DENIED')
 deny(len(canonical(expectation))>16384,'GATEWAY_EXPECTATION_BOUND_DENIED')
 envelope=prepare_interface_observation(plan,receipt,authority_observation,operations)
 verified=_compare_interface_observation(plan,envelope,canonical(interface))
 deny(verified!=interface,'KERNEL_COMPUTE_INTERFACE_PREDECESSOR_DENIED')
 return {**envelope,'interface_predecessor':sha(canonical(interface)),
         'gateway_expectation':{**expectation,**_bind_compute_model(plan,SOURCE)}}


def consume_gateway_observation(plan,receipt,authority_observation,operations,interface,expectation,raw):
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import compare_gateway_correlation_response
 envelope=prepare_gateway_observation(plan,receipt,authority_observation,operations,interface,expectation)
 deny(not isinstance(raw,bytes) or not 0<len(raw)<=65536,'GATEWAY_OUTPUT_DENIED')
 value=strict_json(raw)
 deny(not isinstance(value,dict) or canonical(value)!=raw,'GATEWAY_OUTPUT_DENIED')
 expected_gateway=envelope['gateway_expectation']
 request=value.get('request')
 deny(not isinstance(request,dict) or request.get('previous_evidence_digest')!=envelope['interface_predecessor']
      or request.get('compute_request_id')!=expected_gateway['compute_request_id'],
      'GATEWAY_PREDECESSOR_DENIED')
 prior_rounds=value.get('prior_rounds',[])
 prior_ids=expected_gateway.get('prior_compute_request_ids',[])
 deny(not isinstance(prior_rounds,list) or len(prior_rounds)!=len(prior_ids)
      or any(not isinstance(row,dict) or set(row)!={'response','query'}
             or not isinstance(row['response'],dict) or not isinstance(row['query'],dict)
             for row in prior_rounds)
      or [row['query'].get('compute_request_id') for row in prior_rounds]!=prior_ids
      or any(row['query'].get('previous_evidence_digest')!=envelope['interface_predecessor']
             for row in prior_rounds),'GATEWAY_PREDECESSOR_DENIED')
 host=current_host_gate(HOST_STATE,plan['current_boot_id'])
 boot=current_boot();controls=read_operations_service_controls();anchor=regular(VERIFY_KEY)
 deny(boot!=plan['current_boot_id'] or controls!=operations['service_controls'],
      'KERNEL_OPERATIONS_PROCESS_CHANGED')
 now=datetime.now(timezone.utc)
 deny(_compare_operations_lifecycle(plan,authority_observation,operations['observations'],
      controls,envelope=envelope,boot=boot,anchor=anchor,now=now)!=operations,
      'KERNEL_COMPUTE_OPERATIONS_PREDECESSOR_DENIED')
 deny(_compare_interface_observation(plan,
      {**envelope,'interface_predecessor':sha(canonical(operations))},canonical(interface))!=interface,
      'KERNEL_COMPUTE_INTERFACE_PREDECESSOR_DENIED')
 # Timestamp sampled after prerequisite reads. No returned timestamp renews
 # the actual native conversation or the earlier Authority/O/I evidence.
 now=datetime.now(timezone.utc)
 try:stamp=datetime.fromisoformat(value['observed_at'].replace('Z','+00:00'))
 except (ValueError,TypeError,KeyError,AttributeError) as exc:raise RunnerDenied('GATEWAY_CLOCK_DENIED') from exc
 deny(stamp.utcoffset() is None or not 0<=(now-stamp).total_seconds()<=30,'GATEWAY_STALE')
 subject=canonical(value['subject_evidence'])
 compared=compare_gateway_correlation_response(subject,query=request,source=envelope['source'],
     installed_evidence_sha256=envelope['installed_evidence_sha256'],boot_id=boot,observed_at=now,
     prior_rounds=prior_rounds,
     **{k:v for k,v in envelope['gateway_expectation'].items()
        if k not in {'compute_request_id','prior_compute_request_ids'}})
 expected={**compared,'evidence_authentication':'ROOT_CREATED_PRIVATE_LISTENER',
     'haos_evidence_authentication':'SEPARATE_REQUIRED',
     'native_identity_possession':'NOT_ESTABLISHED_BY_OPERATIONS','request':request,
     'observed_at':value['observed_at'],'subject_bytes_sha256':sha(subject)}
 deny(value!=expected,'GATEWAY_OUTPUT_DENIED')
 return value


def observe_installed_gateway(plan,receipt,authority_observation,operations,interface,expectation):
 """Read-only existing Outpost identity/launcher road, never a domain effect."""
 return _observe_installed_branch(plan,receipt,
     (authority_observation,operations,interface,expectation),branch='GATEWAY')


def read_authority_unit_prestate(*,cleanup=False):
 """Read only the two existing Authority units before ordered construction.

 ADAPT public_generation_transaction.read_bootstrap_unit's fixed systemctl
 property road. Newly placed units can require daemon-reload: report that
 fact, never perform it here or mistake it for installation/admission.
 This supplies lifecycle prestate, not permission to start a partial domain.
 """
 return _read_kernel_units(AUTHORITY_UNITS,allow_transitional=cleanup)


def read_other_kernel_unit_prestate(*,cleanup=False):
 """Observe existing Operations/Interface units; no lifecycle effects."""
 return _read_kernel_units(OTHER_KERNEL_UNITS,allow_transitional=cleanup)


def read_kernel_enablement_prestate(root):
 """Retain existing Kernel dependency links; never enable/disable a unit.

 A missing unit has no manager UnitFileState even when its old .wants link
 remains. Placing its exact file can reveal enabled without an enable call.
 Only an unchanged, root-owned canonical dependency link explains that state.
 """
 root=Path(root);names=set(AUTHORITY_UNITS+OTHER_KERNEL_UNITS);rows=[]
 for relative in ('etc/systemd/system','run/systemd/system'):
  base=root/relative
  if not os.path.lexists(base):continue
  cursor=root
  for part in Path(relative).parts:
   cursor/=part;info=cursor.lstat()
   deny(not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0
        or stat.S_IMODE(info.st_mode)&0o022,'KERNEL_ENABLEMENT_CUSTODY_DENIED')
  def walk_error(error):raise RunnerDenied('KERNEL_ENABLEMENT_READ_DENIED') from error
  for directory,dirs,files in os.walk(base,followlinks=False,onerror=walk_error):
   for name in sorted(dirs+files):
    path=Path(directory)/name;info=path.lstat()
    if not stat.S_ISLNK(info.st_mode):continue
    target=os.readlink(path)
    if name not in names and Path(target).name not in names:continue
    logical='/'+path.relative_to(root).as_posix()
    normalized=os.path.normpath(os.path.join(os.path.dirname(logical),target))
    deny(name not in names or path.parent.parent!=base
         or normalized!='/etc/systemd/system/'+name
         or not path.parent.name.endswith(('.wants','.requires')),
         'KERNEL_ENABLEMENT_LINK_DENIED')
    cursor=base
    for part in path.parent.relative_to(base).parts:
     cursor/=part;parent=cursor.lstat()
     deny(not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or parent.st_gid!=0
          or stat.S_IMODE(parent.st_mode)&0o022,'KERNEL_ENABLEMENT_CUSTODY_DENIED')
    deny(info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1,'KERNEL_ENABLEMENT_CUSTODY_DENIED')
    fresh=path.lstat()
    fields=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,
                         value.st_mode,value.st_nlink,value.st_mtime_ns,value.st_ctime_ns)
    deny(fields(info)!=fields(fresh) or os.readlink(path)!=target,'KERNEL_ENABLEMENT_CHANGED')
    rows.append({'unit':name,'path':logical,'target':target,'fact':list(fields(info))})
 return sorted(rows,key=lambda row:row['path'])


def read_operations_service_controls():
 """Read existing manager identity/restart facts; not a recovery verdict.

 Reuse the fixed show/property road. No start, restart, reload or repair.
 Configured controls alone do not prove executed recovery or Phase B; the
 complete-domain owner must bind these facts to exact installed source and
 independent Operations/Audit observations on the same current boot.
 """
 return _read_kernel_units(OPERATIONS_SERVICES,service_controls=True)


def _verify_recovered_target_prestate(module,root,prestate):
 """Read back the authenticated compensation prestate, including key custody.

 Called only after the installer verifies the signed plan/receipt and completes
 compensation. A preserved service-owned key must retain its recorded owner;
 this comparison grants no new ownership or file mutation authority.
 """
 for row in prestate:
  absent=row['state']=='ABSENT'
  owner=(0,0) if absent else (row['uid'],row['gid'])
  observed=module.target_prestate(root,row,generated=absent,expected_owner=owner)
  deny(observed!=(row if absent else {**row,'state':'PRESENT_PRESERVED'}),
       'KERNEL_RECOVERY_PRESTATE_UNPROVEN')


def recover_failed_construction(root,source,receipt_path,expected):
 return _failed_construction(root,source,receipt_path,expected)


def observe_failed_construction(root,source,receipt_path,expected,retained_lock):
 """Authenticate the exact interrupted attempt without acquiring/releasing a lock.

 This does not admit recovery, execute compensation, or bypass normal O_EXCL.
 A legacy lock lacks original process-incarnation evidence; report that gap.
 """
 deny(not isinstance(retained_lock,dict),'KERNEL_RECOVERY_LOCK_OBSERVATION_DENIED')
 return _failed_construction(root,source,receipt_path,expected,retained_lock=retained_lock)


def _failed_construction(root,source,receipt_path,expected,*,retained_lock=None):
 """Exact failed-attempt compensation owned by the current Outpost successor.

 No restart, continuation, admission or arbitrary service action. The failed
 signed plan keeps its original Outpost identity; the executing generation is
 bound separately. Only a completely placed, never-witnessed attempt is in
 scope. An incomplete stop prevents all ACL/file compensation.
 """
 import subprocess
 root=Path(root);source=Path(source);receipt_path=Path(receipt_path)
 fields={'plan_sha256','receipt_sha256','journal_sha256','witness_sha256','request_sha256',
         'current_outpost_generation','preserved_runtime'}
 deny(os.geteuid()!=0 or not isinstance(expected,dict) or set(expected)!=fields
      or any(not HEX64.fullmatch(str(expected[k])) for k in
             ('plan_sha256','receipt_sha256','journal_sha256','witness_sha256','request_sha256')),
      'KERNEL_RECOVERY_PACKET_DENIED')
 expected=strict_json(canonical(expected));directory=receipt_path.parent
 deny(receipt_path.name!='receipt.json' or directory.parent!=root/'var/lib/serein/rollback'
      or not re.fullmatch(r'kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',directory.name),
      'KERNEL_RECOVERY_SELECTOR_DENIED')
 def read(path):return regular(path,expected_custody=(0,0,0o600))
 plan_raw=read(directory/'plan.json');receipt_raw=read(receipt_path)
 journal_raw=read(directory/'phase-journal.json')
 deny((sha(plan_raw),sha(receipt_raw),sha(journal_raw))!=tuple(expected[k] for k in
      ('plan_sha256','receipt_sha256','journal_sha256')),'KERNEL_RECOVERY_RECORD_CHANGED')
 plan=strict_json(plan_raw);receipt=strict_json(receipt_raw);journal=strict_json(journal_raw)
 anchor=regular(root/'usr/share/serein/outpost/cognition-verification.pem',expected_custody=(0,0,0o644))
 deny(sha(anchor)!=CANONICAL_AUTHORITY_SHA256 or plan.get('authority_sha256')!=sha(anchor),
      'KERNEL_RECOVERY_ANCHOR_DENIED')
 try:load_pem_public_key(anchor).verify(decode(plan['signature']),canonical({k:v for k,v in plan.items() if k!='signature'}))
 except Exception as exc:raise RunnerDenied('KERNEL_RECOVERY_SIGNATURE_DENIED') from exc
 deny(plan.get('schema')!='SereinPublicKernelFirstInstallPlan/v1'
      or plan.get('target_vm_id')!='VM4010' or plan.get('current_boot_id')!=current_boot()
      or plan.get('rollback_selector')!='/'+directory.relative_to(root).as_posix(),
      'KERNEL_RECOVERY_TARGET_DENIED')
 boot=plan['current_boot_id'];witness=root/'var/lib/serein-outpost/kernel/kernel-install-witness.json'
 request_path=root/'var/lib/serein-outpost/kernel/install-request.json'
 request_raw=read(request_path);request=install_request(request_path)
 # Both request versions produce a v1 Kernel plan; bind the original request
 # too. A v2 offline replacement has a separate recovery transaction.
 deny(sha(request_raw)!=expected['request_sha256']
      or request.get('schema')!='SereinOutpostKernelInstallRequest/v1'
      or 'offline_companion' in request or 'native_allocation' in request
      or any(request.get(k)!=plan.get(k) for k in
             ('target_vm_id','source_parent','source_commit','source_tree','archive_sha256','rollback_selector')),
      'KERNEL_RECOVERY_REQUEST_DENIED')
 witness_raw=read(witness)
 deny(sha(witness_raw)!=expected['witness_sha256'] or
      strict_json(witness_raw).get('rollback_selector')==plan['rollback_selector'],
      'KERNEL_RECOVERY_VISIBLE_WITNESS_DENIED')
 manifest=read_json(source/'release-manifest.json')
 module=load_installer(source,manifest,expected_release=plan['release_digest'])
 runtime_module=load_offline_installer(source,manifest,expected_release=plan['release_digest'])
 runtime=runtime_module.OfflineOllamaRealAdapter()
 deny(Path(runtime.root)!=root or runtime.boot_id!=boot,'KERNEL_RECOVERY_RUNTIME_DENIED')
 immutable={path:regular(root/path.lstrip('/'),fact=True) for path in IMMUTABLE_POLICY}
 links=read_kernel_enablement_prestate(root)
 def material_boundary():
  runtime.observe_runtime(expected=expected['preserved_runtime'])
  selected=(read_outpost_generation(root)[0] if retained_lock is not None else capture_outpost_generation(root))
  deny(current_boot()!=boot or selected!=expected['current_outpost_generation'],
       'KERNEL_RECOVERY_CURRENTNESS_CHANGED')
  module.verify_host_identity(root,plan)
  deny(read(directory/'plan.json')!=plan_raw or read(receipt_path)!=receipt_raw or read(request_path)!=request_raw
       or read(witness)!=witness_raw or regular(root/'usr/share/serein/outpost/cognition-verification.pem',expected_custody=(0,0,0o644))!=anchor,
       'KERNEL_RECOVERY_RECORD_CHANGED')
  deny(any(regular(root/path.lstrip('/'),fact=True)!=fact for path,fact in immutable.items())
       or read_kernel_enablement_prestate(root)!=links,'KERNEL_RECOVERY_PRESERVED_STATE_CHANGED')
  deny('sha256:'+sha(canonical(safe_tree(source)))!=plan['source_inventory_digest'],
       'KERNEL_RECOVERY_SOURCE_CHANGED')
 def installed_boundary():
  material_boundary()
  # Validate selector custody before any service effect, not during cleanup.
  checked=module.journal_read(directory,receipt['receipt_digest'])
  deny(checked!=journal or read(directory/'phase-journal.json')!=journal_raw,
       'KERNEL_RECOVERY_RECORD_CHANGED')
  _verify_install_material(root,plan,{'receipt':plan['rollback_selector']+'/receipt.json'},source=source)
  # Recheck write-ahead ownership before each service group and compensation.
  deny(not isinstance(journal.get('ownership'),list) or
       [row.get('target') for row in journal['ownership']]!=journal['completed'],
       'KERNEL_RECOVERY_OWNERSHIP_DENIED')
  for row in journal['ownership']:
   path=root/row['target'].lstrip('/');info=path.lstat()
   deny((info.st_dev,info.st_ino)!=(row['device'],row['inode']),
        'KERNEL_RECOVERY_FOREIGN_TARGET')
 if retained_lock is not None:
  from .public_generation_transaction import observe_interrupted_public_lock
  installed_boundary()
  observation=observe_interrupted_public_lock(root,expected['request_sha256'],boot,retained_lock)
  installed_boundary()
  return {'result':'FAILED_CONSTRUCTION_OBSERVED','boot_id':boot,
      'rollback_selector':plan['rollback_selector'],'plan_sha256':expected['plan_sha256'],
      'receipt_sha256':expected['receipt_sha256'],'journal_sha256':expected['journal_sha256'],
      'request_sha256':expected['request_sha256'],'witness_sha256':expected['witness_sha256'],
      'current_outpost_generation':expected['current_outpost_generation'],
      'retained_lock':observation,'mutation_effect':'NONE','recovery_admitted':False,
      'stage1':'NOT_READY'}
 with public_generation_lock(root,expected['receipt_sha256'],boot):
  installed_boundary()
  before={**read_authority_unit_prestate(cleanup=True),**read_other_kernel_unit_prestate(cleanup=True)}
  stopped=set()
  def units_boundary():
   installed_boundary()
   now={**read_authority_unit_prestate(cleanup=True),**read_other_kernel_unit_prestate(cleanup=True)}
   deny(set(now)!=set(before),'KERNEL_UNIT_SET_DENIED')
   for name,row in now.items():
    deny(any(row[k]!=before[name][k] for k in ('Id','LoadState','UnitFileState','FragmentPath','DropInPaths','NeedDaemonReload')),
         'KERNEL_RECOVERY_DEFINITION_CHANGED')
    if name in stopped:deny((row['ActiveState'],row['SubState'])!=('inactive','dead'),
                           'KERNEL_RECOVERY_STOP_UNPROVEN')
  for names in (RESIDENCY_UNITS,INTERFACE_UNITS,OPERATIONS_UNITS,(AUTHORITY_UNITS[1],AUTHORITY_UNITS[0])):
   units_boundary()
   # Older complete generations did not own residency units. An absent unit
   # is already quiescent; do not turn its absence into a failed stop command.
   loaded=tuple(name for name in names if before[name]['LoadState']=='loaded')
   if loaded:
    subprocess.run(['/usr/bin/systemctl','--no-ask-password','--job-mode=replace','stop',*loaded],
        check=True,timeout=90,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
   stopped.update(names);units_boundary()
  def inactive_boundary():
   material_boundary()
   units={**read_authority_unit_prestate(),**read_other_kernel_unit_prestate()}
   deny(any((row['ActiveState'],row['SubState'])!=('inactive','dead') for row in units.values()),
        'KERNEL_RECOVERY_STOP_UNPROVEN')
  # File compensation legitimately changes the manager's definition cache;
  # retain quiescence, not the pre-removal FragmentPath/NeedDaemonReload tuple.
  installed_boundary()
  result=module.rollback(root,receipt_path,boundary=inactive_boundary)
  deny(result.get('status')!='ROLLBACK_COMPLETE' or result.get('foreign_targets_preserved'),
       'KERNEL_RECOVERY_COMPENSATION_UNPROVEN')
  material_boundary()
  subprocess.run(['/usr/bin/systemctl','--no-ask-password','daemon-reload'],check=True,timeout=90,
      stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
      close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
  material_boundary()
  units={**read_authority_unit_prestate(),**read_other_kernel_unit_prestate()}
  deny(any((row['ActiveState'],row['SubState'])!=('inactive','dead') or row['NeedDaemonReload']!='no'
           for row in units.values()),'KERNEL_RECOVERY_STOP_UNPROVEN')
  _verify_recovered_target_prestate(module,root,receipt['prestate'])
  deny(module.capture_runtime_access(root,plan)!=plan['runtime_access_prestate'],
       'KERNEL_RECOVERY_ACCESS_UNPROVEN')
  return {'result':'FAILED_CONSTRUCTION_RECOVERED','boot_id':boot,'rollback_selector':plan['rollback_selector'],
      'failed_outpost_generation':plan['outpost_generation'],
      'executing_outpost_generation':expected['current_outpost_generation'],
      'journal_sha256':sha(read(directory/'phase-journal.json')),
      'runtime_access_restored':True,'historical_witness_preserved':True,
      'kernel_admission':'UNADMITTED','authority_effect':'NONE','stage1':'NOT_READY'}


def _unit_active(name,row):
 # systemd keeps a socket active/running while its service owns the listener.
 # This is manager state only, never a domain verification/admission verdict.
 return row['ActiveState']=='active' and row['SubState'] in (
     {'listening','running'} if name.endswith('.socket') else
     {'waiting','running','elapsed'} if name==RESIDENCY_UNITS[0] else {'running'})


def _read_kernel_units(names,*,service_controls=False,allow_transitional=False,retirement_controls=False,retirement_prestate=False):
 import subprocess
 deny(type(service_controls) is not bool or type(allow_transitional) is not bool
      or type(retirement_controls) is not bool or type(retirement_prestate) is not bool
      or (service_controls and (retirement_controls or retirement_prestate))
      or (service_controls and allow_transitional) or
      (names not in (OPERATIONS_SERVICES,OPERATIONS_ENDPOINT[:1]) if service_controls else names not in (AUTHORITY_UNITS,OTHER_KERNEL_UNITS,RESIDENCY_UNITS)),
      'KERNEL_UNIT_SET_DENIED')
 properties=('Id','LoadState','ActiveState','SubState','UnitFileState',
             'FragmentPath','DropInPaths','NeedDaemonReload')
 if service_controls:
  properties+=('MainPID','ExecMainStartTimestampMonotonic','InvocationID','User','Group',
               'Restart','RestartUSec','NRestarts','Result','KillMode')
 captured={}
 for name in names:
  selected_properties=properties
  if retirement_controls or retirement_prestate:
   selected_properties+=('Job',)
   if name.endswith('.service'):selected_properties+=('MainPID','ControlPID','ControlGroup')
  try:
   result=subprocess.run(['/usr/bin/systemctl','show','--all','--no-pager',
       '--property='+','.join(selected_properties),name],capture_output=True,text=True,
       timeout=15,check=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
       stdin=subprocess.DEVNULL,close_fds=True)
  except (OSError,subprocess.SubprocessError) as exc:
   raise RunnerDenied('KERNEL_AUTHORITY_UNIT_READ_DENIED') from exc
  deny(len(result.stdout)>16384,'KERNEL_AUTHORITY_UNIT_PRESTATE_DENIED')
  value={}
  for line in result.stdout.splitlines():
   key,separator,item=line.partition('=')
   deny(not separator or key in value,'KERNEL_AUTHORITY_UNIT_PRESTATE_DENIED')
   value[key]=item
  deny(set(value)!=set(selected_properties) or value['Id']!=name
       or value['LoadState'] not in {'loaded','not-found'}
       or value['NeedDaemonReload'] not in {'yes','no'} or value['DropInPaths']
       or not value['ActiveState'] or not value['SubState'],
       'KERNEL_AUTHORITY_UNIT_PRESTATE_DENIED')
  if value['LoadState']=='not-found':
   # systemd retains failed evidence after removing a unit and daemon-reload.
   # Recognize it only in retirement, with native absence of jobs/processes;
   # this is never Kernel readiness or permission to reset failed history.
   absent_state=(value['ActiveState'],value['SubState'])==('inactive','dead')
   retained_failure=((retirement_controls or retirement_prestate)
                     and (value['ActiveState'],value['SubState'])==('failed','failed'))
   deny(value['FragmentPath'] or value['UnitFileState']
        or not (absent_state or retained_failure),
        'KERNEL_AUTHORITY_UNIT_PRESTATE_DENIED')
  else:
   fragment=('serein-kernel-client-gateway@.service'
             if name=='serein-kernel-client-gateway@haos.service' else name)
   deny(value['FragmentPath']!='/etc/systemd/system/'+fragment or not value['UnitFileState'],
        'KERNEL_AUTHORITY_UNIT_PRESTATE_DENIED')
   settled=_unit_active(name,value) or (name==RESIDENCY_UNITS[1] and
           (value['ActiveState'],value['SubState'])==('activating','start')) or (value['ActiveState'],value['SubState']) in {
           ('inactive','dead'),('failed','failed')}
   # Cleanup must be able to cancel this attempt's still-pending start/stop.
   # This is NOT a ready state; only exception cleanup opts into this read.
   transitional=(allow_transitional and value['ActiveState'] in {'activating','deactivating','reloading'}
                 and re.fullmatch(r'[a-z][a-z-]{0,63}',value['SubState']))
   deny(not (settled or transitional)
        or value['UnitFileState'] not in {'enabled','disabled','static'},
        'KERNEL_AUTHORITY_UNIT_UNSETTLED_DENIED')
  if retirement_controls or (retirement_prestate and value['LoadState']=='not-found'):
   deny(value['ActiveState'] not in {'inactive','failed'} or value['Job']
        or (name.endswith('.service') and (value['MainPID']!='0' or value['ControlPID']!='0'
                                         or value['ControlGroup'])),
        'KERNEL_RETIREMENT_QUIESCENCE_DENIED')
  if service_controls:
   deny(any(not re.fullmatch(r'[0-9]{1,20}',value[key]) for key in
            ('MainPID','ExecMainStartTimestampMonotonic','NRestarts'))
        or (value['InvocationID']!='' and not re.fullmatch(r'[0-9a-f]{32}',value['InvocationID'])),
        'KERNEL_OPERATIONS_CONTROL_SHAPE_DENIED')
   if value['LoadState']=='loaded':
    deny(value['User']!='serein-stage1' or value['Group']!='serein-stage1'
         or not value['Restart'] or not value['RestartUSec'] or not value['Result']
         or not value['KillMode'],'KERNEL_OPERATIONS_CONTROL_IDENTITY_DENIED')
    if value['ActiveState']=='active':
     deny(int(value['MainPID'])<=0 or int(value['ExecMainStartTimestampMonotonic'])<=0
          or value['InvocationID'] in {'','0'*32},'KERNEL_OPERATIONS_CONTROL_PROCESS_DENIED')
  captured[name]=value
 return captured


def observe_installed_authority(plan,receipt,request):
 """Execute the existing read-only observer, never start its Kernel subject.

 Called only by the governed root installer after the complete-domain owner
 has made the Authority socket available. This does not activate a branch,
 sign, admit, change a selector, or create a service. Public inputs and bounded
 public output cross the existing root-installer / Outpost-observer boundary.
 """
 return _observe_installed_branch(plan,receipt,request,branch='AUTHORITY')


class _KernelLifecycleOwnership:
 """Retain constituent cleanup until the whole transaction exits successfully.

 Normal context exit verifies one phase; it does not commit that phase alone.
 An outer exit failure must still quiesce its already-exited dependants first.
 """
 def __init__(self):
  self.cleanups=[];self.checks=[];self.closed=False;self.failure=None
 def retain(self,cleanup,verify=None):
  deny(self.closed,'KERNEL_LIFECYCLE_OWNER_CLOSED')
  self.cleanups.append(cleanup)
  if verify is not None:self.checks.append(verify)
 def verify(self):
  deny(self.closed,'KERNEL_LIFECYCLE_OWNER_CLOSED')
  for check in self.checks:check()
 def abort(self):
  if self.failure is not None:raise self.failure
  if self.closed:return
  self.closed=True
  while self.cleanups:
   cleanup=self.cleanups.pop()
   try:cleanup()
   except BaseException as exc:
    # Never retry an uncertain cleanup or remove its prerequisite underneath it.
    self.failure=exc
    raise
 def commit(self):
  deny(self.closed,'KERNEL_LIFECYCLE_OWNER_CLOSED')
  self.cleanups.clear();self.closed=True


@contextmanager
def _authority_lifecycle(plan,receipt,request,*,boundary,owner=None):
 """First constituent of the complete Outpost-owned Kernel transaction.

 The owner retains its generation lock and source/Host boundary throughout
 this context. Only the already-installed Authority socket is started; the
 existing socket service and independent observer supply the native witness.
 No enablement, new unit, privilege change, admission or CLI entry is added.
 A later constituent failure closes this attempt's Authority pair, not files
 or an earlier generation. The inactive-only run entry remains unchanged
 until the entire Kernel lifecycle is composed and proven.
 """
 import subprocess
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import validate_authority_observation
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 request=strict_json(canonical(request));boot=current_boot()
 deny(os.geteuid()!=0 or boot!=plan.get('current_boot_id'),
      'KERNEL_AUTHORITY_LIFECYCLE_TARGET_DENIED')
 boundary()
 # This verifies the whole installed package, signed source and plan, Host,
 # immutable identity and exact observer inputs before any service effect.
 envelope=prepare_authority_observation(plan,receipt,request)
 anchor=regular(VERIFY_KEY)
 before=read_authority_unit_prestate();other=read_other_kernel_unit_prestate()
 deny(set(before)!=set(AUTHORITY_UNITS) or set(other)!=set(OTHER_KERNEL_UNITS),
      'KERNEL_UNIT_SET_DENIED')
 for row in (*before.values(),*other.values()):
  deny(row['LoadState']!='loaded' or row['NeedDaemonReload']!='no'
       or (row['ActiveState'],row['SubState'])!=('inactive','dead'),
       'KERNEL_AUTHORITY_LIFECYCLE_PRESTATE_DENIED')
 def command(action,names):
  # Names/actions are internal constants, never derived from a request.
  try:
   subprocess.run(['/usr/bin/systemctl','--no-ask-password','--job-mode=fail'
       if action=='start' else '--job-mode=replace',action,*names],
       check=True,timeout=90,stdin=subprocess.DEVNULL,
       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,
       env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
  except (OSError,subprocess.SubprocessError) as exc:
   raise RunnerDenied('KERNEL_AUTHORITY_LIFECYCLE_COMMAND_FAILED') from exc
 def unchanged_definitions(rows):
  deny(set(rows)!=set(before),'KERNEL_UNIT_SET_DENIED')
  for name,row in rows.items():
   deny(any(row[key]!=before[name][key] for key in
       ('Id','LoadState','UnitFileState','FragmentPath','DropInPaths','NeedDaemonReload')),
       'KERNEL_AUTHORITY_LIFECYCLE_DEFINITION_CHANGED')
 boundary()
 deny(current_boot()!=boot or read_authority_unit_prestate()!=before
      or read_other_kernel_unit_prestate()!=other,
      'KERNEL_AUTHORITY_LIFECYCLE_PRESTATE_CHANGED')
 def stop_owned():
  deny(current_boot()!=boot,'KERNEL_AUTHORITY_LIFECYCLE_CLEANUP_BOOT_CHANGED')
  unchanged_definitions(read_authority_unit_prestate(cleanup=True))
  command('stop',(AUTHORITY_UNITS[1],AUTHORITY_UNITS[0]))
  stopped=read_authority_unit_prestate();unchanged_definitions(stopped)
  deny(any((row['ActiveState'],row['SubState'])!=('inactive','dead')
           for row in stopped.values()),'KERNEL_AUTHORITY_LIFECYCLE_STOP_UNPROVEN')
 def verify_owned():
  boundary()
  deny(current_boot()!=boot,'KERNEL_AUTHORITY_LIFECYCLE_BOOT_CHANGED')
  final=read_authority_unit_prestate();unchanged_definitions(final)
  deny(not _unit_active(AUTHORITY_UNITS[1],final[AUTHORITY_UNITS[1]])
       or final[AUTHORITY_UNITS[0]]['ActiveState']=='failed',
       'KERNEL_AUTHORITY_LIFECYCLE_CONTINUITY_UNPROVEN')
 if owner is not None:owner.retain(stop_owned,verify_owned)
 try:
  command('start',(AUTHORITY_UNITS[1],))
  after=read_authority_unit_prestate();unchanged_definitions(after)
  deny(current_boot()!=boot or read_other_kernel_unit_prestate()!=other
       or after[AUTHORITY_UNITS[0]]['ActiveState']=='failed'
       or not _unit_active(AUTHORITY_UNITS[1],after[AUTHORITY_UNITS[1]]),
          'KERNEL_AUTHORITY_LIFECYCLE_START_UNPROVEN')
  boundary()
  observation=observe_installed_authority(plan,receipt,request)
  if observation.get('result')!='AUTHORITY_PHASE_A_OBSERVED':
   rejected=RunnerDenied('KERNEL_AUTHORITY_PHASE_A_UNPROVEN')
   rejected.observation=observation
   raise rejected
  boundary()
  current=read_authority_unit_prestate();unchanged_definitions(current)
  deny(current_boot()!=boot or read_other_kernel_unit_prestate()!=other
       or current[AUTHORITY_UNITS[0]]['ActiveState']=='failed'
       or not _unit_active(AUTHORITY_UNITS[1],current[AUTHORITY_UNITS[1]]),
          'KERNEL_AUTHORITY_LIFECYCLE_OBSERVATION_CHANGED')
  # A slow owner-boundary read must not renew an earlier signed observation.
  deny(regular(VERIFY_KEY)!=anchor,'KERNEL_CANONICAL_ANCHOR_CHANGED')
  validate_authority_observation(canonical(observation),**envelope,boot_id=boot,
      observed_at=datetime.now(timezone.utc),anchor=anchor,
      host_machine_id=plan['host_identity']['machine_id'])
  yield observation
  verify_owned()
 except BaseException:
  # Even a timed-out start can leave a manager job. A fixed stop of the pair
  # cancels that attempt before it can remain a partially running Kernel.
  # Do not touch a changed boot or a replaced unit definition.
  if owner is not None:owner.abort()
  else:stop_owned()
  raise


@contextmanager
def _operations_lifecycle(plan,receipt,authority_observation,*,boundary,owner=None):
 """Operations portion of the same complete-domain owner, after Authority.

 PRO-142's six minimum boot predicates are measured by the existing Outpost
 lifecycle observer. This is not standalone admission, generic dispatch
 authority, an executed recovery claim, or a separate installation endpoint.
 """
 import subprocess
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 boot=current_boot()
 deny(os.geteuid()!=0 or boot!=plan.get('current_boot_id'),
      'KERNEL_OPERATIONS_LIFECYCLE_TARGET_DENIED')
 boundary();prepare_operations_observation(plan,receipt,authority_observation)
 authority=read_authority_unit_prestate();before=read_other_kernel_unit_prestate()
 deny(set(authority)!=set(AUTHORITY_UNITS) or set(before)!=set(OTHER_KERNEL_UNITS),
      'KERNEL_UNIT_SET_DENIED')
 deny(any(row['LoadState']!='loaded' or row['NeedDaemonReload']!='no'
          for row in authority.values()),'KERNEL_OPERATIONS_AUTHORITY_UNAVAILABLE')
 deny(not _unit_active(AUTHORITY_UNITS[1],authority[AUTHORITY_UNITS[1]]),
      'KERNEL_OPERATIONS_AUTHORITY_UNAVAILABLE')
 for row in before.values():
  deny(row['LoadState']!='loaded' or row['NeedDaemonReload']!='no'
       or (row['ActiveState'],row['SubState'])!=('inactive','dead'),
       'KERNEL_OPERATIONS_LIFECYCLE_PRESTATE_DENIED')
 started=set();attempted=False
 def definitions(now,expected):
  deny(set(now)!=set(expected),'KERNEL_UNIT_SET_DENIED')
  for name,row in now.items():
   deny(any(row[key]!=expected[name][key] for key in
       ('Id','LoadState','UnitFileState','FragmentPath','DropInPaths','NeedDaemonReload')),
       'KERNEL_OPERATIONS_LIFECYCLE_DEFINITION_CHANGED')
 def phase_boundary():
  boundary();deny(current_boot()!=boot,'KERNEL_OPERATIONS_LIFECYCLE_BOOT_CHANGED')
  current_authority=read_authority_unit_prestate();definitions(current_authority,authority)
  deny(not _unit_active(AUTHORITY_UNITS[1],current_authority[AUTHORITY_UNITS[1]])
       or current_authority[AUTHORITY_UNITS[0]]['ActiveState']=='failed',
       'KERNEL_OPERATIONS_AUTHORITY_UNAVAILABLE')
  current=read_other_kernel_unit_prestate();definitions(current,before)
  for name,row in current.items():
   state=(row['ActiveState'],row['SubState'])
   if name in started:
    deny(not _unit_active(name,row),
         'KERNEL_OPERATIONS_LIFECYCLE_START_UNPROVEN')
   elif name=='serein-kernel-operations-api.service' and 'serein-kernel-operations-api.socket' in started:
    deny(state not in {('inactive','dead'),('active','running')},
         'KERNEL_OPERATIONS_LIFECYCLE_API_UNSETTLED')
   else:deny(state!=('inactive','dead'),'KERNEL_OPERATIONS_EARLY_CONSTITUENT_DENIED')
 def command(action,names):
  try:
   subprocess.run(['/usr/bin/systemctl','--no-ask-password',
       '--job-mode=fail' if action=='start' else '--job-mode=replace',action,*names],
       check=True,timeout=90,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
       stderr=subprocess.DEVNULL,close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
  except (OSError,subprocess.SubprocessError) as exc:
   raise RunnerDenied('KERNEL_OPERATIONS_LIFECYCLE_COMMAND_FAILED') from exc
 def stop_owned():
  if not attempted:return
  deny(current_boot()!=boot,'KERNEL_OPERATIONS_LIFECYCLE_CLEANUP_BOOT_CHANGED')
  definitions(read_other_kernel_unit_prestate(cleanup=True),before)
  command('stop',OPERATIONS_UNITS)
  stopped=read_other_kernel_unit_prestate();definitions(stopped,before)
  deny(any((stopped[name]['ActiveState'],stopped[name]['SubState'])!=('inactive','dead')
           for name in OPERATIONS_UNITS),'KERNEL_OPERATIONS_LIFECYCLE_STOP_UNPROVEN')
 phase_boundary()
 def verify_owned():
  boundary();deny(current_boot()!=boot,'KERNEL_OPERATIONS_LIFECYCLE_BOOT_CHANGED')
  deny(read_operations_service_controls()!=observation['service_controls'],
       'KERNEL_OPERATIONS_PROCESS_CHANGED')
 if owner is not None:owner.retain(stop_owned,verify_owned)
 try:
  for names in (('serein-observation-audit.socket','serein-observation-audit.service'),
                ('serein-kernel-operations-heartbeat.service',),
                ('serein-kernel-operations-api.socket',)):
   phase_boundary();attempted=True;command('start',names);started.update(names);phase_boundary()
  observation=observe_operations_lifecycle(plan,receipt,authority_observation,boundary=phase_boundary)
  if observation.get('result')!='OPERATIONS_MINIMUM_OBSERVED':
   rejected=RunnerDenied('KERNEL_OPERATIONS_MINIMUM_UNPROVEN')
   rejected.observation=observation
   raise rejected
  yield observation
  # Downstream units may now be running under the enclosing transaction. The
  # owner retains the same material guard; do not reapply the entry unit gate.
  verify_owned()
 except BaseException:
  if owner is not None:owner.abort()
  else:stop_owned()
  raise


def observe_installed_operations(plan,receipt,authority_observation):
 """Same fixed unprivileged observer, chained to its signed Authority readback.

 No unit lifecycle effect and no new privileged startup path. The owning
 complete-domain installer must provide the prior trusted observer output.
 """
 return _observe_installed_branch(plan,receipt,authority_observation,branch='OPERATIONS')


def observe_operations_lifecycle(plan,receipt,authority_observation,*,boundary=None):
 """Read the minimum Operations window inside the whole-domain owner.

 No service action, branch admission, recovery execution or source upload.
 Actual independent observers supply the samples; callers cannot substitute
 uploaded observations. Their signed Authority predecessor and installed
 closure remain mandatory. A service restart during this window invalidates
 it instead of silently joining evidence from two process generations.
 """
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import compare_operations_response,validate_authority_observation
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 boot=current_boot()
 deny(boot!=plan.get('current_boot_id'),'KERNEL_OPERATIONS_BOOT_DENIED')
 controls=read_operations_service_controls()
 for name,row in controls.items():
  deny(row['LoadState']!='loaded' or row['ActiveState']!='active'
       or row['SubState']!='running' or row['NeedDaemonReload']!='no'
       or row['Result']!='success' or row['KillMode']!='control-group',
       'KERNEL_OPERATIONS_CONTROLS_UNAVAILABLE')
  # These are the two existing, source-verified services, not a new recovery
  # capability. Restart policy availability is not proof of a restart.
  expected=('on-failure','1s') if name==OPERATIONS_SERVICES[0] else ('always','2s')
  deny((row['Restart'],row['RestartUSec'])!=expected,'KERNEL_OPERATIONS_CONTROLS_UNAVAILABLE')
 observations=[]
 for _ in range(2):
  observations.append(observe_installed_operations(plan,receipt,authority_observation))
  deny(current_boot()!=boot or read_operations_service_controls()!=controls,
       'KERNEL_OPERATIONS_PROCESS_CHANGED')
 return validate_operations_lifecycle(plan,receipt,authority_observation,
     observations,controls,boundary=boundary)


def validate_operations_lifecycle(plan,receipt,authority_observation,observations,controls,*,boundary=None):
 """Revalidate original signed samples before the next internal constituent.

 No renewed timestamps or uploaded admission labels. The same independent
 comparison is used both when collecting and when consuming the window.
 """
 from datetime import datetime,timezone
 boot=current_boot()
 deny(boot!=plan.get('current_boot_id'),'KERNEL_OPERATIONS_BOOT_DENIED')
 deny(not isinstance(observations,list) or len(observations)!=2,
      'KERNEL_OPERATIONS_WINDOW_DENIED')
 observations=strict_json(canonical({'samples':observations}))['samples']
 deny(not isinstance(controls,dict) or set(controls)!=set(OPERATIONS_SERVICES),
      'KERNEL_OPERATIONS_CONTROLS_UNAVAILABLE')
 controls=strict_json(canonical(controls))
 deny(read_operations_service_controls()!=controls,'KERNEL_OPERATIONS_PROCESS_CHANGED')
 for name,row in controls.items():
  deny(row['LoadState']!='loaded' or row['ActiveState']!='active'
       or row['SubState']!='running' or row['NeedDaemonReload']!='no'
       or row['Result']!='success' or row['KillMode']!='control-group',
       'KERNEL_OPERATIONS_CONTROLS_UNAVAILABLE')
  expected=('on-failure','1s') if name==OPERATIONS_SERVICES[0] else ('always','2s')
  deny((row['Restart'],row['RestartUSec'])!=expected,'KERNEL_OPERATIONS_CONTROLS_UNAVAILABLE')
 # The second source scan cannot renew the first sample's freshness. Recheck
 # both against the same final source-bound expectation and original clock.
 envelope=prepare_operations_observation(plan,receipt,authority_observation)
 if boundary is not None:boundary()
 deny(current_boot()!=boot or read_operations_service_controls()!=controls,
      'KERNEL_OPERATIONS_PROCESS_CHANGED')
 anchor=regular(VERIFY_KEY)
 now=datetime.now(timezone.utc)
 return _compare_operations_lifecycle(plan,authority_observation,observations,controls,
      envelope=envelope,boot=boot,anchor=anchor,now=now)


def _compare_operations_lifecycle(plan,authority_observation,observations,controls,*,envelope,boot,anchor,now):
 """Recheck original samples at a final clock without repeating source IO.

 The owning caller must already have validated the source envelope and current
 process controls. This pure comparison neither collects nor renews evidence.
 """
 from outpost.kernel_direct_witness import compare_operations_response,validate_authority_observation
 deny(boot!=plan.get('current_boot_id'),'KERNEL_OPERATIONS_BOOT_DENIED')
 deny(not isinstance(observations,list) or len(observations)!=2,
      'KERNEL_OPERATIONS_WINDOW_DENIED')
 observations=strict_json(canonical({'samples':observations}))['samples']
 deny(not isinstance(controls,dict) or set(controls)!=set(OPERATIONS_SERVICES),
      'KERNEL_OPERATIONS_CONTROLS_UNAVAILABLE')
 controls=strict_json(canonical(controls))
 for name,row in controls.items():
  deny(row['LoadState']!='loaded' or row['ActiveState']!='active'
       or row['SubState']!='running' or row['NeedDaemonReload']!='no'
       or row['Result']!='success' or row['KillMode']!='control-group',
       'KERNEL_OPERATIONS_CONTROLS_UNAVAILABLE')
  expected=('on-failure','1s') if name==OPERATIONS_SERVICES[0] else ('always','2s')
  deny((row['Restart'],row['RestartUSec'])!=expected,'KERNEL_OPERATIONS_CONTROLS_UNAVAILABLE')
 predecessor=validate_authority_observation(authority_observation,source=envelope['source'],
     identity=envelope['identity'],request=envelope['authority_observation']['request'],boot_id=boot,
     observed_at=now,anchor=anchor,host_machine_id=plan['host_identity']['machine_id'])
 deny(predecessor!=envelope['authority_observation'],'KERNEL_OPERATIONS_PREDECESSOR_DENIED')
 samples=[]
 for observed in observations:
  compared=compare_operations_response(canonical(observed['subject_evidence']),
      request=observed['request'],source=envelope['source'],boot_id=boot,
      installed_evidence_sha256=envelope['installed_evidence_sha256'],observed_at=now)
  deny(observed['request']['previous_evidence_digest']!=envelope['authority_observation']['observation_digest']
       or compared['subject_evidence']!=observed['subject_evidence'],
       'KERNEL_OPERATIONS_PREDECESSOR_DENIED')
  sample=compared['subject_evidence']['facts']['observation']
  deny('replay_continuity' not in sample,'KERNEL_OPERATIONS_CONTINUITY_UNAVAILABLE')
  # systemd reports its process start in microseconds; Operations uses the
  # same host monotonic clock in nanoseconds. Old persisted samples cannot
  # prove the current process is producing evidence.
  deny(any(sample['monotonic_ns']<=1000*int(row['ExecMainStartTimestampMonotonic'])
           for row in controls.values()),'KERNEL_OPERATIONS_PREVIOUS_PROCESS_SAMPLE')
  samples.append(sample)
 first,last=samples
 count=last['sequence']-first['sequence'];elapsed=last['monotonic_ns']-first['monotonic_ns']
 deny(count<=0 or elapsed<=0 or last['observed_at']<=first['observed_at']
      or observations[0]['request']['nonce']==observations[1]['request']['nonce'],
      'KERNEL_OPERATIONS_WINDOW_NOT_ADVANCING')
 deny(last['cadence_state']!='OBSERVED' or last['event']!='HEARTBEAT'
      or elapsed>count*1_000_000_000,'KERNEL_OPERATIONS_HEARTBEAT_FLOOR_UNPROVEN')
 return {'result':'OPERATIONS_MINIMUM_OBSERVED','boot_id':boot,
     'source':envelope['source'],'installed_evidence_sha256':envelope['installed_evidence_sha256'],
     'authority_predecessor':envelope['authority_observation']['observation_digest'],
     'observations':observations,'service_controls':controls,
     'checks':{'scheduler':'ADVANCING_AT_OR_ABOVE_60_BPM','vitals':'CURRENT_SOURCE_BOUND',
         'queues_leases':'OBSERVED_WITH_EXPLICIT_UNKNOWNS','event_audit':'SOURCE_BOUND_ACK_CORRELATED',
         'continuity':'AUTHENTICATED_RETAINED_STATE_AND_RESTART_CONTROLS_AVAILABLE'},
     'health_disposition':('EXPIRED_REQUEST_OUTCOME_UNKNOWN'
         if last['replay_continuity']['expired_reservations'] else
         'IDLE' if last['queue_depth']==0 else 'HELD_REQUEST_MATERIAL_REQUIRED'),
     'recovery_execution':'NOT_TESTED','admission':'UNADMITTED','stage1':'NOT_READY','authority_effect':'NONE'}


@contextmanager
def _interface_lifecycle(plan,receipt,authority_observation,operations,*,boundary,owner=None):
 """Open the existing private Interface inside the complete-domain owner.

 The installed HAOS owner checks its signed policy and current Operations
 before readiness. Only its source-defined private sockets/service start;
 no public listener, model load, new credentials or capability admission.
 A later caller must still prove actual Interface/GPU/Companion/Gateway
 behavior. Manager readiness is deliberately not named Interface verified.
 """
 import subprocess
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 operations=strict_json(canonical(operations));boot=current_boot()
 deny(os.geteuid()!=0 or boot!=plan.get('current_boot_id'),
      'KERNEL_INTERFACE_LIFECYCLE_TARGET_DENIED')
 boundary()
 verified=validate_operations_lifecycle(plan,receipt,authority_observation,
     operations.get('observations'),operations.get('service_controls'),boundary=boundary)
 deny(verified!=operations,'KERNEL_INTERFACE_OPERATIONS_PREDECESSOR_DENIED')
 authority=read_authority_unit_prestate();before=read_other_kernel_unit_prestate()
 deny(set(authority)!=set(AUTHORITY_UNITS) or set(before)!=set(OTHER_KERNEL_UNITS),
      'KERNEL_UNIT_SET_DENIED')
 for row in (*authority.values(),*before.values()):
  deny(row['LoadState']!='loaded' or row['NeedDaemonReload']!='no',
       'KERNEL_INTERFACE_LIFECYCLE_PRESTATE_DENIED')
 for name in INTERFACE_UNITS:
  deny((before[name]['ActiveState'],before[name]['SubState'])!=('inactive','dead'),
       'KERNEL_INTERFACE_LIFECYCLE_PRESTATE_DENIED')
 started=set();attempted=False;next_constituent=False;quiesced=False
 def definitions(current,expected):
  deny(set(current)!=set(expected),'KERNEL_UNIT_SET_DENIED')
  for name,row in current.items():
   deny(any(row[key]!=expected[name][key] for key in
       ('Id','LoadState','UnitFileState','FragmentPath','DropInPaths','NeedDaemonReload')),
       'KERNEL_INTERFACE_LIFECYCLE_DEFINITION_CHANGED')
 def current_boundary():
  boundary();deny(current_boot()!=boot,'KERNEL_INTERFACE_LIFECYCLE_BOOT_CHANGED')
  a=read_authority_unit_prestate();definitions(a,authority)
  deny(not _unit_active(AUTHORITY_UNITS[1],a[AUTHORITY_UNITS[1]])
       or a[AUTHORITY_UNITS[0]]['ActiveState']=='failed',
       'KERNEL_INTERFACE_AUTHORITY_UNAVAILABLE')
  rows=read_other_kernel_unit_prestate();definitions(rows,before)
  deny(read_operations_service_controls()!=operations['service_controls'],
       'KERNEL_OPERATIONS_PROCESS_CHANGED')
  for name,row in rows.items():
   state=(row['ActiveState'],row['SubState'])
   if name in started:
    deny(not _unit_active(name,row),
         'KERNEL_INTERFACE_LIFECYCLE_START_UNPROVEN')
   elif (name=='serein-conversation-runtime.service' and next_constituent
         and 'serein-conversation-runtime.socket' in started):
    deny(state not in {('inactive','dead'),('active','running')},
         'KERNEL_INTERFACE_RUNTIME_UNSETTLED')
   elif name in INTERFACE_UNITS:
    deny(state!=('inactive','dead'),'KERNEL_INTERFACE_EARLY_CONSTITUENT_DENIED')
   elif name.endswith('.socket'):
    deny(not _unit_active(name,row),'KERNEL_INTERFACE_OPERATIONS_UNAVAILABLE')
 def command(action,names):
  try:
   subprocess.run(['/usr/bin/systemctl','--no-ask-password',
       '--job-mode=fail' if action=='start' else '--job-mode=replace',action,*names],
       check=True,timeout=90,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
       stderr=subprocess.DEVNULL,close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
  except (OSError,subprocess.SubprocessError) as exc:
   raise RunnerDenied('KERNEL_INTERFACE_LIFECYCLE_COMMAND_FAILED') from exc
 def stop_owned():
  nonlocal quiesced
  deny(current_boot()!=boot,'KERNEL_INTERFACE_LIFECYCLE_CLEANUP_BOOT_CHANGED')
  definitions(read_other_kernel_unit_prestate(cleanup=True),before)
  command('stop',INTERFACE_UNITS)
  stopped=read_other_kernel_unit_prestate();definitions(stopped,before)
  deny(any((stopped[name]['ActiveState'],stopped[name]['SubState'])!=('inactive','dead')
           for name in INTERFACE_UNITS),'KERNEL_INTERFACE_LIFECYCLE_STOP_UNPROVEN')
  started.clear();quiesced=True
 def verify_quiesced():
  deny(not quiesced,'KERNEL_INTERFACE_NOT_QUIESCED')
  current_boundary()
 def quiesce():
  # Only this entered owner knows its fixed consumers and exact definitions.
  boundary();stop_owned();verify_quiesced()
 def start_owned():
  nonlocal attempted,quiesced
  for names in (('serein-conversation-runtime.socket',),
                ('serein-kernel-client-gateway-haos.socket','serein-kernel-client-gateway@haos.service')):
   current_boundary();attempted=True;command('start',names);started.update(names);current_boundary()
  quiesced=False
 def reopen():
  verify_quiesced();start_owned()
 current_boundary()
 def cleanup():
  if attempted:stop_owned()
 if owner is not None:owner.retain(cleanup,current_boundary)
 try:
  start_owned()
  observed=observe_installed_interface(plan,receipt,authority_observation,operations)
  deny(observed.get('result')!='PRIVATE_INTERFACE_DENIAL_CORRELATED',
       'KERNEL_INTERFACE_DENIAL_UNPROVEN')
  # Startup/source reads do not renew the original predecessor's lifetime.
  verified=validate_operations_lifecycle(plan,receipt,authority_observation,
      operations['observations'],operations['service_controls'],boundary=current_boundary)
  deny(verified!=operations,'KERNEL_INTERFACE_OPERATIONS_PREDECESSOR_DENIED')
  next_constituent=True
  yield {'result':'PRIVATE_INTERFACE_STARTED_NOT_VERIFIED','boot_id':boot,
      'source':operations['source'],'admission':'UNADMITTED','stage1':'NOT_READY',
      'public_gateway':'NOT_STARTED','compute':'NOT_PROVEN','authority_effect':'NONE',
      'denial_observation':observed,
      '_runtime_consumers':{'quiesce':quiesce,'verify_quiesced':verify_quiesced,'reopen':reopen}}
  current_boundary()
 except BaseException:
  if owner is not None:owner.abort()
  else:cleanup()
  raise


@contextmanager
def _offline_companion_lifecycle(plan,receipt,authority_observation,operations,
                                request,preparation,signed_runtime_plan,*,boundary,consumers,
                                runtime_disposition=None,owner=None):
 """Optional offline replacement, owned by the complete Kernel transaction.

 This internal constituent has no CLI or signing authority. Its enclosing
 Outpost owner supplies the already-bound signed plan after A/O/I. The public
 source's existing offline transaction owns its exact effects/compensation.
 Neither this context nor its dependency receipt admits a Kernel domain.
 """
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 preparation=strict_json(canonical(preparation))
 signed_runtime_plan=strict_json(canonical(signed_runtime_plan))
 native='native_allocation' in request
 offline=request.get('native_allocation') if native else request.get('offline_companion')
 boot=current_boot()
 deny(os.geteuid()!=0 or boot!=plan.get('current_boot_id') or not isinstance(offline,dict),
      'KERNEL_OFFLINE_LIFECYCLE_TARGET_DENIED')
 boundary()
 validated=validate_operations_lifecycle(plan,receipt,authority_observation,
     operations.get('observations'),operations.get('service_controls'),boundary=boundary)
 deny(validated!=operations,'KERNEL_OFFLINE_OPERATIONS_PREDECESSOR_DENIED')
 observed=observe_installed_interface(plan,receipt,authority_observation,operations)
 deny(observed.get('result')!='PRIVATE_INTERFACE_DENIAL_CORRELATED',
      'KERNEL_OFFLINE_INTERFACE_PREDECESSOR_DENIED')
 # Reclassify the exact current runtime prestate, never sign stale preparation
 # or use a caller-provided module in place of the admitted source generation.
 fresh=(prepare_native_companion(SOURCE,offline['expected_before_sha256'],
     offline['rollback_selector'],offline['request_id']) if native else
     prepare_offline_companion(SOURCE,Path(offline['bundle_root']),offline['expected_before'],
     offline['rollback_selector'],offline['request_id']))
 deny(fresh['plan']!=preparation['plan']
      or fresh['source_receipt_sha256']!=plan['source_receipt_sha256']
      or preparation['source_receipt_sha256']!=fresh['source_receipt_sha256']
      or fresh['plan']['source_generation']!={'commit':plan['source_commit'],'tree':plan['source_tree']}
      or fresh['plan']['boot_id']!=boot,'KERNEL_OFFLINE_PREPARATION_CHANGED')
 unsigned={**signed_runtime_plan,'signature':None}
 deny(unsigned!=fresh['plan'] or not isinstance(signed_runtime_plan.get('signature'),str)
      or not signed_runtime_plan['signature'],'KERNEL_OFFLINE_SIGNED_PLAN_DENIED')
 module=load_offline_installer(SOURCE,read_json(SOURCE/'release-manifest.json'),
      expected_release=plan['release_digest'])
 adapter=module.OfflineOllamaRealAdapter()
 runtime_mutating=False
 if runtime_disposition is None:runtime_disposition={'attempted':False,'restored':False}
 def current_boundary():
  boundary();deny(current_boot()!=boot or adapter.boot_id!=boot,'KERNEL_OFFLINE_LIFECYCLE_BOOT_CHANGED')
  deny(read_operations_service_controls()!=operations['service_controls'],'KERNEL_OPERATIONS_PROCESS_CHANGED')
  if runtime_mutating:consumers['verify_quiesced']()
 adapter.boundary=current_boundary
 current_boundary()
 def fresh_prerequisites():
  import secrets
  current_boundary()
  challenge={'schema':'SEREIN/KernelBranchWitnessRequest/v1','branch':'AUTHORITY',
      'request_id':'kernel-authority-'+secrets.token_hex(16),'nonce':secrets.token_hex(32),
      'previous_evidence_digest':'GENESIS'}
  authority=observe_installed_authority(plan,receipt,challenge)
  deny(authority.get('result')!='AUTHORITY_PHASE_A_OBSERVED',
       'KERNEL_OFFLINE_AUTHORITY_UNPROVEN')
  authority_raw=canonical(authority)
  observed_operations=observe_operations_lifecycle(plan,receipt,authority_raw,boundary=current_boundary)
  deny(observed_operations.get('result')!='OPERATIONS_MINIMUM_OBSERVED',
       'KERNEL_OFFLINE_OPERATIONS_UNPROVEN')
  interface=observe_installed_interface(plan,receipt,authority_raw,observed_operations)
  deny(interface.get('result')!='PRIVATE_INTERFACE_DENIAL_CORRELATED',
       'KERNEL_OFFLINE_INTERFACE_PREDECESSOR_DENIED')
  return authority,observed_operations
 # Source/prestate scans and runtime installation can outlive a witness.
 # Obtain actual fresh signed observations, never extend old timestamps/TTL.
 fresh_prerequisites()
 selector=Path(signed_runtime_plan['rollback_selector']);installed=None
 def cleanup():
  nonlocal runtime_mutating
  if runtime_disposition['attempted']:
   try:
    if native:runtime_disposition['native_mutating']=True
    consumers['quiesce']();runtime_mutating=True
    current_boundary()
    if installed is not None:
     if native:module.rollback_native_allocation(adapter,selector)
     else:module.rollback(adapter,selector)
    # An absent install return can mean its internal compensation failed.
    # Independently read restored prestate without retrying that mutation.
    if native:module.verify_completed_native_allocation_rollback(adapter,selector,
        expected_plan_sha256=signed_runtime_plan['plan_sha256'])
    else:module.verify_completed_rollback(adapter,selector,
        expected_plan_sha256=signed_runtime_plan['plan_sha256'])
    runtime_disposition['restored']=True
    if native:
     runtime_disposition['native_expected']=adapter.observe_runtime()
     runtime_disposition['native_mutating']=False
   except BaseException as exc:
    raise RuntimeCompensationUncertain('KERNEL_RUNTIME_COMPENSATION_UNPROVEN') from exc
 def verify_retained_runtime():
  current_boundary()
  if native and installed is not None:
   module.verify_installed_native_allocation(adapter,selector,
       expected_plan_sha256=signed_runtime_plan['plan_sha256'])
 if owner is not None:owner.retain(cleanup,verify_retained_runtime)
 try:
  # Stop socket activation and every private consumer before install; the
  # callee can compensate its own failure before returning to this owner.
  consumers['quiesce']();runtime_mutating=True;current_boundary()
  runtime_disposition.update(attempted=True,restored=False)
  if native:runtime_disposition['native_mutating']=True
  installed=(module.install_native_allocation(adapter,signed_runtime_plan,selector) if native else
      module.install(adapter,Path(offline['bundle_root']),signed_runtime_plan,selector))
  current_boundary()
  deny(installed.get('receipt_digest')!=module.receipt_digest(installed)
       or installed.get('scope')!='RUNTIME_DEPENDENCY_ONLY'
       or installed.get('rollback_complete') is not False,
       'KERNEL_OFFLINE_DEPENDENCY_RECEIPT_DENIED')
  acceptance=installed.get('acceptance')
  if native:
   verified=module.verify_installed_native_allocation(adapter,selector,
       expected_plan_sha256=signed_runtime_plan['plan_sha256'])
   runtime_disposition['native_expected']=verified['runtime']['runtime']
   runtime_disposition['native_mutating']=False
  else:
   deny(not isinstance(acceptance,dict) or acceptance.get('scope')!='RUNTIME_DEPENDENCY_ONLY'
        or acceptance.get('boot_id')!=boot
        or acceptance.get('request_id')!=signed_runtime_plan['request_id']
        or acceptance.get('source_generation')!=signed_runtime_plan['source_generation'],
        'KERNEL_OFFLINE_DEPENDENCY_ACCEPTANCE_DENIED')
   module.verify_gpu_runtime_recipe(acceptance.get('gpu_runtime_binding'),signed_runtime_plan)
  runtime_mutating=False;consumers['reopen']()
  # Collect fresh actual Operations evidence after the runtime operation; do
  # not retimestamp or reuse the earlier sample window after a long install.
  current_authority,current_operations=fresh_prerequisites()
  yield {'result':'OFFLINE_RUNTIME_DEPENDENCY_OBSERVED','receipt':installed,
      'authority':current_authority,'operations':current_operations,
      'admission':'UNADMITTED','stage1':'NOT_READY'}
  current_boundary()
  if native:module.verify_installed_native_allocation(adapter,selector,
      expected_plan_sha256=signed_runtime_plan['plan_sha256'])
 except BaseException:
  if owner is not None:owner.abort()
  else:cleanup()
  raise


def _observe_installed_branch(plan,receipt,prior,*,branch):
 import selectors,subprocess,time
 from .generation_launcher import read_selector
 deny(os.geteuid()!=0,'KERNEL_OBSERVER_CALLER_DENIED')
 deny(branch not in {'AUTHORITY','OPERATIONS','INTERFACE','COMPUTE','GATEWAY'},'KERNEL_OBSERVER_BRANCH_DENIED')
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 if branch=='AUTHORITY':
  prior=strict_json(canonical(prior))
  envelope=prepare_authority_observation(plan,receipt,prior)
 elif branch=='INTERFACE':
  envelope=prepare_interface_observation(plan,receipt,*prior)
 elif branch=='COMPUTE':
  envelope=prepare_compute_observation(plan,receipt,*prior)
 elif branch=='GATEWAY':
  envelope=prepare_gateway_observation(plan,receipt,*prior)
 else:
  envelope=prepare_operations_observation(plan,receipt,prior)
 encoded=canonical(envelope)
 deny(len(encoded)>65536,'KERNEL_OBSERVER_INPUT_BOUND_DENIED')
 selector_path=Path('/var/lib/serein-outpost/generation-state/current.json')
 generations=Path('/usr/share/serein/outpost-generations')
 launcher=Path('/usr/libexec/serein/outpost-generation-launcher')
 selector,generation=read_selector(selector_path,generations)
 deny(Path(__file__).absolute()!=generation/'install/kernel_first_install_runner.py',
      'KERNEL_OBSERVER_CALLER_GENERATION_DENIED')
 launcher_bytes=regular(launcher,expected_custody=(0,0,0o755))
 deny(launcher_bytes!=regular(generation/'install/generation_launcher.py'),
      'KERNEL_OBSERVER_LAUNCHER_DENIED')
 # Require the selected immutable generation to contain the actual callee.
 regular(generation/'outpost/kernel_direct_witness.py')
 account=identity('serein-outpost')
 deny(account['uid']<=0 or account['gid']<=0 or account['primary_gid']!=account['gid']
      or plan.get('outpost_identity')!=account,'KERNEL_OBSERVER_ACCOUNT_DENIED')
 def boundary():
  deny(read_selector(selector_path,generations)!=(selector,generation)
       or regular(launcher,expected_custody=(0,0,0o755))!=launcher_bytes
       or identity('serein-outpost')!=account,'KERNEL_OBSERVER_GENERATION_CHANGED')
 boundary()
 # CPython performs setgroups/setregid/setreuid before exec; no preexec_fn,
 # shell, inherited secret environment, inherited descriptors or root observer.
 deadline=time.monotonic()+10.0
 raw=bytearray()
 process=None
 try:
  process=subprocess.Popen([str(launcher),'outpost/kernel_direct_witness.py',
      '-' if branch in {'COMPUTE','GATEWAY'} else encoded.decode('utf-8')],
      stdin=subprocess.PIPE if branch in {'COMPUTE','GATEWAY'} else subprocess.DEVNULL,
      stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
      cwd='/',env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},
      shell=False,close_fds=True,user=account['uid'],group=account['gid'],extra_groups=(),umask=0o077)
  with selectors.DefaultSelector() as pending:
   os.set_blocking(process.stdout.fileno(),False)
   pending.register(process.stdout,selectors.EVENT_READ)
   sent=0
   if process.stdin is not None:
    os.set_blocking(process.stdin.fileno(),False)
    pending.register(process.stdin,selectors.EVENT_WRITE)
   while pending.get_map():
    remaining=deadline-time.monotonic()
    deny(remaining<=0,'KERNEL_OBSERVER_DEADLINE_DENIED')
    for key,_ in pending.select(remaining):
     if key.fileobj is process.stdin:
      sent+=os.write(key.fd,encoded[sent:sent+4096])
      if sent==len(encoded):
       pending.unregister(key.fileobj);process.stdin.close()
      continue
     chunk=os.read(key.fd,min(4096,65537-len(raw)))
     if not chunk:pending.unregister(key.fileobj)
     else:
      raw.extend(chunk)
      deny(len(raw)>65536,'KERNEL_OBSERVER_OUTPUT_BOUND_DENIED')
  remaining=deadline-time.monotonic()
  deny(remaining<=0,'KERNEL_OBSERVER_DEADLINE_DENIED')
  deny(process.wait(timeout=remaining)!=0,'KERNEL_OBSERVER_EXECUTION_DENIED')
 except subprocess.TimeoutExpired as exc:
  raise RunnerDenied('KERNEL_OBSERVER_DEADLINE_DENIED') from exc
 except OSError as exc:
  raise RunnerDenied('KERNEL_OBSERVER_EXECUTION_DENIED') from exc
 finally:
  if process is not None:
   if process.poll() is None:process.kill()
   try:process.wait(timeout=1.0)
   except subprocess.TimeoutExpired as exc:
    raise RunnerDenied('KERNEL_OBSERVER_REAP_PENDING') from exc
   finally:
    if process.stdin is not None:process.stdin.close()
    if process.stdout is not None:process.stdout.close()
 raw=bytes(raw)
 deny(not raw or not raw.endswith(b'\n'),'KERNEL_OBSERVER_OUTPUT_DENIED')
 value=strict_json(raw)
 deny(not isinstance(value,dict) or canonical(value)!=raw,'KERNEL_OBSERVER_OUTPUT_DENIED')
 boundary()
 if branch=='AUTHORITY':result=consume_authority_observation(plan,receipt,prior,raw)
 elif branch=='INTERFACE':result=consume_interface_observation(plan,receipt,*prior,raw)
 elif branch=='COMPUTE':result=consume_compute_observation(plan,receipt,*prior,raw)
 elif branch=='GATEWAY':result=consume_gateway_observation(plan,receipt,*prior,raw)
 else:result=consume_operations_observation(plan,receipt,prior,raw)
 boundary()
 deny(time.monotonic()>=deadline,'KERNEL_OBSERVER_DEADLINE_DENIED')
 return result


def prepare_kernel_request(bundle_adapter=None,*,root=Path('/'),source=SOURCE,request_path=REQUEST,
                           host_path=HOST_STATE,verify_path=VERIFY_KEY,source_receipt_path=SOURCE_RECEIPT):
 """Prepare the existing source request without installing or signing.

 The v1 source installer preserves the installed runtime and captures its
 actual process/image/model-root prestate through the source-bound reader.
 It requires no replacement archive and makes no runtime-admission claim.
 Only v2 additionally prepares the optional offline replacement. That installer
 starts inference and belongs after independently verified internal Kernel
 gates; the inactive first-install executor still rejects v2.
 """
 raw=regular(request_path);request=install_request(request_path)
 boot=current_boot()
 native=request.get('native_allocation')
 offline=request.get('offline_companion')
 if offline is not None or native is not None:
  if bundle_adapter is not None:
   deny(Path(bundle_adapter.root)!=Path(root) or bundle_adapter.boot_id!=boot,'KERNEL_OFFLINE_TARGET_DENIED')
  else:
   deny(Path(root)!=Path('/'),'KERNEL_OFFLINE_TARGET_DENIED')
 else:
  deny(bundle_adapter is not None,'KERNEL_OFFLINE_TARGET_DENIED')
 plan,host=build_plan(source,request_path,host_path,verify_path,source_receipt_path,root=root)
 prepared=None;preserved_runtime=None;runtime_adapter=None
 if native is not None:
  prepared=prepare_native_companion(source,native['expected_before_sha256'],
      native['rollback_selector'],native['request_id'],host_path=host_path,verify_path=verify_path,
      source_receipt_path=source_receipt_path,adapter=bundle_adapter)
  deny(prepared['source_receipt_sha256']!=plan['source_receipt_sha256']
       or prepared['plan']['boot_id']!=boot
       or prepared['plan']['source_generation']!={'commit':plan['source_commit'],'tree':plan['source_tree']},
       'KERNEL_OFFLINE_PREPARATION_CHANGED')
 elif offline is not None:
  prepared=prepare_offline_companion(source,Path(offline['bundle_root']),offline['expected_before'],
      offline['rollback_selector'],offline['request_id'],host_path=host_path,verify_path=verify_path,
      source_receipt_path=source_receipt_path,adapter=bundle_adapter)
  deny(prepared['source_receipt_sha256']!=plan['source_receipt_sha256']
       or prepared['plan']['boot_id']!=boot
       or prepared['plan']['source_generation']!={'commit':plan['source_commit'],'tree':plan['source_tree']},'KERNEL_OFFLINE_PREPARATION_CHANGED')
  destinations={row['target'] for row in plan['payload']}
  deny(bool(destinations&{row['target'] for row in prepared['plan']['files']+prepared['plan']['runtime_objects']}),'KERNEL_OFFLINE_TARGET_OVERLAP')
 else:
  runtime_module=load_offline_installer(source,read_json(source/'release-manifest.json'),
      expected_release=plan['release_digest'])
  runtime_adapter=runtime_module.OfflineOllamaRealAdapter()
  deny(Path(runtime_adapter.root)!=Path(root) or runtime_adapter.boot_id!=boot,
       'KERNEL_PRESERVED_RUNTIME_TARGET_DENIED')
  try:preserved_runtime=strict_json(canonical(runtime_adapter.observe_runtime()))
  except runtime_module.TransactionError as exc:
   raise RunnerDenied('KERNEL_PRESERVED_RUNTIME_UNAVAILABLE') from exc
 if runtime_adapter is not None:
  try:runtime_adapter.observe_runtime(expected=preserved_runtime)
  except runtime_module.TransactionError as exc:
   raise RunnerDenied('KERNEL_PRESERVED_RUNTIME_CHANGED') from exc
 fresh=_settled_host_gate(host_path,boot)
 facts=lambda state:canonical({k:v for k,v in state['latest'].items() if k not in {'observed_at','evidence_digest'}})
 deny(capture_outpost_generation(root)!=plan['outpost_generation'],'KERNEL_OUTPOST_GENERATION_CHANGED')
 deny(current_boot()!=boot or regular(request_path)!=raw or facts(host)!=facts(fresh)
      or fresh['latest']['observed_at']<host['latest']['observed_at']
      or source_receipt(source,source_receipt_path,verify_path)[1]!=plan['source_receipt_sha256'],'KERNEL_COMPLETE_PREPARATION_CHANGED')
 return {'kernel_plan':plan,'offline_preparation':prepared,
         'preserved_runtime':preserved_runtime,
         'host_prestate':strict_json(canonical(host)),
         'request_sha256':sha(raw),'kernel_plan_sha256':sha(canonical(plan)),
         'initial_host_projection_digest':host['projection_digest'],
         'status':'PREPARED_UNSIGNED_NOT_AUTHORIZED','authority_effect':'NONE','admission_effect':'NONE'}

def _kernel_material_boundary(plan,host_prestate,request_raw,*,root,source,
                              request_path,host_path,check_parent,preserved_runtime=None):
 """Existing source/Host guard, independent of the current lifecycle phase.

 Placement separately requires all units inactive. Ordered activation uses
 the same immutable material guard without reapplying placement's unit gate.
 This does not authorize an effect or weaken either phase's unit checks.
 """
 plan=strict_json(canonical(plan));host_prestate=strict_json(canonical(host_prestate))
 boot=plan['current_boot_id']
 host_facts=lambda state:canonical({k:v for k,v in state['latest'].items()
                                  if k not in {'observed_at','evidence_digest'}})
 expected_host_facts=host_facts(host_prestate)
 observed_at=host_prestate['latest']['observed_at'];classification=host_prestate['classification']
 immutable={path:regular(Path(root)/path.lstrip('/'),fact=True) for path in IMMUTABLE_POLICY}
 runtime_adapter=None
 if preserved_runtime is not None:
  preserved_runtime=strict_json(canonical(preserved_runtime))
  # This is preservation evidence captured by prepare_kernel_request, not a
  # runtime recipe, authority grant or permission to replace/start Ollama.
  runtime_module=load_offline_installer(source,read_json(source/'release-manifest.json'),
      expected_release=plan['release_digest'])
  runtime_adapter=runtime_module.OfflineOllamaRealAdapter()
  deny(Path(runtime_adapter.root)!=Path(root) or runtime_adapter.boot_id!=boot,
       'KERNEL_PRESERVED_RUNTIME_TARGET_DENIED')
 def boundary():
  nonlocal observed_at,classification
  # Wait before the full material pass. A request, parent, predecessor,
  # identity, source or runtime change during collection must still deny.
  observed=_settled_host_gate(host_path,boot)
  if runtime_adapter is not None:
   try:runtime_adapter.observe_runtime(expected=preserved_runtime)
   except runtime_module.TransactionError as exc:
    raise RunnerDenied('KERNEL_PRESERVED_RUNTIME_CHANGED') from exc
  # Runtime observation can be slow; it must not follow the final material
  # checks and conceal a request/Host/source/identity change during the read.
  check_parent()
  deny(current_boot()!=boot or regular(request_path)!=request_raw,'KERNEL_REQUEST_CHANGED')
  previous=plan.get('installed_predecessor',plan.get('recovered_predecessor'))
  if previous is not None:
   selector=previous['rollback_selector']
   deny(not re.fullmatch(r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',selector),
        'KERNEL_RECOVERED_SELECTOR_DENIED')
   for filename,field in (('plan.json','plan_sha256'),('receipt.json','receipt_sha256'),('phase-journal.json','journal_sha256')):
    raw=regular(Path(root)/selector.lstrip('/')/filename,expected_custody=(0,0,0o600))
    deny(sha(raw)!=previous[field],'KERNEL_RECOVERED_HISTORY_CHANGED')
  deny(capture_outpost_generation(root)!=plan['outpost_generation'],'KERNEL_OUTPOST_GENERATION_CHANGED')
  deny(host_facts(observed)!=expected_host_facts
       or observed['latest']['observed_at']<observed_at
       or observed['classification'] not in {classification,'CURRENT_BOOT_STABLE'},
       'KERNEL_HOST_PRESTATE_CHANGED')
  observed_at=observed['latest']['observed_at'];classification=observed['classification']
  deny(any(regular(Path(root)/path.lstrip('/'),fact=True)!=fact for path,fact in immutable.items()),
       'KERNEL_IMMUTABLE_CHANGED')
  deny('sha256:'+sha(canonical(safe_tree(source)))!=plan['source_inventory_digest'],
       'KERNEL_SOURCE_CHANGED_DURING_INSTALL')
 return boundary


def _observe_owned_gpu(plan,compute,preparation,*,signed_runtime_plan,boundary):
 """Retain real process/GPU binding under the existing complete owner.

 Reuse the source-bound offline runtime reader without inference, installation
 or a replacement-runtime requirement. A preserved process tuple is not a
 signed executable recipe and this observation never admits the domain.
 """
 import types
 boundary()
 relative='payload/serein_stage1/gpu_control.py'
 target='/usr/lib/python3/dist-packages/serein_stage1/gpu_control.py'
 rows=[row for row in plan['payload'] if row.get('source')==relative]
 deny(len(rows)!=1 or rows[0].get('target')!=target,'KERNEL_GPU_SOURCE_DENIED')
 row=rows[0];gpu_raw=regular(SOURCE/relative)
 deny(len(gpu_raw)!=row.get('bytes') or sha(gpu_raw)!=row.get('sha256')
      or regular(Path(target))!=gpu_raw,'KERNEL_GPU_SOURCE_DENIED')
 # Capture exact admitted bytes, never use a cached/PYTHONPATH subject module.
 gpu_module=types.ModuleType('_serein_outpost_bound_gpu')
 exec(compile(gpu_raw,target,'exec'),gpu_module.__dict__)
 module=load_offline_installer(SOURCE,read_json(SOURCE/'release-manifest.json'),
     expected_release=plan['release_digest'])
 adapter=module.OfflineOllamaRealAdapter()
 deny(Path(adapter.root)!=Path('/') or adapter.boot_id!=plan['current_boot_id']
      or current_boot()!=plan['current_boot_id'],'KERNEL_GPU_TARGET_DENIED')
 try:
  retained=compute['subject_evidence']['facts']['observation']
  raw=base64.b64decode(retained['runtime_response_b64'],validate=True)
  deny(sha(raw)!=compute['runtime_result_sha256'],'KERNEL_GPU_COMPUTE_BINDING_DENIED')
  runtime=strict_json(raw)
  gpu=gpu_module.collect()
  deny(gpu!=runtime['compute_observation']['gpu_after']
       or gpu['boot_id']!=plan['current_boot_id'],'KERNEL_GPU_INVENTORY_CHANGED')
  binding=adapter.observe_gpu_binding(gpu,gpu_module=gpu_module)
  child_policy=None
  if preparation['offline_preparation'] is None:
   preserved=preparation['preserved_runtime']
   deny(binding['runtime']!=preserved,'KERNEL_PRESERVED_RUNTIME_CHANGED')
   adapter.observe_runtime(expected=preserved)
   recipe='PRESERVED_PROCESS_NOT_SIGNED_RECIPE'
   previous=plan.get('installed_predecessor',{})
   failed=previous.get('failed_construction')
   if failed is not None:
    # The old failed receipt is source/material evidence, never a successful
    # runtime install receipt. Reuse its verified recipe only to check the
    # currently executing child; no new native effect or ownership retrofit.
    previous_plan=read_json(Path(previous['rollback_selector'])/'plan.json')
    deny(sha(canonical(previous_plan))!=previous['plan_sha256'],'KERNEL_FAILED_PLAN_CHANGED')
    retained=observe_failed_native_prestate(Path('/'),previous_plan,failed,SOURCE,
        expected_release=plan['release_digest'])
    native=retained['native_plan']
    deny(binding['runtime']!=retained['runtime']['runtime'],'KERNEL_NATIVE_RUNTIME_CHANGED')
    module.verify_gpu_runtime_recipe(binding,native,gpu_module=gpu_module)
    child_policy=adapter.observe_native_worker_policy(binding,native)
    deny(adapter.observe_gpu_binding(gpu,gpu_module=gpu_module)!=binding,
         'KERNEL_NATIVE_GPU_WORKER_CHANGED')
    recipe='FAILED_INSTALL_RETAINED_MATERIAL_AND_CHILD_CONFIGURATION_MATCH'
  else:
   deny(not isinstance(signed_runtime_plan,dict),'KERNEL_OFFLINE_SIGNED_PLAN_DENIED')
   module.verify_gpu_runtime_recipe(binding,signed_runtime_plan,gpu_module=gpu_module)
   recipe='SIGNED_RUNTIME_RECIPE_MATCH'
   if signed_runtime_plan.get('schema')==module.NATIVE_ALLOCATION_SCHEMA:
    selected=module.verify_installed_native_allocation(adapter,Path(signed_runtime_plan['rollback_selector']),
        expected_plan_sha256=signed_runtime_plan['plan_sha256'])
    deny(binding['runtime']!=selected['runtime']['runtime'],'KERNEL_NATIVE_RUNTIME_CHANGED')
    child_policy=adapter.observe_native_worker_policy(binding,signed_runtime_plan)
    deny(adapter.observe_gpu_binding(gpu,gpu_module=gpu_module)!=binding,
         'KERNEL_NATIVE_GPU_WORKER_CHANGED')
    recipe='SIGNED_NATIVE_MATERIAL_AND_CHILD_CONFIGURATION_MATCH'
  deny(gpu_module.collect()!=gpu or current_boot()!=plan['current_boot_id'],
       'KERNEL_GPU_INVENTORY_CHANGED')
  boundary()
  deny(regular(SOURCE/relative)!=gpu_raw or regular(Path(target))!=gpu_raw,
       'KERNEL_GPU_SOURCE_CHANGED')
 except (ValueError,KeyError,TypeError,OSError,module.TransactionError) as exc:
  raise RunnerDenied('KERNEL_GPU_PROCESS_BINDING_UNPROVEN') from exc
 result={'result':'RUNTIME_GPU_PROCESS_OBSERVED','binding':binding,
     'runtime_recipe':recipe,'runtime_result_sha256':compute['runtime_result_sha256'],
     'stage1':'NOT_READY','authority_effect':'NONE','admission_effect':'NONE'}
 if child_policy is not None:
  result['native_child_policy']=child_policy
 return result


@contextmanager
def _companion_residency_lifecycle(plan,*,boundary,owner):
 """Restore the proven preload/refresh path inside the whole Kernel owner.

 Historical source: Project-Serein b8760b420796ae54fa788c7bdd8be2e1f3a787e0,
 sfos/stage2/performance/haos-latency. No binary/model installation, download,
 unit enablement, public request, identity write or admission occurs here.
 Called only after Authority/Operations/Interface and runtime preparation.
 """
 import subprocess
 boot=current_boot()
 deny(os.geteuid()!=0 or boot!=plan.get('current_boot_id') or owner is None,
      'KERNEL_RESIDENCY_TARGET_DENIED')
 expected={
  'payload/bin/serein-ollama-warmup':'/usr/libexec/serein/serein-ollama-warmup',
  'payload/systemd/serein-ollama-warmup.service':'/etc/systemd/system/serein-ollama-warmup.service',
  'payload/systemd/serein-ollama-warmup.timer':'/etc/systemd/system/serein-ollama-warmup.timer'}
 for source,target in expected.items():
  rows=[row for row in plan['payload'] if row.get('source')==source]
  deny(len(rows)!=1 or rows[0].get('target')!=target or rows[0].get('branch')!='INTERFACE',
       'KERNEL_RESIDENCY_SOURCE_DENIED')
  raw=regular(SOURCE/source)
  deny(len(raw)!=rows[0].get('bytes') or sha(raw)!=rows[0].get('sha256')
       or regular(Path(target))!=raw,'KERNEL_RESIDENCY_SOURCE_DENIED')
 boundary()
 before=_read_kernel_units(RESIDENCY_UNITS)
 deny(any(row['LoadState']!='loaded' or row['NeedDaemonReload']!='no'
          or (row['ActiveState'],row['SubState'])!=('inactive','dead')
          for row in before.values()),'KERNEL_RESIDENCY_PRESTATE_DENIED')
 attempted=False
 def definitions(rows):
  deny(set(rows)!=set(before) or any(any(row[key]!=before[name][key] for key in
      ('Id','LoadState','UnitFileState','FragmentPath','DropInPaths','NeedDaemonReload'))
      for name,row in rows.items()),'KERNEL_RESIDENCY_DEFINITION_CHANGED')
 def command(action,units):
  try:
   subprocess.run(['/usr/bin/systemctl','--no-ask-password',
       '--job-mode=fail' if action=='start' else '--job-mode=replace',action,*units],
       check=True,timeout=90,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
       stderr=subprocess.DEVNULL,close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
  except (OSError,subprocess.SubprocessError) as exc:
   raise RunnerDenied('KERNEL_RESIDENCY_COMMAND_FAILED') from exc
 def stop_owned():
  if not attempted:return
  deny(current_boot()!=boot,'KERNEL_RESIDENCY_BOOT_CHANGED')
  definitions(_read_kernel_units(RESIDENCY_UNITS,allow_transitional=True))
  # Timer first prevents it queuing another preload during teardown.
  command('stop',RESIDENCY_UNITS)
  stopped=_read_kernel_units(RESIDENCY_UNITS);definitions(stopped)
  failed=tuple(name for name in RESIDENCY_UNITS
               if (stopped[name]['ActiveState'],stopped[name]['SubState'])==('failed','failed'))
  if failed:
   # Reuse the existing successor failure pattern: durable exact evidence
   # before clearing only this attempted generation's stopped manager latch.
   _retain_residency_failure(plan,stopped,boundary=boundary)
   command('reset-failed',failed)
   stopped=_read_kernel_units(RESIDENCY_UNITS);definitions(stopped)
  deny(any((row['ActiveState'],row['SubState'])!=('inactive','dead')
           for row in stopped.values()),'KERNEL_RESIDENCY_STOP_UNPROVEN')
 def verify_owned():
  boundary();deny(current_boot()!=boot,'KERNEL_RESIDENCY_BOOT_CHANGED')
  rows=_read_kernel_units(RESIDENCY_UNITS);definitions(rows)
  deny(not _unit_active(RESIDENCY_UNITS[0],rows[RESIDENCY_UNITS[0]])
       or rows[RESIDENCY_UNITS[1]]['ActiveState']=='failed','KERNEL_RESIDENCY_UNPROVEN')
 owner.retain(stop_owned,verify_owned)
 try:
  boundary();deny(current_boot()!=boot or _read_kernel_units(RESIDENCY_UNITS)!=before,
                  'KERNEL_RESIDENCY_PRESTATE_CHANGED')
  attempted=True
  # Blocking oneshot success precedes refresh-timer activation. Its fixed
  # program checks the model identity and completion; no synthetic inference.
  command('start',(RESIDENCY_UNITS[1],))
  rows=_read_kernel_units(RESIDENCY_UNITS);definitions(rows)
  deny(any((row['ActiveState'],row['SubState'])!=('inactive','dead')
           for row in rows.values()),'KERNEL_RESIDENCY_PRELOAD_UNPROVEN')
  boundary();deny(current_boot()!=boot,'KERNEL_RESIDENCY_BOOT_CHANGED')
  command('start',(RESIDENCY_UNITS[0],));verify_owned()
  yield {'result':'LOCAL_MODEL_PRELOAD_COMPLETED_REFRESH_STARTED','boot_id':boot,
         'model':'qwen3:4b-instruct','context':8192,'refresh_seconds':240,
         'source':'COMPLETE_KERNEL_PAYLOAD','stage1':'NOT_READY','admission_effect':'NONE'}
  verify_owned()
 except BaseException:
  owner.abort()
  raise


def _retain_residency_failure(plan,rows,*,boundary):
 """Existing atomic witness road, scoped to this whole-generation selector."""
 directory=Path(plan['rollback_selector'])
 deny(directory.parent!=Path('/var/lib/serein/rollback')
      or not re.fullmatch(r'kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',directory.name)
      or set(rows)!=set(RESIDENCY_UNITS),'KERNEL_RESIDENCY_FAILURE_SELECTOR_DENIED')
 value={'schema':'SereinKernelResidencyFailure/v1','boot_id':plan['current_boot_id'],
        'plan_sha256':sha(canonical(plan)),'release_digest':plan['release_digest'],
        'units':strict_json(canonical(rows)),'admission_effect':'NONE'}
 with witness_directory(directory) as (fd,unchanged):
  def guard():
   unchanged();boundary()
   deny(current_boot()!=plan['current_boot_id'] or _read_kernel_units(RESIDENCY_UNITS)!=rows,
        'KERNEL_RESIDENCY_FAILURE_STATE_CHANGED')
  atomic(directory/'residency-failure.json',value,fd,guard)


def _complete_kernel_lifecycle(plan,receipt,request,preparation,expectation,*,boundary,
                               read_compute_expectation=None,signed_runtime_plan=None,runtime_disposition=None,
                               read_public_response=None,read_public_request=None,finalize=None):
 """Transaction-owned ordered construction, never a separate domain install.

 The caller owns the existing generation lock and installed receipt. Compute
 expectations select independently retained evidence; they do not authorize
 this worker/Outpost to originate a HAOS call. Public acceptance is still an
 independent acceptance step. The terminal writer may record construction
 observations, never admission. Its failure still belongs to this owner.
 """
 import secrets
 expectation=_compute_model(expectation)
 deny(read_compute_expectation is not None and not callable(read_compute_expectation),
      'KERNEL_COMPUTE_HANDOFF_REQUIRED')
 deny(read_public_response is not None and read_compute_expectation is None,
      'KERNEL_PUBLIC_RESPONSE_HANDOFF_DENIED')
 deny(read_public_response is not None and not callable(read_public_response),
      'KERNEL_PUBLIC_RESPONSE_HANDOFF_DENIED')
 deny(read_public_request is not None and
      (not callable(read_public_request) or read_public_response is None),
      'KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED')
 request=strict_json(canonical(request));preparation=strict_json(canonical(preparation))
 replacement=preparation['offline_preparation']
 deny((replacement is None)!=(request.get('offline_companion',request.get('native_allocation')) is None),
      'KERNEL_PREPARATION_BINDING_DENIED')
 deny(replacement is None and preparation['preserved_runtime'] is None,
      'KERNEL_PREPARATION_BINDING_DENIED')
 deny(replacement is not None and signed_runtime_plan is None,
      'KERNEL_OFFLINE_SIGNED_PLAN_DENIED')
 challenge={'schema':'SEREIN/KernelBranchWitnessRequest/v1','branch':'AUTHORITY',
     'request_id':'kernel-authority-'+secrets.token_hex(16),'nonce':secrets.token_hex(32),
     'previous_evidence_digest':'GENESIS'}
 def observe(authority,operations,interface):
  controls=strict_json(canonical(operations['service_controls']))
  def observation_boundary():
   boundary()
   deny(read_operations_service_controls()!=controls,'KERNEL_OPERATIONS_PROCESS_CHANGED')
  observation_boundary()
  if read_compute_expectation is None:
   # Construction must leave the complete installed owner available for the
   # genuine post-install HAOS call. No synchronized external acceptance round
   # is an installation prerequisite. The retained source/Host/runtime and
   # lifecycle guards still run; absent compute/GPU/public proof stays absent.
   deny(not callable(finalize),'KERNEL_TERMINAL_WRITER_REQUIRED')
   return strict_json(canonical({'authority':authority,'operations':operations,
       'interface':interface,'compute':None,'gpu':None,'public_response':None}))
  # The caller owns this read-only handoff of the actual externally originated
  # request. Installation must not age or retimestamp that request. No default
  # HAOS call, polling loop, authentication or admission is created here.
  fresh_expectation=_compute_expectation(read_compute_expectation())
  deny({key:fresh_expectation[key] for key in expectation}!=expectation,
       'KERNEL_COMPUTE_POLICY_MODEL_DENIED')
  # Capture externally acquired bytes before refreshing the signed observers.
  # No request is originated here and callback presence proves no road identity.
  public_raw=read_public_response() if read_public_response is not None else None
  deny(read_public_response is not None and
       (not isinstance(public_raw,bytes) or not 0<len(public_raw)<=65536),
       'KERNEL_PUBLIC_RESPONSE_HANDOFF_DENIED')
  external_request=None
  if read_public_request is not None:
   # Retain the independently acquired original, not a reconstruction from
   # subject evidence. Detach it before calling observers that may take time.
   try:
    original_request=read_public_request()
    deny(not isinstance(original_request,dict),'KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED')
    original_raw=canonical(original_request)
    deny(not 0<len(original_raw)<=65536,'KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED')
    external_request=strict_json(original_raw)
   except (TransactionError,TypeError,ValueError,RecursionError) as exc:
    raise RunnerDenied('KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED') from exc
  observation_boundary()
  # Waiting for a genuine call can outlive the original signed observations.
  # Reobserve the same owned processes; never extend timestamps or freshness.
  challenge={'schema':'SEREIN/KernelBranchWitnessRequest/v1','branch':'AUTHORITY',
      'request_id':'kernel-authority-'+secrets.token_hex(16),'nonce':secrets.token_hex(32),
      'previous_evidence_digest':'GENESIS'}
  authority=observe_installed_authority(plan,receipt,challenge)
  deny(authority.get('result')!='AUTHORITY_PHASE_A_OBSERVED','KERNEL_COMPUTE_AUTHORITY_UNPROVEN')
  operations=observe_operations_lifecycle(plan,receipt,canonical(authority),boundary=observation_boundary)
  deny(operations.get('result')!='OPERATIONS_MINIMUM_OBSERVED','KERNEL_COMPUTE_OPERATIONS_UNPROVEN')
  interface=observe_installed_interface(plan,receipt,canonical(authority),operations)
  deny(interface.get('result')!='PRIVATE_INTERFACE_DENIAL_CORRELATED','KERNEL_COMPUTE_INTERFACE_UNPROVEN')
  observation_boundary()
  result=observe_installed_compute(plan,receipt,canonical(authority),operations,interface,fresh_expectation)
  deny(result.get('result')!='MEASURED_COMPUTE_CORRELATED',
       'KERNEL_COMPUTE_UNPROVEN')
  observation_boundary()
  public_observation=None
  if public_raw is not None:
   from outpost.kernel_direct_witness import compare_public_conversation_response
   try:
    retained=result['subject_evidence']['facts']['observation']
    runtime_raw=base64.b64decode(retained['runtime_response_b64'],validate=True)
    public_observation=compare_public_conversation_response(public_raw,
        runtime_raw=runtime_raw,expected_runtime_sha256=result['runtime_result_sha256'],
        request=fresh_expectation['request'],external_request=external_request)
   except (KeyError,TypeError,ValueError) as exc:
    raise RunnerDenied('KERNEL_PUBLIC_RESPONSE_UNCORRELATED') from exc
   observation_boundary()
  gpu_observation=_observe_owned_gpu(plan,result,preparation,
      signed_runtime_plan=signed_runtime_plan,boundary=observation_boundary)
  if finalize is not None:
   return strict_json(canonical({'authority':authority,'operations':operations,
       'interface':interface,'compute':result,'gpu':gpu_observation,
       'public_response':public_observation}))
  # No invented route, HAOS identity, successful public probe or Stage-1 flag.
  # This denial MUST occur before leaving the contexts normally; they own all
  # attempted service cleanup, which precedes the caller's file compensation.
  pending=RunnerDenied('KERNEL_PUBLIC_ACCEPTANCE_UNPROVEN')
  pending.observation=result
  pending.public_observation=public_observation
  pending.gpu_observation=gpu_observation
  raise pending
 owner=_KernelLifecycleOwnership()
 def resident_observation(authority,operations,interface):
  with _companion_residency_lifecycle(plan,boundary=boundary,owner=owner) as residency:
   result=observe(authority,operations,interface)
   return {**result,'residency':residency}
 try:
  with _authority_lifecycle(plan,receipt,challenge,boundary=boundary,owner=owner) as authority:
   with _operations_lifecycle(plan,receipt,canonical(authority),boundary=boundary,owner=owner) as operations:
    with _interface_lifecycle(plan,receipt,canonical(authority),operations,boundary=boundary,owner=owner) as interface:
     if replacement is None:
      observations=resident_observation(authority,operations,interface['denial_observation'])
     else:
      with _offline_companion_lifecycle(plan,receipt,canonical(authority),operations,
          request,replacement,signed_runtime_plan,boundary=boundary,
          consumers=interface['_runtime_consumers'],runtime_disposition=runtime_disposition,
          owner=owner) as runtime:
       authority=runtime['authority'];operations=runtime['operations']
       interface=observe_installed_interface(plan,receipt,canonical(authority),operations)
       observations=resident_observation(authority,operations,interface)
  # All constituent exit guards have now passed, but their cleanup remains
  # armed. Publish only within this whole-domain ownership, not after return.
  deny(not callable(finalize),'KERNEL_TERMINAL_WRITER_REQUIRED')
  owner.verify()
  result=finalize(observations,owner.verify)
 except BaseException:
  owner.abort()
  raise
 else:
  owner.commit()
  return result


def _restore_kernel_source_inputs(*,root,source,receipt_path,prior_source,prior_receipt_path,
                                 plan,module,guard,retained_guard):
 """Retain rejected public input bytes and restore the exact signed inbox.

 Called only inside the whole owner after file compensation and quiescence.
 No private identity, provider ref, model, service or admission effect here.
 """
 root=Path(root);source=Path(source);receipt_path=Path(receipt_path)
 prior_source=Path(prior_source);prior_receipt_path=Path(prior_receipt_path)
 selector=root/plan['rollback_selector'].lstrip('/')
 deny(source!=STATE/'source/sfos/kernel' or receipt_path!=STATE/'source-receipt.json',
      'KERNEL_SUCCESSOR_CANONICAL_INPUT_PATH_DENIED')
 guard()
 predecessor=read_json(root/plan['installed_predecessor']['rollback_selector'].lstrip('/')/'plan.json')
 old_receipt=regular(prior_receipt_path,expected_custody=(0,0,0o600))
 deny(sha(old_receipt)!=predecessor['source_receipt_sha256'],'KERNEL_SUCCESSOR_SOURCE_RECEIPT_DENIED')
 current_receipt=regular(receipt_path,expected_custody=(0,0,0o600))
 deny(sha(current_receipt)!=plan['source_receipt_sha256'],'KERNEL_SUCCESSOR_SOURCE_RECEIPT_CHANGED')
 inventory=safe_tree(prior_source)
 deny('sha256:'+sha(canonical(inventory))!=predecessor['source_inventory_digest'],
      'KERNEL_SUCCESSOR_SOURCE_CHANGED')
 staged=selector/'predecessor-source';parked=selector/'candidate-source'
 deny(any(os.path.lexists(path) for path in (staged,parked,selector/'candidate-source-receipt.json')),
      'KERNEL_SUCCESSOR_INPUT_COMPENSATION_COLLISION')
 staged.mkdir(mode=0o700)
 for row in inventory:
  original=prior_source/row['path'];raw=regular(original)
  deny(len(raw)!=row['bytes'] or sha(raw)!=row['sha256'],'KERNEL_SUCCESSOR_SOURCE_CHANGED')
  mode=stat.S_IMODE(original.lstat().st_mode)
  deny(mode not in {0o644,0o755},'KERNEL_SUCCESSOR_SOURCE_CUSTODY_DENIED')
  module.atomic(staged/row['path'],raw,format(mode,'04o'),lambda:None,create_only=True)
 deny(safe_tree(staged)!=inventory,'KERNEL_SUCCESSOR_SOURCE_COPY_DENIED')
 module.atomic(selector/'candidate-source-receipt.json',current_receipt,'0600',guard,create_only=True)
 guard()
 parent_fd=os.open(source.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 selector_fd=os.open(selector,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  for fd,path in ((parent_fd,source.parent),(selector_fd,selector)):
   info=os.fstat(fd);named=path.lstat()
   deny((info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino)
        or (info.st_uid,info.st_gid)!=(0,0) or stat.S_IMODE(info.st_mode)&0o022,
        'KERNEL_SUCCESSOR_INPUT_DIRECTORY_DENIED')
  deny(os.path.lexists(parked) or not source.is_dir() or source.is_symlink(),
       'KERNEL_SUCCESSOR_INPUT_COMPENSATION_COLLISION')
  os.rename(source.name,parked.name,src_dir_fd=parent_fd,dst_dir_fd=selector_fd)
  os.fsync(parent_fd);os.fsync(selector_fd)
  retained_guard()
  deny('sha256:'+sha(canonical(safe_tree(parked)))!=plan['source_inventory_digest']
       or os.path.lexists(source),'KERNEL_SUCCESSOR_CANDIDATE_INPUT_CHANGED')
  os.rename(staged.name,source.name,src_dir_fd=selector_fd,dst_dir_fd=parent_fd)
  os.fsync(parent_fd);os.fsync(selector_fd)
 finally:
  os.close(selector_fd);os.close(parent_fd)
 deny(safe_tree(source)!=inventory,'KERNEL_SUCCESSOR_SOURCE_RESTORATION_UNPROVEN')
 def receipt_guard():
  retained_guard()
  deny(regular(receipt_path,expected_custody=(0,0,0o600))!=current_receipt
       or safe_tree(source)!=inventory
       or 'sha256:'+sha(canonical(safe_tree(parked)))!=plan['source_inventory_digest'],
       'KERNEL_SUCCESSOR_INPUT_COMPENSATION_CHANGED')
 module.atomic(receipt_path,old_receipt,'0600',receipt_guard)
 deny(regular(receipt_path,expected_custody=(0,0,0o600))!=old_receipt,
      'KERNEL_SUCCESSOR_SOURCE_RECEIPT_RESTORATION_UNPROVEN')
 return parked


def _read_failed_operations_endpoint(rows):
 """Bound the observed socket-activation start-limit failure, never arbitrary reset."""
 import subprocess
 service,socket=OPERATIONS_ENDPOINT
 failed=lambda name:(rows[name]['ActiveState'],rows[name]['SubState'])==('failed','failed')
 if not any(failed(name) for name in OPERATIONS_ENDPOINT):return {}
 deny(not failed(service),'KERNEL_SUCCESSOR_ENDPOINT_FAILURE_DENIED')
 controls=_read_kernel_units((service,),service_controls=True)
 value=controls[service]
 deny(value['MainPID']!='0' or value['Result']!='start-limit-hit'
      or any(value[key]!=rows[service][key] for key in rows[service]),
      'KERNEL_SUCCESSOR_ENDPOINT_FAILURE_DENIED')
 if failed(socket):
  try:
   result=subprocess.run(['/usr/bin/systemctl','show','--all','--no-pager',
       '--property=Id,ActiveState,SubState,Result',socket],capture_output=True,text=True,
       timeout=15,check=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
       stdin=subprocess.DEVNULL,close_fds=True)
  except (OSError,subprocess.SubprocessError) as exc:
   raise RunnerDenied('KERNEL_SUCCESSOR_ENDPOINT_FAILURE_DENIED') from exc
  deny(len(result.stdout)>1024,'KERNEL_SUCCESSOR_ENDPOINT_FAILURE_DENIED')
  observed={}
  for line in result.stdout.splitlines():
   key,separator,item=line.partition('=')
   deny(not separator or key in observed,'KERNEL_SUCCESSOR_ENDPOINT_FAILURE_DENIED')
   observed[key]=item
  deny(observed!={'Id':socket,'ActiveState':'failed','SubState':'failed',
                  'Result':'service-start-limit-hit'},'KERNEL_SUCCESSOR_ENDPOINT_FAILURE_DENIED')
  controls[socket]=observed
 return controls


def _read_failed_authority_endpoint(rows):
 """Capture the exact exited, process-free Authority failure before reset.

 Signed predecessor/file/current-boot verification remains the outer owner's
 prerequisite. This reader neither clears a latch nor starts a service.
 """
 import subprocess
 service,socket=AUTHORITY_UNITS
 if (rows[service]['ActiveState'],rows[service]['SubState'])!=('failed','failed'):return {}
 deny((rows[socket]['ActiveState'],rows[socket]['SubState'])!=('inactive','dead'),
      'KERNEL_SUCCESSOR_AUTHORITY_FAILURE_DENIED')
 properties=tuple(rows[service])+('MainPID','ExecMainCode','ExecMainStatus',
     'ExecMainStartTimestampMonotonic','InvocationID','User','Group','Restart',
     'NRestarts','Result','KillMode','ControlGroup','Job')
 try:
  result=subprocess.run(['/usr/bin/systemctl','show','--all','--no-pager',
      '--property='+','.join(properties),service],capture_output=True,text=True,
      timeout=15,check=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
      stdin=subprocess.DEVNULL,close_fds=True)
 except (OSError,subprocess.SubprocessError) as exc:
  raise RunnerDenied('KERNEL_SUCCESSOR_AUTHORITY_FAILURE_DENIED') from exc
 deny(len(result.stdout)>16384 or result.stderr,'KERNEL_SUCCESSOR_AUTHORITY_FAILURE_DENIED')
 value={}
 for line in result.stdout.splitlines():
  key,sep,item=line.partition('=')
  deny(not sep or key in value,'KERNEL_SUCCESSOR_AUTHORITY_FAILURE_DENIED')
  value[key]=item
 exact={'MainPID':'0','ExecMainCode':'1','ExecMainStatus':'1','User':'root','Group':'root',
        'Restart':'no','NRestarts':'0','Result':'exit-code','KillMode':'control-group',
        'ControlGroup':'','Job':''}
 deny(set(value)!=set(properties) or any(value.get(k)!=v for k,v in {**rows[service],**exact}.items())
      or not re.fullmatch(r'[0-9a-f]{32}',value.get('InvocationID',''))
      or value['InvocationID']=='0'*32
      or not re.fullmatch(r'[1-9][0-9]{0,19}',value.get('ExecMainStartTimestampMonotonic',''))
      or os.path.lexists('/sys/fs/cgroup/system.slice/'+service),
      'KERNEL_SUCCESSOR_AUTHORITY_FAILURE_DENIED')
 try:
  journal=subprocess.run(['/usr/bin/journalctl','--no-pager','-b','-o','short-monotonic',
      '_SYSTEMD_INVOCATION_ID='+value['InvocationID'],'+',
      'OBJECT_SYSTEMD_INVOCATION_ID='+value['InvocationID']],capture_output=True,text=True,
      timeout=15,check=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
      stdin=subprocess.DEVNULL,close_fds=True)
 except (OSError,subprocess.SubprocessError) as exc:
  raise RunnerDenied('KERNEL_SUCCESSOR_AUTHORITY_FAILURE_EVIDENCE_DENIED') from exc
 deny(not journal.stdout or len(journal.stdout.encode())>65536 or journal.stderr,
      'KERNEL_SUCCESSOR_AUTHORITY_FAILURE_EVIDENCE_DENIED')
 return {'controls':value,'invocation_journal':journal.stdout,
         'invocation_journal_sha256':sha(journal.stdout.encode()),'cgroup':'ABSENT'}


@contextmanager
def _quiesce_installed_kernel(prestate,*,guard,verify_predecessor,verify_restored,publication,
                             predecessor_boot_id,current_boot_id,retain_prestate=None,failed_predecessor=False):
 """Whole-successor owner: stop only the exact installed Kernel units.

 No host, Outpost, runtime/model or enablement effect. On failure the old
 generation may restart only after its exact signed files are restored.
 """
 import subprocess
 # These bindings come from the authenticated predecessor and current plan,
 # not an optional request flag. Historical services cannot regain authority
 # merely because a successor fails on another boot.
 boot_pattern=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
 deny(any(not isinstance(value,str) or not re.fullmatch(boot_pattern,value)
          for value in (predecessor_boot_id,current_boot_id)),
      'KERNEL_SUCCESSOR_BOOT_BINDING_DENIED')
 deny(type(failed_predecessor) is not bool,'KERNEL_SUCCESSOR_FAILURE_CLASS_DENIED')
 restart_predecessor=predecessor_boot_id==current_boot_id and not failed_predecessor
 groups=(AUTHORITY_UNITS,OPERATIONS_UNITS,INTERFACE_UNITS,RESIDENCY_UNITS)
 names=set(AUTHORITY_UNITS+OTHER_KERNEL_UNITS)
 deny(set(prestate)!=names,'KERNEL_SUCCESSOR_UNIT_SET_DENIED')
 for name,row in prestate.items():
  missing_residency=(name in RESIDENCY_UNITS and row['LoadState']=='not-found'
                     and (row['ActiveState'],row['SubState'])==('inactive','dead'))
  deny((row['LoadState']!='loaded' and not missing_residency) or row['NeedDaemonReload']!='no'
       or not (_unit_active(name,row) or (row['ActiveState'],row['SubState'])==('inactive','dead')
               or (name in SUCCESSOR_FAILURE_UNITS and (row['ActiveState'],row['SubState'])==('failed','failed'))),
       'KERNEL_SUCCESSOR_UNIT_PRESTATE_DENIED')
 original=strict_json(canonical(prestate));attempted=False;restart_errors=[]
 def read(*,cleanup=False):
  if cleanup:return {**read_authority_unit_prestate(cleanup=True),**read_other_kernel_unit_prestate(cleanup=True)}
  return {**read_authority_unit_prestate(),**read_other_kernel_unit_prestate()}
 def definitions(current):
  deny(set(current)!=names or any(any(current[name][key]!=original[name][key] for key in
       ('Id','LoadState','FragmentPath','DropInPaths','UnitFileState','NeedDaemonReload')) for name in names),
       'KERNEL_SUCCESSOR_UNIT_DEFINITION_CHANGED')
 def command(action,units):
  nonlocal attempted
  if not units:return
  guard()
  if action=='stop':attempted=True
  try:subprocess.run(['/usr/bin/systemctl','--no-ask-password',
      '--job-mode=replace' if action=='stop' else '--job-mode=fail',action,*units],
      check=True,timeout=90,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
      close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
  except subprocess.CalledProcessError as exc:
   if action!='start':raise RunnerDenied('KERNEL_SUCCESSOR_QUIESCE_COMMAND_FAILED') from exc
   # systemctl aggregates per-unit job errors. Observe the same requested
   # predecessor, without retrying a start or replacing a conflicting job.
   # This is compensation evidence only; construction still fails below.
   import time
   restart_errors.append(exc)
   deadline=time.monotonic()+10.0
   while True:
    guard();current=read(cleanup=True);definitions(current)
    settled=all(_unit_active(name,row) or (row['ActiveState'],row['SubState'])==('inactive','dead')
                for name,row in current.items())
    if settled and all(_unit_active(name,current[name]) for name in units):break
    if time.monotonic()>=deadline:
     raise RunnerDenied('KERNEL_SUCCESSOR_PREDECESSOR_RESTART_UNPROVEN') from exc
    time.sleep(0.1)
  except (OSError,subprocess.SubprocessError) as exc:raise RunnerDenied('KERNEL_SUCCESSOR_QUIESCE_COMMAND_FAILED') from exc
  guard()
 guard();verify_predecessor()
 deny(read()!=original,'KERNEL_SUCCESSOR_UNIT_PRESTATE_CHANGED')
 failed=tuple(name for name in SUCCESSOR_FAILURE_UNITS if original[name]['ActiveState']=='failed')
 if failed or not restart_predecessor:
  deny(not callable(retain_prestate),'KERNEL_SUCCESSOR_FAILURE_EVIDENCE_REQUIRED')
 endpoint_controls=_read_failed_operations_endpoint(original)
 authority_controls=_read_failed_authority_endpoint(original)
 if failed or not restart_predecessor:
  retain_prestate(original)
  guard();verify_predecessor()
  deny(read()!=original,'KERNEL_SUCCESSOR_UNIT_PRESTATE_CHANGED')
  deny(_read_failed_operations_endpoint(original)!=endpoint_controls,
       'KERNEL_SUCCESSOR_FAILED_PROCESS_CHANGED')
  deny(_read_failed_authority_endpoint(original)!=authority_controls,
       'KERNEL_SUCCESSOR_FAILED_PROCESS_CHANGED')
 try:
  for units in reversed(groups):
   definitions(read())
   command('stop',tuple(name for name in units if original[name]['LoadState']=='loaded'))
   observed=read();definitions(observed)
   # systemd stop leaves an already-failed unit failed. Preserve its exact
   # original evidence first, then clear only that owned predecessor's latch.
   # This never starts it or clears replay/application history. Compensation
   # below restarts only originally active units, never a failed predecessor.
   reset=tuple(name for name in failed if name in units)
   if reset:
    deny(any((observed[name]['ActiveState'],observed[name]['SubState'])!=('failed','failed')
             for name in reset),'KERNEL_SUCCESSOR_FAILED_PRESTATE_CHANGED')
    command('reset-failed',reset)
    observed=read();definitions(observed)
   deny(any((observed[name]['ActiveState'],observed[name]['SubState'])!=('inactive','dead') for name in units),
        'KERNEL_SUCCESSOR_QUIESCENCE_UNPROVEN')
  guard();verify_predecessor()
  yield
 except BaseException as exc:
  if attempted and not publication['completed']:
   try:
    guard();verify_predecessor()
    restored_guard=verify_restored()
    if restored_guard is not None:guard=restored_guard
    guard();definitions(read())
    if restart_predecessor:
     for service,socket in (AUTHORITY_UNITS,OPERATIONS_ENDPOINT,
         ('serein-observation-audit.service','serein-observation-audit.socket'),
         ('serein-conversation-runtime.service','serein-conversation-runtime.socket'),
         ('serein-kernel-client-gateway@haos.service','serein-kernel-client-gateway-haos.socket')):
      deny(_unit_active(service,original[service]) and not _unit_active(socket,original[socket]),
           'KERNEL_SUCCESSOR_PREDECESSOR_SOCKET_UNPROVEN')
     for units in groups:
      # A service requiring an inherited listener must never be started when
      # the corresponding socket start failed. systemctl aggregates job
      # failures; starting both in one call can still launch the service.
      sockets=tuple(name for name in units if name.endswith('.socket') and _unit_active(name,original[name]))
      services=tuple(name for name in units if not name.endswith('.socket') and _unit_active(name,original[name]))
      command('start',sockets)
      if sockets:
       observed=read();definitions(observed)
       deny(any(not _unit_active(name,observed[name]) for name in sockets),
            'KERNEL_SUCCESSOR_PREDECESSOR_SOCKET_UNPROVEN')
      command('start',services)
    current=read();definitions(current)
    deny(any((_unit_active(name,current[name]) if restart_predecessor and _unit_active(name,original[name]) else
              (current[name]['ActiveState'],current[name]['SubState'])==('inactive','dead')) is not True
             for name in names),
         'KERNEL_SUCCESSOR_PREDECESSOR_RESTART_UNPROVEN')
    guard();verify_predecessor()
    for restart_error in restart_errors:
     exc.add_note('Predecessor restart command failed but bounded independent state readback verified restoration: '+str(restart_error))
   except BaseException as recovery_error:
    raise RunnerDenied('KERNEL_SUCCESSOR_COMPENSATION_UNPROVEN') from recovery_error
  raise


def run(root=Path("/"),source=SOURCE,request_path=REQUEST,host_path=HOST_STATE,signing_path=SIGNING_KEY,verify_path=VERIFY_KEY,source_receipt_path=SOURCE_RECEIPT,installer=None,rollback_installer=None,*,construct=False,compute_expectation=None,read_compute_expectation=None,read_public_response=None,read_public_request=None):
 # Serialize with Outpost promotion using its already-proven root-private lock.
 # Do not introduce a service-owned privileged lock or a new root service.
 boot=current_boot();request_raw=regular(request_path)
 request=install_request(request_path)
 deny(type(construct) is not bool,'KERNEL_CONSTRUCTION_MODE_DENIED')
 complete=(construct or request['schema'] in {'SereinOutpostKernelInstallRequest/v2','SereinOutpostKernelInstallRequest/v3'}
           or compute_expectation is not None or read_compute_expectation is not None
           or read_public_response is not None or read_public_request is not None)
 # Complete input absence is action-local, not a blanket implementation hold.
 # Copy before the first lock/file/service effect; never originate a request.
 if complete:
  if compute_expectation is not None or read_compute_expectation is not None:
   compute_expectation=_compute_model(compute_expectation)
  deny(read_compute_expectation is not None and not callable(read_compute_expectation),
       'KERNEL_COMPUTE_HANDOFF_REQUIRED')
  deny(read_public_response is not None and read_compute_expectation is None,
       'KERNEL_PUBLIC_RESPONSE_HANDOFF_DENIED')
  deny(read_public_response is not None and not callable(read_public_response),
       'KERNEL_PUBLIC_RESPONSE_HANDOFF_DENIED')
  deny(read_public_request is not None and
       (not callable(read_public_request) or read_public_response is None),
       'KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED')
 publication={'completed':False}
 with witness_directory(STATE,publication) as (witness_fd,check_parent),public_generation_lock(root,sha(request_raw),boot),ExitStack() as successor_scope:
  prior_witness=None
  prior_binding=request.get('installed_predecessor',request.get('recovered_predecessor'))
  if prior_binding is not None:
   path=STATE/'kernel-install-witness.json'
   raw=regular(path,expected_custody=(0,0,0o600))
   fact=regular(path,fact=True,expected_custody=(0,0,0o600),include_identity=True)
   deny(sha(raw)!=prior_binding.get('witness_sha256') or fact[0]!=sha(raw),
        'KERNEL_WITNESS_PREDECESSOR_CHANGED')
   prior_witness=(raw,fact)
  else:deny(os.path.lexists(STATE/"kernel-install-witness.json"),"KERNEL_WITNESS_COLLISION_DENIED")
  def inactive_kernel_units():
   authority=read_authority_unit_prestate();other=read_other_kernel_unit_prestate()
   deny(set(authority)!=set(AUTHORITY_UNITS) or set(other)!=set(OTHER_KERNEL_UNITS),
        'KERNEL_UNIT_SET_DENIED')
   units=strict_json(canonical({**authority,**other}))
   for name,row in units.items():
    deny((row['ActiveState'],row['SubState'])!=('inactive','dead'),
         'KERNEL_AUTHORITY_NOT_INACTIVE' if name in AUTHORITY_UNITS else 'KERNEL_DOMAIN_NOT_INACTIVE')
   return units
  successor='installed_predecessor' in request
  deny(successor and not complete,'KERNEL_SUCCESSOR_COMPLETE_CONSTRUCTION_REQUIRED')
  unit_prestate=({**read_authority_unit_prestate(),**read_other_kernel_unit_prestate()} if successor else inactive_kernel_units())
  enablement_prestate=read_kernel_enablement_prestate(root) if complete else None
  if complete:
   deny(any(row['NeedDaemonReload']!='no' for row in unit_prestate.values()),
        'KERNEL_UNIT_PRESTATE_RELOAD_REQUIRED')
  unit_poststate=unit_prestate
  units_at_publication=None
  prepared=prepare_kernel_request(root=root,source=source,request_path=request_path,
      host_path=host_path,verify_path=verify_path,source_receipt_path=source_receipt_path)
  plan,host_prestate=prepared['kernel_plan'],prepared['host_prestate']
  if complete:compute_expectation=_bind_compute_model(plan,source,compute_expectation)
  deny((prepared['offline_preparation'] is not None)!=(request.get('offline_companion',request.get('native_allocation')) is not None)
       or (prepared['offline_preparation'] is None and prepared['preserved_runtime'] is None)
       or prepared['request_sha256']!=sha(request_raw)
       or prepared['kernel_plan_sha256']!=sha(canonical(plan))
       or prepared['initial_host_projection_digest']!=host_prestate['projection_digest'],
       'KERNEL_PREPARATION_BINDING_DENIED')
  deny(plan["current_boot_id"]!=boot or regular(request_path)!=request_raw,"KERNEL_REQUEST_CHANGED")
  # The signed projection names the exact initial observation. Independent
  # Host sampling continues during installation; only its time/digest may
  # advance, never the machine, Base/source, GPU or other observed facts.
  check_material=_kernel_material_boundary(plan,host_prestate,request_raw,
      root=root,source=source,request_path=request_path,host_path=host_path,check_parent=check_parent,
      preserved_runtime=prepared['preserved_runtime'])
  runtime_disposition={'attempted':False,'restored':False}
  if 'native_allocation' in request:
   runtime_disposition.update(native_mutating=False,
       native_expected=prepared['offline_preparation']['plan']['runtime_prestate']['runtime'])
  def failed_runtime_boundary(runtime_source):
   failed=request.get('installed_predecessor',{}).get('failed_construction')
   if failed is not None:
    previous=request['installed_predecessor']
    failed_plan=read_json(Path(root)/previous['rollback_selector'].lstrip('/')/'plan.json')
    deny(sha(canonical(failed_plan))!=previous['plan_sha256'],'KERNEL_FAILED_PLAN_CHANGED')
    observe_failed_native_prestate(root,failed_plan,failed,runtime_source,expected_release=plan['release_digest'])
  def material_boundary():
   check_material()
   failed_runtime_boundary(source)
   if 'native_allocation' in request and not runtime_disposition['native_mutating']:
    current_runtime=load_offline_installer(source,read_json(source/'release-manifest.json'),
        expected_release=plan['release_digest']).OfflineOllamaRealAdapter()
    current_runtime.observe_runtime(expected=runtime_disposition['native_expected'])
   if complete:
    deny(read_kernel_enablement_prestate(root)!=enablement_prestate,'KERNEL_ENABLEMENT_CHANGED')
  deny(sha(regular(verify_path))!=CANONICAL_AUTHORITY_SHA256,"KERNEL_CANONICAL_ANCHOR_DENIED")
  private=load_pem_private_key(regular(signing_path),password=None)
  module=load_installer(source,read_json(source/'release-manifest.json'),expected_release=plan['release_digest'])
  if 'installed_predecessor' in plan:
   native_material={'binding':dict(plan['native_identity']),
       'registry':regular(Path(root)/module.NATIVE_REGISTRY.lstrip('/'),expected_custody=(0,0,0o644)),
       'private':regular(Path(root)/module.NATIVE_KEY.lstrip('/'),expected_custody=(0,0,0o600))}
  else:native_material=module.prepare_native_identity(source,plan,private,reserved_ids=set(plan['reserved_domain_ids']))
  plan['native_identity']=native_material['binding']
  plan["signature"]=base64.urlsafe_b64encode(private.sign(canonical(plan))).decode().rstrip("=")
  signed_runtime_plan=None
  if prepared['offline_preparation'] is not None:
   runtime_module=load_offline_installer(source,read_json(source/'release-manifest.json'),
       expected_release=plan['release_digest'])
   signed_runtime_plan=strict_json(canonical(prepared['offline_preparation']['plan']))
   signed_runtime_plan['signature']=base64.urlsafe_b64encode(
       private.sign(runtime_module.signing_payload(signed_runtime_plan))).decode().rstrip('=')
  policy_evidence=module.prepare_installed_policy_evidence(root,source,plan,private,native_material=native_material)
  if successor:
   previous=request['installed_predecessor']
   def verify_predecessor():
    return capture_installed_kernel_prestate(root,Path(root)/previous['source_root'].lstrip('/'),
        {k:v for k,v in previous.items() if k not in {'source_root','source_receipt'}},verify_path=verify_path,
        witness_path=STATE/'kernel-install-witness.json',observation_boot_id=plan['current_boot_id'],
        runtime_source=(Path(root)/plan['rollback_selector'].lstrip('/')/'candidate-source'
                        if os.path.lexists(Path(root)/plan['rollback_selector'].lstrip('/')/'candidate-source') else source),
        runtime_release=plan['release_digest'])
   def verify_restored():
    # Restored runtime bytes alone cannot restart a generation against a new
    # canonical source inbox. Require its original signed provider binding.
    old=verify_predecessor()['plan']
    parked=Path(root)/plan['rollback_selector'].lstrip('/')/'candidate-source'
    immutable_before={name:regular(Path(root)/name.lstrip('/'),fact=True) for name in IMMUTABLE_POLICY}
    retained_material=None
    def retained_guard():
     nonlocal retained_material
     failed_runtime_boundary(parked)
     deny(any(regular(Path(root)/name.lstrip('/'),fact=True)!=value for name,value in immutable_before.items()),
          'KERNEL_IMMUTABLE_CHANGED')
     if retained_material is None:
      retained_material=_kernel_material_boundary(plan,host_prestate,request_raw,
          root=root,source=parked,request_path=request_path,host_path=host_path,check_parent=check_parent,
          preserved_runtime=prepared['preserved_runtime'])
     retained_material()
     deny(read_kernel_enablement_prestate(root)!=enablement_prestate,'KERNEL_ENABLEMENT_CHANGED')
    _restore_kernel_source_inputs(root=root,source=source,receipt_path=source_receipt_path,
        prior_source=Path(root)/previous['source_root'].lstrip('/'),
        prior_receipt_path=Path(root)/previous['source_receipt'].lstrip('/'),
        plan=plan,module=module,guard=material_boundary,retained_guard=retained_guard)
    def restored_guard():
     retained_guard()
     restored,digest=source_receipt(source,source_receipt_path,verify_path)
     deny(digest!=old['source_receipt_sha256'] or any(restored[k]!=old[k] for k in
         ('source_parent','source_commit','source_tree','archive_sha256','release_digest'))
         or restored['inventory_digest']!=old['source_inventory_digest'],
         'KERNEL_SUCCESSOR_RUNTIME_SOURCE_NOT_RESTORED')
    restored_guard()
    return restored_guard
   def retain_prestate(rows):
    controls=read_operations_service_controls()
    endpoint_controls=_read_failed_operations_endpoint(rows)
    authority_controls=_read_failed_authority_endpoint(rows)
    failed=[name for name in OPERATIONS_SERVICES if rows[name]['ActiveState']=='failed']
    deny(any(controls[name]['MainPID']!='0' or any(controls[name][key]!=rows[name][key]
             for key in rows[name]) for name in failed),'KERNEL_SUCCESSOR_FAILED_PROCESS_CHANGED')
    evidence={'schema':'SereinKernelSuccessorQuiescence/v1','boot_id':boot,
        'predecessor_boot_id':plan['installed_predecessor']['current_boot_id'],
        'predecessor_restart':('DENIED_FAILED_CONSTRUCTION' if 'failed_construction' in previous else
                              'SAME_BOOT_ONLY' if plan['installed_predecessor']['current_boot_id']==plan['current_boot_id']
                               else 'DENIED_HISTORICAL_BOOT'),
        'request_sha256':sha(request_raw),'plan_sha256':sha(canonical(plan)),
        'rollback_selector':plan['rollback_selector'],'unit_prestate':rows,
        'operations_service_controls':controls,
        'failed_predecessors':[name for name in SUCCESSOR_FAILURE_UNITS if rows[name]['ActiveState']=='failed'],
        'operations_endpoint_failure_controls':endpoint_controls,
        'authority_failure_controls':authority_controls,
        'failed_predecessor_compensation':'REMAIN_INACTIVE_NEVER_RESTART'}
    evidence['evidence_digest']=sha(canonical(evidence))
    def evidence_boundary():
     material_boundary();verify_predecessor()
     deny(read_operations_service_controls()!=controls,'KERNEL_SUCCESSOR_FAILED_PROCESS_CHANGED')
     deny(_read_failed_operations_endpoint(rows)!=endpoint_controls,'KERNEL_SUCCESSOR_FAILED_PROCESS_CHANGED')
     deny(_read_failed_authority_endpoint(rows)!=authority_controls,'KERNEL_SUCCESSOR_FAILED_PROCESS_CHANGED')
    atomic(STATE/('kernel-successor-quiescence-'+sha(request_raw)+'.json'),
        evidence,witness_fd,evidence_boundary)
   successor_scope.enter_context(_quiesce_installed_kernel(unit_prestate,guard=material_boundary,
       verify_predecessor=verify_predecessor,verify_restored=verify_restored,publication=publication,
       predecessor_boot_id=plan['installed_predecessor']['current_boot_id'],
       current_boot_id=plan['current_boot_id'],
       retain_prestate=retain_prestate,failed_predecessor='failed_construction' in previous))
   successor_unit_prestate=unit_prestate
   unit_prestate=inactive_kernel_units()
  def boundary():
   nonlocal unit_poststate
   material_boundary()
   unit_poststate=inactive_kernel_units()
   deny(units_at_publication is not None and unit_poststate!=units_at_publication,
        'KERNEL_AUTHORITY_UNIT_PUBLICATION_CHANGED')
  boundary()
  if installer is None:
   installer=module.install;rollback_installer=module.rollback
  boundary()
  receipt=installer(root,source,plan,boundary=boundary,native_material=native_material,policy_evidence=policy_evidence);canonical_receipt=Path(root).joinpath(*Path(plan["rollback_selector"]+"/receipt.json").parts[1:])
  runtime_access_attempted=False
  runtime_access_poststate=None
  definitions_refresh_attempted=False
  def refresh_definitions(guard):
   # Existing Outpost bootstrap's manager-refresh road, inside this complete
   # transaction only. No unit start, enablement, reexec or new privilege.
   import subprocess
   guard()
   try:
    subprocess.run(['/usr/bin/systemctl','--no-ask-password','daemon-reload'],
        check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,timeout=90,close_fds=True,
        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
   except (OSError,subprocess.SubprocessError) as exc:
    raise RunnerDenied('KERNEL_UNIT_REFRESH_FAILED') from exc
   guard()
  try:
   deny(receipt.get("status")!="INSTALLED_INACTIVE" or receipt.get("receipt")!=plan["rollback_selector"]+"/receipt.json","KERNEL_INSTALL_RECEIPT_DENIED");deny("sha256:"+sha(canonical(safe_tree(source)))!=plan["source_inventory_digest"],"KERNEL_SOURCE_CHANGED_DURING_INSTALL");receipt_digest=verify_install(root,plan,receipt,source=source)
   witness={"schema":"SereinOutpostKernelInstallWitness/v1","target":"VM4010","boot_id":plan["current_boot_id"],"source_commit":plan["source_commit"],"source_tree":plan["source_tree"],"archive_sha256":plan["archive_sha256"],"source_receipt_sha256":plan["source_receipt_sha256"],"release_digest":plan["release_digest"],"installer_receipt_sha256":receipt_digest,"branch_order":list(ORDER),"install_status":receipt["status"],"admission":"INDEPENDENT_AUDIT_PENDING","stage1":"NOT_READY","rollback_selector":plan["rollback_selector"],"authority_effect":"NONE"}
   witness.update(json.loads(canonical({name:plan[name] for name in
       ('native_identity','host_identity','host_projection_digest')})))
   if complete:
    # A timeout can follow a successful manager effect. Retain its disposition
    # before calling, and refresh restored files on the safe compensation road.
    definitions_refresh_attempted=True
    refresh_definitions(boundary)
    deny(verify_install(root,plan,receipt,source=source)!=receipt_digest,
         'KERNEL_INSTALL_RECEIPT_CHANGED')
    for name,row in unit_poststate.items():
     before=unit_prestate[name]
     retained_enabled=any(link['unit']==name and link['path'].startswith('/etc/')
                          for link in enablement_prestate)
     deny(row['LoadState']!='loaded' or row['NeedDaemonReload']!='no'
          or (row['UnitFileState']!=before['UnitFileState'] if before['LoadState']=='loaded'
              else row['UnitFileState'] not in ({'static','disabled','enabled'}
                    if retained_enabled else {'static','disabled'})),
          'KERNEL_UNIT_REFRESH_READBACK_DENIED')
    def finalize(observations,verify_lifecycle):
     material_boundary()
     deny(verify_install(root,plan,receipt,source=source)!=receipt_digest,
          'KERNEL_INSTALL_RECEIPT_CHANGED')
     verify_lifecycle()
     witness.update(schema='SereinOutpostKernelInstallWitness/v2',
         install_status='CONSTRUCTION_OBSERVED',admission='UNADMITTED',
         admission_effect='NONE',temporal_scope='HISTORICAL_CONSTRUCTION_OBSERVATION',
         public_acceptance='UNPROVEN',observations=observations,
         observations_sha256=sha(canonical(observations)))
     current={**read_authority_unit_prestate(),**read_other_kernel_unit_prestate()}
     deny(set(current)!=set(unit_prestate),'KERNEL_UNIT_SET_DENIED')
     witness.update(authority_unit_prestate={name:unit_prestate[name] for name in AUTHORITY_UNITS},
         authority_unit_poststate={name:current[name] for name in AUTHORITY_UNITS},
         kernel_unit_prestate=unit_prestate,kernel_unit_poststate=current)
     witness['kernel_enablement_prestate']=enablement_prestate
     witness['runtime_access_prestate']=plan['runtime_access_prestate']
     witness['runtime_access_poststate']=runtime_access_poststate
     if successor:witness['installed_predecessor_unit_prestate']=successor_unit_prestate
     def publication_boundary():
      material_boundary()
      verify_lifecycle()
      deny({**read_authority_unit_prestate(),**read_other_kernel_unit_prestate()}!=current,
           'KERNEL_UNIT_PUBLICATION_CHANGED')
     witness['witness_digest']=sha(canonical(witness))
     publication_boundary()
     try:atomic(STATE/'kernel-install-witness.json',witness,witness_fd,publication_boundary,
                **({'predecessor':prior_witness} if prior_witness is not None else {}))
     except WitnessPublicationUncertain:
      # Retain disposition even if service cleanup raises a different error.
      publication['completed']=True
      raise
     publication['completed']=True
     return witness
    runtime_access_attempted=True
    runtime_access_poststate=module.apply_runtime_access(root,plan,boundary)
    def construction_boundary():
     material_boundary()
     deny(module.capture_runtime_access(root,plan)!=runtime_access_poststate,
          'KERNEL_RUNTIME_ACCESS_CHANGED')
    return _complete_kernel_lifecycle(plan,receipt,request,prepared,compute_expectation,
        boundary=construction_boundary,read_compute_expectation=read_compute_expectation,
        signed_runtime_plan=signed_runtime_plan,runtime_disposition=runtime_disposition,
        finalize=finalize,
        **({'read_public_response':read_public_response} if read_public_response is not None else {}),
        **({'read_public_request':read_public_request} if read_public_request is not None else {}))
   # The installed Authority consumer verifies these against this exact signed
   # plan. Preserve its public bindings; never rederive them or export keys.
   # Observation only: placement may make systemd notice new unit files or
   # require daemon-reload. Neither authorizes startup. Pin the final sampled
   # pair through witness publication without changing the signed install plan.
   boundary();units_at_publication=strict_json(canonical(unit_poststate))
   witness.update(authority_unit_prestate={name:unit_prestate[name] for name in AUTHORITY_UNITS},
                  authority_unit_poststate={name:units_at_publication[name] for name in AUTHORITY_UNITS},
                  kernel_unit_prestate=unit_prestate,kernel_unit_poststate=units_at_publication)
   witness["witness_digest"]=sha(canonical(witness));boundary();atomic(STATE/"kernel-install-witness.json",witness,witness_fd,boundary,
       **({'predecessor':prior_witness} if prior_witness is not None else {}))
   publication['completed']=True
  except WitnessPublicationUncertain:
   publication['completed']=True
   raise
  except Exception as exc:
   if publication['completed']:
    raise WitnessPublicationUncertain('KERNEL_WITNESS_PUBLICATION_UNCERTAIN') from exc
   # An inner cleanup exception must not hide unresolved runtime mutation.
   # This disposition is owned by the enclosing transaction, not by a return
   # value or only the outermost exception type.
   if runtime_disposition['attempted'] and not runtime_disposition['restored']:
    raise RuntimeCompensationUncertain('KERNEL_RUNTIME_COMPENSATION_UNPROVEN') from exc
   # A rejected publication snapshot is not the compensation denominator.
   # Keep every safety check, including inactive Authority, but allow harmless
   # manager discovery/reload metadata to differ while undoing inactive files.
   units_at_publication=None
   compensation_boundary=boundary
   if runtime_disposition['attempted']:
    # A/O/I cleanup happened after the inner runtime readback. Reconfirm its
    # exact restored prestate now, and at each existing file-effect boundary.
    # Use the inactive outer guard, not the inner active-Operations guard.
    if signed_runtime_plan is None:
     raise RuntimeCompensationUncertain('KERNEL_RUNTIME_COMPENSATION_UNPROVEN') from exc
    restored_adapter=runtime_module.OfflineOllamaRealAdapter()
    restored_adapter.boundary=boundary
    restored_selector=Path(request.get('offline_companion',request.get('native_allocation'))['rollback_selector'])
    def compensation_boundary():
     try:
      boundary()
      if 'native_allocation' in request:
       runtime_module.verify_completed_native_allocation_rollback(restored_adapter,restored_selector,
           expected_plan_sha256=signed_runtime_plan['plan_sha256'])
      else:
       runtime_module.verify_completed_rollback(restored_adapter,restored_selector,
           expected_plan_sha256=signed_runtime_plan['plan_sha256'])
     except Exception as restoration_error:
      raise RuntimeCompensationUncertain('KERNEL_RUNTIME_COMPENSATION_UNPROVEN') from restoration_error
   compensation_boundary()
   if runtime_access_attempted:
    # Lifecycle cleanup has quiesced all owned units. Do not compensate files
    # under an unresolved permission effect, including a tmpfiles timeout.
    module.restore_runtime_access(root,plan,compensation_boundary)
   deny(rollback_installer is None,"KERNEL_POSTINSTALL_ROLLBACK_UNAVAILABLE")
   rollback_installer(root,canonical_receipt,boundary=compensation_boundary)
   if definitions_refresh_attempted:
    try:
     refresh_definitions(compensation_boundary)
     deny(inactive_kernel_units()!=unit_prestate,'KERNEL_UNIT_COMPENSATION_READBACK_DENIED')
    except Exception as cleanup_error:
     raise RunnerDenied('KERNEL_UNIT_COMPENSATION_UNPROVEN') from cleanup_error
   raise
  return witness
def _read_compute_handoff(stream,*,timeout=10.0):
 """Existing observer's absolute-deadline input pattern, in this owner.

 A byte cap alone cannot bound a root transaction waiting for pipe EOF.
 Preserve the borrowed descriptor's blocking mode; never close its owner.
 """
 import select,time
 fd=stream.fileno();blocking=os.get_blocking(fd);raw=bytearray()
 deadline=time.monotonic()+timeout
 try:
  os.set_blocking(fd,False)
  while True:
   remaining=deadline-time.monotonic()
   deny(remaining<=0 or not select.select([fd],[],[],remaining)[0],
        'KERNEL_COMPUTE_HANDOFF_TIMEOUT')
   try:chunk=os.read(fd,min(4096,65537-len(raw)))
   except BlockingIOError:continue
   if not chunk:break
   raw.extend(chunk)
   deny(len(raw)>65536,'KERNEL_COMPUTE_HANDOFF_DENIED')
  deny(not raw,'KERNEL_COMPUTE_HANDOFF_DENIED')
  return _compute_expectation(strict_json(bytes(raw)))
 except (TransactionError,OSError,TypeError,ValueError,RecursionError) as exc:
  raise RunnerDenied('KERNEL_COMPUTE_HANDOFF_DENIED') from exc
 finally:
  os.set_blocking(fd,blocking)



def _native_observer_generation():
 """Bind this one-shot caller to the complete selected installed generation."""
 from .generation_launcher import read_selector
 from outpost import kernel_direct_witness
 deny(os.geteuid()!=0 or os.getegid()!=0,'KERNEL_OBSERVER_CALLER_DENIED')
 selected=read_selector(Path('/var/lib/serein-outpost/generation-state/current.json'),
     Path('/usr/share/serein/outpost-generations'))
 selector,generation=selected
 deny(Path(__file__).absolute()!=generation/'install/kernel_first_install_runner.py'
      or Path(kernel_direct_witness.__file__).absolute()!=generation/'outpost/kernel_direct_witness.py',
      'KERNEL_OBSERVER_CALLER_GENERATION_DENIED')
 return selected


def _read_installed_stage1(plan,receipt,expectation,preserved_runtime,selected,*,
                           read_public_request=None,read_public_response=None,gateway_expectation=None):
 """Read existing native subjects only; construction and admission stay separate."""
 import secrets,time
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import compare_retained_compute_response,compare_gateway_correlation_response
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 gateway=gateway_expectation is not None
 if gateway:
  deny(expectation is not None or read_public_request is not None or read_public_response is not None,
       'GATEWAY_EXPECTATION_CONFLICT')
  gateway_expectation=strict_json(canonical(gateway_expectation))
 else:expectation=_compute_expectation(expectation)
 preserved_runtime=strict_json(canonical(preserved_runtime))
 deny(not isinstance(preserved_runtime,dict) or not preserved_runtime,
      'KERNEL_PRESERVED_RUNTIME_REQUIRED')
 boot=plan.get('current_boot_id')
 deny(preserved_runtime.get('boot_id')!=boot,'KERNEL_PRESERVED_RUNTIME_BOOT_DENIED')
 def boundary():
  deny(_native_observer_generation()!=selected or current_boot()!=boot,
       'KERNEL_OBSERVER_GENERATION_CHANGED')
 boundary()
 # Reuse the lifecycle reader's bounded external handoff, before refreshing
 # native evidence. These callbacks acquire bytes, not trust or admission.
 deny(read_public_request is not None and read_public_response is None,
      'KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED')
 deny(any(value is not None and not callable(value)
          for value in (read_public_request,read_public_response)),
      'KERNEL_PUBLIC_RESPONSE_HANDOFF_DENIED')
 public_raw=read_public_response() if read_public_response is not None else None
 deny(read_public_response is not None and
      (type(public_raw) is not bytes or not 0<len(public_raw)<=65536),
      'KERNEL_PUBLIC_RESPONSE_HANDOFF_DENIED')
 external_request=None
 if read_public_request is not None:
  try:
   original=read_public_request()
   deny(not isinstance(original,dict),'KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED')
   original_raw=canonical(original)
   deny(not 0<len(original_raw)<=65536,'KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED')
   external_request=strict_json(original_raw)
  except (TransactionError,TypeError,ValueError,RecursionError) as exc:
   raise RunnerDenied('KERNEL_PUBLIC_REQUEST_HANDOFF_DENIED') from exc
 boundary()
 anchor=regular(VERIFY_KEY)
 host=current_host_gate(HOST_STATE,boot)
 if not gateway:expectation=_bind_compute_model(plan,SOURCE,expectation)
 challenge={'schema':'SEREIN/KernelBranchWitnessRequest/v1','branch':'AUTHORITY',
     'request_id':'kernel-authority-'+secrets.token_hex(16),'nonce':secrets.token_hex(32),
     'previous_evidence_digest':'GENESIS'}
 authority=observe_installed_authority(plan,receipt,challenge)
 deny(authority.get('result')!='AUTHORITY_PHASE_A_OBSERVED','KERNEL_COMPUTE_AUTHORITY_UNPROVEN')
 authority_raw=canonical(authority)
 operations=observe_operations_lifecycle(plan,receipt,authority_raw,boundary=boundary)
 deny(operations.get('result')!='OPERATIONS_MINIMUM_OBSERVED','KERNEL_COMPUTE_OPERATIONS_UNPROVEN')
 interface=observe_installed_interface(plan,receipt,authority_raw,operations)
 deny(interface.get('result')!='PRIVATE_INTERFACE_DENIAL_CORRELATED','KERNEL_COMPUTE_INTERFACE_UNPROVEN')
 if gateway:
  compute=observe_installed_gateway(plan,receipt,authority_raw,operations,interface,gateway_expectation)
  deny(compute.get('result')!='NATIVE_HAOS_KERNEL_ANSWER_CORRELATED','GATEWAY_UNPROVEN')
 else:
  compute=observe_installed_compute(plan,receipt,authority_raw,operations,interface,expectation)
  deny(compute.get('result')!='MEASURED_COMPUTE_CORRELATED','KERNEL_COMPUTE_UNPROVEN')
 preparation={'offline_preparation':None,'preserved_runtime':preserved_runtime}
 gpu=_observe_owned_gpu(plan,compute,preparation,signed_runtime_plan=None,boundary=boundary)
 # The original observations must survive the final source/installed-closure
 # comparison. This does not create a conversation or renew any timestamp.
 envelope=(prepare_gateway_observation(plan,receipt,authority_raw,operations,interface,gateway_expectation)
           if gateway else prepare_compute_observation(plan,receipt,authority_raw,operations,interface,expectation))
 deny(_observe_owned_gpu(plan,compute,preparation,signed_runtime_plan=None,boundary=boundary)!=gpu,
      'KERNEL_GPU_INVENTORY_CHANGED')
 fresh=current_host_gate(HOST_STATE,boot)
 facts=lambda state:canonical({k:v for k,v in state['latest'].items()
                              if k not in {'observed_at','evidence_digest'}})
 deny(facts(fresh)!=facts(host) or fresh['latest']['observed_at']<host['latest']['observed_at'],
      'KERNEL_OBSERVATION_PRESTATE_CHANGED')
 deny(regular(VERIFY_KEY)!=anchor or read_operations_service_controls()!=operations['service_controls'],
      'KERNEL_OBSERVATION_PRESTATE_CHANGED')
 public_observation=None
 if public_raw is not None:
  from outpost.kernel_direct_witness import compare_public_conversation_response
  try:
   retained=compute['subject_evidence']['facts']['observation']
   runtime_raw=base64.b64decode(retained['runtime_response_b64'],validate=True)
   public_observation=compare_public_conversation_response(public_raw,
       runtime_raw=runtime_raw,expected_runtime_sha256=compute['runtime_result_sha256'],
       request=expectation['request'],external_request=external_request)
  except (KeyError,TypeError,ValueError) as exc:
   raise RunnerDenied('KERNEL_PUBLIC_RESPONSE_UNCORRELATED') from exc
 boundary()
 # Sample time AFTER all blocking reads. Original clocks expire together.
 samples=[authority,*operations['observations'],interface,compute]
 try:stamps=[datetime.fromisoformat(item['observed_at'].replace('Z','+00:00')) for item in samples]
 except (ValueError,TypeError,KeyError,AttributeError) as exc:
  raise RunnerDenied('KERNEL_OBSERVER_CLOCK_DENIED') from exc
 deny(any(stamp.utcoffset() is None for stamp in stamps),'KERNEL_OBSERVER_CLOCK_DENIED')
 now=time.time();oldest=min(stamp.timestamp() for stamp in stamps)
 deny(any(not 0<=now-stamp.timestamp()<=30 for stamp in stamps),'KERNEL_OBSERVER_STALE')
 clock=datetime.fromtimestamp(now,timezone.utc)
 deny(_compare_operations_lifecycle(plan,authority_raw,operations['observations'],
      operations['service_controls'],envelope=envelope,boot=boot,anchor=anchor,now=clock)!=operations,
      'KERNEL_COMPUTE_OPERATIONS_PREDECESSOR_DENIED')
 deny(_compare_interface_observation(plan,{**envelope,'interface_predecessor':sha(canonical(operations))},
      canonical(interface))!=interface,'KERNEL_COMPUTE_INTERFACE_PREDECESSOR_DENIED')
 if gateway:
  prior_rounds=compute.get('prior_rounds',[])
  expected_gateway=envelope['gateway_expectation']
  prior_ids=expected_gateway.get('prior_compute_request_ids',[])
  deny(not isinstance(prior_rounds,list) or len(prior_rounds)!=len(prior_ids)
       or any(not isinstance(row,dict) or set(row)!={'response','query'}
              or not isinstance(row['response'],dict) or not isinstance(row['query'],dict)
              for row in prior_rounds)
       or [row['query'].get('compute_request_id') for row in prior_rounds]!=prior_ids
       or any(row['query'].get('previous_evidence_digest')!=envelope['interface_predecessor']
              for row in prior_rounds),'GATEWAY_PREDECESSOR_DENIED')
  compared=compare_gateway_correlation_response(canonical(compute['subject_evidence']),
      query=compute['request'],source=envelope['source'],boot_id=boot,observed_at=clock,
      installed_evidence_sha256=envelope['installed_evidence_sha256'],
      prior_rounds=prior_rounds,
      **{k:v for k,v in envelope['gateway_expectation'].items()
         if k not in {'compute_request_id','prior_compute_request_ids'}})
 else:
  compared=compare_retained_compute_response(canonical(compute['subject_evidence']),
      query=compute['request'],source=envelope['source'],
      installed_evidence_sha256=envelope['installed_evidence_sha256'],boot_id=boot,
      observed_at=clock,host_state=fresh,**expectation)
 expected={**compared,'evidence_authentication':'ROOT_CREATED_PRIVATE_LISTENER',
      **({'haos_evidence_authentication':'SEPARATE_REQUIRED'} if gateway else {}),
      'native_identity_possession':'NOT_ESTABLISHED_BY_OPERATIONS','request':compute['request'],
      'observed_at':compute['observed_at'],'subject_bytes_sha256':sha(canonical(compute['subject_evidence']))}
 deny(expected!=compute,'KERNEL_COMPUTE_OUTPUT_DENIED')
 return {'result':'STAGE1_SUPPORTING_EVIDENCE_AGGREGATED','boot_id':boot,
     'observed_at':oldest,'source':operations['source'],
     'installed_evidence_sha256':operations['installed_evidence_sha256'],
     'host_projection_digest':fresh['projection_digest'],
     'native':{'authority':authority,'operations':operations,'interface':interface,
               'compute':compute,'gpu':gpu,'public_response':public_observation},
     'stage1':'NOT_READY','admission':'UNADMITTED','authority_effect':'NONE','admission_effect':'NONE'}


def _stage1_candidate(observation,plan,evidence,verifier):
 """Compose the native owner's result with separately authenticated facts.

 The callback belongs to the authenticated API acquisition owner. Evidence
 labels, hashes and local file custody do not implement that authentication.
 This function neither creates acquisition facts nor admits a lifecycle state.
 """
 from datetime import datetime,timezone
 from outpost.kernel_direct_witness import verify_stage1_candidate
 deny(not callable(verifier) or not isinstance(evidence,dict)
      or set(evidence)!={'predicate_evidence','haos_witness','seen_external_request_ids'},
      'STAGE1_EXTERNAL_EVIDENCE_REQUIRED')
 raw=canonical(evidence)
 deny(not 0<len(raw)<=65536,'STAGE1_EXTERNAL_EVIDENCE_SIZE_DENIED')
 bound=strict_json(raw)
 seen=bound['seen_external_request_ids']
 deny(not isinstance(seen,list) or any(not isinstance(value,str) or not value or len(value)>128
      for value in seen) or len(set(seen))!=len(seen),'STAGE1_REPLAY_HISTORY_DENIED')
 release=plan.get('release_digest')
 deny(not isinstance(release,str) or not re.fullmatch('sha256:[0-9a-f]{64}',release),
      'KERNEL_OBSERVATION_PLAN_DENIED')
 expected={'generation':release[7:],'commit':plan.get('source_commit'),
      'tree':plan.get('source_tree'),
      'canonical_manifest_digest':observation['source']['canonical_manifest_digest']}
 result=verify_stage1_candidate(supporting_observation=observation,expected_source=expected,
      predicate_evidence=bound['predicate_evidence'],
      gateway_correlation=observation['native']['compute'],haos_witness=bound['haos_witness'],
      evidence_verifier=verifier,observed_at=datetime.now(timezone.utc),
      seen_external_request_ids=frozenset(seen))
 deny(canonical(evidence)!=raw,'STAGE1_EXTERNAL_EVIDENCE_CHANGED')
 return result


def observe_installed_stage1(plan,receipt,expectation,*,preserved_runtime,
                             read_public_request=None,read_public_response=None,gateway_expectation=None,
                             stage1_evidence=None,evidence_verifier=None):
 """Explicit root/PVE one-shot read; never the construction CLI or admission."""
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 expectation=None if expectation is None else strict_json(canonical(expectation))
 preserved_runtime=strict_json(canonical(preserved_runtime))
 selected=_native_observer_generation()
 deny((stage1_evidence is None)!=(evidence_verifier is None)
      or (stage1_evidence is not None and gateway_expectation is None),
      'STAGE1_EXTERNAL_EVIDENCE_REQUIRED')
 with public_generation_lock(Path('/'),sha(canonical(plan)),plan.get('current_boot_id')):
  observation=_read_installed_stage1(plan,receipt,expectation,preserved_runtime,selected,
      read_public_request=read_public_request,read_public_response=read_public_response,
      **({'gateway_expectation':gateway_expectation} if gateway_expectation is not None else {}))
  if stage1_evidence is None:return observation
  result=_stage1_candidate(observation,plan,stage1_evidence,evidence_verifier)
  deny(_native_observer_generation()!=selected or current_boot()!=observation['boot_id']
       or current_host_gate(HOST_STATE,observation['boot_id'])['projection_digest']
          !=observation['host_projection_digest'],'KERNEL_OBSERVATION_PRESTATE_CHANGED')
  deny(_stage1_candidate(observation,plan,stage1_evidence,evidence_verifier)!=result,
       'STAGE1_EXTERNAL_EVIDENCE_CHANGED')
  return result


def _write_native_vitals(path,value,*,boundary):
 """Replace only the declared nonsecret summary; private atomic() is unchanged.

 Root-owned 0755 directory and 0644 summary are a separate public-data custody
 contract. Never chmod a named existing directory or read a private predecessor.
 A service-owned parent may rename its child: descriptor/name guards reject that
 substitution. Nothing here publishes a private construction witness.
 """
 import secrets
 deny(os.geteuid()!=0 or os.getegid()!=0,'VITALS_PUBLICATION_CALLER_DENIED')
 path=Path(path);data=canonical(value)
 deny(not path.is_absolute() or '..' in path.parts or path.name!='state.json'
      or len(data)>16384,'VITALS_PUBLICATION_PATH_DENIED')
 handles=[];fd=None;temporary=None;linked=False
 def signature(info):
  return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
 def check():
  for child,parent,name,before in handles:
   deny(signature(os.fstat(child))!=before,'VITALS_PUBLICATION_DIRECTORY_CHANGED')
   if parent is not None:
    deny(signature(os.stat(name,dir_fd=parent,follow_symlinks=False))!=before,
         'VITALS_PUBLICATION_DIRECTORY_CHANGED')
 def leaf():
  try:info=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
  except FileNotFoundError:return None
  deny(not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
       or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o644),
       'VITALS_PUBLICATION_CUSTODY_DENIED')
  return (signature(info),info.st_size,info.st_mtime_ns,info.st_ctime_ns)
 try:
  current=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  handles.append((current,None,None,signature(os.fstat(current))))
  for index,part in enumerate(path.parent.parts[1:]):
   if index==len(path.parent.parts[1:])-1:
    try:os.mkdir(part,0o755,dir_fd=current)
    except FileExistsError:pass
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
   handles.append((child,current,part,signature(os.fstat(child))));current=child
  fd=current
  deny(signature(os.fstat(fd))[2:]!=(0,0,0o755),'VITALS_PUBLICATION_CUSTODY_DENIED')
  check();predecessor=leaf();boundary();check()
  candidate_name='.vitals-'+secrets.token_hex(16)
  output=os.open(candidate_name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=fd)
  temporary=candidate_name
  with os.fdopen(output,'wb') as stream:
   deny((os.fstat(stream.fileno()).st_uid,os.fstat(stream.fileno()).st_gid,
         stat.S_IMODE(os.fstat(stream.fileno()).st_mode))!=(0,0,0o644),
        'VITALS_PUBLICATION_CUSTODY_DENIED')
   stream.write(data);stream.flush();os.fsync(stream.fileno())
  boundary();check()
  deny(leaf()!=predecessor,'VITALS_PUBLICATION_PREDECESSOR_CHANGED')
  if predecessor is None:
   os.link(temporary,path.name,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False)
  else:os.replace(temporary,path.name,src_dir_fd=fd,dst_dir_fd=fd);temporary=None
  linked=True
  if temporary is not None:
   os.unlink(temporary,dir_fd=fd);temporary=None
  os.fsync(fd);check()
  deny(regular(path,expected_custody=(0,0,0o644))!=data,'VITALS_PUBLICATION_READBACK_DENIED')
  boundary();check()
 except BaseException as exc:
  if linked:raise WitnessPublicationUncertain('VITALS_PUBLICATION_RECONCILIATION_REQUIRED') from exc
  if isinstance(exc,OSError):raise RunnerDenied('VITALS_PUBLICATION_IO_DENIED') from exc
  raise
 finally:
  try:
   if temporary is not None and fd is not None:
    try:os.unlink(temporary,dir_fd=fd)
    except FileNotFoundError:pass
    except OSError as exc:
     if linked:raise WitnessPublicationUncertain('VITALS_PUBLICATION_RECONCILIATION_REQUIRED') from exc
     raise
  finally:
   for child,_,_,_ in reversed(handles):os.close(child)


def publish_installed_stage1_vitals(plan,receipt,expectation,*,preserved_runtime,
                                    read_public_request=None,read_public_response=None,gateway_expectation=None,
                                    stage1_evidence=None,evidence_verifier=None):
 """Governed root one-shot: observe itself, then publish only public evidence.

 No uploaded observation is accepted and no service, source, key or admission
 is changed. The caller uses ordinary umask022; restrictive custody is denied,
 never repaired. Installation of this capability is whole-generation only.
 """
 import time
 from outpost.kernel_direct_witness import kernel_vitals_projection
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 expectation=None if expectation is None else strict_json(canonical(expectation))
 preserved_runtime=strict_json(canonical(preserved_runtime))
 selected=_native_observer_generation()
 deny((stage1_evidence is None)!=(evidence_verifier is None)
      or (stage1_evidence is not None and gateway_expectation is None),
      'STAGE1_EXTERNAL_EVIDENCE_REQUIRED')
 with public_generation_lock(Path('/'),sha(canonical(plan)),plan.get('current_boot_id')):
  observation=_read_installed_stage1(plan,receipt,expectation,preserved_runtime,selected,
      read_public_request=read_public_request,read_public_response=read_public_response,
      **({'gateway_expectation':gateway_expectation} if gateway_expectation is not None else {}))
  release=plan.get('release_digest')
  deny(not isinstance(release,str) or not re.fullmatch('sha256:[0-9a-f]{64}',release),
       'KERNEL_OBSERVATION_PLAN_DENIED')
  candidate=(_stage1_candidate(observation,plan,stage1_evidence,evidence_verifier)
             if stage1_evidence is not None else observation)
  projection=kernel_vitals_projection(candidate,outpost_generation=selected[0]['generation'],
      kernel_generation=release[7:])
  def boundary():
   host=current_host_gate(HOST_STATE,observation['boot_id'])
   deny(_native_observer_generation()!=selected or current_boot()!=observation['boot_id'],
        'KERNEL_OBSERVER_GENERATION_CHANGED')
   deny(host['projection_digest']!=projection['payload']['host_projection_digest'],
        'KERNEL_OBSERVATION_PRESTATE_CHANGED')
   deny(not 0<=time.time()-projection['observed_at']<=30,'KERNEL_OBSERVER_STALE')
   if stage1_evidence is not None:
    deny(_stage1_candidate(observation,plan,stage1_evidence,evidence_verifier)!=candidate,
         'STAGE1_EXTERNAL_EVIDENCE_CHANGED')
  boundary()
  _write_native_vitals(Path('/var/lib/serein-outpost/domains/state.json'),projection,boundary=boundary)
  return projection

def main(argv=None):
 """Wire the existing complete owner, without originating its acceptance call.

 Reuse kernel_direct_witness's private-stdin, 64KiB JSON input road. Only the
 static model selector is available before construction; read the existing
 four-field compute expectation when the owner requests it after startup.
 No timestamp, external identity, provider digest or response is synthesized.
 Public HAOS/Vitals acceptance remains a separate independently acquired fact.
 """
 import argparse,sys
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--model')
 parser.add_argument('--model-digest')
 parser.add_argument('--observe-compute',action='store_true',
     help='Read an already-acquired compute expectation on private stdin; not required for construction')
 args=parser.parse_args(argv)
 deny(os.geteuid()!=0,"KERNEL_INSTALLER_ROOT_REQUIRED")
 if args.model is None and args.model_digest is None and not args.observe_compute:
  return run(construct=True)
 model=_compute_model({'model':args.model,'model_digest':args.model_digest})
 if not args.observe_compute:
  return run(construct=True,compute_expectation=model)
 def read_expectation():
  return _read_compute_handoff(sys.stdin.buffer)
 return run(construct=True,compute_expectation=model,read_compute_expectation=read_expectation)

if __name__=="__main__":
 main()
