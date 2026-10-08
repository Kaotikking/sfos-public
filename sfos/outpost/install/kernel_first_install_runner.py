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
OTHER_KERNEL_UNITS=('serein-observation-audit.service','serein-observation-audit.socket',
                    'serein-conversation-runtime.service','serein-conversation-runtime.socket',
                    'serein-kernel-client-gateway@haos.service','serein-kernel-client-gateway-haos.socket',
                    'serein-kernel-operations-heartbeat.service',
                    'serein-kernel-operations-api.service','serein-kernel-operations-api.socket')
OPERATIONS_SERVICES=('serein-kernel-operations-heartbeat.service','serein-observation-audit.service')
OPERATIONS_UNITS=('serein-kernel-operations-api.socket','serein-kernel-operations-api.service',
                  'serein-kernel-operations-heartbeat.service',
                  'serein-observation-audit.socket','serein-observation-audit.service')
INTERFACE_UNITS=('serein-kernel-client-gateway-haos.socket','serein-kernel-client-gateway@haos.service',
                 'serein-conversation-runtime.socket','serein-conversation-runtime.service')
HEX40=re.compile(r"[0-9a-f]{40}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES=16*1024*1024

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
 boot=current_boot();host=current_host_gate(host_path,boot)
 module=load_offline_installer(source,manifest,expected_release=receipt['release_digest'])
 if adapter is None:adapter=module.OfflineOllamaRealAdapter()
 plan=module.classify(adapter,Path(bundle_root),expected_before,rollback_selector,boot_id=boot,
      source_generation={'commit':receipt['source_commit'],'tree':receipt['source_tree']},request_id=request_id)
 fresh=current_host_gate(host_path,boot)
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

def install_request(path):
 request=read_json(path)
 required={"schema","target_vm_id","repository","source_parent","source_commit","source_tree","archive_sha256","rollback_selector","reserved_domain_ids"}
 version=request.get('schema')
 deny(not isinstance(version,str) or version not in {'SereinOutpostKernelInstallRequest/v1','SereinOutpostKernelInstallRequest/v2'},'KERNEL_REQUEST_DENIED')
 if version.endswith('/v2'):required.add('offline_companion')
 if 'recovered_predecessor' in request:required.add('recovered_predecessor')
 if 'installed_predecessor' in request:
  required.add('installed_predecessor')
  previous=request['installed_predecessor']
  fields={'rollback_selector','plan_sha256','receipt_sha256','journal_sha256',
          'witness_sha256','current_boot_id','machine_id_sha256','source_root','source_receipt'}
  deny('recovered_predecessor' in request or not isinstance(previous,dict) or set(previous)!=fields,
       'KERNEL_SUCCESSOR_REQUEST_DENIED')
  for key in ('source_root','source_receipt'):
   location=previous[key]
   deny(not isinstance(location,str) or not location.startswith('/var/lib/serein/rollback/')
        or '\\' in location or '\x00' in location or str(Path(location))!=location
        or '..' in Path(location).parts,'KERNEL_SUCCESSOR_SOURCE_PATH_DENIED')
 deny(set(request)!=required or request['target_vm_id']!='VM4010' or request['repository']!='Kaotikking/sfos-public','KERNEL_REQUEST_DENIED')
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

def capture_outpost_generation(root):
 """Bind the existing selected generation, without exposing its selector."""
 from .generation_launcher import read_selector
 from outpost.service import _validate_generation_identity
 root=Path(root)
 selector,generation=read_selector(root/'var/lib/serein-outpost/generation-state/current.json',
                                  root/'usr/share/serein/outpost-generations')
 _validate_generation_identity(selector)
 executing=Path(__file__).absolute()
 expected=generation/'install/kernel_first_install_runner.py'
 deny(root==Path('/') and executing!=expected.absolute(),'KERNEL_OUTPOST_EXECUTOR_GENERATION_DENIED')
 deny(regular(executing)!=regular(expected),'KERNEL_OUTPOST_EXECUTOR_SOURCE_DENIED')
 return selector


def capture_installed_kernel_prestate(root,source,expected,*,verify_path=VERIFY_KEY,witness_path=None):
 """Authenticate a successful predecessor for a whole-domain successor.

 Read-only: retain birth/replay provenance and exact public preimages. This
 does not run the first-install rollback, generate identity, quiesce services,
 authorize replacement, or describe active mutable databases as frozen.
 """
 root=Path(root);source=Path(source)
 fields={'rollback_selector','plan_sha256','receipt_sha256','journal_sha256',
         'witness_sha256','current_boot_id','machine_id_sha256'}
 deny(not isinstance(expected,dict) or set(expected)!=fields
      or any(not isinstance(expected[k],str) or not HEX64.fullmatch(expected[k])
             for k in fields-{'rollback_selector','current_boot_id'}),
      'KERNEL_SUCCESSOR_EXPECTATION_DENIED')
 expected=strict_json(canonical(expected));selector=expected['rollback_selector']
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
      or any(witness.get(k)!=plan.get(k) for k in ('source_commit','source_tree','archive_sha256',
          'release_digest','source_receipt_sha256','rollback_selector','native_identity','host_identity','host_projection_digest')),
      'KERNEL_SUCCESSOR_PREDECESSOR_DENIED')
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
  deny((root/'proc/sys/kernel/random/boot_id').read_text().strip()!=expected['current_boot_id']
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
 return {'state':'INSTALLED_PREDECESSOR_CAPTURE_ONLY','plan':plan,'receipt_digest':digest,
         'witness':witness,'expected':expected,'public_payload':public,
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
        or not any(name.startswith(prefix) for prefix in module.ROOTS)
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
 host=current_host_gate(host_path,current_boot())
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
      witness_path=STATE/'kernel-install-witness.json')
  prior_receipt,prior_receipt_digest=source_receipt(prior_source,
      Path(root)/previous['source_receipt'].lstrip('/'),verify_path)
  deny(prior_receipt_digest!=installed['plan']['source_receipt_sha256'],
       'KERNEL_SUCCESSOR_SOURCE_RECEIPT_DENIED')
  origin=installed['plan'].get('installation_origin',installed['plan'])
  deny(reserved!=origin['reserved_domain_ids'],'KERNEL_SUCCESSOR_RESERVED_CHANGED')
  deny(set(installed['public_payload'])!={row['target'] for row in rows},
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
   fact=installed['public_payload'][row['target']]['prestate']
   changed=any(fact[k]!=row[k] for k in ('bytes','sha256','mode'))
   prestate.append({**fact,'state':'PRESENT_REPLACE' if changed else 'PRESENT_PRESERVED'})
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
 host=current_host_gate(host_path,boot)
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
 fresh=current_host_gate(host_path,boot)
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


def recover_failed_construction(root,source,receipt_path,expected):
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
      or 'offline_companion' in request
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
  deny(current_boot()!=boot or capture_outpost_generation(root)!=expected['current_outpost_generation'],
       'KERNEL_RECOVERY_CURRENTNESS_CHANGED')
  module.verify_host_identity(root,plan)
  deny(read(directory/'plan.json')!=plan_raw or read(receipt_path)!=receipt_raw or read(request_path)!=request_raw
       or read(witness)!=witness_raw or regular(root/'usr/share/serein/outpost/cognition-verification.pem',expected_custody=(0,0,0o644))!=anchor,
       'KERNEL_RECOVERY_RECORD_CHANGED')
  deny(any(regular(root/path.lstrip('/'),fact=True)!=fact for path,fact in immutable.items())
       or read_kernel_enablement_prestate(root)!=links,'KERNEL_RECOVERY_PRESERVED_STATE_CHANGED')
  deny('sha256:'+sha(canonical(safe_tree(source)))!=plan['source_inventory_digest'],
       'KERNEL_RECOVERY_SOURCE_CHANGED')
 with public_generation_lock(root,expected['receipt_sha256'],boot):
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
  for names in (INTERFACE_UNITS,OPERATIONS_UNITS,(AUTHORITY_UNITS[1],AUTHORITY_UNITS[0])):
   units_boundary()
   subprocess.run(['/usr/bin/systemctl','--no-ask-password','--job-mode=replace','stop',*names],
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
  for row in receipt['prestate']:
   observed=module.target_prestate(root,row,generated=row['state']=='ABSENT')
   deny(observed!=(row if row['state']=='ABSENT' else {**row,'state':'PRESENT_PRESERVED'}),
        'KERNEL_RECOVERY_PRESTATE_UNPROVEN')
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
     {'listening','running'} if name.endswith('.socket') else {'running'})


def _read_kernel_units(names,*,service_controls=False,allow_transitional=False):
 import subprocess
 deny(type(service_controls) is not bool or type(allow_transitional) is not bool
      or (service_controls and allow_transitional) or
      (names!=OPERATIONS_SERVICES if service_controls else names not in (AUTHORITY_UNITS,OTHER_KERNEL_UNITS)),
      'KERNEL_UNIT_SET_DENIED')
 properties=('Id','LoadState','ActiveState','SubState','UnitFileState',
             'FragmentPath','DropInPaths','NeedDaemonReload')
 if service_controls:
  properties+=('MainPID','ExecMainStartTimestampMonotonic','InvocationID','User','Group',
               'Restart','RestartUSec','NRestarts','Result','KillMode')
 captured={}
 for name in names:
  try:
   result=subprocess.run(['/usr/bin/systemctl','show','--all','--no-pager',
       '--property='+','.join(properties),name],capture_output=True,text=True,
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
  deny(set(value)!=set(properties) or value['Id']!=name
       or value['LoadState'] not in {'loaded','not-found'}
       or value['NeedDaemonReload'] not in {'yes','no'} or value['DropInPaths']
       or not value['ActiveState'] or not value['SubState'],
       'KERNEL_AUTHORITY_UNIT_PRESTATE_DENIED')
  if value['LoadState']=='not-found':
   deny(value['FragmentPath'] or value['UnitFileState']
        or value['ActiveState']!='inactive' or value['SubState']!='dead',
        'KERNEL_AUTHORITY_UNIT_PRESTATE_DENIED')
  else:
   fragment=('serein-kernel-client-gateway@.service'
             if name=='serein-kernel-client-gateway@haos.service' else name)
   deny(value['FragmentPath']!='/etc/systemd/system/'+fragment or not value['UnitFileState'],
        'KERNEL_AUTHORITY_UNIT_PRESTATE_DENIED')
   settled=_unit_active(name,value) or (value['ActiveState'],value['SubState']) in {
           ('inactive','dead'),('failed','failed')}
   # Cleanup must be able to cancel this attempt's still-pending start/stop.
   # This is NOT a ready state; only exception cleanup opts into this read.
   transitional=(allow_transitional and value['ActiveState'] in {'activating','deactivating','reloading'}
                 and re.fullmatch(r'[a-z][a-z-]{0,63}',value['SubState']))
   deny(not (settled or transitional)
        or value['UnitFileState'] not in {'enabled','disabled','static'},
        'KERNEL_AUTHORITY_UNIT_UNSETTLED_DENIED')
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
 offline=request.get('offline_companion');boot=current_boot()
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
 fresh=prepare_offline_companion(SOURCE,Path(offline['bundle_root']),offline['expected_before'],
     offline['rollback_selector'],offline['request_id'])
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
    consumers['quiesce']();runtime_mutating=True
    current_boundary()
    if installed is not None:module.rollback(adapter,selector)
    # An absent install return can mean its internal compensation failed.
    # Independently read restored prestate without retrying that mutation.
    module.verify_completed_rollback(adapter,selector,
        expected_plan_sha256=signed_runtime_plan['plan_sha256'])
    runtime_disposition['restored']=True
   except BaseException as exc:
    raise RuntimeCompensationUncertain('KERNEL_RUNTIME_COMPENSATION_UNPROVEN') from exc
 if owner is not None:owner.retain(cleanup,current_boundary)
 try:
  # Stop socket activation and every private consumer before install; the
  # callee can compensate its own failure before returning to this owner.
  consumers['quiesce']();runtime_mutating=True;current_boundary()
  runtime_disposition.update(attempted=True,restored=False)
  installed=module.install(adapter,Path(offline['bundle_root']),signed_runtime_plan,selector)
  current_boundary()
  deny(installed.get('receipt_digest')!=module.receipt_digest(installed)
       or installed.get('scope')!='RUNTIME_DEPENDENCY_ONLY'
       or installed.get('rollback_complete') is not False,
       'KERNEL_OFFLINE_DEPENDENCY_RECEIPT_DENIED')
  acceptance=installed.get('acceptance')
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
 except BaseException:
  if owner is not None:owner.abort()
  else:cleanup()
  raise


def _observe_installed_branch(plan,receipt,prior,*,branch):
 import selectors,subprocess,time
 from .generation_launcher import read_selector
 deny(os.geteuid()!=0,'KERNEL_OBSERVER_CALLER_DENIED')
 deny(branch not in {'AUTHORITY','OPERATIONS','INTERFACE','COMPUTE'},'KERNEL_OBSERVER_BRANCH_DENIED')
 plan=strict_json(canonical(plan));receipt=strict_json(canonical(receipt))
 if branch=='AUTHORITY':
  prior=strict_json(canonical(prior))
  envelope=prepare_authority_observation(plan,receipt,prior)
 elif branch=='INTERFACE':
  envelope=prepare_interface_observation(plan,receipt,*prior)
 elif branch=='COMPUTE':
  envelope=prepare_compute_observation(plan,receipt,*prior)
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
      '-' if branch=='COMPUTE' else encoded.decode('utf-8')],
      stdin=subprocess.PIPE if branch=='COMPUTE' else subprocess.DEVNULL,
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
 offline=request.get('offline_companion')
 if offline is not None:
  if bundle_adapter is not None:
   deny(Path(bundle_adapter.root)!=Path(root) or bundle_adapter.boot_id!=boot,'KERNEL_OFFLINE_TARGET_DENIED')
  else:
   deny(Path(root)!=Path('/'),'KERNEL_OFFLINE_TARGET_DENIED')
 else:
  deny(bundle_adapter is not None,'KERNEL_OFFLINE_TARGET_DENIED')
 plan,host=build_plan(source,request_path,host_path,verify_path,source_receipt_path,root=root)
 prepared=None;preserved_runtime=None;runtime_adapter=None
 if offline is not None:
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
 fresh=current_host_gate(host_path,boot)
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
  observed=current_host_gate(host_path,boot)
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
  if preparation['offline_preparation'] is None:
   preserved=preparation['preserved_runtime']
   deny(binding['runtime']!=preserved,'KERNEL_PRESERVED_RUNTIME_CHANGED')
   adapter.observe_runtime(expected=preserved)
   recipe='PRESERVED_PROCESS_NOT_SIGNED_RECIPE'
  else:
   deny(not isinstance(signed_runtime_plan,dict),'KERNEL_OFFLINE_SIGNED_PLAN_DENIED')
   module.verify_gpu_runtime_recipe(binding,signed_runtime_plan,gpu_module=gpu_module)
   recipe='SIGNED_RUNTIME_RECIPE_MATCH'
  deny(gpu_module.collect()!=gpu or current_boot()!=plan['current_boot_id'],
       'KERNEL_GPU_INVENTORY_CHANGED')
  boundary()
  deny(regular(SOURCE/relative)!=gpu_raw or regular(Path(target))!=gpu_raw,
       'KERNEL_GPU_SOURCE_CHANGED')
 except (ValueError,KeyError,TypeError,OSError,module.TransactionError) as exc:
  raise RunnerDenied('KERNEL_GPU_PROCESS_BINDING_UNPROVEN') from exc
 return {'result':'RUNTIME_GPU_PROCESS_OBSERVED','binding':binding,
     'runtime_recipe':recipe,'runtime_result_sha256':compute['runtime_result_sha256'],
     'stage1':'NOT_READY','authority_effect':'NONE','admission_effect':'NONE'}


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
 deny((replacement is None)!=(request.get('offline_companion') is None),
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
 try:
  with _authority_lifecycle(plan,receipt,challenge,boundary=boundary,owner=owner) as authority:
   with _operations_lifecycle(plan,receipt,canonical(authority),boundary=boundary,owner=owner) as operations:
    with _interface_lifecycle(plan,receipt,canonical(authority),operations,boundary=boundary,owner=owner) as interface:
     if replacement is None:
      observations=observe(authority,operations,interface['denial_observation'])
     else:
      with _offline_companion_lifecycle(plan,receipt,canonical(authority),operations,
          request,replacement,signed_runtime_plan,boundary=boundary,
          consumers=interface['_runtime_consumers'],runtime_disposition=runtime_disposition,
          owner=owner) as runtime:
       authority=runtime['authority'];operations=runtime['operations']
       interface=observe_installed_interface(plan,receipt,canonical(authority),operations)
       observations=observe(authority,operations,interface)
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


@contextmanager
def _quiesce_installed_kernel(prestate,*,guard,verify_predecessor,verify_restored,publication,retain_prestate=None):
 """Whole-successor owner: stop only the exact installed Kernel units.

 No host, Outpost, runtime/model or enablement effect. On failure the old
 generation may restart only after its exact signed files are restored.
 """
 import subprocess
 groups=(AUTHORITY_UNITS,OPERATIONS_UNITS,INTERFACE_UNITS)
 names=set(AUTHORITY_UNITS+OTHER_KERNEL_UNITS)
 deny(set(prestate)!=names,'KERNEL_SUCCESSOR_UNIT_SET_DENIED')
 for name,row in prestate.items():
  deny(row['LoadState']!='loaded' or row['NeedDaemonReload']!='no'
       or not (_unit_active(name,row) or (row['ActiveState'],row['SubState'])==('inactive','dead')
               or (name in OPERATIONS_SERVICES and (row['ActiveState'],row['SubState'])==('failed','failed'))),
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
  if not units:return
  guard()
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
 failed=tuple(name for name in OPERATIONS_SERVICES if original[name]['ActiveState']=='failed')
 if failed:
  deny(not callable(retain_prestate),'KERNEL_SUCCESSOR_FAILURE_EVIDENCE_REQUIRED')
  retain_prestate(original)
  guard();verify_predecessor()
  deny(read()!=original,'KERNEL_SUCCESSOR_UNIT_PRESTATE_CHANGED')
 try:
  for units in reversed(groups):
   definitions(read());attempted=True;command('stop',units)
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
    for units in groups:
     command('start',tuple(name for name in units if _unit_active(name,original[name])))
    current=read();definitions(current)
    deny(any((_unit_active(name,current[name]) if _unit_active(name,original[name]) else
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
 complete=(construct or request['schema']=='SereinOutpostKernelInstallRequest/v2'
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
  deny((prepared['offline_preparation'] is not None)!=(request.get('offline_companion') is not None)
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
  def material_boundary():
   check_material()
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
        witness_path=STATE/'kernel-install-witness.json')
   def verify_restored():
    # Restored runtime bytes alone cannot restart a generation against a new
    # canonical source inbox. Require its original signed provider binding.
    old=verify_predecessor()['plan']
    parked=Path(root)/plan['rollback_selector'].lstrip('/')/'candidate-source'
    immutable_before={name:regular(Path(root)/name.lstrip('/'),fact=True) for name in IMMUTABLE_POLICY}
    retained_material=None
    def retained_guard():
     nonlocal retained_material
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
    failed=[name for name in OPERATIONS_SERVICES if rows[name]['ActiveState']=='failed']
    deny(any(controls[name]['MainPID']!='0' or any(controls[name][key]!=rows[name][key]
             for key in rows[name]) for name in failed),'KERNEL_SUCCESSOR_FAILED_PROCESS_CHANGED')
    evidence={'schema':'SereinKernelSuccessorQuiescence/v1','boot_id':boot,
        'request_sha256':sha(request_raw),'plan_sha256':sha(canonical(plan)),
        'rollback_selector':plan['rollback_selector'],'unit_prestate':rows,
        'operations_service_controls':controls,'failed_predecessors':failed,
        'failed_predecessor_compensation':'REMAIN_INACTIVE_NEVER_RESTART'}
    evidence['evidence_digest']=sha(canonical(evidence))
    def evidence_boundary():
     material_boundary();verify_predecessor()
     deny(read_operations_service_controls()!=controls,'KERNEL_SUCCESSOR_FAILED_PROCESS_CHANGED')
    atomic(STATE/('kernel-successor-quiescence-'+sha(request_raw)+'.json'),
        evidence,witness_fd,evidence_boundary)
   successor_scope.enter_context(_quiesce_installed_kernel(unit_prestate,guard=material_boundary,
       verify_predecessor=verify_predecessor,verify_restored=verify_restored,publication=publication,
       retain_prestate=retain_prestate))
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
  runtime_disposition={'attempted':False,'restored':False}
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
    restored_selector=Path(request['offline_companion']['rollback_selector'])
    def compensation_boundary():
     try:
      boundary()
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
