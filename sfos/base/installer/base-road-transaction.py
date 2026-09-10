#!/usr/bin/env python3
from __future__ import annotations
import base64,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
ROOT=Path('/'); RB=Path('/var/lib/serein/rollback'); UNIT='serein-outpost.target'
PRIV=Path('/etc/serein-outpost/cognition-signing.pem'); PUB=Path('/usr/share/serein/outpost/cognition-verification.pem')
SR=re.compile(r'outpost-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}'); JR=re.compile(r'base-road-\d{8}T\d{6}Z-[0-9a-f]{12}\.json')
PF={'schema','selector','release_digest','identity','identity_actual','identity_state','introduced_directories','introduced_files','generated_files','immutable_inputs','immutable_key_id','immutable_public_key_fingerprint_sha256','unit_prestate','rollback_complete','receipt_signature','receipt_digest'}
JF={'schema','journal','mode','source_kind','state','selectors_before','outpost_selector','parent','unit_prestate','recovery_script','recovery_script_sha256','rollback_command','receipt_signature','receipt_digest'}
def canon(v): return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(v): return hashlib.sha256(v).hexdigest()
def body(v): return canon({k:x for k,x in v.items() if k not in {'receipt_digest','receipt_signature'}})
def confined(p,base,regex):
 p=Path(os.path.abspath(p)); base=Path(os.path.abspath(base))
 if p.parent!=base or not regex.fullmatch(p.name): raise RuntimeError('CANONICAL_PATH_DENIED')
 return p
def custody(p,mode,uid=0,gid=0):
 p=Path(p); cur=ROOT
 for part in p.relative_to(ROOT).parts:
  cur/=part
  if os.path.lexists(cur) and cur.is_symlink(): raise RuntimeError('PATH_SYMLINK_DENIED')
 i=p.lstat()
 if not stat.S_ISREG(i.st_mode): raise RuntimeError('NONREGULAR_DENIED')
 if stat.S_IMODE(i.st_mode)!=mode: raise RuntimeError('MODE_DENIED')
 if (i.st_uid,i.st_gid)!=(uid,gid): raise RuntimeError('OWNER_DENIED')
def authority():
 custody(PRIV,0o640,0,PRIV.lstat().st_gid); custody(PUB,0o644)
 a=serialization.load_pem_private_key(PRIV.read_bytes(),None); b=serialization.load_pem_public_key(PUB.read_bytes())
 if not isinstance(a,Ed25519PrivateKey) or not isinstance(b,Ed25519PublicKey) or a.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)!=b.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw): raise RuntimeError('AUTHORITY_DENIED')
 return a,b
def write_signed(p,row,key):
 v={k:x for k,x in row.items() if k not in {'receipt_digest','receipt_signature'}}; v['receipt_signature']=base64.urlsafe_b64encode(key.sign(canon(v))).decode().rstrip('='); v['receipt_digest']=sha(canon(v))
 t=p.with_name(p.name+'.tmp'); fd=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 try: os.write(fd,(json.dumps(v,indent=2)+'\n').encode()); os.fsync(fd)
 finally: os.close(fd)
 os.replace(t,p); custody(p,0o600); fd=os.open(p.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)); os.fsync(fd); os.close(fd)
def read_signed(p,key):
 custody(p,0o600); v=json.loads(p.read_text())
 if v.get('receipt_digest')!=sha(canon({k:x for k,x in v.items() if k!='receipt_digest'})): raise RuntimeError('JOURNAL_DIGEST_DENIED')
 try: key.verify(base64.urlsafe_b64decode(v['receipt_signature']+'='*(-len(v['receipt_signature'])%4)),body(v))
 except Exception as e: raise RuntimeError('JOURNAL_SIGNATURE_DENIED') from e
 return v
def inventory():
 out=[]
 for p in RB.iterdir():
  if SR.fullmatch(p.name):
   i=p.lstat()
   if p.is_symlink() or not stat.S_ISDIR(i.st_mode) or stat.S_IMODE(i.st_mode)!=0o700 or (i.st_uid,i.st_gid)!=(0,0): raise RuntimeError('SELECTOR_CUSTODY_DENIED')
   out.append(p.name)
 return sorted(out)
def parent(sel,pub):
 sel=confined(sel,RB,SR); p=sel/'receipt.json'; custody(p,0o600); raw=p.read_bytes(); v=json.loads(raw)
 if set(v)!=PF or v.get('schema')!='SereinOutpostRollback/v3' or v.get('selector')!=str(sel) or v.get('rollback_complete') is not False or v.get('receipt_digest')!=sha(canon({k:x for k,x in v.items() if k!='receipt_digest'})): raise RuntimeError('PARENT_RECEIPT_DENIED')
 try: pub.verify(base64.urlsafe_b64decode(v['receipt_signature']+'='*(-len(v['receipt_signature'])%4)),canon({k:x for k,x in v.items() if k not in {'receipt_digest','receipt_signature'}}))
 except Exception as e: raise RuntimeError('PARENT_RECEIPT_SIGNATURE_DENIED') from e
 return {'path':str(p),'sha256':sha(raw),'receipt_digest':v['receipt_digest'],'release_digest':v['release_digest'],'selector':str(sel)}
def run(a,c=False): return subprocess.run(a,check=True,text=True,capture_output=c)
def ustate():
 q=lambda *a: subprocess.run(a,text=True,capture_output=True).stdout.strip()
 return {'enabled':q('systemctl','is-enabled',UNIT) or 'not-found','active':q('systemctl','is-active',UNIT) or 'inactive'}
def restore(v):
 run(['systemctl','stop',UNIT]); run(['systemctl','enable' if v['enabled']=='enabled' else 'disable',UNIT]);
 if v['active']=='active': run(['systemctl','start',UNIT])
def resolve(row):
 before=row['selectors_before']; after=inventory()
 if any(x not in after for x in before): raise RuntimeError('SELECTOR_INVENTORY_CAS_DENIED')
 added=sorted(set(after)-set(before))
 if row.get('outpost_selector'):
  p=confined(row['outpost_selector'],RB,SR)
  if added!=[p.name]: raise RuntimeError('SELECTOR_INVENTORY_CAS_DENIED')
  return p
 if len(added)!=1: raise RuntimeError('FOREIGN_SELECTOR_COLLISION_DENIED')
 return RB/added[0]
def compensate(j,row,priv,pub):
 sel=resolve(row); par=parent(sel,pub)
 if row.get('parent') and row['parent']!=par: raise RuntimeError('PARENT_RECEIPT_CAS_DENIED')
 restore(row['unit_prestate']); tx=Path('/usr/share/serein/outpost/install/transaction.py'); custody(tx,0o755); run([sys.executable,'-B',str(tx),'rollback',str(sel)])
 row={k:x for k,x in row.items() if k not in {'receipt_digest','receipt_signature'}}|{'outpost_selector':str(sel),'parent':par,'state':'COMPENSATED'}; write_signed(j,row,priv)
def recover(j):
 j=confined(j,RB,JR); priv,pub=authority(); row=read_signed(j,pub)
 expected=JF|({'unit_poststate'} if row.get('state')=='COMMITTED' else set())
 if set(row)!=expected or row.get('schema')!='SFOSBaseRoadTransaction/v2' or row.get('journal')!=str(j) or row.get('mode') not in {'CONVERGE_EXISTING','BARE_INSTALL'} or row.get('source_kind') not in {'OFFLINE_USB_MEDIA','PINNED_PUBLIC_REPOSITORY'} or row.get('state') not in {'PENDING','COMMITTED','COMPENSATED'}: raise RuntimeError('JOURNAL_SCHEMA_DENIED')
 if str(Path(__file__).resolve())!=row.get('recovery_script') or sha(Path(__file__).read_bytes())!=row.get('recovery_script_sha256'): raise RuntimeError('RECOVERY_SCRIPT_CAS_DENIED')
 if row.get('rollback_command')!=[sys.executable,'-B',row['recovery_script'],'recover',str(j)]: raise RuntimeError('ROLLBACK_COMMAND_CAS_DENIED')
 if row['state']=='PENDING': compensate(j,row,priv,pub)
 print('BASE_ROAD_RECOVERED')
def install(source,plan,mode,kind):
 if mode not in {'CONVERGE_EXISTING','BARE_INSTALL'} or kind not in {'OFFLINE_USB_MEDIA','PINNED_PUBLIC_REPOSITORY'}: raise RuntimeError('POLICY_DENIED')
 priv,pub=authority(); before=inventory(); token=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+os.urandom(6).hex(); j=RB/('base-road-'+token+'.json'); recovery=RB/('base-road-'+token+'-recover.py')
 recovery_bytes=Path(__file__).read_bytes(); fd=os.open(recovery,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o700)
 try: os.write(fd,recovery_bytes); os.fsync(fd)
 finally: os.close(fd)
 custody(recovery,0o700)
 row={'schema':'SFOSBaseRoadTransaction/v2','journal':str(j),'mode':mode,'source_kind':kind,'state':'PENDING','selectors_before':before,'outpost_selector':None,'parent':None,'unit_prestate':ustate(),'recovery_script':str(recovery),'recovery_script_sha256':sha(recovery_bytes),'rollback_command':[sys.executable,'-B',str(recovery),'recover',str(j)]}; write_signed(j,row,priv)
 try:
  tx=Path(source)/'install'/'transaction.py'; result=run([sys.executable,'-B',str(tx),'install',str(source),str(plan)],True).stdout.strip(); sel=confined(result.removeprefix('INSTALLED_INACTIVE rollback='),RB,SR)
  if sel!=resolve(row): raise RuntimeError('SELECTOR_OUTPUT_CAS_DENIED')
  row|={'outpost_selector':str(sel),'parent':parent(sel,pub)}; write_signed(j,row,priv); run(['systemctl','enable']+(['--now'] if mode=='CONVERGE_EXISTING' else [])+[UNIT]); state=ustate()
  if state['enabled']!='enabled' or (mode=='CONVERGE_EXISTING' and state['active']!='active'): raise RuntimeError('ACTIVATION_DENIED')
  if mode=='CONVERGE_EXISTING' and (run(['systemctl','show','-p','Result','--value','serein-outpost-host-witness.service'],True).stdout.strip()!='success' or run(['systemctl','is-active','serein-outpost-presentation.service'],True).stdout.strip()!='active'): raise RuntimeError('HOST_VITALS_DENIED')
  row|={'state':'COMMITTED','unit_poststate':state}; write_signed(j,row,priv); print(('OUTPOST_BOOTED_AND_HOST_VERIFIED' if mode=='CONVERGE_EXISTING' else 'OUTPOST_ENABLED_FOR_FIRST_HOST_BOOT')+' receipt='+str(j))
 except BaseException: compensate(j,row,priv,pub); raise
def main():
 if os.name=='nt' or os.geteuid()!=0: raise SystemExit('ROOT_LINUX_REQUIRED')
 if len(sys.argv)==3 and sys.argv[1]=='recover': recover(sys.argv[2]); return
 if len(sys.argv)!=6 or sys.argv[1]!='install': raise SystemExit('usage denied')
 install(Path(sys.argv[2]).resolve(),Path(sys.argv[3]).resolve(),sys.argv[4],sys.argv[5])
if __name__=='__main__': main()
