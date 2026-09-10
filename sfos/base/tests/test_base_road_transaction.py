import ast,importlib.util,json,os
from pathlib import Path
import pytest
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

R=Path(__file__).parents[1]; P=R/'installer/base-road-transaction.py'; S=P.read_text()
def load():
 spec=importlib.util.spec_from_file_location('base_road_transaction',P); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

def test_parse_and_order_are_atomic():
 ast.parse(S)
 assert S.index("write_signed(j,row,priv)") < S.index("'install',str(source),str(plan)")
 assert "'parent':parent(sel,pub)" in S and "'state':'COMMITTED'" in S

def test_activation_host_vitals_and_compensation_are_one_transaction():
 assert "['systemctl','enable']+(['--now'] if mode=='CONVERGE_EXISTING' else [])+[UNIT]" in S
 assert 'serein-outpost-host-witness.service' in S and 'serein-outpost-presentation.service' in S
 assert 'except BaseException: compensate(j,row,priv,pub)' in S
 assert "Path('/usr/share/serein/outpost/install/transaction.py')" in S
 assert 'recovery_script_sha256' in S and 'RECOVERY_SCRIPT_CAS_DENIED' in S

def test_signed_custody_and_fixed_schema_guards_exist():
 for marker in ('Ed25519PrivateKey','receipt_signature',"PF={'schema'",'SereinOutpostRollback/v3','PARENT_RECEIPT_SIGNATURE_DENIED','PATH_SYMLINK_DENIED','O_NOFOLLOW','MODE_DENIED','OWNER_DENIED','NONREGULAR_DENIED'):
  assert marker in S
 assert "row['transaction']" not in S

def test_selector_cas_and_foreign_collision_guards_exist():
 assert 'SELECTOR_INVENTORY_CAS_DENIED' in S and 'FOREIGN_SELECTOR_COLLISION_DENIED' in S
 assert "added=sorted(set(after)-set(before))" in S

def test_recomputed_digest_does_not_authorize_tamper(tmp_path,monkeypatch):
 m=load(); monkeypatch.setattr(m,'ROOT',tmp_path); key=Ed25519PrivateKey.generate(); pub=key.public_key(); p=tmp_path/'j.json'
 row={'schema':'SFOSBaseRoadTransaction/v2','state':'PENDING'}; m.write_signed(p,row,key)
 v=json.loads(p.read_text()); v['state']='COMMITTED'; v['receipt_digest']=m.sha(m.canon({k:x for k,x in v.items() if k!='receipt_digest'})); p.write_text(json.dumps(v)); os.chmod(p,0o600)
 with pytest.raises(RuntimeError,match='JOURNAL_SIGNATURE_DENIED'): m.read_signed(p,pub)

@pytest.mark.parametrize('kind,code',[('symlink','PATH_SYMLINK_DENIED'),('directory','NONREGULAR_DENIED'),('mode','MODE_DENIED'),('owner','OWNER_DENIED')])
def test_journal_custody_negatives(tmp_path,monkeypatch,kind,code):
 m=load(); monkeypatch.setattr(m,'ROOT',tmp_path); p=tmp_path/'j'
 if kind=='symlink': (tmp_path/'real').write_text('x'); p.symlink_to(tmp_path/'real')
 elif kind=='directory': p.mkdir()
 else: p.write_text('x'); os.chmod(p,0o644 if kind=='mode' else 0o600)
 if kind=='owner':
  original=Path.lstat
  class Fake:
   st_mode=0o100600; st_uid=123; st_gid=0
  monkeypatch.setattr(Path,'lstat',lambda self: Fake() if self==p else original(self))
 with pytest.raises(RuntimeError,match=code): m.custody(p,0o600)

def test_foreign_selector_collision_fails_closed(monkeypatch):
 m=load(); monkeypatch.setattr(m,'inventory',lambda:['old','outpost-first-install-20260910T000000Z-aaaaaaaaaaaa','outpost-first-install-20260910T000001Z-bbbbbbbbbbbb'])
 with pytest.raises(RuntimeError,match='FOREIGN_SELECTOR_COLLISION_DENIED'): m.resolve({'selectors_before':['old'],'outpost_selector':None})

def parent_fixture(tmp_path,monkeypatch):
 m=load(); monkeypatch.setattr(m,'ROOT',tmp_path); monkeypatch.setattr(m,'RB',tmp_path)
 selector=tmp_path/'outpost-first-install-20260910T000000Z-aaaaaaaaaaaa'; selector.mkdir(mode=0o700)
 key=Ed25519PrivateKey.generate()
 row={name:None for name in m.PF}; row.update(schema='SereinOutpostRollback/v3',selector=str(selector),release_digest='a'*64,identity={},identity_actual={},identity_state='CREATED',introduced_directories=[],introduced_files=[],generated_files=[],immutable_inputs=[],immutable_key_id='outpost-cognition-v1',immutable_public_key_fingerprint_sha256='b'*64,unit_prestate={},rollback_complete=False)
 unsigned={k:v for k,v in row.items() if k not in {'receipt_digest','receipt_signature'}}; row['receipt_signature']=base64.urlsafe_b64encode(key.sign(m.canon(unsigned))).decode().rstrip('='); row['receipt_digest']=m.sha(m.canon({k:v for k,v in row.items() if k!='receipt_digest'}))
 p=selector/'receipt.json'; p.write_text(json.dumps(row)); os.chmod(p,0o600)
 return m,selector,key,row,p

def test_exact_signed_v3_parent_is_accepted(tmp_path,monkeypatch):
 m,selector,key,row,p=parent_fixture(tmp_path,monkeypatch); observed=m.parent(selector,key.public_key())
 assert observed['selector']==str(selector) and observed['sha256']==m.sha(p.read_bytes())

def test_recomputed_parent_digest_cannot_authorize_tamper(tmp_path,monkeypatch):
 m,selector,key,row,p=parent_fixture(tmp_path,monkeypatch); row['release_digest']='c'*64; row['receipt_digest']=m.sha(m.canon({k:v for k,v in row.items() if k!='receipt_digest'})); p.write_text(json.dumps(row)); os.chmod(p,0o600)
 with pytest.raises(RuntimeError,match='PARENT_RECEIPT_SIGNATURE_DENIED'): m.parent(selector,key.public_key())

def test_digest_only_v2_parent_is_rejected(tmp_path,monkeypatch):
 m,selector,key,row,p=parent_fixture(tmp_path,monkeypatch); row['schema']='SereinOutpostRollback/v2'; row.pop('receipt_signature'); row['receipt_digest']=m.sha(m.canon({k:v for k,v in row.items() if k!='receipt_digest'})); p.write_text(json.dumps(row)); os.chmod(p,0o600)
 with pytest.raises(RuntimeError,match='PARENT_RECEIPT_DENIED'): m.parent(selector,key.public_key())
