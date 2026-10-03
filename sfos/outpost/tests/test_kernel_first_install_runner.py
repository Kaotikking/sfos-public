"""Outpost runner only: native Linux fixtures, no systemd or live VM effects.

Installer fixture: sfos-public 0dca6bd7a22b83b04ddf353df901d2c7ea15c294,
blob 5bf3262555b138e8384bc409210173c1880fb22a, kept as test-only input.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
from install import kernel_first_install_runner as runner
from outpost.host_vitality import HostVitalityStore
from tests.test_host_vitality import observation


def put(path,data,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data);path.chmod(mode)
    return path


@pytest.fixture
def candidate(tmp_path,monkeypatch):
    root=tmp_path/'host';root.mkdir()
    state=root/'var/lib/serein-outpost/kernel';state.mkdir(parents=True);state.chmod(0o700)
    source=state/'source/sfos/kernel';source.mkdir(parents=True)
    key=Ed25519PrivateKey.generate()
    signer=put(root/'etc/serein-outpost/cognition-signing.pem',key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()),0o640)
    anchor=put(root/'usr/share/serein/outpost/cognition-verification.pem',key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo),0o644)
    hostroot=root/'var/lib/serein-outpost/host-vitality'
    host=HostVitalityStore(hostroot).record(observation())
    os.chown(hostroot/'state.json',978,978)
    request_path=state/'install-request.json';source_receipt=state/'source-receipt.json'
    for name,value in {'STATE':state,'REQUEST':request_path,'HOST_STATE':hostroot/'state.json','SIGNING_KEY':signer,'VERIFY_KEY':anchor,'SOURCE_RECEIPT':source_receipt}.items():monkeypatch.setattr(runner,name,value)
    # Synthetic fixture authority; real canonical key is not read or modified.
    monkeypatch.setattr(runner,'CANONICAL_AUTHORITY_SHA256',runner.sha(anchor.read_bytes()))
    monkeypatch.setattr(runner,'IMMUTABLE_POLICY',{'/usr/share/serein/outpost/cognition-verification.pem':'0644'})
    monkeypatch.setattr(runner,'current_boot',lambda:host['current_boot_id'])
    monkeypatch.setattr(runner.pwd,'getpwnam',lambda name:SimpleNamespace(pw_uid=978 if name=='serein-outpost' else 977,pw_gid=978 if name=='serein-outpost' else 977))
    monkeypatch.setattr(runner.grp,'getgrnam',lambda name:SimpleNamespace(gr_gid=978 if name=='serein-outpost' else 977,gr_mem=[]))
    put(root/'proc/sys/kernel/random/boot_id',(host['current_boot_id']+'\n').encode(),0o644)
    (root/'var/lib/serein/rollback').mkdir(parents=True,mode=0o755)
    payload=[]
    for branch in runner.ORDER:
        name=branch.lower()+'.py';data=('# inert '+branch+'\n').encode();put(source/'payload'/name,data,0o644)
        payload.append(['payload/'+name,len(data),runner.sha(data),'0644'])
    layout={'payload_roots':{'payload':'/usr/lib/serein/kernel'}}
    put(source/'install-layout.json',runner.canonical(layout),0o644)
    donor=Path(__file__).with_name('donor_kernel_first_install.py').read_bytes()
    assert hashlib.sha1(b'blob '+str(len(donor)).encode()+b'\0'+donor).hexdigest()=='5bf3262555b138e8384bc409210173c1880fb22a'
    put(source/'install/kernel_first_install.py',donor,0o755)
    manifest={'payload':payload,'payload_digest':'sha256:'+runner.sha(runner.canonical(payload)),
              'installer_files':[['install/kernel_first_install.py',len(donor),runner.sha(donor),'0755']]}
    rows=runner.payload_rows(source,manifest,layout)
    manifest['install_denominator_digest']='sha256:'+runner.sha(runner.canonical(rows))
    manifest['self_digest']='sha256:'+runner.sha(runner.canonical(manifest))
    put(source/'release-manifest.json',runner.canonical(manifest),0o644)
    request={'schema':'SereinOutpostKernelInstallRequest/v1','target_vm_id':'VM4010','repository':'Kaotikking/sfos-public',
             'source_parent':'a'*40,'source_commit':'b'*40,'source_tree':'c'*40,'archive_sha256':'d'*64,
             'rollback_selector':'/var/lib/serein/rollback/kernel-first-install-20260929T000000Z-abcdef123456'}
    put(request_path,runner.canonical(request))
    receipt={k:request[k] for k in ('repository','source_parent','source_commit','source_tree','archive_sha256')}
    receipt.update(schema='SereinOutpostKernelSourceReceipt/v1',ref='refs/heads/main',release_digest=manifest['self_digest'],
                   inventory_digest='sha256:'+runner.sha(runner.canonical(runner.safe_tree(source))))
    receipt['signature']=base64.urlsafe_b64encode(key.sign(runner.canonical(receipt))).decode().rstrip('=')
    put(source_receipt,runner.canonical(receipt))
    args=dict(root=root,source=source,request_path=request_path,host_path=hostroot/'state.json',signing_path=signer,verify_path=anchor,source_receipt_path=source_receipt)
    return args,host


def test_exact_donor_installer_produces_inactive_receipt_under_outpost(candidate):
    args,_=candidate
    result=runner.run(**args)
    assert result['install_status']=='INSTALLED_INACTIVE'
    assert result['stage1']=='NOT_READY' and result['admission']=='INDEPENDENT_AUDIT_PENDING'
    assert result['authority_effect']=='NONE'
    for branch in runner.ORDER:assert (args['root']/'usr/lib/serein/kernel'/f'{branch.lower()}.py').is_file()
    assert json.loads((runner.STATE/'kernel-install-witness.json').read_bytes())==result
    assert not (args['root']/'etc/systemd').exists()
    assert not (args['root']/'var/lib/serein/rollback/.outpost-public-generation.lock').exists()


def test_current_host_gate_rejects_stale_or_forged_pass(candidate):
    args,host=candidate
    with pytest.raises(runner.RunnerDenied,match='HOST_GATE_DENIED'):
        runner.current_host_gate(args['host_path'],'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee')
    host['latest']['gpu']['driver_loaded']=False
    args['host_path'].write_bytes(runner.canonical(host))
    with pytest.raises(runner.RunnerDenied,match='HOST_GATE_DENIED'):runner.run(**args)
    assert not (args['root']/'usr/lib/serein/kernel').exists()


def test_root_private_witness_is_create_only_and_custody_bound(tmp_path):
    tmp_path.chmod(0o700);path=tmp_path/'witness.json'
    with runner.witness_directory(tmp_path) as (fd,unchanged):
        runner.atomic(path,{'result':'first'},fd,unchanged)
        with pytest.raises(runner.RunnerDenied,match='COLLISION'):runner.atomic(path,{'result':'second'},fd,unchanged)
        assert json.loads(path.read_bytes())=={'result':'first'}
        tmp_path.chmod(0o777)
        with pytest.raises(runner.RunnerDenied,match='PARENT_CHANGED'):unchanged()
        tmp_path.chmod(0o700)


def test_existing_signer_mode_and_immutable_group_are_preserved(candidate):
    args,_=candidate
    assert runner.regular(args['signing_path'])
    assert args['signing_path'].stat().st_mode&0o777==0o640
    before=runner.regular(args['verify_path'],fact=True)
    os.chown(args['verify_path'],0,12345)
    assert runner.regular(args['verify_path'],fact=True)!=before


def test_source_change_at_installer_boundary_denies_effect(candidate):
    args,_=candidate
    def bad_source(root,source,plan,*,boundary):
        (source/'payload/authority.py').write_bytes(b'changed')
        boundary()
        pytest.fail('boundary permitted changed input')
    with pytest.raises(runner.RunnerDenied,match='SOURCE_CHANGED'):runner.run(**args,installer=bad_source)
    assert not (args['root']/'usr/lib/serein/kernel').exists()


def test_compiled_bytes_must_match_signed_manifest(candidate,monkeypatch):
    args,_=candidate;original=runner.regular;reads=0
    def swapped(path,**kwargs):
        nonlocal reads
        value=original(path,**kwargs)
        if path==args['source']/'install/kernel_first_install.py':
            reads+=1
            # source receipt, plan denominator, pre-execution inventory, then
            # the exact bytes about to be compiled (not another disk check).
            if reads==4:return value+b'\nraise AssertionError("MUST_NOT_EXECUTE")\n'
        return value
    monkeypatch.setattr(runner,'regular',swapped)
    with pytest.raises(runner.RunnerDenied,match='INSTALLER_DENOMINATOR'):runner.run(**args)
    assert reads==4 and not (args['root']/'usr/lib/serein/kernel').exists()


def test_immutable_group_change_is_denied_at_write_boundary(candidate):
    args,_=candidate
    def changed_group(root,source,plan,*,boundary):
        os.chown(args['verify_path'],0,12345);boundary()
        pytest.fail('changed key custody permitted')
    with pytest.raises(runner.RunnerDenied,match='IMMUTABLE_CHANGED'):runner.run(**args,installer=changed_group)
    assert not (args['root']/'usr/lib/serein/kernel').exists()
