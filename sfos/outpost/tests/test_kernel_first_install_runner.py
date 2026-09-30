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
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption,load_pem_private_key
from install import kernel_first_install_runner as runner
from outpost.host_vitality import HostVitalityStore,digest as host_digest
from tests.test_host_vitality import observation


def put(path,data,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data);path.chmod(mode)
    return path


def use_current_installer(args):
    """Replace the historical fixture installer and reseal its synthetic receipt."""
    source=args['source']
    path=Path(__file__).resolve().parents[2]/'kernel/install/kernel_first_install.py'
    candidate_bytes=path.read_bytes()
    put(source/'install/kernel_first_install.py',candidate_bytes,0o755)
    manifest=json.loads((source/'release-manifest.json').read_bytes())
    manifest.update(schema='SereinPortableKernelRelease/v1',branch_order=list(runner.ORDER),
                    classification='PUBLIC_KERNEL_COMPANION_FOUNDATION_INACTIVE',
                    activation='OUTPOST_ONLY_AFTER_INACTIVE_PROOF',
                    installer_files=[['install/kernel_first_install.py',len(candidate_bytes),
                                      runner.sha(candidate_bytes),'0755']])
    manifest.pop('self_digest')
    manifest['self_digest']='sha256:'+runner.sha(runner.canonical(manifest))
    put(source/'release-manifest.json',runner.canonical(manifest),0o644)
    source_receipt=json.loads(args['source_receipt_path'].read_bytes())
    source_receipt.pop('signature')
    source_receipt['release_digest']=manifest['self_digest']
    source_receipt['inventory_digest']='sha256:'+runner.sha(
        runner.canonical(runner.safe_tree(source)))
    key=load_pem_private_key(args['signing_path'].read_bytes(),password=None)
    source_receipt['signature']=base64.urlsafe_b64encode(
        key.sign(runner.canonical(source_receipt))).decode().rstrip('=')
    put(args['source_receipt_path'],runner.canonical(source_receipt))


@pytest.fixture
def candidate(tmp_path,monkeypatch):
    root=tmp_path/'host';root.mkdir()
    state=root/'var/lib/serein-outpost/kernel';state.mkdir(parents=True);state.chmod(0o700)
    source=state/'source/sfos/kernel';source.mkdir(parents=True)
    key=Ed25519PrivateKey.generate()
    signer=put(root/'etc/serein-outpost/cognition-signing.pem',key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()),0o640)
    anchor=put(root/'usr/share/serein/outpost/cognition-verification.pem',key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo),0o644)
    hostroot=root/'var/lib/serein-outpost/host-vitality'
    host_observation=observation()
    host_observation['host']['machine_id']='e'*32
    host_observation['evidence_digest']=host_digest(
        {key:value for key,value in host_observation.items() if key!='evidence_digest'})
    host=HostVitalityStore(hostroot).record(host_observation)
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
    put(root/'etc/machine-id',(host['latest']['host']['machine_id']+'\n').encode(),0o444)
    (root/'var/lib/serein/rollback').mkdir(parents=True,mode=0o755)
    payload=[]
    for branch in runner.ORDER:
        name=branch.lower()+'.py';relative='payload/runtime/'+name
        data=('# inert '+branch+'\n').encode();put(source/relative,data,0o644)
        payload.append([relative,len(data),runner.sha(data),'0644'])
    native_relative='payload/serein_stage1/domain_identity.py'
    native_bytes=(Path(__file__).resolve().parents[2]/'kernel/payload/serein_stage1/domain_identity.py').read_bytes()
    put(source/native_relative,native_bytes,0o644)
    payload.append([native_relative,len(native_bytes),runner.sha(native_bytes),'0644'])
    layout={'payload_roots':{'payload/serein_stage1':'/usr/lib/python3/dist-packages/serein_stage1',
                             'payload/runtime':'/usr/lib/serein/kernel'},
            'payload_branches':dict(zip((row[0] for row in payload),runner.ORDER))}
    layout['payload_branches'][native_relative]='AUTHORITY'
    put(source/'install-layout.json',runner.canonical(layout),0o644)
    donor=Path(__file__).with_name('donor_kernel_first_install.py').read_bytes()
    assert hashlib.sha1(b'blob '+str(len(donor)).encode()+b'\0'+donor).hexdigest()=='5bf3262555b138e8384bc409210173c1880fb22a'
    put(source/'install/kernel_first_install.py',donor,0o755)
    manifest={'schema':'SereinPortableKernelRelease/v1','branch_order':list(runner.ORDER),
              'activation':'OUTPOST_ONLY_AFTER_INACTIVE_PROOF',
              'payload':payload,'payload_digest':'sha256:'+runner.sha(runner.canonical(payload)),
              'installer_files':[['install/kernel_first_install.py',len(donor),runner.sha(donor),'0755']]}
    rows=runner.payload_rows(source,manifest,layout)
    manifest['install_denominator_digest']='sha256:'+runner.sha(runner.canonical(rows))
    manifest['self_digest']='sha256:'+runner.sha(runner.canonical(manifest))
    put(source/'release-manifest.json',runner.canonical(manifest),0o644)
    request={'schema':'SereinOutpostKernelInstallRequest/v1','target_vm_id':'VM4010','repository':'Kaotikking/sfos-public',
             'source_parent':'a'*40,'source_commit':'b'*40,'source_tree':'c'*40,'archive_sha256':'d'*64,
             'rollback_selector':'/var/lib/serein/rollback/kernel-first-install-20260929T000000Z-abcdef123456',
             'reserved_domain_ids':[]}
    put(request_path,runner.canonical(request))
    receipt={k:request[k] for k in ('repository','source_parent','source_commit','source_tree','archive_sha256')}
    receipt.update(schema='SereinOutpostKernelSourceReceipt/v1',ref='refs/heads/main',release_digest=manifest['self_digest'],
                   inventory_digest='sha256:'+runner.sha(runner.canonical(runner.safe_tree(source))))
    receipt['signature']=base64.urlsafe_b64encode(key.sign(runner.canonical(receipt))).decode().rstrip('=')
    put(source_receipt,runner.canonical(receipt))
    args=dict(root=root,source=source,request_path=request_path,host_path=hostroot/'state.json',signing_path=signer,verify_path=anchor,source_receipt_path=source_receipt)
    return args,host


@pytest.mark.parametrize('field,value',(
    ('schema','SereinPublicKernelRelease/v1'),
    ('gate','KERNEL_AUTHORITY'),
    ('activation','ACTIVATE_NOW'),
    ('activation',None),
    ('branch_order',['INTERFACE','OPERATIONS','AUTHORITY']),
    ('branch_order',None),
))
def test_install_plan_rejects_policy_that_handoff_would_reject(candidate,field,value):
    """An authenticated package must pass the same policy before file effects."""
    args,_=candidate;use_current_installer(args)
    path=args['source']/'release-manifest.json'
    manifest=json.loads(path.read_bytes());manifest[field]=value
    manifest.pop('self_digest')
    manifest['self_digest']='sha256:'+runner.sha(runner.canonical(manifest))
    put(path,runner.canonical(manifest),0o644)
    receipt=json.loads(args['source_receipt_path'].read_bytes());receipt.pop('signature')
    receipt['release_digest']=manifest['self_digest']
    receipt['inventory_digest']='sha256:'+runner.sha(runner.canonical(runner.safe_tree(args['source'])))
    key=load_pem_private_key(args['signing_path'].read_bytes(),password=None)
    receipt['signature']=base64.urlsafe_b64encode(key.sign(runner.canonical(receipt))).decode().rstrip('=')
    put(args['source_receipt_path'],runner.canonical(receipt))
    before={str(p):p.read_bytes() for p in args['root'].rglob('*') if p.is_file()}
    with pytest.raises(runner.RunnerDenied,match='KERNEL_MANIFEST_POLICY_DENIED'):
        runner.build_plan(**{k:v for k,v in args.items() if k!='signing_path'})
    assert {str(p):p.read_bytes() for p in args['root'].rglob('*') if p.is_file()}==before
    assert not (runner.STATE/'kernel-install-witness.json').exists()
    assert not (args['root']/'usr/lib/serein/kernel').exists()


@pytest.mark.parametrize('fault',(None,'witness-selector','plan','source','boot'))
def test_read_authority_handoff_uses_original_plan_without_effects(candidate,monkeypatch,fault):
    args,_=candidate;use_current_installer(args)
    installed=runner.run(**args)
    witness_path=runner.STATE/'kernel-install-witness.json'
    expected=runner.sha(witness_path.read_bytes())
    plan_path=args['root']/installed['rollback_selector'].lstrip('/')/'plan.json'
    plan_before=plan_path.read_bytes()
    before={str(path):path.read_bytes() for path in args['root'].rglob('*') if path.is_file()}
    original_regular=runner.regular
    def read_only(path,**kwargs):
        assert Path(path)!=args['signing_path'], 'handoff must not read the installer signer'
        return original_regular(path,**kwargs)
    monkeypatch.setattr(runner,'regular',read_only)
    def no_reconstruction(*args,**kwargs):
        pytest.fail('read-only handoff attempted plan reconstruction or installation')
    monkeypatch.setattr(runner,'build_plan',no_reconstruction)
    monkeypatch.setattr(runner,'run',no_reconstruction)
    if fault=='witness-selector':expected='0'*64
    elif fault=='plan':plan_path.write_bytes(plan_before+b' ')
    elif fault=='source':
        source_file=args['source']/'payload/runtime/authority.py'
        source_file.write_bytes(source_file.read_bytes()+b'# drift\n')
    elif fault=='boot':monkeypatch.setattr(runner,'current_boot',lambda:'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee')
    call=lambda:runner.read_authority_handoff(
        expected_witness_sha256=expected,**{key:args[key] for key in (
            'root','source','host_path','verify_path','source_receipt_path')})
    if fault is not None:
        with pytest.raises(runner.RunnerDenied):call()
        return
    handoff=call()
    assert set(handoff)=={'source','identity'}
    assert handoff['identity']['binding']==installed['native_identity']
    registry=args['root']/runner.NATIVE_REGISTRY.lstrip('/')
    assert handoff['identity']['registry']==json.loads(registry.read_bytes())
    assert handoff['source']=={
        'source_commit':installed['source_commit'],'source_tree':installed['source_tree'],
        'canonical_manifest_digest':runner.sha((args['source']/'release-manifest.json').read_bytes())}
    # Consume the actual handoff through Outpost's independent public verifier.
    # Only the synthetic fixture anchor is substituted; no socket/service runs.
    from outpost import kernel_direct_witness as observer
    anchor=args['verify_path'].read_bytes()
    monkeypatch.setattr(observer,'CANONICAL_AUTHORITY_SHA256',runner.sha(anchor))
    admitted_record=observer.expected_identity(handoff['identity'],anchor,handoff['source'])
    assert admitted_record['instance_id']==installed['native_identity']['instance_id']
    assert admitted_record['authority_effect']==admitted_record['admission_effect']=='NONE'
    assert plan_path.read_bytes()==plan_before
    assert {str(path):path.read_bytes() for path in args['root'].rglob('*') if path.is_file()}==before
    assert (args['root']/runner.NATIVE_KEY.lstrip('/')).read_bytes() not in runner.canonical(handoff)
    assert not (args['root']/'etc/systemd').exists()
    assert not (runner.STATE/'authority-observation.json').exists()


def test_exact_local_package_installs_inactive_and_supplies_original_handoff(candidate,monkeypatch):
    """Real candidate bytes, synthetic Host/signer, no systemd/live acceptance."""
    args,_=candidate
    package=Path(__file__).resolve().parents[2]/'kernel'
    manifest_raw=(package/'release-manifest.json').read_bytes()
    manifest=json.loads(manifest_raw)
    source=args['source']
    fixture_manifest=json.loads((source/'release-manifest.json').read_bytes())
    candidate_paths={row[0] for row in manifest['payload']}
    # Only the explicit synthetic fixture files, never workspace source.
    for relative,_,_,_ in fixture_manifest['payload']:
        if relative not in candidate_paths:
            fixture_path=source/relative
            assert fixture_path.resolve().is_relative_to(args['root'].resolve())
            fixture_path.unlink()
    for relative,size,digest,mode in manifest['payload']+manifest['installer_files']:
        raw=(package/relative).read_bytes()
        assert (len(raw),runner.sha(raw))==(size,digest)
        put(source/relative,raw,int(mode,8))
    put(source/'install-layout.json',(package/'install-layout.json').read_bytes(),0o644)
    put(source/'release-manifest.json',manifest_raw,0o644)
    receipt=json.loads(args['source_receipt_path'].read_bytes());receipt.pop('signature')
    receipt['release_digest']=manifest['self_digest']
    receipt['inventory_digest']='sha256:'+runner.sha(runner.canonical(runner.safe_tree(source)))
    key=load_pem_private_key(args['signing_path'].read_bytes(),password=None)
    receipt['signature']=base64.urlsafe_b64encode(key.sign(runner.canonical(receipt))).decode().rstrip('=')
    put(args['source_receipt_path'],runner.canonical(receipt))
    def no_process(*args,**kwargs):
        pytest.fail('inactive construction must not start a process or service')
    import subprocess
    monkeypatch.setattr(subprocess,'run',no_process)
    monkeypatch.setattr(subprocess,'Popen',no_process)
    installed=runner.run(**args)
    assert installed['install_status']=='INSTALLED_INACTIVE'
    assert installed['admission']=='INDEPENDENT_AUDIT_PENDING'
    assert installed['stage1']=='NOT_READY'
    assert installed['authority_effect']=='NONE'
    for relative,size,digest,mode in manifest['payload']:
        layout=json.loads((package/'install-layout.json').read_bytes())
        prefix=next(p for p in layout['payload_roots'] if relative.startswith(p+'/'))
        target=args['root']/layout['payload_roots'][prefix].lstrip('/')/relative[len(prefix)+1:]
        assert runner.sha(target.read_bytes())==digest
        assert target.stat().st_mode & 0o777 == int(mode,8)
    handoff=runner.read_authority_handoff(
        expected_witness_sha256=runner.sha((runner.STATE/'kernel-install-witness.json').read_bytes()),
        **{k:args[k] for k in ('root','source','host_path','verify_path','source_receipt_path')})
    assert handoff['source']['canonical_manifest_digest']==runner.sha(manifest_raw)
    assert not (args['root']/'etc/systemd/system/multi-user.target.wants').exists()


def test_historical_donor_cannot_consume_current_mixed_prestate_plan(candidate):
    args,_=candidate
    with pytest.raises(runner.RunnerDenied,match='KERNEL_NATIVE_IDENTITY_IMPLEMENTATION_DENIED'):
        runner.run(**args)
    assert not (runner.STATE/'kernel-install-witness.json').exists()
    assert not (args['root']/'usr/lib/serein/kernel').exists()
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


def test_host_machine_id_mismatch_denied_before_plan_effect(candidate):
    args,_=candidate
    machine=args['root']/'etc/machine-id'
    machine.write_text('a'*32+'\n',encoding='ascii');machine.chmod(0o444)
    with pytest.raises(runner.RunnerDenied,match='HOST_IDENTITY_MISMATCH'):
        runner.run(**args)
    assert not (args['root']/'usr/lib/serein/kernel').exists()
    assert not (args['root']/'var/lib/serein/rollback/.outpost-public-generation.lock').exists()


def test_machine_id_inode_change_after_plan_is_denied(candidate):
    args,_=candidate;use_current_installer(args)
    machine=args['root']/'etc/machine-id';before=machine.stat().st_ino
    def changed(root,source,plan,*,boundary,native_material):
        replacement=machine.with_name('.machine-id-replacement')
        put(replacement,machine.read_bytes(),0o444);os.replace(replacement,machine)
        assert machine.stat().st_ino!=before
        boundary();pytest.fail('changed Host identity crossed installer boundary')
    with pytest.raises(runner.RunnerDenied,match='HOST_IDENTITY_CHANGED'):
        runner.run(**args,installer=changed)
    assert not (args['root']/'usr/lib/serein/kernel').exists()


def test_host_projection_timestamp_resample_preserves_same_identity(candidate,monkeypatch):
    args,initial=candidate;use_current_installer(args)
    original=runner.current_host_gate;calls=0
    def resampled(path,boot):
        nonlocal calls
        calls+=1
        if calls==2:
            value=observation();value['observed_at']=2.0
            value['host']['machine_id']='e'*32
            value['evidence_digest']=host_digest(
                {key:item for key,item in value.items() if key!='evidence_digest'})
            HostVitalityStore(path.parent).record(value)
            os.chown(path,978,978)
        return original(path,boot)
    monkeypatch.setattr(runner,'current_host_gate',resampled)
    observed=runner.run(**args)
    assert calls>2 and observed['host_identity']['machine_id']=='e'*32
    assert observed['host_projection_digest']==initial['projection_digest']
    assert json.loads(args['host_path'].read_bytes())['projection_digest']!=initial['projection_digest']


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


def test_target_capture_denies_same_bytes_final_name_inode_swap(tmp_path,monkeypatch):
    root=tmp_path/'host';path=root/'usr/lib/serein/kernel/authority.py'
    data=b'# exact retained payload\n';put(path,data,0o644)
    original_inode=path.stat().st_ino
    row={'target':'/usr/lib/serein/kernel/authority.py','bytes':len(data),
         'sha256':runner.sha(data),'mode':'0644'}
    original_stat=runner.os.stat;swapped=[]
    def stat_hook(name,*args,**kwargs):
        if name==path.name and kwargs.get('dir_fd') is not None and not swapped:
            replacement=path.with_name('.same-bytes-capture-replacement')
            put(replacement,data,0o644);os.replace(replacement,path);swapped.append(True)
        return original_stat(name,*args,**kwargs)
    monkeypatch.setattr(runner.os,'stat',stat_hook)
    with pytest.raises(runner.RunnerDenied,match='PRESTATE_CONTENT_DENIED'):
        runner.target_prestate(root,row)
    assert swapped and path.read_bytes()==data and path.stat().st_ino!=original_inode


def test_source_change_at_installer_boundary_denies_effect(candidate):
    args,_=candidate
    use_current_installer(args)
    def bad_source(root,source,plan,*,boundary,native_material):
        (source/'payload/runtime/authority.py').write_bytes(b'changed')
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
    use_current_installer(args)
    def changed_group(root,source,plan,*,boundary,native_material):
        os.chown(args['verify_path'],0,12345);boundary()
        pytest.fail('changed key custody permitted')
    with pytest.raises(runner.RunnerDenied,match='IMMUTABLE_CHANGED'):runner.run(**args,installer=changed_group)
    assert not (args['root']/'usr/lib/serein/kernel').exists()


def phase_fixture():
    payload=[[f'payload/{name}.py',1,'a'*64,'0644'] for name in ('interface','authority','operations')]
    layout={'payload_roots':{'payload':'/usr/lib/serein/kernel'},
            'payload_branches':dict(zip((row[0] for row in payload),runner.ORDER))}
    return {'payload':payload},layout


def test_explicit_install_phase_is_not_filename_or_runtime_ownership():
    manifest,layout=phase_fixture()
    rows=runner.payload_rows(Path('/unused'),manifest,layout)
    assert [row['branch'] for row in rows]==list(runner.ORDER)
    assert [row['source'] for row in rows]==[row[0] for row in manifest['payload']]


@pytest.mark.parametrize('bad',(None,[],{},'AUTHORITY',{'payload/missing.py':'AUTHORITY'}))
def test_no_phase_map_default_or_partial_fallback(bad):
    manifest,layout=phase_fixture();layout['payload_branches']=bad
    with pytest.raises(runner.RunnerDenied,match='BRANCH_MAP_DENIED'):
        runner.payload_rows(Path('/unused'),manifest,layout)


@pytest.mark.parametrize('bad',('ROOT','authority',None,[],1))
def test_unknown_install_phase_is_denied(bad):
    manifest,layout=phase_fixture();layout['payload_branches']['payload/interface.py']=bad
    with pytest.raises(runner.RunnerDenied,match='BRANCH_MAP_DENIED'):
        runner.payload_rows(Path('/unused'),manifest,layout)


def test_duplicate_payload_cannot_hide_in_exact_key_set():
    manifest,layout=phase_fixture();manifest['payload'].append(manifest['payload'][0])
    with pytest.raises(runner.RunnerDenied,match='BRANCH_MAP_DENIED'):
        runner.payload_rows(Path('/unused'),manifest,layout)


def test_overlapping_payload_roots_are_denied_independent_of_json_key_order():
    manifest={'payload':[
        ['payload/serein_stage1/domain_identity.py',1,'a'*64,'0644'],
        ['payload/runtime/operations.py',1,'b'*64,'0644'],
        ['payload/runtime/interface.py',1,'c'*64,'0644']]}
    branches={'payload/serein_stage1/domain_identity.py':'AUTHORITY',
              'payload/runtime/operations.py':'OPERATIONS',
              'payload/runtime/interface.py':'INTERFACE'}
    for roots in ({'payload':'/wrong','payload/serein_stage1':'/right'},
                  {'payload/serein_stage1':'/right','payload':'/wrong'}):
        with pytest.raises(runner.RunnerDenied,match='LAYOUT_DENIED'):
            runner.payload_rows(Path('/unused'),manifest,
                                {'payload_roots':roots,'payload_branches':branches})


def test_all_authority_map_is_not_complete_kernel():
    manifest,layout=phase_fixture()
    layout['payload_branches']={key:'AUTHORITY' for key in layout['payload_branches']}
    with pytest.raises(runner.RunnerDenied,match='COMPLETE_BRANCH_SET_REQUIRED'):
        runner.payload_rows(Path('/unused'),manifest,layout)


def test_exact_manifest_producer_matches_outpost_consumer(tmp_path,monkeypatch):
    import importlib.util
    refresh_path=Path(__file__).resolve().parents[2]/'kernel/refresh_manifest.py'
    spec=importlib.util.spec_from_file_location('kernel_phase_refresh',refresh_path)
    refresh=importlib.util.module_from_spec(spec);spec.loader.exec_module(refresh)
    monkeypatch.setattr(refresh,'ROOT',tmp_path)
    manifest,layout=phase_fixture()
    manifest['branch_order']=list(runner.ORDER)
    for relative,_,_,_ in manifest['payload']:
        put(tmp_path/relative,b'# inert exact-phase fixture\n',0o644)
    for name in ('kernel_first_install.py','offline_ollama_transaction.py'):
        put(tmp_path/'install'/name,b'# non-executable installer fixture\n',0o755)
    put(tmp_path/'release-manifest.json',runner.canonical(manifest),0o644)
    put(tmp_path/'install-layout.json',runner.canonical(layout),0o644)
    refresh.main()
    sealed=json.loads((tmp_path/'release-manifest.json').read_bytes())
    rows=runner.payload_rows(tmp_path,sealed,layout)
    assert sealed['install_denominator_digest']=='sha256:'+runner.sha(runner.canonical(rows))
    assert [row['source'] for row in rows]==[row[0] for row in manifest['payload']]


def test_outpost_runs_corrected_candidate_installer_and_reads_exact_receipt(candidate):
    """Real candidate transaction with inert A/O/I fixtures, not Kernel admission."""
    args,_=candidate;source=args['source']
    path=Path(__file__).resolve().parents[2]/'kernel/install/kernel_first_install.py'
    candidate_bytes=path.read_bytes()
    put(source/'install/kernel_first_install.py',candidate_bytes,0o755)
    manifest=json.loads((source/'release-manifest.json').read_bytes())
    manifest.update(schema='SereinPortableKernelRelease/v1',branch_order=list(runner.ORDER),
                    classification='PUBLIC_KERNEL_COMPANION_FOUNDATION_INACTIVE',
                    activation='OUTPOST_ONLY_AFTER_INACTIVE_PROOF',
                    installer_files=[['install/kernel_first_install.py',len(candidate_bytes),runner.sha(candidate_bytes),'0755']])
    manifest.pop('self_digest')
    manifest['self_digest']='sha256:'+runner.sha(runner.canonical(manifest))
    put(source/'release-manifest.json',runner.canonical(manifest),0o644)
    source_receipt=json.loads(args['source_receipt_path'].read_bytes())
    source_receipt.pop('signature')
    source_receipt['release_digest']=manifest['self_digest']
    source_receipt['inventory_digest']='sha256:'+runner.sha(runner.canonical(runner.safe_tree(source)))
    # Fixture-only signer created in candidate(); no canonical key is accessed.
    key=load_pem_private_key(args['signing_path'].read_bytes(),password=None)
    source_receipt['signature']=base64.urlsafe_b64encode(key.sign(runner.canonical(source_receipt))).decode().rstrip('=')
    put(args['source_receipt_path'],runner.canonical(source_receipt))
    observed=runner.run(**args)
    assert observed['install_status']=='INSTALLED_INACTIVE'
    assert observed['admission']=='INDEPENDENT_AUDIT_PENDING'
    assert observed['stage1']=='NOT_READY' and observed['authority_effect']=='NONE'
    assert observed['branch_order']==list(runner.ORDER)
    for branch in runner.ORDER:
        assert (args['root']/'usr/lib/serein/kernel'/f'{branch.lower()}.py').read_bytes()==(source/'payload/runtime'/f'{branch.lower()}.py').read_bytes()
    assert not (args['root']/'etc/systemd').exists()
    identity_key=args['root']/runner.NATIVE_KEY.lstrip('/')
    identity_registry=args['root']/runner.NATIVE_REGISTRY.lstrip('/')
    assert identity_key.stat().st_mode&0o777==0o600
    assert identity_registry.stat().st_mode&0o777==0o644
    plan_path=args['root']/observed['rollback_selector'].lstrip('/')/'plan.json'
    plan_raw=plan_path.read_bytes();plan=json.loads(plan_raw)
    assert plan_path.stat().st_mode&0o777==0o600
    assert identity_key.read_bytes() not in plan_raw
    assert identity_registry.read_bytes() not in plan_raw
    witness_raw=(runner.STATE/'kernel-install-witness.json').read_bytes()
    assert identity_key.read_bytes() not in witness_raw
    assert identity_registry.read_bytes() not in witness_raw
    assert observed['native_identity']==plan['native_identity']
    assert observed['native_identity']['instance_id'] not in plan['reserved_domain_ids']

    original=identity_registry.read_bytes()
    identity_registry.write_bytes(original+b'tamper')
    with pytest.raises(runner.RunnerDenied,match='NATIVE_IDENTITY'):
        runner.verify_native_installed(args['root'],plan)
    identity_registry.write_bytes(original)


@pytest.mark.parametrize('swap_before_witness',(False,True))
def test_outpost_mixed_prestate_preserves_exact_payload_and_reports_it(
        candidate,monkeypatch,swap_before_witness):
    """Runner signs and independently verifies one exact preserved payload row."""
    args,_=candidate;source=args['source']
    path=Path(__file__).resolve().parents[2]/'kernel/install/kernel_first_install.py'
    candidate_bytes=path.read_bytes()
    put(source/'install/kernel_first_install.py',candidate_bytes,0o755)
    manifest=json.loads((source/'release-manifest.json').read_bytes())
    manifest.update(schema='SereinPortableKernelRelease/v1',branch_order=list(runner.ORDER),
                    classification='PUBLIC_KERNEL_COMPANION_FOUNDATION_INACTIVE',
                    activation='OUTPOST_ONLY_AFTER_INACTIVE_PROOF',
                    installer_files=[['install/kernel_first_install.py',len(candidate_bytes),runner.sha(candidate_bytes),'0755']])
    manifest.pop('self_digest')
    manifest['self_digest']='sha256:'+runner.sha(runner.canonical(manifest))
    put(source/'release-manifest.json',runner.canonical(manifest),0o644)
    source_receipt=json.loads(args['source_receipt_path'].read_bytes())
    source_receipt.pop('signature')
    source_receipt['release_digest']=manifest['self_digest']
    source_receipt['inventory_digest']='sha256:'+runner.sha(runner.canonical(runner.safe_tree(source)))
    key=load_pem_private_key(args['signing_path'].read_bytes(),password=None)
    source_receipt['signature']=base64.urlsafe_b64encode(
        key.sign(runner.canonical(source_receipt))).decode().rstrip('=')
    put(args['source_receipt_path'],runner.canonical(source_receipt))
    preserved=args['root']/'usr/lib/serein/kernel/operations.py'
    put(preserved,(source/'payload/runtime/operations.py').read_bytes(),0o644)
    before=preserved.stat()
    verified_plans=[]
    original_verify_install=runner.verify_install
    def verify_install(root,plan,receipt):
        verified_plans.append(plan)
        return original_verify_install(root,plan,receipt)
    monkeypatch.setattr(runner,'verify_install',verify_install)

    if swap_before_witness:
        original_atomic=runner.atomic
        def atomic(path,value,directory_fd,check_parent):
            if path.name=='kernel-install-witness.json':
                replacement=preserved.with_name('.same-bytes-witness-replacement')
                put(replacement,preserved.read_bytes(),0o644)
                os.replace(replacement,preserved)
                assert preserved.stat().st_ino!=before.st_ino
            return original_atomic(path,value,directory_fd,check_parent)
        monkeypatch.setattr(runner,'atomic',atomic)

    if swap_before_witness:
        with pytest.raises(runner.RunnerDenied,match='PRESTATE|RECEIPT_CHANGED'):
            runner.run(**args)
        assert preserved.exists() and preserved.read_bytes()==(source/'payload/runtime/operations.py').read_bytes()
        assert preserved.stat().st_ino!=before.st_ino
        assert not (runner.STATE/'kernel-install-witness.json').exists()
        assert not any((args['root']/path.lstrip('/')).exists() for path in (
            '/var/lib/serein/kernel/authority/replay.key',
            '/var/lib/serein/kernel/authority/replay-descriptor.json',
            '/etc/serein/kernel/replay-peer.env',
            runner.NATIVE_KEY,
            runner.NATIVE_REGISTRY,
            '/usr/lib/serein/kernel/authority.py',
            '/usr/lib/serein/kernel/interface.py'))
        return

    observed=runner.run(**args)
    after=preserved.stat()
    assert observed['install_status']=='INSTALLED_INACTIVE'
    assert (after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_mode&0o777)==(
        before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode&0o777)
    receipt=json.loads((args['root']/observed['rollback_selector'].lstrip('/')/'receipt.json').read_bytes())
    prestate={row['target']:row for row in receipt['prestate']}
    assert prestate['/usr/lib/serein/kernel/operations.py']['state']=='PRESENT_PRESERVED'
    assert prestate['/usr/lib/serein/kernel/operations.py']['inode']==before.st_ino
    assert observed['authority_effect']=='NONE' and observed['stage1']=='NOT_READY'

    journal_path=args['root']/observed['rollback_selector'].lstrip('/')/'phase-journal.json'
    journal=json.loads(journal_path.read_bytes())
    ownership=journal['ownership']
    assert all(item['target']!='/usr/lib/serein/kernel/operations.py' for item in ownership)
    malformed=(
        ownership[:-1],
        list(reversed(ownership)),
        ownership+[{'target':'/usr/lib/serein/kernel/operations.py',
                    'device':before.st_dev,'inode':before.st_ino,
                    'temporary':'.kernel-'+'0'*32}],
    )
    receipt_selector={'receipt':observed['rollback_selector']+'/receipt.json'}
    for bad in malformed:
        journal['ownership']=bad
        journal_path.write_bytes(runner.canonical(journal))
        with pytest.raises(runner.RunnerDenied,match='OWNERSHIP'):
            original_verify_install(args['root'],verified_plans[-1],receipt_selector)
    journal['ownership']=ownership
    journal_path.write_bytes(runner.canonical(journal))
