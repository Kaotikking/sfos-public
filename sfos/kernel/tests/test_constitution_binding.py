"""Exact immutable semantic input binding, not Seed or Kernel admission."""
import importlib.util
import base64
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PAYLOAD = Path(__file__).parents[1] / "payload/serein_stage1"
_SPEC = importlib.util.spec_from_file_location("kernel_constitution_binding", PAYLOAD / "authority_boot.py")
authority = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(authority)
_INSTALL_SPEC = importlib.util.spec_from_file_location(
    "kernel_constitution_installer", Path(__file__).parents[1] /
    "install/kernel_first_install.py")
installer = importlib.util.module_from_spec(_INSTALL_SPEC)
_INSTALL_SPEC.loader.exec_module(installer)


def material():
    return ((PAYLOAD / "kernel-seed.v1.json").read_bytes(),
            (PAYLOAD / "authority-proof-contract.v1.json").read_bytes(),
            (PAYLOAD / authority.DICTIONARY_FILE).read_bytes(),
            (PAYLOAD / authority.BLUEPRINT_FILE).read_bytes())


def test_exact_v3_material_is_still_unadmitted_and_no_effect():
    seed, policy = authority.verify_material(*material())
    assert seed["status"] == "CANDIDATE_UNADMITTED"
    assert seed["semantic_reference"]["version"] == 3
    assert seed["authority_effect"] == seed["admission_effect"] == "NONE"
    assert policy["self_admission"] is False


@pytest.mark.parametrize("dictionary", [None, b"", b"Engineering Dictionary v2", b"forged"])
def test_absent_stale_or_changed_dictionary_denied(dictionary):
    seed, policy, _, blueprint = material()
    with pytest.raises(authority.AuthorityDenied, match="DICTIONARY"):
        authority.verify_material(seed, policy, dictionary, blueprint)


@pytest.mark.parametrize("field,value", [
    ("document_id", "unrelated"), ("version", 2), ("source_revision", "stale"),
    ("payload", "../engineering-dictionary.v3.md"), ("sha256", "0"*64)])
def test_rehashed_seed_cannot_rebind_dictionary(monkeypatch, field, value):
    raw, policy, dictionary, blueprint = material()
    seed = authority.strict_json(raw)
    seed["semantic_reference"][field] = value
    altered = authority.canonical(seed)
    # Exercise the inner independent semantic binding, not only outer Seed hash.
    monkeypatch.setattr(authority, "SEED_SHA256", authority.sha(altered))
    with pytest.raises(authority.AuthorityDenied, match="DICTIONARY"):
        authority.verify_material(altered, policy, dictionary, blueprint)


def test_ordinary_seed_or_policy_drift_denied():
    seed, policy, dictionary, blueprint = material()
    with pytest.raises(authority.AuthorityDenied, match="CONSTITUTION"):
        authority.verify_material(seed+b" ", policy, dictionary, blueprint)
    with pytest.raises(authority.AuthorityDenied, match="CONSTITUTION"):
        authority.verify_material(seed, policy+b" ", dictionary, blueprint)


@pytest.mark.parametrize('blueprint', (None, b'', b'Historical or changed blueprint'))
def test_missing_or_changed_blueprint_document_denied(blueprint):
    seed,policy,dictionary,_=material()
    with pytest.raises(authority.AuthorityDenied,match='BLUEPRINT_BINDING'):
        authority.verify_material(seed,policy,dictionary,blueprint)


@pytest.mark.parametrize('field,value', (
    ('issue_id','another-issue'), ('identifier','PRO-181'), ('title','another domain'),
    ('source_revision','stale'), ('source_serialization','unbound text'),
    ('payload','../blueprint.md'), ('sha256','0'*64)))
def test_rehashed_policy_cannot_rebind_blueprint(monkeypatch,field,value):
    seed,policy_raw,dictionary,blueprint=material()
    policy=authority.strict_json(policy_raw)
    policy['blueprint_reference'][field]=value
    changed=authority.canonical(policy)
    monkeypatch.setattr(authority,'POLICY_SHA256',authority.sha(changed))
    with pytest.raises(authority.AuthorityDenied,match='BLUEPRINT_BINDING'):
        authority.verify_material(seed,changed,dictionary,blueprint)


def test_root_custody_and_captured_identity_use_the_same_snapshot(tmp_path, monkeypatch):
    root = tmp_path / "custody-root"
    root.mkdir(mode=0o755)
    path = root / "material"
    path.write_bytes(b"synthetic source\n")
    info = root.stat()
    real_fstat = os.fstat
    changed = False

    def race_after_first_root_snapshot(fd):
        nonlocal changed
        snapshot = real_fstat(fd)
        if not changed and (snapshot.st_dev, snapshot.st_ino) == (info.st_dev, info.st_ino):
            changed = True
            root.chmod(0o777)
        return snapshot

    monkeypatch.setattr(authority.os, "fstat", race_after_first_root_snapshot)
    try:
        with pytest.raises(authority.AuthorityDenied, match="AUTHORITY_PARENT_CHANGED"):
            authority.regular(path, root=root)
    finally:
        root.chmod(info.st_mode & 0o777)
    assert changed


@pytest.mark.parametrize("include_fact", (False, True))
@pytest.mark.parametrize("mutation", (None, "grow", "truncate"))
def test_regular_read_bound_preserves_change_detection(tmp_path, monkeypatch, include_fact, mutation):
    root = tmp_path / "read-root"
    root.mkdir(mode=0o755)
    path = root / "material"
    original = b"synthetic source\n"
    path.write_bytes(original)
    path.chmod(0o644)
    real_fdopen = os.fdopen
    reads = []

    class ObservedReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def read(self, size):
            if not reads and mutation is not None:
                path.write_bytes(original + b"extra" if mutation == "grow" else original[:-1])
            reads.append(size)
            return self.stream.read(size)

    monkeypatch.setattr(authority.os, "fdopen", lambda *args, **kwargs: ObservedReader(real_fdopen(*args, **kwargs)))
    if mutation is None:
        result = authority.regular(path, root=root, include_fact=include_fact)
        assert (result[0] if include_fact else result) == original
        assert len(reads) == (2 if include_fact else 1)
    else:
        with pytest.raises(authority.AuthorityDenied, match="AUTHORITY_INPUT_CHANGED"):
            authority.regular(path, root=root, include_fact=include_fact)
    assert reads and all(size == len(original) + 1 for size in reads)


@pytest.fixture
def source_inventory_fixture(tmp_path,monkeypatch,request):
    """Signed exact-source fixture closure only; no branch is admitted."""
    root=tmp_path/'host';root.mkdir()
    def put(base,name,raw,mode=0o644):
        path=base/name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw);path.chmod(mode);return path
    key=Ed25519PrivateKey.generate()
    anchor=key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
    put(root,authority.ANCHOR,anchor)
    monkeypatch.setattr(authority,'ANCHOR_SHA256',authority.sha(anchor))
    source=root/authority.STATE.lstrip('/')/'source/sfos/kernel';source.mkdir(parents=True)
    rows=[];fixture_variant=getattr(request,'param',None)
    omit_launcher=fixture_variant=='omit'
    launcher_mode='0644' if fixture_variant=='mode0644' else '0755'
    names=('kernel-seed.v1.json','authority-proof-contract.v1.json',authority.DICTIONARY_FILE,authority.BLUEPRINT_FILE,
           'authority_boot.py','kernel_branch_api.py','domain_identity.py')
    for name in names:
        if name == authority.BLUEPRINT_FILE and fixture_variant == 'omit-blueprint':
            continue
        raw=(PAYLOAD/name).read_bytes()
        relative='payload/serein_stage1/'+name
        put(source,relative,raw);put(root,authority.MATERIAL+name,raw)
        rows.append([relative,len(raw),authority.sha(raw),'0644'])
    launcher_relative='payload/bin/serein-kernel-branch-api'
    if not omit_launcher:
        launcher=(Path(__file__).parents[1]/launcher_relative).read_bytes()
        put(source,launcher_relative,launcher,int(launcher_mode,8))
        put(root,'/usr/libexec/serein/serein-kernel-branch-api',launcher,int(launcher_mode,8))
        rows.append([launcher_relative,len(launcher),authority.sha(launcher),launcher_mode])
    for suffix in ('service', 'socket'):
        if fixture_variant == 'omit-' + suffix:
            continue
        name = 'serein-kernel-authority-api.' + suffix
        relative = 'payload/systemd/' + name
        raw = (PAYLOAD.parent / 'systemd' / name).read_bytes()
        mode = '0755' if fixture_variant == 'executable-' + suffix else '0644'
        put(source, relative, raw, int(mode, 8))
        put(root, '/etc/systemd/system/' + name, raw, int(mode, 8))
        rows.append([relative, len(raw), authority.sha(raw), mode])
    manifest={'payload':rows,'payload_digest':'sha256:'+authority.sha(authority.canonical(rows))}
    manifest['self_digest']='sha256:'+authority.sha(authority.canonical(manifest))
    put(source,'release-manifest.json',authority.canonical(manifest))
    put(source,'install-layout.json',authority.canonical({'payload_roots':{
        'payload/serein_stage1':authority.MATERIAL.rstrip('/'),
        'payload/bin':'/usr/libexec/serein',
        'payload/systemd':'/etc/systemd/system'}}))
    inventory=[{'path':p.relative_to(source).as_posix(),'bytes':p.stat().st_size,'sha256':authority.sha(p.read_bytes())}
               for p in sorted(source.rglob('*')) if p.is_file()]
    receipt={'schema':'SereinOutpostKernelSourceReceipt/v1','repository':'Kaotikking/sfos-public','ref':'refs/heads/main',
             'source_parent':'a'*40,'source_commit':'b'*40,'source_tree':'c'*40,'archive_sha256':'d'*64,
             'release_digest':manifest['self_digest'],'inventory_digest':'sha256:'+authority.sha(authority.canonical(inventory))}
    receipt['signature']=base64.urlsafe_b64encode(key.sign(authority.canonical(receipt))).decode().rstrip('=')
    put(root,authority.STATE+'/source-receipt.json',authority.canonical(receipt))
    boot='11111111-2222-4333-8444-555555555555'
    machine_path=put(root,'/etc/machine-id',('e'*32+'\n').encode(),0o444)
    _,machine_fact=authority.regular(machine_path,root=root,include_fact=True)
    rollback_selector='/var/lib/serein/rollback/kernel-first-install-20260930T120000Z-abcdef123456'
    plan_rows=[]
    for relative,size,digest_value,mode in rows:
        target=('/usr/libexec/serein/'+relative.rsplit('/',1)[-1]
                if relative.startswith('payload/bin/')
                else '/etc/systemd/system/'+relative.rsplit('/',1)[-1]
                if relative.startswith('payload/systemd/')
                else authority.MATERIAL+relative.rsplit('/',1)[-1])
        plan_rows.append({'branch':'AUTHORITY','source':relative,
                          'target':target,
                          'bytes':size,'sha256':digest_value,'mode':mode})
    plan={'schema':'SereinPublicKernelFirstInstallPlan/v1','target_vm_id':'VM4010',
          'source_parent':receipt['source_parent'],'source_commit':receipt['source_commit'],
          'source_tree':receipt['source_tree'],'release_digest':receipt['release_digest'],
          'current_boot_id':boot,'outpost_identity':{'uid':978},'replay_identity':{'uid':977},
          'payload':plan_rows,'target_prestate':[],'rollback_selector':rollback_selector,
          'authority_sha256':authority.sha(anchor),'archive_sha256':receipt['archive_sha256'],
          'source_receipt_sha256':authority.sha(authority.canonical(receipt)),
          'source_inventory_digest':receipt['inventory_digest'],'reserved_domain_ids':[],
          'host_identity':{'machine_id':'e'*32,'file':machine_fact},
          'host_projection_digest':'f'*64}
    native=installer.prepare_native_identity(
        source,plan,key,reserved_ids=set(),
        random_bytes=lambda size:bytes.fromhex('0123456789abcdef'))
    plan['native_identity']=native['binding']
    plan['signature']=base64.urlsafe_b64encode(
        key.sign(authority.canonical(plan))).decode().rstrip('=')
    put(root,rollback_selector+'/plan.json',authority.canonical(plan),0o600)
    put(root,'/var/lib/serein/kernel/authority/domain-identity.json',native['registry'])
    witness={'schema':'SereinOutpostKernelInstallWitness/v1','target':'VM4010','boot_id':boot,
             'source_commit':receipt['source_commit'],'source_tree':receipt['source_tree'],
             'archive_sha256':receipt['archive_sha256'],'release_digest':receipt['release_digest'],
             'source_receipt_sha256':authority.sha(authority.canonical(receipt)),
             'install_status':'INSTALLED_INACTIVE','admission':'INDEPENDENT_AUDIT_PENDING',
             'stage1':'NOT_READY','rollback_selector':rollback_selector,
             'native_identity':native['binding'],'host_identity':plan['host_identity'],
             'host_projection_digest':plan['host_projection_digest'],'authority_effect':'NONE'}
    witness['witness_digest']=authority.sha(authority.canonical(witness))
    put(root,authority.STATE+'/kernel-install-witness.json',authority.canonical(witness))
    put(root,'/proc/sys/kernel/random/boot_id',(boot+'\n').encode())
    # Synthetic private material is exposed only to the direct-witness test
    # fixture; constitutional collection never reads or requires it.
    return root,source,key,native


def test_fixture_source_closure_does_not_install_or_admit(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    facts=authority.collect_authority_facts(root)
    assert facts['proof']['self_admission'] is False
    assert sorted(path.name for path in (root/'etc/systemd/system').iterdir()) == [
        'serein-kernel-authority-api.service', 'serein-kernel-authority-api.socket']
    assert not (root/'etc/systemd/system/sockets.target.wants').exists()
    witness=authority.strict_json((root/authority.STATE.lstrip('/')/'kernel-install-witness.json').read_bytes())
    assert witness['admission']=='INDEPENDENT_AUDIT_PENDING' and witness['stage1']=='NOT_READY'
    native=facts['proof']['native_identity']
    assert native['registry_integrity']=='VERIFIED'
    assert native['private_key_possession']=='UNKNOWN'
    assert native['authority_effect']==native['admission_effect']=='NONE'
    assert facts['proof']['frame_identity']=={
        'machine_id':'e'*32,'boot_id':facts['boot_id'],
        'host_projection_digest':'f'*64}
    assert not (root/'var/lib/serein/kernel/authority/domain-identity.pem').exists()
    launcher=root/'usr/libexec/serein/serein-kernel-branch-api'
    source_launcher=root/authority.STATE.lstrip('/')/'source/sfos/kernel/payload/bin/serein-kernel-branch-api'
    assert launcher.read_bytes()==source_launcher.read_bytes()
    assert launcher.stat().st_mode&0o777==source_launcher.stat().st_mode&0o777==0o755
    blueprint=root/authority.MATERIAL.lstrip('/')/authority.BLUEPRINT_FILE
    assert blueprint.read_bytes()==(PAYLOAD/authority.BLUEPRINT_FILE).read_bytes()
    assert blueprint.stat().st_mode&0o777==0o644


@pytest.mark.parametrize('source_inventory_fixture',['omit-blueprint'],indirect=True)
def test_signed_blueprint_omission_is_denied(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    with pytest.raises(authority.AuthorityDenied,match='REQUIRED_MATERIAL_MISSING'):
        authority.collect_authority_facts(root)


@pytest.mark.parametrize('fault',('missing','source-bytes','installed-bytes','installed-custody'))
def test_blueprint_source_and_installed_drift_denied(source_inventory_fixture,fault):
    root,source,_,_=source_inventory_fixture
    installed=root/authority.MATERIAL.lstrip('/')/authority.BLUEPRINT_FILE
    archived=source/'payload/serein_stage1'/authority.BLUEPRINT_FILE
    if fault=='missing':installed.unlink()
    elif fault=='source-bytes':archived.write_bytes(archived.read_bytes()+b'x')
    elif fault=='installed-bytes':installed.write_bytes(installed.read_bytes()+b'x')
    else:installed.chmod(0o600)
    with pytest.raises(authority.AuthorityDenied,match='(INPUT_UNAVAILABLE|SOURCE_INVENTORY|INSTALLED_BYTES|CUSTODY)'):
        authority.collect_authority_facts(root)


@pytest.mark.parametrize('source_inventory_fixture',['omit'],indirect=True)
def test_signed_package_omitting_retained_launcher_is_denied(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    with pytest.raises(authority.AuthorityDenied,match='REQUIRED_MATERIAL_MISSING'):
        authority.collect_authority_facts(root)


@pytest.mark.parametrize('source_inventory_fixture',[
    'omit-service', 'omit-socket', 'executable-service', 'executable-socket'], indirect=True)
def test_signed_authority_unit_omission_or_mode_is_denied(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    with pytest.raises(authority.AuthorityDenied,match='(REQUIRED_MATERIAL_MISSING|UNIT_MODE_DENIED)'):
        authority.collect_authority_facts(root)


@pytest.mark.parametrize('source_inventory_fixture',['mode0644'],indirect=True)
def test_signed_nonexecutable_launcher_mode_is_denied(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    with pytest.raises(authority.AuthorityDenied,match='LAUNCHER_MODE_DENIED'):
        authority.collect_authority_facts(root)


@pytest.mark.parametrize('suffix', ('service', 'socket'))
@pytest.mark.parametrize('fault', ('source-bytes', 'installed-bytes', 'installed-custody'))
def test_authority_unit_source_installed_bytes_and_custody_are_closed(
        source_inventory_fixture, suffix, fault):
    root,source,_,_=source_inventory_fixture
    name = 'serein-kernel-authority-api.' + suffix
    installed = root / 'etc/systemd/system' / name
    source_path = source / 'payload/systemd' / name
    if fault == 'source-bytes':
        source_path.write_bytes(source_path.read_bytes() + b'\n# drift\n')
    elif fault == 'installed-bytes':
        installed.write_bytes(installed.read_bytes() + b'\n# drift\n')
    else:
        installed.chmod(0o600)
    with pytest.raises(authority.AuthorityDenied, match='(SOURCE_INVENTORY|INSTALLED_BYTES|CUSTODY)'):
        authority.collect_authority_facts(root)


@pytest.mark.parametrize('fault',('source-bytes','installed-bytes','installed-custody'))
def test_launcher_source_installed_bytes_and_custody_are_closed(
        source_inventory_fixture,fault):
    root,source,_,_=source_inventory_fixture
    installed=root/'usr/libexec/serein/serein-kernel-branch-api'
    source_path=source/'payload/bin/serein-kernel-branch-api'
    if fault=='source-bytes':source_path.write_bytes(source_path.read_bytes()+b'\n# drift\n')
    elif fault=='installed-bytes':installed.write_bytes(installed.read_bytes()+b'\n# drift\n')
    else:installed.chmod(0o700)
    with pytest.raises(authority.AuthorityDenied,match='(SOURCE_INVENTORY|INSTALLED_BYTES|CUSTODY)'):
        authority.collect_authority_facts(root)


def test_exact_installed_launcher_loads_modules_then_rejects_missing_fd(
        source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    launcher=root/'usr/libexec/serein/serein-kernel-branch-api'
    result=subprocess.run([str(launcher),'--branch','AUTHORITY'],stdin=subprocess.DEVNULL,
                          capture_output=True,text=True,close_fds=True,pass_fds=(),timeout=5)
    assert result.returncode!=0
    assert 'Bad file descriptor' in result.stderr
    assert 'ModuleNotFoundError' not in result.stderr


def test_exact_installed_launcher_rejects_non_authority_branch_at_parser(
        source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    launcher=root/'usr/libexec/serein/serein-kernel-branch-api'
    result=subprocess.run([str(launcher),'--branch','OPERATIONS'],stdin=subprocess.DEVNULL,
                          capture_output=True,text=True,close_fds=True,pass_fds=(),timeout=5)
    assert result.returncode==2
    assert "invalid choice: 'OPERATIONS'" in result.stderr
    assert 'Bad file descriptor' not in result.stderr


def test_exact_launcher_isolated_python_ignores_hostile_pythonpath(
        source_inventory_fixture,tmp_path):
    root,_,_,_=source_inventory_fixture
    launcher=root/'usr/libexec/serein/serein-kernel-branch-api'
    hostile=tmp_path/'hostile';hostile.mkdir();marker=tmp_path/'hostile-imported'
    (hostile/'kernel_branch_api.py').write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n"
        "raise RuntimeError('HOSTILE_MODULE_IMPORTED')\n",encoding='utf-8')
    environment=dict(os.environ);environment['PYTHONPATH']=str(hostile)
    result=subprocess.run([str(launcher),'--branch','AUTHORITY'],stdin=subprocess.DEVNULL,
                          capture_output=True,text=True,close_fds=True,pass_fds=(),timeout=5,
                          env=environment)
    assert result.returncode!=0 and not marker.exists()
    assert 'Bad file descriptor' in result.stderr
    assert 'HOSTILE_MODULE_IMPORTED' not in result.stderr


def test_machine_identity_inode_drift_denied_by_constitution(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    machine=root/'etc/machine-id';replacement=machine.with_name('.machine-id-replacement')
    replacement.write_bytes(machine.read_bytes());replacement.chmod(0o444)
    os.replace(replacement,machine)
    with pytest.raises(authority.AuthorityDenied,match='HOST_IDENTITY_CHANGED'):
        authority.collect_authority_facts(root)


def test_verified_source_material_frame_do_not_claim_complete_phase_a(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    facts=authority.collect_authority_facts(root)
    assert facts['api_health']=='UNKNOWN'
    assert facts['source_integrity']=='VERIFIED'
    assert facts['self_tests']==[
        {'name':name,'verdict':'PASS' if index<3 else 'UNKNOWN'}
        for index,name in enumerate(authority.PHASE_A_CHECKS)]


@pytest.mark.parametrize('kind',('regular','symlink'))
def test_source_added_during_collection_invalidates_closure(source_inventory_fixture,monkeypatch,kind):
    root,source,_,_=source_inventory_fixture
    original=authority.verify_material
    def changed(*args):
        result=original(*args)
        late=source/'late-unmanifested.py'
        if kind=='regular':late.write_bytes(b'# source drift during collection\n')
        else:late.symlink_to(source/'release-manifest.json')
        return result
    monkeypatch.setattr(authority,'verify_material',changed)
    with pytest.raises(authority.AuthorityDenied,match='SOURCE_(INVENTORY|SYMLINK)'):
        authority.collect_authority_facts(root)
    assert (source/'late-unmanifested.py').exists()


@pytest.mark.parametrize('fault',('private-mode','executable-mode','group'))
def test_installed_custody_change_after_initial_read_denied(source_inventory_fixture,monkeypatch,fault):
    root,_,_,_=source_inventory_fixture;original=authority.verify_material
    path=root/authority.MATERIAL.lstrip('/')/'authority-proof-contract.v1.json'
    def changed(*args):
        result=original(*args)
        if fault=='group':os.chown(path,0,12345)
        else:path.chmod(0o600 if fault=='private-mode' else 0o555)
        return result
    monkeypatch.setattr(authority,'verify_material',changed)
    with pytest.raises(authority.AuthorityDenied,match='(CUSTODY|INSTALLED_BYTES)'):
        authority.collect_authority_facts(root)


def test_tampered_native_registry_is_denied(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    registry=root/'var/lib/serein/kernel/authority/domain-identity.json'
    registry.write_bytes(registry.read_bytes()+b' ')
    with pytest.raises(authority.AuthorityDenied,match='NATIVE_(REGISTRY|IDENTITY)'):
        authority.collect_authority_facts(root)


def test_wrong_outer_plan_signature_is_denied(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    witness=authority.strict_json(
        (root/authority.STATE.lstrip('/')/'kernel-install-witness.json').read_bytes())
    plan_path=root/witness['rollback_selector'].lstrip('/')/'plan.json'
    plan=authority.strict_json(plan_path.read_bytes());plan['signature']='0'*128
    plan_path.write_bytes(authority.canonical(plan))
    with pytest.raises(authority.AuthorityDenied,match='NATIVE_IDENTITY'):
        authority.collect_authority_facts(root)


@pytest.mark.parametrize(('field','value'),(
    ('current_boot_id','aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'),
    ('source_commit','f'*40)))
def test_resigned_boot_or_source_substitution_is_denied(
        source_inventory_fixture,field,value):
    root,_,key,_=source_inventory_fixture
    witness=authority.strict_json(
        (root/authority.STATE.lstrip('/')/'kernel-install-witness.json').read_bytes())
    plan_path=root/witness['rollback_selector'].lstrip('/')/'plan.json'
    plan=authority.strict_json(plan_path.read_bytes());plan[field]=value
    plan.pop('signature')
    plan['signature']=base64.urlsafe_b64encode(
        key.sign(authority.canonical(plan))).decode().rstrip('=')
    plan_path.write_bytes(authority.canonical(plan))
    with pytest.raises(authority.AuthorityDenied,match='NATIVE_PLAN_BINDING'):
        authority.collect_authority_facts(root)


@pytest.mark.parametrize('fault',('missing','changed'))
def test_missing_or_changed_signed_plan_is_denied(source_inventory_fixture,fault):
    root,_,_,_=source_inventory_fixture
    witness=authority.strict_json(
        (root/authority.STATE.lstrip('/')/'kernel-install-witness.json').read_bytes())
    plan_path=root/witness['rollback_selector'].lstrip('/')/'plan.json'
    if fault=='missing':plan_path.unlink()
    else:plan_path.write_bytes(plan_path.read_bytes()+b' ')
    with pytest.raises(authority.AuthorityDenied):
        authority.collect_authority_facts(root)


def test_preloaded_permissive_identity_module_cannot_replace_exact_installed_source(
        source_inventory_fixture,monkeypatch):
    root,_,_,_=source_inventory_fixture
    poison=types.ModuleType('serein_stage1.domain_identity')
    poison.verify_lineage=lambda *args,**kwargs:{
        'instance_id':'0000000000000000','public_key':'00'*32,
        'checkpoint':'0'*64,'authority_effect':'GRANTED','admission_effect':'ADMITTED'}
    monkeypatch.setitem(sys.modules,'serein_stage1.domain_identity',poison)
    facts=authority.collect_authority_facts(root)
    native=facts['proof']['native_identity']
    assert native['registry_integrity']=='VERIFIED'
    assert native['instance_id']!='0000000000000000'
    assert native['authority_effect']==native['admission_effect']=='NONE'


def test_actual_collected_facts_allow_private_observation_only(source_inventory_fixture):
    root,_,_,_=source_inventory_fixture
    facts=authority.collect_authority_facts(root)
    decision=authority.authority_boot_decision(facts,requested_effect='OBSERVE_AUTHORITY')
    assert decision=={'schema':'SereinAuthorityBootDecision/v1',
                      'mode':'PRIVATE_VALIDATION_ONLY',
                      'allowed_effects':['OBSERVE_AUTHORITY'],
                      'privileged_execution':False,'branch_advance':False,
                      'authority_effect':'NONE','admission_effect':'NONE'}
    assert [row['verdict'] for row in facts['self_tests']]==['PASS']*3+['UNKNOWN']*3


@pytest.mark.parametrize('field,value',(
    ('identity','OTHER'),('policy','DEFAULT_ALLOW'),
    ('containment','PUBLIC'),('self_admission',True),
))
def test_observation_decision_rejects_contradictory_loaded_policy(
        source_inventory_fixture,field,value):
    root,_,_,_=source_inventory_fixture
    facts=authority.collect_authority_facts(root)
    facts['proof'][field]=value
    decision=authority.authority_boot_decision(facts,requested_effect='OBSERVE_AUTHORITY')
    assert decision['mode']=='SAFE_RECOVERY' and decision['allowed_effects']==[]
    assert decision['privileged_execution'] is decision['branch_advance'] is False
    assert decision['authority_effect']==decision['admission_effect']=='NONE'


@pytest.mark.parametrize('facts',(None,{},'VERIFIED','UNKNOWN','INVALID','STALE','CONFLICT',
                                  {'source_integrity':'VERIFIED'},
                                  {'proof':{'native_identity':{'registry_integrity':'VERIFIED'}}}))
def test_missing_invalid_or_forged_facts_always_choose_safe_recovery(facts):
    decision=authority.authority_boot_decision(facts,requested_effect='OBSERVE_AUTHORITY')
    assert decision['mode']=='SAFE_RECOVERY' and decision['allowed_effects']==[]
    assert decision['privileged_execution'] is decision['branch_advance'] is False
    assert decision['authority_effect']==decision['admission_effect']=='NONE'


@pytest.mark.parametrize('requested',('INSTALL','ADMIT','NORMAL','',None))
def test_actual_facts_cannot_authorize_non_observation_effect(
        source_inventory_fixture,requested):
    root,_,_,_=source_inventory_fixture
    facts=authority.collect_authority_facts(root)
    decision=authority.authority_boot_decision(facts,requested_effect=requested)
    assert decision['mode']=='SAFE_RECOVERY' and decision['allowed_effects']==[]
    assert decision['privileged_execution'] is decision['branch_advance'] is False
    assert decision['authority_effect']==decision['admission_effect']=='NONE'
