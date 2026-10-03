import io
import json
import tarfile
import base64
import os
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from install.public_generation_transaction import _safe_archive, _fixture_archive_material
from install import public_generation_transaction as generation
from install.transaction import TransactionError, canonical, sha


def signed_plan_fields(identity, *, target_root=None):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    plan = {"schema":"SereinPublicOutpostGenerationPlan/v1", "repository":"Kaotikking/sfos-public",
            "repo_url":"https://github.com/Kaotikking/sfos-public.git", "ref":"refs/heads/main",
            "commit":"a"*40, "tree":"b"*40, "archive_url":"https://codeload.github.com/Kaotikking/sfos-public/tar.gz/"+"a"*40,
            "archive_sha256":identity["archive_sha256"], "release_digest":identity["release_digest"],
            "authority_key_id":"outpost-cognition-v1", "authority_sha256":sha(public),
            "current_boot_id":"11111111-2222-4333-8444-555555555555",
            "rollback_selector":"historical-evidence-only-no-effect",
            "immutable_rows":[{"target":target, "bytes":len(public) if target.endswith("verification.pem") else 1,
                "sha256":sha(public) if target.endswith("verification.pem") else "c"*64,
                "mode":mode, "uid":0, "gid":0} for target,mode in generation.IMMUTABLE_POLICY.items()]}
    if target_root is not None:
        for row in plan["immutable_rows"]:
            data=public if row["target"].endswith('verification.pem') else b'synthetic fixture only'
            row.update(bytes=len(data),sha256=sha(data))
            path=target_root/row["target"].lstrip('/')
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(int(row['mode'],8))
        boot=target_root/'proc/sys/kernel/random/boot_id'
        boot.parent.mkdir(parents=True);boot.write_text(plan['current_boot_id']+'\n')
    plan["signature"] = base64.urlsafe_b64encode(private.sign(canonical(plan))).decode().rstrip("=")
    return plan, public


def verified(identity):
    plan, public = signed_plan_fields(identity)
    return generation._verify_plan_bytes(plan, public, sha(public))


@pytest.mark.parametrize('defect', [None, 'unsigned_change', 'extra', 'path', 'digest', 'missing'])
def test_recovery_plan_is_exact_and_signature_bound(defect):
    plan, _ = signed_plan_fields({'archive_sha256':'c'*64, 'release_digest':'sha256:'+'d'*64})
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    plan['authority_sha256'] = sha(public)
    for row in plan['immutable_rows']:
        if row['target'].endswith('verification.pem'):
            row.update(bytes=len(public), sha256=sha(public))
    directory = '/var/lib/serein/rollback/outpost-public-generation-20260930T080850Z-b43cfde96e65'
    plan['recovery'] = {'commit':'a'*40,'tree':'b'*40,'archive_sha256':'c'*64,
        'release_digest':'sha256:'+'d'*64,'source_plan_sha256':'e'*64,
        'predecessor_receipt_path':directory+'/prestate-receipt.json',
        'predecessor_receipt_sha256':'f'*64,'candidate_path':directory+'/candidate.json',
        'candidate_sha256':'1'*64,'current_selector_sha256':'2'*64,
        'lkg_selector_sha256':'4'*64,'lkg_generation':'5'*64}
    if defect == 'extra': plan['recovery']['automatic_fallback'] = True
    elif defect == 'path': plan['recovery']['candidate_path'] = '/etc/serein/current.json'
    elif defect == 'digest': plan['recovery']['current_selector_sha256'] = 'unknown'
    elif defect == 'missing': plan['recovery'].pop('tree')
    plan['signature'] = base64.urlsafe_b64encode(private.sign(canonical({k:v for k,v in plan.items() if k != 'signature'}))).decode().rstrip('=')
    if defect == 'unsigned_change': plan['recovery']['commit'] = '3'*40
    if defect:
        with pytest.raises(TransactionError): generation._verify_plan_bytes(plan, public, sha(public))
    else:
        result = generation._verify_plan_bytes(plan, public, sha(public))
        assert result.as_dict()['recovery'] == plan['recovery']


def successor_fixture(root):
    from tests.test_generation_launcher import native_generation
    donor=root/'fixture';donor.mkdir()
    old_root,_,current,selector=native_generation(donor)
    target=root/'usr/share/serein/outpost-generations'
    target.parent.mkdir(parents=True)
    old_root.rename(target);target.chmod(0o755)
    state=root/'var/lib/serein-outpost/generation-state'
    state.mkdir(parents=True);state.chmod(0o755)
    for name in ('current','lkg'):
        path=state/(name+'.json');path.write_bytes(current.read_bytes());path.chmod(0o644)
    return state,target,selector


def test_exact_transaction_lock_excludes_competitors_and_releases_only_own_inode(tmp_path):
    parent = tmp_path / 'var/lib/serein/rollback'; parent.mkdir(parents=True, mode=0o755)
    boot = '11111111-2222-4333-8444-555555555555'
    with generation.public_generation_lock(tmp_path, 'a'*64, boot) as lock:
        path = tmp_path / lock['path'].lstrip('/')
        assert path.stat().st_mode & 0o777 == 0o600
        assert sha(path.read_bytes()) == lock['lock_sha256']
        with pytest.raises(TransactionError, match='PUBLIC_TRANSACTION_LOCKED'):
            with generation.public_generation_lock(tmp_path, 'b'*64, boot):
                pytest.fail('Concurrent transaction entered')
        assert path.exists()
    assert list(parent.iterdir()) == []


def test_transaction_lock_releases_after_body_failure_without_restoration(tmp_path):
    parent = tmp_path / 'var/lib/serein/rollback'; parent.mkdir(parents=True, mode=0o755)
    with pytest.raises(ValueError, match='injected'):
        with generation.public_generation_lock(tmp_path, 'a'*64, '11111111-2222-4333-8444-555555555555'):
            raise ValueError('injected')
    assert list(parent.iterdir()) == []


@pytest.mark.parametrize('defect', ['existing','symlink','changed','hardlink','replaced','private_parent'])
def test_transaction_lock_never_repairs_or_deletes_foreign_state(tmp_path, defect):
    parent = tmp_path / 'var/lib/serein/rollback'; parent.mkdir(parents=True, mode=0o755)
    path = parent / '.outpost-public-generation.lock'
    preserved = tmp_path / 'preserved'
    if defect == 'existing': path.write_bytes(b'other transaction')
    elif defect == 'symlink': preserved.write_bytes(b'foreign'); path.symlink_to(preserved)
    elif defect == 'private_parent': parent.chmod(0o750)
    with pytest.raises(TransactionError):
        with generation.public_generation_lock(tmp_path, 'a'*64, '11111111-2222-4333-8444-555555555555'):
            if defect == 'changed': path.write_bytes(b'changed')
            elif defect == 'hardlink': os.link(path, preserved)
            elif defect == 'replaced': path.rename(preserved); path.write_bytes(b'foreign')
    if defect == 'existing': assert path.read_bytes() == b'other transaction'
    elif defect == 'symlink': assert path.is_symlink() and preserved.read_bytes() == b'foreign'
    elif defect == 'changed': assert path.read_bytes() == b'changed'
    elif defect == 'hardlink': assert path.exists() and preserved.exists()
    elif defect == 'replaced': assert path.read_bytes() == b'foreign' and preserved.exists()
    else: assert list(parent.iterdir()) == [] and parent.stat().st_mode & 0o777 == 0o750


def test_successor_prestate_captures_both_without_switch_or_admission(tmp_path):
    state,_,selector=successor_fixture(tmp_path)
    before={p.name:p.read_bytes() for p in state.iterdir()}
    result=generation.successor_generation_prestate(tmp_path)
    assert result['classification']=='SUCCESSOR_GENERATION_REPLACEMENT'
    assert result['current_admission']=='UNPROVEN' and result['mutation_effect']=='NONE'
    for name in ('current','lkg'):
        row=result['selectors'][name]
        assert row['selector']==selector and row['sha256']==sha(before[name+'.json'])
    assert before=={p.name:p.read_bytes() for p in state.iterdir()}


def test_selector_capture_preserves_exact_format_without_rewrite(tmp_path):
    state, _, _ = successor_fixture(tmp_path)
    current = state / 'current.json'
    current.write_bytes(current.read_bytes() + b'\n')
    expected = generation.successor_generation_prestate(tmp_path)
    capture = generation.capture_selector_predecessor(tmp_path, expected)
    assert capture == {name: (state/(name+'.json')).read_bytes() for name in ('current','lkg')}
    assert capture['current'] != capture['lkg']


@pytest.mark.parametrize('name', ['current', 'lkg'])
def test_selector_capture_rejects_changed_prestate_without_fallback(tmp_path, name):
    state, _, _ = successor_fixture(tmp_path)
    expected = generation.successor_generation_prestate(tmp_path)
    path = state/(name+'.json')
    path.write_bytes(path.read_bytes() + b'\n')
    changed = path.read_bytes()
    with pytest.raises(TransactionError, match='PUBLIC_SELECTOR_PRESTATE_CHANGED'):
        generation.capture_selector_predecessor(tmp_path, expected)
    assert path.read_bytes() == changed


@pytest.mark.parametrize('defect',['missing_current','bad_current','bad_lkg','private_current','private_state','extra_payload'])
def test_successor_prestate_never_falls_back_or_repairs(tmp_path,defect):
    state,root,selector=successor_fixture(tmp_path)
    if defect=='missing_current':(state/'current.json').unlink()
    elif defect=='bad_current':(state/'current.json').write_text('{}')
    elif defect=='bad_lkg':(state/'lkg.json').write_text('{}')
    elif defect=='private_current':(state/'current.json').chmod(0o600)
    elif defect=='private_state':state.chmod(0o700)
    else:(root/selector['generation']/'extra').write_text('unindexed')
    before={p.name:p.read_bytes() for p in state.iterdir()}
    with pytest.raises(TransactionError):generation.successor_generation_prestate(tmp_path)
    assert before=={p.name:p.read_bytes() for p in state.iterdir()}
    if defect=='private_current':assert (state/'current.json').stat().st_mode & 0o777==0o600
    if defect=='private_state':assert state.stat().st_mode & 0o777==0o700


def bootstrap_fixture(root):
    for source, (target, mode) in generation.IMAGE_FILES.items():
        path = root / target.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(('fixture-only:' + source).encode())
        path.chmod(int(mode, 8))
    return {name: {'Id': name, 'LoadState': 'loaded', 'ActiveState': 'inactive',
                   'SubState': 'dead', 'UnitFileState': 'static',
                   'FragmentPath': '/etc/systemd/system/' + name,
                   'DropInPaths': '', 'NeedDaemonReload': 'no'}
            for name in generation.IMAGE_UNITS}


@pytest.fixture
def private_prestate_record(tmp_path):
    """Synthetic signer only: no canonical key is loaded or changed."""
    target = complete_preparation_fixture(tmp_path)
    units = bootstrap_fixture(tmp_path)
    target['current_boot_id'] = '11111111-2222-4333-8444-555555555555'
    evidence = {'target_prestate':target,'source_plan_sha256':'a'*64}
    release, material = bootstrap_material()
    capture = {'image_bytes':generation.capture_bootstrap_predecessor(tmp_path,target['bootstrap_prestate'],units.__getitem__),
               'selector_bytes':generation.capture_selector_predecessor(tmp_path,target['installed_prestate'])}
    body = generation.prepared_prestate_receipt(evidence,release,material,capture)
    private = Ed25519PrivateKey.generate(); public = private.public_key()
    raw = generation.seal_prestate_receipt(body,private,public)
    selector = '/var/lib/serein/rollback/outpost-public-generation-20260929T020000Z-aaaaaaaaaaaa'
    (tmp_path/'var/lib/serein/rollback').mkdir(parents=True, mode=0o755)
    return body, raw, public, selector, evidence, release, material, capture


@pytest.mark.parametrize('defect', [None, 'wrong_generation', 'candidate_changed', 'generation_changed', 'receipt_changed', 'candidate_symlink', 'oversized', 'late_generation', 'late_candidate'])
def test_retained_predecessor_is_exact_signed_read_only_input(tmp_path, private_prestate_record, defect, monkeypatch):
    body, raw, public, directory, *_ = private_prestate_record
    receipt = generation.persist_prestate_receipt(tmp_path, directory, raw, body, public)
    row = body['selector_pre']['current']
    captured = base64.b64decode(row['content_b64'])
    selector = json.loads(captured)
    candidate_name = directory + '/candidate.json'
    candidate = tmp_path / candidate_name.lstrip('/')
    candidate.write_bytes(captured); candidate.chmod(0o600)
    current = tmp_path / row['target'].lstrip('/')
    current_before = current.read_bytes()
    wanted = selector['generation']
    if defect == 'wrong_generation': wanted = 'f' * 64
    elif defect == 'candidate_changed': candidate.write_bytes(b'{}')
    elif defect == 'generation_changed':
        (tmp_path/'usr/share/serein/outpost-generations'/wanted/'foreign').write_bytes(b'foreign')
    elif defect == 'receipt_changed':
        (tmp_path/receipt['path'].lstrip('/')).write_bytes(raw + b' ')
    elif defect == 'candidate_symlink': candidate.unlink(); candidate.symlink_to(current)
    elif defect == 'oversized': candidate.write_bytes(captured + b' ' * 8192)
    elif defect in {'late_generation', 'late_candidate'}:
        from install import generation_launcher
        original = generation_launcher.read_selector
        calls = []
        def changed_after_read(path, generation_root):
            result = original(path, generation_root)
            if not calls:
                if defect == 'late_generation': (result[1] / 'foreign').write_bytes(b'late')
                else:
                    old = candidate.read_bytes(); candidate.unlink()
                    candidate.write_bytes(old); candidate.chmod(0o600)
            calls.append(1)
            return result
        monkeypatch.setattr(generation_launcher, 'read_selector', changed_after_read)
    if defect:
        with pytest.raises(TransactionError):
            generation.retained_predecessor(tmp_path, receipt, body, public, candidate_name, wanted)
    else:
        result = generation.retained_predecessor(tmp_path, receipt, body, public, candidate_name, wanted)
        assert result['selector'] == selector
        assert result['captured_current'] == row
        assert result['mutation_effect'] == 'NONE' and result['admission'] == 'UNPROVEN'
    assert current.read_bytes() == current_before


@pytest.fixture
def retained_recovery_lkg_case(tmp_path, private_prestate_record, monkeypatch):
    """Real selector inventory/custody; only receipt signature loading is synthetic."""
    from install import public_installer_cli
    from install import generation_launcher
    body, _, _, directory, *_ = private_prestate_record
    installed = generation.successor_generation_prestate(tmp_path)
    selector = installed['selectors']['current']['selector']
    candidate_name = directory + '/candidate.json'
    candidate = tmp_path / candidate_name.lstrip('/')
    candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidate.write_bytes(canonical(selector)); candidate.chmod(0o600)
    source = {'schema': 'SereinOutpostPublicSource/v1',
              'repository': 'Kaotikking/sfos-public', 'commit': 'a' * 40,
              'tree': 'b' * 40, 'archive_sha256': 'c' * 64,
              'release_digest': 'sha256:' + selector['generation'],
              'source_plan_sha256': selector['predecessor_receipt_sha256']}
    record_path = directory + '/prestate-receipt.json'
    record = dict(body, receipt_signature='fixture', receipt_digest='d' * 64)
    fields = {
        'repository': source['repository'],
        'immutable_rows': [{'target': str(generation.CANONICAL_AUTHORITY_PATH),
                            'bytes': 1, 'sha256': '0' * 64, 'mode': '0644', 'uid': 0, 'gid': 0}],
        'recovery': {
            'predecessor_receipt_path': record_path,
            'predecessor_receipt_sha256': '1' * 64,
            'candidate_path': candidate_name,
            'candidate_sha256': '2' * 64,
            'release_digest': source['release_digest'],
            'source_plan_sha256': source['source_plan_sha256'],
            'current_selector_sha256': installed['selectors']['current']['sha256'],
            'lkg_selector_sha256': body['selector_pre']['lkg']['sha256'],
            'lkg_generation': json.loads(base64.b64decode(body['selector_pre']['lkg']['content_b64']))['generation'],
            **{key: source[key] for key in ('commit', 'tree', 'archive_sha256')},
        },
    }
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    def load(path, _digest):
        return record if str(path).endswith('prestate-receipt.json') else selector
    monkeypatch.setattr(public_installer_cli, '_load_plan', load)
    monkeypatch.setattr(generation, '_read_target_fact', lambda *_args, **_kwargs: public_pem)
    monkeypatch.setattr(generation, 'retained_predecessor',
                        lambda *_args, **_kwargs: {
                            'selector': selector,
                            'captured_current': body['selector_pre']['current'],
                            'predecessor_receipt': {'path': record_path},
                            'candidate_path': candidate_name,
                            'generation': selector['generation'],
                            'mutation_effect': 'NONE', 'admission': 'UNPROVEN'})
    original_read = generation_launcher._read_regular
    monkeypatch.setattr(generation_launcher, '_read_regular',
                        lambda path, mode: (canonical(source), SimpleNamespace())
                        if path.name == 'public-source.json' else original_read(path, mode))
    return SimpleNamespace(fields=fields, record=record, body=body, selector=selector,
                           state=tmp_path / 'var/lib/serein-outpost/generation-state')


def test_retained_recovery_authenticates_original_lkg_pair(tmp_path, retained_recovery_lkg_case):
    case = retained_recovery_lkg_case
    result = generation.retained_recovery_prestate(tmp_path, case.fields)
    expected = generation.successor_generation_prestate(tmp_path)['selectors']['lkg']
    assert result['preserved_lkg'] == expected
    assert result['retained']['mutation_effect'] == 'NONE'


@pytest.mark.parametrize('field', ['lkg_selector_sha256', 'lkg_generation'])
def test_retained_recovery_denies_signed_wrong_lkg_identity(tmp_path, retained_recovery_lkg_case, field):
    case = retained_recovery_lkg_case
    case.fields['recovery'][field] = 'f' * 64
    with pytest.raises(TransactionError, match='PUBLIC_RECOVERY_LKG_DENIED'):
        generation.retained_recovery_prestate(tmp_path, case.fields)


@pytest.mark.parametrize('defect', ['format', 'custody', 'selector'])
def test_retained_recovery_denies_live_lkg_drift(tmp_path, retained_recovery_lkg_case, defect):
    case = retained_recovery_lkg_case
    path = case.state / 'lkg.json'
    if defect == 'format':
        path.write_bytes(path.read_bytes() + b'\n')
    elif defect == 'custody':
        path.chmod(0o600)
    else:
        value = json.loads(path.read_bytes()); value['generation'] = 'f' * 64
        path.write_bytes(canonical(value) + b'\n')
    with pytest.raises(TransactionError):
        generation.retained_recovery_prestate(tmp_path, case.fields)


@pytest.mark.parametrize('defect', ['missing', 'target', 'mode', 'bytes', 'content'])
def test_retained_recovery_denies_invalid_historical_lkg_row(tmp_path, retained_recovery_lkg_case, defect):
    case = retained_recovery_lkg_case
    row = case.record['selector_pre']['lkg']
    if defect == 'missing': case.record['selector_pre'].pop('lkg')
    elif defect == 'target': row['target'] = '/etc/shadow'
    elif defect == 'mode': row['mode'] = '0600'
    elif defect == 'bytes': row['bytes'] += 1
    else: row['content_b64'] = base64.b64encode(b'{}').decode()
    with pytest.raises(TransactionError, match='PUBLIC_RECOVERY_LKG_DENIED'):
        generation.retained_recovery_prestate(tmp_path, case.fields)


def test_private_prestate_record_exact_durable_readback_and_collision(tmp_path, private_prestate_record):
    body, raw, public, selector, *_ = private_prestate_record
    result = generation.persist_prestate_receipt(tmp_path,selector,raw,body,public)
    path = tmp_path/result['path'].lstrip('/')
    assert path.read_bytes() == raw and path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert result['sha256'] == sha(raw) and result['activation'] == 'NONE'
    readback = generation.verify_prestate_receipt(path.read_bytes(),body,public)
    assert readback['receipt_digest'] == result['receipt_digest']
    for name,row in body['selector_pre'].items():
        assert base64.b64decode(row['content_b64']) == (tmp_path/row['target'].lstrip('/')).read_bytes()
    with pytest.raises(TransactionError,match='PUBLIC_ROLLBACK_COLLISION_DENIED'):
        generation.persist_prestate_receipt(tmp_path,selector,raw,body,public)
    assert path.read_bytes() == raw


@pytest.mark.parametrize('defect',['image','selector','extra_image','extra_selector','boot'])
def test_private_prestate_record_rejects_capture_substitution(private_prestate_record,defect):
    _,_,_,_,evidence,release,material,capture = private_prestate_record
    if defect == 'image': capture['image_bytes'][next(iter(capture['image_bytes']))] = b'changed'
    elif defect == 'selector': capture['selector_bytes']['current'] += b'\n'
    elif defect == 'extra_image': capture['image_bytes']['/etc/shadow'] = b'forbidden'
    elif defect == 'extra_selector': capture['selector_bytes']['replacement'] = b'{}'
    else: evidence['target_prestate']['current_boot_id'] = 'unknown'
    with pytest.raises(TransactionError,match='PUBLIC_PRESTATE_CAPTURE_BINDING_DENIED'):
        generation.prepared_prestate_receipt(evidence,release,material,capture)


@pytest.mark.parametrize('defect',['signature','expected_boot','expected_plan','truncated','extra_field','wrong_key','bad_path'])
def test_private_prestate_record_denies_before_write(tmp_path,private_prestate_record,defect):
    body,raw,public,selector,*_ = private_prestate_record
    if defect in {'signature','extra_field'}:
        value = json.loads(raw)
        if defect == 'signature': value['receipt_signature'] = 'a'*86
        else: value['extra'] = 'not allowed'
        value['receipt_digest'] = sha(canonical({key:item for key,item in value.items() if key!='receipt_digest'}))
        raw = canonical(value)
    elif defect == 'expected_boot': body['boot_id'] = '22222222-2222-4333-8444-555555555555'
    elif defect == 'expected_plan': body['source_plan_sha256'] = 'b'*64
    elif defect == 'truncated': raw = raw[:40]
    elif defect == 'wrong_key': public = Ed25519PrivateKey.generate().public_key()
    else: selector = '/etc/new-record'
    with pytest.raises(TransactionError): generation.persist_prestate_receipt(tmp_path,selector,raw,body,public)
    assert list((tmp_path/'var/lib/serein/rollback').iterdir()) == []


def test_private_prestate_record_interruption_preserves_collision_evidence(tmp_path,private_prestate_record,monkeypatch):
    body,raw,public,selector,*_ = private_prestate_record
    original = generation.os.fsync
    def fail(_): raise OSError('injected durability failure')
    monkeypatch.setattr(generation.os,'fsync',fail)
    with pytest.raises(TransactionError,match='PUBLIC_PRESTATE_RECORD_IO_DENIED'):
        generation.persist_prestate_receipt(tmp_path,selector,raw,body,public)
    monkeypatch.setattr(generation.os,'fsync',original)
    path = tmp_path/selector.lstrip('/')/'prestate-receipt.json'
    assert path.exists()
    before = path.read_bytes()
    with pytest.raises(TransactionError,match='PUBLIC_ROLLBACK_COLLISION_DENIED'):
        generation.persist_prestate_receipt(tmp_path,selector,raw,body,public)
    assert path.read_bytes() == before


def test_record_signer_denies_fixture_plan_before_any_key_read(monkeypatch):
    _,identity = archive()
    calls = []
    monkeypatch.setattr(generation,'_read_target_fact',lambda *a,**k:calls.append(a))
    with pytest.raises(TransactionError,match='PUBLIC_VERIFIED_PLAN_REQUIRED'):
        generation.load_prestate_signer(verified(identity))
    assert calls == []


@pytest.mark.parametrize('defect',[None,'wrong_pair','wrong_anchor'])
def test_record_signer_binds_existing_pair_without_key_changes(monkeypatch,defect):
    """Replace only read seams; no canonical private key is accessed."""
    _,identity = archive()
    fixture = verified(identity)
    plan = generation.VerifiedSourcePlan(fixture.encoded,fixture.authority_sha256,_token=generation._VERIFIED)
    private = Ed25519PrivateKey.generate()
    signing = private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    public = private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = sha(public)
    if defect == 'wrong_pair':
        public = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr(generation,'CANONICAL_AUTHORITY_SHA256','0'*64 if defect=='wrong_anchor' else fingerprint)
    calls=[]
    def read(root,path,*,expected,capture=False):
        assert root == Path('/') and expected['target']==path
        calls.append((path,capture))
        return (signing if path.endswith('signing.pem') else public) if capture else None
    monkeypatch.setattr(generation,'_read_target_fact',read)
    if defect:
        with pytest.raises(TransactionError,match='PUBLIC_RECEIPT_KEYPAIR_DENIED'): generation.load_prestate_signer(plan)
    else:
        returned,anchor = generation.load_prestate_signer(plan)
        anchor.verify(returned.sign(b'fixture'),b'fixture')
        assert [capture for _,capture in calls]==[True,True,False,False]


def test_private_key_capture_requires_allowlisted_exact_expected_row(tmp_path):
    with pytest.raises(TransactionError,match='PUBLIC_KEY_CAPTURE_PATH_DENIED'):
        generation._read_target_fact(tmp_path,'/etc/serein-outpost/readonly.token',expected={},capture=True)
    with pytest.raises(TransactionError,match='PUBLIC_KEY_CAPTURE_PATH_DENIED'):
        generation._read_target_fact(tmp_path,'/etc/serein-outpost/cognition-signing.pem',capture=True)


@pytest.mark.parametrize('defect',[None,'bytes','mode','hardlink','symlink','directory_mode','digest','path'])
def test_private_prestate_final_readback_denies_late_changes(tmp_path,private_prestate_record,defect):
    body,raw,public,selector,*_ = private_prestate_record
    receipt = generation.persist_prestate_receipt(tmp_path,selector,raw,body,public)
    path = tmp_path/receipt['path'].lstrip('/')
    if defect=='bytes': path.write_bytes(raw+b'\n')
    elif defect=='mode': path.chmod(0o644)
    elif defect=='hardlink': os.link(path,tmp_path/'alias')
    elif defect=='symlink':
        saved=tmp_path/'saved';path.rename(saved);path.symlink_to(saved)
    elif defect=='directory_mode': path.parent.chmod(0o755)
    elif defect=='digest': receipt['receipt_digest']='0'*64
    elif defect=='path': receipt['path']='/etc/shadow'
    if defect:
        with pytest.raises(TransactionError): generation.reread_prestate_receipt(tmp_path,receipt,body,public)
    else:
        assert generation.reread_prestate_receipt(tmp_path,receipt,body,public)==receipt
    if defect=='mode': assert path.stat().st_mode & 0o777==0o644
    if defect=='symlink': assert path.is_symlink()


@pytest.mark.parametrize('defect',[None,'file','directory','symlink','parent_mode','late','bad_digest'])
def test_prospective_generation_denies_collisions_without_target_effect(tmp_path,monkeypatch,defect):
    parent=tmp_path/'usr/share/serein/outpost-generations';parent.mkdir(parents=True,mode=0o755)
    path=parent/('e'*64);digest='sha256:'+'e'*64
    if defect=='file':path.write_text('preserve')
    elif defect=='directory':path.mkdir()
    elif defect=='symlink':path.symlink_to(tmp_path/'absent')
    elif defect=='parent_mode':parent.chmod(0o700)
    elif defect=='bad_digest':digest='../../etc'
    elif defect=='late':
        original=generation.os.path.lexists;calls=0
        def appear(value):
            nonlocal calls
            if value==path:
                calls+=1
                if calls==2:path.write_text('late external writer')
            return original(value)
        monkeypatch.setattr(generation.os.path,'lexists',appear)
    if defect:
        with pytest.raises(TransactionError):generation.prospective_generation_prestate(tmp_path,digest)
    else:
        result=generation.prospective_generation_prestate(tmp_path,digest)
        assert result['state']=='ABSENT' and result['target'].endswith('e'*64)
        assert not path.exists()
    if defect=='file':assert path.read_text()=='preserve'
    if defect=='directory':assert path.is_dir()
    if defect=='symlink':assert path.is_symlink()
    if defect=='late':assert path.read_text()=='late external writer'
    if defect=='parent_mode':assert parent.stat().st_mode & 0o777==0o700


@pytest.mark.parametrize('changed',[False,True])
def test_native_preflight_rereads_final_generation_destination(monkeypatch,changed):
    _,identity=archive();fixture=verified(identity)
    plan=generation.VerifiedSourcePlan(fixture.encoded,fixture.authority_sha256,_token=generation._VERIFIED)
    calls=[]
    monkeypatch.setattr(generation,'_target_prestate',lambda *a:{'boot':'fixture'})
    monkeypatch.setattr(generation,'successor_generation_prestate',lambda *a:{'selectors':'fixture'})
    monkeypatch.setattr(generation,'bootstrap_prestate',lambda *a:{'units':'fixture'})
    def destination(root,digest):
        assert root==Path('/') and digest==plan.as_dict()['release_digest']
        calls.append(digest)
        return {'state':'ABSENT','parent':len(calls) if changed else 1}
    monkeypatch.setattr(generation,'prospective_generation_prestate',destination)
    if changed:
        with pytest.raises(TransactionError,match='PUBLIC_GENERATION_DESTINATION_CHANGED'):
            generation.preflight_target(plan)
    else:
        assert generation.preflight_target(plan)['generation_destination']=={'state':'ABSENT','parent':1}
    assert len(calls)==2


@pytest.fixture
def prepared_forward(tmp_path,private_prestate_record):
    body,_,_,selector,*_=private_prestate_record
    private=Ed25519PrivateKey.generate();public=private.public_key()
    prestate=generation.seal_prestate_receipt(body,private,public)
    receipt=generation.persist_prestate_receipt(tmp_path,selector,prestate,body,public)
    raw=generation.seal_prepared_forward_state(prestate,body,private,public)
    return body,prestate,public,receipt,raw,private


@pytest.mark.parametrize('retained_recovery', [False, True])
@pytest.mark.parametrize('failure',[None,'image','witness','restored_unit','disabled_target','vitals_absent','vitals_wrong_generation','vitals_inactive','exit_stop','exit_image','exit_reload','exit_selector'])
def test_complete_g0_promotion_native_files_and_exact_failure_compensation(tmp_path,private_prestate_record,failure,retained_recovery):
    """Real Linux file CAS/journal; synthetic systemd/witness, never VM proof."""
    body,_,_,directory,_,release,material,_=private_prestate_record
    body['unit_prestate']['serein-outpost.target']['UnitFileState']='disabled' if failure=='disabled_target' else 'enabled'
    if failure == 'exit_stop':
        body['unit_prestate']['serein-outpost.service'].update(ActiveState='active',SubState='running')
    private=Ed25519PrivateKey.generate();public=private.public_key()
    raw=generation.seal_prestate_receipt(body,private,public)
    receipt=generation.persist_prestate_receipt(tmp_path,directory,raw,body,public)
    forward=generation.seal_prepared_forward_state(raw,body,private,public)
    generation.prepared_forward_record(tmp_path,receipt,raw,body,public,create_raw=forward)
    selector=generation.prepared_generation_selector(release,material,body['source_plan_sha256'])
    retained = None
    if retained_recovery:
        # Recovery keeps the retained selector's original source-plan binding.
        selector = generation.prepared_generation_selector(release,material,'b'*64)
        restored_row = generation._effect_row(body['selector_pre']['current']['target'], canonical(selector) + b'\n\n', '0644')
        retained = {'selector':selector, 'generation':selector['generation'],
                    'captured_current':restored_row, 'mutation_effect':'NONE'}
    precheck={'result':'G0_SOURCE_PREDICATES_PASS','selector':selector,
              'source_plan_sha256':selector['predecessor_receipt_sha256'],'constitution':{'status':'CANDIDATE_BOUND_UNADMITTED'}}
    class FixtureIO(generation._GenerationFileIO):
        def __init__(self):
            super().__init__(tmp_path,directory)
            self.units={name:dict(value) for name,value in body['unit_prestate'].items()}
            self.calls=[];self.injected=False
        def unit_state(self,name):return dict(self.units[name])
        def unit(self,action,name=None):
            self.calls.append((action,name))
            if action=='start':
                for selected in (generation.IMAGE_UNITS if name=='serein-outpost.target' else (name,)):
                    self.units[selected].update(ActiveState='active',SubState='running')
                if failure=='vitals_inactive':
                    self.units['serein-https-gateway-adapter.service'].update(ActiveState='inactive',SubState='dead')
            if action=='stop':self.units[name].update(ActiveState='inactive',SubState='dead')
            if action in {'enable','disable'}:self.units[name]['UnitFileState']='enabled' if action=='enable' else 'disabled'
            if not self.injected and ((failure=='exit_stop' and action=='stop') or (failure=='exit_reload' and action=='daemon-reload')):
                self.injected=True;raise SystemExit('injected catchable interruption')
        def replace(self,path,before,after):
            super().replace(path,before,after)
            if failure=='image' and path==body['image_files'][1]['target'] and not self.injected:
                self.injected=True;raise OSError('injected failure after durable image write')
            if not self.injected and ((failure=='exit_image' and path==body['image_files'][0]['target']) or (failure=='exit_selector' and path==body['selector_pre']['current']['target'])):
                self.injected=True;raise KeyboardInterrupt('injected catchable interruption')
    io=FixtureIO();boundaries=[]
    def invariant():boundaries.append('same-boot-identity-keys')
    def accept(expected,not_before):
        assert expected==selector and not_before>0
        assert json.loads(base64.b64decode(io.read(body['selector_pre']['current']['target'])['content_b64']))==selector
        if failure in {'witness','restored_unit'}:
            if failure=='restored_unit':
                original=io.unit
                def sticky_stop(action,name=None):
                    if action=='stop' and name=='serein-outpost.service':return
                    original(action,name)
                io.unit=sticky_stop
            raise TransactionError('INJECTED_WITNESS_FAILURE')
        result={'result':'SUPPORTING_CURRENT_BOOT_WITNESS','witness':{'boot_id':body['boot_id'],'generation_identity':selector}}
        if failure!='vitals_absent':
            result['vitals']={'result':'LOCAL_VITALS_JSON_HTML_OBSERVED','boot_id':body['boot_id'],
                'generation':'f'*64 if failure=='vitals_wrong_generation' else selector['generation']}
        return result
    if failure in {'disabled_target','restored_unit'}:
        match='PUBLIC_ENABLED_SUCCESSOR_TARGET_REQUIRED' if failure=='disabled_target' else 'PUBLIC_INSTALL_FAILED_RECOVERY_UNPROVEN'
        with pytest.raises(TransactionError,match=match):
            generation._complete_bootstrap_promotion(io,{'candidate_selector':selector},body,raw,private,public,precheck,invariant,accept,retained=retained)
        if failure=='disabled_target':assert io.calls==[]
        assert json.loads((tmp_path/directory.lstrip('/')/'forward-state.json').read_bytes())['phase']!='RESTORED_CAPTURED_PRESTATE'
        return
    if failure:
        with pytest.raises(TransactionError,match='PUBLIC_INSTALL_FAILED_CAPTURED_PRESTATE_RESTORED'):
            generation._complete_bootstrap_promotion(io,{'candidate_selector':selector},body,raw,private,public,precheck,invariant,accept,retained=retained)
        for row in body['image_files']:assert io.read(row['target'])==row['pre']
        assert io.read(body['selector_pre']['current']['target'])==body['selector_pre']['current']
        assert io.unit_state('serein-outpost.target')['UnitFileState']=='enabled'
        phase='RESTORED_CAPTURED_PRESTATE'
    else:
        result=generation._complete_bootstrap_promotion(io,{'candidate_selector':selector},body,raw,private,public,precheck,invariant,accept,retained=retained)
        assert result['result']==('RESTORED_CURRENT_BOOT_OBSERVED' if retained_recovery else 'INSTALLED_CURRENT_BOOT_OBSERVED')
        if retained_recovery:
            assert io.read(body['selector_pre']['current']['target']) == retained['captured_current']
            assert result['preserved_lkg_sha256'] == body['selector_pre']['lkg']['sha256']
            assert result['preserved_lkg_selector'] == json.loads(base64.b64decode(body['selector_pre']['lkg']['content_b64']))
        assert result['stage1']==result['sfos_admission']==result['outpost_admission']=='UNPROVEN'
        assert result['downstream_activation']=='NONE'
        for row in body['image_files']:assert io.read(row['target'])==row['post']
        phase='COMPLETE'
    assert io.read(body['selector_pre']['lkg']['target'])==body['selector_pre']['lkg']
    assert json.loads((tmp_path/directory.lstrip('/')/'forward-state.json').read_bytes())['phase']==phase
    assert all(name is None or name in generation.IMAGE_UNITS for _,name in io.calls)
    assert boundaries


def test_bootstrap_constitution_rejects_rehashed_invented_policy():
    from outpost.constitutional_registry import bootstrap_constitution_binding, ConstitutionalRegistryError
    raw=(Path(__file__).parents[1]/'outpost/bootstrap-constitution.json').read_bytes()
    assert bootstrap_constitution_binding(raw,sha(raw))['status']=='CANDIDATE_BOUND_UNADMITTED'
    value=json.loads(raw);value['clauses']=['x','y'];replacement=canonical(value)
    with pytest.raises(ConstitutionalRegistryError):bootstrap_constitution_binding(replacement,sha(replacement))


@pytest.mark.parametrize('defect',[None,'file_drift','extra_file','inventory','selector','collision','prestate','mode'])
def test_candidate_record_uses_actual_launcher_without_launch(tmp_path,prepared_forward,monkeypatch,defect):
    from install.transaction import stage_inactive_generation
    from install import generation_launcher
    body,prestate,public,receipt,_,_=prepared_forward
    release,material=bootstrap_material()
    stage=tmp_path/'private-stage';stage.mkdir(mode=0o700)
    selector=generation.prepared_generation_selector(release,material,body['source_plan_sha256'])
    stage_inactive_generation(stage,selector['generation'],material)
    package=stage/selector['generation']
    assert package.stat().st_mode & 0o777==0o755 and stage.stat().st_mode & 0o777==0o700
    original=generation_launcher.read_selector;calls=[]
    def consume(path,parent):
        calls.append(path);return original(path,parent)
    monkeypatch.setattr(generation_launcher,'read_selector',consume)
    monkeypatch.setattr(generation_launcher.os,'execve',lambda *a:pytest.fail('must not launch'))
    path=(tmp_path/receipt['path'].lstrip('/')).with_name('candidate.json')
    if defect=='file_drift':(package/next(iter(material))).write_bytes(b'drift')
    elif defect=='extra_file':(package/'extra').write_text('unindexed')
    elif defect=='inventory':(package/'generation-inventory.json').write_text('[]')
    elif defect=='selector':selector['predecessor_receipt_sha256']='b'*64
    elif defect=='collision':path.write_bytes(b'existing');path.chmod(0o600)
    elif defect=='prestate':(tmp_path/receipt['path'].lstrip('/')).write_bytes(b'changed')
    elif defect=='mode':package.chmod(0o700)
    if defect:
        with pytest.raises(TransactionError):generation.prepared_candidate_record(
            tmp_path,receipt,prestate,body,public,selector,stage,create=True)
        if defect=='collision':assert path.read_bytes()==b'existing'
    else:
        result=generation.prepared_candidate_record(tmp_path,receipt,prestate,body,public,selector,stage,create=True)
        assert result['activation']=='NONE' and path.read_bytes()==canonical(selector)+b'\n'
        assert generation.prepared_candidate_record(tmp_path,receipt,prestate,body,public,selector,stage)==result
        assert len(calls)==2
        (package/next(iter(material))).write_bytes(b'late drift')
        with pytest.raises(TransactionError):generation.prepared_candidate_record(
            tmp_path,receipt,prestate,body,public,selector,stage)


@pytest.mark.parametrize('defect',[None,'collision','prestate','material','interrupted'])
def test_canonical_inactive_placement_preserves_current_and_consumes_exact_package(tmp_path,prepared_forward,monkeypatch,defect):
    from install import transaction
    from install.generation_launcher import read_selector
    body,prestate,public,receipt,_,_=prepared_forward
    before=generation.successor_generation_prestate(tmp_path)
    release,material=bootstrap_material();digest=release['self_digest']
    destination=generation.prospective_generation_prestate(tmp_path,digest)
    target=tmp_path/destination['target'].lstrip('/')
    if defect=='collision':target.mkdir()
    elif defect=='prestate':destination['parent']['inode']+=1
    elif defect=='material':material[next(iter(material))]=b'changed'
    elif defect=='interrupted':
        original=transaction.os.fsync
        def fail(_):raise OSError('injected durability failure')
        monkeypatch.setattr(transaction.os,'fsync',fail)
    if defect:
        with pytest.raises(TransactionError):transaction.place_inactive_generation(tmp_path,release,material,destination)
        if defect=='interrupted':
            monkeypatch.setattr(transaction.os,'fsync',original)
            assert target.is_dir()
            preserved={str(p):p.read_bytes() for p in target.rglob('*') if p.is_file()}
            with pytest.raises(TransactionError):transaction.place_inactive_generation(tmp_path,release,material,destination)
            assert preserved=={str(p):p.read_bytes() for p in target.rglob('*') if p.is_file()}
        elif defect!='collision':assert not target.exists()
    else:
        result=transaction.place_inactive_generation(tmp_path,release,material,destination)
        assert result['result']=='PLACED_INACTIVE_BYTES_ONLY' and result['activation']=='NONE'
        # Independently use the actual consumer on the final package tree.
        selector=generation.prepared_generation_selector(release,material,body['source_plan_sha256'])
        candidate=(tmp_path/receipt['path'].lstrip('/')).with_name('candidate.json')
        candidate.write_bytes(canonical(selector)+b'\n');candidate.chmod(0o600)
        assert read_selector(candidate,target.parent)==(selector,target)
        bound=generation.prepared_candidate_record(tmp_path,receipt,prestate,body,public,
            selector,target.parent,placed=True)
        units=bootstrap_fixture(tmp_path)
        monkeypatch.setattr(generation,'_target_prestate',lambda *a:{'current_boot_id':body['boot_id']})
        fields={'rollback_selector':str(Path(receipt['path']).parent),'release_digest':digest}
        observed=generation._placed_target_prestate(tmp_path,fields,selector,bound,
            body['source_plan_sha256'],units.__getitem__)
        assert observed['generation_destination']=={**destination,'state':'PRESENT','selector':selector}
        assert observed['installed_prestate']==before
        assert observed['bootstrap_prestate']==generation.bootstrap_prestate(tmp_path,units.__getitem__)
    assert generation.successor_generation_prestate(tmp_path)==before


def test_prepared_forward_exact_record_and_no_reentry(tmp_path,prepared_forward):
    body,prestate,public,receipt,raw,_=prepared_forward
    before=generation.successor_generation_prestate(tmp_path)
    journal=generation.prepared_forward_record(tmp_path,receipt,prestate,body,public,create_raw=raw)
    assert journal['phase']=='PREPARED' and journal['step']==0 and journal['activation']=='NONE'
    path=tmp_path/journal['path'].lstrip('/')
    assert path.read_bytes()==raw and path.stat().st_mode & 0o777==0o600
    assert generation.prepared_forward_record(tmp_path,receipt,prestate,body,public,journal=journal)==journal
    with pytest.raises(TransactionError,match='PUBLIC_FORWARD_STATE_COLLISION_DENIED'):
        generation.prepared_forward_record(tmp_path,receipt,prestate,body,public,create_raw=raw)
    assert path.read_bytes()==raw and generation.successor_generation_prestate(tmp_path)==before


@pytest.mark.parametrize('defect',['phase','step','bool_step','prestate_digest','boot','source','generation','extra','signature'])
def test_prepared_forward_rejects_signed_substitutions_before_write(tmp_path,prepared_forward,defect):
    body,prestate,public,receipt,raw,private=prepared_forward
    value=json.loads(raw);value.pop('state_signature');value.pop('state_digest')
    key,val={'phase':('phase','COMPLETE'),'step':('step',1),'bool_step':('step',False),
             'prestate_digest':('prestate_receipt_digest','0'*64),'boot':('boot_id','other'),
             'source':('source_plan_sha256','b'*64),'generation':('generation_target','/other'),
             'extra':('admission','ADMITTED'),'signature':('phase','PREPARED')}[defect]
    value[key]=val
    value['state_signature']=base64.urlsafe_b64encode(private.sign(canonical(value))).decode().rstrip('=')
    if defect=='signature':value['state_signature']='a'*86
    value['state_digest']=sha(canonical(value));raw=canonical(value)
    with pytest.raises(TransactionError):
        generation.prepared_forward_record(tmp_path,receipt,prestate,body,public,create_raw=raw)
    assert not (tmp_path/receipt['path'].lstrip('/')).with_name('forward-state.json').exists()


@pytest.mark.parametrize('defect',['bytes','mode','hardlink','symlink','parent_mode','prestate','path','digest'])
def test_prepared_forward_independent_readback_rejects_changes(tmp_path,prepared_forward,defect):
    body,prestate,public,receipt,raw,_=prepared_forward
    journal=generation.prepared_forward_record(tmp_path,receipt,prestate,body,public,create_raw=raw)
    path=tmp_path/journal['path'].lstrip('/')
    if defect=='bytes':path.write_bytes(raw+b'\n')
    elif defect=='mode':path.chmod(0o644)
    elif defect=='hardlink':os.link(path,tmp_path/'alias')
    elif defect=='symlink':
        saved=tmp_path/'saved';path.rename(saved);path.symlink_to(saved)
    elif defect=='parent_mode':path.parent.chmod(0o755)
    elif defect=='prestate':(tmp_path/receipt['path'].lstrip('/')).write_bytes(prestate+b'\n')
    elif defect=='path':journal['path']='/etc/shadow'
    else:journal['state_digest']='0'*64
    with pytest.raises(TransactionError):
        generation.prepared_forward_record(tmp_path,receipt,prestate,body,public,journal=journal)


def test_prepared_forward_interrupted_persistence_retains_evidence(tmp_path,prepared_forward,monkeypatch):
    body,prestate,public,receipt,raw,_=prepared_forward
    original=generation.os.fsync
    def fail(_):raise OSError('injected durability failure')
    monkeypatch.setattr(generation.os,'fsync',fail)
    with pytest.raises(TransactionError,match='PUBLIC_FORWARD_STATE_IO_DENIED'):
        generation.prepared_forward_record(tmp_path,receipt,prestate,body,public,create_raw=raw)
    monkeypatch.setattr(generation.os,'fsync',original)
    path=(tmp_path/receipt['path'].lstrip('/')).with_name('forward-state.json')
    assert path.exists();before=path.read_bytes()
    with pytest.raises(TransactionError,match='PUBLIC_FORWARD_STATE_COLLISION_DENIED'):
        generation.prepared_forward_record(tmp_path,receipt,prestate,body,public,create_raw=raw)
    assert path.read_bytes()==before


@pytest.fixture
def current_boot_observer(tmp_path):
    state,_,selector=successor_fixture(tmp_path)
    path=tmp_path/'var/lib/serein-outpost/coordinator/current.json'
    path.parent.mkdir(mode=0o750)
    value={'schema':'SereinOutpostCoordinatorWitness/v2',
           'boot_id':'11111111-2222-4333-8444-555555555555','previous_boot_id':None,
           'observed_at':12.0,'host_gate':'HOST_GATE_UNAVAILABLE',
           'registry_state':'HOLD_INTENTIONAL','downstream_activation':'DENIED_HELD_SEED_CONTENT',
           'generation_identity':selector,'authority_effect':'NONE','admission_effect':'NONE','mutation_effect':'NONE'}
    path.write_bytes(canonical(value));path.chmod(0o600)
    boot=tmp_path/'proc/sys/kernel/random/boot_id';boot.parent.mkdir(parents=True)
    boot.write_text(value['boot_id']+'\n')
    args=dict(expected_generation=selector,boot_id=value['boot_id'],not_before=10.0,
              observed_at=15.0,service_uid=0,service_gid=0)
    return path,value,args,state


def test_current_boot_observer_preserves_unavailable_host_without_admission(tmp_path,current_boot_observer):
    path,value,args,state=current_boot_observer
    result=generation.read_generation_witness(tmp_path,**args)
    assert result['witness']==value and result['coordinator_sha256']==sha(path.read_bytes())
    assert result['admission']=='UNPROVEN' and result['authority_effect']==result['mutation_effect']=='NONE'
    assert result['current_selector_sha256']==sha((state/'current.json').read_bytes())


@pytest.mark.parametrize('defect',['missing','unbound','wrong_generation','boot','stale','future',
                                 'mode','parent_mode','hardlink','symlink','uid','nan_boundary','bool_boundary','admitted','host_boot'])
def test_current_boot_observer_rejects_invalid_runtime_evidence(tmp_path,current_boot_observer,defect):
    path,value,args,state=current_boot_observer
    if defect=='unbound': value['generation_identity']=None
    elif defect=='wrong_generation': value['generation_identity']={**args['expected_generation'],'inventory_digest':'f'*64}
    elif defect=='boot': value['boot_id']='22222222-2222-4333-8444-555555555555'
    elif defect=='stale': value['observed_at']=9.0
    elif defect=='future': value['observed_at']=16.0
    elif defect=='admitted': value['admission_effect']='ADMIT'
    path.write_bytes(canonical(value))
    if defect=='missing': path.unlink()
    elif defect=='mode': path.chmod(0o644)
    elif defect=='parent_mode': path.parent.chmod(0o755)
    elif defect=='hardlink': os.link(path,tmp_path/'alias')
    elif defect=='symlink':
        saved=tmp_path/'saved';path.rename(saved);path.symlink_to(saved)
    elif defect=='uid': args['service_uid']=12345
    elif defect=='nan_boundary': args['observed_at']=float('nan')
    elif defect=='bool_boundary': args['not_before']=True
    elif defect=='host_boot': (tmp_path/'proc/sys/kernel/random/boot_id').write_text('22222222-2222-4333-8444-555555555555\n')
    with pytest.raises(TransactionError): generation.read_generation_witness(tmp_path,**args)


def test_current_boot_observer_rechecks_actual_boot_after_witness(tmp_path,current_boot_observer,monkeypatch):
    _,_,args,_=current_boot_observer
    original=generation._read_target_fact;calls=[]
    def read(root,path,**kwargs):
        calls.append(path)
        if len(calls)==2: return b'22222222-2222-4333-8444-555555555555\n'
        return original(root,path,**kwargs)
    monkeypatch.setattr(generation,'_read_target_fact',read)
    with pytest.raises(TransactionError,match='PUBLIC_BOOT_DRIFT_DENIED'):
        generation.read_generation_witness(tmp_path,**args)
    assert len(calls)==2


@pytest.mark.parametrize('future',[False,True])
def test_current_boot_observer_samples_clock_after_intervening_publication(tmp_path,current_boot_observer,monkeypatch,future):
    path,value,args,_=current_boot_observer
    del args['observed_at']
    original=generation.successor_generation_prestate
    events=[]
    def prestate(root):
        state=original(root)
        if not events:
            value['observed_at']=21.0 if future else 19.0
            path.write_bytes(canonical(value));events.append('publication')
        return state
    def now():
        assert events==['publication']
        events.append('clock');return 20.0
    monkeypatch.setattr(generation,'successor_generation_prestate',prestate)
    monkeypatch.setattr(generation.time,'time',now)
    if future:
        with pytest.raises(TransactionError,match='PUBLIC_CURRENT_BOOT_WITNESS_DENIED'):
            generation.read_generation_witness(tmp_path,**args)
    else:
        result=generation.read_generation_witness(tmp_path,**args)
        assert result['witness']['observed_at']==19.0 and result['admission']=='UNPROVEN'
    assert events==['publication','clock']


def test_bootstrap_prestate_binds_exact_files_and_units_without_effect(tmp_path):
    units = bootstrap_fixture(tmp_path)
    result = generation.bootstrap_prestate(tmp_path, units.__getitem__)
    assert len(result['files']) == 6 and result['units'] == units
    assert result['mutation_effect'] == 'NONE' and result['admission'] == 'UNPROVEN'
    for row in result['files']:
        data = (tmp_path / row['target'].lstrip('/')).read_bytes()
        assert row['sha256'] == sha(data) and row['bytes'] == len(data)
        assert 'content_b64' not in row


def test_bootstrap_prestate_records_missing_coordinator_without_classification(tmp_path):
    units = bootstrap_fixture(tmp_path)
    name = 'serein-outpost.service'
    (tmp_path / 'etc/systemd/system' / name).unlink()
    units[name].update(LoadState='not-found', UnitFileState='', FragmentPath='')
    result = generation.bootstrap_prestate(tmp_path, units.__getitem__)
    assert next(row for row in result['files'] if row['target'].endswith('/'+name))['state'] == 'ABSENT'
    assert 'classification' not in result


@pytest.mark.parametrize('defect', ['symlink', 'hardlink', 'private', 'directory',
                                    'changed_file', 'changed_unit', 'dropin', 'reload',
                                    'wrong_fragment', 'missing_field', 'unit_file_mismatch'])
def test_bootstrap_prestate_rejects_conflicts_without_repair(tmp_path, defect):
    units = bootstrap_fixture(tmp_path)
    target = tmp_path / 'etc/systemd/system/serein-outpost.service'
    row = units['serein-outpost.service']
    if defect == 'symlink':
        other = tmp_path / 'preserved'; target.rename(other); target.symlink_to(other)
    elif defect == 'hardlink': os.link(target, tmp_path / 'preserved')
    elif defect == 'private': target.chmod(0o600)
    elif defect == 'directory': target.unlink(); target.mkdir()
    elif defect == 'dropin': row['DropInPaths'] = '/etc/systemd/system/service.d/override.conf'
    elif defect == 'reload': row['NeedDaemonReload'] = 'yes'
    elif defect == 'wrong_fragment': row['FragmentPath'] = '/usr/lib/systemd/system/serein-outpost.service'
    elif defect == 'missing_field': del row['ActiveState']
    elif defect == 'unit_file_mismatch': row.update(LoadState='not-found', FragmentPath='', UnitFileState='')
    calls = 0
    def read(name):
        nonlocal calls
        calls += 1
        if calls == len(generation.IMAGE_UNITS):
            if defect == 'changed_file': target.write_bytes(b'changed fixture')
            elif defect == 'changed_unit': row['ActiveState'] = 'active'
        return units[name]
    with pytest.raises(TransactionError): generation.bootstrap_prestate(tmp_path, read)
    if defect == 'private': assert target.stat().st_mode & 0o777 == 0o600
    if defect == 'symlink': assert target.is_symlink()


def test_native_unit_reader_uses_only_bounded_systemctl_show(monkeypatch, tmp_path):
    units = bootstrap_fixture(tmp_path)
    name = generation.IMAGE_UNITS[0]
    calls = []
    def read(command, **options):
        calls.append(command)
        assert options == dict(capture_output=True, text=True, timeout=15, check=True)
        return subprocess.CompletedProcess(command, 0, '\n'.join(key+'='+value for key,value in units[name].items()))
    monkeypatch.setattr(subprocess, 'run', read)
    assert generation.read_bootstrap_unit(name) == units[name]
    assert calls == [['/usr/bin/systemctl', 'show', '--all', '--no-pager',
                      '--property=' + ','.join(generation.UNIT_PROPERTIES), name]]
    with pytest.raises(TransactionError): generation.read_bootstrap_unit('serein-kernel.service')
    assert len(calls) == 1


def test_predecessor_capture_retains_exact_bytes_and_absence_without_effect(tmp_path):
    units = bootstrap_fixture(tmp_path)
    name = 'serein-outpost.service'
    (tmp_path/'etc/systemd/system'/name).unlink()
    units[name].update(LoadState='not-found', FragmentPath='', UnitFileState='')
    before = generation.bootstrap_prestate(tmp_path, units.__getitem__)
    captured = generation.capture_bootstrap_predecessor(tmp_path, before, units.__getitem__)
    for row in before['files']:
        data = captured[row['target']]
        if row['state'] == 'ABSENT': assert data is None
        else: assert sha(data) == row['sha256'] and len(data) == row['bytes']
    assert generation.bootstrap_prestate(tmp_path, units.__getitem__) == before


@pytest.mark.parametrize('when', ['before', 'during', 'unit'])
def test_predecessor_capture_rejects_drift_without_restoring(tmp_path, monkeypatch, when):
    units = bootstrap_fixture(tmp_path)
    before = generation.bootstrap_prestate(tmp_path, units.__getitem__)
    target = tmp_path / 'etc/systemd/system/serein-outpost.service'
    if when == 'before': target.write_bytes(b'changed')
    elif when == 'unit': units['serein-outpost.service']['ActiveState'] = 'active'
    else:
        original = generation._bootstrap_file_state
        def changed(*args, **kwargs):
            if kwargs.get('capture'): target.write_bytes(b'changed')
            return original(*args, **kwargs)
        monkeypatch.setattr(generation, '_bootstrap_file_state', changed)
    with pytest.raises(TransactionError, match='PUBLIC_BOOTSTRAP_PRESTATE_CHANGED'):
        generation.capture_bootstrap_predecessor(tmp_path, before, units.__getitem__)
    if when != 'unit': assert target.read_bytes() == b'changed'


@pytest.mark.parametrize('stdout', ['', 'Id=one\nId=two', 'not a property'])
def test_native_unit_reader_does_not_default_missing_evidence(monkeypatch, stdout):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a[0], 0, stdout))
    with pytest.raises(TransactionError): generation.read_bootstrap_unit(generation.IMAGE_UNITS[0])


def archive(extra=(), modify=None):
    payload = b"inactive source fixture"
    release = {"schema":"SereinOutpostSourceRelease/v2", "classification":"PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED",
               "payload":[{"path":"payload.py", "bytes":len(payload), "sha256":sha(payload)}], "source_only_files":[]}
    if modify: modify(release)
    release["self_digest"] = "sha256:" + sha(canonical(release))
    rows = [("repo/sfos/outpost/payload.py", payload, tarfile.REGTYPE),
            ("repo/sfos/outpost/release-manifest.json", canonical(release), tarfile.REGTYPE)] + list(extra)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as output:
        for name, data, kind in rows:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}: item.linkname = "/outside"
            output.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    raw = buffer.getvalue()
    return raw, {"archive_sha256":sha(raw), "release_digest":release["self_digest"]}


def bootstrap_material():
    """Synthetic complete G0 image bytes; never install authority."""
    material = {name: ('fixture:' + name).encode() for name in generation.IMAGE_FILES}
    material['payload.py'] = b'inactive source fixture'
    release = {'schema':'SereinOutpostSourceRelease/v2',
               'classification':'PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED',
               'payload':[{'path':name, 'bytes':len(data), 'sha256':sha(data)}
                          for name,data in material.items()], 'source_only_files':[]}
    release['self_digest'] = 'sha256:' + sha(canonical(release))
    material['release-manifest.json'] = canonical(release)
    return release, material


def test_generated_public_source_is_exact_plan_bound_and_inventory_covered():
    release,material=bootstrap_material()
    source={'schema':'SereinOutpostPublicSource/v1','repository':'Kaotikking/sfos-public',
            'commit':'a'*40,'tree':'b'*40,'archive_sha256':'c'*64,
            'release_digest':release['self_digest'],'source_plan_sha256':'d'*64}
    material['public-source.json']=canonical(source)
    assert generation.bind_generation_material(release,material,release['self_digest'])==material
    selector=generation.prepared_generation_selector(release,material,'d'*64)
    assert selector['inventory_digest']==sha(canonical(generation.generation_inventory(material)))
    assert any(row['path']=='public-source.json' for row in generation.generation_inventory(material))
    with pytest.raises(TransactionError,match='SOURCE_PLAN_BINDING'):
        generation.prepared_generation_selector(release,material,'e'*64)
    source['private_key']='forbidden'
    material['public-source.json']=canonical(source)
    with pytest.raises(TransactionError,match='PUBLIC_SOURCE_DENIED'):
        generation.bind_generation_material(release,material,release['self_digest'])


@pytest.mark.parametrize('defect', [None, 'payload', 'inventory', 'source', 'hardlink', 'late_inventory_swap'])
def test_capture_retained_material_reads_real_inventory_list(tmp_path, defect, monkeypatch):
    release, material = bootstrap_material()
    source = {'schema':'SereinOutpostPublicSource/v1','repository':'Kaotikking/sfos-public',
              'commit':'a'*40,'tree':'b'*40,'archive_sha256':'c'*64,
              'release_digest':release['self_digest'],'source_plan_sha256':'d'*64}
    material['public-source.json'] = canonical(source)
    selector = generation.prepared_generation_selector(release, material, 'd'*64)
    directory = tmp_path/'usr/share/serein/outpost-generations'/selector['generation']
    directory.mkdir(parents=True); directory.chmod(0o755)
    inventory = generation.generation_inventory(material)
    for row in inventory:
        path = directory/row['path']
        if row['kind'] == 'directory':
            path.mkdir(parents=True, exist_ok=True); path.chmod(int(row['mode'],8))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(material[row['path']]); path.chmod(int(row['mode'],8))
    index = directory/'generation-inventory.json'
    index.write_bytes(canonical(inventory)+b'\n'); index.chmod(0o644)
    candidate = tmp_path/'var/lib/serein/rollback/outpost-public-generation-20260930T080850Z-b43cfde96e65/candidate.json'
    candidate.parent.mkdir(parents=True);candidate.parent.chmod(0o700)
    candidate.write_bytes(canonical(selector)+b'\n');candidate.chmod(0o600)
    destination = {'target':'/'+directory.relative_to(tmp_path).as_posix(),
        'retained':{'selector':selector,'candidate_path':'/'+candidate.relative_to(tmp_path).as_posix()},
        'source':dict(source)}
    if defect == 'payload': (directory/'payload.py').write_bytes(b'changed')
    elif defect == 'inventory': index.write_bytes(b'{}')
    elif defect == 'source': destination['source']['commit'] = 'e'*40
    elif defect == 'hardlink': os.link(directory/'payload.py', tmp_path/'foreign-link')
    elif defect == 'late_inventory_swap':
        from install import generation_launcher
        original = generation_launcher._read_regular
        calls = []
        def swapped(path, mode=None):
            assert '..' not in path.parts, 'External target must never be opened'
            data, info = original(path, mode)
            if path == index:
                calls.append(1)
                if len(calls) == 2:
                    data = canonical([{'kind':'file','path':'../../external',
                        'mode':'0644','bytes':0,'sha256':sha(b''),'uid':0,'gid':0}])
            return data, info
        monkeypatch.setattr(generation_launcher, '_read_regular', swapped)
    before = {p.relative_to(directory).as_posix():p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    if defect:
        with pytest.raises(TransactionError): generation.capture_retained_material(tmp_path, destination)
    else:
        assert generation.capture_retained_material(tmp_path, destination) == (release, material)
    assert before == {p.relative_to(directory).as_posix():p.read_bytes() for p in directory.rglob('*') if p.is_file()}


def complete_preparation_fixture(root):
    successor_fixture(root)
    units = bootstrap_fixture(root)
    return {'installed_prestate':generation.successor_generation_prestate(root),
            'bootstrap_prestate':generation.bootstrap_prestate(root, units.__getitem__)}


def test_prepared_image_binds_each_source_to_exact_predecessor_and_poststate(tmp_path):
    release,material = bootstrap_material()
    before = complete_preparation_fixture(tmp_path)
    image = generation.prepared_bootstrap_image(release, material, before)
    assert [row['target'] for row in image] == [item[0] for item in generation.IMAGE_FILES.values()]
    for row, pre in zip(image, before['bootstrap_prestate']['files']):
        assert row['pre'] == pre and row['pre'] is not pre
        assert row['post']['sha256'] == sha(material[row['source']])
        assert row['post']['mode'] == generation.IMAGE_FILES[row['source']][1]
    assert generation.successor_generation_prestate(tmp_path) == before['installed_prestate']


@pytest.mark.parametrize('defect', ['missing_prestate','missing_selectors','missing_image',
                                    'duplicate_target','missing_unit','bad_pre_hash','bad_unit',
                                    'mismatched_unit'])
def test_prepared_image_denies_incomplete_or_contradictory_binding(tmp_path, defect):
    release, material = bootstrap_material()
    before = complete_preparation_fixture(tmp_path)
    if defect == 'missing_prestate': before = None
    elif defect == 'missing_selectors': before['installed_prestate']['selectors'].pop('current')
    elif defect == 'missing_image':
        name = next(iter(generation.IMAGE_FILES)); material.pop(name)
        release['payload'] = [row for row in release['payload'] if row['path'] != name]
        release.pop('self_digest'); release['self_digest'] = 'sha256:' + sha(canonical(release))
        material['release-manifest.json'] = canonical(release)
    elif defect == 'duplicate_target': before['bootstrap_prestate']['files'][1] = before['bootstrap_prestate']['files'][0]
    elif defect == 'missing_unit': before['bootstrap_prestate']['units'].pop(generation.IMAGE_UNITS[0])
    elif defect == 'bad_pre_hash': before['bootstrap_prestate']['files'][0]['sha256'] = 'bad'
    elif defect == 'bad_unit': before['bootstrap_prestate']['units'][generation.IMAGE_UNITS[0]]['NeedDaemonReload'] = 'yes'
    elif defect == 'mismatched_unit':
        row = before['bootstrap_prestate']['files'][1]
        before['bootstrap_prestate']['files'][1] = {'target':row['target'], 'state':'ABSENT'}
    with pytest.raises(TransactionError): generation.prepared_bootstrap_image(release, material, before)


def test_prepared_selector_uses_existing_consumer_digest_without_authority(tmp_path):
    from install.generation_launcher import _digest
    raw,identity=archive();plan=verified(identity)
    release,material=_fixture_archive_material(raw,plan)
    selector=generation.prepared_generation_selector(release,material,sha(plan.encoded))
    assert selector['selector_digest']==_digest(selector)
    assert selector['release_digest']==identity['release_digest']
    assert selector['predecessor_receipt_sha256']==sha(plan.encoded)
    assert selector['inventory_digest']==sha(canonical(generation.generation_inventory(material)))
    assert list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('binding',[None,'',{},'f'*63,'sha256:'+'f'*64])
def test_prepared_selector_requires_exact_source_plan_binding(binding):
    raw,identity=archive();release,material=_fixture_archive_material(raw,verified(identity))
    with pytest.raises(TransactionError,match='SOURCE_PLAN_BINDING_DENIED'):
        generation.prepared_generation_selector(release,material,binding)


def test_verified_archive_returns_only_inactive_payload_bytes(tmp_path):
    raw, plan = archive()
    release, material = _fixture_archive_material(raw, verified(plan))
    assert set(material) == {"payload.py", "release-manifest.json"}
    assert json.loads(material["release-manifest.json"]) == release
    assert list(tmp_path.iterdir()) == []
    assert not hasattr(generation, "install_public_generation")


@pytest.mark.parametrize("names,code", [
    (["outpost", "outpost/service.py"], "PATH_CONFLICT"),
    (["outpost/service.py", "outpost"], "PATH_CONFLICT"),
    (["generation-inventory.json"], "INVENTORY_COLLISION"),
    (["generation-inventory.json/child"], "INVENTORY_COLLISION"),
    (["release-manifest.json/child"], "PATH_CONFLICT"),
])
def test_signed_archive_cannot_supply_unbuildable_generation(names, code):
    additions = [("repo/sfos/outpost/" + name, b"inert", tarfile.REGTYPE) for name in names]
    def extend(release):
        release["payload"].extend({"path":name, "bytes":5, "sha256":sha(b"inert")} for name in names)
    raw, identity = archive(additions, extend)
    with pytest.raises(TransactionError, match=code):
        _fixture_archive_material(raw, verified(identity))


def test_generation_inventory_is_exhaustive_sorted_and_inactive(tmp_path):
    material = {"outpost/nested/b.py":b"b", "release-manifest.json":b"{}", "outpost/a.py":b"a"}
    expected = [
        {"kind":"directory", "path":"outpost", "mode":"0755", "uid":0, "gid":0},
        {"kind":"directory", "path":"outpost/nested", "mode":"0755", "uid":0, "gid":0},
    ] + [{"kind":"file", "path":name, "bytes":len(data), "sha256":sha(data),
          "mode":"0644", "uid":0, "gid":0} for name, data in sorted(material.items())]
    before = dict(material)
    inventory = generation.generation_inventory(material)
    assert inventory == expected
    assert canonical(inventory) == canonical(generation.generation_inventory(dict(reversed(list(material.items())))))
    assert sha(canonical(inventory) + b"\n") == sha(canonical(expected) + b"\n")
    assert material == before and not list(tmp_path.iterdir())


def test_native_generation_staging_writes_exact_inactive_bytes_and_inventory(tmp_path):
    from install.transaction import stage_inactive_generation
    parent = tmp_path / "staging"
    parent.mkdir(mode=0o700)
    material = {"outpost/service.py":b"inert bytes, never executed", "release-manifest.json":b"{}"}
    result = stage_inactive_generation(parent, "a" * 64, material)
    root = parent / ("a" * 64)
    expected = canonical(generation.generation_inventory(material)) + b"\n"
    assert result["result"] == "STAGED_INACTIVE_BYTES_ONLY"
    assert result["installed"] == "UNPROVEN" and result["activation"] == "NONE"
    assert result["inventory_sha256"] == sha(expected)
    assert (root / "generation-inventory.json").read_bytes() == expected
    for name, data in material.items():
        assert (root / name).read_bytes() == data
        assert (root / name).stat().st_mode & 0o777 == 0o644
    assert root.stat().st_mode & 0o777 == 0o755
    assert parent.stat().st_mode & 0o777 == 0o700
    assert len(list(parent.iterdir())) == 1


def test_generation_staging_ignores_ambient_umask_without_changing_parent_or_caller(tmp_path):
    code = '''import os,sys
from install.transaction import stage_inactive_generation
os.umask(0o077)
stage_inactive_generation(sys.argv[1], "a"*64, {"outpost/service.py":b"inert"})
assert os.umask(0o077)==0o077
'''
    before = tmp_path.stat()
    result = subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    root = tmp_path / ("a" * 64)
    assert root.stat().st_mode & 0o777 == 0o755
    assert tmp_path.stat().st_mode & 0o777 == 0o700
    assert (root / "outpost").stat().st_mode & 0o777 == 0o755
    assert (root / "outpost/service.py").stat().st_mode & 0o777 == 0o644
    after = tmp_path.stat()
    assert (before.st_mode,before.st_uid,before.st_gid) == (after.st_mode,after.st_uid,after.st_gid)


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_staging_existing_destination_is_never_resumed_or_overwritten(tmp_path, kind):
    from install.transaction import stage_inactive_generation
    target = tmp_path / ("a" * 64)
    if kind == "directory": target.mkdir()
    elif kind == "file": target.write_bytes(b"preserve")
    else: target.symlink_to(tmp_path / "absent")
    before = target.lstat()
    with pytest.raises(TransactionError, match="STAGING_COLLISION_NEW_INSTALL_REQUIRED"):
        stage_inactive_generation(tmp_path, "a" * 64, {"file":b"inert"})
    assert target.lstat() == before
    assert list(tmp_path.iterdir()) == [target]


def test_staging_failure_retains_attempt_and_does_not_resume(tmp_path, monkeypatch):
    from install import transaction
    calls = []
    def fail(fd):
        calls.append(fd)
        raise OSError("fixture flush failure")
    monkeypatch.setattr(transaction.os, "fsync", fail)
    with pytest.raises(TransactionError, match="STAGING_FAILED_NEW_INSTALL_REQUIRED"):
        transaction.stage_inactive_generation(tmp_path, "a" * 64, {"file":b"inert"})
    assert calls and (tmp_path / ("a" * 64) / "file").read_bytes() == b"inert"
    with pytest.raises(TransactionError, match="STAGING_COLLISION_NEW_INSTALL_REQUIRED"):
        transaction.stage_inactive_generation(tmp_path, "a" * 64, {"file":b"inert"})


@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_staging_requires_private_native_parent_without_changing_permissions(tmp_path, mode):
    from install.transaction import stage_inactive_generation
    tmp_path.chmod(mode)
    with pytest.raises(TransactionError, match="PRIVATE_STAGING_PARENT_REQUIRED"):
        stage_inactive_generation(tmp_path, "a" * 64, {"file":b"inert"})
    assert tmp_path.stat().st_mode & 0o777 == mode and not list(tmp_path.iterdir())


@pytest.mark.parametrize("name,kind", [
    ("repo/../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
    ("other/file", tarfile.REGTYPE), ("repo/sfos/outpost/payload.py", tarfile.REGTYPE),
    ("repo/link", tarfile.SYMTYPE), ("repo/link", tarfile.LNKTYPE), ("repo/fifo", tarfile.FIFOTYPE),
    ("repo/a\\b", tarfile.REGTYPE), ("repo/C:escape", tarfile.REGTYPE),
])
def test_hostile_archive_denied_in_memory(name, kind):
    raw, plan = archive([(name, b"unexpected", kind)])
    with pytest.raises(TransactionError): _fixture_archive_material(raw, verified(plan))


@pytest.mark.parametrize("change", ["archive_hash", "release_digest", "payload_hash", "extra", "duplicate"])
def test_exact_source_denominator_is_required(change):
    modify = (lambda release: release["payload"][0].update(sha256="0"*64)) if change == "payload_hash" else None
    if change == "duplicate": modify = lambda release: release["source_only_files"].extend(release["payload"])
    extra = [("repo/sfos/outpost/undeclared", b"x", tarfile.REGTYPE)] if change == "extra" else []
    raw, plan = archive(extra, modify)
    if change == "archive_hash": plan["archive_sha256"] = "0"*64
    if change == "release_digest": plan["release_digest"] = "sha256:"+"0"*64
    with pytest.raises(TransactionError): _fixture_archive_material(raw, verified(plan))


def test_compressed_archive_cannot_exceed_expanded_budget(monkeypatch):
    raw, plan = archive([("repo/large", b"0"*10000, tarfile.REGTYPE)])
    assert len(raw) < 4096
    monkeypatch.setattr(generation, "MAX_ARCHIVE_BYTES", 4096)
    with pytest.raises(TransactionError, match="EXPANSION_DENIED"):
        _fixture_archive_material(raw, verified(plan))


@pytest.mark.parametrize("raw_plan", [None, [], {}, {"archive_sha256":"0"*64}])
def test_unverified_plan_cannot_release_archive_material(raw_plan):
    with pytest.raises(TransactionError, match="VERIFIED_PLAN_REQUIRED"):
        _safe_archive(b"archive", raw_plan)


@pytest.mark.parametrize("field,replacement", [("repository","other/repo"), ("ref","refs/heads/other"),
    ("commit","c"*40), ("tree","c"*40), ("authority_key_id","other"), ("current_boot_id","unknown"),
    ("signature","invalid!"), ("release_digest","sha256:"+"d"*64), ("archive_sha256","d"*64)])
def test_changed_signed_fields_never_verify(field, replacement):
    _, identity = archive()
    plan, public = signed_plan_fields(identity)
    plan[field] = replacement
    with pytest.raises(TransactionError): generation._verify_plan_bytes(plan, public, sha(public))


def test_plan_cannot_choose_its_own_unpinned_authority():
    _, identity = archive()
    plan, public = signed_plan_fields(identity)
    with pytest.raises(TransactionError, match="AUTHORITY_IDENTITY_DENIED"):
        generation._verify_plan_bytes(plan, public, "0"*64)


def test_verified_plan_copy_cannot_change_original_or_claim_native_custody():
    _, identity = archive()
    value = verified(identity)
    changed = value.as_dict()
    changed["commit"] = "0"*40
    assert value.as_dict()["commit"] == "a"*40
    assert value.authority_custody_proven is False
    with pytest.raises(TransactionError): generation.VerifiedSourcePlan(b"{}", "0"*64)


def test_fixture_signature_cannot_claim_custody_or_enter_production_archive():
    raw, identity = archive()
    plan, public = signed_plan_fields(identity)
    with pytest.raises(TypeError):
        generation._verify_plan_bytes(plan, public, sha(public), _custody=True)
    with pytest.raises(TransactionError, match="VERIFIED_PLAN_REQUIRED"):
        _safe_archive(raw, verified(identity))


def test_production_verifier_has_no_caller_selected_anchor(monkeypatch):
    assert generation.CANONICAL_AUTHORITY_SHA256 == "1f7533bbd5e2645f52a0d7e17502166f079a76c8c1fd31c8feaa0fc057a48652"
    monkeypatch.setattr(generation, "CANONICAL_AUTHORITY_SHA256", None)
    monkeypatch.setattr(generation.os, "open", lambda *a, **k: pytest.fail("missing pin accessed filesystem"))
    with pytest.raises(TransactionError, match="CANONICAL_AUTHORITY_UNKNOWN"):
        generation._verify_plan({})
    with pytest.raises(TypeError):
        generation._verify_plan({}, authority_path="/arbitrary", expected_authority_sha256="0"*64)


def test_production_verifier_rejects_changed_identity_before_key_access(monkeypatch):
    _, identity = archive()
    plan, _ = signed_plan_fields(identity)
    monkeypatch.setattr(generation.os, "open", lambda *a, **k: pytest.fail("wrong identity accessed filesystem"))
    with pytest.raises(TransactionError, match="PUBLIC_AUTHORITY_IDENTITY_DENIED"):
        generation._verify_plan(plan)


def target_fixture(root):
    _,identity=archive()
    plan,public=signed_plan_fields(identity,target_root=root)
    (root/'etc/os-release').write_text('ID=debian\nVERSION_ID="13"\n')
    (root/'etc/hostname').write_text('outpost-fixture\n')
    (root/'etc/machine-id').write_text('1234567890abcdef1234567890abcdef\n')
    return generation._verify_plan_bytes(plan,public,sha(public))


def snapshot(root):
    return {p.relative_to(root).as_posix():(p.read_bytes(),p.stat().st_mode,p.stat().st_uid,p.stat().st_gid)
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


def test_target_preflight_compares_real_native_fixture_files_without_effect(tmp_path,monkeypatch):
    plan=target_fixture(tmp_path);before=snapshot(tmp_path)
    monkeypatch.setattr(generation,'_safe_archive',lambda *a:pytest.fail('No source acquisition'))
    result=generation._fixture_target_prestate(tmp_path,plan)
    assert result['result']=='FIXTURE_TARGET_PRESTATE_ONLY'
    assert result['immutable_rows']==plan.as_dict()['immutable_rows']
    assert result['installed']=='UNPROVEN' and result['authority_effect']==result['mutation_effect']=='NONE'
    assert snapshot(tmp_path)==before
    assert 'synthetic fixture only' not in json.dumps(result)


def test_target_preflight_binds_existing_host_identity_without_admission(tmp_path):
    plan=target_fixture(tmp_path)
    result=generation._fixture_target_prestate(tmp_path,plan)
    assert result['host_identity']['os_id']=='debian'
    assert result['host_identity']['os_version_id']=='13'
    assert result['host_identity']['machine_id']=='1234567890abcdef1234567890abcdef'
    assert result['host_identity']['boot_id']==result['current_boot_id']
    assert result['installed']=='UNPROVEN' and result['authority_effect']=='NONE'


@pytest.mark.parametrize('path,value', [
    ('etc/os-release','ID=ubuntu\nVERSION_ID="13"\n'),
    ('etc/os-release','ID=debian\nVERSION_ID="12"\n'),
    ('etc/machine-id','0'*32+'\n'),
    ('etc/machine-id',None),
    ('etc/hostname','\n'),
])
def test_target_preflight_rejects_invalid_bootstrap_host_without_repair(tmp_path,path,value):
    plan=target_fixture(tmp_path)
    target=tmp_path/path
    if value is None:target.unlink()
    else:target.write_text(value)
    before=snapshot(tmp_path)
    with pytest.raises(TransactionError,match='PUBLIC_HOST_IDENTITY_DENIED'):
        generation._fixture_target_prestate(tmp_path,plan)
    assert snapshot(tmp_path)==before


@pytest.mark.parametrize('defect',['boot','missing','content','size','mode','uid','gid','hardlink','symlink','parent_symlink'])
def test_target_preflight_denies_drift_without_repair(tmp_path,defect):
    root=tmp_path/'target';root.mkdir();plan=target_fixture(root)
    path=root/'etc/serein-outpost/readonly.token'
    if defect=='boot':(root/'proc/sys/kernel/random/boot_id').write_text('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n')
    elif defect=='missing':path.unlink()
    elif defect=='content':path.write_bytes(b'X'*path.stat().st_size)
    elif defect=='size':path.write_bytes(path.read_bytes()+b'x')
    elif defect=='mode':path.chmod(0o644)
    elif defect=='uid':os.chown(path,12345,0)
    elif defect=='gid':os.chown(path,0,12345)
    elif defect=='hardlink':os.link(path,tmp_path/'another')
    elif defect=='symlink':
        path.rename(tmp_path/'outside');path.symlink_to(tmp_path/'outside')
    else:
        path.parent.rename(tmp_path/'outside');path.parent.symlink_to(tmp_path/'outside',target_is_directory=True)
    before=snapshot(root)
    with pytest.raises(TransactionError,match='PUBLIC_'):
        generation._fixture_target_prestate(root,plan)
    assert snapshot(root)==before


def test_fixture_authority_cannot_inspect_real_target(monkeypatch,tmp_path):
    plan=target_fixture(tmp_path)
    monkeypatch.setattr(generation.os,'open',lambda *a,**k:pytest.fail('No production target read'))
    with pytest.raises(TransactionError,match='PUBLIC_VERIFIED_PLAN_REQUIRED'):
        generation.preflight_target(plan)
    with pytest.raises(TransactionError,match='FIXTURE_ROOT_REQUIRED'):
        generation._fixture_target_prestate(Path('/'),plan)


def test_target_replacement_during_descriptor_read_is_denied(tmp_path,monkeypatch):
    plan=target_fixture(tmp_path)
    path=tmp_path/'etc/serein-outpost/readonly.token';original=path.read_bytes()
    original_stat=os.stat;swapped=False
    def swap(name,*args,**kwargs):
        nonlocal swapped
        if name=='readonly.token' and kwargs.get('dir_fd') is not None and not swapped:
            swapped=True;path.rename(path.with_name('preserved-original'))
            path.write_bytes(original);path.chmod(0o640)
        return original_stat(name,*args,**kwargs)
    monkeypatch.setattr(generation.os,'stat',swap)
    with pytest.raises(TransactionError,match='PUBLIC_TARGET_CHANGED_DURING_READ'):
        generation._fixture_target_prestate(tmp_path,plan)
    assert path.read_bytes()==original and path.with_name('preserved-original').read_bytes()==original
