"""Network is stubbed; these tests do not download or install Outpost."""
import socket
import os
import stat
import pytest
from install import public_installer_cli as cli

URL = "https://codeload.github.com/Kaotikking/sfos-public/tar.gz/" + "a" * 40


@pytest.mark.parametrize("target,kind", [
    ("/", "PINNED_PUBLIC_REPOSITORY"),
    ("/", "OFFLINE_USB_MEDIA"),
    ("/target", "OFFLINE_USB_MEDIA"),
])
def test_shared_entry_preserves_exact_wrapper_tuple_without_io(monkeypatch, target, kind):
    from dataclasses import FrozenInstanceError, astuple
    def forbidden(*args, **kwargs):
        pytest.fail("Request syntax must not read files, fetch or change target")
    monkeypatch.setattr(cli.os, "open", forbidden)
    monkeypatch.setattr(cli, "fetch_exact", forbidden)
    args = ("relative source/sfos/outpost", "install", target,
            "relative plan", "a"*64, kind, "relative receipt")
    request = cli.parse_install_request(args)
    assert astuple(request) == args
    with pytest.raises(FrozenInstanceError):
        request.target = "/changed"
    assert not hasattr(request, "authority_custody_proven")


@pytest.mark.parametrize("arguments", [None, "abcdefg", [], ["x"]*6, ["x"]*8])
def test_shared_entry_rejects_wrong_arity(arguments):
    with pytest.raises(cli.TransactionError, match="ENTRY_ARGUMENTS_REQUIRED"):
        cli.parse_install_request(arguments)


@pytest.mark.parametrize("index,value,code", [
    (0, "", "ARGUMENT_INVALID"), (3, None, "ARGUMENT_INVALID"),
    (6, "receipt\0other", "ARGUMENT_INVALID"),
    (1, "repair", "ACTION_DENIED"), (1, "rollback", "ACTION_DENIED"),
    (1, "resume", "ACTION_DENIED"), (2, "/target/", "TARGET_DENIED"),
    (2, "/target/..", "TARGET_DENIED"), (2, "/tmp", "TARGET_DENIED"),
    (4, "A"*64, "PLAN_BYTES_REQUIRED"), (4, "a"*63, "PLAN_BYTES_REQUIRED"),
    (5, "OTHER", "SOURCE_KIND_DENIED"),
])
def test_shared_entry_rejects_incompatible_request_before_effect(index, value, code):
    args = ["source", "install", "/", "plan", "a"*64,
            "PINNED_PUBLIC_REPOSITORY", "receipt"]
    args[index] = value
    with pytest.raises(cli.TransactionError, match=code):
        cli.parse_install_request(args)


def test_fresh_entry_does_not_accept_online_source_substitution():
    with pytest.raises(cli.TransactionError, match="OFFLINE_INSTALLER_SOURCE_REQUIRED"):
        cli.parse_install_request(["source", "install", "/target", "plan", "a"*64,
                                   "PINNED_PUBLIC_REPOSITORY", "receipt"])


@pytest.fixture
def entry_source(tmp_path, monkeypatch):
    """Real file/source verifiers; synthetic signer/target and provider reply."""
    from install import public_generation_transaction as generation
    from tests.test_public_generation_transaction import bootstrap_material, complete_preparation_fixture, signed_plan_fields
    release, material = bootstrap_material()
    identity = {'archive_sha256':'a'*64, 'release_digest':release['self_digest']}
    root = tmp_path / "tree"
    source = root / "sfos/outpost"
    source.mkdir(parents=True)
    for name, data in material.items():
        path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
    target = tmp_path / 'fixture-target'; target.mkdir()
    target_prestate = complete_preparation_fixture(target)
    plan, key = signed_plan_fields(identity)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(generation.canonical(plan))
    plan_path.chmod(0o600)
    road = cli._source_road_module()
    receipt = {"schema":"SFOSSourceRoadReceipt/v1", "source_kind":"PINNED_PUBLIC_REPOSITORY",
               "repository":road.PUBLIC_REPOSITORY, "commit":plan["commit"], "tree":plan["tree"],
               "outpost_release_digest":release["self_digest"]}
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(generation.canonical(receipt))
    expected = road.payload_blobs(root)
    monkeypatch.setattr(road, "github_tree", lambda commit: receipt["tree"])
    monkeypatch.setattr(road, "github_payload", lambda tree: expected)
    monkeypatch.setattr(cli, "_source_road_module", lambda: road)
    events = []
    def verify(value):
        events.append("plan")
        return generation._verify_plan_bytes(value, key, cli.sha(key))
    def prestate(value):
        events.append("target")
        return target_prestate
    monkeypatch.setattr(generation, "_verify_plan", verify)
    monkeypatch.setattr(generation, "preflight_target", prestate)
    monkeypatch.setattr(cli, "fetch_exact", lambda *_: pytest.fail("No archive fetch in entry preflight"))
    args = [str(source), "install", "/", str(plan_path), cli.sha(plan_path.read_bytes()),
            "PINNED_PUBLIC_REPOSITORY", str(receipt_path)]
    return args, receipt, receipt_path, road, events


def test_entry_binds_real_source_receipt_and_plan_before_target(entry_source):
    args, receipt, _, _, events = entry_source
    request, plan, evidence = cli.preflight_install_request(args)
    assert request.source == args[0] and plan.as_dict()["commit"] == receipt["commit"]
    assert events == ["plan", "target"]
    assert evidence["source_receipt"] == receipt
    assert evidence["result"] == "ENTRY_PREFLIGHT_ONLY_NOT_INSTALLED"
    assert evidence["mutation_effect"] == "NONE" and evidence["installed"] == "UNPROVEN"


@pytest.mark.parametrize("field", ["commit", "tree"])
def test_entry_cannot_mix_valid_provider_source_with_another_signed_plan(entry_source, field):
    args, receipt, path, _, events = entry_source
    receipt[field] = "e"*40
    path.write_bytes(cli.json.dumps(receipt).encode())
    with pytest.raises(cli.TransactionError, match="SOURCE_PLAN_MISMATCH"):
        cli.preflight_install_request(args)
    assert events == ["plan"]


def test_entry_does_not_resolve_away_receipt_symlink(entry_source, tmp_path):
    args, _, path, _, events = entry_source
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    args[6] = str(alias)
    with pytest.raises(SystemExit, match="PAYLOAD_UNSAFE_ENTRY"):
        cli.preflight_install_request(args)
    assert events == []


def test_entry_source_failure_prevents_plan_and_target_reads(entry_source):
    from pathlib import Path
    args, _, _, _, events = entry_source
    (Path(args[0]) / "payload.py").write_bytes(b"changed")
    with pytest.raises(SystemExit, match="PAYLOAD_HASH_DENIED"):
        cli.preflight_install_request(args)
    assert events == []


def test_entry_rejects_identical_package_outside_canonical_tree_path(entry_source):
    from pathlib import Path
    import shutil
    args, _, _, _, events = entry_source
    source = Path(args[0])
    sibling = source.parent.parent / "other/outpost"
    shutil.copytree(source, sibling)
    args[0] = str(sibling)
    with pytest.raises(cli.TransactionError, match="CANONICAL_SOURCE_PATH_REQUIRED"):
        cli.preflight_install_request(args)
    assert events == []


def test_entry_does_not_substitute_live_root_for_offline_target(entry_source, monkeypatch):
    args, _, _, road, events = entry_source
    args[2], args[5] = "/target", "OFFLINE_USB_MEDIA"
    def deny(*_): raise SystemExit("SOURCE_ROAD_DENIED:OFFLINE_SOURCE_AUTHORITY_UNPROVEN")
    monkeypatch.setattr(road, "verify", deny)
    with pytest.raises(SystemExit, match="OFFLINE_SOURCE_AUTHORITY_UNPROVEN"):
        cli.preflight_install_request(args)
    assert events == []


def test_entry_acquisition_reuses_one_verified_plan_and_rechecks_target(entry_source, monkeypatch):
    args, _, _, _, events = entry_source
    seen = []
    def fetch(plan):
        events.append("fetch")
        seen.append(plan)
        return {"fixture":"release"}, {"fixture.py":b"inactive"}
    monkeypatch.setattr(cli, "fetch_verified_source", fetch)
    evidence, release, material = cli.prepare_install_request(args)
    assert events == ["plan", "target", "fetch", "target"]
    assert len(seen) == 1 and evidence["source"]["commit"] == seen[0].as_dict()["commit"]
    assert evidence["plan_sha256"] == args[4]
    assert evidence["entry"]["source_receipt"]["commit"] == evidence["source"]["commit"]
    assert evidence["installed"] == "UNPROVEN" and evidence["mutation_effect"] == "NONE"
    assert release == {"fixture":"release"} and material == {"fixture.py":b"inactive"}


def test_entry_acquisition_cannot_return_source_after_target_drift(entry_source, monkeypatch):
    from install import public_generation_transaction as generation
    args, _, _, _, events = entry_source
    observations = 0
    def prestate(plan):
        nonlocal observations
        observations += 1
        events.append("target")
        return {"fixture":"before" if observations == 1 else "changed"}
    monkeypatch.setattr(generation, "preflight_target", prestate)
    def fetch(plan):
        events.append("fetch")
        return {}, {}
    monkeypatch.setattr(cli, "fetch_verified_source", fetch)
    with pytest.raises(cli.TransactionError, match="TARGET_CHANGED_DURING_ACQUISITION"):
        cli.prepare_install_request(args)
    assert events == ["plan", "target", "fetch", "target"]


def test_complete_entry_request_reaches_exact_inactive_staging(entry_source, tmp_path, monkeypatch):
    from pathlib import Path
    args, _, _, _, events = entry_source
    source = Path(args[0])
    release = cli.json.loads((source/"release-manifest.json").read_text())
    material = {path.relative_to(source).as_posix():path.read_bytes() for path in source.rglob('*') if path.is_file()}
    def fetch(plan):
        events.append("fetch")
        assert plan.as_dict()["release_digest"] == release["self_digest"]
        return release, material
    monkeypatch.setattr(cli, "fetch_verified_source", fetch)
    parent = tmp_path/"staging"
    parent.mkdir(mode=0o700)
    result = cli.prepare_and_stage_install_request(args, staging_parent=parent)
    assert events == ["plan", "target", "fetch", "target", "plan", "target"]
    generation_id = release["self_digest"].removeprefix("sha256:")
    for name, data in material.items():
        assert (parent/generation_id/name).read_bytes() == data
    assert result["activation"] == "NONE" and result["installed"] == "UNPROVEN"
    assert result["preparation"]["entry"]["source_receipt"]["outpost_release_digest"] == release["self_digest"]


class Response:
    def __init__(self, data=b"archive", url=URL, length="7", status=200):
        self.data, self.url, self.status = data, url, status
        self.headers = {} if length is None else {"Content-Length": length}
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def geturl(self): return self.url
    def read(self, size): return self.data[:size]


def opener(monkeypatch, response):
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == URL and timeout == 30
            if isinstance(response, Exception): raise response
            return response
    monkeypatch.setattr(cli.urllib.request, "build_opener", lambda *_: Opener())


@pytest.mark.parametrize("length", ["7", None])
def test_exact_public_fetch_with_content_length_or_chunked_body(monkeypatch, length):
    opener(monkeypatch, Response(length=length))
    assert cli.fetch_exact(URL) == (b"archive", URL)


@pytest.mark.parametrize("response,code", [
    (Response(url="https://other.invalid"), "REDIRECT"),
    (Response(status=503), "STATUS"),
    (Response(length="not-a-number"), "CONTENT_LENGTH"),
    (Response(length="9"), "TRUNCATED"),
    (Response(length=str(cli.MAX_ARCHIVE_BYTES + 1)), "SIZE"),
    (Response(data=b"", length="0"), "SIZE"),
])
def test_invalid_fetch_cannot_become_source(monkeypatch, response, code):
    opener(monkeypatch, response)
    with pytest.raises(cli.TransactionError, match=code): cli.fetch_exact(URL)


def test_chunked_oversize_is_bounded(monkeypatch):
    monkeypatch.setattr(cli, "MAX_ARCHIVE_BYTES", 4)
    opener(monkeypatch, Response(data=b"12345", length=None))
    with pytest.raises(cli.TransactionError, match="SIZE"): cli.fetch_exact(URL)


@pytest.mark.parametrize("url", ["http://codeload.github.com/x", URL+"?secret=x", URL.replace("a"*40, "main"), "https://example.com/archive"])
def test_unapproved_url_rejected_before_network(monkeypatch, url):
    def forbidden(*_): raise AssertionError("network attempted")
    monkeypatch.setattr(cli.urllib.request, "build_opener", forbidden)
    with pytest.raises(cli.TransactionError, match="URL_DENIED"): cli.fetch_exact(url)


def test_network_error_does_not_echo_sensitive_details(monkeypatch):
    opener(monkeypatch, socket.timeout("private detail"))
    with pytest.raises(cli.TransactionError) as caught: cli.fetch_exact(URL)
    assert "private detail" not in str(caught.value)


def test_redirect_handler_denies_without_following():
    with pytest.raises(cli.TransactionError, match="REDIRECT_DENIED"):
        cli._NoRedirect().redirect_request(None, None, 302, "", {}, URL)


def test_plan_requires_exact_hash_before_path_access(tmp_path):
    with pytest.raises(cli.TransactionError, match="BYTES_REQUIRED"):
        cli._load_plan(tmp_path/"absent", "")


def test_plan_symlink_is_denied_before_bytes(tmp_path):
    target = tmp_path/"plan"
    target.write_text("{}")
    link = tmp_path/"alias"
    link.symlink_to(target)
    with pytest.raises(cli.TransactionError, match="SYMLINK_DENIED"):
        cli._load_plan(link, cli.sha(b"{}"))


def test_no_install_or_activation_entry_is_imported():
    assert not hasattr(cli, "install_public_generation")
    assert not hasattr(cli, "canonical_generation_install")
    assert not hasattr(cli, "RealAdapter")


def test_fixture_signature_cannot_enter_production_fetch(monkeypatch):
    from tests.test_public_generation_transaction import archive, verified
    raw, identity = archive()
    plan = verified(identity)
    calls = []
    def fetch(url):
        calls.append(url)
        return raw, url
    monkeypatch.setattr(cli, "fetch_exact", fetch)
    with pytest.raises(cli.TransactionError, match="VERIFIED_PLAN_REQUIRED"):
        cli.fetch_verified_source(plan)
    assert not calls
    with pytest.raises(cli.TransactionError, match="VERIFIED_PLAN_REQUIRED"):
        cli.fetch_verified_source(identity)
    assert not calls


def test_native_root_private_plan_custody_and_exact_bytes(tmp_path):
    """Native Linux filesystem fixture only; never a canonical signed plan."""
    path = tmp_path / "fixture-plan.json"
    raw = b'{"fixture":"not-installation-authority"}'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    info = path.stat()
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o600)
    assert cli._load_plan(path, cli.sha(raw)) == {"fixture":"not-installation-authority"}
    with pytest.raises(cli.TransactionError, match="PUBLIC_PLAN_BYTES_DENIED"):
        cli._load_plan(path, "0" * 64)
    assert path.read_bytes() == raw


def test_native_readable_or_hardlinked_plan_is_denied(tmp_path):
    path = tmp_path / "fixture-plan.json"
    path.write_bytes(b"{}")
    path.chmod(0o644)
    with pytest.raises(cli.TransactionError, match="PUBLIC_PLAN_CUSTODY_DENIED"):
        cli._load_plan(path, cli.sha(b"{}"))
    path.chmod(0o600)
    os.link(path, tmp_path / "second-name")
    with pytest.raises(cli.TransactionError, match="PUBLIC_PLAN_CUSTODY_DENIED"):
        cli._load_plan(path, cli.sha(b"{}"))


@pytest.fixture
def preparation_wiring(monkeypatch):
    """Wiring fixture, not canonical key custody or production target proof."""
    from install import public_generation_transaction as generation
    from tests.test_public_generation_transaction import archive,verified
    raw,identity=archive();plan=verified(identity)
    events=[];path='fixture-plan.json';digest='d'*64
    def load(p,h):
        assert p==path and h==digest
        events.append('load');return plan.as_dict()
    def verify(value):
        assert value==plan.as_dict()
        events.append('verify');return plan
    def preflight(value):
        assert value is plan
        events.append('target')
        return {'result':'FIXTURE_TARGET_PRESTATE_ONLY','current_boot_id':plan.as_dict()['current_boot_id']}
    def fetch(value):
        assert value is plan
        events.append('fetch')
        return {'fixture':'release'}, {'fixture.py':b'inactive bytes'}
    monkeypatch.setattr(cli,'_load_plan',load)
    monkeypatch.setattr(generation,'_verify_plan',verify)
    monkeypatch.setattr(generation,'preflight_target',preflight)
    monkeypatch.setattr(cli,'fetch_verified_source',fetch)
    return generation,plan,events,path,digest


def test_preparation_preserves_order_binds_identity_and_returns_inactive_bytes_only(preparation_wiring,tmp_path):
    _,plan,events,path,digest=preparation_wiring
    evidence,release,material=cli.prepare_generation(path,digest)
    assert events==['load','verify','target','fetch','target']
    assert evidence['result']=='SOURCE_PREPARED_INACTIVE' and evidence['plan_sha256']==digest
    assert evidence['source_plan_sha256']==cli.sha(plan.encoded)
    assert evidence['source']=={key:plan.as_dict()[key] for key in ('repository','commit','tree','archive_sha256','release_digest')}
    assert evidence['installed']=='UNPROVEN' and evidence['authority_effect']==evidence['mutation_effect']=='NONE'
    assert material=={'fixture.py':b'inactive bytes'} and list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('code',['PUBLIC_BOOT_DRIFT_DENIED','PUBLIC_IMMUTABLE_PRESTATE_DENIED'])
def test_target_rejection_prevents_source_acquisition(preparation_wiring,monkeypatch,code):
    generation,_,events,path,digest=preparation_wiring
    def denied(_):raise cli.TransactionError(code)
    monkeypatch.setattr(generation,'preflight_target',denied)
    with pytest.raises(cli.TransactionError,match=code):cli.prepare_generation(path,digest)
    assert events==['load','verify']


@pytest.mark.parametrize('changed_result',[False,True])
def test_changed_target_during_fetch_cannot_return_prepared_source(preparation_wiring,monkeypatch,changed_result):
    generation,_,events,path,digest=preparation_wiring
    calls=0
    def preflight(_):
        nonlocal calls
        calls+=1
        if calls==2 and not changed_result:raise cli.TransactionError('PUBLIC_IMMUTABLE_PRESTATE_DENIED')
        return {'sequence':calls}
    monkeypatch.setattr(generation,'preflight_target',preflight)
    with pytest.raises(cli.TransactionError,match='PUBLIC_(TARGET_CHANGED_DURING_ACQUISITION|IMMUTABLE_PRESTATE_DENIED)'):
        cli.prepare_generation(path,digest)
    assert events==['load','verify','fetch'] and calls==2


def test_prepared_release_is_staged_under_its_verified_identity_only(tmp_path, monkeypatch):
    """Synthetic preparation seam plus native staging, not live authority."""
    from tests.test_public_generation_transaction import bootstrap_material, complete_preparation_fixture
    target = tmp_path / 'target'; target.mkdir()
    staging = tmp_path / 'staging'; staging.mkdir(mode=0o700)
    release, material = bootstrap_material()
    identity = {'release_digest':release['self_digest']}
    evidence = {"source":identity, "plan_sha256":"d"*64,"source_plan_sha256":"e"*64,
                'target_prestate':complete_preparation_fixture(target)}
    calls = []
    def prepare(path, digest):
        calls.append((path, digest))
        return evidence, release, material
    monkeypatch.setattr(cli, "prepare_generation", prepare)
    rechecks = []
    monkeypatch.setattr(cli, 'recheck_prepared_target', lambda *args: rechecks.append(args))
    result = cli.prepare_and_stage_generation("fixture-plan", "d"*64, staging_parent=staging)
    assert calls == [("fixture-plan", "d"*64)]
    assert rechecks == [('fixture-plan', 'd'*64, evidence)]
    generation_id = identity["release_digest"].removeprefix("sha256:")
    assert [path.name for path in staging.iterdir()] == [generation_id]
    assert result["preparation"] == evidence and result["staging"]["generation"] == generation_id
    assert result["installed"] == "UNPROVEN" and result["activation"] == "NONE"
    assert result['candidate_selector']['generation']==generation_id
    assert result['candidate_selector']['predecessor_receipt_sha256']=='e'*64
    assert result['candidate_selector']['inventory_digest']==result['staging']['inventory_digest']
    assert len(result['bootstrap_image']) == 4
    for row in result['bootstrap_image']:
        assert row['post']['sha256'] == cli.sha(material[row['source']])
    assert not (tmp_path/'current.json').exists() and not (tmp_path/'lkg.json').exists()
    for name, data in material.items():
        assert (staging / generation_id / name).read_bytes() == data


def test_missing_bootstrap_payload_denies_before_staging(tmp_path, monkeypatch):
    from tests.test_public_generation_transaction import archive, verified, complete_preparation_fixture
    from install.public_generation_transaction import _fixture_archive_material
    target = tmp_path / 'target'; target.mkdir()
    staging = tmp_path / 'staging'; staging.mkdir(mode=0o700)
    raw, identity = archive()
    release, material = _fixture_archive_material(raw, verified(identity))
    evidence = {'source':identity, 'source_plan_sha256':'e'*64,
                'target_prestate':complete_preparation_fixture(target)}
    monkeypatch.setattr(cli, 'prepare_generation', lambda *_: (evidence, release, material))
    with pytest.raises(cli.TransactionError, match='PREPARED_BOOTSTRAP_PAYLOAD_MISSING'):
        cli.prepare_and_stage_generation('fixture-plan', 'd'*64, staging_parent=staging)
    assert list(staging.iterdir()) == []


@pytest.mark.parametrize('changed', [False, True])
def test_poststage_recheck_uses_same_plan_and_exact_target(entry_source, monkeypatch, changed):
    from install import public_generation_transaction as generation
    args, _, _, _, events = entry_source
    monkeypatch.setattr(cli, 'fetch_verified_source', lambda plan: ({}, {}))
    evidence, _, _ = cli.prepare_install_request(args)
    if changed:
        monkeypatch.setattr(generation, 'preflight_target', lambda plan: {'changed':'target'})
        with pytest.raises(cli.TransactionError, match='PUBLIC_TARGET_CHANGED_DURING_STAGING'):
            cli.recheck_prepared_target(args[3], args[4], evidence)
    else:
        cli.recheck_prepared_target(args[3], args[4], evidence)
        assert events[-2:] == ['plan', 'target']


@pytest.mark.parametrize('field', ['source_plan_sha256', 'plan_sha256', 'source'])
def test_poststage_recheck_rejects_preparation_source_substitution(entry_source, monkeypatch, field):
    args, _, _, _, events = entry_source
    monkeypatch.setattr(cli, 'fetch_verified_source', lambda plan: ({}, {}))
    evidence, _, _ = cli.prepare_install_request(args)
    evidence[field] = 'changed'
    with pytest.raises(cli.TransactionError, match='PREPARED_SOURCE_BINDING_CHANGED'):
        cli.recheck_prepared_target(args[3], args[4], evidence)
    assert events[-1] == 'plan'


def test_poststage_target_drift_preserves_inactive_attempt_without_success(tmp_path, monkeypatch):
    from tests.test_public_generation_transaction import bootstrap_material, complete_preparation_fixture
    target = tmp_path / 'target'; target.mkdir()
    staging = tmp_path / 'staging'; staging.mkdir(mode=0o700)
    release, material = bootstrap_material()
    evidence = {'source':{'release_digest':release['self_digest']},
                'source_plan_sha256':'e'*64, 'target_prestate':complete_preparation_fixture(target)}
    monkeypatch.setattr(cli, 'prepare_generation', lambda *_: (evidence, release, material))
    def deny(*args): raise cli.TransactionError('PUBLIC_TARGET_CHANGED_DURING_STAGING')
    monkeypatch.setattr(cli, 'recheck_prepared_target', deny)
    with pytest.raises(cli.TransactionError, match='PUBLIC_TARGET_CHANGED_DURING_STAGING'):
        cli.prepare_and_stage_generation('fixture-plan', 'd'*64, staging_parent=staging)
    generation_id = release['self_digest'].removeprefix('sha256:')
    assert (staging / generation_id).is_dir()
    assert not (staging / 'current.json').exists() and not (staging / 'lkg.json').exists()


def test_failed_preparation_never_creates_staging(tmp_path, monkeypatch):
    def denied(*_): raise cli.TransactionError("PUBLIC_BOOT_DRIFT_DENIED")
    monkeypatch.setattr(cli, "prepare_generation", denied)
    with pytest.raises(cli.TransactionError, match="PUBLIC_BOOT_DRIFT_DENIED"):
        cli.prepare_and_stage_generation("fixture-plan", "d"*64, staging_parent=tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('failure', [None, 'before_capture', 'before_stage', 'after_stage', 'consumer'])
def test_locked_preparation_orders_capture_and_revalidation(tmp_path, monkeypatch, failure):
    """Native isolated files/lock; synthetic plan never establishes authority."""
    from install import public_generation_transaction as generation
    from tests.test_public_generation_transaction import (bootstrap_material,
        complete_preparation_fixture, bootstrap_fixture, verified, archive)
    root = tmp_path/'target'; root.mkdir()
    staging = tmp_path/'staging'; staging.mkdir(mode=0o700)
    lock_parent = root/'var/lib/serein/rollback'; lock_parent.mkdir(parents=True, mode=0o755)
    target = complete_preparation_fixture(root)
    units = bootstrap_fixture(root)
    release, material = bootstrap_material()
    _, identity = archive(); plan = verified(identity)
    evidence = {'source':{'release_digest':release['self_digest']},
                'source_plan_sha256':cli.sha(plan.encoded), 'target_prestate':target}
    real_lock = generation.public_generation_lock
    real_images = generation.capture_bootstrap_predecessor
    real_selectors = generation.capture_selector_predecessor
    events = []
    lock_path = lock_parent/'.outpost-public-generation.lock'
    def recheck(*args):
        events.append('check')
        count = events.count('check')
        assert lock_path.exists() == (count > 1)
        if count == {'before_capture':2, 'before_stage':3, 'after_stage':4}.get(failure):
            raise cli.TransactionError('injected drift')
        return plan
    def images(_, expected, read_unit):
        assert lock_path.exists(); events.append('images')
        return real_images(root, expected, units.__getitem__)
    def selectors(_, expected):
        assert lock_path.exists(); events.append('selectors')
        return real_selectors(root, expected)
    monkeypatch.setattr(cli, 'recheck_prepared_target', recheck)
    monkeypatch.setattr(generation, 'public_generation_lock', lambda _, digest, boot: real_lock(root,digest,boot))
    monkeypatch.setattr(generation, 'capture_bootstrap_predecessor', images)
    monkeypatch.setattr(generation, 'capture_selector_predecessor', selectors)
    def consume():
        with cli.locked_prepared_generation('fixture','d'*64,evidence,release,material,
                                            staging_parent=staging) as (result, capture, lock):
            assert lock_path.exists()
            assert result['activation'] == 'NONE'
            assert set(capture['selector_bytes']) == {'current','lkg'}
            assert len(capture['image_bytes']) == 4
            if failure == 'consumer': raise RuntimeError('injected consumer')
    if failure:
        with pytest.raises((cli.TransactionError, RuntimeError), match='injected'):
            consume()
    else:
        consume()
        assert events == ['check','check','images','selectors','check','check']
    assert not lock_path.exists()
    assert bool(list(staging.iterdir())) == (failure not in {'before_capture','before_stage'})
    assert generation.successor_generation_prestate(root) == target['installed_prestate']
    assert generation.bootstrap_prestate(root,units.__getitem__) == target['bootstrap_prestate']


@pytest.mark.parametrize('failure',[None,'signer','record','postrecord','reread','forward','postforward','forward_reread','candidate','postcandidate','candidate_reread','placement','postplacement','placed_readback','promote'])
def test_recorded_preparation_keeps_lock_and_private_material_internal(monkeypatch,tmp_path,failure):
    from contextlib import contextmanager
    from pathlib import Path
    from install import public_generation_transaction as generation
    events=[]; locked=False
    evidence={'target_prestate':{'generation_destination':{'fixture':'destination'}}};release={};material={};capture={'private':'never exposed'}
    expected_receipt={'sha256':'digest-only'}
    if failure=='promote':
        expected_receipt['path']='/var/lib/serein/rollback/outpost-public-generation-20260929T020000Z-aaaaaaaaaaaa/prestate-receipt.json'
        evidence['source_plan_sha256']='a'*64
        evidence['target_prestate'].update(current_boot_id='same-boot',host_identity='same-host',immutable_rows='same-keys')
    class Plan:
        encoded=b'fixture-plan'
        def as_dict(self): return {'rollback_selector':'bound-selector'}
    @contextmanager
    def lock(*args,**kwargs):
        nonlocal locked
        locked=True;events.append('lock')
        try: yield {'installed':'UNPROVEN','activation':'NONE','candidate_selector':{'fixture':'selector'}},capture,{'lock':'bound'}
        finally: locked=False;events.append('release')
    def body(*args):
        assert locked and args[-1] is capture
        events.append('body');return {'private':'record'}
    def recheck(*args,**kwargs):
        assert locked;events.append('check')
        if failure=='postrecord' and 'record' in events: raise cli.TransactionError('injected drift')
        if failure=='postforward' and 'forward' in events: raise cli.TransactionError('injected drift')
        if failure=='postcandidate' and 'candidate' in events: raise cli.TransactionError('injected drift')
        if 'placed' in kwargs:
            assert 'placement' in events
            if failure=='postplacement':raise cli.TransactionError('injected placed drift')
        return Plan()
    def signer(plan):
        assert locked;events.append('signer')
        if failure=='signer': raise cli.TransactionError('injected signer')
        return 'private-key','public-key'
    def seal(*args):
        assert locked;events.append('seal');return b'private record'
    def record(root,selector,raw,expected,public):
        assert locked and root==Path('/') and selector=='bound-selector'
        assert raw==b'private record' and public=='public-key'
        events.append('record')
        if failure=='record': raise cli.TransactionError('injected record')
        return expected_receipt
    def reread(root,receipt,body,public):
        assert locked and receipt==expected_receipt
        events.append('reread')
        if failure=='reread': raise cli.TransactionError('injected reread')
        return receipt
    def seal_forward(*args):
        assert locked and args==(b'private record',{'private':'record'},'private-key','public-key')
        events.append('seal_forward');return b'private forward'
    def forward(root,receipt,raw,body,public,**kwargs):
        assert locked and raw==b'private record' and public=='public-key'
        event='forward' if 'create_raw' in kwargs else 'forward_reread'
        events.append(event)
        if failure==event: raise cli.TransactionError('injected forward')
        if event=='forward': assert kwargs=={'create_raw':b'private forward'}
        else: assert kwargs=={'journal':{'sha256':'forward-only'}}
        return {'sha256':'forward-only'}
    def candidate(root,receipt,raw,body,public,selector,staging_parent,*,create=False,placed=False):
        assert locked and selector=={'fixture':'selector'}
        assert staging_parent==(Path('/usr/share/serein/outpost-generations') if placed else tmp_path)
        event='placed_readback' if placed else ('candidate' if create else 'candidate_reread');events.append(event)
        if failure==event:raise cli.TransactionError('injected candidate')
        return {'sha256':'candidate-only'}
    def placement(root,r,m,destination):
        assert locked and root==Path('/') and destination=={'fixture':'destination'}
        events.append('placement')
        if failure=='placement':raise cli.TransactionError('injected placement')
        return {'activation':'NONE'}
    from install import transaction
    monkeypatch.setattr(transaction,'place_inactive_generation',placement)
    monkeypatch.setattr(cli,'locked_prepared_generation',lock)
    monkeypatch.setattr(cli,'recheck_prepared_target',recheck)
    monkeypatch.setattr(generation,'prepared_prestate_receipt',body)
    monkeypatch.setattr(generation,'load_prestate_signer',signer)
    monkeypatch.setattr(generation,'seal_prestate_receipt',seal)
    monkeypatch.setattr(generation,'persist_prestate_receipt',record)
    monkeypatch.setattr(generation,'reread_prestate_receipt',reread)
    monkeypatch.setattr(generation,'seal_prepared_forward_state',seal_forward)
    monkeypatch.setattr(generation,'prepared_forward_record',forward)
    monkeypatch.setattr(generation,'prepared_candidate_record',candidate)
    if failure=='promote':
        monkeypatch.setattr(generation,'bootstrap_candidate_precheck',lambda *args:{'fixture':'precheck'})
        monkeypatch.setattr(cli,'_bootstrap_service_account',lambda:(978,978))
        monkeypatch.setattr(generation,'_target_prestate',lambda *args:{key:evidence['target_prestate'][key] for key in ('current_boot_id','host_identity','immutable_rows')})
        monkeypatch.setattr(generation,'_verify_plan',lambda *args:Plan())
        monkeypatch.setattr(cli,'_load_plan',lambda *args:{'fixture':'verified-plan'})
        io=object()
        monkeypatch.setattr(generation,'_GenerationFileIO',lambda *args:io)
        def complete(actual_io,prepared,expected,raw,private,public,precheck,invariants,accept):
            assert locked and actual_io is io and events[-1]=='placed_readback'
            assert prepared['candidate_selector']=={'fixture':'selector'}
            assert raw==b'private record' and private=='private-key' and public=='public-key'
            assert precheck=={'fixture':'precheck'}
            invariants();events.append('promote')
            return {'result':'INSTALLED_CURRENT_BOOT_OBSERVED','admission':'UNPROVEN'}
        monkeypatch.setattr(generation,'_complete_bootstrap_promotion',complete)
    def consume():
        with cli.recorded_prepared_generation('fixture','d'*64,evidence,release,material,staging_parent=tmp_path,promote=failure=='promote') as result:
            assert locked
            if failure=='promote':assert result=={'result':'INSTALLED_CURRENT_BOOT_OBSERVED','admission':'UNPROVEN'}
            else:
                assert result['prestate_receipt']==expected_receipt
                assert result['forward_state']=={'sha256':'forward-only'}
                assert result['candidate_record']=={'sha256':'candidate-only'}
            assert 'private' not in repr(result)
            events.append('consume')
    if failure=='promote':
        consume()
        assert events[-4:]==['reread','promote','consume','release']
    elif failure:
        with pytest.raises(cli.TransactionError,match='injected'): consume()
        assert 'consume' not in events
    else:
        consume()
        assert events==['lock','body','check','signer','seal','check','record','check','reread',
                        'seal_forward','forward','check','forward_reread',
                        'candidate','check','candidate_reread','check','placement','check',
                        'forward_reread','placed_readback','consume','release']
    assert not locked and events[-1]=='release'


@pytest.mark.parametrize('defect',[None,'boot','immutable','current','bootstrap','parent','target','state'])
def test_postplacement_recheck_permits_only_exact_candidate_presence(monkeypatch,defect):
    import copy
    from install import public_generation_transaction as generation
    from tests.test_public_generation_transaction import archive,verified
    _,identity=archive();plan=verified(identity);fields=plan.as_dict()
    before={'current_boot_id':'boot','immutable_rows':['preserved'],
            'installed_prestate':{'current':'old','lkg':'older'},'bootstrap_prestate':{'files':'old','units':'inactive'},
            'generation_destination':{'target':'canonical','state':'ABSENT','parent':{'inode':1}}}
    evidence={'plan_sha256':'d'*64,'source_plan_sha256':cli.sha(plan.encoded),
              'source':{key:fields[key] for key in ('repository','commit','tree','archive_sha256','release_digest')},
              'target_prestate':before}
    after=copy.deepcopy(before);after['generation_destination'].update(state='PRESENT',selector={'exact':'selector'})
    if defect=='boot':after['current_boot_id']='changed'
    elif defect=='immutable':after['immutable_rows']=['changed']
    elif defect=='current':after['installed_prestate']['current']='changed'
    elif defect=='bootstrap':after['bootstrap_prestate']['units']='active'
    elif defect in {'parent','target','state'}:after['generation_destination'][defect]='changed'
    monkeypatch.setattr(cli,'_load_plan',lambda *a:fields)
    monkeypatch.setattr(generation,'_verify_plan',lambda *a:plan)
    monkeypatch.setattr(generation,'preflight_placed_target',lambda *a:after)
    monkeypatch.setattr(generation,'preflight_target',lambda *a:pytest.fail('absence-only check used after placement'))
    if defect:
        with pytest.raises(cli.TransactionError):cli.recheck_prepared_target('fixture','d'*64,evidence,placed={'selector':{},'record':{}})
    else:
        assert cli.recheck_prepared_target('fixture','d'*64,evidence,placed={'selector':{},'record':{}}) is plan


def test_canonical_entry_joins_same_locked_recorded_path(entry_source,monkeypatch,tmp_path):
    from contextlib import contextmanager
    from pathlib import Path
    args,*_ = entry_source
    evidence,release,material = {'fixture':'evidence'},{'fixture':'release'},{'fixture':b'inactive'}
    order=[]
    def prepare(arguments):
        assert arguments==args;order.append('prepare');return evidence,release,material
    @contextmanager
    def record(path,digest,e,r,m,*,staging_parent):
        assert path==Path(args[3]) and digest==args[4]
        assert e is evidence and r is release and m is material and staging_parent==tmp_path
        order.append('locked')
        try: yield {'installed':'UNPROVEN','activation':'NONE'}
        finally: order.append('release')
    monkeypatch.setattr(cli,'prepare_install_request',prepare)
    monkeypatch.setattr(cli,'recorded_prepared_generation',record)
    with cli.prepare_recorded_install_request(args,staging_parent=tmp_path) as result:
        assert order==['prepare','locked'] and result['activation']=='NONE'
    assert order==['prepare','locked','release']


def test_invalid_canonical_entry_never_acquires_or_records(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(cli,'prepare_install_request',lambda *a:calls.append(a))
    with pytest.raises(cli.TransactionError,match='OUTPOST_ENTRY_ARGUMENTS_REQUIRED'):
        with cli.prepare_recorded_install_request([],staging_parent=tmp_path):
            pytest.fail('invalid entry reached transaction')
    assert not calls and list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('uid,gid',[(0,978),(978,0),(978,978)])
def test_bootstrap_service_identity_is_checked_without_creating_or_repairing_accounts(monkeypatch,uid,gid):
    import pwd,grp
    from types import SimpleNamespace
    monkeypatch.setattr(pwd,'getpwnam',lambda name:SimpleNamespace(pw_uid=uid))
    monkeypatch.setattr(grp,'getgrnam',lambda name:SimpleNamespace(gr_gid=gid))
    if uid==0 or gid==0:
        with pytest.raises(cli.TransactionError,match='PUBLIC_WITNESS_ACCOUNT_DENIED'):cli._bootstrap_service_account()
    else:assert cli._bootstrap_service_account()==(978,978)


@pytest.mark.parametrize('defect',[None,'source','account','root_account','target_drift'])
def test_postpromotion_reader_binds_signed_source_native_account_and_target(monkeypatch,defect):
    import pwd,grp
    from types import SimpleNamespace
    from install import public_generation_transaction as generation
    from tests.test_public_generation_transaction import archive,verified
    _,identity=archive();plan=verified(identity);calls=[]
    selector={'release_digest':plan.as_dict()['release_digest'],'predecessor_receipt_sha256':cli.sha(plan.encoded)}
    monkeypatch.setattr(cli,'_load_plan',lambda *a:plan.as_dict())
    monkeypatch.setattr(generation,'_verify_plan',lambda raw:plan)
    def target(root,fields):
        calls.append('target')
        return {'prestate':len(calls) if defect=='target_drift' else 'same'}
    def user(name):
        assert name=='serein-outpost'
        if defect=='account': raise KeyError(name)
        return SimpleNamespace(pw_uid=0 if defect=='root_account' else 978)
    def read(root,**kwargs):
        assert str(root)=='/' and kwargs['expected_generation']==selector
        assert kwargs['boot_id']==plan.as_dict()['current_boot_id'] and kwargs['not_before']==1.0
        assert kwargs['service_uid']==kwargs['service_gid']==978 and 'observed_at' not in kwargs
        calls.append('witness');return {'result':'SUPPORTING_CURRENT_BOOT_WITNESS','admission':'UNPROVEN'}
    monkeypatch.setattr(generation,'_target_prestate',target)
    monkeypatch.setattr(generation,'read_generation_witness',read)
    monkeypatch.setattr(pwd,'getpwnam',user)
    monkeypatch.setattr(grp,'getgrnam',lambda name:SimpleNamespace(gr_gid=978))
    if defect=='source': selector['release_digest']='sha256:'+'f'*64
    if defect:
        with pytest.raises(cli.TransactionError): cli.read_postpromotion_witness('fixture','d'*64,selector,not_before=1.0)
        if defect in {'source','account','root_account'}: assert 'witness' not in calls
    else:
        assert cli.read_postpromotion_witness('fixture','d'*64,selector,not_before=1.0)['admission']=='UNPROVEN'
        assert calls==['target','witness','target']


@pytest.mark.parametrize("digest", ["invalid", "sha256:" + "e"*64])
def test_inconsistent_prepared_release_cannot_create_staging(tmp_path, monkeypatch, digest):
    monkeypatch.setattr(cli, "prepare_generation", lambda *_: (
        {"source":{"release_digest":digest}}, {"self_digest":"sha256:"+"a"*64}, {"file":b"inert"}))
    with pytest.raises(cli.TransactionError, match="PREPARED_RELEASE_IDENTITY_DENIED"):
        cli.prepare_and_stage_generation("fixture-plan", "d"*64, staging_parent=tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("defect", ["manifest", "changed", "extra", "missing", "mutable"])
def test_prepared_material_drift_is_denied_before_any_staging_write(tmp_path, monkeypatch, defect):
    from tests.test_public_generation_transaction import archive, verified
    from install.public_generation_transaction import _fixture_archive_material
    raw, identity = archive()
    release, material = _fixture_archive_material(raw, verified(identity))
    if defect == "manifest": material["release-manifest.json"] = b"{}"
    if defect == "changed": material["payload.py"] = b"changed"
    if defect == "extra": material["extra.py"] = b"extra"
    if defect == "missing": del material["payload.py"]
    if defect == "mutable": material["payload.py"] = bytearray(material["payload.py"])
    monkeypatch.setattr(cli, "prepare_generation", lambda *_: ({"source":identity}, release, material))
    with pytest.raises(cli.TransactionError, match="PREPARED_"):
        cli.prepare_and_stage_generation("fixture-plan", "d"*64, staging_parent=tmp_path)
    assert not list(tmp_path.iterdir())
