import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from install.transaction import Adapter,TransactionError,install as transaction_install,installed_parity,rollback,validate_receipt
from verify_install_preflight import verify_source


ROOT=Path(__file__).resolve().parents[1]


def manifest(): return json.loads((ROOT/"release-manifest.json").read_text(encoding="utf-8"))


def seed_immutable(adapter,m,*,private=None,public=None,mode_override=None):
    private=private or Ed25519PrivateKey.generate(); public=public or private.public_key()
    values={
        "/etc/serein-outpost/readonly.token":b"r"*48,
        "/etc/serein-outpost/admission.token":b"a"*48,
        "/etc/serein-outpost/cognition-signing.pem":private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),
        "/usr/share/serein/outpost/cognition-verification.pem":public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo),
        "/etc/serein/tls/serein-backend-cert.pem":b"test-certificate",
        "/etc/serein/tls/serein-backend-key.pem":b"test-private-key",
    }
    identity=adapter.identity("serein-outpost") or adapter.planned_identity(m["identity_policy"])
    for declared in m["required_immutable_inputs"]:
        target=declared["target"]; path=adapter.root/target.lstrip("/"); path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(values[target]); mode=int(declared["mode"],8); os.chmod(path,mode)
        gid=identity["gid"] if declared.get("gid_policy")=="identity_gid" else declared["gid"]
        adapter.file_metadata_overrides[target]={"mode":mode,"uid":declared["uid"],"gid":gid}
    for target,mode,gid in (("/etc/serein-outpost",0o750,identity["gid"]),("/usr/share/serein/outpost",0o755,0)):
        adapter.directory_metadata_overrides[target]={"mode":mode,"uid":0,"gid":gid}
    adapter.directory_metadata_overrides.setdefault("/usr/share/serein",{"mode":0o755,"uid":0,"gid":0})
    if mode_override:
        adapter.file_metadata_overrides[mode_override[0]]["mode"]=mode_override[1]
    public_der=public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    declared_targets={row["target"] for row in m["required_immutable_inputs"]}
    return {"schema":"SereinOutpostImmutableInputPlan/v1","source":"OFFLINE_USB_MEDIA","target":"SEREIN_HOST","method":"VERIFIED_PUBLIC_INSTALLER","release_digest":m["self_digest"],"key_id":"outpost-cognition-v1","public_key_fingerprint_sha256":__import__("hashlib").sha256(public_der).hexdigest(),"files":[{"target":target,"sha256":__import__("hashlib").sha256(data).hexdigest()} for target,data in values.items() if target in declared_targets]}


def install(adapter,source,m,selector,plan=None):
    return transaction_install(adapter,source,m,selector,plan or seed_immutable(adapter,m))


def fixture(tmp_path,fail_after=None,identity=None):
    # Match a generic fresh-install shape: /usr/share/serein is absent.
    for path in ("var/lib/serein/rollback","usr/share","usr/libexec","etc","etc/systemd/system","var/lib","run/serein"):
        (tmp_path/path).mkdir(parents=True,exist_ok=True)
    adapter=Adapter(tmp_path,fail_after=fail_after)
    adapter.directory_metadata_overrides["/usr/libexec"]={"mode":0o755,"uid":0,"gid":0}
    if identity is not None: adapter.identities["serein-outpost"]=identity
    selector=tmp_path/"var/lib/serein/rollback/outpost-first-install-20260901T000000Z-123456789abc"
    return adapter,selector


def expected_identity(**changes):
    value={"user":"serein-outpost","uid":900,"gid":900,"group":"serein-outpost","group_gid":900,"home":"/nonexistent","shell":"/usr/sbin/nologin","supplementary_groups":[]}
    value.update(changes); return value


def assert_absent(adapter,m):
    for row in m["install_files"]+m["generated_files"]:
        assert not os.path.lexists(adapter.root/row["target"].lstrip("/"))
    for row in m["required_immutable_inputs"]:
        assert os.path.isfile(adapter.root/row["target"].lstrip("/"))
    assert adapter.identity("serein-outpost") is None
    assert (adapter.root/"usr/share/serein/outpost").is_dir()


def assert_bootstrap_absent(adapter,m):
    for row in m["install_files"]+m["generated_files"]+m["required_immutable_inputs"]:
        assert not os.path.lexists(adapter.root/row["target"].lstrip("/"))
    assert adapter.identity("serein-outpost") is None
    assert not (adapter.root/"usr/share/serein").exists()


def test_fresh_target_without_shared_payload_parent_installs_and_rolls_back(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path)
    assert not (adapter.root/"usr/share/serein").exists()
    install(adapter,ROOT,m,selector)
    assert (adapter.root/"usr/share/serein/outpost").is_dir()
    rollback(adapter,selector)
    assert (adapter.root/"usr/share/serein/outpost/cognition-verification.pem").is_file()


def test_exact_shared_payload_parent_is_adopted_and_preserved(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path)
    parent=adapter.root/"usr/share/serein"; parent.mkdir(mode=0o755)
    adapter.directory_metadata_overrides["/usr/share/serein"]={"mode":0o755,"uid":0,"gid":0}
    install(adapter,ROOT,m,selector)
    rollback(adapter,selector)
    assert parent.is_dir()


def test_identity_directories_and_root_credential_directory_match_declared_custody(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path)
    receipt=install(adapter,ROOT,m,selector)
    identity_gid=receipt["identity_actual"]["gid"]
    assert adapter.directory_metadata_overrides["/etc/serein-outpost"]=={"mode":0o750,"uid":0,"gid":identity_gid}
    assert adapter.directory_metadata_overrides["/run/serein/outpost"]=={"mode":0o750,"uid":receipt["identity_actual"]["uid"],"gid":identity_gid}
    assert adapter.directory_metadata_overrides["/var/lib/serein-outpost"]=={"mode":0o750,"uid":receipt["identity_actual"]["uid"],"gid":identity_gid}
    rollback(adapter,selector)
    assert_absent(adapter,m)


@pytest.mark.parametrize("metadata",[
    {"mode":0o755,"uid":1,"gid":0},
    {"mode":0o755,"uid":0,"gid":1},
    {"mode":0o750,"uid":0,"gid":0},
])
def test_shared_payload_parent_wrong_prestate_is_denied_before_writes(tmp_path,metadata):
    m=manifest(); adapter,selector=fixture(tmp_path)
    parent=adapter.root/"usr/share/serein"; parent.mkdir(mode=0o755)
    adapter.directory_metadata_overrides["/usr/share/serein"]=metadata
    with pytest.raises(TransactionError,match="DIRECTORY_ADOPTION_PRESTATE_DENIED:/usr/share/serein"):
        install(adapter,ROOT,m,selector)
    assert adapter.writes==0
    assert not selector.exists()
    assert parent.is_dir()


@pytest.mark.skipif(os.name=="nt",reason="symlink creation and no-follow semantics are proven in Linux provider lane")
def test_shared_payload_parent_symlink_is_denied_before_writes(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path)
    real=adapter.root/"usr/share/foreign"; real.mkdir(mode=0o755)
    (adapter.root/"usr/share/serein").symlink_to(real,target_is_directory=True)
    with pytest.raises(TransactionError,match="PATH_SYMLINK_DENIED"):
        install(adapter,ROOT,m,selector)
    assert adapter.writes==0
    assert not selector.exists()


def test_closed_source_denominator_rejects_extra_file(tmp_path):
    clean=tmp_path/"source"; shutil.copytree(ROOT,clean,ignore=shutil.ignore_patterns("__pycache__","*.pyc",".pytest_cache"))
    release=json.loads((clean/"release-manifest.json").read_text(encoding="utf-8")); verify_source(clean,release)
    (clean/"UNMANIFESTED_PAYLOAD.txt").write_text("denied",encoding="utf-8")
    with pytest.raises(SystemExit,match="SOURCE_DENOMINATOR_DENIED"): verify_source(clean,release)


def test_installed_boot_denominator_allows_only_declared_generated_file(tmp_path):
    clean=tmp_path/"source"; shutil.copytree(ROOT,clean,ignore=shutil.ignore_patterns("__pycache__","*.pyc",".pytest_cache"))
    release=json.loads((clean/"release-manifest.json").read_text(encoding="utf-8"))
    generated="cognition-verification.pem"
    (clean/generated).write_text("public verification material\n",encoding="utf-8")
    verify_source(clean,release,{generated})
    (clean/"undeclared-runtime-file").write_text("denied\n",encoding="utf-8")
    with pytest.raises(SystemExit,match="SOURCE_DENOMINATOR_DENIED"): verify_source(clean,release,{generated})


def test_import_order_cannot_contaminate_source_denominator(tmp_path):
    clean=tmp_path/"source"; shutil.copytree(ROOT,clean,ignore=shutil.ignore_patterns("__pycache__","*.pyc",".pytest_cache"))
    environment={**os.environ,"PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":str(clean)}
    program="import json; from pathlib import Path; import outpost.presentation_service, install.transaction; from verify_install_preflight import verify_source; root=Path.cwd(); verify_source(root,json.loads((root/'release-manifest.json').read_text(encoding='utf-8')))"
    subprocess.run([sys.executable,"-c",program],cwd=clean,env=environment,check=True)
    assert not list(clean.rglob("*.pyc")) and not list(clean.rglob("__pycache__"))


def test_generated_bytecode_is_still_rejected(tmp_path):
    clean=tmp_path/"source"; shutil.copytree(ROOT,clean,ignore=shutil.ignore_patterns("__pycache__","*.pyc",".pytest_cache"))
    release=json.loads((clean/"release-manifest.json").read_text(encoding="utf-8"))
    cache=clean/"outpost/__pycache__"; cache.mkdir(); (cache/"service.cpython-312.pyc").write_bytes(b"unmanifested-bytecode")
    with pytest.raises(SystemExit,match="SOURCE_DENOMINATOR_DENIED"): verify_source(clean,release)


@pytest.mark.skipif(os.name=="nt",reason="actual POSIX install wrapper executes in Linux provider lane")
def test_actual_install_wrapper_preflight_twice_is_intrinsically_bytecode_free(tmp_path):
    clean=tmp_path/"source"; shutil.copytree(ROOT,clean,ignore=shutil.ignore_patterns("__pycache__","*.pyc",".pytest_cache"))
    preflight=json.loads((clean/"install-preflight.json").read_text(encoding="utf-8")); target=tmp_path/"target"
    assert preflight["transaction"]=="FIRST_INSTALL_ONLY"
    (target/"etc").mkdir(parents=True); (target/"etc/hostname").write_text("existing-gaming-pc\n",encoding="utf-8")
    (target/"etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n',encoding="utf-8")
    rollback_base=target/preflight["expected_before"]["rollback_base"]["path"].lstrip("/")
    rollback_base.mkdir(parents=True); rollback_base.chmod(0o755)
    environment={key:value for key,value in os.environ.items() if key!="PYTHONDONTWRITEBYTECODE"}
    command=["/bin/sh",str(clean/"install/install-outpost.sh"),str(clean),"preflight",str(target)]
    subprocess.run(command,env=environment,check=True); subprocess.run(command,env=environment,check=True)
    assert not list(clean.rglob("*.pyc")) and not list(clean.rglob("__pycache__"))


def test_full_install_parity_rollback_and_retry(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path)
    receipt=install(adapter,ROOT,m,selector); validate_receipt(adapter,selector); installed_parity(adapter,{**m,"install_files":m["install_files"]+[{"source":"release-manifest.json","target":"/usr/share/serein/outpost/release-manifest.json","bytes":len((ROOT/"release-manifest.json").read_bytes()),"sha256":__import__("hashlib").sha256((ROOT/"release-manifest.json").read_bytes()).hexdigest(),"mode":"0644","uid":0,"gid":0}]},receipt)
    rollback(adapter,selector); assert_absent(adapter,m)
    second=tmp_path/"var/lib/serein/rollback/outpost-first-install-20260901T000001Z-abcdefabcdef"
    install(adapter,ROOT,m,second); rollback(adapter,second); assert_absent(adapter,m)


def test_every_declared_protected_unit_is_captured_and_preserved(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path)
    receipt=install(adapter,ROOT,m,selector)
    assert set(receipt["unit_prestate"])=={"serein-outpost-host-witness.service","serein-outpost-presentation.service","serein-outpost.target"}
    assert m["protected_unit_state"]=={}
    rollback(adapter,selector); assert_absent(adapter,m)


def test_fresh_install_has_no_downstream_unit_precondition(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path)
    assert m["protected_unit_state"]=={}
    unrelated={"enabled":"disabled","active":"inactive"}
    adapter.unit_state["unrelated.service"]=dict(unrelated)
    install(adapter,ROOT,m,selector)
    assert adapter.unit_state["unrelated.service"]==unrelated
    rollback(adapter,selector)
    assert adapter.unit_state["unrelated.service"]==unrelated


@pytest.mark.parametrize("state",[
    {"enabled":"enabled","active":"inactive"},
    {"enabled":"disabled","active":"active"},
])
def test_outpost_units_must_be_inactive_and_unenabled_before_install(tmp_path,state):
    m=manifest(); adapter,selector=fixture(tmp_path)
    adapter.unit_state["serein-outpost-host-witness.service"]=state
    with pytest.raises(TransactionError,match="PROTECTED_UNIT_PRESTATE_DENIED"):
        transaction_install(adapter,ROOT,m,selector,None,"OFFLINE_USB_MEDIA")
    assert adapter.writes==0 and not selector.exists()


def test_every_install_write_boundary_compensates_without_residue(tmp_path):
    probe_root=tmp_path/"probe"; probe_root.mkdir(); adapter,selector=fixture(probe_root); m=manifest(); install(adapter,ROOT,m,selector); boundaries=adapter.writes; rollback(adapter,selector)
    assert boundaries>len(m["install_files"])
    for point in range(1,boundaries+1):
        case=tmp_path/f"failure-{point}"; case.mkdir(); adapter,selector=fixture(case,fail_after=point)
        with pytest.raises(TransactionError,match="INJECTED_WRITE_FAILURE"): install(adapter,ROOT,m,selector)
        assert_absent(adapter,m)


def test_transaction_owned_bootstrap_restores_exact_absence_at_every_failure_boundary(tmp_path):
    m=manifest(); probe=tmp_path/"bootstrap-probe"; probe.mkdir(); adapter,selector=fixture(probe)
    receipt=transaction_install(adapter,ROOT,m,selector,None,"PINNED_PUBLIC_REPOSITORY")
    assert all(row.get("created") is True for row in receipt["immutable_inputs"])
    boundaries=adapter.writes
    rollback(adapter,selector); assert_bootstrap_absent(adapter,m)
    for point in range(1,boundaries+1):
        case=tmp_path/f"bootstrap-failure-{point}"; case.mkdir(); adapter,selector=fixture(case,fail_after=point)
        with pytest.raises(TransactionError,match="INJECTED_WRITE_FAILURE"):
            transaction_install(adapter,ROOT,m,selector,None,"OFFLINE_USB_MEDIA")
        assert_bootstrap_absent(adapter,m)


def test_collisions_are_denied_and_preserved(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); collision=adapter.root/"etc/systemd/system/serein-outpost-host-witness.service"; collision.write_text("foreign",encoding="utf-8")
    with pytest.raises(TransactionError,match="TARGET_COLLISION_DENIED"): install(adapter,ROOT,m,selector)
    assert collision.read_text(encoding="utf-8")=="foreign"


@pytest.mark.parametrize("changes",[{"home":"/tmp"},{"shell":"/bin/sh"},{"group":"other"},{"group_gid":902},{"supplementary_groups":["wheel"]},{"uid":1000},{"gid":901,"group_gid":901},{"partial":True}])
def test_preexisting_identity_must_match_every_policy_axis(tmp_path,changes):
    m=manifest(); adapter,selector=fixture(tmp_path,identity=expected_identity(**changes))
    with pytest.raises(TransactionError,match="IDENTITY_"): install(adapter,ROOT,m,selector)
    assert adapter.identity("serein-outpost") is not None


def test_approved_preexisting_identity_is_adopted_not_removed(tmp_path):
    m=manifest(); identity=expected_identity(); adapter,selector=fixture(tmp_path,identity=identity)
    receipt=install(adapter,ROOT,m,selector); assert receipt["identity_state"]=="APPROVED_EXISTING"
    rollback(adapter,selector); assert adapter.identity("serein-outpost")==identity


def test_tampered_or_incomplete_rollback_receipt_is_denied(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); install(adapter,ROOT,m,selector); path=selector/"receipt.json"; receipt=json.loads(path.read_text(encoding="utf-8"))
    receipt["introduced_files"]=receipt["introduced_files"][:-1]; path.write_text(json.dumps(receipt),encoding="utf-8"); os.chmod(path,0o600)
    with pytest.raises(TransactionError,match="ROLLBACK_RECEIPT_INTEGRITY_DENIED"): rollback(adapter,selector)
    receipt.pop("receipt_digest",None); path.write_text(json.dumps(receipt),encoding="utf-8"); os.chmod(path,0o600)
    with pytest.raises(TransactionError,match="ROLLBACK_RECEIPT_INTEGRITY_DENIED"): rollback(adapter,selector)


def test_installed_tamper_and_unexpected_residue_fail_closed(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); receipt=install(adapter,ROOT,m,selector)
    target=adapter.root/m["install_files"][0]["target"].lstrip("/"); target.write_text("tampered",encoding="utf-8")
    with pytest.raises(TransactionError,match="INSTALLED_CONTENT_DENIED"): rollback(adapter,selector)
    target.write_bytes((ROOT/m["install_files"][0]["source"]).read_bytes()); os.chmod(target,int(m["install_files"][0]["mode"],8))
    residue=adapter.root/"usr/share/serein/outpost/unexpected"; residue.write_text("x",encoding="utf-8")
    with pytest.raises(TransactionError,match="ROLLBACK_UNEXPECTED_RESIDUE_DENIED"): rollback(adapter,selector)


def test_missing_immutable_input_is_denied_before_transaction(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path)
    with pytest.raises(TransactionError,match="IMMUTABLE_INPUT_PLAN_DENIED"):
        transaction_install(adapter,ROOT,m,selector,None)
    assert adapter.writes==0 and not selector.exists()


def test_substituted_immutable_input_hash_is_denied(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); plan=seed_immutable(adapter,m)
    plan["files"][0]["sha256"]="0"*64
    with pytest.raises(TransactionError,match="IMMUTABLE_INPUT_HASH_DENIED"):
        transaction_install(adapter,ROOT,m,selector,plan)
    assert adapter.writes==0 and not selector.exists()


def test_stale_release_bound_input_plan_is_denied(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); plan=seed_immutable(adapter,m); plan["release_digest"]="sha256:"+"0"*64
    with pytest.raises(TransactionError,match="IMMUTABLE_INPUT_AUTHORITY_DENIED"):
        transaction_install(adapter,ROOT,m,selector,plan)


def test_wrong_immutable_input_mode_is_denied(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); plan=seed_immutable(adapter,m,mode_override=("/etc/serein-outpost/readonly.token",0o644))
    with pytest.raises(TransactionError,match="IMMUTABLE_INPUT_CUSTODY_DENIED"):
        transaction_install(adapter,ROOT,m,selector,plan)
    assert adapter.writes==0 and not selector.exists()


def test_wrong_immutable_input_owner_is_denied(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); plan=seed_immutable(adapter,m)
    adapter.file_metadata_overrides["/etc/serein-outpost/admission.token"]["uid"]=900
    with pytest.raises(TransactionError,match="IMMUTABLE_INPUT_CUSTODY_DENIED"):
        transaction_install(adapter,ROOT,m,selector,plan)
    assert adapter.writes==0 and not selector.exists()


def test_mismatched_immutable_key_pair_is_denied(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); plan=seed_immutable(adapter,m,public=Ed25519PrivateKey.generate().public_key())
    with pytest.raises(TransactionError,match="IMMUTABLE_KEY_PAIR_DENIED"):
        transaction_install(adapter,ROOT,m,selector,plan)
    assert adapter.writes==0 and not selector.exists()


def test_rollback_preserves_exact_immutable_bytes(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); plan=seed_immutable(adapter,m)
    before={row["target"]:(adapter.root/row["target"].lstrip("/")).read_bytes() for row in m["required_immutable_inputs"]}
    receipt=transaction_install(adapter,ROOT,m,selector,plan)
    assert receipt["immutable_key_id"]=="outpost-cognition-v1"
    rollback(adapter,selector)
    after={target:(adapter.root/target.lstrip("/")).read_bytes() for target in before}
    assert after==before


@pytest.mark.skipif(os.name=="nt",reason="symlink creation requires Linux provider lane")
def test_symlinked_immutable_input_is_denied(tmp_path):
    m=manifest(); adapter,selector=fixture(tmp_path); plan=seed_immutable(adapter,m)
    path=adapter.root/"etc/serein-outpost/readonly.token"; value=path.read_bytes(); path.unlink()
    backing=adapter.root/"etc/serein-outpost/backing"; backing.write_bytes(value); path.symlink_to(backing)
    with pytest.raises(TransactionError,match="PATH_SYMLINK_DENIED|IMMUTABLE_INPUT_TYPE_DENIED"):
        transaction_install(adapter,ROOT,m,selector,plan)
