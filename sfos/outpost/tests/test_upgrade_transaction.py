import copy
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from install.transaction import Adapter, RealAdapter, TransactionError, canonical, sha
from install.upgrade_transaction import migrate_flat_predecessor, read_runtime, replacement_plan_digest, rollback, rollback_flat_migration, upgrade, validate_replacement_plan, validate_upgrade_receipt
from install.generation_launcher import LaunchDenied, launch, read_selector, select_generation


def row(target, data, source=None, mode="0644"):
    value={"target":target,"bytes":len(data),"sha256":sha(data),"mode":mode,"uid":0,"gid":0}
    if source is not None: value["source"]=source
    return value


def write(root, target, data, mode="0644"):
    path=root/target.lstrip("/"); path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data); os.chmod(path,int(mode,8)); return path


def rebind_controlled(plan,root,target,data):
    controlled=next(row for row in plan["controlled_inventory"] if row["target"]==target); controlled.update(bytes=len(data),sha256=sha(data))
    digest=sha(canonical(plan["controlled_inventory"])); binding=plan["controlled_inventory_receipt"]; receipt={"schema":"SereinOutpostControlledInventoryReceipt/v1","controlled_inventory_digest":digest}; receipt["receipt_digest"]=sha(canonical(receipt)); receipt_bytes=(json.dumps(receipt,indent=2)+"\n").encode(); write(root,binding["receipt"],receipt_bytes,"0600"); binding.update(sha256=sha(receipt_bytes),inventory_digest=digest)


def fixture(tmp_path):
    source=tmp_path/"source"; source.mkdir(); new_a=b"new-a\n"; kept=b"kept\n"
    (source/"a.bin").write_bytes(new_a); (source/"keep.bin").write_bytes(kept)
    units={"running.service":{"enabled":"enabled","active":"active","substate":"running","main_pid":42},"oneshot.service":{"enabled":"static","active":"active","substate":"exited","main_pid":0},"failed.service":{"enabled":"disabled","active":"failed","substate":"failed","main_pid":0},"inactive.service":{"enabled":"disabled","active":"inactive","substate":"dead","main_pid":0},"domain-install@.service":{"enabled":"static","active":"inactive","substate":"dead"},"watch.path":{"enabled":"enabled","active":"active","substate":"waiting"},"outpost.target":{"enabled":"static","active":"active","substate":"active"}}
    release={"self_digest":"sha256:"+"1"*64,"implementation_base_commit":"0"*40,"implementation_base_tree":"1"*40,"identity_policy":{"user":"serein-outpost"},"replacement_unit_allowlist":list(units),"replacement_controlled_roots":["/usr/share/serein/outpost"],"install_directories":[{"target":"/usr/share/serein/outpost","mode":"0755","uid":0,"gid":0}],
        "install_files":[row("/opt/serein/a.bin",new_a,"a.bin"),row("/opt/serein/keep.bin",kept,"keep.bin")],
        "generated_files":[{"target":"/etc/serein-outpost/rollback-root","mode":"0600","uid":0,"gid":0}],"required_immutable_inputs":[
            {"target":"/etc/serein-outpost/readonly.token","mode":"0640","uid":0,"gid_policy":"identity_gid"},
            {"target":"/etc/serein-outpost/admission.token","mode":"0640","uid":0,"gid_policy":"identity_gid"},
            {"target":"/etc/serein-outpost/cognition-signing.pem","mode":"0640","uid":0,"gid_policy":"identity_gid"},
            {"target":"/usr/share/serein/outpost/cognition-verification.pem","mode":"0644","uid":0,"gid":0},
            {"target":"/etc/serein/tls/serein-backend-cert.pem","mode":"0600","uid":0,"gid":0},
            {"target":"/etc/serein/tls/serein-backend-key.pem","mode":"0600","uid":0,"gid":0}]}
    release_bytes=(json.dumps(release,sort_keys=True)+"\n").encode(); (source/"release-manifest.json").write_bytes(release_bytes)
    old_a=b"old-a\n"; removed=b"remove-me\n"; old_release=b"old-release\n"; old_rollback=b"/var/lib/serein/rollback/predecessor\n"
    inventory=[row("/opt/serein/a.bin",old_a),row("/opt/serein/keep.bin",kept,mode="0664"),row("/opt/serein/obsolete.bin",removed),row("/usr/share/serein/outpost/release-manifest.json",old_release),row("/etc/serein-outpost/rollback-root",old_rollback,mode="0600")]
    for item,data in zip(inventory,(old_a,kept,removed,old_release,old_rollback)):
        write(tmp_path,item["target"],data,item["mode"])
    cognition_private=ed25519.Ed25519PrivateKey.generate(); cognition_public=cognition_private.public_key()
    tls_private=rsa.generate_private_key(public_exponent=65537,key_size=2048); name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"serein.test")]); now=datetime.now(timezone.utc)
    certificate=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(tls_private.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).sign(tls_private,hashes.SHA256())
    values={"/etc/serein-outpost/readonly.token":b"r"*48,"/etc/serein-outpost/admission.token":b"a"*48,
        "/etc/serein-outpost/cognition-signing.pem":cognition_private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),
        "/usr/share/serein/outpost/cognition-verification.pem":cognition_public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo),
        "/etc/serein/tls/serein-backend-cert.pem":certificate.public_bytes(serialization.Encoding.PEM),
        "/etc/serein/tls/serein-backend-key.pem":tls_private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())}
    immutable=[]
    for declared in release["required_immutable_inputs"]:
        data=values[declared["target"]]; write(tmp_path,declared["target"],data,declared["mode"])
        immutable.append(row(declared["target"],data,mode=declared["mode"])|{"gid":900 if declared.get("gid_policy")=="identity_gid" else declared["gid"]})
    write(tmp_path,"/usr/share/serein/outpost/.pytest_cache/v/cache.bin",b"cache\n")
    controlled=[]; controlled_root=tmp_path/"usr/share/serein/outpost"; known={item["target"]:item for item in inventory+immutable}
    for path in [controlled_root]+sorted(controlled_root.rglob("*")):
        target="/"+path.relative_to(tmp_path).as_posix(); info=path.stat(); base={"target":target,"mode":f"{stat.S_IMODE(info.st_mode):04o}","uid":0,"gid":0}
        controlled.append(({"kind":"directory"}|base) if path.is_dir() else ({"kind":"file"}|(known.get(target) or ({"bytes":len(path.read_bytes()),"sha256":sha(path.read_bytes())}|base))))
    boot="11111111-2222-3333-4444-555555555555"; write(tmp_path,"/proc/sys/kernel/random/boot_id",(boot+"\n").encode())
    predecessor={"schema":"SereinOutpostInstalledReceipt/v1","files":inventory}; predecessor["receipt_digest"]=sha(canonical(predecessor))
    receipt_bytes=(json.dumps(predecessor,indent=2)+"\n").encode(); receipt_target="/var/lib/serein/rollback/outpost-first-install-20260901T000000Z-123456789abc/receipt.json"; write(tmp_path,receipt_target,receipt_bytes,"0600")
    controlled_receipt={"schema":"SereinOutpostControlledInventoryReceipt/v1","controlled_inventory_digest":sha(canonical(controlled))}; controlled_receipt["receipt_digest"]=sha(canonical(controlled_receipt)); controlled_receipt_bytes=(json.dumps(controlled_receipt,indent=2)+"\n").encode(); controlled_receipt_target="/var/lib/serein/rollback/outpost-prestate-20260909T115900Z-abcdef123456/controlled-inventory.json"; write(tmp_path,controlled_receipt_target,controlled_receipt_bytes,"0600")
    identity={"user":"serein-outpost","uid":900,"gid":900,"group":"serein-outpost","group_gid":900,"home":"/var/lib/serein-outpost","shell":"/usr/sbin/nologin","supplementary_groups":[]}
    selector_target="/var/lib/serein/rollback/outpost-upgrade-20260909T120000Z-abcdef123456"
    fingerprint=sha(cognition_public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
    plan={"schema":"SereinOutpostReplacementPlan/v1","source":"F:/SFOS","candidate_release_digest":release["self_digest"],"candidate_source_commit":"a"*40,"candidate_source_tree":"b"*40,"candidate_archive_sha256":"c"*64,"current_boot_id":boot,"active_inventory":inventory,"predecessor":{"receipt":receipt_target,"sha256":sha(receipt_bytes),"inventory_digest":sha(canonical(inventory))},"identity":identity,"immutable_rows":immutable,"cognition_key_id":"outpost-cognition-v1","cognition_public_key_fingerprint_sha256":fingerprint,"unit_runtime":units,"unit_stop_order":list(units),"controlled_roots":["/usr/share/serein/outpost"],"controlled_inventory":controlled,"controlled_inventory_receipt":{"receipt":controlled_receipt_target,"sha256":sha(controlled_receipt_bytes),"inventory_digest":sha(canonical(controlled))},"removed_files":["/opt/serein/obsolete.bin","/usr/share/serein/outpost/.pytest_cache/v/cache.bin"],"removed_directories":["/usr/share/serein/outpost/.pytest_cache/v","/usr/share/serein/outpost/.pytest_cache"],"rollback_selector":selector_target}
    plan["plan_digest"]=replacement_plan_digest(plan)
    adapter=Adapter(tmp_path); adapter.identities["serein-outpost"]=copy.deepcopy(identity); adapter.unit_state=copy.deepcopy(units)
    for item in controlled: adapter.directory_metadata_overrides[item["target"]]={"mode":int(item["mode"],8),"uid":item["uid"],"gid":item["gid"]}
    return adapter,source,release,plan,tmp_path/selector_target.lstrip("/")


def test_external_plan_replaces_exact_tree_removes_obsolete_and_stays_inactive(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); receipt=upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    assert (tmp_path/"opt/serein/a.bin").read_bytes()==b"new-a\n"; assert not (tmp_path/"opt/serein/obsolete.bin").exists()
    assert not (tmp_path/"usr/share/serein/outpost/.pytest_cache").exists()
    assert receipt["removed_files"][0]["predecessor"]["sha256"]==sha(b"remove-me\n")
    assert receipt["action_journal"]==[{"action":"stop","unit":"running.service"}]
    assert adapter.read_unit("running.service")["active"]=="inactive"
    assert adapter.read_unit("oneshot.service")==plan["unit_runtime"]["oneshot.service"]
    assert adapter.read_unit("failed.service")==plan["unit_runtime"]["failed.service"]
    assert adapter.read_unit("watch.path")==plan["unit_runtime"]["watch.path"]
    assert adapter.read_unit("outpost.target")==plan["unit_runtime"]["outpost.target"]
    assert adapter.read_unit("domain-install@.service")==plan["unit_runtime"]["domain-install@.service"]
    validate_upgrade_receipt(selector)


def test_rollback_restores_files_and_only_previously_running_process(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path)
    immutable={r["target"]:(tmp_path/r["target"].lstrip("/")).read_bytes() for r in plan["immutable_rows"]}
    upgrade(adapter,source,release,plan,selector,plan["plan_digest"]); receipt=rollback(adapter,selector)
    assert (tmp_path/"opt/serein/a.bin").read_bytes()==b"old-a\n"; assert (tmp_path/"opt/serein/obsolete.bin").read_bytes()==b"remove-me\n"
    assert adapter.read_unit("running.service")["active"]=="active"; assert adapter.read_unit("running.service")["substate"]=="running"
    assert adapter.read_unit("oneshot.service")==plan["unit_runtime"]["oneshot.service"]
    assert receipt["rollback_complete"] is True
    assert immutable=={r["target"]:(tmp_path/r["target"].lstrip("/")).read_bytes() for r in plan["immutable_rows"]}


def test_existing_rollback_root_is_replaced_once_and_compensates_exactly(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); target="/etc/serein-outpost/rollback-root"; before=(tmp_path/target.lstrip("/")).read_bytes()
    receipt=upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    assert (tmp_path/target.lstrip("/")).read_bytes()==(str(selector)+"\n").encode()
    groups={"kept":[row["target"] for row in receipt["kept_files"]],"replaced":[row["target"] for row in receipt["replaced_files"]],"removed":[row["target"] for row in receipt["removed_files"]],"introduced":[row["target"] for row in receipt["introduced_files"]],"generated":[row["target"] for row in receipt["introduced_generated_files"]]}
    assert groups["replaced"].count(target)==1
    assert all(target not in values for name,values in groups.items() if name!="replaced")
    rollback(adapter,selector)
    assert (tmp_path/target.lstrip("/")).read_bytes()==before


def test_metadata_only_drift_is_backed_up_replaced_and_restored(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); target="/opt/serein/keep.bin"; before=(tmp_path/target.lstrip("/")).read_bytes()
    receipt=upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    replacement=next(row for row in receipt["replaced_files"] if row["target"]==target)
    assert replacement["predecessor"]["sha256"]==replacement["candidate"]["sha256"]
    assert replacement["predecessor"]["mode"]=="0664"
    assert replacement["candidate"]["mode"]=="0644"
    assert target not in {row["target"] for row in receipt["kept_files"]}
    assert (selector/replacement["backup"]).read_bytes()==before
    rollback(adapter,selector)
    assert (tmp_path/target.lstrip("/")).read_bytes()==before


@pytest.mark.parametrize("field,error",[("current_boot_id","REPLACEMENT_BOOT_DENIED"),("candidate_source_commit","REPLACEMENT_SOURCE_COMMIT_DENIED"),("removed_files","REMOVED_FILES_SET_DENIED")])
def test_exact_plan_drift_fails_before_selector(tmp_path,field,error):
    adapter,source,release,plan,selector=fixture(tmp_path); plan[field]=[] if field=="removed_files" else "wrong"; plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match=error): upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    assert not selector.exists()


def test_predecessor_receipt_and_inventory_are_both_bound(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); plan["predecessor"]["inventory_digest"]="0"*64; plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match="PREDECESSOR_INVENTORY_BINDING_DENIED"): validate_replacement_plan(adapter,release,plan,plan["plan_digest"])
    assert not selector.exists()


def test_unlisted_predecessor_file_is_not_silently_deleted(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); plan["removed_files"].append("/opt/serein/foreign.bin"); plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match="REMOVED_FILES_SET_DENIED"): upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    assert not selector.exists()


def test_unbound_hidden_residue_fails_exhaustive_inventory_before_selector(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); write(tmp_path,"/usr/share/serein/outpost/__pycache__/foreign.pyc",b"foreign\n")
    with pytest.raises(TransactionError,match="CONTROLLED_INVENTORY_NOT_EXHAUSTIVE"): upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    assert not selector.exists()


def test_controlled_symlink_fails_closed_without_following(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); link=tmp_path/"usr/share/serein/outpost/cache-link"
    try: link.symlink_to(tmp_path/"opt/serein",target_is_directory=True)
    except OSError: pytest.skip("symlink creation unavailable")
    with pytest.raises(TransactionError,match="CONTROLLED_SYMLINK_DENIED"): upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    assert not selector.exists()


@pytest.mark.parametrize("point",tuple(range(1,45)))
def test_injected_mutation_failure_compensates_when_receipt_exists(tmp_path,point):
    adapter,source,release,plan,selector=fixture(tmp_path); before={p.relative_to(tmp_path).as_posix():p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}; adapter.fail_after=point
    with pytest.raises(TransactionError,match="INJECTED_WRITE_FAILURE"): upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    for relative,data in before.items(): assert (tmp_path/relative).read_bytes()==data
    if selector.exists() and (selector/"upgrade-receipt.json").exists(): assert validate_upgrade_receipt(selector)["rollback_complete"] is True


def test_foreign_removed_path_collision_fails_closed_but_restores_running_process(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    write(tmp_path,"/opt/serein/obsolete.bin",b"foreign\n")
    with pytest.raises(TransactionError,match="ROLLBACK_REMOVED_COLLISION_DENIED"): rollback(adapter,selector)
    assert adapter.read_unit("running.service")["active"]=="active"
    assert validate_upgrade_receipt(selector)["rollback_complete"] is False


def test_immutable_metadata_drift_is_denied(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); plan["immutable_rows"][0]["mode"]="0600"; plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match="IMMUTABLE_METADATA_DENIED"): validate_replacement_plan(adapter,release,plan,plan["plan_digest"])


def test_cognition_keypair_mismatch_is_denied(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); target="/usr/share/serein/outpost/cognition-verification.pem"
    data=ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo); write(tmp_path,target,data,"0644")
    binding=next(row for row in plan["immutable_rows"] if row["target"]==target); binding.update(bytes=len(data),sha256=sha(data)); rebind_controlled(plan,tmp_path,target,data); plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match="COGNITION_KEYPAIR_DENIED"): validate_replacement_plan(adapter,release,plan,plan["plan_digest"])


def test_tls_keypair_mismatch_is_denied(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); target="/etc/serein/tls/serein-backend-key.pem"
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048); data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()); write(tmp_path,target,data,"0600")
    binding=next(row for row in plan["immutable_rows"] if row["target"]==target); binding.update(bytes=len(data),sha256=sha(data)); plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match="TLS_KEYPAIR_DENIED"): validate_replacement_plan(adapter,release,plan,plan["plan_digest"])


def test_candidate_selectors_and_unit_allowlist_are_exact(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); plan["candidate_source_tree"]="wrong"; plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match="REPLACEMENT_SOURCE_TREE_DENIED"): validate_replacement_plan(adapter,release,plan,plan["plan_digest"])
    plan["candidate_source_tree"]="b"*40; plan["candidate_archive_sha256"]="wrong"; plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match="REPLACEMENT_ARCHIVE_DENIED"): validate_replacement_plan(adapter,release,plan,plan["plan_digest"])
    plan["candidate_archive_sha256"]="c"*64; plan["unit_runtime"]["foreign.service"]={"enabled":"disabled","active":"inactive","substate":"dead","main_pid":0}; plan["unit_stop_order"].append("foreign.service"); plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match="UNIT_RUNTIME_DENOMINATOR_DENIED"): validate_replacement_plan(adapter,release,plan,plan["plan_digest"])


def test_external_plan_authority_digest_is_required(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path)
    with pytest.raises(TransactionError,match="REPLACEMENT_PLAN_AUTHORITY_DENIED"): validate_replacement_plan(adapter,release,plan,"0"*64)


def test_nonservice_units_normalize_missing_pid_and_receive_no_actions(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path); receipt=upgrade(adapter,source,release,plan,selector,plan["plan_digest"])
    assert {row["unit"] for row in receipt["action_journal"]}=={"running.service"}
    assert receipt["unit_prestate"]["watch.path"]["main_pid"]==0
    assert receipt["unit_prestate"]["outpost.target"]["main_pid"]==0
    assert adapter.read_unit("watch.path")==plan["unit_runtime"]["watch.path"]
    assert adapter.read_unit("outpost.target")==plan["unit_runtime"]["outpost.target"]


@pytest.mark.parametrize("unit,state,error",[
    ("watch.path",{"enabled":"enabled","active":"active","substate":"waiting","main_pid":9},"UNIT_RUNTIME_NONPROCESS_PID_DENIED"),
    ("outpost.target",{"enabled":"static","active":"active","substate":"active","main_pid":1},"UNIT_RUNTIME_NONPROCESS_PID_DENIED"),
    ("running.service",{"enabled":"enabled","active":"active","substate":"running"},"UNIT_RUNTIME_MAINPID_DENIED"),
])
def test_unit_type_runtime_schema_fails_closed(tmp_path,unit,state,error):
    adapter,source,release,plan,selector=fixture(tmp_path); plan["unit_runtime"][unit]=state; plan["plan_digest"]=replacement_plan_digest(plan)
    with pytest.raises(TransactionError,match=error): validate_replacement_plan(adapter,release,plan,plan["plan_digest"])


def real_adapter_for_template():
    adapter=object.__new__(RealAdapter); adapter.root=None; adapter.read_unit=lambda unit:{"enabled":"static","active":"inactive"}
    return adapter


def test_template_unit_never_calls_invalid_systemctl_show(monkeypatch):
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        if "list-units" in command: return SimpleNamespace(stdout="")
        if "list-unit-files" in command: return SimpleNamespace(stdout="domain-install@.service static\n")
        raise AssertionError("template must not call systemctl show")
    monkeypatch.setattr("subprocess.run",run)
    assert read_runtime(real_adapter_for_template(),"domain-install@.service")=={"enabled":"static","active":"inactive","substate":"dead","main_pid":0}
    assert all("show" not in command for command in calls)


@pytest.mark.parametrize("loaded,installed",[("domain-install@alpha.service loaded active running\n","domain-install@.service static\n"),("","domain-install@.service static\ndomain-install@alpha.service enabled\n")])
def test_template_instances_cannot_be_hidden(monkeypatch,loaded,installed):
    def run(command,**kwargs):
        if "list-units" in command: return SimpleNamespace(stdout=loaded)
        if "list-unit-files" in command: return SimpleNamespace(stdout=installed)
        raise AssertionError("unexpected systemctl call")
    monkeypatch.setattr("subprocess.run",run)
    with pytest.raises(TransactionError,match="UNIT_TEMPLATE_INSTANCE_DENIED"): read_runtime(real_adapter_for_template(),"domain-install@.service")


def migration_fixture(tmp_path):
    adapter,source,release,plan,selector=fixture(tmp_path)
    legacy={"self_digest":"sha256:"+"d"*64}
    data=(json.dumps(legacy,sort_keys=True)+"\n").encode()
    target="/usr/share/serein/outpost/release-manifest.json"
    write(tmp_path,target,data)
    next(row for row in plan["active_inventory"] if row["target"]==target).update(bytes=len(data),sha256=sha(data))
    predecessor=json.loads((tmp_path/plan["predecessor"]["receipt"].lstrip("/")).read_text())
    next(row for row in predecessor["files"] if row["target"]==target).update(bytes=len(data),sha256=sha(data))
    predecessor["receipt_digest"]=sha(canonical({k:v for k,v in predecessor.items() if k!="receipt_digest"}))
    predecessor_bytes=(json.dumps(predecessor,indent=2)+"\n").encode(); write(tmp_path,plan["predecessor"]["receipt"],predecessor_bytes,"0600")
    plan["predecessor"].update(sha256=sha(predecessor_bytes),inventory_digest=sha(canonical(plan["active_inventory"])))
    rebind_controlled(plan,tmp_path,target,data)
    plan["plan_digest"]=replacement_plan_digest(plan)
    launcher=tmp_path/"launcher"; launcher.write_bytes(b"#!/usr/bin/python3\n"); launcher.chmod(0o755)
    release["install_files"].append({"path":"install/generation_launcher.py","source":"install/generation_launcher.py","target":"/usr/libexec/serein/outpost-generation-launcher","bytes":len(launcher.read_bytes()),"sha256":sha(launcher.read_bytes()),"mode":"0755","uid":0,"gid":0})
    return adapter,release,plan,selector,launcher


def test_flat_predecessor_migrates_without_changing_legacy_tree(tmp_path):
    adapter,release,plan,selector,launcher=migration_fixture(tmp_path)
    before={p.relative_to(tmp_path).as_posix():p.read_bytes() for p in (tmp_path/"usr/share/serein/outpost").rglob("*") if p.is_file()}
    receipt=migrate_flat_predecessor(adapter,release,plan,selector,launcher)
    generation=tmp_path/"usr/share/serein/outpost-generations"/("d"*64)
    assert receipt["activated"] is False
    assert (generation/"release-manifest.json").is_file()
    assert before=={p.relative_to(tmp_path).as_posix():p.read_bytes() for p in (tmp_path/"usr/share/serein/outpost").rglob("*") if p.is_file()}
    current=tmp_path/"var/lib/serein-outpost/generation-state/current.json"
    value,resolved=read_selector(current,tmp_path/"usr/share/serein/outpost-generations")
    assert value["generation"]=="d"*64 and resolved==generation


def test_flat_migration_rollback_removes_only_new_control_plane(tmp_path):
    adapter,release,plan,selector,launcher=migration_fixture(tmp_path)
    legacy=(tmp_path/"usr/share/serein/outpost/release-manifest.json").read_bytes()
    migrate_flat_predecessor(adapter,release,plan,selector,launcher)
    receipt=rollback_flat_migration(adapter,selector)
    assert receipt["rollback_complete"] is True
    assert (tmp_path/"usr/share/serein/outpost/release-manifest.json").read_bytes()==legacy
    assert not (tmp_path/"usr/share/serein/outpost-generations"/("d"*64)).exists()
    assert not (tmp_path/"var/lib/serein-outpost/generation-state/current.json").exists()


def test_flat_migration_rewrites_only_bound_outpost_unit_and_rollback_is_exact(tmp_path):
    adapter,release,plan,selector,launcher=migration_fixture(tmp_path)
    target="/etc/systemd/system/serein-outpost-stage1-install.service"
    before=b"[Service]\nExecStart=/usr/bin/python3 -B /usr/share/serein/outpost/install/stage1_transaction_runner.py kernel\n"
    write(tmp_path,target,before)
    unit_row=row(target,before); plan["active_inventory"].append(unit_row)
    receipt_path=tmp_path/plan["predecessor"]["receipt"].lstrip("/")
    predecessor=json.loads(receipt_path.read_text()); predecessor["files"].append(unit_row)
    predecessor["receipt_digest"]=sha(canonical({k:v for k,v in predecessor.items() if k!="receipt_digest"}))
    predecessor_bytes=(json.dumps(predecessor,indent=2)+"\n").encode(); receipt_path.write_bytes(predecessor_bytes); receipt_path.chmod(0o600)
    plan["predecessor"].update(sha256=sha(predecessor_bytes),inventory_digest=sha(canonical(plan["active_inventory"])))
    plan["plan_digest"]=replacement_plan_digest(plan)
    migrate_flat_predecessor(adapter,release,plan,selector,launcher)
    changed=(tmp_path/target.lstrip("/")).read_text()
    assert "outpost-generation-launcher install/stage1_transaction_runner.py kernel" in changed
    rollback_flat_migration(adapter,selector)
    assert (tmp_path/target.lstrip("/")).read_bytes()==before


def test_generation_selector_rejects_symlink(tmp_path):
    target=tmp_path/"selector.json"; target.write_text("{}")
    link=tmp_path/"current.json"
    try: link.symlink_to(target)
    except OSError: pytest.skip("symlink creation unavailable")
    with pytest.raises(LaunchDenied,match="GENERATION_SELECTOR_TYPE_DENIED"):
        read_selector(link,tmp_path/"generations")


def test_flat_migration_every_failure_boundary_preserves_legacy_and_removes_residue(tmp_path):
    probe=tmp_path/"probe"; probe.mkdir(); adapter,release,plan,selector,launcher=migration_fixture(probe)
    migrate_flat_predecessor(adapter,release,plan,selector,launcher); boundaries=adapter.writes
    for point in range(1,boundaries+1):
        case=tmp_path/f"case-{point}"; case.mkdir(); adapter,release,plan,selector,launcher=migration_fixture(case)
        legacy=(case/"usr/share/serein/outpost/release-manifest.json").read_bytes(); adapter.fail_after=point
        with pytest.raises(TransactionError,match="INJECTED_WRITE_FAILURE"):
            migrate_flat_predecessor(adapter,release,plan,selector,launcher)
        assert (case/"usr/share/serein/outpost/release-manifest.json").read_bytes()==legacy
        assert not (case/"usr/share/serein/outpost-generations"/("d"*64)).exists()
        assert not (case/"var/lib/serein-outpost/generation-state/current.json").exists()


def test_flat_migration_denies_launcher_symlink_and_lock_collision(tmp_path):
    adapter,release,plan,selector,launcher=migration_fixture(tmp_path)
    real=tmp_path/"real-launcher"; launcher.rename(real); launcher.symlink_to(real)
    with pytest.raises(TransactionError,match="GENERATION_LAUNCHER_SOURCE_DENIED"):
        migrate_flat_predecessor(adapter,release,plan,selector,launcher)
    launcher.unlink(); real.rename(launcher)
    lock=tmp_path/"var/lib/serein/rollback/.outpost-generation-migration.lock"; lock.write_text("held")
    with pytest.raises(TransactionError,match="GENERATION_TRANSACTION_LOCKED"):
        migrate_flat_predecessor(adapter,release,plan,selector,launcher)


def test_generation_inventory_metadata_tamper_denied(tmp_path):
    adapter,release,plan,selector,launcher=migration_fixture(tmp_path)
    migrate_flat_predecessor(adapter,release,plan,selector,launcher)
    generation=tmp_path/"usr/share/serein/outpost-generations"/("d"*64)
    target=generation/"release-manifest.json"; target.chmod(0o600)
    with pytest.raises(LaunchDenied,match="GENERATION_FILE_POLICY_DENIED"):
        read_selector(tmp_path/"var/lib/serein-outpost/generation-state/current.json",tmp_path/"usr/share/serein/outpost-generations")


def test_selector_uses_only_lkg_after_invalid_current(tmp_path,capsys):
    adapter,release,plan,selector,launcher=migration_fixture(tmp_path)
    migrate_flat_predecessor(adapter,release,plan,selector,launcher)
    state=tmp_path/"var/lib/serein-outpost/generation-state"; (state/"current.json").write_text("{}")
    value,_,selected=select_generation(state/"current.json",state/"lkg.json",tmp_path/"usr/share/serein/outpost-generations")
    assert selected=="lkg" and value["generation"]=="d"*64
    assert "SereinOutpostGenerationRecoveryWitness/v1" in capsys.readouterr().err


def test_launcher_executes_selected_entrypoint_as_package_module(tmp_path,monkeypatch):
    generation=tmp_path/("d"*64); target=generation/"outpost/service.py"; target.parent.mkdir(parents=True); target.write_text("pass\n")
    calls=[]
    monkeypatch.setattr("install.generation_launcher.select_generation",lambda *args:({"generation":"d"*64},generation,"current"))
    monkeypatch.setattr("os.execve",lambda executable,argv,environment:calls.append((executable,argv,environment)))
    launch(tmp_path/"current.json",tmp_path,"outpost/service.py",["--probe"])
    assert calls[0][1]==["/usr/bin/python3","-B","-m","outpost.service","--probe"]
    assert calls[0][2]["PYTHONPATH"].endswith("/"+("d"*64))


@pytest.mark.parametrize("target",("current","lkg","launcher","generation"))
def test_migration_rollback_denies_control_plane_drift_before_effect(tmp_path,target):
    adapter,release,plan,selector,launcher_source=migration_fixture(tmp_path)
    migrate_flat_predecessor(adapter,release,plan,selector,launcher_source)
    legacy=(tmp_path/"usr/share/serein/outpost/release-manifest.json").read_bytes()
    paths={
        "current":tmp_path/"var/lib/serein-outpost/generation-state/current.json",
        "lkg":tmp_path/"var/lib/serein-outpost/generation-state/lkg.json",
        "launcher":tmp_path/"usr/libexec/serein/outpost-generation-launcher",
        "generation":tmp_path/"usr/share/serein/outpost-generations"/("d"*64)/"release-manifest.json",
    }
    paths[target].write_bytes(paths[target].read_bytes()+b"drift")
    with pytest.raises((TransactionError,LaunchDenied)):
        rollback_flat_migration(adapter,selector)
    assert (tmp_path/"usr/share/serein/outpost/release-manifest.json").read_bytes()==legacy
    assert (tmp_path/"usr/libexec/serein/outpost-generation-launcher").exists()


@pytest.mark.parametrize("drift_kind",("file","symlink"))
def test_migration_rollback_denies_late_generation_drift_after_unit_restore(tmp_path,drift_kind):
    adapter,release,plan,selector,launcher_source=migration_fixture(tmp_path)
    unit="/etc/systemd/system/serein-outpost-stage1-install.service"
    before=b"[Service]\nExecStart=/usr/bin/python3 -B /usr/share/serein/outpost/install/stage1_transaction_runner.py kernel\n"
    write(tmp_path,unit,before)
    unit_row=row(unit,before); plan["active_inventory"].append(unit_row)
    predecessor_path=tmp_path/plan["predecessor"]["receipt"].lstrip("/")
    predecessor=json.loads(predecessor_path.read_text()); predecessor["files"].append(unit_row)
    predecessor["receipt_digest"]=sha(canonical({k:v for k,v in predecessor.items() if k!="receipt_digest"}))
    predecessor_bytes=(json.dumps(predecessor,indent=2)+"\n").encode(); predecessor_path.write_bytes(predecessor_bytes); predecessor_path.chmod(0o600)
    plan["predecessor"].update(sha256=sha(predecessor_bytes),inventory_digest=sha(canonical(plan["active_inventory"])))
    plan["plan_digest"]=replacement_plan_digest(plan)
    migrate_flat_predecessor(adapter,release,plan,selector,launcher_source)
    generation=tmp_path/"usr/share/serein/outpost-generations"/("d"*64)
    foreign=generation/"foreign"
    original_reload=adapter.daemon_reload
    def inject_after_reload():
        original_reload()
        if drift_kind=="file": foreign.write_bytes(b"external\n")
        else:
            try: foreign.symlink_to(generation/"release-manifest.json")
            except OSError: pytest.skip("symlink creation unavailable")
    adapter.daemon_reload=inject_after_reload
    with pytest.raises(TransactionError,match="GENERATION_ROLLBACK_FINAL_INVENTORY_DENIED"):
        rollback_flat_migration(adapter,selector)
    assert foreign.is_symlink() if drift_kind=="symlink" else foreign.read_bytes()==b"external\n"
    assert (tmp_path/unit.lstrip("/")).read_bytes()==before
    assert (tmp_path/"var/lib/serein-outpost/generation-state/current.json").is_file()
    assert (tmp_path/"usr/libexec/serein/outpost-generation-launcher").is_file()
