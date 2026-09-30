"""Local transaction proof only; fixtures are not a complete/admitted Kernel."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_SPEC = importlib.util.spec_from_file_location(
    "kernel_install_boundary", Path(__file__).parents[1] / "install/kernel_first_install.py")
txn = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(txn)
BOOT = "11111111-2222-3333-8444-555555555555"


def fixture(tmp_path):
    root, source = tmp_path / "root", tmp_path / "source"
    boot = root / "proc/sys/kernel/random/boot_id"
    boot.parent.mkdir(parents=True)
    boot.write_text(BOOT)
    machine_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    machine = root / "etc/machine-id"
    machine.parent.mkdir(parents=True)
    machine.write_text(machine_id + "\n", encoding="ascii")
    machine.chmod(0o444)
    (root / "var/lib/serein/rollback").mkdir(parents=True)
    source.mkdir()
    rows = []
    for branch in txn.ORDER:
        name = branch.lower() + ".py"
        data = (branch + "\n").encode()
        (source / name).write_bytes(data)
        rows.append(dict(branch=branch, source=name,
                         target="/usr/lib/serein/kernel/" + name,
                         bytes=len(data), sha256=txn.sha(data), mode="0644"))
    native_source = Path(__file__).parents[1] / "payload/serein_stage1/domain_identity.py"
    native_data = native_source.read_bytes()
    native_relative = "payload/serein_stage1/domain_identity.py"
    (source / native_relative).parent.mkdir(parents=True)
    (source / native_relative).write_bytes(native_data)
    rows.insert(1, dict(branch="AUTHORITY", source=native_relative,
                        target="/usr/lib/python3/dist-packages/serein_stage1/domain_identity.py",
                        bytes=len(native_data), sha256=txn.sha(native_data), mode="0644"))
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    anchor = txn.target(root, txn.AUTHORITY)
    anchor.parent.mkdir(parents=True)
    anchor.write_bytes(public)

    def identity(user, group):
        return dict(user=user, group=group, uid=0, gid=0, primary_gid=0, members=[])

    plan = dict(schema=txn.SCHEMA, target_vm_id="VM4010",
                source_parent="9"*40, source_commit="a"*40, source_tree="b"*40,
                current_boot_id=BOOT, outpost_identity=identity("serein-outpost", "serein-outpost"),
                replay_identity=identity("serein-stage1", "serein-stage1"),
                payload=rows, rollback_selector="/var/lib/serein/rollback/kernel-first-install-20260930T120000Z-abcdef123456",
                authority_sha256=txn.sha(public), archive_sha256="c"*64,
                source_receipt_sha256="d"*64, source_inventory_digest="sha256:"+"e"*64,
                reserved_domain_ids=[], host_projection_digest="f"*64)
    machine_raw = machine.read_bytes()
    machine_row = {"target":"/etc/machine-id","bytes":len(machine_raw),
                   "sha256":txn.sha(machine_raw),"mode":"0444"}
    plan["host_identity"] = {"machine_id":machine_id,
                             "file":txn.target_prestate(
                                 root,machine_row,include_bytes=True)[0]}

    def seal(*, capture_prestate=True):
        declared = [[r["source"], r["bytes"], r["sha256"], r["mode"]] for r in plan["payload"]]
        manifest = dict(schema="SereinPortableKernelRelease/v1",
                        classification="PUBLIC_KERNEL_COMPANION_FOUNDATION_INACTIVE",
                        branch_order=list(txn.ORDER), payload=declared,
                        payload_digest="sha256:"+txn.sha(txn.canonical(declared)),
                        install_denominator_digest="sha256:"+txn.sha(txn.canonical(plan["payload"])),
                        activation="OUTPOST_ONLY_AFTER_INACTIVE_PROOF")
        manifest["self_digest"] = "sha256:"+txn.sha(txn.canonical(manifest))
        (source / "release-manifest.json").write_bytes(txn.canonical(manifest))
        plan["release_digest"] = manifest["self_digest"]
        if capture_prestate:
            plan["target_prestate"] = txn.capture_target_prestate(root, plan["payload"])
        material = txn.prepare_native_identity(
            source, plan, private, reserved_ids=set(plan["reserved_domain_ids"]),
            random_bytes=lambda size: bytes.fromhex("0123456789abcdef"))
        plan["native_identity"] = material["binding"]
        identity.native_material = material
        plan.pop("signature", None)
        plan["signature"] = base64.urlsafe_b64encode(
            private.sign(txn.canonical(plan))).decode().rstrip("=")
    seal()
    return root, source, plan, identity, seal


def test_complete_branch_package_stays_inactive_and_preserves_anchor(tmp_path):
    root, source, plan, identity, _ = fixture(tmp_path)
    anchor = txn.target(root, txn.AUTHORITY).read_bytes()
    result = txn.install(root, source, plan, identity_lookup=identity,
                         native_material=identity.native_material)
    assert result["status"] == "INSTALLED_INACTIVE"
    assert result["branch_order"] == list(txn.ORDER)
    assert txn.target(root, txn.AUTHORITY).read_bytes() == anchor
    journal = json.loads((txn.target(root, plan["rollback_selector"]) / txn.ROLLBACK_JOURNAL).read_text())
    assert journal["state"] == "INSTALLED_INACTIVE"
    assert [row["state"] for row in plan["target_prestate"]] == ["ABSENT"] * 9
    assert not (root / "etc/systemd/system/multi-user.target.wants").exists()
    assert txn.rollback(root, txn.target(root, plan["rollback_selector"]) / "receipt.json")["status"] == "ROLLBACK_COMPLETE"
    assert all(not txn.target(root, row["target"]).exists() for row in plan["payload"])


def test_host_machine_identity_is_read_only_0444_and_not_rollback_payload(tmp_path):
    root, source, plan, identity, _ = fixture(tmp_path)
    machine = txn.target(root, "/etc/machine-id")
    before = machine.stat()
    raw = machine.read_bytes()
    result = txn.install(root, source, plan, identity_lookup=identity,
                         native_material=identity.native_material)
    after = machine.stat()
    assert raw == machine.read_bytes() == b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n"
    assert (after.st_dev, after.st_ino, after.st_mode & 0o777) == (
        before.st_dev, before.st_ino, 0o444)
    receipt_path = txn.target(root, result["receipt"])
    receipt = json.loads(receipt_path.read_bytes())
    assert all(row["target"] != "/etc/machine-id" for row in receipt["replacements"])
    assert all(row["target"] != "/etc/machine-id" for row in receipt["prestate"])
    assert txn.rollback(root, receipt_path)["status"] == "ROLLBACK_COMPLETE"
    assert machine.read_bytes() == raw and machine.stat().st_ino == before.st_ino


def test_signed_bad_machine_id_mismatch_fails_before_effect(tmp_path):
    root, source, plan, identity, seal = fixture(tmp_path)
    plan["host_identity"]["machine_id"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    seal(capture_prestate=False)
    with pytest.raises(txn.Denied, match="HOST_IDENTITY_MISMATCH"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=identity.native_material)
    assert not txn.target(root, plan["rollback_selector"]).exists()
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)


def test_machine_id_inode_change_after_signed_plan_fails_before_effect(tmp_path):
    root, source, plan, identity, _ = fixture(tmp_path)
    machine = txn.target(root, "/etc/machine-id")
    original = machine.stat().st_ino
    replacement = machine.with_name(".machine-id-replacement")
    replacement.write_bytes(machine.read_bytes());replacement.chmod(0o444)
    os.replace(replacement, machine)
    assert machine.stat().st_ino != original
    with pytest.raises(txn.Denied, match="HOST_IDENTITY_CHANGED"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=identity.native_material)
    assert machine.read_bytes() == b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n"
    assert not txn.target(root, plan["rollback_selector"]).exists()


def test_machine_id_change_inside_first_effect_boundary_writes_no_private_artifact(tmp_path):
    root, source, plan, identity, _ = fixture(tmp_path)
    machine = txn.target(root, "/etc/machine-id")
    changed = []
    def boundary():
        if not changed:
            machine.write_text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", encoding="ascii")
            machine.chmod(0o444);changed.append(True)
    with pytest.raises(txn.Denied, match="KERNEL_TARGET_PRESTATE_CONTENT_DENIED"):
        txn.install(root, source, plan, boundary=boundary, identity_lookup=identity,
                    native_material=identity.native_material)
    assert changed and machine.read_text().strip() == "a" * 32
    assert not txn.target(root, plan["rollback_selector"]).exists()
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)


def test_native_identity_files_are_private_unexported_and_rollback_owned(tmp_path):
    root, source, plan, identity, _ = fixture(tmp_path)
    material = identity.native_material
    result = txn.install(root, source, plan, identity_lookup=identity,
                         native_material=material)
    private_path = txn.target(root, txn.NATIVE_KEY)
    registry_path = txn.target(root, txn.NATIVE_REGISTRY)
    assert private_path.read_bytes() == material["private"]
    assert registry_path.read_bytes() == material["registry"]
    assert private_path.stat().st_mode & 0o777 == 0o600
    assert registry_path.stat().st_mode & 0o777 == 0o644
    if os.name != "nt":
        assert (private_path.stat().st_uid, private_path.stat().st_gid) == (0, 0)
        assert (registry_path.stat().st_uid, registry_path.stat().st_gid) == (0, 0)
    receipt_path = txn.target(root, result["receipt"])
    receipt_raw = receipt_path.read_bytes()
    assert material["private"] not in receipt_raw
    assert material["registry"] not in receipt_raw
    assert "native_material" not in result and result["secret_exported"] is False
    assert txn.rollback(root, receipt_path)["status"] == "ROLLBACK_COMPLETE"
    assert not private_path.exists() and not registry_path.exists()


@pytest.mark.parametrize("name", (txn.NATIVE_KEY, txn.NATIVE_REGISTRY))
def test_native_identity_collision_preserves_foreign_existing_file(tmp_path, name):
    root, source, plan, identity, _ = fixture(tmp_path)
    collision = txn.target(root, name)
    collision.parent.mkdir(parents=True, exist_ok=True)
    collision.write_bytes(b"pre-existing identity custody\n")
    collision.chmod(0o600 if name == txn.NATIVE_KEY else 0o644)
    before = collision.stat()
    with pytest.raises(txn.Denied, match="PRESTATE|COLLISION"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=identity.native_material)
    assert collision.read_bytes() == b"pre-existing identity custody\n"
    assert collision.stat().st_ino == before.st_ino
    assert not txn.target(root, plan["rollback_selector"]).exists()


@pytest.mark.parametrize("field", ("private", "registry", "binding"))
def test_native_identity_tamper_fails_before_effect(tmp_path, field):
    root, source, plan, identity, _ = fixture(tmp_path)
    material = copy.deepcopy(identity.native_material)
    if field == "binding":
        material["binding"]["checkpoint"] = "0" * 64
    else:
        material[field] += b"tamper"
    with pytest.raises(txn.Denied, match="NATIVE_IDENTITY"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=material)
    assert not txn.target(root, plan["rollback_selector"]).exists()
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)


@pytest.mark.parametrize("same_bytes", [False, True])
def test_late_collision_keeps_foreign_inode_and_bytes(tmp_path, same_bytes):
    root, source, plan, identity, _ = fixture(tmp_path)
    collision = txn.target(root, plan["payload"][0]["target"])
    foreign = (source / plan["payload"][0]["source"]).read_bytes() if same_bytes else b"EXISTING OWNER\n"
    foreign_inode = []

    def boundary():
        if collision.parent.exists() and list(collision.parent.glob(".kernel-*")) and not foreign_inode:
            collision.write_bytes(foreign)
            collision.chmod(0o644)
            foreign_inode.append(collision.stat().st_ino)

    with pytest.raises(txn.Denied, match="COLLISION"):
        txn.install(root, source, plan, boundary=boundary, identity_lookup=identity,
                    native_material=identity.native_material)
    assert collision.read_bytes() == foreign
    assert collision.stat().st_ino == foreign_inode[0]
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)


def test_existing_payload_never_replaced(tmp_path):
    root, source, plan, identity, _ = fixture(tmp_path)
    existing = txn.target(root, plan["payload"][0]["target"])
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"VM4010 legacy behavior")
    before = existing.stat()
    with pytest.raises(txn.Denied, match="PRESTATE"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=identity.native_material)
    assert existing.read_bytes() == b"VM4010 legacy behavior"
    assert existing.stat().st_ino == before.st_ino
    assert not txn.target(root, plan["rollback_selector"]).exists()


def test_exact_mixed_prestate_preserves_inode_bytes_and_custody(tmp_path):
    root, source, plan, identity, seal = fixture(tmp_path)
    preserved_row = plan["payload"][1]
    preserved = txn.target(root, preserved_row["target"])
    preserved.parent.mkdir(parents=True, exist_ok=True)
    preserved.write_bytes((source / preserved_row["source"]).read_bytes())
    preserved.chmod(int(preserved_row["mode"], 8))
    before = preserved.stat()
    seal()
    states = [(row["target"], row["state"]) for row in plan["target_prestate"]]
    assert states[:5] == [(name, "ABSENT") for name in txn.GENERATED]
    assert [target for target, _ in states[5:]] == [row["target"] for row in plan["payload"]]
    assert dict(states)[preserved_row["target"]] == "PRESENT_PRESERVED"

    result = txn.install(root, source, plan, identity_lookup=identity,
                         native_material=identity.native_material)
    assert result["status"] == "INSTALLED_INACTIVE"
    after = preserved.stat()
    assert (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
            after.st_mode & 0o777, after.st_nlink) == (
                before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                before.st_mode & 0o777, before.st_nlink)
    assert preserved.read_bytes() == (source / preserved_row["source"]).read_bytes()

    receipt = txn.target(root, plan["rollback_selector"]) / "receipt.json"
    assert txn.rollback(root, receipt)["status"] == "ROLLBACK_COMPLETE"
    assert preserved.exists() and preserved.stat().st_ino == before.st_ino
    for row in plan["payload"]:
        if row is not preserved_row:
            assert not txn.target(root, row["target"]).exists()
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)


@pytest.mark.parametrize("fault", ("bytes", "mode", "hardlink", "symlink"))
def test_invalid_present_payload_is_rejected_during_capture(tmp_path, fault):
    root, source, plan, _, seal = fixture(tmp_path)
    row = plan["payload"][0]
    path = txn.target(root, row["target"])
    path.parent.mkdir(parents=True, exist_ok=True)
    if fault == "symlink":
        path.symlink_to(source / row["source"])
    else:
        path.write_bytes((source / row["source"]).read_bytes()
                         if fault != "bytes" else b"wrong bytes\n")
        path.chmod(0o600 if fault == "mode" else int(row["mode"], 8))
        if fault == "hardlink":
            os.link(path, tmp_path / "second-link")
    with pytest.raises(txn.Denied, match="PRESTATE"):
        seal()


def test_generated_target_must_be_absent_during_capture(tmp_path):
    root, _, _, _, seal = fixture(tmp_path)
    generated = txn.target(root, txn.KEY)
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_bytes(b"x" * 32)
    generated.chmod(0o600)
    with pytest.raises(txn.Denied, match="PRESTATE"):
        seal()


def test_capture_to_install_drift_is_denied_before_effect(tmp_path):
    root, source, plan, identity, _ = fixture(tmp_path)
    row = plan["payload"][0]
    drift = txn.target(root, row["target"])
    drift.parent.mkdir(parents=True, exist_ok=True)
    drift.write_bytes((source / row["source"]).read_bytes())
    drift.chmod(int(row["mode"], 8))
    with pytest.raises(txn.Denied, match="PRESTATE"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=identity.native_material)
    assert drift.exists()
    assert not txn.target(root, plan["rollback_selector"]).exists()
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)


def test_preserved_drift_during_install_rolls_back_created_only(tmp_path):
    root, source, plan, identity, seal = fixture(tmp_path)
    row = plan["payload"][1]
    preserved = txn.target(root, row["target"])
    preserved.parent.mkdir(parents=True, exist_ok=True)
    preserved.write_bytes((source / row["source"]).read_bytes())
    preserved.chmod(int(row["mode"], 8))
    seal()
    changed = []

    def boundary():
        if txn.target(root, txn.KEY).exists() and not changed:
            preserved.write_bytes(b"foreign preserved drift\n")
            preserved.chmod(int(row["mode"], 8))
            changed.append(True)

    with pytest.raises(txn.Denied, match="PRESERVED|PRESTATE|CAS"):
        txn.install(root, source, plan, boundary=boundary, identity_lookup=identity,
                    native_material=identity.native_material)
    assert preserved.read_bytes() == b"foreign preserved drift\n"
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)
    for candidate in plan["payload"]:
        if candidate is not row:
            assert not txn.target(root, candidate["target"]).exists()


def test_same_bytes_inode_swap_before_first_effect_is_denied(tmp_path):
    root, source, plan, identity, seal = fixture(tmp_path)
    row = plan["payload"][1]
    preserved = txn.target(root, row["target"])
    preserved.parent.mkdir(parents=True, exist_ok=True)
    preserved.write_bytes((source / row["source"]).read_bytes())
    preserved.chmod(int(row["mode"], 8))
    seal()
    original_inode = preserved.stat().st_ino
    calls = 0

    def random_bytes(size):
        nonlocal calls
        calls += 1
        if calls == 1:
            replacement = preserved.with_name(".same-bytes-replacement")
            replacement.write_bytes(preserved.read_bytes())
            replacement.chmod(int(row["mode"], 8))
            os.replace(replacement, preserved)
            assert preserved.stat().st_ino != original_inode
        return bytes([calls]) * size

    with pytest.raises(txn.Denied, match="PRESERVED_PRESTATE_CHANGED"):
        txn.install(root, source, plan, random_bytes=random_bytes,
                    identity_lookup=identity, native_material=identity.native_material)
    assert preserved.read_bytes() == (source / row["source"]).read_bytes()
    assert preserved.stat().st_ino != original_inode
    assert not txn.target(root, plan["rollback_selector"]).exists()
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)


def test_same_bytes_inode_swap_at_final_journal_publication_rolls_back_created_only(
        tmp_path, monkeypatch):
    root, source, plan, identity, seal = fixture(tmp_path)
    row = plan["payload"][1]
    preserved = txn.target(root, row["target"])
    preserved.parent.mkdir(parents=True, exist_ok=True)
    preserved.write_bytes((source / row["source"]).read_bytes())
    preserved.chmod(int(row["mode"], 8))
    seal()
    original_inode = preserved.stat().st_ino
    original_journal_write = txn.journal_write
    swapped = []

    def journal_write(rollback, digest, state, completed, boundary, ownership=()):
        if state == "INSTALLED_INACTIVE" and not swapped:
            replacement = preserved.with_name(".same-bytes-final-replacement")
            replacement.write_bytes(preserved.read_bytes())
            replacement.chmod(int(row["mode"], 8))
            os.replace(replacement, preserved)
            swapped.append(True)
        return original_journal_write(
            rollback, digest, state, completed, boundary, ownership)

    monkeypatch.setattr(txn, "journal_write", journal_write)
    with pytest.raises(txn.Denied, match="PRESERVED_PRESTATE_CHANGED"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=identity.native_material)
    assert swapped and preserved.stat().st_ino != original_inode
    assert preserved.read_bytes() == (source / row["source"]).read_bytes()
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)
    for candidate in plan["payload"]:
        if candidate is not row:
            assert not txn.target(root, candidate["target"]).exists()


def test_authority_only_denominator_rejected_before_effect(tmp_path):
    root, source, plan, identity, seal = fixture(tmp_path)
    plan["payload"] = [row for row in plan["payload"] if row["branch"] == "AUTHORITY"]
    seal()
    with pytest.raises(txn.Denied, match="BRANCH"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=identity.native_material)
    assert not txn.target(root, plan["rollback_selector"]).exists()


@pytest.mark.parametrize("source_path", ["../outside.py", "ABSOLUTE", "nested/../../outside.py"])
def test_source_escape_rejected_before_effect(tmp_path, source_path):
    root, source, plan, identity, seal = fixture(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_bytes((source / plan["payload"][0]["source"]).read_bytes())
    (source / "nested").mkdir()
    if source_path == "ABSOLUTE":
        source_path = str(outside)
    plan["payload"][0]["source"] = source_path
    seal()
    with pytest.raises(txn.Denied, match="SOURCE_PATH"):
        txn.install(root, source, plan, identity_lookup=identity,
                    native_material=identity.native_material)
    assert not txn.target(root, plan["rollback_selector"]).exists()


def test_mixed_manifest_order_has_canonical_journal_order(tmp_path):
    root, source, plan, identity, seal = fixture(tmp_path)
    plan["payload"].reverse()
    seal()
    txn.install(root, source, plan, identity_lookup=identity,
                native_material=identity.native_material)
    receipt_path = txn.target(root, plan["rollback_selector"]) / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    assert [r["branch"] for r in receipt["replacements"]][-3:] == list(txn.ORDER)
    assert txn.rollback(root, receipt_path)["status"] == "ROLLBACK_COMPLETE"


def test_changed_source_after_validation_is_rejected(tmp_path):
    root, source, plan, identity, _ = fixture(tmp_path)
    changed = []

    def boundary():
        if not changed:
            (source / plan["payload"][0]["source"]).write_bytes(b"changed after preflight")
            changed.append(True)

    with pytest.raises(txn.Denied, match="SOURCE_HASH"):
        txn.install(root, source, plan, boundary=boundary, identity_lookup=identity,
                    native_material=identity.native_material)
    assert all(not txn.target(root, r["target"]).exists() for r in plan["payload"])
    assert not any(txn.target(root, name).exists() for name in txn.GENERATED)

