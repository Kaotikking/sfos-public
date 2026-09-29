"""Base delegation guardrails only; not an installation witness."""
import subprocess
import os
from pathlib import Path

import pytest
from install.transaction import TransactionError, enable_first_host_boot, sha

SCRIPT=Path(__file__).parents[2]/"base/installer/converge-existing.sh"
FRESH_SCRIPT=SCRIPT.with_name("late-install.sh")


def _retired_base_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "retired_base_road", SCRIPT.with_name("base-road-transaction.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_retired_base_road_exposes_no_legacy_transaction_or_private_key_mutators():
    module = _retired_base_module()
    for name in ("install", "recover", "compensate", "restore", "authority", "write_signed", "run"):
        assert not hasattr(module, name), name


@pytest.mark.parametrize("args", [
    [], ["recover", "/unused"],
    ["install", "/unused", "/unused", "CONVERGE_EXISTING", "PINNED_PUBLIC_REPOSITORY"],
    ["install", "/unused", "/unused", "BARE_INSTALL", "OFFLINE_USB_MEDIA"],
    ["unexpected"],
])
def test_retired_base_entry_denies_without_access_or_argument_translation(monkeypatch, args):
    import builtins
    import sys
    module = _retired_base_module()
    monkeypatch.setattr(sys, "argv", ["base-road-transaction.py", *args])
    def forbidden(*a, **k):
        pytest.fail("Retired Base entry must not inspect or change any target")
    # Before the correction these guards intercept the legacy call, without
    # executing its filesystem/private-key/service behavior even in a fixture.
    for name in ("install", "recover", "authority", "compensate", "restore", "run"):
        if hasattr(module, name):
            monkeypatch.setattr(module, name, forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(SystemExit) as caught:
        module.main()
    assert caught.value.code == "RETIRED_BASE_ROAD_USE_CANONICAL_INSTALL_OUTPOST"


def test_g0_target_does_not_require_later_surfaces_or_successful_host_collection():
    """PRO-132 Sep26 G0 cut; target-only contract, not runtime admission."""
    import configparser
    path=Path(__file__).parents[1]/"systemd/serein-outpost.target"
    unit=configparser.ConfigParser(interpolation=None)
    unit.read_string(path.read_text())
    assert set(unit.sections())=={"Unit","Install"}
    assert set(unit["Unit"]["Requires"].split())=={"serein-outpost.service"}
    assert set(unit["Unit"]["After"].split())=={"serein-outpost.service"}
    assert set(unit["Unit"]["Wants"].split())=={"serein-outpost-host-witness.service"}
    assert unit["Install"]["WantedBy"]=="multi-user.target"
    assert set(unit["Unit"])=={"description","requires","after","wants"}
    assert set(unit["Install"])=={"wantedby"}


def test_g0_host_witness_unit_uses_existing_unprivileged_collector_contract():
    import configparser
    import shlex
    path = Path(__file__).parents[1] / "systemd/serein-outpost-host-witness.service"
    unit = configparser.ConfigParser(interpolation=None)
    unit.read_string(path.read_text())
    assert set(unit.sections()) == {"Unit", "Service"}
    assert unit["Unit"].get("Requires", "") == ""
    assert unit["Unit"].get("Before", "") == ""
    assert unit["Unit"]["Wants"] == "network-online.target"
    service = unit["Service"]
    assert service["Type"] == "oneshot"
    assert service["User"] == service["Group"] == "serein-outpost"
    assert shlex.split(service["ExecStart"]) == [
        "/usr/libexec/serein/outpost-generation-launcher",
        "outpost/host_witness_runner.py", "--state-root",
        "/var/lib/serein-outpost/host-vitality"]
    assert service["StateDirectory"] == "serein-outpost/host-vitality"
    assert service["StateDirectoryMode"] == "0750"
    assert service["ReadWritePaths"] == "/var/lib/serein-outpost/host-vitality"
    assert service["NoNewPrivileges"] == "true"
    # The read-only GPU witness must retain access to the actual GPU devices.
    assert service.get("PrivateDevices", "false") == "false"
    assert "LoadCredential" not in service


def test_fresh_debian_delegates_to_one_package_without_partial_staging():
    source=FRESH_SCRIPT.read_text()
    assert 'ENTRY=$SOURCE/install/install-outpost.sh' in source
    assert source.count('exec /bin/sh') == 1
    assert '"$SOURCE_KIND" "$SOURCE_RECEIPT"' in source
    for forbidden in ('cp ', 'mktemp', 'chmod ', 'chown ', 'systemctl ',
                      'base-road-transaction.py', 'host_witness_runner', 'python3 ',
                      'rm -rf', 'rollback', 'reboot '):
        assert forbidden not in source
    subprocess.run(['/bin/sh','-n',str(FRESH_SCRIPT)],check=True,capture_output=True)


def test_g0_coordinator_unit_keeps_existing_unprivileged_runtime_road():
    """No Host collection, presentation or downstream prerequisite for G0."""
    import configparser
    path=Path(__file__).parents[1]/"systemd/serein-outpost.service"
    unit=configparser.ConfigParser(interpolation=None)
    unit.read_string(path.read_text())
    assert set(unit.sections())=={"Unit","Service","Install"}
    assert unit["Unit"].get("Requires", "")==""
    assert unit["Unit"]["After"]=="local-fs.target"
    service=unit["Service"]
    assert service["User"]==service["Group"]=="serein-outpost"
    assert service["Type"]=="notify" and service["NotifyAccess"]=="main"
    assert service["ExecStart"]==(
        "/usr/libexec/serein/outpost-generation-launcher outpost/service.py "
        "--host-vitality-root /var/lib/serein-outpost/host-vitality")
    assert service["CapabilityBoundingSet"]==service["AmbientCapabilities"]==""
    assert service["NoNewPrivileges"]=="yes"
    assert "LoadCredential" not in service
    assert service["StateDirectory"]=="serein-outpost/coordinator"
    assert service["StateDirectoryMode"]=="0750"
    assert unit["Install"]["WantedBy"]=="serein-outpost.target"


@pytest.mark.parametrize('args',[[],['x']*5,['x']*7])
def test_fresh_wrapper_requires_explicit_plan_digest_before_any_target_read(tmp_path,args):
    result=subprocess.run(['/bin/sh',str(FRESH_SCRIPT),*args],cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode==64 and 'usage:' in result.stderr
    assert list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('target',['/','/tmp','/target/../','/target/'])
def test_fresh_wrapper_cannot_target_running_host_or_an_arbitrary_root(tmp_path,target):
    result=subprocess.run(['/bin/sh',str(FRESH_SCRIPT),target,'absent','OFFLINE_USB_MEDIA','absent','absent','a'*64],
                          cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode==64 and 'OFFLINE_INSTALLER_TARGET_REQUIRED' in result.stderr
    assert list(tmp_path.iterdir())==[]


def test_existing_debian_delegates_once_to_existing_canonical_entry_contract():
    source=SCRIPT.read_text()
    assert 'ENTRY=$SOURCE/install/install-outpost.sh' in source
    assert 'exec /bin/sh "$ENTRY" "$SOURCE" install / "$IMMUTABLE_INPUT_PLAN" "$EXPECTED_PLAN_SHA256"' in source
    assert source.count("exec /bin/sh")==1
    assert '"$EXPECTED_PLAN_SHA256" "$SOURCE_KIND" "$SOURCE_RECEIPT"' in source
    assert "--mode source" in source and "verify-source-road.py" in source
    assert "IMMUTABLE_INPUT_PLAN_CUSTODY_DENIED" in source
    assert "CANONICAL_OUTPOST_ENTRY_UNAVAILABLE" in source


def test_base_wrapper_does_not_install_around_outpost_or_require_host_pass_first():
    source=SCRIPT.read_text()
    for forbidden in ("host_witness_runner", "WITNESS_ROOT", "HOST_GATE_DENIED",
                      "base-road-transaction.py", "ROLLBACK_BASE_REQUIRED", "NEW_OUTPOST_REQUIRED",
                      "systemctl", "mktemp", "rm -rf", "chown", "chmod"):
        assert forbidden not in source
    assert "'partitioning':False" in source and "'identity_replacement':False" in source
    assert "'reboot':False" in source


@pytest.mark.parametrize("args",[[],["x"]*5,["x"]*7])
def test_missing_or_extra_arguments_deny_before_target_effect(tmp_path,args):
    result=subprocess.run(["/bin/sh",str(SCRIPT),*args],cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode==64
    assert "usage:" in result.stderr
    assert list(tmp_path.iterdir())==[]


@pytest.mark.parametrize("sha",["","a"*63,"A"*64,"g"*64,"a"*65])
def test_missing_or_malformed_expected_plan_hash_denies_before_target_read(tmp_path,sha):
    result=subprocess.run(["/bin/sh",str(SCRIPT),*(["nonexistent"]*5),sha],cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode==64
    assert "EXPECTED_PLAN_SHA256_REQUIRED" in result.stderr
    assert list(tmp_path.iterdir())==[]


def test_conversion_script_has_valid_posix_shell_syntax():
    subprocess.run(["/bin/sh","-n",str(SCRIPT)],check=True,capture_output=True)


@pytest.fixture
def offline_root(tmp_path):
    unit = tmp_path / "target/etc/systemd/system/serein-outpost.target"
    unit.parent.mkdir(parents=True)
    (unit.parent / "multi-user.target.wants").mkdir()
    unit.write_bytes(b"[Unit]\nDescription=Offline fixture only\n[Install]\nWantedBy=multi-user.target\n")
    return tmp_path / "target", unit


def test_native_offline_enablement_creates_only_outpost_link_without_start(offline_root, monkeypatch):
    root, unit = offline_root
    calls = []
    native_run = subprocess.run
    def capture(command, **kwargs):
        calls.append(command)
        return native_run(command, **kwargs)
    monkeypatch.setattr(subprocess, "run", capture)
    result = enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)
    assert calls[0] == ["systemd-analyze", "unit-paths"]
    assert calls[1][:2] == ["systemctl", "--root"]
    assert calls[1][2] != str(root) and Path(calls[1][2]).parent == root.parent
    assert calls[1][3:] == ["enable", "serein-outpost.target"]
    assert not Path(calls[1][2]).exists()
    assert result["started"] is False
    assert result["installed"] == result["host_gate"] == "UNPROVEN"
    link = root / result["enabled_link"]
    assert link.is_symlink()
    assert {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()} == {
        "etc/systemd/system/serein-outpost.target", result["enabled_link"]}


@pytest.mark.parametrize("defect", ["wrong_hash", "extra_enablement", "conflicting_link", "host_root"])
def test_offline_enablement_denies_wrong_target_or_expanded_effect_before_command(offline_root, monkeypatch, defect):
    root, unit = offline_root
    if defect == "extra_enablement":
        unit.write_bytes(unit.read_bytes() + b"Also=unrelated.service\n")
    elif defect == "conflicting_link":
        wants = unit.parent / "multi-user.target.wants"
        wants.mkdir(exist_ok=True)
        (wants / unit.name).symlink_to("/etc/systemd/system/unrelated.target")
    digest = "0" * 64 if defect == "wrong_hash" else sha(unit.read_bytes())
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("Command must not run"))
    with pytest.raises(TransactionError, match="OFFLINE_"):
        enable_first_host_boot("/" if defect == "host_root" else root, digest, staging_parent=root.parent)


def test_successful_command_without_target_link_is_not_enablement_proof(offline_root, monkeypatch):
    root, unit = offline_root
    def incomplete(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="/etc/systemd/system\n" if command[0] == "systemd-analyze" else "")
    monkeypatch.setattr(subprocess, "run", incomplete)
    with pytest.raises(TransactionError, match="OFFLINE_ENABLEMENT_FAILED_NEW_ATOMIC_INSTALL_REQUIRED"):
        enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)


@pytest.mark.parametrize("base", ["etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system"])
@pytest.mark.parametrize("directive", ["Also=unrelated.service", "Alias=foreign.target", "WantedBy=foreign.target"])
def test_effective_install_dropins_deny_before_enablement(offline_root, monkeypatch, base, directive):
    root, unit = offline_root
    drop = root / base / "serein-outpost.target.d/override.conf"
    drop.parent.mkdir(parents=True)
    drop.write_text("[Install]\n" + directive + "\n")
    native_run = subprocess.run
    def reads_only(command, **kwargs):
        assert command == ["systemd-analyze", "unit-paths"]
        return native_run(command, **kwargs)
    monkeypatch.setattr(subprocess, "run", reads_only)
    with pytest.raises(TransactionError, match="OFFLINE_UNIT_DROPIN_DENIED"):
        enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)
    assert list((unit.parent / "multi-user.target.wants").iterdir()) == []


@pytest.mark.parametrize("name", ["serein-.target.d", "target.d"])
def test_prefix_and_type_dropins_deny(offline_root, name):
    root, unit = offline_root
    (unit.parent / name).mkdir()
    with pytest.raises(TransactionError, match="OFFLINE_UNIT_DROPIN_DENIED"):
        enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)


def test_vendor_shadow_denies(offline_root):
    root, unit = offline_root
    shadow = root / "usr/lib/systemd/system/serein-outpost.target"
    shadow.parent.mkdir(parents=True)
    shadow.write_bytes(unit.read_bytes())
    with pytest.raises(TransactionError, match="OFFLINE_UNIT_SHADOW_DENIED"):
        enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)


def test_extra_link_is_failed_install_not_success_or_predecessor_reactivation(offline_root, monkeypatch):
    root, unit = offline_root
    original = unit.read_bytes()
    native_run = subprocess.run
    def contaminated(command, **kwargs):
        result = native_run(command, **kwargs)
        if command[0] == "systemctl":
            (Path(command[2]) / "etc/systemd/system/foreign.target").symlink_to("/etc/systemd/system/unrelated.target")
        return result
    monkeypatch.setattr(subprocess, "run", contaminated)
    with pytest.raises(TransactionError, match="OFFLINE_ENABLEMENT_FAILED_NEW_ATOMIC_INSTALL_REQUIRED"):
        enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)
    assert unit.read_bytes() == original
    assert list((unit.parent / "multi-user.target.wants").iterdir()) == []
    assert not (unit.parent / "foreign.target").exists()
    assert sorted(p.name for p in root.parent.iterdir()) == ["target"]



def test_failed_native_stage_leaves_real_target_unchanged(offline_root, monkeypatch):
    root, unit = offline_root
    native_run = subprocess.run
    original = unit.read_bytes()
    def failed(command, **kwargs):
        result = native_run(command, **kwargs)
        if command[0] == "systemctl":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="injected")
        return result
    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises(TransactionError, match="NEW_ATOMIC_INSTALL_REQUIRED") as caught:
        enable_first_host_boot(root, sha(original), staging_parent=root.parent)
    assert caught.value.evidence["target_effect"] == "NONE"
    assert unit.read_bytes() == original
    assert list((unit.parent / "multi-user.target.wants").iterdir()) == []
    assert sorted(p.name for p in root.parent.iterdir()) == ["target"]


def test_exact_preexisting_link_is_not_resumed(offline_root, monkeypatch):
    root, unit = offline_root
    link = unit.parent / "multi-user.target.wants" / unit.name
    link.symlink_to("/etc/systemd/system/serein-outpost.target")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("No staging or command"))
    with pytest.raises(TransactionError, match="COLLISION_NEW_INSTALL_REQUIRED"):
        enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)
    assert os.readlink(link) == "/etc/systemd/system/serein-outpost.target"


def test_directory_swap_cannot_redirect_descriptor_commit(offline_root, monkeypatch):
    root, unit = offline_root
    wants = unit.parent / "multi-user.target.wants"
    detached = unit.parent / "detached-wants"
    outside = root.parent / "outside"
    outside.mkdir()
    native_symlink = os.symlink
    def swapped(source, destination, **kwargs):
        if kwargs.get("dir_fd") is not None:
            wants.rename(detached)
            native_symlink(str(outside), wants)
        return native_symlink(source, destination, **kwargs)
    monkeypatch.setattr(os, "symlink", swapped)
    with pytest.raises(TransactionError, match="OFFLINE_TARGET_DIRECTORY_CHANGED"):
        enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)
    assert list(outside.iterdir()) == []


def test_primary_unit_symlink_swap_at_commit_is_not_followed(offline_root, monkeypatch):
    root, unit = offline_root
    original = unit.read_bytes()
    replacement = root.parent / "foreign-unit"
    replacement.write_bytes(original)
    native_symlink = os.symlink
    def swapped(source, destination, **kwargs):
        result = native_symlink(source, destination, **kwargs)
        if kwargs.get("dir_fd") is not None:
            unit.unlink()
            native_symlink(str(replacement), unit)
        return result
    monkeypatch.setattr(os, "symlink", swapped)
    with pytest.raises(TransactionError, match="OFFLINE_TARGET_COMMIT_DENIED"):
        enable_first_host_boot(root, sha(original), staging_parent=root.parent)
    assert replacement.read_bytes() == original


def test_commit_eexist_denies_without_replacing_link(offline_root, monkeypatch):
    root, unit = offline_root
    native_symlink = os.symlink
    def collision(source, destination, **kwargs):
        if kwargs.get("dir_fd") is not None:
            native_symlink("/preserved-collision", destination, **kwargs)
        return native_symlink(source, destination, **kwargs)
    monkeypatch.setattr(os, "symlink", collision)
    with pytest.raises(TransactionError, match="COLLISION_NEW_INSTALL_REQUIRED"):
        enable_first_host_boot(root, sha(unit.read_bytes()), staging_parent=root.parent)
    assert os.readlink(unit.parent / "multi-user.target.wants" / unit.name) == "/preserved-collision"
