import hashlib
import json
from pathlib import Path
import pytest
from verify_install_preflight import canonical, main, verify_source, verify_host_identity, collect_source_rows, collect_public_installer_manifest
from install.transaction import TransactionError, strict_json


def source(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    data = b"Outpost fixture, not an installable generation\n"
    (root / "payload.txt").write_bytes(data)
    release = {"schema": "SereinOutpostSourceRelease/v2",
               "classification": "PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED",
               "payload": [{"path": "payload.txt", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}],
               "source_only_files": []}
    seal(root, release)
    return root, release


def seal(root, release):
    release["self_digest"] = "sha256:" + hashlib.sha256(canonical({k:v for k,v in release.items() if k != "self_digest"})).hexdigest()
    (root / "release-manifest.json").write_bytes(canonical(release))


def test_public_package_excludes_private_role_matrix():
    """Audit evidence is retained privately, never installed as runtime payload."""
    package = Path(__file__).resolve().parents[1]
    release = json.loads((package / "release-manifest.json").read_bytes())
    combined = json.loads((package.parent / "public-installer-manifest.json").read_bytes())
    assert not (package / "outpost-role-matrix.json").exists()
    assert "outpost-role-matrix.json" not in {
        row["path"] for row in release["payload"] + release["source_only_files"]
    }
    assert "outpost/outpost-role-matrix.json" not in {
        row["path"] for row in combined["files"]
    }


def test_combined_manifest_binds_base_and_outpost_without_installation_claim(tmp_path):
    paths = {"base/packages.lock":b"# descriptive reference only\n", "outpost/release-manifest.json":b"{}"}
    for name, data in paths.items():
        path = tmp_path/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    value = collect_public_installer_manifest(tmp_path, list(paths))
    assert value["schema"] == "SFOSPublicInstallerManifest/v1"
    assert value["scope"] == "DEBIAN_BASE_AND_OUTPOST_ONLY"
    assert [row["path"] for row in value["files"]] == sorted(paths)
    assert value["self_digest"] == "sha256:" + hashlib.sha256(canonical(
        {key:entry for key,entry in value.items() if key != "self_digest"})).hexdigest()
    assert not (tmp_path/"public-installer-manifest.json").exists()
    (tmp_path/"public-installer-manifest.json").write_bytes(canonical(value))
    assert collect_public_installer_manifest(tmp_path, list(paths)) == value
    (tmp_path/"base/packages.lock").write_bytes(b"changed")
    assert collect_public_installer_manifest(tmp_path, list(paths))["self_digest"] != value["self_digest"]


def test_combined_manifest_cannot_silently_import_downstream_or_omit_base(tmp_path):
    for name in ("base/packages.lock", "outpost/release-manifest.json", "kernel/payload.py"):
        path = tmp_path/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"inert")
    with pytest.raises(SystemExit, match="PUBLIC_INSTALLER_SCOPE_DENIED"):
        collect_public_installer_manifest(tmp_path, ["base/packages.lock", "outpost/release-manifest.json", "kernel/payload.py"])
    with pytest.raises(SystemExit, match="SOURCE_DENOMINATOR_DENIED"):
        collect_public_installer_manifest(tmp_path, ["outpost/release-manifest.json"])


def test_source_rows_are_deterministic_exhaustive_and_do_not_write_manifest(tmp_path):
    (tmp_path/"tests").mkdir()
    files={"b.py":b"second", "a.py":b"first", "tests/check.py":b"proof"}
    for path,data in files.items(): (tmp_path/path).write_bytes(data)
    rows=collect_source_rows(tmp_path,list(files))
    assert rows==collect_source_rows(tmp_path,list(reversed(files)))
    assert [row["path"] for row in rows["payload"]]==["a.py","b.py"]
    assert [row["path"] for row in rows["source_only_files"]]==["tests/check.py"]
    for row in rows["payload"]+rows["source_only_files"]:
        data=files[row["path"]]
        assert row=={"path":row["path"],"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
    assert not (tmp_path/"release-manifest.json").exists()


@pytest.mark.parametrize("defect", ["extra","missing","symlink","hardlink"])
def test_source_row_collection_denies_unreconciled_or_redirected_source(tmp_path,defect):
    import os
    (tmp_path/"one").write_bytes(b"one")
    if defect=="extra": (tmp_path/"extra").write_bytes(b"extra")
    if defect=="missing": (tmp_path/"one").unlink()
    if defect in {"symlink","hardlink"}:
        (tmp_path/"two").write_bytes(b"two")
        (tmp_path/"one").unlink()
        if defect=="symlink": (tmp_path/"one").symlink_to(tmp_path/"two")
        else: os.link(tmp_path/"two",tmp_path/"one")
    with pytest.raises(SystemExit): collect_source_rows(tmp_path,["one"])


def test_source_row_collection_detects_change_after_an_earlier_file_was_hashed(tmp_path,monkeypatch):
    import verify_install_preflight as source_preflight
    (tmp_path/"a").write_bytes(b"a")
    (tmp_path/"b").write_bytes(b"b")
    original=source_preflight._read_regular
    def read(path,limit):
        data=original(path,limit)
        if path.name=="b": (tmp_path/"a").write_bytes(b"changed")
        return data
    monkeypatch.setattr(source_preflight,"_read_regular",read)
    with pytest.raises(SystemExit,match="SOURCE_CHANGED_DURING_COLLECTION"):
        collect_source_rows(tmp_path,["a","b"])
    assert (tmp_path/"a").read_bytes()==b"changed"  # No repair or restore.


def test_exact_source_bytes_only_not_readiness(tmp_path, capsys):
    root, release = source(tmp_path)
    verify_source(root, release)
    main(["--source", str(root)])
    assert capsys.readouterr().out.strip() == "PASS_OUTPOST_SOURCE_BYTES_ONLY_NOT_INSTALL_READY"


@pytest.mark.parametrize("corruption", ["hash", "missing", "extra", "duplicate", "disk_manifest"])
def test_incomplete_or_different_source_cannot_pass(tmp_path, corruption):
    root, release = source(tmp_path)
    if corruption == "hash": (root/"payload.txt").write_bytes(b"changed")
    elif corruption == "missing": (root/"payload.txt").unlink()
    elif corruption == "extra": (root/"extra.txt").write_text("undeclared")
    elif corruption == "duplicate":
        release["source_only_files"] = list(release["payload"])
        seal(root, release)
    else: (root/"release-manifest.json").write_text("{}")
    with pytest.raises(SystemExit): verify_source(root, release)


@pytest.mark.parametrize("path", ["../escape", "/etc/passwd", "a/../payload.txt", "a//b", "./payload.txt", "C:\\private", "a\\b", "release-manifest.json"])
def test_unsafe_manifest_path_is_rejected(tmp_path, path):
    root, release = source(tmp_path)
    release["payload"][0]["path"] = path
    seal(root, release)
    with pytest.raises(SystemExit, match="PAYLOAD_PATH_DENIED"):
        verify_source(root, release)


@pytest.mark.parametrize("redirect", ["symlink", "hardlink"])
def test_source_cannot_redirect_payload_to_another_file(tmp_path, redirect):
    import os
    root, release = source(tmp_path)
    target = tmp_path/"target"
    target.write_bytes((root/"payload.txt").read_bytes())
    (root/"payload.txt").unlink()
    if redirect == "symlink": (root/"payload.txt").symlink_to(target)
    else: os.link(target, root/"payload.txt")
    with pytest.raises(SystemExit): verify_source(root, release)


def test_source_mode_cannot_skip_extra_paths_or_admit_installed_state(tmp_path):
    root, release = source(tmp_path)
    for kwargs in ({"installed": True}, {"allowed_extra": {"unknown"}}):
        with pytest.raises(SystemExit, match="INSTALLED_PREFLIGHT_NOT_IMPLEMENTED"):
            verify_source(root, release, **kwargs)


def test_sparse_oversized_payload_is_rejected_before_large_read(tmp_path):
    root, release = source(tmp_path)
    with (root/"payload.txt").open("r+b") as stream:
        stream.truncate(2*1024*1024)
    with pytest.raises(SystemExit, match="SOURCE_SIZE_DENIED"):
        verify_source(root, release)


def test_oversized_manifest_is_rejected_before_parse(tmp_path):
    root, _ = source(tmp_path)
    with (root/"release-manifest.json").open("wb") as stream:
        stream.truncate(1024*1024+1)
    with pytest.raises(SystemExit, match="SOURCE_SIZE_DENIED"):
        main(["--source", str(root)])


@pytest.mark.parametrize("raw", [b'{"schema":1,"schema":2}', b'{"rows":[{"path":"a","path":"b"}]}',
    b'[]', b'null', b'{"value":NaN}', b'{"value":"\\ud800"}', b'\xff'])
def test_strict_json_denies_ambiguous_or_invalid_values(raw):
    with pytest.raises(TransactionError): strict_json(raw)


def test_release_duplicate_key_on_disk_cannot_match_parsed_manifest(tmp_path):
    root, release = source(tmp_path)
    raw = canonical(release)
    (root/"release-manifest.json").write_bytes(b'{"schema":"wrong",'+raw[1:])
    with pytest.raises(TransactionError, match="DUPLICATE_KEY"):
        verify_source(root, release)


IDENTITY_POLICY={"os_id":"debian","os_version_id":"13","hostname_policy":"PRESERVE_NONEMPTY"}


def identity_fixture(root):
    files={"etc/os-release":'ID=debian\nVERSION_ID="13"\n',"etc/hostname":"existing-host\n",
           "etc/machine-id":"a"*32+"\n","proc/sys/kernel/random/boot_id":"11111111-2222-4333-8444-555555555555\n"}
    for path,data in files.items():
        target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(data)
    return {path:(root/path).read_bytes() for path in files}


def test_debian_identity_preflight_is_read_only_and_preserves_existing_identity(tmp_path):
    before=identity_fixture(tmp_path)
    observed=verify_host_identity(tmp_path,IDENTITY_POLICY)
    assert observed["hostname"]=="existing-host" and observed["machine_id"]=="a"*32
    assert {path:(tmp_path/path).read_bytes() for path in before}==before


@pytest.mark.parametrize("path,data", [("etc/os-release","ID=ubuntu\nVERSION_ID=13\n"),
    ("etc/os-release","ID=debian\nVERSION_ID=12\n"),
    ("etc/os-release","ID=ubuntu\nID=debian\nVERSION_ID=13\n"),
    ("etc/hostname",""),("etc/hostname","invalid/host"),
    ("etc/machine-id","0"*32),("proc/sys/kernel/random/boot_id","unknown")])
def test_incompatible_or_ambiguous_target_identity_denies_without_repair(tmp_path,path,data):
    identity_fixture(tmp_path);target=tmp_path/path;target.write_text(data)
    with pytest.raises(SystemExit):verify_host_identity(tmp_path,IDENTITY_POLICY)
    assert target.read_text()==data


def test_identity_preflight_accepts_only_canonical_debian_os_release_link(tmp_path):
    identity_fixture(tmp_path)
    target=tmp_path/"usr/lib/os-release";target.parent.mkdir(parents=True)
    (tmp_path/"etc/os-release").rename(target)
    (tmp_path/"etc/os-release").symlink_to("../usr/lib/os-release")
    assert verify_host_identity(tmp_path,IDENTITY_POLICY)["os_id"]=="debian"
    (tmp_path/"etc/os-release").unlink()
    (tmp_path/"etc/os-release").symlink_to(target)
    with pytest.raises(SystemExit,match="TARGET_OS_LINK_DENIED"):
        verify_host_identity(tmp_path,IDENTITY_POLICY)


def test_identity_policy_cannot_switch_target_os(tmp_path):
    identity_fixture(tmp_path)
    with pytest.raises(SystemExit,match="TARGET_IDENTITY_POLICY_DENIED"):
        verify_host_identity(tmp_path,{**IDENTITY_POLICY,"os_id":"ubuntu"})
