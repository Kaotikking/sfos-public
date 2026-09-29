"""Exact public-tree source verification; fixtures are not provider admission."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2]/"base/installer/verify-source-road.py"
SPEC = importlib.util.spec_from_file_location("base_source_road", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
COMMIT = "1" * 40
TREE = "2" * 40
RELEASE = "sha256:" + "3" * 64


@pytest.fixture
def source(tmp_path, monkeypatch):
    root=tmp_path/"downloaded-public-tree"
    payload=root/"sfos/outpost"
    payload.mkdir(parents=True)
    (payload/"release-manifest.json").write_text(json.dumps({"self_digest":RELEASE}))
    (payload/"payload.py").write_text("# synthetic non-executable payload\n")
    lock=root/"sfos/base/installer/media-lock.json"
    lock.parent.mkdir(parents=True)
    lock.write_text(json.dumps({"image_sha256":"4"*64}))
    expected=MOD.payload_blobs(root)
    calls=[]
    def provider(url):
        calls.append(url)
        if url==MOD.PUBLIC_API+COMMIT:
            return {"sha":COMMIT,"commit":{"tree":{"sha":TREE}}}
        assert url=="https://api.github.com/repos/Kaotikking/sfos-public/git/trees/"+TREE+"?recursive=1"
        return {"sha":TREE,"truncated":False,"tree":[
            {"path":path,"mode":"100644","type":"blob","sha":sha}
            for path,sha in expected.items()]}
    monkeypatch.setattr(MOD,"provider_json",provider)
    return root, tmp_path/"source-receipt.json", calls


def receipt(root, path, kind):
    value={"schema":"SFOSSourceRoadReceipt/v1","source_kind":kind,
           "outpost_release_digest":RELEASE}
    if kind=="PINNED_PUBLIC_REPOSITORY":
        value.update(repository=MOD.PUBLIC_REPOSITORY,commit=COMMIT,tree=TREE)
    else:
        lock=root/"sfos/base/installer/media-lock.json"
        count,digest=MOD.payload_identity(root)
        value.update(build_id="sfos-usb-fixture-only",media_lock_sha256=MOD.digest(lock),
                     debian_iso_sha256="4"*64,public_repository=MOD.PUBLIC_REPOSITORY,
                     public_commit=COMMIT,public_tree=TREE,payload_file_count=count,
                     payload_manifest_sha256=digest)
    path.write_text(json.dumps(value))
    return value


@pytest.mark.parametrize("kind",["PINNED_PUBLIC_REPOSITORY","OFFLINE_USB_MEDIA"])
def test_both_roads_bind_downloaded_bytes_without_git_directory(source,kind):
    root,path,calls=source
    receipt(root,path,kind)
    assert not (root/".git").exists()
    if kind=="PINNED_PUBLIC_REPOSITORY":
        MOD.verify(root,kind,path)
        assert len(calls)==2
    else:
        value=MOD.verify_offline_payload(root,MOD.load_exact(path))
        assert value["result"]=="OFFLINE_PAYLOAD_INTEGRITY_ONLY"
        assert value["authority"]=="UNPROVEN"
        with pytest.raises(SystemExit,match="OFFLINE_SOURCE_AUTHORITY_UNPROVEN"):
            MOD.verify(root,kind,path)
        assert calls==[]


@pytest.mark.parametrize("kind",["PINNED_PUBLIC_REPOSITORY","OFFLINE_USB_MEDIA"])
@pytest.mark.parametrize("change",["modified","extra","cache","missing"])
def test_matching_commit_label_cannot_hide_changed_or_untracked_payload(source,kind,change):
    root,path,_=source
    receipt(root,path,kind)
    target=root/"sfos/outpost/payload.py"
    if change=="modified": target.write_text("# changed\n")
    elif change=="missing": target.unlink()
    elif change=="extra": (target.parent/"untracked.py").write_text("# extra\n")
    else:
        cache=target.parent/"__pycache__"
        cache.mkdir()
        (cache/"hidden.pyc").write_bytes(b"not ignored")
    with pytest.raises(SystemExit,match="PROVIDER_PAYLOAD_MISMATCH" if kind=="PINNED_PUBLIC_REPOSITORY" else "OFFLINE_PAYLOAD_MISMATCH"):
        MOD.verify(root,kind,path)


@pytest.mark.parametrize("raw",[b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'\xff'])
def test_ambiguous_json_denied(raw):
    with pytest.raises(SystemExit,match="JSON_"):
        MOD.strict_json(raw)


@pytest.mark.parametrize("mode,kind",[("120000","blob"),("160000","commit")])
def test_provider_symlink_and_submodule_denied(monkeypatch,mode,kind):
    monkeypatch.setattr(MOD,"provider_json",lambda url:{"sha":TREE,"truncated":False,
        "tree":[{"path":"sfos/unsafe","mode":mode,"type":kind,"sha":"5"*40}]})
    with pytest.raises(SystemExit,match="PUBLIC_TREE_BLOB_SET"):
        MOD.github_payload(TREE)


def test_truncated_provider_tree_denied(monkeypatch):
    monkeypatch.setattr(MOD,"provider_json",lambda url:{"sha":TREE,"truncated":True,"tree":[]})
    with pytest.raises(SystemExit,match="PUBLIC_TREE_API_IDENTITY"):
        MOD.github_payload(TREE)


def test_redirect_denied_before_following():
    with pytest.raises(SystemExit,match="PUBLIC_REDIRECT_DENIED"):
        MOD.NoRedirect().redirect_request(None,None,302,"redirect",{},"https://elsewhere.invalid/")


def test_payload_budget_denied_before_read(source,monkeypatch):
    root,_,_=source
    monkeypatch.setattr(MOD,"MAX_PAYLOAD_BYTES",1)
    with pytest.raises(SystemExit,match="SOURCE_SIZE_LIMIT"):
        MOD.payload_blobs(root)


def test_builder_generated_plan_is_not_mistaken_for_an_extra_public_source_file(source):
    root, path, calls = source
    receipt(root, path, "OFFLINE_USB_MEDIA")
    # build-media.sh maps this captured per-install input after it binds the
    # canonical public source tree. It is not part of that provider tree.
    (root / "sfos/immutable-input-plan.json").write_bytes(b'{"fixture":"not authority"}\n')
    # The source-only comparison must reach, but never bypass, the separate
    # portable-authority denial. Offline plan admission is still unavailable;
    # rendering/receipt hashes are not authority or custody proof.
    with pytest.raises(SystemExit, match="OFFLINE_SOURCE_AUTHORITY_UNPROVEN"):
        MOD.verify(root, "OFFLINE_USB_MEDIA", path)
    assert calls == []


def test_online_provider_checks_do_not_ignore_generated_plan_path(source):
    root, path, _ = source
    receipt(root, path, "PINNED_PUBLIC_REPOSITORY")
    (root / "sfos/immutable-input-plan.json").write_bytes(b'{}\n')
    with pytest.raises(SystemExit, match="PUBLIC_PROVIDER_PAYLOAD_MISMATCH"):
        MOD.verify(root, "PINNED_PUBLIC_REPOSITORY", path)


@pytest.mark.parametrize("change", ["symlink", "hardlink", "directory", "oversize"])
def test_offline_generated_plan_must_still_be_a_bounded_regular_file(source, tmp_path, change):
    import os
    root, path, _ = source
    receipt(root, path, "OFFLINE_USB_MEDIA")
    plan = root / "sfos/immutable-input-plan.json"
    external = tmp_path / "external.json"
    external.write_bytes(b'{}\n')
    if change == "symlink": plan.symlink_to(external)
    elif change == "hardlink": os.link(external, plan)
    elif change == "directory": plan.mkdir()
    else: plan.write_bytes(b'x' * (1024 * 1024 + 1))
    with pytest.raises(SystemExit, match="PAYLOAD_UNSAFE_ENTRY|SOURCE_SIZE_LIMIT|SOURCE_UNREADABLE"):
        MOD.verify(root, "OFFLINE_USB_MEDIA", path)
    assert external.read_bytes() == b'{}\n'


@pytest.mark.parametrize("link_target", ["source_root", "receipt"])
def test_cli_preserves_symlink_evidence_for_the_existing_custody_check(source, tmp_path, link_target):
    import subprocess
    import sys
    root, path, calls = source
    receipt(root, path, "OFFLINE_USB_MEDIA")
    link = tmp_path / "caller-symlink"
    if link_target == "source_root":
        link.symlink_to(root, target_is_directory=True)
        root = link
    else:
        link.symlink_to(path)
        path = link
    result = subprocess.run([sys.executable, "-B", str(SCRIPT), str(root),
                             "OFFLINE_USB_MEDIA", str(path)], capture_output=True, text=True)
    assert result.returncode != 0
    assert "SOURCE_ROAD_DENIED:PAYLOAD_UNSAFE_ENTRY" in result.stderr
    assert "OFFLINE_SOURCE_AUTHORITY_UNPROVEN" not in result.stderr
    assert calls == []


def test_cli_regular_relative_paths_reach_but_do_not_bypass_offline_authority(source, tmp_path):
    import subprocess
    import sys
    root, path, calls = source
    receipt(root, path, "OFFLINE_USB_MEDIA")
    result = subprocess.run([sys.executable, "-B", str(SCRIPT),
                             str(root.relative_to(tmp_path)), "OFFLINE_USB_MEDIA",
                             str(path.relative_to(tmp_path))], cwd=tmp_path,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert result.stderr.strip() == "SOURCE_ROAD_DENIED:OFFLINE_SOURCE_AUTHORITY_UNPROVEN"
    assert calls == []
