#!/usr/bin/env python3
"""Fail-closed provenance check for the two public installer source roads."""
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
PUBLIC_REPOSITORY = "https://github.com/Kaotikking/sfos-public"
PUBLIC_API = "https://api.github.com/repos/Kaotikking/sfos-public/commits/"


def deny(reason):
    raise SystemExit("SOURCE_ROAD_DENIED:" + reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_exact(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        deny("RECEIPT_UNREADABLE")
    if not isinstance(value, dict):
        deny("RECEIPT_SHAPE")
    return value


def git(root, expression):
    result = subprocess.run(
        ["git", "-c", f"safe.directory={root.resolve()}", "-C", str(root), "rev-parse", expression],
        text=True, capture_output=True,
    )
    if result.returncode != 0:
        deny("GIT_IDENTITY_UNAVAILABLE")
    return result.stdout.strip().lower()


def github_tree(commit):
    try:
        request=urllib.request.Request(PUBLIC_API+commit,headers={"Accept":"application/vnd.github+json","User-Agent":"sfos-public-installer/1"})
        with urllib.request.urlopen(request,timeout=15) as response:
            if response.status != 200: deny("PUBLIC_API_STATUS")
            value=json.load(response)
    except SystemExit:
        raise
    except Exception:
        deny("PUBLIC_API_UNAVAILABLE")
    tree=value.get("commit",{}).get("tree",{}).get("sha","").lower()
    if value.get("sha","").lower()!=commit or not HEX40.fullmatch(tree): deny("PUBLIC_API_IDENTITY")
    return tree


def github_payload(tree):
    try:
        request=urllib.request.Request(
            "https://api.github.com/repos/Kaotikking/sfos-public/git/trees/"+tree+"?recursive=1",
            headers={"Accept":"application/vnd.github+json","User-Agent":"sfos-public-installer/1"},
        )
        with urllib.request.urlopen(request,timeout=15) as response:
            if response.status != 200: deny("PUBLIC_TREE_API_STATUS")
            value=json.load(response)
    except SystemExit:
        raise
    except Exception:
        deny("PUBLIC_TREE_API_UNAVAILABLE")
    if value.get("sha","").lower()!=tree or value.get("truncated") is True: deny("PUBLIC_TREE_API_IDENTITY")
    rows={}
    for row in value.get("tree",[]):
        path=row.get("path","")
        if path.startswith("sfos/") and row.get("type")=="blob": rows[path]=row.get("sha","").lower()
    if not rows or any(not HEX40.fullmatch(value) for value in rows.values()): deny("PUBLIC_TREE_BLOB_SET")
    return rows


def payload_identity(root):
    entries=[]
    payload=root/"sfos"
    if not payload.is_dir(): deny("PAYLOAD_ROOT")
    for path in sorted(payload.rglob("*"),key=lambda p:p.as_posix()):
        rel=path.relative_to(root).as_posix()
        if rel=="sfos/source-road-receipt.json" or "__pycache__" in path.parts or path.name.endswith(".pyc") or path.name==".pytest_cache": continue
        if path.is_symlink() or (not path.is_dir() and not path.is_file()): deny("PAYLOAD_UNSAFE_ENTRY")
        if path.is_file(): entries.append({"path":rel,"bytes":path.stat().st_size,"sha256":digest(path)})
    encoded=json.dumps(entries,sort_keys=True,separators=(",",":")).encode()
    return len(entries),hashlib.sha256(encoded).hexdigest()


def payload_blobs(root):
    rows={}
    for path in sorted((root/"sfos").rglob("*"),key=lambda p:p.as_posix()):
        rel=path.relative_to(root).as_posix()
        if rel=="sfos/source-road-receipt.json" or "__pycache__" in path.parts or path.name.endswith(".pyc") or path.name==".pytest_cache": continue
        if path.is_symlink() or (not path.is_dir() and not path.is_file()): deny("PAYLOAD_UNSAFE_ENTRY")
        if path.is_file():
            data=path.read_bytes()
            rows[rel]=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
    return rows


def verify(root, kind, receipt_path):
    receipt = load_exact(receipt_path)
    manifest = load_exact(root / "sfos/outpost/release-manifest.json")
    release_digest = manifest.get("self_digest")
    if not isinstance(release_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", release_digest):
        deny("RELEASE_DIGEST")

    common = {"schema", "source_kind", "outpost_release_digest"}
    if receipt.get("schema") != "SFOSSourceRoadReceipt/v1" or receipt.get("source_kind") != kind or receipt.get("outpost_release_digest") != release_digest:
        deny("COMMON_BINDING")

    if kind == "PINNED_PUBLIC_REPOSITORY":
        required = common | {"repository", "commit", "tree"}
        if set(receipt) != required or receipt.get("repository") != PUBLIC_REPOSITORY:
            deny("PUBLIC_RECEIPT_SHAPE")
        commit, tree = receipt.get("commit", ""), receipt.get("tree", "")
        if not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
            deny("PUBLIC_IDENTITY_FORMAT")
        if git(root, "HEAD") != commit or git(root, "HEAD^{tree}") != tree:
            deny("PUBLIC_IDENTITY_MISMATCH")
        if github_tree(commit) != tree: deny("PUBLIC_PROVIDER_TREE_MISMATCH")
    elif kind == "OFFLINE_USB_MEDIA":
        required = common | {"build_id", "media_lock_sha256", "debian_iso_sha256","public_repository","public_commit","public_tree","payload_file_count","payload_manifest_sha256"}
        if set(receipt) != required or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}", str(receipt.get("build_id", ""))):
            deny("OFFLINE_RECEIPT_SHAPE")
        lock_path = root / "sfos/base/installer/media-lock.json"
        lock = load_exact(lock_path)
        if not HEX64.fullmatch(str(receipt.get("media_lock_sha256", ""))) or digest(lock_path) != receipt["media_lock_sha256"]:
            deny("OFFLINE_MEDIA_LOCK_MISMATCH")
        if not HEX64.fullmatch(str(receipt.get("debian_iso_sha256", ""))) or receipt["debian_iso_sha256"] != lock.get("image_sha256"):
            deny("OFFLINE_DEBIAN_MEDIA_MISMATCH")
        if receipt.get("public_repository")!=PUBLIC_REPOSITORY or not HEX40.fullmatch(str(receipt.get("public_commit",""))) or not HEX40.fullmatch(str(receipt.get("public_tree",""))): deny("OFFLINE_PUBLIC_IDENTITY")
        if github_tree(receipt["public_commit"]) != receipt["public_tree"]: deny("OFFLINE_PROVIDER_TREE_MISMATCH")
        if payload_blobs(root) != github_payload(receipt["public_tree"]): deny("OFFLINE_PROVIDER_PAYLOAD_MISMATCH")
        count,manifest_hash=payload_identity(root)
        if receipt.get("payload_file_count")!=count or receipt.get("payload_manifest_sha256")!=manifest_hash: deny("OFFLINE_PAYLOAD_MISMATCH")
    else:
        deny("SOURCE_KIND")
    print("VERIFIED_EXACT_SOURCE_ROAD")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(64)
    verify(Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve())
