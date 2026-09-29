#!/usr/bin/env python3
"""Fail-closed provenance check for the two public installer source roads."""
import hashlib
import json
import os
import re
import stat
import sys
import urllib.request
from pathlib import Path

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
PUBLIC_REPOSITORY = "https://github.com/Kaotikking/sfos-public"
PUBLIC_API = "https://api.github.com/repos/Kaotikking/sfos-public/commits/"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024


def deny(reason):
    raise SystemExit("SOURCE_ROAD_DENIED:" + reason)


def digest(path):
    return hashlib.sha256(read_regular(path, MAX_PAYLOAD_BYTES)).hexdigest()


def read_regular(path, limit):
    path = Path(os.path.abspath(path))
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink(): deny("PAYLOAD_UNSAFE_ENTRY")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                deny("PAYLOAD_UNSAFE_ENTRY")
            if info.st_size > limit: deny("SOURCE_SIZE_LIMIT")
            raw = stream.read(limit + 1)
    except OSError:
        deny("SOURCE_UNREADABLE")
    if len(raw) > limit: deny("SOURCE_SIZE_LIMIT")
    return raw


def strict_json(raw):
    def object_pairs(pairs):
        value = {}
        for key, entry in pairs:
            if key in value: deny("JSON_DUPLICATE_KEY")
            value[key] = entry
        return value
    def constant(_):
        deny("JSON_NONFINITE")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                           parse_constant=constant)
    except (ValueError, UnicodeError):
        deny("JSON_INVALID")
    if not isinstance(value, dict): deny("RECEIPT_SHAPE")
    return value


def load_exact(path):
    return strict_json(read_regular(path, MAX_JSON_BYTES))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        deny("PUBLIC_REDIRECT_DENIED")


def provider_json(url):
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "sfos-public-installer/1"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            if response.status != 200: deny("PUBLIC_API_STATUS")
            if response.geturl() != url: deny("PUBLIC_REDIRECT_DENIED")
            raw = response.read(MAX_JSON_BYTES + 1)
    except (OSError, ValueError):
        deny("PUBLIC_API_UNAVAILABLE")
    if len(raw) > MAX_JSON_BYTES: deny("SOURCE_SIZE_LIMIT")
    return strict_json(raw)


def github_tree(commit):
    if not isinstance(commit, str) or not HEX40.fullmatch(commit): deny("PUBLIC_IDENTITY_FORMAT")
    value = provider_json(PUBLIC_API + commit)
    try:
        tree=value["commit"]["tree"]["sha"]
    except (KeyError, TypeError):
        deny("PUBLIC_API_IDENTITY")
    if value.get("sha")!=commit or not isinstance(tree, str) or not HEX40.fullmatch(tree): deny("PUBLIC_API_IDENTITY")
    return tree


def github_payload(tree):
    if not isinstance(tree, str) or not HEX40.fullmatch(tree): deny("PUBLIC_IDENTITY_FORMAT")
    value = provider_json("https://api.github.com/repos/Kaotikking/sfos-public/git/trees/"+tree+"?recursive=1")
    if value.get("sha")!=tree or value.get("truncated") is not False or not isinstance(value.get("tree"), list): deny("PUBLIC_TREE_API_IDENTITY")
    rows={}
    for row in value["tree"]:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str): deny("PUBLIC_TREE_BLOB_SET")
        path=row["path"]
        if not path.startswith("sfos/"): continue
        if any(part in ("", ".", "..") for part in path.split("/")) or "\\" in path: deny("PUBLIC_TREE_BLOB_SET")
        if row.get("type")=="tree" and row.get("mode")=="040000": continue
        if row.get("type")!="blob" or row.get("mode") not in ("100644", "100755") or path in rows: deny("PUBLIC_TREE_BLOB_SET")
        if not isinstance(row.get("sha"), str): deny("PUBLIC_TREE_BLOB_SET")
        rows[path]=row["sha"]
    if not rows or any(not HEX40.fullmatch(value) for value in rows.values()): deny("PUBLIC_TREE_BLOB_SET")
    return rows


def payload_identity(root, *, offline_media=False):
    entries=[]
    payload=root/"sfos"
    if not payload.is_dir(): deny("PAYLOAD_ROOT")
    total=0
    for path in sorted(payload.rglob("*"),key=lambda p:p.as_posix()):
        rel=path.relative_to(root).as_posix()
        if rel=="sfos/source-road-receipt.json": continue
        if offline_media and rel=="sfos/immutable-input-plan.json":
            # Exact generated media input, not a public-source file. Check its
            # shape/custody; captured-plan hashes remain separate byte evidence.
            # This exclusion never admits the plan or portable media authority.
            read_regular(path, 1024 * 1024)
            continue
        if path.is_symlink() or (not path.is_dir() and not path.is_file()): deny("PAYLOAD_UNSAFE_ENTRY")
        if path.is_file():
            data=read_regular(path,MAX_PAYLOAD_BYTES-total)
            total+=len(data)
            entries.append({"path":rel,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
    encoded=json.dumps(entries,sort_keys=True,separators=(",",":")).encode()
    return len(entries),hashlib.sha256(encoded).hexdigest()


def payload_blobs(root):
    rows={}
    total=0
    if not (root/"sfos").is_dir() or (root/"sfos").is_symlink(): deny("PAYLOAD_ROOT")
    for path in sorted((root/"sfos").rglob("*"),key=lambda p:p.as_posix()):
        rel=path.relative_to(root).as_posix()
        if rel=="sfos/source-road-receipt.json": continue
        if path.is_symlink() or (not path.is_dir() and not path.is_file()): deny("PAYLOAD_UNSAFE_ENTRY")
        if path.is_file():
            data=read_regular(path,MAX_PAYLOAD_BYTES-total)
            total+=len(data)
            rows[rel]=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
    return rows


def verify_offline_payload(root, receipt):
    """Media-contained integrity only: no network and no source admission.

    The external build receipt binds the finished ISO. This mounted-tree check
    cannot establish the authenticity of a self-supplied receipt by itself.
    """
    required = {"schema", "source_kind", "outpost_release_digest", "build_id", "media_lock_sha256", "debian_iso_sha256", "public_repository", "public_commit", "public_tree", "payload_file_count", "payload_manifest_sha256"}
    if set(receipt) != required or receipt.get("schema") != "SFOSSourceRoadReceipt/v1" or receipt.get("source_kind") != "OFFLINE_USB_MEDIA" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}", str(receipt.get("build_id", ""))):
        deny("OFFLINE_RECEIPT_SHAPE")
    lock_path = root / "sfos/base/installer/media-lock.json"
    lock = load_exact(lock_path)
    if not HEX64.fullmatch(str(receipt.get("media_lock_sha256", ""))) or digest(lock_path) != receipt["media_lock_sha256"]:
        deny("OFFLINE_MEDIA_LOCK_MISMATCH")
    if not HEX64.fullmatch(str(receipt.get("debian_iso_sha256", ""))) or receipt["debian_iso_sha256"] != lock.get("image_sha256"):
        deny("OFFLINE_DEBIAN_MEDIA_MISMATCH")
    if receipt.get("public_repository")!=PUBLIC_REPOSITORY or not HEX40.fullmatch(str(receipt.get("public_commit",""))) or not HEX40.fullmatch(str(receipt.get("public_tree",""))): deny("OFFLINE_PUBLIC_IDENTITY")
    count,manifest_hash=payload_identity(root, offline_media=True)
    if type(receipt.get("payload_file_count")) is not int or receipt["payload_file_count"]!=count or receipt.get("payload_manifest_sha256")!=manifest_hash: deny("OFFLINE_PAYLOAD_MISMATCH")
    return {"result":"OFFLINE_PAYLOAD_INTEGRITY_ONLY", "authority":"UNPROVEN",
            "payload_file_count":count,"payload_manifest_sha256":manifest_hash}


def media_file_identity(path, expected_size):
    """Hash actual regular image bytes without reading a whole ISO into RAM."""
    if type(expected_size) is not int or not 1 <= expected_size <= 8*1024**3:
        deny("MEDIA_SIZE_DENIED")
    path=Path(os.path.abspath(path))
    if any(item.is_symlink() for item in (path,*path.parents)): deny("MEDIA_CUSTODY_DENIED")
    digest=hashlib.sha256()
    try:
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(descriptor,"rb") as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: deny("MEDIA_CUSTODY_DENIED")
            if before.st_size!=expected_size: deny("MEDIA_SIZE_DENIED")
            remaining=expected_size
            while remaining:
                block=stream.read(min(1024*1024,remaining))
                if not block: deny("MEDIA_TRUNCATED")
                digest.update(block);remaining-=len(block)
            if stream.read(1): deny("MEDIA_SIZE_DENIED")
            after=os.fstat(stream.fileno())
            if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns): deny("MEDIA_CHANGED_DURING_READ")
    except OSError:
        deny("MEDIA_UNREADABLE")
    return digest.hexdigest()


def verify_media_artifact_integrity(root, source_iso, output_iso, build_receipt_path):
    """Read actual input/output artifacts against the existing external receipt.

    This is byte identity only, not Debian signature verification, final-media
    authority, bootability, installation, or the mounted ISO's payload readback.
    """
    root,source_iso,output_iso=map(Path,(root,source_iso,output_iso))
    lock_path=root/"sfos/base/installer/media-lock.json"
    lock=load_exact(lock_path)
    receipt=load_exact(build_receipt_path)
    if receipt.get("schema")!="SFOSPublicMediaBuildReceipt/v1" or receipt.get("result")!="BUILT_NOT_INSTALLED": deny("MEDIA_BUILD_RECEIPT_DENIED")
    source,output,payload=(receipt.get(key) for key in ("source","output","payload"))
    if any(not isinstance(value,dict) for value in (source,output,payload)): deny("MEDIA_BUILD_RECEIPT_DENIED")
    if (source.get("filename")!=source_iso.name or source.get("filename")!=lock.get("image_filename")
            or source.get("bytes")!=lock.get("image_bytes") or source.get("sha256")!=lock.get("image_sha256")
            or source.get("media_lock_sha256")!=digest(lock_path)): deny("MEDIA_INPUT_BINDING_DENIED")
    if source.get("sha256")!=media_file_identity(source_iso,source.get("bytes")): deny("MEDIA_INPUT_HASH_DENIED")
    if output.get("filename")!=output_iso.name or not isinstance(output.get("sha256"),str) or not HEX64.fullmatch(output["sha256"]): deny("MEDIA_OUTPUT_BINDING_DENIED")
    if output["sha256"]!=media_file_identity(output_iso,output.get("bytes")): deny("MEDIA_OUTPUT_HASH_DENIED")
    count,manifest_hash=payload_identity(root)
    if payload.get("file_count")!=count or payload.get("manifest_sha256")!=manifest_hash: deny("MEDIA_PAYLOAD_BINDING_DENIED")
    return {"result":"MEDIA_ARTIFACT_INTEGRITY_ONLY","input_sha256":source["sha256"],
            "output_sha256":output["sha256"],"authority":"UNPROVEN","bootability":"UNPROVEN",
            "installed":"UNPROVEN","mounted_payload":"UNPROVEN"}


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
        if github_tree(commit) != tree: deny("PUBLIC_PROVIDER_TREE_MISMATCH")
        # The Debian bootstrap downloads an exact public archive, not a Git
        # working copy. Bind its installed-source bytes to the provider tree;
        # a matching local HEAD would not detect modified or added files.
        if payload_blobs(root) != github_payload(tree): deny("PUBLIC_PROVIDER_PAYLOAD_MISMATCH")
    elif kind == "OFFLINE_USB_MEDIA":
        verify_offline_payload(root, receipt)
        # Do not turn a locally consistent unsigned receipt into installation
        # authority. No portable final-media authority contract is admitted yet.
        deny("OFFLINE_SOURCE_AUTHORITY_UNPROVEN")
    else:
        deny("SOURCE_KIND")
    print("VERIFIED_EXACT_SOURCE_ROAD")
    return receipt


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(64)
    # Preserve caller path spelling so read_regular can reject symlinks.
    # Resolving first would erase the evidence needed by that custody check.
    verify(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
