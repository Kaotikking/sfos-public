#!/usr/bin/env python3
"""Source-only portion of the canonical Outpost installation preflight.

Adapted from the attributed verify_install_preflight.py donor. Target and boot
preflight are deliberately absent until the coherent startup contract is
admitted. Passing this verifier is not permission to install or activate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from install.transaction import strict_json

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _path(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\x00" in value:
        raise SystemExit("PAYLOAD_PATH_DENIED")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value or value in {".", "release-manifest.json"}:
        raise SystemExit("PAYLOAD_PATH_DENIED")
    return value


def _read_regular(path, limit=MAX_MANIFEST_BYTES):
    if any(parent.is_symlink() for parent in path.parents):
        raise SystemExit("SOURCE_SYMLINK_DENIED")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("SOURCE_CUSTODY_DENIED")
        if info.st_size > limit:
            raise SystemExit("SOURCE_SIZE_DENIED")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise SystemExit("SOURCE_SIZE_DENIED")
        return data


def _collect_rows(root, expected_paths, manifest_name):
    root = Path(os.path.abspath(root))
    if root.is_symlink() or not root.is_dir() or any(parent.is_symlink() for parent in root.parents):
        raise SystemExit("SOURCE_ROOT_DENIED")
    if not isinstance(expected_paths, (list, tuple, set, frozenset)) or not expected_paths:
        raise SystemExit("SOURCE_PATH_SET_REQUIRED")
    expected = {_path(name) for name in expected_paths}
    if len(expected) != len(expected_paths):
        raise SystemExit("SOURCE_PATH_SET_DUPLICATE")

    def inventory():
        result = {}
        for path in root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SystemExit("SOURCE_CUSTODY_DENIED")
            if relative == manifest_name:
                continue  # Existing schema excludes its self-digest container.
            result[relative] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                info.st_gid, info.st_nlink, info.st_size,
                                info.st_mtime_ns, info.st_ctime_ns)
        return result

    before = inventory()
    if set(before) != expected:
        raise SystemExit("SOURCE_DENOMINATOR_DENIED")
    rows, total = [], 0
    for name in sorted(expected):
        data = _read_regular(root / name, MAX_SOURCE_BYTES - total)
        total += len(data)
        rows.append({"path":name, "bytes":len(data), "sha256":hashlib.sha256(data).hexdigest()})
    if inventory() != before:
        raise SystemExit("SOURCE_CHANGED_DURING_COLLECTION")
    return rows


def collect_source_rows(root, expected_paths):
    """Collect an explicit reconciled Outpost path set, without writing it."""
    rows = _collect_rows(root, expected_paths, "release-manifest.json")
    return {"payload":[row for row in rows if not row["path"].startswith("tests/")],
            "source_only_files":[row for row in rows if row["path"].startswith("tests/")]}


def collect_public_installer_manifest(root, expected_paths):
    """Existing aggregate schema, exact local bytes only, not public authority.

    Adapted from the attributed refresh_manifest.py aggregate collector. Do
    not silently ignore caches, symlinks or import any downstream domain while
    assembling the currently authorized Base/Outpost-only candidate.
    """
    rows = _collect_rows(root, expected_paths, "public-installer-manifest.json")
    if any(not row["path"].startswith(("base/", "outpost/")) for row in rows):
        raise SystemExit("PUBLIC_INSTALLER_SCOPE_DENIED")
    if not any(row["path"].startswith("base/") for row in rows) or not any(
            row["path"] == "outpost/release-manifest.json" for row in rows):
        raise SystemExit("PUBLIC_INSTALLER_DENOMINATOR_DENIED")
    value = {"schema":"SFOSPublicInstallerManifest/v1",
             "repository":"Kaotikking/sfos-public", "ref":"refs/heads/main",
             "scope":"DEBIAN_BASE_AND_OUTPOST_ONLY", "files":rows}
    value["self_digest"] = "sha256:" + hashlib.sha256(canonical(value)).hexdigest()
    return value


def verify_host_identity(root, expected):
    """Read-only compatibility slice of the attributed target preflight.

    This verifies Debian identity, not signed package state, source admission,
    service startup or permission to install. It preserves all observed files.
    """
    if expected != {"os_id":"debian", "os_version_id":"13", "hostname_policy":"PRESERVE_NONEMPTY"}:
        raise SystemExit("TARGET_IDENTITY_POLICY_DENIED")
    root = Path(os.path.abspath(root))
    if root.is_symlink() or not root.is_dir():
        raise SystemExit("TARGET_ROOT_DENIED")
    os_path = root / "etc/os-release"
    if os_path.is_symlink():
        if os.readlink(os_path) != "../usr/lib/os-release":
            raise SystemExit("TARGET_OS_LINK_DENIED")
        os_path = root / "usr/lib/os-release"
    raw = _read_regular(os_path, 65536)
    fields = {}
    for line in raw.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise SystemExit("TARGET_OS_FIELDS_DENIED")
        fields[key] = value.strip().strip('"')
    if fields.get("ID") != expected["os_id"] or fields.get("VERSION_ID") != expected["os_version_id"]:
        raise SystemExit("TARGET_OS_DENIED")
    hostname = _read_regular(root / "etc/hostname", 254).decode("ascii").strip()
    if not hostname or len(hostname) > 253 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", hostname):
        raise SystemExit("TARGET_HOSTNAME_DENIED")
    machine = _read_regular(root / "etc/machine-id", 33).decode("ascii").strip()
    boot = _read_regular(root / "proc/sys/kernel/random/boot_id", 37).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{32}", machine) or machine == "0" * 32:
        raise SystemExit("TARGET_MACHINE_ID_DENIED")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", boot):
        raise SystemExit("TARGET_BOOT_ID_DENIED")
    return {"os_id":fields["ID"], "os_version_id":fields["VERSION_ID"], "hostname":hostname,
            "machine_id":machine, "boot_id":boot, "os_release_sha256":hashlib.sha256(raw).hexdigest()}


def verify_source(root, release, allowed_extra=frozenset(), *, installed=False):
    # No arbitrary exclusions or runtime inventory mode in this new candidate.
    # Those would bypass a not-yet-admitted installed-generation contract.
    if allowed_extra or installed:
        raise SystemExit("INSTALLED_PREFLIGHT_NOT_IMPLEMENTED")
    root = Path(os.path.abspath(root))
    if root.is_symlink() or not root.is_dir():
        raise SystemExit("SOURCE_ROOT_DENIED")
    if not isinstance(release, dict) or release.get("schema") != "SereinOutpostSourceRelease/v2":
        raise SystemExit("RELEASE_SCHEMA_DENIED")
    unsigned = {key: value for key, value in release.items() if key != "self_digest"}
    if release.get("self_digest") != "sha256:" + hashlib.sha256(canonical(unsigned)).hexdigest():
        raise SystemExit("RELEASE_SELF_DIGEST_DENIED")
    if release.get("classification") != "PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED":
        raise SystemExit("RELEASE_CLASSIFICATION_DENIED")
    payload, source_only = release.get("payload"), release.get("source_only_files", [])
    if not isinstance(payload, list) or not payload or not isinstance(source_only, list):
        raise SystemExit("PAYLOAD_SCHEMA_DENIED")
    expected = {}
    for row in payload + source_only:
        if (not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}
                or type(row["bytes"]) is not int or row["bytes"] < 0
                or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise SystemExit("PAYLOAD_SCHEMA_DENIED")
        name = _path(row["path"])
        if name in expected:
            raise SystemExit("PAYLOAD_DUPLICATE_DENIED")
        expected[name] = row
    if sum(row["bytes"] for row in expected.values()) > MAX_SOURCE_BYTES:
        raise SystemExit("SOURCE_BUDGET_DENIED")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SystemExit("SOURCE_SYMLINK_DENIED")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SystemExit("SOURCE_CUSTODY_DENIED")
        actual.add(path.relative_to(root).as_posix())
    if actual != set(expected) | {"release-manifest.json"}:
        raise SystemExit("SOURCE_DENOMINATOR_DENIED")
    # The passed object cannot replace a contradictory manifest on disk.
    disk_release = strict_json(_read_regular(root / "release-manifest.json"))
    if disk_release != release:
        raise SystemExit("RELEASE_DISK_BINDING_DENIED")
    for name, row in expected.items():
        data = _read_regular(root / name, row["bytes"])
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise SystemExit("PAYLOAD_HASH_DENIED")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--mode", choices=("source",), default="source")
    args = parser.parse_args(argv)
    root = Path(args.source)
    release = strict_json(_read_regular(root / "release-manifest.json"))
    verify_source(root, release)
    print("PASS_OUTPOST_SOURCE_BYTES_ONLY_NOT_INSTALL_READY")


if __name__ == "__main__":
    main()
