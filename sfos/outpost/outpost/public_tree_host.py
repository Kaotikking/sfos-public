"""Bind the admitted public SFOS Base contract to signed Debian Host evidence."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from .host_vitality import JOINED_SCHEMA, digest, validate

REPOSITORY = "Kaotikking/sfos-public"
BASE_COMMIT = "0dca6bd7a22b83b04ddf353df901d2c7ea15c294"
BASE_TREE = "8c56a80487f25150ffec90316a946ac89f64fb92"
LOCK_PATH = "sfos/base/packages.lock"
POLICY_PATH = "sfos/base/installer/base-policy.json"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class PublicTreeHostError(ValueError):
    pass


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise PublicTreeHostError("PUBLIC_GIT_REDIRECT_DENIED")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _api(path: str) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPOSITORY + path,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "serein-outpost-host-witness/1"},
    )
    try:
        opener = urllib.request.build_opener(_RejectRedirect())
        with opener.open(request, timeout=15) as response:
            if response.geturl() != request.full_url:
                raise PublicTreeHostError("PUBLIC_GIT_REDIRECT_DENIED")
            if response.status != 200:
                raise PublicTreeHostError("PUBLIC_GIT_STATUS_DENIED")
            value = json.load(response)
    except PublicTreeHostError:
        raise
    except Exception as exc:
        raise PublicTreeHostError("PUBLIC_GIT_UNAVAILABLE") from exc
    if not isinstance(value, dict):
        raise PublicTreeHostError("PUBLIC_GIT_RESPONSE_DENIED")
    return value


def _public_blob(commit: str, tree: str, path: str) -> bytes:
    if commit != BASE_COMMIT or tree != BASE_TREE:
        raise PublicTreeHostError("PUBLIC_BASE_LINEAGE_DENIED")
    head = _api("/commits/" + commit)
    if head.get("sha") != commit or head.get("commit", {}).get("tree", {}).get("sha") != tree:
        raise PublicTreeHostError("PUBLIC_COMMIT_TREE_DENIED")
    listing = _api("/git/trees/" + tree + "?recursive=1")
    if listing.get("sha") != tree or listing.get("truncated") is True:
        raise PublicTreeHostError("PUBLIC_TREE_DENIED")
    rows = [row for row in listing.get("tree", []) if isinstance(row, dict) and row.get("path") == path and row.get("type") == "blob"]
    if len(rows) != 1 or not HEX40.fullmatch(str(rows[0].get("sha", ""))):
        raise PublicTreeHostError("PUBLIC_BASE_PATH_DENIED")
    value = _api("/git/blobs/" + rows[0]["sha"])
    if value.get("sha") != rows[0]["sha"] or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
        raise PublicTreeHostError("PUBLIC_BLOB_DENIED")
    try:
        # GitHub wraps its Base64 response in lines. Strip only transport line
        # endings: all other invalid characters still fail strict decoding.
        encoded = value["content"].replace("\r", "").replace("\n", "")
        data = __import__("base64").b64decode(encoded, validate=True)
    except Exception as exc:
        raise PublicTreeHostError("PUBLIC_BLOB_DENIED") from exc
    if _git_blob(data) != rows[0]["sha"]:
        raise PublicTreeHostError("PUBLIC_BLOB_HASH_DENIED")
    return data


def _lock(data: bytes) -> dict[str, str]:
    packages: dict[str, str] = {}
    for line in data.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("=") != 1:
            raise PublicTreeHostError("PUBLIC_BASE_LOCK_DENIED")
        name, version = line.split("=", 1)
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) or not version or name in packages:
            raise PublicTreeHostError("PUBLIC_BASE_LOCK_DENIED")
        packages[name] = version
    if not packages:
        raise PublicTreeHostError("PUBLIC_BASE_LOCK_DENIED")
    return dict(sorted(packages.items()))


def _os_release(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PublicTreeHostError("HOST_OS_RELEASE_DENIED") from exc
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    if values.get("ID") != "debian" or values.get("VERSION_ID") != "13":
        raise PublicTreeHostError("HOST_BASE_IDENTITY_DENIED")
    return values


def _installed_packages() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Package}=${Version}\\n"],
            text=True, capture_output=True, check=True, timeout=15,
        )
    except Exception as exc:
        raise PublicTreeHostError("HOST_PACKAGE_OBSERVATION_DENIED") from exc
    rows = {}
    for line in result.stdout.splitlines():
        if line.count("=") != 1:
            raise PublicTreeHostError("HOST_PACKAGE_OBSERVATION_DENIED")
        name, version = line.split("=", 1)
        rows[name] = version
    return rows


def _gpu() -> dict[str, Any]:
    try:
        result = subprocess.run(["nvidia-smi", "-L"], text=True, capture_output=True, check=True, timeout=15)
    except Exception:
        return {"pci_present": False, "driver_loaded": False, "device_count": 0, "driver_packages": {}, "status": "FAIL"}
    count = len([line for line in result.stdout.splitlines() if line.strip()])
    return {"pci_present": count > 0, "driver_loaded": count > 0, "device_count": count, "driver_packages": {}, "status": "PASS" if count else "FAIL"}


def bind_signed_debian_observation(observation: Mapping[str, Any]) -> dict:
    """Join one signature-verified Debian observation to the pinned SFOS tree.

    The public tree specifies Serein's exact Base contract. Debian's signed
    Release/index evidence independently establishes that the observed package
    facts are authentic Debian facts. Either denominator can fail the Host gate.
    """
    checked = validate(observation)
    if checked.get("schema") != "SereinOutpostHostVitalityObservation/v1":
        raise PublicTreeHostError("SIGNED_DEBIAN_OBSERVATION_DENIED")
    lock_bytes = _public_blob(BASE_COMMIT, BASE_TREE, LOCK_PATH)
    policy_bytes = _public_blob(BASE_COMMIT, BASE_TREE, POLICY_PATH)
    try:
        policy = json.loads(policy_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicTreeHostError("PUBLIC_BASE_POLICY_DENIED") from exc
    if not isinstance(policy, dict) or policy.get("schema") != "SFOSDebianBasePolicy/v1" or policy.get("source_kinds") != ["OFFLINE_USB_MEDIA", "PINNED_PUBLIC_REPOSITORY"]:
        raise PublicTreeHostError("PUBLIC_BASE_POLICY_DENIED")
    expected = _lock(lock_bytes)
    debian = checked["debian"]
    installed = debian["installed_packages"]
    repository = debian["repository_packages"]
    exact_diff = [{"package": name, "expected": version, "observed": installed.get(name)} for name, version in expected.items() if installed.get(name) != version]
    unknowns = ["PUBLIC_LOCK_VERSION_NOT_IN_SIGNED_INDEX:" + name for name, version in expected.items() if repository.get(name) != version]
    configured = [row for pin in debian["pins"] if isinstance(pin,dict)
                  for row in pin.get("sources",[]) if isinstance(row,dict)]
    components = policy.get("components")
    if (not isinstance(components,list) or not components
            or any(not isinstance(item,str) or not item for item in components)
            or len(set(components)) != len(components)):
        unknowns.append("PUBLIC_BASE_COMPONENT_POLICY_UNKNOWN")
    elif not configured:
        unknowns.append("INSTALLED_SOURCE_COMPONENTS_UNKNOWN")
    elif any(not isinstance(row.get("components"),list)
             or any(not isinstance(item,str) for item in row["components"])
             or set(row["components"]) != set(components) for row in configured):
        # Do not silently narrow signed Host evidence or rewrite the Base
        # policy to conceal their disagreement. Outpost remains observable.
        unknowns.append("PUBLIC_BASE_COMPONENTS_MISMATCH")
    source = {
        "repository": REPOSITORY,
        "commit": BASE_COMMIT,
        "tree": BASE_TREE,
        "lock_path": LOCK_PATH,
        "lock_sha256": _sha(lock_bytes),
        "policy_path": POLICY_PATH,
        "policy_sha256": _sha(policy_bytes),
        "expected_packages": expected,
        "observed_packages": {name: installed.get(name) for name in expected},
        "exact_diff": exact_diff,
        "unknowns": unknowns,
        "status": "PASS" if debian["status"] == "PASS" and not exact_diff and not unknowns else "DRIFT",
    }
    body = {
        "schema": JOINED_SCHEMA,
        "target": checked["target"],
        "boot_id": checked["boot_id"],
        "observed_at": checked["observed_at"],
        "host": checked["host"],
        "gpu": checked["gpu"],
        "debian": debian,
        "public_base": source,
    }
    return validate({**body, "evidence_digest": digest(body)})


def collect(boot_id: str, observed_at: float | None = None, os_release_path: Path = Path("/etc/os-release"), machine_id_path: Path = Path("/etc/machine-id")) -> dict:
    lock_bytes = _public_blob(BASE_COMMIT, BASE_TREE, LOCK_PATH)
    policy_bytes = _public_blob(BASE_COMMIT, BASE_TREE, POLICY_PATH)
    try:
        policy = json.loads(policy_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicTreeHostError("PUBLIC_BASE_POLICY_DENIED") from exc
    if not isinstance(policy, dict) or policy.get("schema") != "SFOSDebianBasePolicy/v1" or policy.get("source_kinds") != ["OFFLINE_USB_MEDIA", "PINNED_PUBLIC_REPOSITORY"]:
        raise PublicTreeHostError("PUBLIC_BASE_POLICY_DENIED")
    expected = _lock(lock_bytes)
    observed = _installed_packages()
    exact_diff = [{"package": name, "expected": version, "observed": observed.get(name)} for name, version in expected.items() if observed.get(name) != version]
    source = {
        "repository": REPOSITORY,
        "commit": BASE_COMMIT,
        "tree": BASE_TREE,
        "lock_path": LOCK_PATH,
        "lock_sha256": _sha(lock_bytes),
        "policy_path": POLICY_PATH,
        "policy_sha256": _sha(policy_bytes),
        "expected_packages": expected,
        "observed_packages": {name: observed.get(name) for name in expected},
        "exact_diff": exact_diff,
        "unknowns": [],
        "status": "PASS" if not exact_diff else "DRIFT",
    }
    os_values = _os_release(os_release_path)
    return {
        "schema": "SereinOutpostHostVitalityObservation/v2",
        "target": "SEREIN_HOST",
        "boot_id": boot_id,
        "observed_at": time.time() if observed_at is None else observed_at,
        "host": {"hostname": os_values.get("PRETTY_NAME", "debian"), "os_id": "debian", "os_version_id": "13", "machine_id": machine_id_path.read_text(encoding="utf-8").strip(), "status": "PASS"},
        "gpu": _gpu(),
        "public_base": source,
    }
