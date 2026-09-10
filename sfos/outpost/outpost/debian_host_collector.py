"""Evidence-derived Debian 13 Host/GPU observation for the Outpost Host gate.

The collector accepts no caller verdicts.  It reads allowlisted local facts and
verifies the configured Debian archive metadata with ``gpgv`` before producing
the observation consumed by :mod:`outpost.host_vitality`.
"""
from __future__ import annotations

import hashlib
import json
import lzma
import re
import subprocess
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from .host_vitality import SCHEMA, digest, validate

CANONICAL_KEYRING = "/usr/share/keyrings/debian-archive-keyring.gpg"
KEYRING = Path(CANONICAL_KEYRING)
EXPECTED_SOURCES = (
    ("https://deb.debian.org/debian", ("trixie", "trixie-updates"), ("main", "contrib", "non-free", "non-free-firmware")),
    ("https://security.debian.org/debian-security", ("trixie-security",), ("main", "contrib", "non-free", "non-free-firmware")),
)
EXPECTED_RELEASES = {
    "debian:trixie": "trixie",
    "debian:trixie-updates": "trixie-updates",
    "security:trixie-security": "trixie-security",
}
EXPECTED_SUITE_LABELS = {
    "debian:trixie": "stable",
    "debian:trixie-updates": "stable-updates",
    "security:trixie-security": "stable-security",
}
_HEX = re.compile(r"^[0-9A-Fa-f]+$")


class DebianHostEvidenceError(RuntimeError):
    """The Host denominator could not be proved from trusted evidence."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise DebianHostEvidenceError(f"REGULAR_FILE_REQUIRED:{path}")
    return path.read_bytes()


def _read_debian_archive_keyring(path: Path) -> bytes:
    if not path.is_symlink():
        return _read_regular(path)
    if path.name != "debian-archive-keyring.gpg" or path.readlink() != Path("debian-archive-keyring.pgp"):
        raise DebianHostEvidenceError(f"CANONICAL_KEYRING_LINK_REQUIRED:{path}")
    return _read_regular(path.parent / "debian-archive-keyring.pgp")


def _read_debian_os_release(path: Path) -> bytes:
    if not path.is_symlink():
        return _read_regular(path)
    if path.name != "os-release" or path.readlink() != Path("../usr/lib/os-release"):
        raise DebianHostEvidenceError(f"CANONICAL_OS_RELEASE_LINK_REQUIRED:{path}")
    return _read_regular(path.parent / "../usr/lib/os-release")


def _fields(data: str) -> dict[str, str]:
    result: dict[str, str] = {}
    key: str | None = None
    for line in data.splitlines():
        if line[:1].isspace() and key:
            result[key] += "\n" + line.strip()
        elif ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
        elif not line.strip():
            key = None
    return result


def _deb822_records(data: str) -> list[dict[str, str]]:
    return [_fields(block) for block in re.split(r"\n\s*\n", data.strip()) if block.strip()]


def verify_sources(source_path: Path, keyring: Path = KEYRING) -> list[dict[str, object]]:
    _read_debian_archive_keyring(keyring)
    text=_read_regular(source_path).decode("utf-8")
    if source_path.suffix != ".sources":
        normalized=[]
        pattern=re.compile(r"^deb \[signed-by=/usr/share/keyrings/debian-archive-keyring\.gpg\] (https://\S+) (\S+) (main(?: contrib non-free non-free-firmware)?)$")
        grouped={}
        for line in text.splitlines():
            line=line.strip()
            if not line or line.startswith("#"): continue
            match=pattern.fullmatch(line)
            if not match: raise DebianHostEvidenceError("DEBIAN_SOURCE_TRUST_DENIED")
            uri,suite,components=match.groups();bucket=grouped.setdefault(uri,{"suites":[],"components":components.split()});bucket["suites"].append(suite)
            if bucket["components"]!=components.split(): raise DebianHostEvidenceError("DEBIAN_SOURCE_SET_DENIED")
        expected={(uri,tuple(suites)) for uri,suites,_ in EXPECTED_SOURCES}
        if {(uri,tuple(row["suites"])) for uri,row in grouped.items()}!=expected: raise DebianHostEvidenceError("DEBIAN_SOURCE_SET_DENIED")
        return sorted(({"uri":uri,"suites":row["suites"],"components":row["components"],"signed_by":CANONICAL_KEYRING} for uri,row in grouped.items()),key=lambda row:str(row["uri"]))
    records = _deb822_records(text)
    normalized = []
    for row in records:
        # Signed-By is guest configuration and must retain its canonical guest
        # path even when ``root`` redirects reads for offline validation.
        if row.get("Types") != "deb" or row.get("Signed-By") != CANONICAL_KEYRING:
            raise DebianHostEvidenceError("DEBIAN_SOURCE_TRUST_DENIED")
        uris = tuple(row.get("URIs", "").split())
        suites = tuple(row.get("Suites", "").split())
        components = tuple(row.get("Components", "").split())
        if len(uris) != 1 or (uris[0], suites, components) not in EXPECTED_SOURCES:
            raise DebianHostEvidenceError("DEBIAN_SOURCE_SET_DENIED")
        normalized.append({"uri": uris[0], "suites": list(suites), "components": list(components), "signed_by": CANONICAL_KEYRING})
    if len(normalized) != len(EXPECTED_SOURCES):
        raise DebianHostEvidenceError("DEBIAN_SOURCE_SET_DENIED")
    return sorted(normalized, key=lambda x: str(x["uri"]))


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), check=False, text=True, capture_output=True, timeout=30)


def verify_inrelease(
    inrelease: Path,
    *,
    keyring: Path = KEYRING,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _run,
    now: float | None = None,
) -> dict[str, object]:
    raw = _read_regular(inrelease)
    proc = runner(("gpgv", "--status-fd", "1", "--keyring", str(keyring), str(inrelease)))
    if proc.returncode != 0:
        raise DebianHostEvidenceError("DEBIAN_INRELEASE_SIGNATURE_DENIED")
    fingerprints = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] == "VALIDSIG" and _HEX.fullmatch(parts[2]):
            fingerprints.append(parts[2].lower())
    if not fingerprints:
        raise DebianHostEvidenceError("DEBIAN_INRELEASE_SIGNER_UNKNOWN")
    clear_start = raw.find(b"\n\n")
    sig_start = raw.find(b"\n-----BEGIN PGP SIGNATURE-----")
    if not raw.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----") or clear_start < 0 or sig_start < 0:
        raise DebianHostEvidenceError("DEBIAN_INRELEASE_FORMAT_DENIED")
    clear = raw[clear_start + 2:sig_start].replace(b"\n- ", b"\n")
    meta = _fields(clear.decode("utf-8"))
    hashes: dict[str, tuple[str, int]] = {}
    for line in meta.get("SHA256", "").splitlines():
        parts = line.split()
        if len(parts) == 3 and len(parts[0]) == 64 and _HEX.fullmatch(parts[0]) and parts[1].isdigit():
            hashes[parts[2]] = (parts[0].lower(), int(parts[1]))
    if not hashes or not meta.get("Suite") or not meta.get("Codename") or not meta.get("Date"):
        raise DebianHostEvidenceError("DEBIAN_RELEASE_METADATA_DENIED")
    try:
        current = time.time() if now is None else now
        issued = parsedate_to_datetime(meta["Date"]).astimezone(timezone.utc).timestamp()
        valid_until = parsedate_to_datetime(meta["Valid-Until"]).astimezone(timezone.utc).timestamp() if meta.get("Valid-Until") else None
    except (TypeError, ValueError, OverflowError) as exc:
        raise DebianHostEvidenceError("DEBIAN_RELEASE_TIME_DENIED") from exc
    stable_without_expiry = meta["Suite"] == "stable" and meta["Codename"] == "trixie" and valid_until is None
    if (issued > current + 300
            or (valid_until is not None and current >= valid_until)
            or (valid_until is None and not stable_without_expiry and current - issued > 14 * 86400)):
        raise DebianHostEvidenceError("DEBIAN_RELEASE_STALE")
    signer_binding = _sha256("\n".join(sorted(set(fingerprints))).encode())
    return {"sha256": _sha256(raw), "signer_binding": signer_binding, "fingerprints": sorted(set(fingerprints)), "suite": meta["Suite"], "codename": meta["Codename"], "date": meta.get("Date", ""), "valid_until": meta.get("Valid-Until", ""), "indexes": hashes}


def verify_indexes(releases: Mapping[str, Mapping[str, object]], index_files: Mapping[str, Path]) -> dict[str, bytes]:
    """Verify ``release-key:index-name`` files against signed Release hashes."""
    verified: dict[str, bytes] = {}
    for binding, path in sorted(index_files.items()):
        if ":" not in binding:
            raise DebianHostEvidenceError("DEBIAN_INDEX_BINDING_DENIED")
        release_key, name = binding.rsplit(":", 1)
        release = releases.get(release_key)
        hashes = release.get("indexes", {}) if release else {}
        expected = hashes.get(name) if isinstance(hashes, Mapping) else None
        raw = _read_regular(path)
        if not expected or expected != (_sha256(raw), len(raw)):
            raise DebianHostEvidenceError(f"DEBIAN_INDEX_HASH_DENIED:{binding}")
        if path.suffix == ".xz":
            raw = lzma.decompress(raw)
        verified[binding] = raw
    if not verified:
        raise DebianHostEvidenceError("DEBIAN_INDEX_SET_EMPTY")
    return verified


def _packages(data: bytes) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for row in _deb822_records(data.decode("utf-8", errors="strict")):
        name, version = row.get("Package"), row.get("Version")
        if name and version:
            result.setdefault(name, set()).add(version)
    return result


def _os_release(path: Path) -> dict[str, str]:
    values = {}
    for line in _read_debian_os_release(path).decode().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def _installed_packages(status_path: Path) -> dict[str, str]:
    rows = _deb822_records(_read_regular(status_path).decode())
    return {row["Package"]: row["Version"] for row in rows if row.get("Status") == "install ok installed" and row.get("Package") and row.get("Version")}


def _gpu_facts(sys_root: Path, modules_path: Path, runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]], installed: Mapping[str, str]) -> dict[str, object]:
    devices = []
    pci_root = sys_root / "bus/pci/devices"
    if pci_root.is_dir():
        for node in pci_root.iterdir():
            try:
                vendor = (node / "vendor").read_text().strip().lower()
                cls = (node / "class").read_text().strip().lower()
            except OSError:
                continue
            if vendor == "0x10de" and cls.startswith("0x03"):
                devices.append(node.name)
    modules = _read_regular(modules_path).decode().splitlines()
    driver_loaded = any(line.split()[:1] == ["nvidia"] for line in modules)
    proc = runner(("nvidia-smi", "--query-gpu=pci.bus_id,driver_version", "--format=csv,noheader,nounits"))
    smi_rows = [line.strip() for line in proc.stdout.splitlines() if line.strip()] if proc.returncode == 0 else []
    driver_packages = {k: v for k, v in installed.items() if k == "nvidia-driver" or k.startswith("nvidia-driver-")}
    passed = bool(devices) and driver_loaded and len(smi_rows) == len(devices) and bool(driver_packages)
    return {"pci_present": bool(devices), "driver_loaded": driver_loaded, "device_count": len(devices), "driver_packages": driver_packages, "status": "PASS" if passed else "DRIFT"}


def collect_host_observation(
    *,
    target: str = "SEREIN_HOST",
    root: Path = Path("/"),
    sources_path: Path | None = None,
    inrelease_files: Mapping[str, Path],
    index_files: Mapping[str, Path],
    package_exceptions: Iterable[str] = (),
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _run,
    observed_at: float | None = None,
    now: float | None = None,
) -> dict:
    if target != "SEREIN_HOST":
        raise DebianHostEvidenceError("HOST_TARGET_DENIED")
    keyring = Path(root, CANONICAL_KEYRING.lstrip("/"))
    if sources_path is None:
        deb822=root / "etc/apt/sources.list.d/debian.sources"
        sources_path=deb822 if deb822.is_file() else root / "etc/apt/sources.list"
    sources = verify_sources(sources_path, keyring)
    if observed_at is not None and now is not None:
        raise DebianHostEvidenceError("OBSERVATION_TIME_AMBIGUOUS")
    current_time = time.time() if observed_at is None and now is None else (observed_at if observed_at is not None else now)
    if set(inrelease_files) != set(EXPECTED_RELEASES):
        raise DebianHostEvidenceError("DEBIAN_RELEASE_SET_DENIED")
    releases = {name: verify_inrelease(path, keyring=keyring, runner=runner, now=current_time) for name, path in sorted(inrelease_files.items())}
    if {str(row["uri"]) for row in sources} != {"https://deb.debian.org/debian", "https://security.debian.org/debian-security"}:
        raise DebianHostEvidenceError("DEBIAN_RELEASE_SET_DENIED")
    for name, codename in EXPECTED_RELEASES.items():
        if releases[name]["suite"] != EXPECTED_SUITE_LABELS[name] or releases[name]["codename"] != codename:
            raise DebianHostEvidenceError("DEBIAN_RELEASE_BINDING_DENIED")
    arch_result = runner(("dpkg", "--print-architecture"))
    architecture = arch_result.stdout.strip() if arch_result.returncode == 0 else ""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", architecture):
        raise DebianHostEvidenceError("DEBIAN_ARCHITECTURE_UNKNOWN")
    components = {component for _, _, configured in EXPECTED_SOURCES for component in configured}
    expected_indexes = {f"{release}:{component}/binary-{architecture}/Packages.xz" for release in EXPECTED_RELEASES for component in components}
    if set(index_files) != expected_indexes:
        raise DebianHostEvidenceError("DEBIAN_INDEX_COVERAGE_DENIED")
    indexes = verify_indexes(releases, index_files)
    repository_versions: dict[str, set[str]] = {}
    for raw in indexes.values():
        for package, versions in _packages(raw).items():
            repository_versions.setdefault(package, set()).update(versions)
    installed = _installed_packages(root / "var/lib/dpkg/status")
    repository: dict[str, str] = {}
    ambiguous = []
    for package, installed_version in sorted(installed.items()):
        versions = repository_versions.get(package, set())
        if installed_version in versions:
            repository[package] = installed_version
        elif len(versions) == 1:
            repository[package] = next(iter(versions))
        elif len(versions) > 1:
            ambiguous.append(f"AMBIGUOUS_REPOSITORY_VERSION:{package}")
    allowed = set(package_exceptions)
    exact_diff = [{"package": name, "installed": version, "repository": repository.get(name)} for name, version in sorted(installed.items()) if name not in allowed and repository.get(name) != version]
    unknowns = ambiguous + [f"PACKAGE_NOT_IN_VERIFIED_INDEX:{row['package']}" for row in exact_diff if row["repository"] is None]
    os_info = _os_release(root / "etc/os-release")
    boot_id = _read_regular(root / "proc/sys/kernel/random/boot_id").decode().strip()
    machine_id = _read_regular(root / "etc/machine-id").decode().strip()
    hostname = _read_regular(root / "etc/hostname").decode().strip()
    gpu = _gpu_facts(root / "sys", root / "proc/modules", runner, installed)
    identity_ok = os_info.get("ID") == "debian" and os_info.get("VERSION_ID") == "13"
    debian_ok = identity_ok and not exact_diff and not unknowns
    release_binding = _sha256(json.dumps({k: {x: v[x] for x in ("sha256", "signer_binding", "suite", "codename")} for k, v in releases.items()}, sort_keys=True, separators=(",", ":")).encode())
    signer_binding = _sha256("\n".join(sorted(str(v["signer_binding"]) for v in releases.values())).encode())
    debian = {"release": "Debian 13 trixie/trixie-updates/trixie-security", "release_sha256": release_binding, "signer_fingerprint": signer_binding, "repositories": ["deb.debian.org", "security.debian.org"], "installed_identity": {"id": os_info.get("ID", ""), "version_id": os_info.get("VERSION_ID", ""), "pretty_name": os_info.get("PRETTY_NAME", "")}, "installed_packages": dict(sorted(installed.items())), "repository_packages": dict(sorted(repository.items())), "exact_diff": exact_diff, "pins": [{"sources_sha256": _sha256(_read_regular(sources_path or root / "etc/apt/sources.list.d/debian.sources")), "sources": sources}], "exceptions": sorted(allowed), "unknowns": unknowns, "correction_result": "NOT_REQUIRED" if debian_ok else "PENDING", "status": "PASS" if debian_ok else "DRIFT"}
    body = {"schema": SCHEMA, "target": target, "boot_id": boot_id, "observed_at": current_time, "host": {"hostname": hostname, "os_id": os_info.get("ID", ""), "os_version_id": os_info.get("VERSION_ID", ""), "machine_id": machine_id, "status": "PASS" if identity_ok else "DRIFT"}, "gpu": gpu, "debian": debian}
    return validate({**body, "evidence_digest": digest(body)})
