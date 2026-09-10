import hashlib
import json
import lzma
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from outpost.debian_host_collector import DebianHostEvidenceError, _read_debian_archive_keyring, _read_debian_os_release, collect_host_observation, verify_inrelease


def test_release_declares_canonical_debian_archive_keyring_dependency():
    release = json.loads((Path(__file__).parents[1] / "release-manifest.json").read_text(encoding="utf-8"))
    assert {
        "path": "/usr/share/keyrings/debian-archive-keyring.gpg",
        "debian_package": "debian-archive-keyring",
        "purpose": "Debian archive trust anchor",
        "required_before_install": True,
    } in release["runtime_dependencies"]


def test_canonical_debian_keyring_relative_symlink_is_accepted(tmp_path: Path):
    root, releases, indexes = _fixture(tmp_path)
    keyring = root / "usr/share/keyrings/debian-archive-keyring.gpg"
    target = keyring.with_name("debian-archive-keyring.pgp")
    target.write_bytes(keyring.read_bytes())
    keyring.unlink()
    try:
        keyring.symlink_to("debian-archive-keyring.pgp")
    except OSError:
        pytest.skip("symlink creation unavailable")
    result = collect_host_observation(root=root, inrelease_files=releases, index_files=indexes, runner=_runner, now=1788912000)
    assert result["debian"]["pins"][0]["sources"]


def test_noncanonical_debian_keyring_symlink_fails_closed(tmp_path: Path):
    root, releases, indexes = _fixture(tmp_path)
    keyring = root / "usr/share/keyrings/debian-archive-keyring.gpg"
    target = keyring.with_name("other.pgp")
    target.write_bytes(keyring.read_bytes())
    keyring.unlink()
    try:
        keyring.symlink_to("other.pgp")
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(DebianHostEvidenceError, match="CANONICAL_KEYRING_LINK_REQUIRED"):
        collect_host_observation(root=root, inrelease_files=releases, index_files=indexes, runner=_runner, now=1788912000)


def test_canonical_keyring_link_contract_without_platform_symlink_support():
    class Target:
        def is_symlink(self): return False
        def is_file(self): return True
        def read_bytes(self): return b"canonical-keyring"

    class Parent:
        def __truediv__(self, name):
            assert name == "debian-archive-keyring.pgp"
            return Target()

    class Link:
        name = "debian-archive-keyring.gpg"
        parent = Parent()
        def is_symlink(self): return True
        def readlink(self): return Path("debian-archive-keyring.pgp")

    assert _read_debian_archive_keyring(Link()) == b"canonical-keyring"


def test_canonical_os_release_link_contract_without_platform_symlink_support():
    class Target:
        def is_symlink(self): return False
        def is_file(self): return True
        def read_bytes(self): return b"ID=debian\nVERSION_ID=13\n"
    class Parent:
        def __truediv__(self, name):
            assert name == "../usr/lib/os-release"
            return Target()
    class Link:
        name = "os-release"
        parent = Parent()
        def is_symlink(self): return True
        def readlink(self): return Path("../usr/lib/os-release")
    assert _read_debian_os_release(Link()) == b"ID=debian\nVERSION_ID=13\n"


def _write(path: Path, data: bytes | str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def _fixture(tmp_path: Path):
    root = tmp_path / "root"
    _write(root / "usr/share/keyrings/debian-archive-keyring.gpg", b"keyring")
    _write(root / "etc/apt/sources.list.d/debian.sources", """Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main contrib non-free non-free-firmware
Signed-By: %s

Types: deb
URIs: https://security.debian.org/debian-security
Suites: trixie-security
Components: main contrib non-free non-free-firmware
Signed-By: %s
""" % ("/usr/share/keyrings/debian-archive-keyring.gpg", "/usr/share/keyrings/debian-archive-keyring.gpg"))
    _write(root / "etc/os-release", 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13"\n')
    _write(root / "etc/hostname", "serein\n")
    _write(root / "etc/machine-id", "a" * 32 + "\n")
    _write(root / "proc/sys/kernel/random/boot_id", "12345678-1234-4123-8123-123456789abc\n")
    _write(root / "proc/modules", "nvidia 1 0 - Live 0x0\n")
    # The collector only needs an opaque sysfs directory name; avoid ':' so
    # this Linux-layout fixture also runs on the Windows validation host.
    _write(root / "sys/bus/pci/devices/pci-device-1/vendor", "0x10de\n")
    _write(root / "sys/bus/pci/devices/pci-device-1/class", "0x030000\n")
    packages = b"Package: base-files\nVersion: 13.8\n\nPackage: nvidia-driver\nVersion: 550.1\n\n"
    _write(root / "var/lib/dpkg/status", "Package: base-files\nStatus: install ok installed\nVersion: 13.8\n\nPackage: nvidia-driver\nStatus: install ok installed\nVersion: 550.1\n")
    releases, indexes = {}, {}
    for key, suite, codename in (("debian:trixie", "stable", "trixie"), ("debian:trixie-updates", "stable-updates", "trixie-updates"), ("security:trixie-security", "stable-security", "trixie-security")):
        rows=[]
        component_payloads={}
        for component in ("main","contrib","non-free","non-free-firmware"):
            packed=lzma.compress(packages if component in ("main","non-free") else b"")
            logical=f"{component}/binary-amd64/Packages.xz"
            component_payloads[logical]=packed
            rows.append(f" {hashlib.sha256(packed).hexdigest()} {len(packed)} {logical}")
        release = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                   f"Suite: {suite}\nCodename: {codename}\nDate: Sun, 06 Sep 2026 00:00:00 +0000\nValid-Until: Sun, 13 Sep 2026 00:00:00 +0000\nSHA256:\n {hashlib.sha256(packed).hexdigest()} {len(packed)} {logical}\n"
                   "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n")
        release=release.replace(f" {hashlib.sha256(packed).hexdigest()} {len(packed)} {logical}\n","\n".join(rows)+"\n")
        rp=root/f"{key}.InRelease";_write(rp,release);releases[key]=rp
        for ordinal,(logical,packed) in enumerate(component_payloads.items()):
            ip=root/f"{key}.{ordinal}.Packages.xz";_write(ip,packed);indexes[f"{key}:{logical}"]=ip
    return root, releases, indexes


def _runner(argv):
    if argv[0] == "gpgv":
        return CompletedProcess(argv, 0, "[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-09-06 0 4 0 1 10 01 " + "A" * 40 + "\n", "")
    if argv[0] == "dpkg":
        return CompletedProcess(argv, 0, "amd64\n", "")
    return CompletedProcess(argv, 0, "00000000:01:00.0, 550.1\n", "")


def test_collects_pass_only_from_verified_local_and_repository_facts(tmp_path):
    root, releases, indexes = _fixture(tmp_path)
    result = collect_host_observation(root=root, inrelease_files=releases, index_files=indexes, runner=_runner, observed_at=1788652800)
    assert result["host"]["status"] == "PASS"
    assert result["gpu"]["status"] == "PASS"
    assert result["debian"]["status"] == "PASS"
    assert result["debian"]["correction_result"] == "NOT_REQUIRED"


def test_collects_from_keyring_bound_legacy_sources_list(tmp_path):
    root,releases,indexes=_fixture(tmp_path);(root/"etc/apt/sources.list.d/debian.sources").unlink()
    option="[signed-by=/usr/share/keyrings/debian-archive-keyring.gpg]"
    components="main contrib non-free non-free-firmware"
    _write(root/"etc/apt/sources.list",f"deb {option} https://deb.debian.org/debian trixie {components}\ndeb {option} https://deb.debian.org/debian trixie-updates {components}\ndeb {option} https://security.debian.org/debian-security trixie-security {components}\n")
    result=collect_host_observation(root=root,inrelease_files=releases,index_files=indexes,runner=_runner,observed_at=1788652800)
    assert result["debian"]["status"]=="PASS"


def test_unbound_legacy_source_is_denied(tmp_path):
    root,releases,indexes=_fixture(tmp_path);(root/"etc/apt/sources.list.d/debian.sources").unlink();_write(root/"etc/apt/sources.list","deb https://deb.debian.org/debian trixie main\n")
    with pytest.raises(DebianHostEvidenceError,match="DEBIAN_SOURCE_TRUST_DENIED"):
        collect_host_observation(root=root,inrelease_files=releases,index_files=indexes,runner=_runner,observed_at=1788652800)


def test_rejects_index_not_bound_by_signed_release(tmp_path):
    root, releases, indexes = _fixture(tmp_path)
    next(iter(indexes.values())).write_bytes(b"tampered")
    with pytest.raises(DebianHostEvidenceError, match="DEBIAN_INDEX_HASH_DENIED"):
        collect_host_observation(root=root, inrelease_files=releases, index_files=indexes, runner=_runner, observed_at=1788652800)


def test_rejects_unverified_inrelease(tmp_path):
    root, releases, indexes = _fixture(tmp_path)
    def bad(argv):
        return CompletedProcess(argv, 2, "", "bad signature") if argv[0] == "gpgv" else _runner(argv)
    with pytest.raises(DebianHostEvidenceError, match="DEBIAN_INRELEASE_SIGNATURE_DENIED"):
        collect_host_observation(root=root, inrelease_files=releases, index_files=indexes, runner=bad, observed_at=1788652800)


def test_only_signed_trixie_stable_may_omit_valid_until_beyond_fallback(tmp_path):
    root, releases, _ = _fixture(tmp_path)
    stable = releases["debian:trixie"]
    stable.write_bytes(stable.read_bytes().replace(b"Valid-Until: Sun, 13 Sep 2026 00:00:00 +0000\n", b""))
    result = verify_inrelease(stable, keyring=root / "usr/share/keyrings/debian-archive-keyring.gpg", runner=_runner, now=1789862400)
    assert result["suite"] == "stable" and result["codename"] == "trixie" and result["valid_until"] == ""


def test_signed_valid_until_remains_mandatory(tmp_path):
    root, releases, _ = _fixture(tmp_path)
    with pytest.raises(DebianHostEvidenceError, match="DEBIAN_RELEASE_STALE"):
        verify_inrelease(releases["debian:trixie"], keyring=root / "usr/share/keyrings/debian-archive-keyring.gpg", runner=_runner, now=1790208000)


def test_gpu_status_is_derived_not_supplied(tmp_path):
    root, releases, indexes = _fixture(tmp_path)
    (root / "proc/modules").write_text("")
    result = collect_host_observation(root=root, inrelease_files=releases, index_files=indexes, runner=_runner, observed_at=1788652800)
    assert result["gpu"]["status"] == "DRIFT"
