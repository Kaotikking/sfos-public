"""Local canonical two-path policy proof, not an OS installation test."""
import json
from pathlib import Path
from outpost.debian_host_collector import EXPECTED_SOURCES


def policy():
    return json.loads((Path(__file__).parents[2]/"base/installer/base-policy.json").read_text())


def test_base_policy_preserves_two_install_paths_and_signed_debian_denominator():
    value=policy()
    assert value["suite"]=="trixie" and value["version_id"]=="13"
    assert value["modes"]==["BARE_INSTALL","CONVERGE_EXISTING"]
    assert value["source_kinds"]==["OFFLINE_USB_MEDIA","PINNED_PUBLIC_REPOSITORY"]
    assert value["components"]==["main","contrib","non-free","non-free-firmware"]
    assert all(tuple(value["components"])==components for _,_,components in EXPECTED_SOURCES)
    assert value["repository_hosts"]==["deb.debian.org","security.debian.org"]


def test_conversion_cannot_partition_format_replace_bootloader_or_identity():
    value=policy()
    assert value["converge_existing"]=={"partitioning":False,"formatting":False,"bootloader_replacement":False,"identity_replacement":False}
    assert value["bare_install"]=={"operator_disk_required":True,"stable_disk_identity_required":True,"destructive_confirmation_required":True,"automatic_disk_selection":False}
    assert all(row["reboot"] is False and row["commission"] is False for row in value["activation"].values())
    assert value["unknown_policy"]=="FAIL_CLOSED"


def test_fresh_installer_uses_same_components_and_declared_crypto_dependency():
    preseed=(Path(__file__).parents[2]/"base/installer/preseed.cfg").read_text()
    for component in ("contrib", "non-free", "non-free-firmware"):
        assert f"d-i apt-setup/{component} boolean true" in preseed.splitlines()
    packages=next(line.split(" string ",1)[1].split() for line in preseed.splitlines()
                  if line.startswith("d-i pkgsel/include string "))
    assert {"ca-certificates", "debian-archive-keyring", "gpgv", "python3",
            "python3-cryptography", "systemd"} <= set(packages)
    for guard in ("partman-auto/disk", "partman/confirm", "partman/confirm_nooverwrite"):
        assert f"d-i {guard} seen false" in preseed.splitlines()
    assert "partman-auto/disk string" not in preseed
    assert "reboot_in_progress" not in preseed
    assert "VM4010" not in preseed
