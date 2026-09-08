from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_builder_verifies_exact_media_before_xorriso_and_replays_boot_equipment():
    script = (ROOT / "installer/build-media.sh").read_text()
    assert script.index('"$SCRIPT_DIR/verify-media.sh"') < script.index("xorriso \\")
    assert "-boot_image any replay" in script
    assert '-map "$PUBLIC_TREE/sfos" /sfos' in script
    assert '-map "$SOURCE_ROAD_RECEIPT" /sfos/source-road-receipt.json' in script
    assert '-map "$PUBLIC_TREE/sfos/base/installer/preseed.cfg" /preseed.cfg' in script


def test_builder_is_fail_closed_and_emits_lineage_receipt():
    script = (ROOT / "installer/build-media.sh").read_text()
    assert "OUTPUT_ALREADY_EXISTS" in script
    assert "RECEIPT_ALREADY_EXISTS" in script
    assert "SFOSPublicMediaBuildReceipt/v1" in script
    assert "media_lock_sha256" in script
    assert "manifest_sha256" in script
    assert "BUILT_NOT_INSTALLED" in script
    assert "EMBEDDED_MEDIA_LOCK_MISMATCH" in script
    assert "PUBLIC_TREE_UNSAFE_ENTRY" in script
    assert "INTERACTIVE_STORAGE_GUARD_MISSING" in script
    assert 'SFOSSourceRoadReceipt/v1' in script
    assert 'outpost_release_digest' in script
    assert 'source_road_receipt_sha256' in script


def test_bare_install_remains_operator_selected_and_non_rebooting():
    preseed = (ROOT / "installer/preseed.cfg").read_text()
    assert "partman-auto/disk seen false" in preseed
    assert "partman/confirm seen false" in preseed
    assert "partman/confirm_nooverwrite seen false" in preseed
    assert "reboot_in_progress" not in preseed
    assert "/cdrom/sfos/source-road-receipt.json" in preseed


def test_operator_instructions_use_official_file_preseed_road_and_limit_claim():
    guide = (ROOT / "installer/MEDIA_BUILD.md").read_text()
    assert "preseed/file=/cdrom/preseed.cfg" in guide
    assert "Disk choice and both destructive confirmations remain interactive" in guide
    assert "BUILT_NOT_INSTALLED" in guide
    assert "hardware boot" in guide
