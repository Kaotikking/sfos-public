"""Media byte/framework regressions, never boot or installed-Outpost proof."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

BASE=Path(__file__).parents[2]/"base/installer"
SPEC=importlib.util.spec_from_file_location("media_source_road",BASE/"verify-source-road.py")
MOD=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


@pytest.mark.parametrize("collision", [None, "file", "directory", "symlink"])
@pytest.mark.parametrize("target", ["iso", "receipt"])
def test_final_media_handoff_never_clobbers_a_late_destination(tmp_path, collision, target):
    script = (BASE / "build-media.sh").read_text()
    # Execute the actual final handoff, after the build's early absence checks.
    stanza = script[script.index('\nmv '):]
    staged_iso = tmp_path / "staged.iso"
    staged_receipt = tmp_path / "staged.json"
    staged_iso.write_bytes(b"exact new image")
    staged_receipt.write_bytes(b"exact new receipt")
    output_iso = tmp_path / "output.iso"
    output_receipt = tmp_path / "output.json"
    destination = output_iso if target == "iso" else output_receipt
    missing = tmp_path / "never-follow-this"
    if collision == "file":
        destination.write_bytes(b"independent existing output")
    elif collision == "directory":
        destination.mkdir()
    elif collision == "symlink":
        destination.symlink_to(missing)
    env = {**os.environ, "STAGED_ISO": str(staged_iso), "STAGED_RECEIPT": str(staged_receipt),
           "OUTPUT_ISO": str(output_iso), "RECEIPT": str(output_receipt)}
    result = subprocess.run(["/bin/sh", "-e", "-c", stanza], env=env,
                            capture_output=True, text=True)
    if collision is None:
        assert result.returncode == 0, result.stderr
        assert output_iso.read_bytes() == b"exact new image"
        assert output_receipt.read_bytes() == b"exact new receipt"
        assert "SFOS_PUBLIC_MEDIA_BUILT:" in result.stdout
        return
    assert result.returncode != 0
    assert "SFOS_PUBLIC_MEDIA_BUILT:" not in result.stdout
    if collision == "file":
        assert destination.read_bytes() == b"independent existing output"
    elif collision == "directory":
        assert destination.is_dir() and list(destination.iterdir()) == []
    else:
        assert destination.is_symlink() and destination.readlink() == missing
        assert not missing.exists()
    if target == "iso":
        assert not output_receipt.exists()
    else:
        # A two-file handoff is not atomic. Preserve the first artifact as
        # incomplete evidence; never claim BUILT or delete unrelated outputs.
        assert output_iso.read_bytes() == b"exact new image"


@pytest.fixture
def artifacts(tmp_path):
    root=tmp_path/"source"
    lockpath=root/"sfos/base/installer/media-lock.json"
    lockpath.parent.mkdir(parents=True)
    original=tmp_path/"debian-fixture.iso"
    output=tmp_path/"sfos-fixture.iso"
    original.write_bytes(b"synthetic input image, not bootable")
    output.write_bytes(b"synthetic output image, not bootable")
    sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    lock={"image_filename":original.name,"image_bytes":original.stat().st_size,"image_sha256":sha(original)}
    lockpath.write_text(json.dumps(lock))
    count,digest=MOD.payload_identity(root)
    receipt=tmp_path/"receipt.json"
    receipt.write_text(json.dumps({"schema":"SFOSPublicMediaBuildReceipt/v1","result":"BUILT_NOT_INSTALLED",
      "source":{"filename":original.name,"bytes":original.stat().st_size,"sha256":sha(original),"media_lock_sha256":sha(lockpath)},
      "output":{"filename":output.name,"bytes":output.stat().st_size,"sha256":sha(output)},
      "payload":{"file_count":count,"manifest_sha256":digest}}))
    return root,original,output,receipt


def test_real_bytes_required_but_matching_hashes_do_not_claim_authority_or_boot(artifacts):
    result=MOD.verify_media_artifact_integrity(*artifacts)
    assert result["result"]=="MEDIA_ARTIFACT_INTEGRITY_ONLY"
    assert all(result[key]=="UNPROVEN" for key in ("authority","bootability","installed","mounted_payload"))


@pytest.mark.parametrize("index",[1,2])
@pytest.mark.parametrize("change",["missing","changed","truncated"])
def test_actual_input_and_output_damage_denied(artifacts,index,change):
    path=artifacts[index]
    if change=="missing":path.unlink()
    elif change=="changed":path.write_bytes(b"X"*path.stat().st_size)
    else:path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(SystemExit,match="MEDIA_(UNREADABLE|INPUT_HASH_DENIED|OUTPUT_HASH_DENIED|SIZE_DENIED)"):
        MOD.verify_media_artifact_integrity(*artifacts)


@pytest.mark.parametrize("epoch",["","not-an-epoch","-1","9999999999999999999999999999"])
def test_builder_requires_valid_explicit_epoch_before_creating_any_output(tmp_path,epoch):
    env={**os.environ,"SOURCE_DATE_EPOCH":epoch}
    result=subprocess.run(["/bin/sh",str(BASE/"build-media.sh"),*(["not-used"]*10)],env=env,cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode!=0
    assert "MEDIA_SOURCE_DATE_EPOCH_" in result.stderr
    assert list(tmp_path.iterdir())==[]


def test_actual_xorriso_mapping_is_reproducible_despite_payload_timestamps(tmp_path):
    """Execute the builder's real xorriso stanza on small NONBOOTABLE fixtures.

    Closes timestamp nondeterminism only, not signed Debian/release/USB proof.
    """
    assert shutil.which("xorriso"),"Canonical build dependency must be provisioned"
    script=(BASE/"build-media.sh").read_text()
    stanza=script[script.index("xorriso \\"):script.index('\npython3 - "$LOCK" "$PUBLIC_TREE" "$SOURCE_ISO"')]
    source=tmp_path/"input.iso"
    upstream=tmp_path/"upstream"
    upstream.mkdir();(upstream/"README").write_text("Synthetic ISO framework only\n")
    env={**os.environ,"SOURCE_DATE_EPOCH":"1700000000","TZ":"UTC","LC_ALL":"C"}
    subprocess.run(["xorriso","-no_rc","-outdev",str(source),"-map",str(upstream),"/",
                    "-volume_date","all_file_dates","=1700000000","-commit"],env=env,check=True,capture_output=True)
    tree=tmp_path/"tree"
    preseed=tree/"sfos/base/installer/preseed.cfg"
    preseed.parent.mkdir(parents=True);preseed.write_text("# fixture only\n")
    receipt=tmp_path/"source-road-receipt.json";receipt.write_text("{}\n")
    plan=tmp_path/"immutable-input-plan.json";plan.write_text("{}\n")
    images=[]
    for index,stamp in enumerate((1000000000,1800000000)):
        for path in (preseed,receipt,plan,*preseed.parents):
            if path==tmp_path:break
            os.utime(path,(stamp,stamp))
        image=tmp_path/f"output-{index}.iso"
        build_env={**env,"SOURCE_ISO":str(source),"STAGED_ISO":str(image),"PUBLIC_TREE":str(tree),
                   "SOURCE_ROAD_RECEIPT":str(receipt),"STAGED_PLAN":str(plan),"STAGED_PRESEED":str(preseed)}
        subprocess.run(["/bin/sh","-c",stanza],env=build_env,check=True,capture_output=True)
        images.append(image)
    assert images[0].read_bytes()==images[1].read_bytes()


def test_rendered_preseed_binds_sixth_argument_without_changing_public_tree(tmp_path):
    import shlex
    script=(BASE/'build-media.sh').read_text()
    start=script.index('python3 - "$PUBLIC_TREE" "$IMMUTABLE_INPUT_PLAN" "$STAGED_PRESEED"')
    end=script.index('\nPY',start)+3
    tree=tmp_path/'tree'
    template=tree/'sfos/base/installer/preseed.cfg'
    template.parent.mkdir(parents=True)
    original=(BASE/'preseed.cfg').read_bytes()
    template.write_bytes(original)
    plan=tmp_path/'plan.json';plan.write_bytes(b'{"fixture":"not authority"}\n');plan.chmod(0o600)
    output=tmp_path/'preseed.cfg'
    snapshot=tmp_path/'staged-plan.json'
    env={**os.environ,'PUBLIC_TREE':str(tree),'IMMUTABLE_INPUT_PLAN':str(plan),'STAGED_PRESEED':str(output),'STAGED_PLAN':str(snapshot)}
    subprocess.run(['/bin/sh','-c',script[start:end]],env=env,check=True,capture_output=True)
    line=next(row for row in output.read_text().splitlines() if row.startswith('d-i preseed/late_command string '))
    command=shlex.split(line.split(' string ',1)[1])
    assert len(command[2:])==6
    assert command[-1]==hashlib.sha256(plan.read_bytes()).hexdigest()
    frozen=plan.read_bytes()
    assert snapshot.read_bytes()==frozen and snapshot.stat().st_mode & 0o777 == 0o600
    # Replace the caller's path after rendering. Mapping and receipt must never
    # return to that mutable path; they consume only the exact captured bytes.
    plan.unlink();plan.write_bytes(b'{"different":"later input"}\n')
    assert snapshot.read_bytes()==frozen
    mapping=script[script.index('xorriso \\'):script.index('\npython3 - "$LOCK" "$PUBLIC_TREE" "$SOURCE_ISO"')]
    assert '-map "$STAGED_PLAN" /sfos/immutable-input-plan.json' in mapping
    assert '$IMMUTABLE_INPUT_PLAN' not in mapping
    receipt_args=next(line for line in script.splitlines() if line.startswith('python3 - "$LOCK" "$PUBLIC_TREE" "$SOURCE_ISO"'))
    assert '"$STAGED_PLAN"' in receipt_args and '$IMMUTABLE_INPUT_PLAN' not in receipt_args
    assert '@SFOS_' not in output.read_text()
    assert template.read_bytes()==original
    # Read back the bytes from a real NONBOOTABLE fixture image, not just the
    # command's argument list. The replaced original input must be irrelevant.
    upstream=tmp_path/'upstream';upstream.mkdir()
    (upstream/'README').write_text('Nonbootable test image only\n')
    source_iso=tmp_path/'input.iso';built_iso=tmp_path/'built.iso'
    source_receipt=tmp_path/'source-receipt.json';source_receipt.write_text('{}\n')
    media_env={**env,'SOURCE_DATE_EPOCH':'1700000000','TZ':'UTC','LC_ALL':'C',
               'SOURCE_ISO':str(source_iso),'STAGED_ISO':str(built_iso),
               'SOURCE_ROAD_RECEIPT':str(source_receipt)}
    subprocess.run(['xorriso','-no_rc','-outdev',str(source_iso),'-map',str(upstream),'/',
                    '-volume_date','all_file_dates','=1700000000','-commit'],
                   env=media_env,check=True,capture_output=True)
    subprocess.run(['/bin/sh','-c',mapping],env=media_env,check=True,capture_output=True)
    readback_plan=tmp_path/'readback-plan.json';readback_preseed=tmp_path/'readback-preseed.cfg'
    subprocess.run(['xorriso','-no_rc','-osirrox','on','-indev',str(built_iso),
                    '-extract','/sfos/immutable-input-plan.json',str(readback_plan),
                    '-extract','/preseed.cfg',str(readback_preseed)],
                   env=media_env,check=True,capture_output=True)
    assert readback_plan.read_bytes()==frozen
    assert readback_preseed.read_bytes()==output.read_bytes()
    before=output.read_bytes()
    # No overwrite or implicit reuse of a previous media rendering.
    retry=subprocess.run(['/bin/sh','-c',script[start:end]],env=env,capture_output=True)
    assert retry.returncode!=0 and output.read_bytes()==before


@pytest.mark.parametrize("name", ["immutable-input-plan.json", "source-road-receipt.json"])
def test_builder_never_overwrites_public_source_with_generated_overlay(tmp_path, name):
    script = (BASE / "build-media.sh").read_text()
    start = script.index('python3 - "$LOCK" "$PUBLIC_TREE" <<')
    end = script.index('\nPY', start) + 3
    tree = tmp_path / "tree"
    embedded = tree / "sfos/base/installer/media-lock.json"
    embedded.parent.mkdir(parents=True)
    embedded.write_bytes(b'{"fixture":"not signed media"}\n')
    (embedded.parent / "preseed.cfg").write_bytes((BASE / "preseed.cfg").read_bytes())
    collision = tree / "sfos" / name
    collision.write_bytes(b'public source must not be hidden\n')
    before = collision.read_bytes()
    env = {**os.environ, "LOCK": str(embedded), "PUBLIC_TREE": str(tree)}
    result = subprocess.run(["/bin/sh", "-c", script[start:end]], env=env,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "PUBLIC_TREE_GENERATED_OVERLAY_COLLISION:" + name in result.stderr
    assert collision.read_bytes() == before


@pytest.mark.parametrize("drift", [None, "before_mapping", "after_mapping", "source_iso"])
def test_builder_receipt_matches_actual_iso_overlay_without_granting_authority(tmp_path, drift):
    """Real xorriso bytes, synthetic NONBOOTABLE media, no installer effect."""
    script = (BASE / "build-media.sh").read_text()
    tree = tmp_path / "tree"
    lock = tree / "sfos/base/installer/media-lock.json"
    lock.parent.mkdir(parents=True)
    preseed = lock.with_name("preseed.cfg")
    preseed.write_bytes((BASE / "preseed.cfg").read_bytes())
    release = tree / "sfos/outpost/release-manifest.json"
    release.parent.mkdir(parents=True)
    release.write_text(json.dumps({"self_digest": "sha256:" + "3" * 64}))
    public = tmp_path / "public-source.json"
    public.write_text(json.dumps({"repository": MOD.PUBLIC_REPOSITORY,
                                  "commit": "1" * 40, "tree": "2" * 40}))
    road = tmp_path / "source-road-receipt.json"
    plan = tmp_path / "captured-plan.json"
    plan.write_bytes(b'{"fixture":"not admitted"}\n')
    source_iso = tmp_path / "input.iso"
    output_iso = tmp_path / "output.iso"
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    (upstream / "README").write_text("Nonbootable fixture only\n")
    env = {**os.environ, "LOCK": str(lock), "PUBLIC_TREE": str(tree),
           "PUBLIC_SOURCE_RECEIPT": str(public), "SOURCE_ROAD_RECEIPT": str(road),
           "STAGED_PLAN": str(plan), "STAGED_PRESEED": str(preseed),
           "SOURCE_ISO": str(source_iso), "STAGED_ISO": str(output_iso),
           "OUTPUT_ISO": str(tmp_path / "final.iso"),
           "STAGED_RECEIPT": str(tmp_path / "build.json"), "SCRIPT_DIR": str(BASE),
           "SOURCE_DATE_EPOCH": "1700000000", "TZ": "UTC", "LC_ALL": "C"}
    subprocess.run(["xorriso", "-no_rc", "-outdev", str(source_iso),
                    "-map", str(upstream), "/", "-volume_date", "all_file_dates",
                    "=1700000000", "-commit"], env=env, check=True, capture_output=True)
    lock.write_text(json.dumps({"image_sha256": hashlib.sha256(source_iso.read_bytes()).hexdigest(),
                                "image_bytes": source_iso.stat().st_size, "image_filename": source_iso.name,
                                "release": "fixture", "accepted_signing_fingerprints": []}))
    start = script.index('python3 - "$LOCK" "$PUBLIC_TREE" "$PUBLIC_SOURCE_RECEIPT"')
    end = script.index('\nPY', start) + 3
    subprocess.run(["/bin/sh", "-c", script[start:end]], env=env, check=True, capture_output=True)
    if drift == "before_mapping":
        (tree / "sfos/late-source.txt").write_text("changed after receipt\n")
    start = script.index("xorriso \\")
    end = script.index('\npython3 - "$LOCK" "$PUBLIC_TREE" "$SOURCE_ISO"', start)
    subprocess.run(["/bin/sh", "-c", script[start:end]], env=env, check=True, capture_output=True)
    if drift == "after_mapping":
        (tree / "sfos/late-source.txt").write_text("changed after image\n")
    elif drift == "source_iso":
        source_iso.write_bytes(b"X" * source_iso.stat().st_size)
    receipt_start = script.index('python3 - "$LOCK" "$PUBLIC_TREE" "$SOURCE_ISO"')
    receipt_end = script.index('\nPY', receipt_start) + 3
    built = subprocess.run(["/bin/sh", "-e", "-c", script[receipt_start:receipt_end]],
                           env=env, capture_output=True, text=True)
    if drift:
        assert built.returncode != 0
        expected = {"before_mapping": "OFFLINE_PAYLOAD_MISMATCH",
                    "after_mapping": "MEDIA_PUBLIC_SOURCE_CHANGED",
                    "source_iso": "MEDIA_INPUT_HASH_DENIED"}[drift]
        assert expected in built.stderr
        assert not Path(env["STAGED_RECEIPT"]).exists()
        return
    assert built.returncode == 0, built.stderr
    external = json.loads(Path(env["STAGED_RECEIPT"]).read_text())
    assert (external["payload"]["file_count"], external["payload"]["manifest_sha256"]) == MOD.payload_identity(tree)
    assert external["output"]["sha256"] == hashlib.sha256(output_iso.read_bytes()).hexdigest()
    assert external["payload"]["immutable_input_plan_sha256"] == hashlib.sha256(plan.read_bytes()).hexdigest()
    readback = tmp_path / "readback"
    readback.mkdir()
    subprocess.run(["xorriso", "-no_rc", "-osirrox", "on", "-indev", str(output_iso),
                    "-extract", "/sfos", str(readback / "sfos")],
                   env=env, check=True, capture_output=True)
    assert (readback / "sfos/immutable-input-plan.json").read_bytes() == plan.read_bytes()
    mounted_receipt = readback / "sfos/source-road-receipt.json"
    result = MOD.verify_offline_payload(readback, MOD.load_exact(mounted_receipt))
    assert result["result"] == "OFFLINE_PAYLOAD_INTEGRITY_ONLY"
    assert result["authority"] == "UNPROVEN"
    with pytest.raises(SystemExit, match="OFFLINE_SOURCE_AUTHORITY_UNPROVEN"):
        MOD.verify(readback, "OFFLINE_USB_MEDIA", mounted_receipt)
