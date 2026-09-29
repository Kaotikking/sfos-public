#!/bin/sh
set -eu

usage() {
  echo "usage: $0 LOCK ISO SUMS SIGNATURE KEYRING PUBLIC_TREE PUBLIC_SOURCE_RECEIPT IMMUTABLE_INPUT_PLAN OUTPUT_ISO RECEIPT" >&2
  exit 64
}

[ "$#" -eq 10 ] || usage
LOCK=$1
SOURCE_ISO=$2
SUMS=$3
SIGNATURE=$4
KEYRING=$5
PUBLIC_TREE=$6
PUBLIC_SOURCE_RECEIPT=$7
IMMUTABLE_INPUT_PLAN=$8
OUTPUT_ISO=$9
RECEIPT=${10}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# A caller must bind this reproducible-build input to the exact source release.
# Never derive it from the local clock or mutable filesystem timestamps.
case ${SOURCE_DATE_EPOCH-} in
  ''|*[!0-9]*) echo "MEDIA_SOURCE_DATE_EPOCH_REQUIRED" >&2; exit 65 ;;
esac
python3 - "$SOURCE_DATE_EPOCH" <<'PY'
import sys
from datetime import datetime, timezone
try:
    stamp = datetime.fromtimestamp(int(sys.argv[1]), timezone.utc)
except (OverflowError, OSError, ValueError):
    raise SystemExit("MEDIA_SOURCE_DATE_EPOCH_DENIED")
if not 1970 <= stamp.year <= 2999:
    raise SystemExit("MEDIA_SOURCE_DATE_EPOCH_DENIED")
PY
TZ=UTC
LC_ALL=C
export SOURCE_DATE_EPOCH TZ LC_ALL

for tool in python3 gpgv sha256sum xorriso; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "MEDIA_BUILD_PREREQUISITE_MISSING:$tool" >&2
    exit 69
  }
done

[ -d "$PUBLIC_TREE/sfos" ] || { echo "PUBLIC_TREE_SFOS_MISSING" >&2; exit 66; }
[ -f "$PUBLIC_TREE/sfos/base/installer/preseed.cfg" ] || { echo "PUBLIC_TREE_PRESEED_MISSING" >&2; exit 66; }
[ ! -e "$OUTPUT_ISO" ] || { echo "OUTPUT_ALREADY_EXISTS" >&2; exit 73; }
[ ! -e "$RECEIPT" ] || { echo "RECEIPT_ALREADY_EXISTS" >&2; exit 73; }
[ -f "$IMMUTABLE_INPUT_PLAN" ] && [ ! -L "$IMMUTABLE_INPUT_PLAN" ] || { echo "IMMUTABLE_INPUT_PLAN_REQUIRED" >&2; exit 66; }
[ "$(stat -c '%a:%u:%g' "$IMMUTABLE_INPUT_PLAN")" = 600:0:0 ] || { echo "IMMUTABLE_INPUT_PLAN_CUSTODY_DENIED" >&2; exit 77; }

python3 -B "$PUBLIC_TREE/sfos/base/installer/verify-source-road.py" "$PUBLIC_TREE" PINNED_PUBLIC_REPOSITORY "$PUBLIC_SOURCE_RECEIPT"

python3 - "$LOCK" "$PUBLIC_TREE" <<'PY'
import hashlib, os, sys
from pathlib import Path

lock, tree = map(Path, sys.argv[1:])
embedded = tree / "sfos/base/installer/media-lock.json"
if not embedded.is_file() or hashlib.sha256(lock.read_bytes()).digest() != hashlib.sha256(embedded.read_bytes()).digest():
    raise SystemExit("EMBEDDED_MEDIA_LOCK_MISMATCH")
for generated in ("source-road-receipt.json", "immutable-input-plan.json"):
    if os.path.lexists(tree / "sfos" / generated):
        raise SystemExit("PUBLIC_TREE_GENERATED_OVERLAY_COLLISION:" + generated)
for path in (tree / "sfos").rglob("*"):
    if path.is_symlink() or (not path.is_dir() and not path.is_file()):
        raise SystemExit("PUBLIC_TREE_UNSAFE_ENTRY:" + path.relative_to(tree).as_posix())
preseed = (tree / "sfos/base/installer/preseed.cfg").read_text(encoding="utf-8")
for required in ("partman-auto/disk seen false", "partman/confirm seen false", "partman/confirm_nooverwrite seen false"):
    if required not in preseed:
        raise SystemExit("INTERACTIVE_STORAGE_GUARD_MISSING:" + required)
PY

# Authenticity and exact upstream identity are established before any output is made.
"$SCRIPT_DIR/verify-media.sh" "$LOCK" "$SOURCE_ISO" "$SUMS" "$SIGNATURE" "$KEYRING"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
STAGED_ISO="$WORK_DIR/sfos-public.iso"
STAGED_RECEIPT="$WORK_DIR/build-receipt.json"
SOURCE_ROAD_RECEIPT="$WORK_DIR/source-road-receipt.json"
STAGED_PRESEED="$WORK_DIR/preseed.cfg"
STAGED_PLAN="$WORK_DIR/immutable-input-plan.json"

# Render only the root convenience preseed; never alter the exact public tree.
# A digest binds input bytes, not portable installation authority. The latter
# must still pass the canonical package's independent source/authority gate.
python3 - "$PUBLIC_TREE" "$IMMUTABLE_INPUT_PLAN" "$STAGED_PRESEED" "$STAGED_PLAN" <<'PY'
import hashlib,os,stat,sys
from pathlib import Path
tree,plan,output,snapshot=map(Path,sys.argv[1:])
template=(tree/'sfos/base/installer/preseed.cfg').read_text(encoding='utf-8')
marker='@SFOS_IMMUTABLE_PLAN_SHA256@'
if template.count(marker)!=1: raise SystemExit('PRESEED_PLAN_BINDING_DENIED')
fd=os.open(plan,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as stream:
 info=os.fstat(stream.fileno())
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o600: raise SystemExit('IMMUTABLE_INPUT_PLAN_CUSTODY_DENIED')
 raw=stream.read(1024*1024+1)
 if not raw or len(raw)>1024*1024: raise SystemExit('IMMUTABLE_INPUT_PLAN_SIZE_DENIED')
 after=os.fstat(stream.fileno())
 if (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise SystemExit('IMMUTABLE_INPUT_PLAN_CHANGED')
fd=os.open(snapshot,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream:
 stream.write(raw);stream.flush();os.fsync(stream.fileno())
rendered=template.replace(marker,hashlib.sha256(raw).hexdigest())
with output.open('x',encoding='utf-8',newline='\n') as stream: stream.write(rendered)
PY

python3 - "$LOCK" "$PUBLIC_TREE" "$PUBLIC_SOURCE_RECEIPT" "$SOURCE_ROAD_RECEIPT" <<'PY'
import hashlib,json,sys
from pathlib import Path
lock_path,tree,public_receipt_path,output=map(Path,sys.argv[1:])
lock=json.loads(lock_path.read_text(encoding="utf-8"))
release=json.loads((tree/"sfos/outpost/release-manifest.json").read_text(encoding="utf-8"))
public=json.loads(public_receipt_path.read_text(encoding="utf-8"))
lock_hash=hashlib.sha256(lock_path.read_bytes()).hexdigest()
entries=[]
for path in sorted((tree/"sfos").rglob("*"),key=lambda p:p.as_posix()):
 rel=path.relative_to(tree).as_posix()
 if rel=="sfos/source-road-receipt.json": continue
 if path.is_symlink() or (not path.is_dir() and not path.is_file()): raise SystemExit("PUBLIC_TREE_UNSAFE_ENTRY:"+rel)
 if path.is_file(): entries.append({"path":rel,"bytes":path.stat().st_size,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
encoded=json.dumps(entries,sort_keys=True,separators=(",",":")).encode()
payload={
 "schema":"SFOSSourceRoadReceipt/v1",
 "source_kind":"OFFLINE_USB_MEDIA",
 "outpost_release_digest":release["self_digest"],
 "build_id":"sfos-usb-"+release["self_digest"].split(":",1)[1][:16],
 "media_lock_sha256":lock_hash,
 "debian_iso_sha256":lock["image_sha256"],
 "public_repository":public["repository"],
 "public_commit":public["commit"],
 "public_tree":public["tree"],
 "payload_file_count":len(entries),
 "payload_manifest_sha256":hashlib.sha256(encoded).hexdigest(),
}
output.write_text(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
PY

# Replay the signed Debian image's existing BIOS/UEFI boot equipment, changing only
# the target-neutral public installer tree and the root preseed convenience copy.
xorriso \
  -no_rc \
  -indev "$SOURCE_ISO" \
  -outdev "$STAGED_ISO" \
  -map "$PUBLIC_TREE/sfos" /sfos \
  -map "$SOURCE_ROAD_RECEIPT" /sfos/source-road-receipt.json \
  -map "$STAGED_PLAN" /sfos/immutable-input-plan.json \
  -map "$STAGED_PRESEED" /preseed.cfg \
  -boot_image any replay \
  -volume_date all_file_dates "=$SOURCE_DATE_EPOCH" \
  -volid SFOS_PUBLIC_13_6 \
  -commit

python3 - "$LOCK" "$PUBLIC_TREE" "$SOURCE_ISO" "$STAGED_ISO" "$OUTPUT_ISO" "$STAGED_RECEIPT" "$SOURCE_ROAD_RECEIPT" "$STAGED_PRESEED" "$STAGED_PLAN" "$SCRIPT_DIR" <<'PY'
import hashlib, importlib.util, json, os, subprocess, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

lock_path, tree_path, source_path, staged_path, final_path, receipt_path, source_road_path, preseed_path, plan_path, script_dir = map(Path, sys.argv[1:])
lock = json.loads(lock_path.read_text(encoding="utf-8"))

def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

spec = importlib.util.spec_from_file_location("build_source_road", script_dir / "verify-source-road.py")
road = importlib.util.module_from_spec(spec)
spec.loader.exec_module(road)
bound = road.load_exact(source_road_path)
if source_path.name != lock.get("image_filename"):
    raise SystemExit("MEDIA_INPUT_BINDING_DENIED")
source_sha256 = road.media_file_identity(source_path, lock.get("image_bytes"))
if source_sha256 != lock.get("image_sha256"):
    raise SystemExit("MEDIA_INPUT_HASH_DENIED")
entries = []
# Read the real staged image, not just the mutable build input. This proves
# integrity only; the unsigned receipt still cannot grant portable authority.
with tempfile.TemporaryDirectory(prefix="media-readback-", dir=staged_path.parent) as name:
    readback = Path(name)
    subprocess.run(["xorriso", "-no_rc", "-osirrox", "on", "-indev", str(staged_path),
                    "-extract", "/sfos", str(readback / "sfos"),
                    "-extract", "/preseed.cfg", str(readback / "preseed.cfg")],
                   check=True, capture_output=True)
    for extracted, captured in ((readback / "sfos/source-road-receipt.json", source_road_path),
                                (readback / "sfos/immutable-input-plan.json", plan_path),
                                (readback / "preseed.cfg", preseed_path)):
        if road.read_regular(extracted, road.MAX_JSON_BYTES) != road.read_regular(captured, road.MAX_JSON_BYTES):
            raise SystemExit("MEDIA_CAPTURED_OVERLAY_MISMATCH")
    road.verify_offline_payload(readback, bound)
    if road.payload_identity(tree_path) != (bound["payload_file_count"], bound["payload_manifest_sha256"]):
        raise SystemExit("MEDIA_PUBLIC_SOURCE_CHANGED")
    for path in sorted((readback / "sfos").rglob("*"), key=lambda p: p.as_posix()):
        rel = path.relative_to(readback).as_posix()
        if rel in ("sfos/source-road-receipt.json", "sfos/immutable-input-plan.json"):
            continue
        if path.is_file():
            raw = road.read_regular(path, road.MAX_PAYLOAD_BYTES)
            entries.append({"path": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
manifest_bytes = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
receipt = {
    "schema": "SFOSPublicMediaBuildReceipt/v1",
    "result": "BUILT_NOT_INSTALLED",
    "authority": "OFFICIAL_DEBIAN_SIGNED_RELEASE_PLUS_PUBLIC_SFOS_TREE",
    "created_at": datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]), timezone.utc).isoformat().replace("+00:00", "Z"),
    "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "source": {
        "filename": source_path.name,
        "bytes": lock["image_bytes"],
        "sha256": source_sha256,
        "media_lock_sha256": digest_file(lock_path),
        "debian_release": lock["release"],
        "debian_signing_fingerprints": lock["accepted_signing_fingerprints"],
    },
    "payload": {
        "root": "sfos",
        "file_count": len(entries),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "files": entries,
        "source_road_receipt_sha256": digest_file(source_road_path),
        "root_preseed_sha256": digest_file(preseed_path),
        "immutable_input_plan_sha256": digest_file(plan_path),
    },
    "output": {
        "filename": final_path.name,
        "bytes": staged_path.stat().st_size,
        "sha256": digest_file(staged_path),
        "volume_id": "SFOS_PUBLIC_13_6",
        "boot_equipment": "REPLAYED_FROM_VERIFIED_DEBIAN_SOURCE",
    },
    "installation_policy": {
        "target_neutral": True,
        "disk_selection": "INTERACTIVE",
        "destructive_confirmation": "INTERACTIVE",
        "automatic_reboot": False,
        "modes": ["BARE_INSTALL", "CONVERGE_EXISTING"],
    },
}
Path(receipt_path).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
PY

# Recheck absence at the native move boundary. Never clobber a late output or
# interpret a destination directory as a container. A skipped move must fail.
mv -T --update=none-fail -- "$STAGED_ISO" "$OUTPUT_ISO"
mv -T --update=none-fail -- "$STAGED_RECEIPT" "$RECEIPT"
echo "SFOS_PUBLIC_MEDIA_BUILT:$OUTPUT_ISO"
