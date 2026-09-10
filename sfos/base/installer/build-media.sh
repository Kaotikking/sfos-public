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
 if rel=="sfos/source-road-receipt.json" or "__pycache__" in path.parts or path.name.endswith(".pyc") or path.name==".pytest_cache": continue
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
  -indev "$SOURCE_ISO" \
  -outdev "$STAGED_ISO" \
  -map "$PUBLIC_TREE/sfos" /sfos \
  -map "$SOURCE_ROAD_RECEIPT" /sfos/source-road-receipt.json \
  -map "$IMMUTABLE_INPUT_PLAN" /sfos/immutable-input-plan.json \
  -map "$PUBLIC_TREE/sfos/base/installer/preseed.cfg" /preseed.cfg \
  -boot_image any replay \
  -volid SFOS_PUBLIC_13_6 \
  -commit

python3 - "$LOCK" "$PUBLIC_TREE" "$SOURCE_ISO" "$STAGED_ISO" "$OUTPUT_ISO" "$STAGED_RECEIPT" "$SOURCE_ROAD_RECEIPT" <<'PY'
import hashlib, json, os, sys
from datetime import datetime, timezone
from pathlib import Path

lock_path, tree_path, source_path, staged_path, final_path, receipt_path, source_road_path = map(Path, sys.argv[1:])
lock = json.loads(lock_path.read_text(encoding="utf-8"))

def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

entries = []
for path in sorted((tree_path / "sfos").rglob("*"), key=lambda p: p.as_posix()):
    if path.is_file():
        rel = path.relative_to(tree_path).as_posix()
        entries.append({"path": rel, "bytes": path.stat().st_size, "sha256": digest_file(path)})
manifest_bytes = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
receipt = {
    "schema": "SFOSPublicMediaBuildReceipt/v1",
    "result": "BUILT_NOT_INSTALLED",
    "authority": "OFFICIAL_DEBIAN_SIGNED_RELEASE_PLUS_PUBLIC_SFOS_TREE",
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "source": {
        "filename": source_path.name,
        "bytes": source_path.stat().st_size,
        "sha256": digest_file(source_path),
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
    },
}
Path(receipt_path).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
PY

mv "$STAGED_ISO" "$OUTPUT_ISO"
mv "$STAGED_RECEIPT" "$RECEIPT"
echo "SFOS_PUBLIC_MEDIA_BUILT:$OUTPUT_ISO"
