#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
[ "$#" -eq 6 ] || { echo "usage: converge-existing.sh POLICY PUBLIC_TREE SOURCE_KIND SOURCE_RECEIPT IMMUTABLE_INPUT_PLAN EXPECTED_PLAN_SHA256" >&2; exit 64; }
POLICY=$1 PUBLIC_TREE=$2 SOURCE_KIND=$3 SOURCE_RECEIPT=$4 IMMUTABLE_INPUT_PLAN=$5 EXPECTED_PLAN_SHA256=$6
case "$EXPECTED_PLAN_SHA256" in ''|*[!0-9a-f]*) echo EXPECTED_PLAN_SHA256_REQUIRED >&2; exit 64 ;; esac
[ "${#EXPECTED_PLAN_SHA256}" -eq 64 ] || { echo EXPECTED_PLAN_SHA256_REQUIRED >&2; exit 64; }
SOURCE=$PUBLIC_TREE/sfos/outpost
[ "$SOURCE_KIND" = OFFLINE_USB_MEDIA ] || [ "$SOURCE_KIND" = PINNED_PUBLIC_REPOSITORY ] || exit 1
[ "$(id -u)" -eq 0 ] && [ "$(dpkg --print-architecture)" = amd64 ] || exit 1
grep -q '^ID=debian$' /etc/os-release && grep -Eq '^VERSION_ID="?13"?$' /etc/os-release || exit 1
python3 - "$POLICY" "$SOURCE_KIND" <<'PY'
import json,sys
from pathlib import Path
p=json.loads(Path(sys.argv[1]).read_text())
if p.get('schema')!='SFOSDebianBasePolicy/v1' or sys.argv[2] not in p.get('source_kinds',[]) or p.get('unknown_policy')!='FAIL_CLOSED': raise SystemExit('BASE_POLICY_DENIED')
if p.get('converge_existing')!={'partitioning':False,'formatting':False,'bootloader_replacement':False,'identity_replacement':False}: raise SystemExit('CONVERGENCE_POLICY_DENIED')
if p.get('activation',{}).get('converge_existing')!={'enable':True,'start':True,'reboot':False,'commission':False}: raise SystemExit('ACTIVATION_POLICY_DENIED')
PY
python3 -B "$SOURCE/verify_install_preflight.py" --source "$SOURCE" --mode source
python3 -B "$PUBLIC_TREE/sfos/base/installer/verify-source-road.py" "$PUBLIC_TREE" "$SOURCE_KIND" "$SOURCE_RECEIPT"
[ -f "$IMMUTABLE_INPUT_PLAN" ] && [ ! -L "$IMMUTABLE_INPUT_PLAN" ] || { echo IMMUTABLE_INPUT_PLAN_REQUIRED >&2; exit 1; }
[ "$(stat -c '%a:%u:%g' "$IMMUTABLE_INPUT_PLAN")" = 600:0:0 ] || { echo IMMUTABLE_INPUT_PLAN_CUSTODY_DENIED >&2; exit 1; }
# Debian delegates the complete transaction to the canonical package entry.
# Outpost, once installed, derives Host drift. This wrapper must not demand a
# pre-existing Host PASS, reject preserved immutable-key directories, stage a
# partial install, operate units or invoke the old compensating Base wrapper.
# Target classification, immutable preservation and atomic acceptance remain
# the package entry's responsibility; no preflight is bypassed here.
ENTRY=$SOURCE/install/install-outpost.sh
[ -f "$ENTRY" ] && [ ! -L "$ENTRY" ] || { echo CANONICAL_OUTPOST_ENTRY_UNAVAILABLE >&2; exit 1; }
exec /bin/sh "$ENTRY" "$SOURCE" install / "$IMMUTABLE_INPUT_PLAN" "$EXPECTED_PLAN_SHA256" "$SOURCE_KIND" "$SOURCE_RECEIPT"
