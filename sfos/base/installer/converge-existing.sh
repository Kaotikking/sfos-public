#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
[ "$#" -eq 4 ] || { echo "usage: converge-existing.sh POLICY PUBLIC_TREE SOURCE_KIND SOURCE_RECEIPT" >&2; exit 64; }
POLICY=$1 PUBLIC_TREE=$2 SOURCE_KIND=$3 SOURCE_RECEIPT=$4
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
if p.get('activation')!={'enable':False,'start':False,'reboot':False,'commission':False}: raise SystemExit('ACTIVATION_POLICY_DENIED')
PY
python3 -B "$SOURCE/verify_install_preflight.py" --source "$SOURCE" --mode source
python3 -B "$PUBLIC_TREE/sfos/base/installer/verify-source-road.py" "$PUBLIC_TREE" "$SOURCE_KIND" "$SOURCE_RECEIPT"
for path in /usr/share/serein/outpost /etc/serein-outpost /var/lib/serein-outpost /run/serein/outpost; do
  [ ! -e "$path" ] || { echo NEW_OUTPOST_REQUIRED >&2; exit 1; }
done
[ -d /var/lib/serein/rollback ] && [ ! -L /var/lib/serein/rollback ] || { echo ROLLBACK_BASE_REQUIRED >&2; exit 1; }
[ "$(stat -c '%a:%u:%g' /var/lib/serein/rollback)" = 755:0:0 ] || { echo ROLLBACK_BASE_POLICY_DENIED >&2; exit 1; }
WITNESS_ROOT=$(mktemp -d /var/tmp/sfos-converge-witness.XXXXXX)
cleanup() { rm -rf "$WITNESS_ROOT"; }
trap cleanup EXIT HUP INT TERM
PYTHONPATH="$SOURCE" python3 -B -m outpost.host_witness_runner --state-root "$WITNESS_ROOT"
python3 - "$WITNESS_ROOT/state.json" <<'PY'
import json,sys
from pathlib import Path
s=json.loads(Path(sys.argv[1]).read_text()); o=s.get('latest',{})
if s.get('authority_effect')!='NONE' or s.get('mutation_effect')!='NONE': raise SystemExit('HOST_WITNESS_EFFECT_DENIED')
if o.get('target')!='SEREIN_HOST' or o.get('host',{}).get('status')!='PASS' or o.get('gpu',{}).get('status')!='PASS': raise SystemExit('HOST_GATE_DENIED')
d=o.get('debian',{})
if d.get('status')!='PASS' or d.get('exact_diff') or d.get('unknowns') or d.get('correction_result')!='NOT_REQUIRED': raise SystemExit('DEBIAN_HOST_GATE_DENIED')
PY
# The existing transaction captures and fsyncs exact prestate plus an executable
# rollback selector before its first payload/identity write, and verifies the
# resulting Outpost remains disabled, stopped, and uncommissioned.
python3 -B "$SOURCE/install/transaction.py" bootstrap "$SOURCE" "$SOURCE_KIND"
echo OUTPOST_INSTALLED_INACTIVE
