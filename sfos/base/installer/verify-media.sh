#!/bin/sh
set -eu
[ "$#" -eq 5 ] || exit 64
LOCK=$1 ISO=$2 SUMS=$3 SIGNATURE=$4 KEYRING=$5
python3 - "$LOCK" "$ISO" "$SUMS" "$SIGNATURE" <<'PY'
import hashlib,json,re,sys
from pathlib import Path
l=json.loads(Path(sys.argv[1]).read_text())
if l.get('schema')!='SFOSDebianMediaLock/v1' or l.get('status')!='BOUND' or l.get('authority')!='OFFICIAL_DEBIAN_SIGNED_RELEASE_ONLY': raise SystemExit('MEDIA_LOCK_UNBOUND')
for supplied,key in ((sys.argv[2],'image_sha256'),(sys.argv[3],'checksums_sha256'),(sys.argv[4],'signature_sha256')):
 if not re.fullmatch(r'[0-9a-f]{64}',str(l.get(key))) or hashlib.sha256(Path(supplied).read_bytes()).hexdigest()!=l[key]: raise SystemExit('MEDIA_ARTIFACT_HASH_DENIED')
if Path(sys.argv[2]).name!=l.get('image_filename') or Path(sys.argv[2]).stat().st_size!=l.get('image_bytes'): raise SystemExit('MEDIA_IDENTITY_DENIED')
PY
STATUS=$(mktemp); trap 'rm -f "$STATUS"' EXIT HUP INT TERM
gpgv --status-fd 1 --keyring "$KEYRING" "$SIGNATURE" "$SUMS" >"$STATUS" 2>/dev/null || exit 1
python3 - "$LOCK" "$STATUS" <<'PY'
import json,sys
from pathlib import Path
l=json.loads(Path(sys.argv[1]).read_text()); allowed={x.replace(' ','').upper() for x in l['accepted_signing_fingerprints']}; seen={x.split()[2] for x in Path(sys.argv[2]).read_text().splitlines() if x.startswith('[GNUPG:] VALIDSIG ')}
if not seen or not seen <= allowed: raise SystemExit('MEDIA_SIGNER_DENIED')
PY
python3 - "$LOCK" "$SUMS" "$ISO" <<'PY'
import json,re,sys
from pathlib import Path
l=json.loads(Path(sys.argv[1]).read_text()); name=Path(sys.argv[3]).name
records=[]
for line in Path(sys.argv[2]).read_text(encoding='utf-8').splitlines():
 m=re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)',line)
 if m and m.group(2)==name: records.append(m.group(1).lower())
if len(records)!=1 or records[0]!=l['image_sha256']: raise SystemExit('MEDIA_SUM_RECORD_DENIED')
PY
printf '%s  %s\n' "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_sha256"])' "$LOCK")" "$ISO" | sha256sum --check --strict -
echo VERIFIED_OFFICIAL_DEBIAN_MEDIA
