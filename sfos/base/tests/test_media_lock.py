import json
from pathlib import Path
R=Path(__file__).parents[1]
def test_bound_media_is_exact_and_signature_precedes_checksum():
 lock=json.loads((R/'installer/media-lock.json').read_text())
 assert lock['status']=='BOUND'
 assert lock['image_filename']=='debian-13.6.0-amd64-netinst.iso'
 assert lock['image_bytes']==791674880
 assert len(lock['image_sha256'])==64 and len(lock['image_sha512'])==128
 assert lock['accepted_signing_fingerprints']==['DF9B9C49EAA9298432589D76DA87E80D6294BE9B']
 s=(R/'installer/verify-media.sh').read_text(); assert s.index('gpgv --status-fd') < s.index('sha256sum --check')
 assert 'MEDIA_LOCK_UNBOUND' in s and 'MEDIA_SIGNER_DENIED' in s
 assert 'len(records)!=1' in s and 'MEDIA_SUM_RECORD_DENIED' in s
 assert 'grep -F' not in s and '--ignore-missing' not in s
