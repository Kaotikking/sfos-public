import json
from pathlib import Path
R=Path(__file__).parents[1]
def test_converge_accepts_only_governed_source_roads_and_reuses_atomic_transaction():
 p=json.loads((R/'installer/base-policy.json').read_text()); assert p['source_kinds']==['OFFLINE_USB_MEDIA','PINNED_PUBLIC_REPOSITORY']
 s=(R/'installer/converge-existing.sh').read_text(); assert '--mode source' in s
 assert 'outpost.host_witness_runner' in s
 assert 'transaction.py" install' in s
 assert 'OUTPOST_INSTALLED_INACTIVE' in s
 assert 'ROLLBACK_BASE_REQUIRED' in s and 'IMMUTABLE_INPUT_PLAN_REQUIRED' in s
 assert "stat -c '%a:%u:%g'" in s and '600:0:0' in s
 assert s.index('outpost.host_witness_runner') < s.index('transaction.py" install')
 assert not any(x in s for x in ('VM4010','PVE_REST_QGA','parted ','mkfs','grub-install','apt-get install','systemctl enable','systemctl start','shutdown -','reboot\n'))

def test_convergence_preserves_host_identity_and_fails_closed_on_debian_or_gpu_drift():
 s=(R/'installer/converge-existing.sh').read_text()
 assert 'identity_replacement' in s and "'status')!='PASS'" in s
 assert "d.get('exact_diff')" in s and "d.get('unknowns')" in s
 preflight=json.loads((R.parent/'outpost/install-preflight.json').read_text())
 assert preflight['expected_before']['hostname_policy']=='PRESERVE_NONEMPTY'
 assert 'hostname' not in preflight['expected_before']
