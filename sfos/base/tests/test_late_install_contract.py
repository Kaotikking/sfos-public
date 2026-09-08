from pathlib import Path
R=Path(__file__).parents[1]
def test_late_install_verifies_and_stays_inactive():
 s=(R/'installer/late-install.sh').read_text(); assert '--mode source' in s and 'OFFLINE_USB_MEDIA' in s and 'PINNED_PUBLIC_REPOSITORY' in s
 assert 'verify-source-road.py' in s and 'SOURCE_RECEIPT=$4' in s
 assert 'cp -a "$SOURCE/." "$STAGE/"' in s and 'trap cleanup EXIT HUP INT TERM' in s
 assert 'mktemp -d' in s and "stat -c '%u:%a:%F'" in s and '0:700:directory' in s
 assert 'sfos-outpost-source.$$' not in s
 assert 'openssl genpkey' not in s and 'openssl rand' not in s
 assert 'groupadd' not in s and 'useradd' not in s
 assert 'transaction.py" bootstrap' in s
 assert 'base-road-complete.json' in s and 'rollback_selector' in s
 assert 'NEW_OUTPOST_REQUIRED' in s and 'OUTPOST_INSTALLED_INACTIVE' in s
 assert not any(x in s for x in ('systemctl enable','systemctl start','reboot','shutdown','poweroff'))
