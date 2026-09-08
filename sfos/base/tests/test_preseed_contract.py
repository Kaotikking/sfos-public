from pathlib import Path
R=Path(__file__).parents[1]
def test_preseed_is_neutral_and_keeps_disk_interactive():
 s=(R/'installer/preseed.cfg').read_text()
 assert 'partman-auto/disk string' not in s and 'partman-auto/disk seen false' in s
 assert 'VM4010' not in s and 'PVE_REST_QGA' not in s and '/target /cdrom' in s
