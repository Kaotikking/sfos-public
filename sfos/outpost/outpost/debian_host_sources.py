"""One-time, fail-closed migration of the Debian installer source shape."""
from __future__ import annotations
import hashlib, json, os
from pathlib import Path

LEGACY_ACTIVE = "deb http://deb.debian.org/debian trixie main contrib non-free-firmware non-free"
CANONICAL = """Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://security.debian.org/debian-security
Suites: trixie-security
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
"""
class DebianSourceMigrationError(RuntimeError): pass

def migrate(root: Path = Path("/")) -> dict[str, str]:
    legacy=root/"etc/apt/sources.list";target=root/"etc/apt/sources.list.d/debian.sources"
    if target.is_file():
        if target.read_text(encoding="utf-8") != CANONICAL: raise DebianSourceMigrationError("DEBIAN_SOURCES_EXISTING_CONFLICT")
        return {"status":"CANONICAL_ALREADY_PRESENT"}
    if legacy.is_symlink() or not legacy.is_file(): raise DebianSourceMigrationError("LEGACY_SOURCES_REGULAR_FILE_REQUIRED")
    original=legacy.read_bytes();text=original.decode("utf-8")
    active=[line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if active != [LEGACY_ACTIVE]: raise DebianSourceMigrationError("LEGACY_SOURCES_SHAPE_DENIED")
    digest=hashlib.sha256(original).hexdigest();rollback=root/"var/lib/serein/rollback"/f"outpost-host-sources-{digest[:16]}"
    rollback.mkdir(parents=True,exist_ok=False);(rollback/"sources.list.before").write_bytes(original)
    receipt={"schema":"SereinOutpostDebianSourceMigration/v1","before_sha256":digest,"rollback_selector":str(rollback),"target":"/etc/apt/sources.list.d/debian.sources"}
    (rollback/"receipt.json").write_text(json.dumps(receipt,sort_keys=True)+"\n",encoding="utf-8")
    target.parent.mkdir(parents=True,exist_ok=True);temporary=target.with_suffix(".sources.new")
    temporary.write_text(CANONICAL,encoding="utf-8",newline="\n");os.replace(temporary,target)
    legacy.write_text("\n".join("# serein-migrated "+line if line.strip()==LEGACY_ACTIVE else line for line in text.splitlines())+"\n",encoding="utf-8",newline="\n")
    return {"status":"CANONICAL_SOURCES_INSTALLED","before_sha256":digest,"rollback_selector":str(rollback)}

if __name__ == "__main__": print(json.dumps(migrate(),sort_keys=True))
