from pathlib import Path
import pytest
from outpost.debian_host_sources import CANONICAL, LEGACY_ACTIVE, DebianSourceMigrationError, migrate

def test_exact_installer_source_migrates_with_prestate(tmp_path: Path):
    legacy=tmp_path/"etc/apt/sources.list";legacy.parent.mkdir(parents=True)
    original="# installer media\n"+LEGACY_ACTIVE+"\n";legacy.write_text(original,encoding="utf-8")
    result=migrate(tmp_path)
    assert result["status"]=="CANONICAL_SOURCES_INSTALLED"
    assert (tmp_path/"etc/apt/sources.list.d/debian.sources").read_text(encoding="utf-8")==CANONICAL
    assert (Path(result["rollback_selector"])/"sources.list.before").read_text(encoding="utf-8")==original

def test_unknown_active_source_fails_without_effect(tmp_path: Path):
    legacy=tmp_path/"etc/apt/sources.list";legacy.parent.mkdir(parents=True);legacy.write_text("deb https://example.invalid trixie main\n",encoding="utf-8")
    with pytest.raises(DebianSourceMigrationError,match="LEGACY_SOURCES_SHAPE_DENIED"): migrate(tmp_path)
    assert not (tmp_path/"etc/apt/sources.list.d/debian.sources").exists()
