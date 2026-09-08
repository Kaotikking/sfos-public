from pathlib import Path
import pytest

from outpost import host_witness_runner as runner


def test_download_rejects_every_noncanonical_url(tmp_path):
    with pytest.raises(RuntimeError, match="DEBIAN_DOWNLOAD_URL_DENIED"):
        runner.download("https://example.com/Packages.xz", tmp_path / "x", 1)


def test_runner_binds_each_suite_before_recording(monkeypatch, tmp_path):
    def fake_download(url, destination, maximum):
        destination.write_bytes(url.encode())
    def fake_verify(path):
        url=path.read_text()
        codename=url.split("/dists/",1)[1].split("/",1)[0]
        suites={"trixie":"stable","trixie-updates":"stable-updates","trixie-security":"stable-security"}
        return {"suite":suites[codename],"codename":codename,"indexes":{index:("0"*64,1) for index in runner.INDEXES}}
    observed={"schema":"SereinOutpostHostVitalityObservation/v1"}
    monkeypatch.setattr(runner,"download",fake_download)
    monkeypatch.setattr(runner,"verify_inrelease",fake_verify)
    collected={}
    def collect(**kwargs):
        collected.update(kwargs)
        return observed
    monkeypatch.setattr(runner,"collect_host_observation",collect)
    class Store:
        def __init__(self,path): self.path=path
        def record(self,value): return {"classification":"FIRST_BOOT_OBSERVED","value":value}
    monkeypatch.setattr(runner,"HostVitalityStore",Store)
    result=runner.run(tmp_path)
    assert result["classification"]=="FIRST_BOOT_OBSERVED" and result["value"] is observed
    assert collected["package_exceptions"] == ("serein-outpost",)
    assert not list(tmp_path.glob(".debian-witness-*"))
