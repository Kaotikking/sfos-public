from outpost import host_witness_runner as runner
from outpost.host_vitality import digest
from outpost import public_tree_host
from email.message import Message
from io import BytesIO
import urllib.request
import urllib.response
import pytest
import hashlib


@pytest.mark.parametrize("state", ["healthy", "degraded", "malformed", "unsigned"])
def test_service_completion_is_observation_not_host_admission(monkeypatch,tmp_path,state):
    from outpost.host_vitality import HostVitalityStore, HostVitalityError
    from tests.test_host_vitality import observation
    import sys
    body=observation()
    if state=="degraded":
        body["public_base"]["status"]="DRIFT"
        body["public_base"]["exact_diff"]=[{"package":"openssl","expected":"3.5.7-1~deb13u2","observed":"3.5.6-1~deb13u2"}]
        body["evidence_digest"]=digest({key:value for key,value in body.items() if key!="evidence_digest"})
    witness=HostVitalityStore(tmp_path).record(body)
    monkeypatch.setattr(sys,"argv",["host_witness_runner","--state-root",str(tmp_path)])
    if state=="unsigned":
        def rejected(_): raise RuntimeError("DEBIAN_SIGNATURE_DENIED")
        monkeypatch.setattr(runner,"run",rejected)
        with pytest.raises(RuntimeError,match="DEBIAN_SIGNATURE_DENIED"): runner.main()
        return
    monkeypatch.setattr(runner,"run",lambda _:{} if state=="malformed" else witness)
    if state=="malformed":
        with pytest.raises(HostVitalityError): runner.main()
        return
    before=dict(witness)
    runner.main()
    assert witness==before
    assert witness["classification"]==("DRIFT_DETECTED" if state=="degraded" else "FIRST_BOOT_OBSERVED")
    assert witness["authority_effect"]==witness["mutation_effect"]=="NONE"


def test_runner_records_joined_public_tree_and_signed_debian_host_contract(monkeypatch, tmp_path):
    body={"schema":"SereinOutpostHostVitalityObservation/v1","target":"SEREIN_HOST","boot_id":"11111111-2222-4333-8444-555555555555","observed_at":1.0,"host":{"hostname":"vm4010","os_id":"debian","os_version_id":"13","machine_id":"m","status":"PASS"},"gpu":{"pci_present":True,"driver_loaded":True,"device_count":1,"driver_packages":{},"status":"PASS"},"debian":{"release":"Debian 13","release_sha256":"a"*64,"signer_fingerprint":"b"*64,"repositories":["deb.debian.org","security.debian.org"],"installed_identity":{"id":"debian","version_id":"13","pretty_name":"Debian GNU/Linux 13 (trixie)"},"installed_packages":{"python3":"3.13.5-1"},"repository_packages":{"python3":"3.13.5-1"},"exact_diff":[],"pins":[],"exceptions":[],"unknowns":[],"correction_result":"NOT_REQUIRED","status":"PASS"}}
    from tests.active_host import active_host
    from outpost.host_vitality import HostCollectionAttempts
    debian={**body,"evidence_digest":digest(body)};joined=active_host(body)
    monkeypatch.setattr(runner,"_current_boot_id",lambda:body["boot_id"])
    clock=iter((0.0,2.0));monkeypatch.setattr(runner.time,"time",lambda:next(clock))
    monkeypatch.setattr(runner,"download",lambda url,path,maximum,**kwargs:path.write_bytes(b"signed"))
    monkeypatch.setattr(runner,"verify_inrelease",lambda path:{"codename":"trixie" if "release-0" in path.name else "trixie-updates" if "release-1" in path.name else "trixie-security","indexes":{name:(hashlib.sha256(b"signed").hexdigest(),6) for name in runner.INDEXES}})
    monkeypatch.setattr(runner,"collect_host_observation",lambda **kwargs:debian)
    monkeypatch.setattr(runner,"bind_signed_debian_observation",lambda observed:joined)
    result=runner.run(tmp_path)
    assert result["classification"]=="FIRST_BOOT_OBSERVED" and result["latest"]==joined
    assert HostCollectionAttempts(tmp_path).latest()["terminal"]["payload"]["projection_digest"]==result["projection_digest"]


@pytest.mark.parametrize("source", ["debian", "public"])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_source_redirect_is_denied_before_second_request(monkeypatch, tmp_path, source, status):
    url = runner.RELEASES["debian:trixie"] if source == "debian" else "https://api.github.com/repos/Kaotikking/sfos-public/commits/" + public_tree_host.BASE_COMMIT
    requested = []

    def response_without_network(self, request, data=None):
        requested.append(request.full_url)
        headers = Message()
        if request.full_url == url:
            headers["Location"] = "https://outside.invalid/witness"
            code = status
        else:
            code = 200
        response = urllib.response.addinfourl(BytesIO(b"{}"), headers, request.full_url, code)
        response.msg = "Found" if code != 200 else "OK"
        return response

    monkeypatch.setattr(urllib.request.OpenerDirector, "_open", response_without_network)
    error = None
    destination = tmp_path / "release.InRelease"
    try:
        if source == "debian":
            runner.download(url, destination, runner.MAX_INRELEASE)
        else:
            public_tree_host._api("/commits/" + public_tree_host.BASE_COMMIT)
    except (RuntimeError, public_tree_host.PublicTreeHostError) as exc:
        error = str(exc)
    assert requested == [url]
    assert error == ("DEBIAN_DOWNLOAD_REDIRECT_DENIED" if source == "debian" else "PUBLIC_GIT_REDIRECT_DENIED")
    assert not destination.exists()


@pytest.mark.parametrize("source", ["debian", "public"])
def test_exact_source_response_still_reads_without_redirect(monkeypatch, tmp_path, source):
    requested = []

    def response_without_network(self, request, data=None):
        requested.append(request.full_url)
        response = urllib.response.addinfourl(BytesIO(b'{"ok":true}'), Message(), request.full_url, 200)
        response.msg = "OK"
        return response

    monkeypatch.setattr(urllib.request.OpenerDirector, "_open", response_without_network)
    if source == "debian":
        destination = tmp_path / "release.InRelease"
        url = runner.RELEASES["debian:trixie"]
        runner.download(url, destination, runner.MAX_INRELEASE)
        assert destination.read_bytes() == b'{"ok":true}'
    else:
        url = "https://api.github.com/repos/Kaotikking/sfos-public/commits/" + public_tree_host.BASE_COMMIT
        assert public_tree_host._api("/commits/" + public_tree_host.BASE_COMMIT) == {"ok": True}
    assert requested == [url]


@pytest.mark.parametrize("error", [RuntimeError("DEBIAN_INRELEASE_SIGNATURE_DENIED"), OSError("private transport details must not be retained"), RuntimeError("PUBLIC_INVENTED_MEANING")])
def test_failed_attempt_is_durable_and_does_not_replace_last_signed_success(tmp_path, monkeypatch, error):
    from outpost.host_vitality import HostCollectionAttempts, HostVitalityStore
    from outpost.vitals_runtime import VitalsRuntimeStore
    from outpost.http_readonly import present
    from tests.test_host_vitality import observation
    import json
    host=tmp_path/"host"
    saved=HostVitalityStore(host).record(observation())
    before=(host/"state.json").read_bytes()
    monkeypatch.setattr(runner,"_current_boot_id",lambda:saved["current_boot_id"])
    monkeypatch.setattr(runner.time,"time",lambda:10.0)
    def fail(*_):
        assert HostCollectionAttempts(host).latest()["terminal"] is None
        raise error
    monkeypatch.setattr(runner,"download",fail)
    with pytest.raises(type(error)):
        runner.run(host)
    attempt=HostCollectionAttempts(host).latest()
    assert attempt["terminal"]["event_kind"]=="HOST_COLLECTION_FAILED"
    assert attempt["terminal"]["payload"]["error_code"]==("DEBIAN_INRELEASE_SIGNATURE_DENIED" if str(error)=="DEBIAN_INRELEASE_SIGNATURE_DENIED" else "HOST_COLLECTION_UNAVAILABLE")
    assert (host/"state.json").read_bytes()==before
    assert b"private transport" not in (host/"collection-attempts.jsonl").read_bytes()
    runtime=VitalsRuntimeStore(host,tmp_path/"producers",tmp_path/"domain",tmp_path/"recovery")
    response=present(runtime,"GET","/v1/runtime/status","application/json",saved["current_boot_id"])
    assert response.status==200
    section=json.loads(response.body)["sections"]["host"]
    assert section["claim"]=="HOST_COLLECTION_FAILED"
    assert section["perspectives"][0]["payload"]["last_successful_observation"]==saved


def test_process_death_after_start_does_not_leave_a_false_current_success(tmp_path):
    from outpost.host_vitality import HostCollectionAttempts, HostVitalityStore
    from outpost.vitals_runtime import VitalsRuntimeStore
    from tests.test_host_vitality import observation
    host=tmp_path/"host"
    saved=HostVitalityStore(host).record(observation())
    HostCollectionAttempts(host).start(saved["current_boot_id"],2.0)
    # Reopen exactly the durable prefix that remains after process death.
    runtime=VitalsRuntimeStore(host,tmp_path/"producers",tmp_path/"domain",tmp_path/"recovery")
    assert runtime.snapshot(current_boot_id=saved["current_boot_id"])["sections"]["host"]["claim"]=="HOST_COLLECTION_INCOMPLETE"


@pytest.mark.parametrize("by_hash", [True, False])
def test_index_download_binds_signed_hash_and_size_without_mutable_fallback(monkeypatch, tmp_path, by_hash):
    index = runner.INDEXES[0]
    checksum = "a" * 64
    metadata = {"indexes": {index: (checksum, 123)}, "acquire_by_hash": by_hash}
    calls = []
    monkeypatch.setattr(runner, "download", lambda *args, **kwargs: calls.append((args, kwargs)))
    base = runner.RELEASES["debian:trixie"]
    destination = tmp_path / "Packages.xz"
    runner.download_index(base, index, metadata, destination)
    suffix = index.rsplit("/", 1)[0] + "/by-hash/SHA256/" + checksum if by_hash else index
    assert calls == [((base.rsplit("/", 1)[0] + "/" + suffix, destination, 123), {"expected_sha256": checksum})]


@pytest.mark.parametrize("expected", [("x" * 64, 1), ("a" * 64, -1), ("a" * 64, True), ("a" * 64, runner.MAX_PACKAGES + 1), None])
def test_invalid_signed_index_binding_denies_before_download(monkeypatch, tmp_path, expected):
    monkeypatch.setattr(runner, "download", lambda *a, **k: pytest.fail("No download"))
    with pytest.raises(RuntimeError, match="DEBIAN_INDEX_"):
        runner.download_index(runner.RELEASES["debian:trixie"], runner.INDEXES[0],
                              {"indexes": {runner.INDEXES[0]: expected}}, tmp_path / "index")


def test_by_hash_response_must_match_exact_verified_bytes(monkeypatch, tmp_path):
    body = b"signed-index-fixture"
    checksum = hashlib.sha256(body).hexdigest()
    url = runner.RELEASES["debian:trixie"].rsplit("/", 1)[0] + "/main/binary-amd64/by-hash/SHA256/" + checksum
    def response(self, request, data=None):
        result = urllib.response.addinfourl(BytesIO(body), Message(), request.full_url, 200)
        result.msg = "OK"
        return result
    monkeypatch.setattr(urllib.request.OpenerDirector, "_open", response)
    runner.download(url, tmp_path / "exact", len(body), expected_sha256=checksum)
    with pytest.raises(RuntimeError, match="DEBIAN_INDEX_HASH_DENIED"):
        runner.download(url, tmp_path / "truncated", len(body) + 1, expected_sha256=checksum)
    with pytest.raises(RuntimeError, match="DEBIAN_DOWNLOAD_URL_DENIED"):
        runner.download(url, tmp_path / "unbound", len(body))
