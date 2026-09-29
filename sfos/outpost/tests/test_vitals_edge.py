import json
from pathlib import Path
import pytest
import socket
import threading

from outpost import vitals_edge
from outpost.host_vitality import digest
from outpost.vitals_aggregation import aggregate_vitals,producer_observation
from tests.active_host import active_host

BOOT="11111111-2222-4333-8444-555555555555"


def test_presentation_socket_allows_existing_edge_supplementary_group_only():
    """Distinct child identities, creation umask only, no socket chmod repair."""
    import os,stat,tempfile,time
    from outpost import presentation_service
    from outpost.vitals_runtime import VitalsRuntimeStore
    assert os.geteuid()==0  # Native isolated Debian proof; no host accounts changed.
    with tempfile.TemporaryDirectory(prefix='outpost-vitals-peer-',dir='/tmp') as name:
        root=Path(name);root.chmod(0o750);os.chown(root,65533,65533)
        address=root/'status.sock';boot=root/'boot';boot.write_text(BOOT);boot.chmod(0o644)
        producer=os.fork()
        if producer==0:
            try:
                os.setgroups([]);os.setgid(65533);os.setuid(65533);os.umask(0o007)
                presentation_service.BOOT_ID_PATH=boot
                store=VitalsRuntimeStore(root/'host',root/'producers',root/'domains',root/'recovery')
                with presentation_service.PresentationServer(str(address),store) as server:
                    server.timeout=5;server.handle_request()
                os._exit(0)
            except BaseException:os._exit(1)
        try:
            for _ in range(100):
                if address.exists():break
                time.sleep(0.01)
            assert stat.S_IMODE(address.stat().st_mode)==0o770
            assert address.stat().st_uid==address.stat().st_gid==65533
            outsider=os.fork()
            if outsider==0:
                try:
                    os.setgroups([]);os.setgid(65534);os.setuid(65534)
                    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                        client.connect(str(address))
                    os._exit(1)
                except PermissionError:os._exit(0)
                except BaseException:os._exit(1)
            assert os.waitpid(outsider,0)[1]==0
            consumer=os.fork()
            if consumer==0:
                try:
                    os.setgroups([65533]);os.setgid(65534);os.setuid(65534)
                    vitals_edge.PRESENTATION_SOCKET=address
                    status,_,_,body=vitals_edge._presentation('GET','/v1/runtime/status','application/json')
                    os._exit(0 if status==200 and json.loads(body)['current_boot_id']==BOOT else 1)
                except BaseException:os._exit(1)
            assert os.waitpid(consumer,0)[1]==0
            assert os.waitpid(producer,0)[1]==0;producer=None
        finally:
            if producer is not None:
                try:os.kill(producer,15)
                except ProcessLookupError:pass
                os.waitpid(producer,0)


@pytest.mark.parametrize('fault',[None,'wrong_generation','stale','html_tamper','wrong_certificate'])
def test_installer_vitals_witness_uses_real_unix_tls_json_and_html(tmp_path,monkeypatch,fault):
    """Native ephemeral listeners and synthetic TLS; not public-edge proof."""
    import ssl,time,datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from install import public_generation_transaction as transaction
    from outpost import presentation_service,service
    from outpost.vitals_runtime import VitalsRuntimeStore
    from tests.test_generation_launcher import native_generation
    fixture=tmp_path/'fixture';fixture.mkdir()
    _,_,_,selector=native_generation(fixture)
    monkeypatch.setattr(service,'current_generation_identity',lambda:selector)
    boot=tmp_path/'boot';boot.write_text(BOOT)
    not_before=time.time()-1
    service.coordinator_witness(host_root=tmp_path/'host',state_path=tmp_path/'coordinator/current.json',
        boot_id_path=boot,observed_at=time.time()-100 if fault=='stale' else time.time())
    runtime=VitalsRuntimeStore(tmp_path/'host',tmp_path/'producers',tmp_path/'domains/state.json',tmp_path/'recovery/current.json')
    monkeypatch.setattr(presentation_service,'BOOT_ID_PATH',boot)
    address=tmp_path/'s';monkeypatch.setattr(vitals_edge,'PRESENTATION_SOCKET',address)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'serein.sardonyxsapphire.us')])
    now=datetime.datetime.now(datetime.timezone.utc)
    def cert(serial):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(serial).not_valid_before(now-datetime.timedelta(days=1))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('serein.sardonyxsapphire.us')]),False)
            .sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    certificate=cert(1);certpath=tmp_path/'cert.pem';certpath.write_bytes(certificate)
    keypath=tmp_path/'key.pem';keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    expected_cert=cert(2) if fault=='wrong_certificate' else certificate
    def read_cert(root,path,**kwargs):
        assert path=='/etc/serein/tls/serein-backend-cert.pem'
        return expected_cert if kwargs.get('capture') else None
    monkeypatch.setattr(transaction,'_read_target_fact',read_cert)
    original=vitals_edge.edge_response
    def response(method,path,accept):
        status,kind,headers,body=original(method,path,accept)
        if fault=='html_tamper' and 'text/html' in accept:body+=b'tampered'
        return status,kind,headers,body
    monkeypatch.setattr(vitals_edge,'edge_response',response)
    with presentation_service.PresentationServer(str(address),runtime) as local:
        server=vitals_edge.ThreadingHTTPServer(('127.0.0.1',0),vitals_edge.VitalsHandler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certpath,keypath)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        monkeypatch.setattr(vitals_edge,'BACKEND_ADDRESS','127.0.0.1')
        monkeypatch.setattr(vitals_edge,'BACKEND_PORT',server.server_port)
        threads=[threading.Thread(target=local.serve_forever),threading.Thread(target=server.serve_forever)]
        for thread in threads:thread.start()
        try:
            expected=dict(selector,generation='f'*64) if fault=='wrong_generation' else selector
            arguments=dict(expected_generation=expected,boot_id=BOOT,not_before=not_before,
                           certificate_row={'sha256':transaction.sha(expected_cert)})
            if fault:
                with pytest.raises(transaction.TransactionError):transaction.read_vitals_witness(**arguments)
            else:
                result=transaction.read_vitals_witness(**arguments)
                assert result['result']=='LOCAL_VITALS_JSON_HTML_OBSERVED'
                assert result['generation']==selector['generation']
                assert result['public_edge']=='INDEPENDENT_VERIFICATION_REQUIRED'
                assert not (tmp_path/'host').exists()  # unavailable Host remains observable
        finally:
            server.shutdown();local.shutdown();server.server_close()
            for thread in threads:thread.join(timeout=3)


@pytest.mark.parametrize("accept", ["application/json", "text/html"])
def test_native_vitals_presentation_socket_without_host_or_gateway(tmp_path, monkeypatch, accept):
    """Native temporary Unix API, not canonical edge or service acceptance."""
    from outpost import presentation_service
    from outpost.vitals_runtime import VitalsRuntimeStore
    boot = tmp_path / "boot"
    boot.write_text(BOOT)
    monkeypatch.setattr(presentation_service, "BOOT_ID_PATH", boot)
    address = tmp_path / "s"
    store = VitalsRuntimeStore(tmp_path/"host", tmp_path/"producers", tmp_path/"domains", tmp_path/"recovery")
    monkeypatch.setattr(vitals_edge, "PRESENTATION_SOCKET", address)
    with presentation_service.PresentationServer(str(address), store) as server:
        server.timeout = 2
        worker = threading.Thread(target=server.handle_request)
        worker.start()
        try:
            status, content_type, headers, body = vitals_edge._presentation("GET", "/v1/runtime/status", accept)
        finally:
            worker.join(timeout=3)
        assert not worker.is_alive()
    assert status == 200
    if accept == "application/json":
        state = json.loads(body)
        assert state["sections"]["host"]["claim"] == "HOST_WITNESS_UNAVAILABLE"
        assert not vitals_edge._ready(body)
        assert state["admission_effect"] == "NONE"
    else:
        assert b"<title>Serein Vitals</title>" in body
    assert not (tmp_path/"host").exists() and not (tmp_path/"domains").exists()
    # Closing the descriptor is not authority to remove the pathname.
    # The installed service manager owns runtime-directory cleanup.
    assert address.exists()


def test_partial_presentation_request_is_bounded_and_replacement_path_survives(tmp_path, monkeypatch):
    from outpost import presentation_service
    address = tmp_path / "s"
    monkeypatch.setattr(presentation_service, "REQUEST_TIMEOUT_SECONDS", 0.05)
    with presentation_service.PresentationServer(str(address), None) as server:
        server.timeout = 1
        worker = threading.Thread(target=server.handle_request)
        worker.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect(str(address))
            client.sendall(b"{")
            response = json.loads(client.recv(4096))
        worker.join(timeout=2)
        assert not worker.is_alive() and response["status"] == 503
        address.unlink()  # Fixture replacement after this server owned it.
        address.write_bytes(b"replacement must survive")
    assert address.read_bytes() == b"replacement must survive"


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_presentation_never_replaces_existing_socket_path(tmp_path, kind):
    from outpost.presentation_service import PresentationServer
    path = tmp_path / "s"
    if kind == "file": path.write_bytes(b"preserve")
    else: path.symlink_to(tmp_path / "absent")
    before = path.lstat()
    with pytest.raises(ValueError, match="PRESENTATION_SOCKET_COLLISION_DENIED"):
        PresentationServer(str(path), None)
    assert path.lstat() == before


def test_presentation_bind_collision_does_not_delete_competing_path(tmp_path, monkeypatch):
    from outpost import presentation_service
    address = tmp_path / "s"
    original = presentation_service.PresentationServer.server_bind
    def replaced_before_bind(server):
        address.write_bytes(b"competing path")
        return original(server)
    monkeypatch.setattr(presentation_service.PresentationServer, "server_bind", replaced_before_bind)
    with pytest.raises(OSError):
        presentation_service.PresentationServer(str(address), None)
    assert address.read_bytes() == b"competing path"


def test_presentation_does_not_duplicate_manager_path_cleanup_or_permissions(tmp_path, monkeypatch):
    from outpost import presentation_service
    address = tmp_path / "s"
    server = presentation_service.PresentationServer(str(address), None)
    address.unlink()
    address.write_bytes(b"replacement")
    def denied(*_, **__): raise AssertionError("application mutated runtime path")
    with monkeypatch.context() as bounded:
        bounded.setattr(presentation_service.os, "unlink", denied)
        bounded.setattr(presentation_service.os, "chmod", denied)
        server.server_close()
    assert address.read_bytes() == b"replacement"


@pytest.mark.parametrize("content_type,headers",[("application/json\r\nInjected: yes",[]),("application/json",[["Content-Security-Policy","default-src 'none'\r\nInjected: yes"]])])
def test_edge_rejects_response_header_injection(monkeypatch,content_type,headers):
    monkeypatch.setattr(vitals_edge,"_presentation",lambda *_:(200,content_type,headers,b"{}"))
    assert vitals_edge.edge_response("GET","/v1/runtime/status","application/json")[0]==503


def test_optional_csp_does_not_remove_mandatory_headers(monkeypatch):
    monkeypatch.setattr(vitals_edge,"_presentation",lambda *_:(200,"application/json",[["Content-Security-Policy","default-src 'none'"]],b"{}"))
    headers=dict(vitals_edge.edge_response("GET","/v1/runtime/status","application/json")[2])
    assert headers["Cache-Control"]=="no-store" and headers["X-Content-Type-Options"]=="nosniff"


def test_vitals_tls_paths_match_the_declared_systemd_credential_unit():
    unit = Path(__file__).resolve().parents[1] / "systemd" / "serein-https-gateway-adapter.service"
    definition = unit.read_text()
    # systemd includes the full unit name, including .service, in this path.
    expected_root = Path("/run/credentials") / unit.name
    for credential in (vitals_edge.CERTIFICATE, vitals_edge.PRIVATE_KEY):
        assert credential.parent == expected_root
        assert f"LoadCredential={credential.name}:" in definition


def _host_state(*, ready=True, claim="CURRENT_BOOT_STABLE", boot_id=BOOT):
    observation=active_host({"target":"SEREIN_HOST","boot_id":boot_id,"observed_at":1.0,"host":{"hostname":"host","os_id":"debian","os_version_id":"13","machine_id":"m","status":"PASS"},"gpu":{"pci_present":True,"driver_loaded":True,"device_count":1,"driver_packages":{"nvidia-driver":"x"},"status":"PASS"}})
    previous=None if claim=="FIRST_BOOT_OBSERVED" else (boot_id if claim=="CURRENT_BOOT_STABLE" else "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    recorded={"schema":"SereinOutpostHostVitalityState/v1","projection_revision":1,"projection_digest":digest(observation),"previous_boot_id":previous,"current_boot_id":boot_id,"sample_count":1 if previous is None else 2,"latest":observation,"classification":claim,"authority_effect":"NONE","mutation_effect":"NONE"}
    witness=producer_observation(perspective="host",producer="OUTPOST_HOST_WITNESS",claim=claim if ready else "DRIFT_DETECTED",observed_at=1.0,boot_id=boot_id,evidence_ref="host-vitality:"+digest(observation),payload=recorded)
    return json.dumps(aggregate_vitals({"host":[witness]},current_boot_id=BOOT,generated_at=2.0)).encode()


def test_vitals_edge_accepts_only_status_and_readiness_without_gateway(monkeypatch):
    monkeypatch.setattr(vitals_edge, "_presentation", lambda *_: (200, "application/json", [["Cache-Control", "no-store"]], _host_state()))
    status, _, _, body = vitals_edge.edge_response("GET", "/health/ready", "application/json")
    assert status == 200 and json.loads(body) == {"status": "READY"}
    status, _, _, body = vitals_edge.edge_response("GET", "/v1/runtime/status", "application/json")
    assert status == 200 and json.loads(body)["sections"]["host"]["claim"] == "CURRENT_BOOT_STABLE"
    assert vitals_edge.edge_response("GET", "/v1/voice/conversation", "application/json")[0] == 404
    assert vitals_edge.edge_response("POST", "/v1/runtime/status", "application/json")[0] == 405


def test_vitals_remains_available_without_granting_failed_host_admission(monkeypatch):
    monkeypatch.setattr(vitals_edge, "_presentation", lambda *_: (200, "application/json", [], _host_state(ready=False)))
    assert vitals_edge.edge_response("GET", "/health/ready", "application/json")[0] == 200
    status, _, _, body = vitals_edge.edge_response("GET", "/v1/runtime/status", "application/json")
    assert status == 200 and json.loads(body)["sections"]["host"]["claim"] == "DRIFT_DETECTED"
    assert not vitals_edge._ready(body)  # Installer/Host admission still fails.


def test_vitals_remains_available_with_no_host_or_downstream_producer(monkeypatch):
    body=json.dumps(aggregate_vitals({},current_boot_id=BOOT,generated_at=2.0)).encode()
    monkeypatch.setattr(vitals_edge, "_presentation", lambda *_: (200, "application/json", [], body))
    assert vitals_edge.edge_response("GET", "/health/ready", "application/json")[0] == 200
    assert not vitals_edge._ready(body)
    data=json.loads(body)
    assert data["sections"]["host"]["state"] == data["sections"]["serein"]["state"] == "UNKNOWN"
    assert data["admission_effect"] == "NONE"


@pytest.mark.parametrize("status,body", [(503,b'{}'),(200,b'{}'),(200,b'not json')])
def test_vitals_edge_health_rejects_unavailable_or_invalid_presentation(monkeypatch,status,body):
    monkeypatch.setattr(vitals_edge, "_presentation", lambda *_: (status, "application/json", [], body))
    assert vitals_edge.edge_response("GET", "/health/ready", "application/json")[0] == 503


def test_vitals_edge_health_rejects_tampered_recovery_projection(monkeypatch):
    state=json.loads(_host_state())
    state["projection_digest"]="0"*64
    body=json.dumps(state).encode()
    monkeypatch.setattr(vitals_edge, "_presentation", lambda *_: (200, "application/json", [], body))
    assert vitals_edge.edge_response("GET", "/health/ready", "application/json")[0] == 503


@pytest.mark.parametrize("claim",["FIRST_BOOT_OBSERVED","CURRENT_BOOT_STABLE","RECOVERED_AFTER_BOOT_CHANGE"])
def test_vitals_edge_accepts_canonical_healthy_host_history_classes(claim):
    assert vitals_edge._ready(_host_state(claim=claim))


def test_vitals_edge_rejects_stale_or_contradictory_host_evidence():
    state=json.loads(_host_state())
    witness=state["sections"]["host"]["perspectives"][0]
    witness["freshness"]="STALE"
    assert not vitals_edge._ready(json.dumps(state).encode())
    state=json.loads(_host_state())
    witness=state["sections"]["host"]["perspectives"][0]
    payload=witness["payload"]["latest"];payload["public_base"]["unknowns"]=["UNPROVEN"]
    payload["evidence_digest"]=digest({k:v for k,v in payload.items() if k!="evidence_digest"})
    witness["payload"]["projection_digest"]=digest(payload)
    assert not vitals_edge._ready(json.dumps(state).encode())


def test_vitals_edge_rejects_history_claim_not_bound_to_host_record():
    state=json.loads(_host_state(claim="FIRST_BOOT_OBSERVED"))
    host=state["sections"]["host"];host["claim"]="RECOVERED_AFTER_BOOT_CHANGE"
    host["perspectives"][0]["claim"]=host["claim"]
    assert not vitals_edge._ready(json.dumps(state).encode())
    host["perspectives"][0]["payload"]["classification"]=host["claim"]
    assert not vitals_edge._ready(json.dumps(state).encode())
    host["perspectives"][0]["payload"].update(previous_boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",sample_count=2)
    assert not vitals_edge._ready(json.dumps(state).encode())
