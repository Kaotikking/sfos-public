import base64
import json
import socket
import threading
import socketserver

from outpost.host_vitality import HostVitalityStore, digest
from outpost.presentation_service import PresentationServer
import outpost.presentation_service as presentation_service


def observation():
    body={"schema":"SereinOutpostHostVitalityObservation/v1","target":"SEREIN_HOST","boot_id":"11111111-2222-4333-8444-555555555555","observed_at":1.0,"host":{"hostname":"serein-host","os_id":"debian","os_version_id":"13","machine_id":"m","status":"PASS"},"gpu":{"pci_present":True,"driver_loaded":True,"device_count":1,"driver_packages":{"nvidia-driver":"x"},"status":"PASS"},"debian":{"release":"trixie","release_sha256":"a"*64,"signer_fingerprint":"b"*64,"repositories":["deb.debian.org"],"installed_identity":{"source":"dpkg-status"},"installed_packages":{"base-files":"13.6"},"repository_packages":{"base-files":"13.6"},"exact_diff":[],"pins":[],"exceptions":["serein-outpost"],"unknowns":[],"correction_result":"NOT_REQUIRED","status":"PASS"}}
    return {**body,"evidence_digest":digest(body)}


def exchange(address, request):
    family=socket.AF_UNIX if isinstance(address,str) else socket.AF_INET
    with socket.socket(family,socket.SOCK_STREAM) as client:
        client.connect(address);client.sendall(json.dumps(request).encode()+b"\n")
        return json.loads(client.makefile("rb").readline())


def server_address(tmp_path):
    return str(tmp_path/"status.sock") if hasattr(socketserver,"UnixStreamServer") else ("127.0.0.1",0)


def test_local_api_projects_exact_json_html_and_denies_mutation(tmp_path):
    store=HostVitalityStore(tmp_path/"state");snapshot=store.record(observation())
    presentation_service.BOOT_ID_PATH=tmp_path/"boot_id";presentation_service.BOOT_ID_PATH.write_text(snapshot["current_boot_id"],encoding="ascii")
    server=PresentationServer(server_address(tmp_path),store);address=server.server_address;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        result=exchange(address,{"method":"GET","path":"/v1/runtime/status","accept":"application/json"})
        assert result["status"]==200 and json.loads(base64.b64decode(result["body_base64"]))==snapshot
        assert exchange(address,{"method":"GET","path":"/v1/runtime/status","accept":"text/html"})["content_type"].startswith("text/html")
        for method in ("HEAD","POST","PUT","PATCH","DELETE","OPTIONS","TRACE"):
            assert exchange(address,{"method":method,"path":"/v1/runtime/status","accept":"application/json"})["status"]==405
    finally:
        server.shutdown();server.server_close();thread.join()


def test_local_api_unavailable_and_unknown_path_fail_closed(tmp_path):
    presentation_service.BOOT_ID_PATH=tmp_path/"boot_id";presentation_service.BOOT_ID_PATH.write_text("11111111-2222-4333-8444-555555555555",encoding="ascii")
    server=PresentationServer(server_address(tmp_path),HostVitalityStore(tmp_path/"state"));address=server.server_address;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        assert exchange(address,{"method":"GET","path":"/v1/runtime/status","accept":"application/json"})["status"]==503
        assert exchange(address,{"method":"GET","path":"/other","accept":"application/json"})["status"]==404
        assert exchange(address,{"method":"GET","path":"/v1/runtime/status","accept":"application/json","extra":True})["status"]==400
    finally:
        server.shutdown();server.server_close();thread.join()


def test_local_api_unreadable_boot_identity_fails_closed(tmp_path):
    store=HostVitalityStore(tmp_path/"state");store.record(observation())
    presentation_service.BOOT_ID_PATH=tmp_path/"missing-boot-id"
    server=PresentationServer(server_address(tmp_path),store);address=server.server_address;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        result=exchange(address,{"method":"GET","path":"/v1/runtime/status","accept":"application/json"})
        assert result["status"]==503 and json.loads(base64.b64decode(result["body_base64"]))=={"error":"VITALITY_UNAVAILABLE"}
    finally:
        server.shutdown();server.server_close();thread.join()
