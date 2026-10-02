import json
import pytest
from outpost.service import coordinator_witness, validate_coordinator_witness, held_domain_boot_view, DOMAIN_GATE_ORDER, OutpostServiceError
from outpost.host_vitality import HostCollectionAttempts,HostVitalityStore
from outpost.constitutional_registry import DOMAIN_ORDER
from outpost.vitals_runtime import VitalsRuntimeStore
from outpost.http_readonly import present, html_body
from outpost.vitals_aggregation import producer_observation
from tests.test_host_vitality import observation

BOOT="11111111-2222-4333-8444-555555555555"


def test_main_enables_location_only_fatal_evidence_before_coordinator(monkeypatch):
    import faulthandler
    from outpost import service
    calls = []
    monkeypatch.setattr(faulthandler, "enable", lambda **kw: calls.append(("faults", kw)))
    monkeypatch.setattr(service, "run_coordinator", lambda **kw: calls.append(("run", kw)))
    service.main(["--host-vitality-root", "/synthetic/host"])
    assert calls[0] == ("faults", {"all_threads": False})
    assert calls[1][0] == "run"
    assert len(calls) == 2


def test_fatal_coordinator_signal_records_location_without_local_values(tmp_path):
    """Child-only SIGABRT; no service, VM, core file or live state effect."""
    import os
    import subprocess
    import sys
    from pathlib import Path
    if os.name != "posix":
        pytest.skip("POSIX fatal-signal acceptance")
    code = '''
import os, resource, signal
from outpost import service
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
def synthetic_coordinator_stall(**kwargs):
    private_value = "SYNTHETIC_MUST_NOT_APPEAR_IN_CRASH_OUTPUT"
    os.kill(os.getpid(), signal.SIGABRT)
service.run_coordinator = synthetic_coordinator_stall
service.main(["--host-vitality-root", "/synthetic/host"])
'''
    environment = dict(os.environ)
    environment.pop("PYTHONFAULTHANDLER", None)
    environment.pop("PYTHONDEVMODE", None)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    result = subprocess.run([sys.executable, "-B", "-c", code], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=5)
    assert result.returncode == -6
    assert "synthetic_coordinator_stall" in result.stderr
    assert "SYNTHETIC_MUST_NOT_APPEAR_IN_CRASH_OUTPUT" not in result.stderr
    assert result.stdout == ""
    assert list(tmp_path.iterdir()) == []


def test_current_generation_identity_binds_running_module_and_exact_bytes(tmp_path):
    from outpost.service import current_generation_identity
    from tests.test_generation_launcher import native_generation
    root,generation,current,selector=native_generation(tmp_path)
    args={'module_path':generation/'outpost/service.py','selector_path':current,'generation_root':root}
    assert current_generation_identity(**args)==selector
    assert current_generation_identity(**{**args,'module_path':tmp_path/'other/outpost/service.py'}) is None
    (generation/'outpost/service.py').write_text('changed source')
    assert current_generation_identity(**args) is None


def test_generation_acceptance_cannot_use_unbound_observer(tmp_path):
    from tests.test_generation_launcher import native_generation
    fixture=tmp_path/'fixture';fixture.mkdir()
    _,_,_,selector=native_generation(fixture)
    value=produce(tmp_path)
    assert value['generation_identity'] is None
    with pytest.raises(OutpostServiceError,match='GENERATION_DENIED'):
        validate_coordinator_witness(value,boot_id=BOOT,observed_at=2.0,expected_generation=selector)


@pytest.mark.parametrize('release',[[],None,{'self_digest':None}])
def test_malformed_generation_remains_observable_without_admission(tmp_path,monkeypatch,release):
    from outpost import service
    from install import generation_launcher
    from tests.test_generation_launcher import native_generation
    fixture=tmp_path/'fixture';fixture.mkdir()
    root,generation,current,selector=native_generation(fixture)
    (generation/'release-manifest.json').write_text(json.dumps(release))
    if isinstance(release,dict):
        selector['release_digest']=None
        selector['selector_digest']=generation_launcher._digest(selector)
        current.write_text(json.dumps(selector))
    original=service.current_generation_identity
    monkeypatch.setattr(service,'current_generation_identity',lambda:original(
        module_path=generation/'outpost/service.py',selector_path=current,generation_root=root))
    result=produce(tmp_path)
    assert result['generation_identity'] is None
    assert result['admission_effect']=='NONE'
    assert json.loads((tmp_path/'coordinator/current.json').read_text())==result


def test_generation_witness_is_source_bound_not_admission(tmp_path,monkeypatch):
    from outpost import service
    from tests.test_generation_launcher import native_generation
    fixture=tmp_path/'fixture';fixture.mkdir()
    _,_,_,selector=native_generation(fixture)
    monkeypatch.setattr(service,'current_generation_identity',lambda:selector)
    value=produce(tmp_path)
    assert validate_coordinator_witness(value,boot_id=BOOT,observed_at=2.0,expected_generation=selector)==value
    assert value['admission_effect']=='NONE' and value['registry_state']=='HOLD_INTENTIONAL'
    altered=dict(selector,generation='f'*64)
    with pytest.raises(OutpostServiceError,match='GENERATION_DENIED'):
        validate_coordinator_witness(value,boot_id=BOOT,observed_at=2.0,expected_generation=altered)
    value['generation_identity']=dict(selector,inventory_digest='f'*64)
    with pytest.raises(OutpostServiceError,match='GENERATION_DENIED'):
        validate_coordinator_witness(value,boot_id=BOOT,observed_at=2.0)


@pytest.mark.parametrize('document',['selector','release','inventory'])
def test_deep_json_does_not_crash_generation_observation(tmp_path,document):
    from outpost.service import current_generation_identity
    from tests.test_generation_launcher import native_generation
    root,generation,current,_=native_generation(tmp_path)
    path={'selector':current,'release':generation/'release-manifest.json',
          'inventory':generation/'generation-inventory.json'}[document]
    path.write_text('['*1100+'0'+']'*1100)
    assert current_generation_identity(module_path=generation/'outpost/service.py',
        selector_path=current,generation_root=root) is None


def test_native_coordinator_loop_publishes_before_notify_without_host_or_admission(tmp_path, monkeypatch):
    import socket
    from outpost import service
    boot = tmp_path / "boot"
    boot.write_text(BOOT)
    state = tmp_path / "coordinator/current.json"
    notify = tmp_path / "notify.sock"
    messages, records, waits = [], [], []
    class Stop:
        def is_set(self): return len(waits) == 2
        def wait(self, seconds):
            waits.append(seconds)
            # The production loop must already have durably published state.
            records.append(json.loads(state.read_text()))
            messages.append(receiver.recv(4096).decode())
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
        receiver.bind(str(notify))
        receiver.settimeout(1)
        monkeypatch.setenv("NOTIFY_SOCKET", str(notify))
        service.run_coordinator(host_root=tmp_path/"host", state_path=state,
                                boot_id_path=boot, stop=Stop())
    assert waits == [5.0, 5.0]
    assert messages == ["READY=1\nWATCHDOG=1\nSTATUS=HOST_GATE_UNAVAILABLE"] * 2
    assert records[1]["observed_at"] >= records[0]["observed_at"]
    assert all(row["boot_id"] == BOOT and row["admission_effect"] == "NONE" for row in records)
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"vitals-producers",
                                tmp_path/"domains/state.json", tmp_path/"recovery/current.json")
    snapshot = runtime.snapshot(current_boot_id=BOOT)
    assert snapshot["sections"]["domains"]["claim"] == "DENIED_HELD_SEED_CONTENT"
    producers = {row["producer"]: row for row in snapshot["sections"]["outpost"]["perspectives"]}
    assert producers["OUTPOST_WATCHDOG"]["claim"] == "DEGRADED"
    assert producers["OUTPOST_VITALITY_CHRONOLOGY"]["claim"] == "CHRONOLOGY_OBSERVED"
    assert producers["OUTPOST_VITALITY_CHRONOLOGY"]["payload"]["event_count"] == 2


def test_coordinator_loop_failure_never_sends_ready_or_watchdog(tmp_path, monkeypatch):
    from outpost import service
    def failed(**_): raise OSError("injected publication failure")
    monkeypatch.setattr(service, "coordinator_witness", failed)
    monkeypatch.setattr(service, "_notify", lambda _: pytest.fail("No ready after failure"))
    with pytest.raises(OSError, match="publication failure"):
        service.run_coordinator(host_root=tmp_path/"host", state_path=tmp_path/"state",
                                boot_id_path=tmp_path/"boot")


def test_producer_failure_prevents_ready_notification(tmp_path, monkeypatch):
    from outpost import service
    boot = tmp_path / "boot"
    boot.write_text(BOOT)
    def failed(**_):
        raise OSError("injected watchdog producer failure")
    monkeypatch.setattr(service, "witness_once", failed)
    monkeypatch.setattr(service, "_notify", lambda _: pytest.fail("No ready after producer failure"))
    with pytest.raises(OSError, match="watchdog producer failure"):
        service.run_coordinator(host_root=tmp_path/"host", state_path=tmp_path/"coordinator/current.json",
                                boot_id_path=boot)


def test_coordinator_declares_only_its_unprivileged_evidence_directories():
    from pathlib import Path
    unit = (Path(__file__).resolve().parents[1]/"systemd/serein-outpost.service").read_text()
    directories = next(line.partition("=")[2].split() for line in unit.splitlines()
                       if line.startswith("StateDirectory="))
    assert directories == ["serein-outpost/coordinator", "serein-outpost/watchdog",
                           "serein-outpost/vitals-producers", "serein-outpost/recovery"]
    for setting in ("User=serein-outpost", "Group=serein-outpost", "NoNewPrivileges=yes",
                    "ProtectSystem=strict", "CapabilityBoundingSet=", "AmbientCapabilities="):
        assert setting in unit.splitlines()
    assert not any(line.startswith(("ExecStart=+", "ExecStart=!", "ReadWritePaths="))
                   for line in unit.splitlines())


@pytest.mark.parametrize("host_condition", ["missing", "failed_after_success", "healthy", "chronology_failed"])
def test_actual_producer_pipeline_reaches_independent_presentation_socket(tmp_path, monkeypatch, host_condition):
    """Real local producer files/socket, not canonical TLS/public installation."""
    import threading
    from outpost import service, presentation_service, vitals_edge
    boot = tmp_path/"boot"
    boot.write_text(BOOT)
    if host_condition != "missing":
        produce(tmp_path, completed=True)
    if host_condition == "failed_after_success":
        attempts = HostCollectionAttempts(tmp_path/"host")
        identifier = attempts.start(BOOT, 3.0)
        attempts.finish(identifier, 4.0, error_code="DEBIAN_INRELEASE_SIGNATURE_DENIED")
    if host_condition == "chronology_failed":
        watchdog_root = tmp_path/"watchdog"
        watchdog_root.mkdir()
        (watchdog_root/"chronology.jsonl").write_text("injected malformed chronology\n")
    healthy_host = host_condition in {"healthy", "chronology_failed"}
    stop = threading.Event()
    def notify(message):
        assert message.endswith("CURRENT_BOOT_OBSERVED" if healthy_host else "HOST_GATE_UNAVAILABLE")
        stop.set()
    monkeypatch.setattr(service, "_notify", notify)
    service.run_coordinator(host_root=tmp_path/"host", state_path=tmp_path/"coordinator/current.json",
                            boot_id_path=boot, stop=stop)
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"vitals-producers",
                                tmp_path/"domains/state.json", tmp_path/"recovery/current.json")
    address = tmp_path/"s"
    monkeypatch.setattr(presentation_service, "BOOT_ID_PATH", boot)
    monkeypatch.setattr(vitals_edge, "PRESENTATION_SOCKET", address)
    with presentation_service.PresentationServer(str(address), runtime) as server:
        server.timeout = 2
        for accept in ("application/json", "text/html"):
            worker = threading.Thread(target=server.handle_request)
            worker.start()
            try:
                status, content_type, headers, body = vitals_edge._presentation(
                    "GET", "/v1/runtime/status", accept)
            finally:
                worker.join(timeout=3)
            assert not worker.is_alive() and status == 200
            if accept == "application/json":
                value = json.loads(body)
                expected_host = {"missing": "HOST_WITNESS_UNAVAILABLE",
                                 "failed_after_success": "HOST_COLLECTION_FAILED",
                                 "healthy": "FIRST_BOOT_OBSERVED",
                                 "chronology_failed": "FIRST_BOOT_OBSERVED"}
                assert value["sections"]["host"]["claim"] == expected_host[host_condition]
                rows = {row["producer"]:row for row in value["sections"]["outpost"]["perspectives"]}
                assert value["sections"]["outpost"]["state"] == "OBSERVED"
                assert value["sections"]["outpost"]["claim"] is None
                assert rows["OUTPOST_WATCHDOG"]["claim"] == (
                    "CURRENT_BOOT_WITNESS" if host_condition == "healthy" else "DEGRADED")
                history = rows["OUTPOST_VITALITY_CHRONOLOGY"]
                assert history["claim"] == (
                    "CHRONOLOGY_UNAVAILABLE" if host_condition == "chronology_failed" else "CHRONOLOGY_OBSERVED")
                if host_condition == "chronology_failed":
                    assert history["payload"] == {"status": "UNAVAILABLE"}
                else:
                    assert history["payload"]["event_count"] >= 1
                coordinator = json.loads((tmp_path/"coordinator/current.json").read_text())
                for producer in (rows["OUTPOST_WATCHDOG"], history):
                    assert producer["boot_id"] == coordinator["boot_id"] == BOOT
                    assert producer["observed_at"] == coordinator["observed_at"]
                    assert producer["freshness"] == "CURRENT_BOOT_ATTRIBUTABLE"
                assert value["admission_effect"] == "NONE"
                # Edge Host readiness is separate from Kernel/Stage-1 admission.
                assert vitals_edge._ready(body) is healthy_host
                assert value["sections"]["domains"]["claim"] == "DENIED_HELD_SEED_CONTENT"
            else:
                assert b"<title>Serein Vitals</title>" in body
                assert b"State: DISAGREEMENT" not in body
                assert b"held, not admitted" in body
                assert (b"CHRONOLOGY_UNAVAILABLE" if host_condition == "chronology_failed" else b"CHRONOLOGY_OBSERVED") in body
                assert (b"CURRENT_BOOT_WITNESS" if host_condition == "healthy" else b"DEGRADED") in body
    assert not (tmp_path/"domains").exists()


def test_coordinator_persists_bytes_then_directory_before_return(tmp_path,monkeypatch):
    import os,stat
    from outpost import service
    seen=[]
    original_fsync=os.fsync;original_replace=os.replace
    def fsync(fd):
        seen.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
        return original_fsync(fd)
    def replace(*args,**kwargs):
        seen.append('replace')
        return original_replace(*args,**kwargs)
    monkeypatch.setattr(service.os,'fsync',fsync)
    monkeypatch.setattr(service.os,'replace',replace)
    result=produce(tmp_path)
    assert seen==['file','replace','directory']
    assert json.loads((tmp_path/'coordinator/current.json').read_text())==result


def test_coordinator_does_not_return_success_after_directory_flush_failure(tmp_path,monkeypatch):
    import os,stat
    from outpost import service
    original_fsync=os.fsync
    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('injected directory fsync failure')
        return original_fsync(fd)
    monkeypatch.setattr(service.os,'fsync',fsync)
    with pytest.raises(OSError,match='injected directory fsync failure'):
        produce(tmp_path)
    # Failure is not permission to delete/restore the preceding observation.
    assert (tmp_path/'coordinator/current.json').is_file()
    assert list((tmp_path/'coordinator').glob('.outpost-service-*'))==[]


def produce(root,*,completed=False):
    boot=root/"boot";boot.write_text(BOOT)
    if completed:
        attempts=HostCollectionAttempts(root/"host")
        identifier=attempts.start(BOOT,0.0)
        state=HostVitalityStore(root/"host").record(observation())
        attempts.finish(identifier,1.0,state=state)
    return coordinator_witness(host_root=root/"host",state_path=root/"coordinator/current.json",boot_id_path=boot,observed_at=2.0)


@pytest.mark.parametrize("completed",[False,True])
def test_coordinator_always_denies_downstream_and_binds_native_host_attempt(tmp_path,completed):
    value=produce(tmp_path,completed=completed)
    assert value["host_gate"]==("CURRENT_BOOT_OBSERVED" if completed else "HOST_GATE_UNAVAILABLE")
    assert value["downstream_activation"]=="DENIED_HELD_SEED_CONTENT"
    assert json.loads((tmp_path/"coordinator/current.json").read_text())==value
    assert validate_coordinator_witness(value,boot_id=BOOT,observed_at=2.0)==value
    assert not (tmp_path/"domains").exists()


@pytest.mark.parametrize("field,value",[("downstream_activation","ADMIT"),("registry_state","PASS"),
    ("authority_effect","GRANTED"),("admission_effect","SELF_ADMIT"),("mutation_effect","INSTALL"),
    ("observed_at",float("nan")),("boot_id","aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")])
def test_coordinator_cannot_admit_or_replace_boot_identity(tmp_path,field,value):
    state=produce(tmp_path);state[field]=value
    with pytest.raises(OutpostServiceError):validate_coordinator_witness(state,boot_id=BOOT,observed_at=3.0)


def test_vitals_shows_all_ten_held_domains_in_order_without_inventing_admission(tmp_path):
    produce(tmp_path)
    runtime=VitalsRuntimeStore(tmp_path/"host",tmp_path/"vitals-producers",tmp_path/"domains/state.json",tmp_path/"recovery/current.json")
    snapshot=runtime.snapshot(current_boot_id=BOOT)
    assert snapshot["sections"]["domains"]["claim"]=="DENIED_HELD_SEED_CONTENT"
    response=present(runtime,"GET","/v1/runtime/status","text/html",BOOT)
    assert response.status==200
    page=response.body.decode()
    positions=[page.index("<li>"+name+": HOLD_INTENTIONAL; DENIED_HELD_SEED_CONTENT.") for name in DOMAIN_ORDER]
    assert positions==sorted(positions)
    assert "held, not admitted" in page and "permits no downstream activation" in page


def test_coordinator_claim_cannot_override_a_newer_native_host_failure(tmp_path):
    produce(tmp_path,completed=True)
    attempts=HostCollectionAttempts(tmp_path/"host")
    identifier=attempts.start(BOOT,3.0)
    attempts.finish(identifier,4.0,error_code="DEBIAN_INRELEASE_SIGNATURE_DENIED")
    runtime=VitalsRuntimeStore(tmp_path/"host",tmp_path/"vitals-producers",tmp_path/"domains/state.json",tmp_path/"recovery/current.json")
    snapshot=runtime.snapshot(current_boot_id=BOOT)
    assert snapshot["sections"]["domains"]["claim"]=="DOMAIN_STATE_UNAVAILABLE"
    assert snapshot["sections"]["host"]["claim"]=="HOST_COLLECTION_FAILED"


def domain_observation(state="LAGGING",boot=BOOT):
    return producer_observation(perspective="domains",producer="OUTPOST_DOMAIN_OBSERVER",
      claim=state,observed_at=8.0,boot_id=boot,evidence_ref="fixture:domain-attempt-1",
      payload={"domain":"KERNEL","step":"SELF_TEST_HEALTH","state":state,"started_at":2.0})


@pytest.mark.parametrize("state",["PENDING","LAGGING","TIMED_OUT","RETRYING","RECOVERY","FAILED","HELD"])
def test_lag_and_failure_are_reported_without_becoming_admission(state):
    view=held_domain_boot_view(boot_id=BOOT,observed_at=9.0,observations=[domain_observation(state)])
    assert [row["domain"] for row in view["domains"]]==list(DOMAIN_ORDER)
    first=view["domains"][0]
    assert first["observation"]["claim"]==state
    assert first["observation_elapsed"]==6.0
    assert first["current_gate"]=="LOAD_SEED_CONSTITUTION"
    assert first["verification"]=="DENIED_HELD_SEED_CONTENT"
    assert first["downstream_hold"]==list(DOMAIN_ORDER[1:])
    assert first["seed"]["digest"] is None and first["blueprint"]["digest"] is None
    assert all(row["admission_effect"]=="NONE" and row["gate_order"]==list(DOMAIN_GATE_ORDER) for row in view["domains"])


@pytest.mark.parametrize("state",["PASS","ADMITTED","VERIFIED"])
def test_prior_or_current_success_cannot_override_held_seed(state):
    with pytest.raises(OutpostServiceError,match="DOMAIN_BOOT_OBSERVATION_DENIED"):
        held_domain_boot_view(boot_id=BOOT,observed_at=9.0,observations=[domain_observation(state)])


def test_prior_boot_observation_stays_history_and_current_boot_restarts_at_seed():
    prior=domain_observation(boot="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    view=held_domain_boot_view(boot_id=BOOT,observed_at=9.0,observations=[prior])
    assert view["domains"][0]["observation"] is None
    assert view["domains"][0]["historical_observation"]==prior
    assert view["earliest_unproven_domain"]=="KERNEL"
    assert view["earliest_unproven_gate"]=="LOAD_SEED_CONSTITUTION"


def test_domain_boot_presentation_distinguishes_lag_from_current_verification(tmp_path):
    produce(tmp_path)
    runtime=VitalsRuntimeStore(tmp_path/"host",tmp_path/"vitals-producers",tmp_path/"domains/state.json",tmp_path/"recovery/current.json")
    snapshot=runtime.snapshot(current_boot_id=BOOT)
    current=domain_observation()
    old=domain_observation(boot="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    payload=snapshot["sections"]["domains"]["perspectives"][0]["payload"]
    payload["boot_verification"]=held_domain_boot_view(boot_id=BOOT,observed_at=9.0,observations=[old,current])
    page=html_body(snapshot).decode()
    assert "Every-boot verification" in page
    assert "Supporting observation only: LAGGING at SELF_TEST_HEALTH" in page
    assert "Observed elapsed seconds: 6.0" in page
    assert "Prior-boot observation: HISTORICAL ONLY" in page
    assert "Blueprint reference: PRO-180 (unadmitted)" in page
    assert "Installed generation: UNPROVEN" in page
    assert "Current gate: LOAD_SEED_CONSTITUTION" in page


def test_future_observation_and_conflicting_same_time_are_denied():
    with pytest.raises(OutpostServiceError):
        held_domain_boot_view(boot_id=BOOT,observed_at=7.0,observations=[domain_observation()])
    with pytest.raises(OutpostServiceError,match="DOMAIN_BOOT_OBSERVATION_CONFLICT"):
        held_domain_boot_view(boot_id=BOOT,observed_at=9.0,
          observations=[domain_observation(),domain_observation("FAILED")])
