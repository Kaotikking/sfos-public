import json
import pytest

from outpost.host_vitality import HostVitalityStore, HostCollectionAttempts, digest
from outpost.watchdog import WatchdogError, witness_once
from outpost.vitals_runtime import VitalsRuntimeStore
from outpost.http_readonly import present
from tests.active_host import active_host


BOOT = "11111111-2222-4333-8444-555555555555"


def test_watchdog_publication_flushes_file_then_directory(tmp_path, monkeypatch):
    import os, stat
    from outpost import watchdog
    events = []
    original_fsync, original_replace = os.fsync, os.replace
    def fsync(fd):
        events.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        return original_fsync(fd)
    def replace(*args, **kwargs):
        events.append("replace")
        return original_replace(*args, **kwargs)
    monkeypatch.setattr(watchdog.os, "fsync", fsync)
    monkeypatch.setattr(watchdog.os, "replace", replace)
    watchdog._write_atomic(tmp_path/"current.json", {"fixture":"evidence"})
    assert events == ["file", "replace", "directory"]


def test_watchdog_failed_directory_flush_is_not_reported_as_success(tmp_path, monkeypatch):
    import os, stat
    from outpost import watchdog
    original = os.fsync
    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError("injected directory flush")
        return original(fd)
    monkeypatch.setattr(watchdog.os, "fsync", fsync)
    with pytest.raises(OSError, match="directory flush"):
        watchdog._write_atomic(tmp_path/"current.json", {"fixture":"evidence"})
    assert json.loads((tmp_path/"current.json").read_text()) == {"fixture":"evidence"}
    assert not list(tmp_path.glob(".watchdog-*"))


def record_completed(root, observation):
    attempts=HostCollectionAttempts(root)
    identifier=attempts.start(observation["boot_id"],observation["observed_at"])
    state=HostVitalityStore(root).record(observation)
    attempts.finish(identifier,observation["observed_at"],state=state)
    return state


def test_watchdog_writes_current_boot_witness_without_admitting_held_seeds(tmp_path):
    observation = {
        "schema": "SereinOutpostHostVitalityObservation/v2", "target": "VM4010", "boot_id": BOOT,
        "observed_at": 1.0,
        "host": {"hostname": "serein-vm4010", "os_id": "debian", "os_version_id": "13", "machine_id": "m", "status": "PASS"},
        "gpu": {"pci_present": True, "driver_loaded": True, "device_count": 1, "driver_packages": {}, "status": "PASS"},
        "public_base": {"repository":"Kaotikking/sfos-public","commit":"a"*40,"tree":"b"*40,"lock_path":"sfos/base/packages.lock","lock_sha256":"a"*64,"policy_path":"sfos/base/installer/base-policy.json","policy_sha256":"b"*64,"expected_packages":{},"observed_packages":{},"exact_diff":[],"unknowns":[],"status":"PASS"},
    }
    host_root = tmp_path / "host"
    record_completed(host_root,active_host(observation))
    boot = tmp_path / "boot"; boot.write_text(BOOT, encoding="ascii")
    state = witness_once(state_root=tmp_path / "watchdog", host_root=host_root, boot_id_path=boot, observed_at=2.0)
    assert state["watchdog_state"] == "CURRENT_BOOT_WITNESS"
    assert state["registry_state"] == "HOLD_INTENTIONAL"
    assert json.loads((tmp_path / "watchdog" / "current.json").read_text(encoding="utf-8")) == state


@pytest.mark.parametrize("condition", ["missing", "corrupt", "drift", "stale"])
def test_watchdog_records_degradation_without_exiting_on_bad_host_evidence(tmp_path, condition):
    host = tmp_path / "host"
    host.mkdir()
    if condition == "corrupt":
        (host / "state.json").write_text("{}")
    if condition in {"drift", "stale"}:
        body = {"target": "SEREIN_HOST", "boot_id": BOOT if condition == "drift" else "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "observed_at": 1.0,
                "host": {"hostname": "host", "os_id": "debian", "os_version_id": "13", "machine_id": "m", "status": "PASS"},
                "gpu": {"pci_present": True, "driver_loaded": condition != "drift", "device_count": 1, "driver_packages": {}, "status": "PASS"}}
        record_completed(host,active_host(body))
    boot = tmp_path / "boot"
    boot.write_text(BOOT, encoding="ascii")
    state = witness_once(state_root=tmp_path / "watchdog", host_root=host, boot_id_path=boot, observed_at=2.0)
    assert state["watchdog_state"] == "DEGRADED"
    assert state["host_witness"] == ("CURRENT" if condition == "drift" else "STALE_OR_UNAVAILABLE")
    assert state["authority_effect"] == state["admission_effect"] == state["mutation_effect"] == "NONE"
    assert json.loads((tmp_path / "watchdog" / "current.json").read_text()) == state


def test_watchdog_cannot_invent_boot_identity(tmp_path):
    boot = tmp_path / "boot"
    boot.write_text("not-a-boot-id", encoding="ascii")
    with pytest.raises(WatchdogError, match="WATCHDOG_SOURCE_UNAVAILABLE"):
        witness_once(state_root=tmp_path / "watchdog", host_root=tmp_path / "host", boot_id_path=boot)
    assert not (tmp_path / "watchdog" / "current.json").exists()


def test_real_watchdog_output_reaches_vitals_and_chronology(tmp_path):
    boot = tmp_path / "boot"
    boot.write_text(BOOT, encoding="ascii")
    witness_once(state_root=tmp_path/"watchdog", host_root=tmp_path/"host", boot_id_path=boot, observed_at=2.0)
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"vitals-producers", tmp_path/"domains.json", tmp_path/"recovery/current.json")
    response = present(runtime, "GET", "/v1/runtime/status", "application/json", BOOT)
    assert response.status == 200
    producers = {row["producer"]: row for row in json.loads(response.body)["sections"]["outpost"]["perspectives"]}
    assert producers["OUTPOST_WATCHDOG"]["claim"] == "DEGRADED"
    history = producers["OUTPOST_VITALITY_CHRONOLOGY"]["payload"]
    assert history["event_count"] == 1
    assert history["latest_event"]["payload"]["watchdog_state"] == "DEGRADED"
    page = present(runtime, "GET", "/v1/runtime/status", "text/html", BOOT)
    assert page.status == 200
    assert "OUTPOST_WATCHDOG" in page.body.decode()
    assert "Black-box event chronology: UNKNOWN" not in page.body.decode()
    assert not (tmp_path/"domains.json").exists()


@pytest.mark.parametrize("delayed_host", [False, True])
def test_observed_boot_change_produces_recovery_witness_without_power_effect(tmp_path, delayed_host):
    boot = tmp_path / "boot"
    host = HostVitalityStore(tmp_path/"host")
    for boot_id, observed in [(BOOT, 1.0), ("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", 3.0)]:
        if delayed_host and observed == 3.0:
            boot.write_text(boot_id, encoding="ascii")
            witness_once(state_root=tmp_path/"watchdog", host_root=tmp_path/"host", boot_id_path=boot, observed_at=2.5)
        body = {"target": "SEREIN_HOST", "boot_id": boot_id, "observed_at": observed,
                "host": {"hostname": "host", "os_id": "debian", "os_version_id": "13", "machine_id": "m", "status": "PASS"},
                "gpu": {"pci_present": True, "driver_loaded": True, "device_count": 1, "driver_packages": {}, "status": "PASS"}}
        record_completed(tmp_path/"host",active_host(body))
        boot.write_text(boot_id, encoding="ascii")
        witness_once(state_root=tmp_path/"watchdog", host_root=tmp_path/"host", boot_id_path=boot, observed_at=observed+1)
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"vitals-producers", tmp_path/"domains.json", tmp_path/"recovery/current.json")
    recovery = runtime.snapshot(current_boot_id=boot_id)["sections"]["recovery"]
    assert recovery["claim"] == "BOOT_RECOVERY_UNKNOWN"
    payload = recovery["perspectives"][0]["payload"]
    assert payload["previous_boot_id"] == BOOT and payload["new_boot_id"] == boot_id
    assert payload["cause"] == "REBOOT_CAUSE_UNKNOWN"
    assert payload["witness_mode"] == "POST_BOOT_INFERRED_REBOOT"
    assert payload["post_boot"]["readiness"] == "UNKNOWN"
    assert not (tmp_path/"systemd").exists()  # No startup/edge proof was supplied.
    assert payload["first_post_boot_at"] == (2.5 if delayed_host else 4.0)
    assert payload["authority_effect"] == payload["mutation_effect"] == "NONE"
    assert payload["policy_version"] == host.snapshot()["latest"]["public_base"]["policy_sha256"]
    assert not (tmp_path/"domains.json").exists()


def test_watchdog_does_not_call_old_success_current_after_new_failure(tmp_path):
    from tests.test_host_vitality import observation
    host=tmp_path/"host"
    record_completed(host,observation())
    attempts=HostCollectionAttempts(host)
    identifier=attempts.start(BOOT,2.0)
    attempts.finish(identifier,3.0,error_code="DEBIAN_INRELEASE_SIGNATURE_DENIED")
    boot=tmp_path/"boot";boot.write_text(BOOT)
    value=witness_once(state_root=tmp_path/"watchdog",host_root=host,boot_id_path=boot,observed_at=4.0)
    assert value["watchdog_state"]=="DEGRADED"
    assert value["host_witness"]=="STALE_OR_UNAVAILABLE"


@pytest.mark.parametrize("defect", [None, "package"])
def test_recipe_witness_reaches_watchdog_vitals_and_boot_history(tmp_path, monkeypatch, defect):
    from outpost import public_tree_host, vitals_runtime
    from outpost.host_vitality import recipe_observation
    from tests.test_host_vitality import recipe_witness
    recipe = recipe_witness(defect)
    monkeypatch.setattr(public_tree_host, "installed_public_source", lambda: recipe["source"])
    boot = tmp_path / "boot"
    for boot_id, observed in [(BOOT, 1.0), ("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", 3.0)]:
        recipe["comparison"]["boot_id"] = boot_id
        recipe["comparison"]["evidence_digest"] = digest({k:v for k,v in recipe["comparison"].items() if k != "evidence_digest"})
        recipe["evidence_digest"] = digest({k:v for k,v in recipe.items() if k != "evidence_digest"})
        record_completed(tmp_path / "host", recipe_observation(recipe, observed))
        boot.write_text(boot_id, encoding="ascii")
        state = witness_once(state_root=tmp_path/"watchdog", host_root=tmp_path/"host", boot_id_path=boot, observed_at=observed+1)
        assert state["host_witness"] == "CURRENT"
        assert state["watchdog_state"] == ("DEGRADED" if defect else "CURRENT_BOOT_WITNESS")
    monkeypatch.setattr(vitals_runtime.time, "time", lambda: 4.0)
    runtime = VitalsRuntimeStore(tmp_path/"host", tmp_path/"vitals-producers", tmp_path/"domains.json", tmp_path/"recovery/current.json")
    snapshot = runtime.snapshot(current_boot_id=boot_id)
    expected = "DRIFT_DETECTED" if defect else "RECOVERED_AFTER_BOOT_CHANGE"
    assert snapshot["sections"]["host"]["claim"] == expected
    recovery = snapshot["sections"]["recovery"]["perspectives"][0]["payload"]
    assert recovery["policy_version"] == recipe["manifest_sha256"]
    assert recovery["previous_boot_id"] == BOOT
    page = present(runtime, "GET", "/v1/runtime/status", "text/html", boot_id)
    assert page.status == 200 and expected in page.body.decode()
    assert snapshot["admission_effect"] == snapshot["mutation_effect"] == "NONE"
    monkeypatch.setattr(public_tree_host, "installed_public_source", lambda: {**recipe["source"], "commit": "0"*40})
    assert runtime.snapshot(current_boot_id=boot_id)["sections"]["host"]["claim"] == "HOST_ATTEMPT_RESULT_UNBOUND"
    changed = witness_once(state_root=tmp_path/"watchdog", host_root=tmp_path/"host", boot_id_path=boot, observed_at=5.0)
    assert changed["watchdog_state"] == "DEGRADED" and changed["host_witness"] == "STALE_OR_UNAVAILABLE"
