from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[1]
def text(path): return (ROOT/path).read_text(encoding="utf-8")

def test_host_witness_precedes_local_presentation():
    witness=text("systemd/serein-outpost-host-witness.service")
    presentation=text("systemd/serein-outpost-presentation.service")
    target=text("systemd/serein-outpost.target")
    assert "Before=serein-outpost-presentation.service" in witness
    assert "Requires=serein-outpost-host-witness.service" in presentation
    assert "After=serein-outpost-host-witness.service" in presentation
    expected="serein-outpost-host-witness.service serein-outpost-presentation.service"
    assert f"Requires={expected}" in target and f"After={expected}" in target
    assert "[Install]" in target and "WantedBy=multi-user.target" in target
    launcher="/usr/libexec/serein/outpost-generation-launcher"
    assert f"ExecStart={launcher} outpost/host_witness_runner.py" in witness
    assert f"ExecStart={launcher} outpost/presentation_service.py" in presentation
    assert "PYTHONPATH=/usr/share/serein/outpost" not in witness+presentation

def test_presentation_is_read_only_local_unix_socket():
    unit=text("systemd/serein-outpost-presentation.service")
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "ExecStart=/usr/libexec/serein/outpost-generation-launcher outpost/presentation_service.py" in unit
    assert "AF_INET" not in unit and "LoadCredential=" not in unit

def test_public_release_has_no_downstream_install_targets():
    release=json.loads(text("release-manifest.json"))
    forbidden_targets=("/var/lib/serein/kernel","/etc/serein/kernel","/usr/lib/serein/kernel","/run/serein/kernel")
    assert not any(row["target"].startswith(forbidden_targets) for row in release["install_files"])
    assert all(row["target"].startswith(("/usr/share/serein/outpost/","/etc/systemd/system/","/usr/libexec/serein/")) for row in release["install_files"])

def test_kernel_installer_is_outpost_owned_and_inactive():
    unit=text("systemd/serein-outpost-kernel-install.service")
    target=text("systemd/serein-outpost.target")
    assert "ExecStart=/usr/libexec/serein/outpost-generation-launcher install/kernel_first_install_runner.py" in unit
    assert "ConditionPathExists=/var/lib/serein-outpost/kernel/install-request.json" in unit
    assert "[Install]" not in unit and "WantedBy=" not in unit
    assert "serein-outpost-kernel-install.service" not in target
