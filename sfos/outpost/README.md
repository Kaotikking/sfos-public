# Serein SFOS Base and Outpost

This public source contains the reproducible Debian Base profile and the first-install Outpost Host gate. It intentionally contains no private credentials, network topology, Gateway implementation, model material, Kernel payload, or downstream domain payload.

Outpost performs two independent Host duties:

1. Fetch only allowlisted Debian `InRelease` and package indexes.
2. Verify their signatures using Debian's archive keyring, compare the installed Debian package state, capture GPU continuity, persist a current-boot witness, and expose the read-only **Serein Vitals** presentation through a local Unix socket.

Serein Vitals retains the complete historical Operator-lens semantics formerly
described as Mission Control: independent producer perspectives, explicit
disagreement, append-only chronology, budget and recovery producer slots,
Rescue/Resume guidance, and expected/unexpected reboot plus recovery lifecycle.
Missing producers remain `UNKNOWN`; the presentation, aggregators, and chronology
grant no authority and perform no recovery or domain activation.

First installation is inactive by default and creates a complete rollback
receipt before writing payload files. Existing flat installations migrate to an
immutable content-addressed predecessor generation. Later public updates stage
an exact signed generation, probe its boot preflight and Vitals acceptance while
current remains unchanged, then atomically advance LKG and current selectors.
Executable rollback is receipt-bound, resumable, and fail-closed; it never scans
for a newest generation. Neither road enables downstream domains, reboots, or
advances Kernel.

## Verification

From `sfos/outpost`, set `PYTHONPATH=.` and run:

```text
python refresh_manifest.py
python verify_install_preflight.py --source . --mode source
python -m pytest -q -p no:cacheprovider tests/test_debian_host_collector.py tests/test_debian_host_sources.py tests/test_host_vitality.py tests/test_host_witness_runner.py tests/test_http_readonly.py tests/test_presentation_service.py tests/test_systemd_contract.py tests/test_transaction.py
```

Private target binding and any immutable inputs are supplied only at governed delivery time. Kernel and later domains remain separate, ordered payloads that are unavailable until Outpost has independently passed the Host gate.
