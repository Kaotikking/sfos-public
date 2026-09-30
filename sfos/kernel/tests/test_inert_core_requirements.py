"""Pure future-input requirements; no Core identity, service or Seed creation."""
import copy
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "inert_core_requirements", Path(__file__).resolve().parents[1] /
    "payload/serein_stage1/core_attachments.py")
attachments = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(attachments)


def test_exact_requirements_are_inert_and_never_native_identity_records():
    rows = attachments.contracts()
    assert [row["domain"] for row in rows] == list(attachments.CORE_ORDER)
    for index, row in enumerate(rows):
        assert row["core_dependencies"] == list(attachments.CORE_ORDER[:index])
        assert row["prerequisites"] == ["STAGE1_READY", "KERNEL_AUTHORITY_CHECK"]
        assert not {"identity", "instance_id", "public_key", "fingerprint", "registry"} & row.keys()
        assert row["identity_requirement"] == {
            "record_schema": "SereinDomainIdentityRecord/v1", "state": "UNASSIGNED"}
    assert attachments.validate_inert(rows) == {
        "state": "INERT", "admission_state": "UNADMITTED", "authority_effect": "NONE"}


@pytest.mark.parametrize("change", (
    "reorder", "duplicate", "fake_identity", "dependency", "prerequisite",
    "loaded_blueprint", "loaded_seed", "api_false", "api_integer", "admitted", "effect",
))
def test_drift_cannot_pass_inert_contract_validation(change):
    rows = copy.deepcopy(attachments.contracts())
    if change == "reorder": rows[0], rows[1] = rows[1], rows[0]
    elif change == "duplicate": rows[1] = rows[0]
    elif change == "fake_identity": rows[0]["identity"] = "SEREIN_DOMAIN_PLATFORM"
    elif change == "dependency": rows[1]["core_dependencies"] = []
    elif change == "prerequisite": rows[0]["prerequisites"] = []
    elif change == "loaded_blueprint": rows[0]["blueprint"] = "LOADED"
    elif change == "loaded_seed": rows[0]["seed"] = "ADMITTED"
    elif change == "api_false": rows[0]["api_required"] = False
    elif change == "api_integer": rows[0]["api_required"] = 1
    elif change == "admitted": rows[0]["admission_state"] = "ADMITTED"
    elif change == "effect": rows[0]["authority_effect"] = "GRANTED"
    with pytest.raises(attachments.AttachmentDenied):
        attachments.validate_inert(rows)
