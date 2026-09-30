"""Donor-only GPU observation contract: never hardware/admission proof."""
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "gpu_observation_contract", Path(__file__).resolve().parents[1] /
    "payload/serein_stage1/gpu_control.py")
gpu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gpu)


def test_caller_shaped_gpu_fact_cannot_claim_custody_or_readiness():
    shaped = {"schema": "SEREIN/KernelGPUControlWitness/v1",
              "boot_id": "synthetic-unmeasured-boot", "device_count": 1,
              "driver_loaded": True, "gpu_inventory_sha256": "a" * 64,
              "authority_effect": "NONE"}
    result = gpu.verify(shaped)
    assert result["status"] == "UNPROVEN"
    assert result["owner"] == "UNPROVEN"
    assert result["authority_effect"] == "NONE"
    assert "READY" not in result.values() and "KERNEL" not in result.values()


@pytest.mark.parametrize("value", (None, {}, {"status": "READY", "owner": "KERNEL"}))
def test_missing_gpu_observation_is_denied(value):
    with pytest.raises(gpu.GPUControlDenied):
        gpu.verify(value)
