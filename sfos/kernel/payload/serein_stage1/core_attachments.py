"""Inert nine-Core requirements adapted from public blob788b49c7.

These are installation requirements, not DomainID records, loaded Seeds,
runtime APIs or admission witnesses. Constructing them performs no effects.
"""
CORE_ORDER = ("PLATFORM", "ROOT", "MEMORY", "KNOWLEDGE", "UI", "AUDIO",
              "PERSONALITY", "MODULAR", "CLOUD")


class AttachmentDenied(ValueError):
    pass


def contracts():
    return [{"domain": name,
             "identity_requirement": {"record_schema": "SereinDomainIdentityRecord/v1",
                                      "state": "UNASSIGNED"},
             "api_version": "v1", "blueprint": "REQUIRED_UNLOADED",
             "seed": "REQUIRED_UNLOADED",
             "core_dependencies": list(CORE_ORDER[:index]),
             "prerequisites": ["STAGE1_READY", "KERNEL_AUTHORITY_CHECK"],
             "admission_state": "UNADMITTED", "state": "INERT",
             "activation": "OUTPOST_ONLY", "api_required": True,
             "authority_effect": "NONE"}
            for index, name in enumerate(CORE_ORDER)]


def validate_inert(value):
    """Check exact inert requirements; success grants no runtime authority."""
    expected = contracts()
    if (not isinstance(value, list) or len(value) != len(expected)
            or any(not isinstance(row, dict) or row != wanted
                   or row.get("api_required") is not True
                   for row, wanted in zip(value, expected))):
        raise AttachmentDenied("INERT_CORE_REQUIREMENTS_DENIED")
    return {"state": "INERT", "admission_state": "UNADMITTED",
            "authority_effect": "NONE"}
