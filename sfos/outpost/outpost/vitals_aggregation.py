"""Non-authoritative, credential-free aggregation for Serein Vitals."""
from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any
from .host_vitality import BOOT

SCHEMA = "SereinVitalsAggregation/v1"
SOURCE_SCHEMA = "SereinVitalsProducerObservation/v1"
PERSPECTIVES = ("host", "serein", "outpost", "domains", "budget", "recovery")
# These existing native readers report different subjects, not competing
# answers to one question. Unknown producers retain conservative comparison.
_OUTPOST_RESPONSIBILITIES = frozenset({"OUTPOST_WATCHDOG", "OUTPOST_VITALITY_CHRONOLOGY", "OUTPOST_CONSTITUTIONAL_REGISTRY"})
_SECRET_KEYS = {"authorization", "cookie", "credential", "credentials", "password", "private_key", "secret", "token", "access_token", "refresh_token"}


class VitalsAggregationError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise VitalsAggregationError("VITALS_PRODUCER_VALUE_DENIED") from error


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _reject_credentials(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in _SECRET_KEYS:
                raise VitalsAggregationError("VITALS_CREDENTIAL_MATERIAL_DENIED")
            _reject_credentials(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _reject_credentials(child)


def producer_observation(*, perspective: str, producer: str, claim: str,
                         observed_at: float, boot_id: str, evidence_ref: str,
                         payload: Mapping[str, Any]) -> dict[str, Any]:
    body = {
        "schema": SOURCE_SCHEMA, "perspective": perspective, "producer": producer,
        "claim": claim, "observed_at": observed_at, "boot_id": boot_id,
        "evidence_ref": evidence_ref, "payload": dict(payload),
        "authority_effect": "NONE", "admission_effect": "NONE", "mutation_effect": "NONE",
    }
    _validate_body(body)
    return {**body, "evidence_digest": _digest(body)}


def _validate_body(body: Mapping[str, Any]) -> None:
    expected = {"schema", "perspective", "producer", "claim", "observed_at", "boot_id", "evidence_ref", "payload", "authority_effect", "admission_effect", "mutation_effect"}
    if not isinstance(body, Mapping) or set(body) != expected or body.get("schema") != SOURCE_SCHEMA:
        raise VitalsAggregationError("VITALS_PRODUCER_SHAPE_DENIED")
    if body.get("perspective") not in PERSPECTIVES:
        raise VitalsAggregationError("VITALS_PERSPECTIVE_DENIED")
    if not all(isinstance(body.get(key), str) and body[key] for key in ("producer", "claim", "boot_id", "evidence_ref")) or not BOOT.fullmatch(body["boot_id"]):
        raise VitalsAggregationError("VITALS_PRODUCER_IDENTITY_DENIED")
    observed_at = body.get("observed_at")
    if type(observed_at) not in (int, float) or not math.isfinite(observed_at) or observed_at < 0 or not isinstance(body.get("payload"), Mapping):
        raise VitalsAggregationError("VITALS_PRODUCER_VALUE_DENIED")
    if any(body.get(key) != "NONE" for key in ("authority_effect", "admission_effect", "mutation_effect")):
        raise VitalsAggregationError("VITALS_EFFECT_DENIED")
    _reject_credentials(body)


def validate_producer(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or "evidence_digest" not in value:
        raise VitalsAggregationError("VITALS_PRODUCER_SHAPE_DENIED")
    body = {key: child for key, child in value.items() if key != "evidence_digest"}
    _validate_body(body)
    if value.get("evidence_digest") != _digest(body):
        raise VitalsAggregationError("VITALS_PRODUCER_DIGEST_DENIED")
    return dict(value)


def aggregate_vitals(sources: Mapping[str, Sequence[Mapping[str, Any]]], *, current_boot_id: str, generated_at: float) -> dict[str, Any]:
    if not isinstance(sources, Mapping) or set(sources) - set(PERSPECTIVES):
        raise VitalsAggregationError("VITALS_SOURCE_SET_DENIED")
    if not isinstance(current_boot_id, str) or not BOOT.fullmatch(current_boot_id) or type(generated_at) not in (int, float) or not math.isfinite(generated_at) or generated_at < 0:
        raise VitalsAggregationError("VITALS_AGGREGATION_IDENTITY_DENIED")
    sections: dict[str, Any] = {}
    for perspective in PERSPECTIVES:
        raw = sources.get(perspective, ())
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
            raise VitalsAggregationError("VITALS_PRODUCER_LIST_DENIED")
        observations = [validate_producer(item) for item in raw]
        if any(item["perspective"] != perspective for item in observations):
            raise VitalsAggregationError("VITALS_PERSPECTIVE_BINDING_DENIED")
        # No canonical producer TTL is specified. Bind the boot and timestamps
        # without asserting quantitative freshness from a matching boot alone.
        rendered = [{**item, "freshness": "INVALID_FUTURE" if item["observed_at"] > generated_at else "CURRENT_BOOT_ATTRIBUTABLE" if item["boot_id"] == current_boot_id else "STALE"} for item in observations]
        current = [item for item in rendered if item["freshness"] == "CURRENT_BOOT_ATTRIBUTABLE"]
        groups: dict[str, list[dict[str, Any]]] = {}
        separate_roles = perspective == "outpost" and all(item["producer"] in _OUTPOST_RESPONSIBILITIES for item in current)
        for item in current:
            groups.setdefault(item["producer"] if separate_roles else perspective, []).append(item)
        disagreement = any(len({item["claim"] for item in group}) != 1
                           or len({_canonical(item["payload"]) for item in group}) != 1
                           for group in groups.values())
        state = "UNKNOWN" if not current else "DISAGREEMENT" if disagreement else "OBSERVED"
        # OBSERVED is evidence availability, never health or admission. Keep
        # unlike role claims on their producers rather than inventing one PASS.
        claim = current[0]["claim"] if state == "OBSERVED" and len(groups) == 1 else None
        sections[perspective] = {"state": state, "claim": claim, "producer_count": len(rendered), "current_producer_count": len(current), "perspectives": rendered}
    body = {"schema": SCHEMA, "current_boot_id": current_boot_id, "generated_at": generated_at, "sections": sections, "authority_effect": "NONE", "admission_effect": "NONE", "mutation_effect": "NONE"}
    return {**body, "projection_digest": _digest(body)}
