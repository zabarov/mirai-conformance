"""Independent semantic checks for Mirai 2.2 Autonomic Fabric artifacts."""

from __future__ import annotations

import fnmatch
from typing import Any

from jsonschema import Draft202012Validator

from .canonical import digest_value


NEVER_AUTOMATIC = {
    "protected_invariant", "authority", "capability", "approval",
    "conflict_resolution", "effectful_program", "history_deletion",
    "autonomy_envelope",
}


def _without_digest(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "digest"}


def _schema_errors(document: Any, schema: dict[str, Any]) -> list[str]:
    return sorted(
        f"schema:{'/'.join(str(part) for part in error.absolute_path) or '/'}:{error.message}"
        for error in Draft202012Validator(schema).iter_errors(document)
    )


def _digest_errors(document: dict[str, Any], label: str) -> list[str]:
    return [] if digest_value(_without_digest(document)) == document.get("digest") else [f"{label}:digest_mismatch"]


def _boundary(document: dict[str, Any], label: str) -> list[str]:
    return [] if document.get("canonical_write_allowed") is False else [f"{label}:canonical_write_must_be_false"]


def validate_source_snapshot(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "source_snapshot") + _digest_errors(document, "source_snapshot")
    keys = [item.get("key") for item in document.get("items", [])]
    if len(keys) != len(set(keys)):
        errors.append("source_snapshot:duplicate_item_key")
    if document.get("source", {}).get("read_only") is not True:
        errors.append("source_snapshot:source_not_read_only")
    return errors


def validate_normalized_unit(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("instructions_authorized") is not False:
        errors.append("normalized_unit:source_instruction_authorized")
    if digest_value(document.get("content")) != document.get("content_digest"):
        errors.append("normalized_unit:content_digest_mismatch")
    if not document.get("source_ref") or not document.get("source_fingerprint"):
        errors.append("normalized_unit:provenance_missing")
    return errors


def validate_knowledge_proposal(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "knowledge") + _digest_errors(document, "knowledge")
    conflicts = document.get("conflicts", [])
    if any(item.get("resolution") != "owner_review_required" for item in conflicts):
        errors.append("knowledge:conflict_without_owner_review")
    ambiguous = [item for item in document.get("identity_resolutions", []) if item.get("resolution") == "ambiguous"]
    if (conflicts or ambiguous) and document.get("quality", {}).get("readiness") != "blocked":
        errors.append("knowledge:blocking_finding_marked_ready")
    if any(not item.get("provenance") for item in document.get("assertions", [])):
        errors.append("knowledge:assertion_provenance_missing")
    return errors


def validate_process_observation(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "process_observation")
    if not document.get("sequence"):
        errors.append("process_observation:sequence_missing")
    return errors


def validate_process_candidate(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "process_candidate") + _digest_errors(document, "process_candidate")
    if document.get("mode") == "observed" and document.get("technology_draft_allowed") is not False:
        errors.append("process_candidate:observed_practice_promoted")
    if document.get("mode") == "intended" and not document.get("normative_authority_present") and document.get("technology_draft_allowed"):
        errors.append("process_candidate:normative_authority_missing")
    return errors


def validate_autonomy_envelope(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "autonomy_envelope") + _digest_errors(document, "autonomy_envelope")
    if any(kind in NEVER_AUTOMATIC for kind in document.get("allowed_change_kinds", [])):
        errors.append("autonomy_envelope:protected_kind_allowed")
    if not document.get("approver_signatures"):
        errors.append("autonomy_envelope:signature_required")
    if document.get("rollback_contract", {}).get("required") is not True or document.get("rollback_contract", {}).get("verify_readback") is not True:
        errors.append("autonomy_envelope:rollback_required")
    if any(not str(pattern).startswith("adaptive/") for pattern in document.get("resource_patterns", [])):
        errors.append("autonomy_envelope:resource_outside_adaptive_stratum")
    return errors


def validate_evolution_proposal(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "evolution_proposal") + _digest_errors(document, "evolution_proposal")
    for change in document.get("changes", []):
        if digest_value(change.get("payload")) != change.get("payload_digest"):
            errors.append(f"evolution_proposal:payload_digest_mismatch:{change.get('id')}")
    return errors


def _change_must_not_be_automatic(change: dict[str, Any], envelope: dict[str, Any], proposal: dict[str, Any]) -> bool:
    if change.get("kind") in NEVER_AUTOMATIC or change.get("stratum") != "adaptive_canonical":
        return True
    if change.get("effectful") is True or change.get("conflict_refs") or change.get("reversible") is not True:
        return True
    if not str(change.get("target_ref", "")).startswith("adaptive/"):
        return True
    if proposal.get("scope") != envelope.get("scope"):
        return True
    if any(fnmatch.fnmatchcase(str(change.get("target_ref")), pattern) for pattern in envelope.get("forbidden_targets", [])):
        return True
    return False


def validate_evolution_decision(document: dict[str, Any], proposal: dict[str, Any] | None, envelope: dict[str, Any] | None) -> list[str]:
    errors = _boundary(document, "evolution_decision") + _digest_errors(document, "evolution_decision")
    if proposal is None or envelope is None:
        return errors + ["evolution_decision:proposal_and_envelope_required"]
    if document.get("proposal_digest") != proposal.get("digest") or document.get("envelope_digest") != envelope.get("digest"):
        errors.append("evolution_decision:binding_mismatch")
    decisions = {item.get("change_id"): item for item in document.get("change_decisions", [])}
    for change in proposal.get("changes", []):
        decision = decisions.get(change.get("id"))
        if decision is None:
            errors.append(f"evolution_decision:change_missing:{change.get('id')}")
        elif _change_must_not_be_automatic(change, envelope, proposal) and decision.get("verdict") == "allow_automatic":
            errors.append(f"evolution_decision:unsafe_automatic_verdict:{change.get('id')}")
    if any(item.get("verdict") == "deny" for item in decisions.values()) and document.get("verdict") != "denied":
        errors.append("evolution_decision:aggregate_verdict_mismatch")
    return errors


def validate_promotion_receipt(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "promotion_receipt") + _digest_errors(document, "promotion_receipt")
    if document.get("readback_verified") is not True:
        errors.append("promotion_receipt:readback_not_verified")
    if not str(document.get("state_ref", "")).startswith(".mirai/"):
        errors.append("promotion_receipt:state_outside_host_local_root")
    return errors


def validate_autonomic_cycle(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "autonomic_cycle") + _digest_errors(document, "autonomic_cycle")
    if document.get("knowledge", {}).get("readiness") == "blocked" and document.get("status") not in {"manual_review_required", "denied"}:
        errors.append("autonomic_cycle:blocked_knowledge_advanced")
    for candidate in document.get("processes", {}).get("candidates", []):
        if candidate.get("mode") == "observed" and candidate.get("technology_draft_allowed") is not False:
            errors.append("autonomic_cycle:observed_process_promoted")
    errors.extend(validate_evolution_proposal(document.get("evolution_proposal", {})))
    return errors


VALIDATORS = {
    "source-snapshot": validate_source_snapshot,
    "normalized-unit": validate_normalized_unit,
    "knowledge-proposal": validate_knowledge_proposal,
    "process-observation": validate_process_observation,
    "process-candidate": validate_process_candidate,
    "autonomy-envelope": validate_autonomy_envelope,
    "evolution-proposal": validate_evolution_proposal,
    "promotion-receipt": validate_promotion_receipt,
    "autonomic-cycle": validate_autonomic_cycle,
}


def check_autonomic(
    kind: str,
    document: dict[str, Any],
    schema: dict[str, Any],
    *,
    proposal: dict[str, Any] | None = None,
    envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors = _schema_errors(document, schema)
    if not errors:
        if kind == "evolution-decision":
            errors.extend(validate_evolution_decision(document, proposal, envelope))
        elif kind in VALIDATORS:
            errors.extend(VALIDATORS[kind](document))
        else:
            errors.append(f"autonomic:unknown_kind:{kind}")
    return {
        "contract_version": "1.0.0",
        "implementation": "python_independent",
        "kind": kind,
        "status": "passed" if not errors else "failed",
        "artifact_digest": digest_value(document),
        "errors": sorted(set(errors)),
        "canonical_write_performed": False,
        "effects_executed": False,
    }
