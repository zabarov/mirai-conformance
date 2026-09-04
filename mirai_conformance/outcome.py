"""Independent semantic checks for Mirai 2.5 Outcome Completion."""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .canonical import digest_value


def _schema_errors(document: Any, schema: dict[str, Any]) -> list[str]:
    return sorted(
        f"schema:{'/'.join(str(part) for part in error.absolute_path) or '/'}:{error.message}"
        for error in Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document)
    )


def _digest(document: dict[str, Any]) -> str:
    return digest_value({key: value for key, value in document.items() if key != "digest"})


def _boundaries(document: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append(f"{prefix}:canonical_write_must_be_false")
    if "execution_allowed" in document and document.get("execution_allowed") is not False:
        errors.append(f"{prefix}:execution_must_be_false")
    if _digest(document) != document.get("digest"):
        errors.append(f"{prefix}:digest_mismatch")
    return errors


def validate_contract(document: dict[str, Any]) -> list[str]:
    errors = _boundaries(document, "outcome_contract")
    slots = document.get("required_slots", []) + document.get("optional_slots", [])
    slot_ids = [slot.get("id") for slot in slots]
    if len(slot_ids) != len(set(slot_ids)):
        errors.append("outcome_contract:duplicate_slot_id")
    if document.get("template_authority") == "ephemeral_read_only" and document.get("scope", {}).get("effect") != "read_only":
        errors.append("outcome_contract:effectful_ephemeral_contract")
    if document.get("completion_policy", {}).get("all_critical_required") is not True:
        errors.append("outcome_contract:critical_completion_weakened")
    return errors


def validate_candidates(document: dict[str, Any], contract: dict[str, Any] | None) -> list[str]:
    errors = _boundaries(document, "outcome_candidates")
    if document.get("accepted") is not False or document.get("content_is_untrusted_data") is not True:
        errors.append("outcome_candidates:trust_boundary_broken")
    if contract is not None and document.get("contract_digest") != contract.get("digest"):
        errors.append("outcome_candidates:contract_binding_mismatch")
    return errors


def _expected_status(contract: dict[str, Any], candidates: dict[str, Any], assessment: dict[str, Any]) -> str:
    scope = contract.get("scope", {})
    context = candidates.get("context", {})
    if context.get("purpose") != scope.get("purpose") or any(domain not in scope.get("domains", []) for domain in context.get("domains", [])):
        return "out_of_scope"
    if context.get("availability") == "failed":
        return "failed"
    if context.get("availability") == "temporarily_unavailable":
        return "temporarily_unavailable"
    if context.get("handoff_required") is True:
        return "handoff_required"
    definitions = {slot["id"]: slot for slot in contract.get("required_slots", []) + contract.get("optional_slots", [])}
    slots = assessment.get("slots", [])
    if any(
        slot.get("state") == "conflicting"
        and (
            definitions.get(slot.get("slot_id"), {}).get("critical")
            or contract.get("conflict_policy", {}).get("noncritical_conflict") == "block"
        )
        for slot in slots
    ):
        return "blocked_by_conflict"
    if any(slot.get("state") == "missing" and definitions.get(slot.get("slot_id"), {}).get("acquisition") == "user_input" for slot in slots):
        return "needs_input"
    if any(slot.get("state") != "confirmed" and definitions.get(slot.get("slot_id"), {}).get("critical") for slot in slots):
        return "insufficient_evidence"
    required = {slot["id"] for slot in contract.get("required_slots", [])}
    if all(slot.get("state") == "confirmed" for slot in slots if slot.get("slot_id") in required):
        return "satisfied"
    if contract.get("completion_policy", {}).get("allow_partial") and any(slot.get("state") == "confirmed" for slot in slots):
        return "partially_satisfied"
    return "insufficient_evidence"


def validate_assessment(document: dict[str, Any], contract: dict[str, Any] | None, candidates: dict[str, Any] | None, evidence: dict[str, Any] | None) -> list[str]:
    errors = _boundaries(document, "outcome_assessment")
    if contract is None or candidates is None or evidence is None:
        return errors + ["outcome_assessment:bindings_required"]
    if document.get("contract_digest") != contract.get("digest") or document.get("candidate_set_digest") != candidates.get("digest") or document.get("evidence_set_digest") != evidence.get("digest"):
        errors.append("outcome_assessment:binding_mismatch")
    if document.get("status") != _expected_status(contract, candidates, document):
        errors.append("outcome_assessment:status_mismatch")
    items = {item.get("id"): item for item in evidence.get("items", [])}
    candidate_by_id = {item.get("id"): item for item in candidates.get("candidates", [])}
    for slot in document.get("slots", []):
        if slot.get("state") != "confirmed":
            continue
        for candidate_id in slot.get("candidate_refs", []):
            candidate = candidate_by_id.get(candidate_id)
            if candidate is None:
                errors.append(f"outcome_assessment:unknown_candidate:{candidate_id}")
                continue
            for evidence_id in slot.get("admitted_evidence_refs", []):
                item = items.get(evidence_id)
                if item is None or item.get("authorized") is not True or evidence_id not in candidate.get("evidence_refs", []) or item.get("source_ref") not in candidate.get("source_refs", []):
                    errors.append(f"outcome_assessment:forged_evidence:{evidence_id}")
    critical = {slot["id"] for slot in contract.get("required_slots", []) if slot.get("critical")}
    confirmed = {slot.get("slot_id") for slot in document.get("slots", []) if slot.get("state") == "confirmed"}
    if document.get("status") == "satisfied" and not critical.issubset(confirmed):
        errors.append("outcome_assessment:satisfied_without_critical_slots")
    return errors


def validate_delivery(document: dict[str, Any], assessment: dict[str, Any] | None) -> list[str]:
    errors = _boundaries(document, "outcome_delivery")
    if assessment is None or document.get("assessment_digest") != assessment.get("digest"):
        errors.append("outcome_delivery:assessment_binding_mismatch")
    if assessment is not None and document.get("status") != assessment.get("status"):
        errors.append("outcome_delivery:status_mismatch")
    for fact in document.get("confirmed_facts", []):
        if not fact.get("evidence_refs") or not fact.get("source_refs"):
            errors.append(f"outcome_delivery:fact_without_evidence:{fact.get('slot_id')}")
    return errors


def validate_pilot(document: dict[str, Any]) -> list[str]:
    errors = _boundaries(document, "outcome_pilot")
    if document.get("production_effects") is not False:
        errors.append("outcome_pilot:production_effects_forbidden")
    if any(value != 0 for value in document.get("hard_gate_violations", {}).values()):
        errors.append("outcome_pilot:hard_gate_violation")
    if document.get("metrics", {}).get("status_accuracy") != 1:
        errors.append("outcome_pilot:status_accuracy_failed")
    return errors


def check_outcome(kind: str, document: dict[str, Any], schema: dict[str, Any], *, contract: dict[str, Any] | None = None, candidates: dict[str, Any] | None = None, evidence: dict[str, Any] | None = None, assessment: dict[str, Any] | None = None) -> dict[str, Any]:
    errors = _schema_errors(document, schema)
    if not errors:
        if kind == "contract": errors.extend(validate_contract(document))
        elif kind == "candidate-set": errors.extend(validate_candidates(document, contract))
        elif kind == "assessment": errors.extend(validate_assessment(document, contract, candidates, evidence))
        elif kind == "delivery-plan": errors.extend(validate_delivery(document, assessment))
        elif kind == "pilot-result": errors.extend(validate_pilot(document))
        else: errors.append(f"outcome:unknown_kind:{kind}")
    return {"contract_version": "1.0.0", "implementation": "python_independent", "kind": kind, "status": "passed" if not errors else "failed", "artifact_digest": digest_value(document), "errors": sorted(set(errors)), "canonical_write_performed": False, "effects_executed": False}
