"""Independent semantic checks for Mirai 2.5 Outcome Completion."""

from __future__ import annotations

import math
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .canonical import canonical_json, digest_value


_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_AUTHORITIES = {"proposal": 0, "derived": 1, "informational": 2, "supporting": 3, "owner_asserted": 4, "canonical": 5, "canonical_external": 6}
_FRESHNESS = {"unknown": 0, "stale": 1, "aging": 2, "current": 3}
_REQUIRED_FRESHNESS = {"allow_stale": 1, "allow_aging": 2, "current": 3}
_CHILD_STATUS_PRECEDENCE = ("out_of_scope", "failed", "temporarily_unavailable", "handoff_required", "blocked_by_conflict", "needs_input", "insufficient_evidence")


def _schema_errors(document: Any, schema: dict[str, Any]) -> list[str]:
    return sorted(
        f"schema:{'/'.join(str(part) for part in error.absolute_path) or '/'}:{error.message}"
        for error in Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document)
    )


def _digest(document: dict[str, Any]) -> str:
    return digest_value({key: value for key, value in document.items() if key != "digest"})


def _seal(document: dict[str, Any]) -> dict[str, Any]:
    return {**document, "digest": digest_value(document)}


def _unique(values: list[str]) -> list[str]:
    return sorted(set(values))


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
    if any(slot.get("critical") is True and slot.get("evidence_required") is not True for slot in slots):
        errors.append("outcome_contract:critical_slot_requires_evidence")
    return errors


def validate_candidates(document: dict[str, Any], contract: dict[str, Any] | None) -> list[str]:
    errors = _boundaries(document, "outcome_candidates")
    if document.get("accepted") is not False or document.get("content_is_untrusted_data") is not True:
        errors.append("outcome_candidates:trust_boundary_broken")
    if contract is not None and document.get("contract_digest") != contract.get("digest"):
        errors.append("outcome_candidates:contract_binding_mismatch")
    return errors


def validate_evidence(document: dict[str, Any], contract: dict[str, Any] | None = None) -> list[str]:
    errors = _boundaries(document, "outcome_evidence")
    if not _DIGEST.fullmatch(str(document.get("snapshot_digest", ""))) or not _DIGEST.fullmatch(str(document.get("policy_digest", ""))):
        errors.append("outcome_evidence:set_binding_invalid")
    items = document.get("items")
    if not isinstance(items, list):
        return errors + ["outcome_evidence:items_invalid"]
    ids = [item.get("id") for item in items if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        errors.append("outcome_evidence:duplicate_item_id")
    for index, item in enumerate(items):
        prefix = f"outcome_evidence:item:{index}"
        if not isinstance(item, dict):
            errors.append(f"{prefix}:invalid")
            continue
        digest_fields = ("contract_digest", "value_digest", "admission_receipt_digest", "digest")
        if any(not _DIGEST.fullmatch(str(item.get(field, ""))) for field in digest_fields):
            errors.append(f"{prefix}:binding_invalid")
        if item.get("digest") != _digest(item):
            errors.append(f"{prefix}:digest_mismatch")
        if contract is not None and item.get("contract_digest") != contract.get("digest"):
            errors.append(f"{prefix}:contract_binding_mismatch")
        if not item.get("slot_id") or not item.get("source_ref"):
            errors.append(f"{prefix}:identity_invalid")
        if item.get("authority") not in _AUTHORITIES or item.get("freshness") not in _FRESHNESS:
            errors.append(f"{prefix}:classification_invalid")
        if not isinstance(item.get("conflict_refs"), list) or not isinstance(item.get("authorized"), bool):
            errors.append(f"{prefix}:state_invalid")
    return errors


def _valid_value(value_type: str, value: Any) -> bool:
    if value_type == "boolean":
        return isinstance(value, bool)
    if value_type in {"string", "identifier", "reference", "timestamp", "duration"}:
        return isinstance(value, str) and bool(value)
    if value_type == "int64":
        return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 2**53 - 1
    if value_type == "decimal":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if value_type == "list":
        return isinstance(value, list)
    if value_type in {"record", "map"}:
        return isinstance(value, dict) and bool(value)
    return False


def _empty_slot(slot_id: str, state: str, reasons: list[str], candidate_refs: list[str] | None = None, source_refs: list[str] | None = None) -> dict[str, Any]:
    return {"slot_id": slot_id, "state": state, "candidate_refs": candidate_refs or [], "admitted_evidence_refs": [], "source_refs": source_refs or [], "reasons": reasons, "content_is_untrusted_data": True}


def _assess_slot(contract: dict[str, Any], slot: dict[str, Any], candidates: dict[str, Any], evidence: dict[str, Any], admitted_receipts: set[str]) -> dict[str, Any]:
    matches = sorted((item for item in candidates.get("candidates", []) if item.get("slot_id") == slot.get("id")), key=lambda item: item.get("id", ""))
    if not matches:
        reason = "user_input_required" if slot.get("acquisition") == "user_input" else "candidate_missing"
        return _empty_slot(slot["id"], "missing", [reason])
    valid = [item for item in matches if _valid_value(slot.get("value_type", ""), item.get("value"))]
    if not valid:
        return _empty_slot(slot["id"], "invalid", ["candidate_value_type_invalid"], [item["id"] for item in matches])
    selected = valid[0]
    value_digest = digest_value(selected.get("value"))
    matching = [
        item for item in evidence.get("items", [])
        if item.get("id") in selected.get("evidence_refs", [])
        and item.get("source_ref") in selected.get("source_refs", [])
        and item.get("contract_digest") == contract.get("digest")
        and item.get("slot_id") == slot.get("id")
        and item.get("value_digest") == value_digest
        and _DIGEST.fullmatch(str(item.get("admission_receipt_digest", "")))
        and item.get("digest") == _digest(item)
        and item.get("admission_receipt_digest") in admitted_receipts
    ]
    authorized = [item for item in matching if item.get("authorized") is True]
    if slot.get("evidence_required") and not matching:
        return _empty_slot(slot["id"], "unsupported", ["evidence_binding_not_admitted"], [selected["id"]], selected.get("source_refs", []))
    if slot.get("evidence_required") and not authorized:
        return _empty_slot(slot["id"], "unauthorized", ["evidence_not_authorized"], [selected["id"]], selected.get("source_refs", []))
    admissible = authorized if slot.get("evidence_required") else (authorized or matching)

    def assessed(state: str, reasons: list[str]) -> dict[str, Any]:
        return {"slot_id": slot["id"], "state": state, "candidate_refs": [selected["id"]], "admitted_evidence_refs": [item["id"] for item in admissible], "source_refs": [item["source_ref"] for item in admissible], "reasons": reasons, "content_is_untrusted_data": True}

    if slot.get("evidence_required") and not any(_AUTHORITIES.get(item.get("authority"), -1) >= _AUTHORITIES.get(slot.get("minimum_authority"), 99) for item in admissible):
        return assessed("unsupported", ["authority_below_requirement"])
    if any(item.get("conflict_refs") for item in admissible):
        return assessed("conflicting", ["admitted_evidence_conflict"])
    if slot.get("evidence_required") and not any(_FRESHNESS.get(item.get("freshness"), -1) >= _REQUIRED_FRESHNESS.get(slot.get("freshness_required"), 99) for item in admissible):
        return assessed("stale", ["freshness_below_requirement"])
    if len({canonical_json(item.get("value")) for item in valid}) > 1:
        return {**assessed("conflicting", ["candidate_values_conflict"]), "candidate_refs": [item["id"] for item in valid]}
    return {"slot_id": slot["id"], "state": "confirmed", "value": selected.get("value"), "candidate_refs": [item["id"] for item in valid], "admitted_evidence_refs": _unique([item["id"] for item in admissible]), "source_refs": _unique([item["source_ref"] for item in admissible]), "reasons": [], "content_is_untrusted_data": True}


def _expected_status(contract: dict[str, Any], context: dict[str, Any], slots: list[dict[str, Any]]) -> str:
    scope = contract.get("scope", {})
    if context.get("purpose") != scope.get("purpose") or any(domain not in scope.get("domains", []) for domain in context.get("domains", [])):
        return "out_of_scope"
    if context.get("availability") == "failed":
        return "failed"
    if context.get("availability") == "temporarily_unavailable":
        return "temporarily_unavailable"
    if context.get("handoff_required") is True:
        return "handoff_required"
    definitions = {slot["id"]: slot for slot in contract.get("required_slots", []) + contract.get("optional_slots", [])}
    if any(slot.get("state") == "conflicting" and (definitions.get(slot.get("slot_id"), {}).get("critical") or contract.get("conflict_policy", {}).get("noncritical_conflict") == "block") for slot in slots):
        return "blocked_by_conflict"
    if any(slot.get("state") == "missing" and definitions.get(slot.get("slot_id"), {}).get("acquisition") == "user_input" for slot in slots):
        return "needs_input"
    if any(slot.get("state") != "confirmed" and definitions.get(slot.get("slot_id"), {}).get("critical") for slot in slots):
        return "insufficient_evidence"
    required_ids = {slot["id"] for slot in contract.get("required_slots", [])}
    required = [slot for slot in slots if slot.get("slot_id") in required_ids]
    if all(slot.get("state") == "confirmed" for slot in required):
        return "satisfied"
    if contract.get("completion_policy", {}).get("allow_partial") and any(slot.get("state") == "confirmed" for slot in slots):
        return "partially_satisfied"
    return "insufficient_evidence"


def _next_action(status: str) -> str:
    return "prepare_delivery" if status == "satisfied" else "deliver_confirmed_part_and_disclose_gaps" if status == "partially_satisfied" else "ask_clarifying_question" if status == "needs_input" else "handoff_with_confirmed_slots" if status == "handoff_required" else "do_not_claim_completion"


def _coverage(confirmed: int, total: int) -> int | float:
    value = confirmed / total if total else 1
    return int(value) if value in {0.0, 1.0} else value


def _assessment_body(contract: dict[str, Any], candidates: dict[str, Any], evidence: dict[str, Any], admitted_receipts: set[str]) -> dict[str, Any]:
    definitions = contract.get("required_slots", []) + contract.get("optional_slots", [])
    slots = [_assess_slot(contract, slot, candidates, evidence, admitted_receipts) for slot in definitions]
    status = _expected_status(contract, candidates.get("context", {}), slots)
    by_state = lambda state: [slot["slot_id"] for slot in slots if slot.get("state") == state]
    required_ids = {slot["id"] for slot in contract.get("required_slots", [])}
    required = [slot for slot in slots if slot["slot_id"] in required_ids]
    question = next((slot for slot in slots if slot.get("state") == "missing" and next((item for item in definitions if item["id"] == slot["slot_id"]), {}).get("acquisition") == "user_input"), None)
    body: dict[str, Any] = {"contract_version": "1.0.0", "id": f"assessment.{contract['id']}.{candidates['id']}", "contract_digest": contract["digest"]}
    if contract.get("parent_contract_digest"):
        body["parent_contract_digest"] = contract["parent_contract_digest"]
    body.update({"candidate_set_digest": candidates["digest"], "evidence_set_digest": evidence["digest"], "slots": slots, "missing_slots": by_state("missing"), "stale_slots": by_state("stale"), "conflicting_slots": by_state("conflicting"), "unsupported_slots": _unique(by_state("unsupported") + by_state("invalid")), "unauthorized_slots": by_state("unauthorized"), "evidence_coverage": _coverage(sum(slot.get("state") == "confirmed" for slot in required), len(required)), "status": status, "clarifying_question": f"Please provide {question['slot_id']}." if status == "needs_input" and question else None, "next_safe_action": _next_action(status), "limitations": _unique(evidence.get("limitations", [])), "execution_allowed": False, "canonical_write_allowed": False})
    return body


def _recompute_assessment(contract: dict[str, Any], candidates: dict[str, Any], evidence: dict[str, Any], admitted_receipts: set[str]) -> dict[str, Any]:
    return _seal(_assessment_body(contract, candidates, evidence, admitted_receipts))


def validate_assessment(document: dict[str, Any], contract: dict[str, Any] | None, candidates: dict[str, Any] | None, evidence: dict[str, Any] | None, admission_policy_digest: str | None, admitted_receipts: set[str]) -> list[str]:
    errors = _boundaries(document, "outcome_assessment")
    if contract is None or candidates is None or evidence is None or admission_policy_digest is None:
        return errors + ["outcome_assessment:bindings_required"]
    errors.extend(validate_contract(contract))
    errors.extend(validate_candidates(candidates, contract))
    errors.extend(validate_evidence(evidence, contract))
    if evidence.get("policy_digest") != admission_policy_digest:
        errors.append("outcome_assessment:admission_policy_mismatch")
    if not admitted_receipts:
        errors.append("outcome_assessment:admission_receipts_required")
    if any(slot.get("content_is_untrusted_data") is not True for slot in document.get("slots", [])):
        errors.append("outcome_assessment:trust_boundary_broken")
    if document != _recompute_assessment(contract, candidates, evidence, admitted_receipts):
        errors.append("outcome_assessment:semantic_mismatch")
    return errors


def _aggregate_body(contract: dict[str, Any], assessments: list[dict[str, Any]]) -> dict[str, Any]:
    definitions = contract.get("required_slots", []) + contract.get("optional_slots", [])
    severity = ("conflicting", "unauthorized", "stale", "unsupported", "invalid", "missing")
    slots: list[dict[str, Any]] = []
    for definition in definitions:
        children = [slot for assessment in assessments for slot in assessment.get("slots", []) if slot.get("slot_id") == definition.get("id")]
        confirmed = [slot for slot in children if slot.get("state") == "confirmed"]
        values = {canonical_json(slot.get("value")) for slot in confirmed}
        common = {"slot_id": definition["id"], "candidate_refs": _unique([ref for slot in children for ref in slot.get("candidate_refs", [])]), "admitted_evidence_refs": _unique([ref for slot in children for ref in slot.get("admitted_evidence_refs", [])]), "source_refs": _unique([ref for slot in children for ref in slot.get("source_refs", [])]), "content_is_untrusted_data": True}
        if len(values) > 1 or any(slot.get("state") == "conflicting" for slot in children):
            slots.append({**common, "state": "conflicting", "reasons": _unique(["child_assessments_conflict"] + [reason for slot in children for reason in slot.get("reasons", [])])})
        elif confirmed:
            slots.append({**common, "state": "confirmed", "value": confirmed[0].get("value"), "reasons": []})
        else:
            state = next((value for value in severity if any(slot.get("state") == value for slot in children)), "missing")
            reasons = [reason for slot in children for reason in slot.get("reasons", [])]
            slots.append({**common, "state": state, "reasons": _unique(reasons or (["child_slot_missing"] if not children else []))})
    statuses = {assessment.get("status") for assessment in assessments}
    availability = "failed" if "failed" in statuses else "temporarily_unavailable" if "temporarily_unavailable" in statuses else "available"
    context = {"purpose": contract.get("scope", {}).get("purpose"), "domains": contract.get("scope", {}).get("domains", []), "availability": availability, "handoff_required": "handoff_required" in statuses}
    status = _expected_status(contract, context, slots)
    status = next((item for item in _CHILD_STATUS_PRECEDENCE if item in statuses), status)
    if "partially_satisfied" in statuses and status == "satisfied":
        status = "partially_satisfied" if contract.get("completion_policy", {}).get("allow_partial") else "insufficient_evidence"
    by_state = lambda state: [slot["slot_id"] for slot in slots if slot.get("state") == state]
    required_ids = {slot["id"] for slot in contract.get("required_slots", [])}
    required = [slot for slot in slots if slot["slot_id"] in required_ids]
    question = next((slot for slot in slots if slot.get("state") == "missing" and next((item for item in definitions if item["id"] == slot["slot_id"]), {}).get("acquisition") == "user_input"), None)
    body: dict[str, Any] = {"contract_version": "1.0.0", "id": f"assessment.aggregate.{contract['id']}", "contract_digest": contract["digest"]}
    if contract.get("parent_contract_digest"):
        body["parent_contract_digest"] = contract["parent_contract_digest"]
    body.update({"candidate_set_digest": digest_value([item["candidate_set_digest"] for item in assessments]), "evidence_set_digest": digest_value([item["evidence_set_digest"] for item in assessments]), "slots": slots, "missing_slots": by_state("missing"), "stale_slots": by_state("stale"), "conflicting_slots": by_state("conflicting"), "unsupported_slots": _unique(by_state("unsupported") + by_state("invalid")), "unauthorized_slots": by_state("unauthorized"), "evidence_coverage": _coverage(sum(slot.get("state") == "confirmed" for slot in required), len(required)), "status": status, "clarifying_question": f"Please provide {question['slot_id']}." if status == "needs_input" and question else None, "next_safe_action": _next_action(status), "limitations": _unique([value for item in assessments for value in item.get("limitations", [])]), "execution_allowed": False, "canonical_write_allowed": False})
    return body


def _child_preserves_parent(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    parent_scope, child_scope = parent.get("scope", {}), child.get("scope", {})
    if child_scope.get("purpose") != parent_scope.get("purpose"):
        return False
    if any(domain not in parent_scope.get("domains", []) for domain in child_scope.get("domains", [])):
        return False
    if parent_scope.get("effect") == "read_only" and child_scope.get("effect") != "read_only":
        return False
    if parent.get("conflict_policy", {}).get("noncritical_conflict") == "block" and child.get("conflict_policy", {}).get("noncritical_conflict") != "block":
        return False
    child_slots = {slot.get("id"): slot for slot in child.get("required_slots", []) + child.get("optional_slots", [])}
    for parent_slot in parent.get("required_slots", []) + parent.get("optional_slots", []):
        child_slot = child_slots.get(parent_slot.get("id"))
        if child_slot is None:
            continue
        if child_slot.get("value_type") != parent_slot.get("value_type"):
            return False
        if parent_slot.get("critical") and not child_slot.get("critical"):
            return False
        if parent_slot.get("evidence_required") and not child_slot.get("evidence_required"):
            return False
        if _AUTHORITIES.get(child_slot.get("minimum_authority"), -1) < _AUTHORITIES.get(parent_slot.get("minimum_authority"), 99):
            return False
        if _REQUIRED_FRESHNESS.get(child_slot.get("freshness_required"), -1) < _REQUIRED_FRESHNESS.get(parent_slot.get("freshness_required"), 99):
            return False
    return True


def validate_aggregate(document: dict[str, Any], contract: dict[str, Any] | None, child_bundles: list[dict[str, Any]] | None, admission_policy_digest: str | None, admitted_receipts: set[str]) -> list[str]:
    errors = _boundaries(document, "outcome_aggregate")
    if contract is None or not child_bundles or admission_policy_digest is None or not admitted_receipts:
        return errors + ["outcome_aggregate:bindings_required"]
    errors.extend(validate_contract(contract))
    assessments: list[dict[str, Any]] = []
    for index, bundle in enumerate(child_bundles):
        prefix = f"outcome_aggregate:child:{index}"
        if not isinstance(bundle, dict) or not all(isinstance(bundle.get(key), dict) for key in ("contract", "candidates", "evidence", "assessment")):
            errors.append(f"{prefix}:bundle_invalid")
            continue
        child_contract, candidates, evidence, assessment = (bundle[key] for key in ("contract", "candidates", "evidence", "assessment"))
        child_errors = validate_contract(child_contract) + validate_candidates(candidates, child_contract) + validate_evidence(evidence, child_contract)
        if child_contract.get("digest") != contract.get("digest") and child_contract.get("parent_contract_digest") != contract.get("digest"):
            child_errors.append("parent_binding_mismatch")
        if not _child_preserves_parent(contract, child_contract):
            child_errors.append("child_policy_weakened")
        if evidence.get("policy_digest") != admission_policy_digest:
            child_errors.append("admission_policy_mismatch")
        recomputed = _recompute_assessment(child_contract, candidates, evidence, admitted_receipts)
        if assessment != recomputed:
            child_errors.append("assessment_semantic_mismatch")
        if any(slot.get("content_is_untrusted_data") is not True for slot in assessment.get("slots", [])):
            child_errors.append("assessment_trust_boundary_broken")
        if child_errors:
            errors.extend(f"{prefix}:{error}" for error in child_errors)
        else:
            assessments.append(recomputed)
    if len(assessments) != len(child_bundles):
        return errors
    if document != _seal(_aggregate_body(contract, assessments)):
        errors.append("outcome_aggregate:semantic_mismatch")
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
        if fact.get("content_is_untrusted_data") is not True:
            errors.append(f"outcome_delivery:trust_boundary_broken:{fact.get('slot_id')}")
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


def check_outcome(kind: str, document: dict[str, Any], schema: dict[str, Any], *, contract: dict[str, Any] | None = None, candidates: dict[str, Any] | None = None, evidence: dict[str, Any] | None = None, assessment: dict[str, Any] | None = None, child_bundles: list[dict[str, Any]] | None = None, admission_policy_digest: str | None = None, admitted_receipts: set[str] | None = None) -> dict[str, Any]:
    admitted_receipts = admitted_receipts or set()
    errors = _schema_errors(document, schema)
    if not errors:
        if kind == "contract": errors.extend(validate_contract(document))
        elif kind == "candidate-set": errors.extend(validate_candidates(document, contract))
        elif kind == "evidence-set": errors.extend(validate_evidence(document, contract))
        elif kind == "assessment": errors.extend(validate_assessment(document, contract, candidates, evidence, admission_policy_digest, admitted_receipts))
        elif kind == "aggregate-assessment": errors.extend(validate_aggregate(document, contract, child_bundles, admission_policy_digest, admitted_receipts))
        elif kind == "delivery-plan":
            errors.extend(validate_delivery(document, assessment))
            if assessment is not None:
                errors.extend(validate_assessment(assessment, contract, candidates, evidence, admission_policy_digest, admitted_receipts))
        elif kind == "pilot-result": errors.extend(validate_pilot(document))
        else: errors.append(f"outcome:unknown_kind:{kind}")
    return {"contract_version": "1.0.0", "implementation": "python_independent", "kind": kind, "status": "passed" if not errors else "failed", "artifact_digest": digest_value(document), "errors": sorted(set(errors)), "canonical_write_performed": False, "effects_executed": False}
