"""Independent semantic checks for Mirai 2.2 Autonomic Fabric artifacts."""

from __future__ import annotations

import fnmatch
import json
import re
from datetime import datetime
from typing import Any

from jsonschema import Draft202012Validator

from .canonical import digest_value


NEVER_AUTOMATIC = {
    "protected_invariant", "authority", "capability", "approval",
    "conflict_resolution", "effectful_program", "history_deletion",
    "autonomy_envelope",
}
ADAPTIVE_CHANGE_KINDS = {
    "source_freshness", "derived_navigation", "reviewed_alias",
    "adaptive_statistic", "effect_free_program",
}
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SAFE_ADAPTIVE_TARGET = re.compile(r"^adaptive/[A-Za-z0-9._:/-]+$")


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


def _safe_adaptive_target(value: Any) -> bool:
    return isinstance(value, str) and SAFE_ADAPTIVE_TARGET.fullmatch(value) is not None and all(
        part not in {".", ".."} for part in value.split("/")
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


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
    if not SAFE_ID.fullmatch(str(document.get("id", ""))) or not str(document.get("scope", "")).strip():
        errors.append("autonomy_envelope:identity_invalid")
    if any(kind in NEVER_AUTOMATIC for kind in document.get("allowed_change_kinds", [])):
        errors.append("autonomy_envelope:protected_kind_allowed")
    if any(kind not in ADAPTIVE_CHANGE_KINDS for kind in document.get("allowed_change_kinds", [])):
        errors.append("autonomy_envelope:unknown_change_kind")
    if not document.get("approver_signatures"):
        errors.append("autonomy_envelope:signature_required")
    if document.get("rollback_contract", {}).get("required") is not True or document.get("rollback_contract", {}).get("verify_readback") is not True:
        errors.append("autonomy_envelope:rollback_required")
    if any(not str(pattern).startswith("adaptive/") for pattern in document.get("resource_patterns", [])):
        errors.append("autonomy_envelope:resource_outside_adaptive_stratum")
    budget = document.get("change_budget", {})
    if not isinstance(budget.get("max_changes"), int) or budget.get("max_changes", 0) < 1:
        errors.append("autonomy_envelope:change_count_budget_invalid")
    if not isinstance(budget.get("max_payload_bytes"), int) or budget.get("max_payload_bytes", 0) < 1:
        errors.append("autonomy_envelope:payload_budget_invalid")
    issued = _parse_time(document.get("issued_at"))
    expires = _parse_time(document.get("expires_at"))
    if issued is None or expires is None or issued >= expires:
        errors.append("autonomy_envelope:lifetime_invalid")
    return errors


def validate_evolution_proposal(document: dict[str, Any]) -> list[str]:
    errors = _boundary(document, "evolution_proposal") + _digest_errors(document, "evolution_proposal")
    if not SAFE_ID.fullmatch(str(document.get("id", ""))) or not str(document.get("scope", "")).strip():
        errors.append("evolution_proposal:identity_invalid")
    seen: set[str] = set()
    for change in document.get("changes", []):
        change_id = str(change.get("id", ""))
        if not SAFE_ID.fullmatch(change_id) or change_id in seen:
            errors.append(f"evolution_proposal:change_identity_invalid:{change_id or 'missing'}")
        seen.add(change_id)
        if not _safe_adaptive_target(change.get("target_ref")):
            errors.append(f"evolution_proposal:target_invalid:{change_id}")
        if digest_value(change.get("payload")) != change.get("payload_digest"):
            errors.append(f"evolution_proposal:payload_digest_mismatch:{change_id}")
    return errors


def _change_decision(change: dict[str, Any], envelope: dict[str, Any], proposal: dict[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    kind = change.get("kind")
    target = str(change.get("target_ref", ""))
    if kind in NEVER_AUTOMATIC:
        reasons.append("change_kind_never_automatic")
    if change.get("stratum") != "adaptive_canonical":
        reasons.append("change_outside_adaptive_stratum")
    if kind not in envelope.get("allowed_change_kinds", []):
        reasons.append("change_kind_not_allowed")
    if change.get("risk") in {"high", "critical"} or RISK_ORDER.get(str(change.get("risk")), 99) > RISK_ORDER.get(str(envelope.get("risk_ceiling")), -1):
        reasons.append("risk_ceiling_exceeded")
    confidence = change.get("confidence")
    if not isinstance(confidence, (int, float)) or confidence < envelope.get("confidence_floor", 1):
        reasons.append("confidence_below_floor")
    if change.get("reversible") is not True:
        reasons.append("change_not_reversible")
    if change.get("effectful") is True:
        reasons.append("effectful_change_requires_approval")
    if change.get("conflict_refs"):
        reasons.append("conflict_resolution_requires_review")
    if proposal.get("scope") != envelope.get("scope"):
        reasons.append("autonomy_scope_mismatch")
    if not _safe_adaptive_target(target) or not any(fnmatch.fnmatchcase(target, pattern) for pattern in envelope.get("resource_patterns", [])):
        reasons.append("resource_outside_envelope")
    if any(fnmatch.fnmatchcase(target, pattern) for pattern in envelope.get("forbidden_targets", [])):
        reasons.append("target_explicitly_forbidden")
    if not _safe_adaptive_target(target):
        reasons.append("adaptive_target_prefix_required")
    for evidence in envelope.get("evidence_requirements", []):
        if evidence not in change.get("evidence_refs", []):
            reasons.append(f"required_evidence_missing:{evidence}")
    replay = envelope.get("replay_requirements", {})
    if kind in replay.get("required_for", []) and len(change.get("successful_replay_refs", [])) < replay.get("minimum_successful_replays", 0):
        reasons.append("successful_replay_requirement_missing")
    deny_markers = ("never_automatic", "outside_adaptive", "effectful", "conflict", "explicitly_forbidden", "target_prefix")
    verdict = "allow_automatic" if not reasons else "deny" if any(marker in reason for reason in reasons for marker in deny_markers) else "manual_review"
    return verdict, sorted(set(reasons))


def validate_evolution_decision(document: dict[str, Any], proposal: dict[str, Any] | None, envelope: dict[str, Any] | None) -> list[str]:
    errors = _boundary(document, "evolution_decision") + _digest_errors(document, "evolution_decision")
    if proposal is None or envelope is None:
        return errors + ["evolution_decision:proposal_and_envelope_required"]
    errors.extend(validate_evolution_proposal(proposal))
    errors.extend(validate_autonomy_envelope(envelope))
    if document.get("proposal_id") != proposal.get("id") or document.get("envelope_id") != envelope.get("id"):
        errors.append("evolution_decision:identity_binding_mismatch")
    if document.get("proposal_digest") != proposal.get("digest") or document.get("envelope_digest") != envelope.get("digest"):
        errors.append("evolution_decision:binding_mismatch")
    evaluated = _parse_time(document.get("evaluated_at"))
    issued = _parse_time(envelope.get("issued_at"))
    expires = _parse_time(envelope.get("expires_at"))
    if evaluated is None or issued is None or expires is None or evaluated < issued or evaluated >= expires:
        errors.append("evolution_decision:envelope_not_active")
    decision_items = document.get("change_decisions", [])
    decisions = {item.get("change_id"): item for item in decision_items}
    if len(decisions) != len(decision_items):
        errors.append("evolution_decision:duplicate_change_decision")
    proposal_ids = {item.get("id") for item in proposal.get("changes", [])}
    if set(decisions) - proposal_ids:
        errors.append("evolution_decision:unknown_change_decision")
    budget = envelope.get("change_budget", {})
    payload_bytes = len(json.dumps([item.get("payload") for item in proposal.get("changes", [])], ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    budget_exceeded = len(proposal.get("changes", [])) > budget.get("max_changes", 0) or payload_bytes > budget.get("max_payload_bytes", 0)
    for change in proposal.get("changes", []):
        decision = decisions.get(change.get("id"))
        if decision is None:
            errors.append(f"evolution_decision:change_missing:{change.get('id')}")
            continue
        expected_verdict, expected_reasons = _change_decision(change, envelope, proposal)
        if budget_exceeded:
            expected_verdict = "deny"
            expected_reasons = sorted(set(expected_reasons + [
                "change_count_budget_exceeded" if len(proposal.get("changes", [])) > budget.get("max_changes", 0) else "",
                "change_payload_budget_exceeded" if payload_bytes > budget.get("max_payload_bytes", 0) else "",
            ]) - {""})
        if decision.get("verdict") != expected_verdict or sorted(set(decision.get("reason_codes", []))) != expected_reasons:
            errors.append(f"evolution_decision:decision_mismatch:{change.get('id')}")
    expected_global = "denied" if budget_exceeded or any(item.get("verdict") == "deny" for item in decisions.values()) else "manual_review_required" if any(item.get("verdict") == "manual_review" for item in decisions.values()) else "automatic_promotion_allowed"
    if document.get("verdict") != expected_global:
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
