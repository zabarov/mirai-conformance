"""Independent semantic checks for Mirai 2.4 Retrieval Fabric artifacts."""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .canonical import digest_value


def _schema_errors(document: Any, schema: dict[str, Any]) -> list[str]:
    return sorted(
        f"schema:{'/'.join(str(part) for part in error.absolute_path) or '/'}:{error.message}"
        for error in Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document)
    )


def _digest(document: dict[str, Any], *, omit: set[str] | None = None) -> str:
    omitted = {"digest"} | (omit or set())
    return digest_value({key: value for key, value in document.items() if key not in omitted})


def validate_descriptor(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("retrieval_descriptor:canonical_write_must_be_false")
    if _digest(document, omit={"built_at"}) != document.get("digest"):
        errors.append("retrieval_descriptor:digest_mismatch")
    if document.get("semantic_status") == "ready":
        required = ("semantic_model", "semantic_revision", "semantic_files_digest", "dimensions")
        if any(not document.get(field) for field in required):
            errors.append("retrieval_descriptor:semantic_binding_missing")
    return errors


def validate_plan(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("retrieval_plan:canonical_write_must_be_false")
    if _digest(document) != document.get("digest"):
        errors.append("retrieval_plan:digest_mismatch")
    if document.get("semantic_status") != "ready" and "semantic" in document.get("channels", []):
        errors.append("retrieval_plan:silent_semantic_fallback")
    if len(document.get("channels", [])) != len(set(document.get("channels", []))):
        errors.append("retrieval_plan:duplicate_channel")
    return errors


def validate_evidence(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("retrieval_evidence:canonical_write_must_be_false")
    if document.get("instructions_authorized") is not False:
        errors.append("retrieval_evidence:instructions_must_be_untrusted")
    if _digest(document) != document.get("digest"):
        errors.append("retrieval_evidence:digest_mismatch")
    for hit in document.get("hits", []):
        if not hit.get("source_ref") or not hit.get("evidence_refs"):
            errors.append(f"retrieval_evidence:unbound_hit:{hit.get('document_id')}")
    if document.get("conflicts") and not document.get("partial"):
        errors.append("retrieval_evidence:conflict_not_marked_partial")
    return errors


def validate_answer(document: dict[str, Any], evidence: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False or document.get("execution_allowed") is not False:
        errors.append("retrieval_answer:authority_boundary_broken")
    if document.get("content_is_untrusted_data") is not True:
        errors.append("retrieval_answer:content_trust_boundary_missing")
    if _digest(document) != document.get("digest"):
        errors.append("retrieval_answer:digest_mismatch")
    for index, claim in enumerate(document.get("claims", [])):
        if not claim.get("evidence_refs") or not claim.get("source_refs"):
            errors.append(f"retrieval_answer:claim_without_evidence:{index}")
    if document.get("status") in {"clarification_required", "insufficient_evidence"} and document.get("claims"):
        errors.append("retrieval_answer:unsupported_claims")
    if evidence is not None:
        if document.get("evidence_bundle_digest") != evidence.get("digest"):
            errors.append("retrieval_answer:evidence_binding_mismatch")
        evidence_refs = {ref for hit in evidence.get("hits", []) for ref in hit.get("evidence_refs", [])}
        for index, claim in enumerate(document.get("claims", [])):
            if not set(claim.get("evidence_refs", [])).issubset(evidence_refs):
                errors.append(f"retrieval_answer:unknown_evidence_ref:{index}")
    return errors


def validate_federated_envelope(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("federated_query:canonical_write_must_be_false")
    visited = document.get("visited_graph_ids", [])
    if len(visited) != len(set(visited)):
        errors.append("federated_query:route_cycle")
    if len(visited) > document.get("max_hops", 0):
        errors.append("federated_query:hop_budget_exceeded")
    if document.get("max_fan_out", 0) < 1 or document.get("max_hops", 0) < 1:
        errors.append("federated_query:invalid_budget")
    return errors


def validate_federated_result(document: dict[str, Any], envelope: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("federated_result:canonical_write_must_be_false")
    if document.get("instructions_authorized") is not False:
        errors.append("federated_result:instructions_must_be_untrusted")
    if _digest(document) != document.get("digest"):
        errors.append("federated_result:digest_mismatch")
    evidence = document.get("evidence_bundle", {})
    errors.extend(validate_evidence(evidence))
    if document.get("query_digest") != evidence.get("query_digest") or document.get("policy_digest") != evidence.get("policy_digest"):
        errors.append("federated_result:evidence_binding_mismatch")
    if envelope is not None and document.get("query_id") != envelope.get("id"):
        errors.append("federated_result:query_id_mismatch")
    return errors


def validate_evaluation(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if _digest(document) != document.get("digest"):
        errors.append("retrieval_evaluation:digest_mismatch")
    if not document.get("limitations"):
        errors.append("retrieval_evaluation:limitations_required")
    return errors


VALIDATORS = {
    "index-descriptor": validate_descriptor,
    "plan": validate_plan,
    "evidence-bundle": validate_evidence,
    "federated-envelope": validate_federated_envelope,
    "evaluation": validate_evaluation,
}


def check_retrieval(kind: str, document: dict[str, Any], schema: dict[str, Any], *, evidence: dict[str, Any] | None = None, envelope: dict[str, Any] | None = None) -> dict[str, Any]:
    errors = _schema_errors(document, schema)
    if not errors:
        if kind == "answer":
            errors.extend(validate_answer(document, evidence))
        elif kind == "federated-result":
            errors.extend(validate_federated_result(document, envelope))
        elif kind in VALIDATORS:
            errors.extend(VALIDATORS[kind](document))
        else:
            errors.append(f"retrieval:unknown_kind:{kind}")
    return {
        "contract_version": "1.0.0", "implementation": "python_independent", "kind": kind,
        "status": "passed" if not errors else "failed", "artifact_digest": digest_value(document),
        "errors": sorted(set(errors)), "canonical_write_performed": False, "effects_executed": False,
    }
