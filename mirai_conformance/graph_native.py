"""Independent semantic checks for Mirai 2.1 graph-native artifacts."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from jsonschema import Draft202012Validator

from .canonical import canonical_json, digest_value


def _schema_errors(document: Any, schema: dict[str, Any]) -> list[str]:
    return sorted(
        f"schema:{'/'.join(str(part) for part in error.absolute_path) or '/'}:{error.message}"
        for error in Draft202012Validator(schema).iter_errors(document)
    )


def _without_digest(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "digest"}


def _duplicate_ids(items: list[dict[str, Any]], label: str) -> list[str]:
    counts: dict[str, int] = defaultdict(int)
    for item in items:
        counts[str(item.get("id"))] += 1
    return [f"{label}:duplicate_id:{item}" for item, count in sorted(counts.items()) if count > 1]


def _frontiers(plan: dict[str, Any], errors: list[str]) -> list[list[str]]:
    paths = {item.get("id") for item in plan.get("activated_paths", [])}
    edges = plan.get("dependency_dag", [])
    for edge in edges:
        if edge.get("from") not in paths or edge.get("to") not in paths:
            errors.append(f"activation:unknown_dependency:{edge.get('from')}:{edge.get('to')}")
    remaining = set(paths)
    completed: set[str] = set()
    result: list[list[str]] = []
    while remaining:
        frontier = sorted(
            node for node in remaining
            if all(edge.get("from") in completed for edge in edges if edge.get("to") == node)
        )
        if not frontier:
            errors.append("activation:dependency_cycle")
            break
        result.append(frontier)
        completed.update(frontier)
        remaining.difference_update(frontier)
    return result


def validate_source_catalog(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("source_catalog:canonical_write_must_be_false")
    if document.get("policies", {}).get("include_secrets") is not False:
        errors.append("source_catalog:secrets_must_be_excluded")
    if digest_value(_without_digest(document)) != document.get("digest"):
        errors.append("source_catalog:digest_mismatch")
    errors.extend(_duplicate_ids(document.get("items", []), "source_catalog"))
    return errors


def validate_assimilation_proposal(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("assimilation:canonical_write_must_be_false")
    if digest_value(_without_digest(document)) != document.get("digest"):
        errors.append("assimilation:digest_mismatch")
    if any(item.get("resolution") != "owner_review_required" for item in document.get("conflicts", [])):
        errors.append("assimilation:conflict_without_owner_review")
    blocking = sum(1 for item in document.get("diagnostics", []) if item.get("severity") == "blocking")
    if document.get("quality", {}).get("blocking_diagnostic_count") != blocking:
        errors.append("assimilation:blocking_count_mismatch")
    if blocking and document.get("quality", {}).get("readiness") != "blocked":
        errors.append("assimilation:blocking_conflict_marked_ready")
    return errors


def validate_component_package(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("components:canonical_write_must_be_false")
    collections = ["interfaces", "operation_contracts", "component_types", "component_instances", "program_implementations", "contextual_bindings"]
    for collection in collections:
        errors.extend(_duplicate_ids(document.get(collection, []), f"components:{collection}"))
    operations = {item.get("id") for item in document.get("operation_contracts", [])}
    component_types = {item.get("id"): item for item in document.get("component_types", [])}
    implementations = {item.get("id"): item for item in document.get("program_implementations", [])}
    for instance in document.get("component_instances", []):
        if instance.get("instance_of") not in component_types:
            errors.append(f"components:unknown_instance_type:{instance.get('id')}")
    groups: dict[str, list[str]] = defaultdict(list)
    for binding in document.get("contextual_bindings", []):
        component = component_types.get(binding.get("component_type"))
        implementation = implementations.get(binding.get("implementation"))
        if not component or binding.get("operation") not in component.get("exposes", []):
            errors.append(f"components:operation_not_exposed:{binding.get('id')}")
        if not implementation or implementation.get("operation") != binding.get("operation"):
            errors.append(f"components:implementation_mismatch:{binding.get('id')}")
        key = canonical_json({
            "component_type": binding.get("component_type"), "operation": binding.get("operation"),
            "scope": binding.get("scope", "*"), "conditions": binding.get("conditions", {}), "priority": binding.get("priority")
        })
        groups[key].append(str(binding.get("id")))
    for values in groups.values():
        if len(values) > 1:
            errors.append(f"components:ambiguous_dispatch:{','.join(sorted(values))}")
    for item in document.get("program_implementations", []):
        if item.get("operation") not in operations:
            errors.append(f"components:unknown_implementation_operation:{item.get('id')}")
    return errors


def validate_relation_fact(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    participants = document.get("participants", [])
    roles = [item.get("role") for item in participants]
    if len(participants) < 2:
        errors.append("relation:at_least_two_participants_required")
    if len(roles) != len(set(roles)):
        errors.append("relation:participant_roles_must_be_unique")
    if not document.get("provenance"):
        errors.append("relation:provenance_required")
    if not 0 <= document.get("confidence", -1) <= 1:
        errors.append("relation:confidence_out_of_range")
    if document.get("authority") == "proposal" and document.get("priority", 0) > 1000:
        errors.append("relation:proposal_cannot_gain_implicit_authority")
    return errors


def validate_technology_draft(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("technology:canonical_write_must_be_false")
    diagnostics = document.get("diagnostics", [])
    blocking = any(item.get("severity") == "blocking" for item in diagnostics)
    if blocking and document.get("status") not in {"blocked", "proposal"}:
        errors.append("technology:blocking_diagnostic_did_not_block")
    return errors


def validate_activation_plan(document: dict[str, Any], snapshot: dict[str, Any] | None = None) -> tuple[list[str], list[list[str]]]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("activation:canonical_write_must_be_false")
    if digest_value(_without_digest(document)) != document.get("digest"):
        errors.append("activation:plan_digest_mismatch")
    paths = document.get("activated_paths", [])
    errors.extend(_duplicate_ids(paths, "activation:path"))
    order = document.get("join", {}).get("deterministic_order", [])
    path_ids = sorted(str(item.get("id")) for item in paths)
    if order != path_ids:
        errors.append("activation:deterministic_order_mismatch")
    frontiers = _frontiers(document, errors)
    if any(len(frontier) > document.get("budgets", {}).get("max_parallel", 0) for frontier in frontiers):
        errors.append("activation:parallel_budget_exceeded")
    if snapshot is not None:
        computed = digest_value({"id": snapshot.get("id"), "components": snapshot.get("components"), "relation_facts": snapshot.get("relation_facts")})
        if computed != snapshot.get("graph_snapshot_digest"):
            errors.append("activation:graph_snapshot_digest_mismatch")
        if document.get("graph_snapshot_digest") != snapshot.get("graph_snapshot_digest"):
            errors.append("activation:plan_snapshot_binding_mismatch")
    return errors, frontiers


def validate_activation_run(document: dict[str, Any], plan: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    if document.get("canonical_write_allowed") is not False:
        errors.append("activation_run:canonical_write_must_be_false")
    if document.get("learning_update_allowed") is not False:
        errors.append("activation_run:learning_update_must_be_false")
    results = document.get("path_results", [])
    successful = sorted(item.get("path_id") for item in results if item.get("status") == "completed")
    if sorted(document.get("successful_path_ids", [])) != successful:
        errors.append("activation_run:successful_paths_mismatch")
    trace_basis = {
        "plan_digest": document.get("plan_digest"),
        "status": document.get("status"),
        "paths": [
            {key: item[key] for key in ("path_id", "status", "program_digest", "trace_digest", "output_digest", "effects_executed", "blocker") if key in item}
            for item in results
        ],
    }
    if digest_value(trace_basis) != document.get("aggregate_trace_digest"):
        errors.append("activation_run:aggregate_trace_digest_mismatch")
    if plan is not None:
        if document.get("plan_digest") != plan.get("digest"):
            errors.append("activation_run:plan_binding_mismatch")
        plan_ids = {item.get("id") for item in plan.get("activated_paths", [])}
        if {item.get("path_id") for item in results} != plan_ids:
            errors.append("activation_run:path_coverage_mismatch")
        plan_errors, expected_frontiers = validate_activation_plan(plan)
        errors.extend(f"activation_run:bound_plan:{item}" for item in plan_errors)
        if document.get("frontiers") != expected_frontiers:
            errors.append("activation_run:frontier_mismatch")
        pure_only = set(plan.get("required_capabilities", [])) <= {"pure"}
        if pure_only and (document.get("effects_executed") or any(item.get("effects_executed") for item in results)):
            errors.append("activation_run:pure_plan_executed_effect")
    return errors


def check_graph_native(
    kind: str,
    document: dict[str, Any],
    schema: dict[str, Any],
    *,
    graph_snapshot: dict[str, Any] | None = None,
    activation_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors = _schema_errors(document, schema)
    if not errors:
        if kind == "source-catalog":
            errors.extend(validate_source_catalog(document))
        elif kind == "assimilation-proposal":
            errors.extend(validate_assimilation_proposal(document))
        elif kind == "component-package":
            errors.extend(validate_component_package(document))
        elif kind == "relation-fact":
            errors.extend(validate_relation_fact(document))
        elif kind == "technology-draft":
            errors.extend(validate_technology_draft(document))
        elif kind == "activation-plan":
            plan_errors, _ = validate_activation_plan(document, graph_snapshot)
            errors.extend(plan_errors)
        elif kind == "activation-run-result":
            errors.extend(validate_activation_run(document, activation_plan))
        else:
            errors.append(f"graph_native:unknown_kind:{kind}")
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
