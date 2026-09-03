"""Independent Mirai Program shape and semantic validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .canonical import canonical_json, program_digest
from .program_extensions import TASK_EFFECTS, validate_bindings

ALLOWED_EFFECTS = {
    "pure",
    "repository_read",
    "git_read",
    "workspace_patch",
    "process_run",
    "human_approval",
}
NODE_KINDS = {
    "call",
    "branch",
    "match",
    "foreach",
    "parallel",
    "await",
    "retry",
    "timeout",
    "cancel",
    "compensate",
    "emit",
    "return",
}
PRIMITIVE_TYPES = {
    "boolean",
    "string",
    "int64",
    "decimal",
    "timestamp",
    "duration",
    "identifier",
    "reference",
    "error",
}


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _is_record(value: Any) -> bool:
    return isinstance(value, dict)


def _type_key(value: Any) -> str | None:
    return canonical_json(value) if value is not None else None


def value_matches_type(value: Any, type_spec: Any) -> bool:
    if isinstance(type_spec, str):
        if type_spec == "boolean":
            return isinstance(value, bool)
        if type_spec == "int64":
            return isinstance(value, int) and not isinstance(value, bool) and -(2**53 - 1) <= value <= 2**53 - 1
        if type_spec == "decimal":
            if not isinstance(value, str):
                return False
            import re

            return bool(re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value))
        return type_spec in {"string", "timestamp", "duration", "identifier", "reference", "error"} and isinstance(value, str)
    if not isinstance(type_spec, dict):
        return False
    kind = type_spec.get("kind")
    if kind == "enum":
        return isinstance(value, str) and value in type_spec.get("values", [])
    if kind == "list":
        return isinstance(value, list) and all(value_matches_type(item, type_spec.get("items")) for item in value)
    if kind == "map":
        return isinstance(value, dict) and all(value_matches_type(item, type_spec.get("values")) for item in value.values())
    if kind == "option":
        return value is None or value_matches_type(value, type_spec.get("value"))
    if kind == "record":
        fields = type_spec.get("fields", {})
        return isinstance(value, dict) and all(key in value and value_matches_type(value[key], item) for key, item in fields.items())
    if kind == "result":
        return isinstance(value, dict) and (
            ("ok" in value and value_matches_type(value["ok"], type_spec.get("ok")))
            or ("error" in value and value_matches_type(value["error"], type_spec.get("error", "error")))
        )
    return False


def _validate_type(type_spec: Any, label: str, errors: list[str]) -> bool:
    if isinstance(type_spec, str):
        if type_spec not in PRIMITIVE_TYPES:
            errors.append(f"{label}:unknown_type:{type_spec}")
            return False
        return True
    if not isinstance(type_spec, dict) or not isinstance(type_spec.get("kind"), str):
        errors.append(f"{label}:invalid_type_spec")
        return False
    kind = type_spec["kind"]
    if kind == "enum":
        values = type_spec.get("values")
        if not isinstance(values, list) or not values or not all(isinstance(item, str) for item in values):
            errors.append(f"{label}:invalid_enum")
        return True
    if kind == "record":
        fields = type_spec.get("fields")
        if not isinstance(fields, dict):
            errors.append(f"{label}:invalid_record_fields")
        else:
            for key, value in fields.items():
                _validate_type(value, f"{label}.{key}", errors)
        return True
    if kind in {"list", "map", "option"}:
        field = {"list": "items", "map": "values", "option": "value"}[kind]
        return _validate_type(type_spec.get(field), f"{label}.{field}", errors)
    if kind == "result":
        _validate_type(type_spec.get("ok"), f"{label}.ok", errors)
        if "error" in type_spec:
            _validate_type(type_spec["error"], f"{label}.error", errors)
        return True
    errors.append(f"{label}:unknown_type_kind:{kind}")
    return False


def _infer_literal(value: Any) -> Any:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "int64"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        inferred = [_infer_literal(item) for item in value]
        if all(item is not None for item in inferred) and all(_type_key(item) == _type_key(inferred[0]) for item in inferred):
            return {"kind": "list", "items": inferred[0] if inferred else "string"}
    return None


def _infer_expression(expression: Any, env: dict[str, Any], errors: list[str], label: str) -> Any:
    if not isinstance(expression, dict) or not isinstance(expression.get("op"), str):
        errors.append(f"{label}:invalid_expression")
        return None
    op = expression["op"]
    if op == "literal":
        return _infer_literal(expression.get("value"))
    if op == "ref":
        path = expression.get("path")
        if not isinstance(path, str):
            errors.append(f"{label}:invalid_ref")
            return None
        result = env.get(path)
        if result is None:
            errors.append(f"{label}:unknown_ref:{path}")
        return result
    if op == "get":
        target = _infer_expression(expression.get("target"), env, errors, f"{label}.target")
        key = expression.get("key")
        if not isinstance(target, dict) or target.get("kind") != "record" or not isinstance(key, str) or key not in target.get("fields", {}):
            errors.append(f"{label}:invalid_get")
            return None
        return target["fields"][key]
    if op in {"eq", "ne", "lt", "lte", "gt", "gte", "and", "or", "in"}:
        left = _infer_expression(expression.get("left"), env, errors, f"{label}.left")
        right = _infer_expression(expression.get("right"), env, errors, f"{label}.right")
        if op in {"and", "or"} and (left != "boolean" or right != "boolean"):
            errors.append(f"{label}:boolean_operands_required")
        elif op != "in" and left is not None and right is not None and _type_key(left) != _type_key(right):
            errors.append(f"{label}:operand_type_mismatch")
        return "boolean"
    if op == "not":
        if _infer_expression(expression.get("value"), env, errors, f"{label}.value") != "boolean":
            errors.append(f"{label}:boolean_operand_required")
        return "boolean"
    if op == "coalesce":
        values = expression.get("values")
        if not isinstance(values, list) or not values:
            errors.append(f"{label}:coalesce_values_required")
            return None
        types = [
            _infer_expression(value, env, errors, f"{label}.values[{index}]")
            for index, value in enumerate(values)
        ]
        types = [item for item in types if item is not None]
        if types and any(_type_key(item) != _type_key(types[0]) for item in types):
            errors.append(f"{label}:coalesce_type_mismatch")
        return types[0] if types else None
    errors.append(f"{label}:unknown_expression_op:{op}")
    return None


def _require_node(value: Any, refs: set[str], label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or value not in refs:
        errors.append(f"{label}:unknown_node_ref:{value}")


def _require_program(value: Any, program: dict[str, Any], label: str, errors: list[str]) -> None:
    refs = {program.get("id")}
    for item in program.get("imports", []):
        refs.update({item.get("alias"), item.get("ref")})
    if not isinstance(value, str) or value not in refs:
        errors.append(f"{label}:unknown_program_ref:{value}")


def _validate_node(node: dict[str, Any], refs: set[str], env: dict[str, Any], program: dict[str, Any], errors: list[str]) -> None:
    node_id = node.get("id")
    kind = node.get("kind")
    label = f"node:{node_id}"
    if kind not in NODE_KINDS:
        errors.append(f"{label}:unknown_kind:{kind}")
        return
    if "next" in node:
        _require_node(node["next"], refs, f"{label}.next", errors)
    if kind == "call":
        target = node.get("target")
        if not isinstance(target, dict) or target.get("kind") not in {"adapter", "program"}:
            errors.append(f"{label}:invalid_target")
        elif target["kind"] == "program":
            _require_program(target.get("program"), program, f"{label}.target.program", errors)
        elif not target.get("adapter") or not target.get("operation"):
            errors.append(f"{label}:adapter_binding_required")
        if isinstance(target, dict) and target.get("kind") == "adapter" and not node.get("effects"):
            errors.append(f"{label}:effects_required")
        for key, expression in (node.get("args") or {}).items():
            _infer_expression(expression, env, errors, f"{label}.args.{key}")
        for effect in node.get("effects", []):
            if effect not in ALLOWED_EFFECTS and not (program.get("contract_version") == "1.1.0" and effect in TASK_EFFECTS):
                errors.append(f"{label}:unknown_effect:{effect}")
            if effect not in program.get("policies", {}).get("allowed_effects", []):
                errors.append(f"{label}:effect_not_allowed:{effect}")
        if any(effect != "pure" for effect in node.get("effects", [])) and not node.get("capability"):
            errors.append(f"{label}:capability_required")
        if "on_error" in node:
            _require_node(node["on_error"], refs, f"{label}.on_error", errors)
        if "result" in node and f"state.{node['result']}" not in env:
            errors.append(f"{label}:unknown_result_state:{node['result']}")
    elif kind == "branch":
        if _infer_expression(node.get("condition"), env, errors, f"{label}.condition") != "boolean":
            errors.append(f"{label}:condition_must_be_boolean")
        _require_node(node.get("then"), refs, f"{label}.then", errors)
        _require_node(node.get("else"), refs, f"{label}.else", errors)
    elif kind == "match":
        _infer_expression(node.get("value"), env, errors, f"{label}.value")
        cases = node.get("cases")
        if not isinstance(cases, list) or not cases:
            errors.append(f"{label}:cases_required")
        else:
            for index, item in enumerate(cases):
                _require_node(item.get("to"), refs, f"{label}.cases[{index}]", errors)
        _require_node(node.get("default"), refs, f"{label}.default", errors)
    elif kind == "foreach":
        item_type = _infer_expression(node.get("items"), env, errors, f"{label}.items")
        if not isinstance(item_type, dict) or item_type.get("kind") != "list":
            errors.append(f"{label}:items_must_be_list")
        maximum = node.get("max_iterations")
        budget = program.get("policies", {}).get("budgets", {}).get("max_iterations", 0)
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1 or maximum > budget:
            errors.append(f"{label}:unbounded_foreach")
        if not node.get("program") or not node.get("item"):
            errors.append(f"{label}:program_and_item_required")
        else:
            _require_program(node["program"], program, f"{label}.program", errors)
        if "result" in node and f"state.{node['result']}" not in env:
            errors.append(f"{label}:unknown_result_state:{node['result']}")
    elif kind == "parallel":
        branches = node.get("branches")
        if not isinstance(branches, list) or not branches:
            errors.append(f"{label}:branches_required")
        else:
            for index, branch in enumerate(branches):
                _require_program(branch.get("program"), program, f"{label}.branches[{index}].program", errors)
            if len({branch.get("id") for branch in branches}) != len(branches):
                errors.append(f"{label}:duplicate_parallel_branch")
        maximum = node.get("max_parallel")
        budget = program.get("policies", {}).get("budgets", {}).get("max_parallel", 0)
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1 or maximum > budget:
            errors.append(f"{label}:parallel_budget_invalid")
        if "result" in node and f"state.{node['result']}" not in env:
            errors.append(f"{label}:unknown_result_state:{node['result']}")
    elif kind == "await":
        if not node.get("event") or not isinstance(node.get("deadline_ms"), int) or node["deadline_ms"] < 1:
            errors.append(f"{label}:event_and_deadline_required")
        _require_node(node.get("on_timeout"), refs, f"{label}.on_timeout", errors)
        if "result" in node and f"state.{node['result']}" not in env:
            errors.append(f"{label}:unknown_result_state:{node['result']}")
    elif kind == "retry":
        maximum = node.get("max_attempts")
        budget = program.get("policies", {}).get("budgets", {}).get("max_iterations", 0)
        if not node.get("program") or not isinstance(maximum, int) or maximum < 1 or maximum > budget:
            errors.append(f"{label}:retry_budget_invalid")
        else:
            _require_program(node["program"], program, f"{label}.program", errors)
        if not isinstance(node.get("timeout_ms"), int) or node["timeout_ms"] < 1 or not isinstance(node.get("backoff_ms"), int) or node["backoff_ms"] < 0:
            errors.append(f"{label}:retry_timing_invalid")
        _require_node(node.get("on_error"), refs, f"{label}.on_error", errors)
    elif kind == "timeout":
        if not node.get("program") or not isinstance(node.get("timeout_ms"), int) or node["timeout_ms"] < 1:
            errors.append(f"{label}:timeout_invalid")
        else:
            _require_program(node["program"], program, f"{label}.program", errors)
        _require_node(node.get("on_timeout"), refs, f"{label}.on_timeout", errors)
    elif kind == "compensate":
        _infer_expression(node.get("receipt"), env, errors, f"{label}.receipt")
        if "on_error" in node:
            _require_node(node["on_error"], refs, f"{label}.on_error", errors)
    elif kind == "emit":
        if not node.get("event"):
            errors.append(f"{label}:event_required")
        if "payload" in node:
            _infer_expression(node["payload"], env, errors, f"{label}.payload")
    elif kind == "return":
        for output in program.get("outputs", []):
            expression = (node.get("values") or {}).get(output.get("id"))
            if output.get("required") is not False and expression is None:
                errors.append(f"{label}:missing_output:{output.get('id')}")
            elif expression is not None:
                actual = _infer_expression(expression, env, errors, f"{label}.values.{output.get('id')}")
                if actual is not None and _type_key(actual) != _type_key(output.get("type")):
                    errors.append(f"{label}:output_type_mismatch:{output.get('id')}")

    if kind in {"call", "foreach", "parallel", "await", "retry", "timeout", "compensate", "emit"} and "next" not in node:
        errors.append(f"{label}:next_required")


def validate_program(program: Any, schema: dict[str, Any] | None = None, verify_digest: bool = True, catalog=None, schema_registry=None) -> list[str]:
    errors: list[str] = []
    if schema is not None:
        validator = Draft202012Validator(schema)
        for error in validator.iter_errors(program):
            path = "/" + "/".join(str(item) for item in error.absolute_path)
            errors.append(f"schema:{path}:{error.message}")
    if not isinstance(program, dict):
        return sorted(set(errors + ["program_not_object"]))
    nodes = program.get("nodes")
    policies = program.get("policies")
    if not isinstance(nodes, list) or not isinstance(policies, dict) or not isinstance(policies.get("budgets"), dict):
        return sorted(set(errors + ["program_structure_missing"]))

    refs: set[str] = set()
    for node in nodes:
        node_id = node.get("id") if isinstance(node, dict) else None
        if node_id in refs:
            errors.append(f"duplicate_node:{node_id}")
        if isinstance(node_id, str):
            refs.add(node_id)
    _require_node(program.get("entry"), refs, "entry", errors)

    env: dict[str, Any] = {}
    for group, slots_key in (("input", "inputs"), ("state", "state")):
        seen: set[str] = set()
        for slot in program.get(slots_key, []):
            slot_id = slot.get("id")
            if slot_id in seen:
                errors.append(f"duplicate_{group}:{slot_id}")
            seen.add(slot_id)
            if _validate_type(slot.get("type"), f"{group}:{slot_id}", errors):
                env[f"{group}.{slot_id}"] = slot["type"]
                if "default" in slot and not value_matches_type(slot["default"], slot["type"]):
                    errors.append(f"{group}:{slot_id}:default_type_mismatch")
                if group == "state" and slot.get("required") is not False and "default" not in slot:
                    errors.append(f"state:{slot_id}:default_required")
    output_ids: set[str] = set()
    for slot in program.get("outputs", []):
        slot_id = slot.get("id")
        if slot_id in output_ids:
            errors.append(f"duplicate_output:{slot_id}")
        output_ids.add(slot_id)
        _validate_type(slot.get("type"), f"output:{slot_id}", errors)

    aliases: set[str] = set()
    for item in program.get("imports", []):
        alias = item.get("alias")
        if alias in aliases:
            errors.append(f"duplicate_import_alias:{alias}")
        aliases.add(alias)
    for effect in policies.get("allowed_effects", []):
        if effect not in ALLOWED_EFFECTS and not (program.get("contract_version") == "1.1.0" and effect in TASK_EFFECTS):
            errors.append(f"unknown_allowed_effect:{effect}")
    if policies.get("canonical_write_allowed") is not False:
        errors.append("canonical_write_must_be_false")
    errors.extend(validate_bindings(program, catalog, schema_registry))
    for node in nodes:
        if isinstance(node, dict):
            _validate_node(node, refs, env, program, errors)
    for route in program.get("error_routes", []):
        _require_node(route.get("to"), refs, f"error_route:{route.get('error')}", errors)
    source_map = program.get("source_map")
    if isinstance(source_map, dict):
        for node in nodes:
            if isinstance(node, dict) and node.get("id") not in source_map:
                errors.append(f"source_map_missing:{node.get('id')}")
    if verify_digest and isinstance(program.get("digest"), str):
        expected = program_digest(program)
        if program["digest"] != expected:
            errors.append(f"digest_mismatch:{program['digest']}:{expected}")
    return sorted(set(errors))
