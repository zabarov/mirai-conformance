"""Mirai expression AST evaluator. String eval is intentionally absent."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .canonical import canonical_json
from .errors import MiraiConformanceError


def _resolve(scope: dict[str, dict[str, Any]], path: str) -> Any:
    parts = path.split(".")
    root = parts.pop(0)
    if root not in {"input", "state", "local"}:
        raise MiraiConformanceError("unknown_ref_root", f"Unknown reference root: {root}")
    value: Any = scope.get(root, {})
    for part in parts:
        if not isinstance(value, dict) or part not in value:
            raise MiraiConformanceError("unknown_ref", f"Unknown reference path: {path}")
        value = value[part]
    return value


def evaluate(expression: dict[str, Any], scope: dict[str, dict[str, Any]]) -> Any:
    op = expression.get("op")
    if op == "literal":
        return deepcopy(expression.get("value"))
    if op == "ref":
        return deepcopy(_resolve(scope, expression["path"]))
    if op == "get":
        target = evaluate(expression["target"], scope)
        key = expression["key"]
        if not isinstance(target, dict) or key not in target:
            raise MiraiConformanceError("invalid_get", f"Missing key {key}")
        return deepcopy(target[key])
    if op == "not":
        return not bool(evaluate(expression["value"], scope))
    if op == "coalesce":
        for item in expression["values"]:
            value = evaluate(item, scope)
            if value is not None:
                return value
        return None

    left = evaluate(expression["left"], scope)
    right = evaluate(expression["right"], scope)
    if op == "eq":
        return canonical_json(left) == canonical_json(right)
    if op == "ne":
        return canonical_json(left) != canonical_json(right)
    if op == "lt":
        return left < right
    if op == "lte":
        return left <= right
    if op == "gt":
        return left > right
    if op == "gte":
        return left >= right
    if op == "and":
        return bool(left) and bool(right)
    if op == "or":
        return bool(left) or bool(right)
    if op == "in":
        if isinstance(right, list):
            return any(canonical_json(item) == canonical_json(left) for item in right)
        if isinstance(right, dict) and isinstance(left, str):
            return left in right
        return False
    raise MiraiConformanceError("unknown_expression", f"Unsupported expression {op}")


def evaluate_map(
    expressions: dict[str, dict[str, Any]] | None,
    scope: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        key: evaluate(expression, scope)
        for key, expression in sorted((expressions or {}).items())
    }
