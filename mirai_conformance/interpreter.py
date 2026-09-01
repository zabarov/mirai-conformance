"""Deterministic pure Mirai Program interpreter implemented in Python."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_json, digest_value
from .errors import MiraiConformanceError, ProgramValidationError
from .expression import evaluate, evaluate_map
from .validator import validate_program, value_matches_type

_MISSING = object()


@dataclass
class ExecutionState:
    root: dict[str, Any]
    registry: dict[str, dict[str, Any]]
    events: dict[str, Any]
    trace: list[dict[str, Any]] = field(default_factory=list)
    emitted: list[dict[str, Any]] = field(default_factory=list)
    steps: int = 0
    iterations: int = 0
    logical_time: int = 0


def _initialize_slots(slots: list[dict[str, Any]], values: dict[str, Any], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    slot_ids = {slot["id"] for slot in slots}
    for slot in slots:
        present = slot["id"] in values
        value = values[slot["id"]] if present else slot.get("default", _MISSING)
        if value is _MISSING and slot.get("required") is not False:
            raise MiraiConformanceError(f"{label}_required", f"Missing {label} {slot['id']}")
        if value is not _MISSING and not value_matches_type(value, slot["type"]):
            raise MiraiConformanceError(f"{label}_type_mismatch", f"Invalid {label} {slot['id']}")
        if value is not _MISSING:
            result[slot["id"]] = deepcopy(value)
    for key in values:
        if key not in slot_ids:
            raise MiraiConformanceError(f"unknown_{label}", f"Unknown {label} {key}")
    return result


def _record(
    state: ExecutionState,
    program: dict[str, Any],
    node: dict[str, Any],
    depth: int,
    decision: str,
    result: Any = _MISSING,
) -> None:
    state.logical_time += 1
    if state.logical_time > state.root["policies"]["budgets"]["max_duration_ms"]:
        raise MiraiConformanceError("duration_budget_exceeded", "Program exceeded max_duration_ms", node["id"])
    event: dict[str, Any] = {
        "sequence": len(state.trace) + 1,
        "logical_time": state.logical_time,
        "depth": depth,
        "program_id": program["id"],
        "node_id": node["id"],
        "kind": node["kind"],
        "decision": decision,
    }
    if result is not _MISSING:
        event["result_digest"] = digest_value(result)
    state.trace.append(event)


def _step(state: ExecutionState, program: dict[str, Any], node: dict[str, Any], depth: int) -> None:
    state.steps += 1
    if state.steps > state.root["policies"]["budgets"]["max_steps"]:
        raise MiraiConformanceError("step_budget_exceeded", "Program exceeded max_steps", node["id"])
    if depth > state.root["policies"]["budgets"]["max_depth"] or depth > program["policies"]["budgets"]["max_depth"]:
        raise MiraiConformanceError("depth_budget_exceeded", "Program exceeded max_depth", node["id"])


def _resolve_program(state: ExecutionState, parent: dict[str, Any], reference: str) -> dict[str, Any]:
    imported = next(
        (item for item in parent.get("imports", []) if item["alias"] == reference or item["ref"] == reference),
        None,
    )
    child = state.registry.get(reference)
    if child is None and imported is not None:
        child = state.registry.get(imported["ref"]) or state.registry.get(imported["alias"])
    if child is None:
        raise MiraiConformanceError("program_not_found", f"Program not found: {reference}")
    if imported is not None and imported["digest"] != child.get("digest"):
        raise MiraiConformanceError("import_digest_mismatch", f"Import digest mismatch: {reference}")
    return child


def _route_error(program: dict[str, Any], node: dict[str, Any], error: Exception) -> str | None:
    if node["kind"] in {"call", "compensate"} and node.get("on_error"):
        return node["on_error"]
    code = error.code if isinstance(error, MiraiConformanceError) else str(error)
    route = next((item for item in program.get("error_routes", []) if item["error"] in {code, "*"}), None)
    return route["to"] if route else None


def _pure_adapter(adapter: str, operation: str, args: dict[str, Any]) -> Any:
    if adapter != "pure":
        raise MiraiConformanceError("adapter_operation_not_found", f"{adapter}.{operation}")
    if operation == "identity":
        return deepcopy(args["value"] if "value" in args else args)
    if operation == "add_int64":
        left, right = args.get("left"), args.get("right")
        if not isinstance(left, int) or isinstance(left, bool):
            raise MiraiConformanceError("pure_adapter_invalid_int64:left")
        if not isinstance(right, int) or isinstance(right, bool):
            raise MiraiConformanceError("pure_adapter_invalid_int64:right")
        return left + right
    if operation == "concat":
        values = args.get("values", [args.get("left"), args.get("right")])
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise MiraiConformanceError("pure_adapter_invalid_string")
        separator = args.get("separator") if isinstance(args.get("separator"), str) else ""
        return separator.join(values)
    if operation == "length":
        value = args.get("value")
        if isinstance(value, (str, list, dict)):
            return len(value)
        raise MiraiConformanceError("pure_adapter_length_unsupported")
    if operation == "fail":
        code = args.get("code") if isinstance(args.get("code"), str) else "pure_adapter_requested_failure"
        raise MiraiConformanceError(code)
    raise MiraiConformanceError("adapter_operation_not_found", f"{adapter}.{operation}")


def _js_string(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return str(value)


def _execute_program(
    program: dict[str, Any],
    raw_input: dict[str, Any],
    state: ExecutionState,
    depth: int,
) -> dict[str, Any]:
    errors = validate_program(program, schema=None)
    if errors:
        raise ProgramValidationError(errors)
    if any(effect != "pure" for effect in program["policies"]["allowed_effects"]):
        raise MiraiConformanceError("non_pure_effect_forbidden", "Pure interpreter accepts only pure effects")
    inputs = _initialize_slots(program.get("inputs", []), raw_input, "input")
    local_state = _initialize_slots(program.get("state", []), {}, "state")
    scope = {"input": inputs, "state": local_state, "local": {}}
    by_id = {node["id"]: node for node in program["nodes"]}
    current: str | None = program["entry"]

    while current:
        node = by_id.get(current)
        if node is None:
            raise MiraiConformanceError("node_not_found", f"Node not found: {current}", current)
        _step(state, program, node, depth)
        try:
            kind = node["kind"]
            if kind == "call":
                args = evaluate_map(node.get("args"), scope)
                target = node["target"]
                if target["kind"] == "program":
                    result = _execute_program(
                        _resolve_program(state, program, target["program"]),
                        args,
                        state,
                        depth + 1,
                    )["outputs"]
                else:
                    effects = node.get("effects", ["pure"])
                    if any(effect != "pure" for effect in effects):
                        raise MiraiConformanceError(
                            "non_pure_effect_forbidden",
                            "Adapter call is not authorized for pure execution",
                            node["id"],
                        )
                    result = _pure_adapter(target["adapter"], target["operation"], args)
                if node.get("result"):
                    local_state[node["result"]] = deepcopy(result)
                _record(state, program, node, depth, "completed", result)
                current = node.get("next")
            elif kind == "branch":
                selected = node["then"] if bool(evaluate(node["condition"], scope)) else node["else"]
                _record(state, program, node, depth, f"selected:{selected}")
                current = selected
            elif kind == "match":
                value = evaluate(node["value"], scope)
                selected = next(
                    (item["to"] for item in node["cases"] if canonical_json(item["equals"]) == canonical_json(value)),
                    node["default"],
                )
                _record(state, program, node, depth, f"selected:{selected}")
                current = selected
            elif kind == "foreach":
                items = evaluate(node["items"], scope)
                if not isinstance(items, list):
                    raise MiraiConformanceError("foreach_items_not_list", "foreach items must be a list", node["id"])
                if len(items) > node["max_iterations"]:
                    raise MiraiConformanceError("foreach_node_budget_exceeded", "foreach max_iterations exceeded", node["id"])
                state.iterations += len(items)
                if state.iterations > state.root["policies"]["budgets"]["max_iterations"]:
                    raise MiraiConformanceError("iteration_budget_exceeded", "Program exceeded max_iterations", node["id"])
                child = _resolve_program(state, program, node["program"])
                results: list[Any] = []
                for item in items:
                    child_input = evaluate_map(node.get("input"), scope)
                    child_input[node["item"]] = deepcopy(item)
                    results.append(_execute_program(child, child_input, state, depth + 1)["outputs"])
                if node.get("result"):
                    local_state[node["result"]] = results
                _record(state, program, node, depth, f"iterations:{len(items)}", results)
                current = node.get("next")
            elif kind == "parallel":
                if len(node["branches"]) > node["max_parallel"] or len(node["branches"]) > state.root["policies"]["budgets"]["max_parallel"]:
                    raise MiraiConformanceError("parallel_budget_exceeded", "Parallel width exceeded", node["id"])
                branch_results: list[tuple[str, dict[str, Any]]] = []
                for branch in node["branches"]:
                    child = _resolve_program(state, program, branch["program"])
                    value = _execute_program(child, evaluate_map(branch.get("input"), scope), state, depth + 1)["outputs"]
                    branch_results.append((branch["id"], value))
                if node["merge"] == "array":
                    merged: Any = [value for _, value in branch_results]
                elif node["merge"] == "object":
                    merged = {branch_id: value for branch_id, value in branch_results}
                else:
                    merged = all(value is not None for _, value in branch_results)
                if node.get("result"):
                    local_state[node["result"]] = merged
                _record(state, program, node, depth, f"joined:{node['merge']}", merged)
                current = node.get("next")
            elif kind == "await":
                if node["event"] in state.events:
                    value = deepcopy(state.events[node["event"]])
                    if node.get("result"):
                        local_state[node["result"]] = value
                    _record(state, program, node, depth, "event_received", value)
                    current = node.get("next")
                else:
                    _record(state, program, node, depth, "deadline_elapsed")
                    current = node["on_timeout"]
            elif kind == "retry":
                child = _resolve_program(state, program, node["program"])
                result: dict[str, Any] | None = None
                last_error: Exception | None = None
                for attempt in range(1, node["max_attempts"] + 1):
                    state.iterations += 1
                    if state.iterations > state.root["policies"]["budgets"]["max_iterations"]:
                        raise MiraiConformanceError("iteration_budget_exceeded", "Program exceeded max_iterations", node["id"])
                    try:
                        started = state.logical_time
                        result = _execute_program(child, evaluate_map(node.get("input"), scope), state, depth + 1)
                        duration = state.logical_time - started
                        if duration > node["timeout_ms"]:
                            result = None
                            raise MiraiConformanceError("retry_attempt_timeout", f"Retry attempt exceeded timeout_ms: {duration}")
                        _record(state, program, node, depth, f"succeeded_attempt:{attempt}", result["outputs"])
                        break
                    except Exception as error:  # noqa: BLE001 - conformance mirrors runtime routing
                        last_error = error
                        _record(state, program, node, depth, f"failed_attempt:{attempt}")
                if result is None:
                    _record(state, program, node, depth, f"exhausted:{last_error}")
                    current = node["on_error"]
                else:
                    if node.get("result"):
                        local_state[node["result"]] = result["outputs"]
                    current = node.get("next")
            elif kind == "timeout":
                before = state.logical_time
                result = _execute_program(
                    _resolve_program(state, program, node["program"]),
                    evaluate_map(node.get("input"), scope),
                    state,
                    depth + 1,
                )
                duration = state.logical_time - before
                if duration > node["timeout_ms"]:
                    _record(state, program, node, depth, f"timed_out:{duration}")
                    current = node["on_timeout"]
                else:
                    if node.get("result"):
                        local_state[node["result"]] = result["outputs"]
                    _record(state, program, node, depth, f"completed_within:{duration}", result["outputs"])
                    current = node.get("next")
            elif kind == "cancel":
                reason = evaluate(node["reason"], scope) if "reason" in node else "cancelled_by_program"
                _record(state, program, node, depth, f"cancelled:{_js_string(reason)}")
                return {"status": "cancelled", "outputs": {}, "state": local_state}
            elif kind == "compensate":
                receipt = evaluate(node["receipt"], scope)
                _record(state, program, node, depth, "pure_compensation_recorded", receipt)
                current = node.get("next")
            elif kind == "emit":
                payload = evaluate(node["payload"], scope) if "payload" in node else None
                state.emitted.append({"event": node["event"], "payload": deepcopy(payload)})
                _record(state, program, node, depth, f"emitted:{node['event']}", payload)
                current = node.get("next")
            elif kind == "return":
                outputs = evaluate_map(node.get("values"), scope)
                _initialize_slots(program.get("outputs", []), outputs, "output")
                _record(state, program, node, depth, "returned", outputs)
                return {"status": "completed", "outputs": outputs, "state": local_state}
        except Exception as error:  # noqa: BLE001 - conformance mirrors runtime routing
            target = _route_error(program, node, error)
            if target is None:
                raise
            _record(state, program, node, depth, f"error_routed:{target}")
            current = target
    raise MiraiConformanceError("missing_terminal", f"Program {program['id']} ended without return or cancel")


def execute_pure(
    program: dict[str, Any],
    inputs: dict[str, Any] | None = None,
    programs: dict[str, dict[str, Any]] | None = None,
    events: dict[str, Any] | None = None,
) -> dict[str, Any]:
    registry = {program["id"]: program, **(programs or {})}
    state = ExecutionState(root=program, registry=registry, events=events or {})
    result = _execute_program(program, deepcopy(inputs or {}), state, 0)
    input_digest = digest_value(inputs or {})
    output_digest = digest_value(result["outputs"])
    trace_digest = digest_value(state.trace)
    episode_seed = {"program": program["digest"], "input": input_digest, "trace": trace_digest}
    return {
        "contract_version": "1.0.0",
        "episode_id": f"episode.{digest_value(episode_seed)[7:23]}",
        "program_id": program["id"],
        "program_digest": program["digest"],
        "input_digest": input_digest,
        "replay_input": deepcopy(inputs or {}),
        "status": result["status"],
        "outputs": result["outputs"],
        "output_digest": output_digest,
        "final_state": result["state"],
        "emitted_events": state.emitted,
        "trace": state.trace,
        "trace_digest": trace_digest,
        "steps": state.steps,
        "logical_duration_ms": state.logical_time,
        "effects_executed": False,
        "canonical_write_allowed": False,
        "limitations": ["Pure episodes contain no external effects or runtime authorization."],
    }
