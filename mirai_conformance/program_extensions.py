"""Bounded Program 1.1 binding checks, independent of the JS implementation.

The catalog is trusted test input, not a catalog supplied by the Program.
Dynamic values remain invocation-time checks, not a static type proof.
"""
import re

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry

from .canonical import digest_value


TASK_OPERATIONS = {
    "submit": ("task_control", []),
    "dispatch": ("task_dispatch", ["task_id"]),
    "inference": ("inference_invoke", ["task_id"]),
    "inspect": ("task_read", []),
    "collect": ("task_read", []),
    "accept": ("task_control", ["task_id", "reviewer", "result_digest", "verdict"]),
    "cancel": ("task_control", []),
    "reconcile": ("task_control", ["task_id"]),
}
TASK_EFFECTS = {entry[0] for entry in TASK_OPERATIONS.values()}


def task_argument(name, value):
    if not isinstance(value, str):
        return False
    if name.endswith("_digest"):
        return re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None
    if name == "verdict":
        return value in {"accepted", "rejected"}
    return re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,159}", value) is not None


def validate_bindings(program, catalog=None, schema_registry=None):
    errors = []
    modern = program.get("contract_version") == "1.1.0"
    if not modern and "operation_catalog" in program:
        errors.append("legacy_catalog_forbidden")
    operations = {}
    if modern:
        if not isinstance(catalog, dict):
            errors.append("trusted_catalog_required")
        else:
            digest = digest_value({k: v for k, v in catalog.items() if k != "digest"})
            if digest != catalog.get("digest"):
                errors.append("catalog_digest_invalid")
            if program.get("operation_catalog") != {"id": "mirai.stdlib", "contract_version": "1.0.0", "digest": digest}:
                errors.append("catalog_binding_invalid")
            operations = {op["id"]: op for op in catalog["operations"]}
            if len(operations) != len(catalog["operations"]):
                errors.append("catalog_duplicate_operation")
    for node in program.get("nodes", []):
        if node.get("kind") != "call":
            continue
        target = node.get("target", {})
        effects = node.get("effects", [])
        args = node.get("args", {})
        if target.get("kind") == "adapter" and target.get("adapter") == "mirai_tasks":
            if not modern:
                errors.append("task_program_version")
            descriptor = TASK_OPERATIONS.get(target.get("operation"))
            if descriptor is None:
                errors.append("unknown_task_operation")
                continue
            effect, required = descriptor
            if effects != [effect]:
                errors.append("task_effect_mismatch")
            fields = {"registry_digest", "plan_digest", *required}
            if set(args) != fields:
                errors.append("task_argument_names")
            for key, expr in args.items():
                if expr.get("op") == "literal" and not task_argument(key, expr.get("value")):
                    errors.append("task_argument_invalid")
        elif any(effect in TASK_EFFECTS for effect in effects):
            errors.append("task_adapter_required")
        if modern and target.get("kind") == "adapter" and target.get("adapter") == "mirai_stdlib":
            descriptor = operations.get(target.get("operation"))
            if descriptor is None:
                errors.append("unknown_standard_operation")
                continue
            if effects != [descriptor["effect"]] or "capability" in node:
                errors.append("standard_operation_effect")
            shape = descriptor["input_schema"]
            props = shape.get("properties", {})
            if not set(shape.get("required", [])) <= set(args) or not set(args) <= set(props):
                errors.append("standard_operation_argument_names")
            for key, expr in args.items():
                if key in props and expr.get("op") == "literal":
                    validator = Draft202012Validator(props[key], format_checker=FormatChecker(), registry=schema_registry or Registry())
                    if not validator.is_valid(expr.get("value")):
                        errors.append("standard_operation_argument_invalid")
    return errors
