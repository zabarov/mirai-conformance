"""Independent validation for public Mirai episodes and sanitized evidence."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .canonical import digest_value
from .validator import load_json


_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_PRIVATE_PATH_RE = re.compile(r"(?:/Users/|/home/[^/]+/|[A-Za-z]:\\Users\\)")
_SECRET_RE = re.compile(r"(?:ghp_[A-Za-z0-9]+|xoxb-[A-Za-z0-9-]+|BEGIN PRIVATE KEY|raw \.env)")
_FORBIDDEN_EXPORT_KEYS = {
    "approval_signature",
    "capability_grant_ref",
    "command_output",
    "content",
    "result",
    "sandbox_path",
    "secret",
    "signature",
    "stderr",
    "stdout",
}


def _schema_errors(document: Any, schema: dict[str, Any] | None) -> list[str]:
    if schema is None:
        return []
    errors: list[str] = []
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in validator.iter_errors(document):
        path = "/" + "/".join(str(item) for item in error.absolute_path)
        errors.append(f"schema:{path}:{error.message}")
    return errors


def _walk_public_export(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else key
            if key in _FORBIDDEN_EXPORT_KEYS:
                errors.append(f"public_export:forbidden_key:{child}")
            _walk_public_export(item, child, errors)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_public_export(item, f"{path}[{index}]", errors)
        return
    if isinstance(value, str):
        if _PRIVATE_PATH_RE.search(value):
            errors.append(f"public_export:private_path:{path}")
        if _SECRET_RE.search(value):
            errors.append(f"public_export:secret_pattern:{path}")


def _check_digest(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        errors.append(f"{label}:invalid_digest")


def validate_pure_episode(
    episode: Any,
    schema: dict[str, Any] | None = None,
    program: dict[str, Any] | None = None,
) -> list[str]:
    """Validate a pure episode without executing the TypeScript runtime."""

    errors = _schema_errors(episode, schema)
    if not isinstance(episode, dict):
        return sorted(set(errors + ["episode:not_object"]))

    for key in ("program_digest", "input_digest", "output_digest", "trace_digest"):
        _check_digest(episode.get(key), f"episode:{key}", errors)

    if episode.get("input_digest") != digest_value(episode.get("replay_input")):
        errors.append("episode:input_digest_mismatch")
    if episode.get("output_digest") != digest_value(episode.get("outputs")):
        errors.append("episode:output_digest_mismatch")
    if episode.get("trace_digest") != digest_value(episode.get("trace")):
        errors.append("episode:trace_digest_mismatch")

    trace = episode.get("trace")
    if not isinstance(trace, list) or not trace:
        errors.append("episode:trace_required")
    else:
        sequences = [item.get("sequence") if isinstance(item, dict) else None for item in trace]
        if sequences != list(range(1, len(trace) + 1)):
            errors.append("episode:trace_sequence_not_contiguous")
        logical_times = [item.get("logical_time") if isinstance(item, dict) else None for item in trace]
        if not all(isinstance(item, int) and not isinstance(item, bool) for item in logical_times):
            errors.append("episode:logical_time_invalid")
        elif any(current <= previous for previous, current in zip(logical_times, logical_times[1:])):
            errors.append("episode:logical_time_not_monotonic")
        if episode.get("status") == "completed" and (
            not isinstance(trace[-1], dict) or trace[-1].get("kind") != "return"
        ):
            errors.append("episode:completed_without_terminal_return")
    if episode.get("steps") != (len(trace) if isinstance(trace, list) else None):
        errors.append("episode:step_count_mismatch")
    if episode.get("effects_executed") is not False:
        errors.append("episode:pure_effect_boundary_broken")
    if episode.get("canonical_write_allowed") is not False:
        errors.append("episode:canonical_write_must_be_false")

    if program is not None:
        if episode.get("program_id") != program.get("id"):
            errors.append("episode:program_id_mismatch")
        if episode.get("program_digest") != program.get("digest"):
            errors.append("episode:program_digest_mismatch")
    return sorted(set(errors))


def validate_sanitized_evidence(
    evidence: Any,
    schema: dict[str, Any] | None = None,
) -> list[str]:
    """Validate cross-record consistency in a sanitized runtime evidence pack."""

    errors = _schema_errors(evidence, schema)
    if not isinstance(evidence, dict):
        return sorted(set(errors + ["evidence:not_object"]))
    _walk_public_export(evidence, "", errors)

    run = evidence.get("run")
    episode = evidence.get("episode")
    receipts = evidence.get("receipts")
    if not isinstance(run, dict) or not isinstance(episode, dict) or not isinstance(receipts, list):
        return sorted(set(errors + ["evidence:required_sections_missing"]))

    if evidence.get("canonical_write_allowed") is not False:
        errors.append("evidence:canonical_write_must_be_false")
    if episode.get("canonical_write_allowed") is not False:
        errors.append("episode:canonical_write_must_be_false")
    if episode.get("learning_update_allowed") is not False:
        errors.append("episode:learning_update_must_be_false")
    if run.get("sandbox_ref") != "redacted-host-local":
        errors.append("run:sandbox_not_redacted")

    shared_fields = ("run_id", "program_id", "program_digest", "input_digest")
    for key in shared_fields:
        if key in run and run.get(key) != episode.get(key):
            errors.append(f"run_episode:{key}_mismatch")
    if episode.get("replay_input_digest") != episode.get("input_digest"):
        errors.append("episode:replay_input_digest_mismatch")

    receipt_ids: set[str] = set()
    receipt_sequences: list[Any] = []
    receipts_by_id: dict[str, dict[str, Any]] = {}
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            errors.append(f"receipt:{index}:not_object")
            continue
        receipt_id = receipt.get("receipt_id")
        if not isinstance(receipt_id, str) or receipt_id in receipt_ids:
            errors.append(f"receipt:{index}:duplicate_or_missing_id")
        else:
            receipt_ids.add(receipt_id)
            receipts_by_id[receipt_id] = receipt
        receipt_sequences.append(receipt.get("sequence"))
        for key in ("program_digest", "args_digest", "idempotency_key"):
            _check_digest(receipt.get(key), f"receipt:{receipt_id}:{key}", errors)
        for key in ("run_id", "program_id", "program_digest"):
            if receipt.get(key) != run.get(key):
                errors.append(f"receipt:{receipt_id}:{key}_mismatch")
        if run.get("status") == "completed" and receipt.get("status") not in {"verified", "compensated"}:
            errors.append(f"receipt:{receipt_id}:nonterminal_status_for_completed_run")

    if receipt_sequences != list(range(1, len(receipts) + 1)):
        errors.append("receipts:sequence_not_contiguous")

    summaries = episode.get("effect_summaries")
    if not isinstance(summaries, list):
        errors.append("episode:effect_summaries_missing")
        summaries = []
    summary_sequences = [item.get("sequence") if isinstance(item, dict) else None for item in summaries]
    if summary_sequences != list(range(1, len(summaries) + 1)):
        errors.append("episode:effect_summary_sequence_not_contiguous")
    if len(summaries) != len(receipts):
        errors.append("episode:receipt_summary_count_mismatch")

    comparable = (
        "sequence",
        "node_id",
        "invocation_id",
        "adapter",
        "operation",
        "args_digest",
        "status",
        "result_digest",
    )
    for index, summary in enumerate(summaries):
        if not isinstance(summary, dict):
            errors.append(f"effect_summary:{index}:not_object")
            continue
        receipt_id = summary.get("receipt_id")
        receipt = receipts_by_id.get(receipt_id)
        if receipt is None:
            errors.append(f"effect_summary:{index}:receipt_not_found:{receipt_id}")
            continue
        for key in comparable:
            if summary.get(key) != receipt.get(key):
                errors.append(f"effect_summary:{receipt_id}:{key}_mismatch")

    effects_executed = episode.get("effects_executed")
    if bool(receipts) != (effects_executed is True):
        errors.append("episode:effects_executed_receipt_mismatch")
    if run.get("status") != episode.get("status"):
        errors.append("run_episode:status_mismatch")
    return sorted(set(errors))


def check_episode(
    episode_path: str | Path,
    schema_path: str | Path | None = None,
    program_path: str | Path | None = None,
) -> dict[str, Any]:
    episode = load_json(episode_path)
    schema = load_json(schema_path) if schema_path else None
    program = load_json(program_path) if program_path else None
    errors = validate_pure_episode(episode, schema, program)
    return {
        "contract_version": "1.0.0",
        "implementation": "python_independent",
        "artifact_type": "pure_episode",
        "source_ref": str(episode_path),
        "schema_ref": str(schema_path) if schema_path else None,
        "program_ref": str(program_path) if program_path else None,
        "status": "passed" if not errors else "failed",
        "checks": [
            "schema",
            "digest_recalculation",
            "trace_sequence",
            "logical_time",
            "effect_boundary",
            "program_binding",
        ],
        "errors": errors,
        "limitations": [
            "This result checks the supplied episode and does not authorize an external effect."
        ],
    }


def check_evidence(
    evidence_path: str | Path,
    schema_path: str | Path | None = None,
) -> dict[str, Any]:
    evidence = load_json(evidence_path)
    schema = load_json(schema_path) if schema_path else None
    errors = validate_sanitized_evidence(evidence, schema)
    return {
        "contract_version": "1.0.0",
        "implementation": "python_independent",
        "artifact_type": "sanitized_runtime_evidence",
        "source_ref": str(evidence_path),
        "schema_ref": str(schema_path) if schema_path else None,
        "status": "passed" if not errors else "failed",
        "checks": [
            "schema",
            "public_export_boundary",
            "run_episode_binding",
            "receipt_sequence",
            "receipt_summary_consistency",
            "terminal_receipt_status",
            "canonical_and_learning_boundary",
        ],
        "errors": errors,
        "limitations": [
            "This result checks sanitized evidence only and cannot attest to hidden host-local effect payloads."
        ],
    }
