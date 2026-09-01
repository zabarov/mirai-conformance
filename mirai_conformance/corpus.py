"""Portable Mirai conformance corpus runner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import digest_value
from .interpreter import execute_pure
from .validator import load_json, validate_program


def _load_program(path: Path, schema: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    program = load_json(path)
    return program, validate_program(program, schema=schema)


def run_corpus(corpus_path: str | Path, program_schema_path: str | Path) -> dict[str, Any]:
    corpus_file = Path(corpus_path).resolve()
    corpus = load_json(corpus_file)
    schema = load_json(Path(program_schema_path).resolve())
    if corpus.get("contract_version") != "1.0.0" or not corpus.get("id") or not isinstance(corpus.get("cases"), list):
        raise ValueError("invalid_pure_conformance_corpus")

    results: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        try:
            program, validation_errors = _load_program(corpus_file.parent / case["program"], schema)
            expected_validation_error = case.get("expected_validation_error")
            if expected_validation_error:
                passed = any(expected_validation_error in error for error in validation_errors)
                results.append(
                    {
                        "id": case["id"],
                        "passed": passed,
                        "status": "expected_validation_failure" if passed else "failed",
                        "errors": [] if passed else validation_errors or ["expected_validation_error_missing"],
                    }
                )
                continue
            if validation_errors:
                results.append(
                    {
                        "id": case["id"],
                        "passed": False,
                        "status": "failed",
                        "errors": validation_errors,
                    }
                )
                continue

            programs: dict[str, dict[str, Any]] = {}
            import_errors: list[str] = []
            for alias, source in (case.get("imports") or {}).items():
                imported, errors = _load_program(corpus_file.parent / source, schema)
                import_errors.extend(f"import:{alias}:{error}" for error in errors)
                programs[alias] = imported
                programs[imported["id"]] = imported
            if import_errors:
                results.append({"id": case["id"], "passed": False, "status": "failed", "errors": import_errors})
                continue

            episodes = [
                execute_pure(
                    program,
                    inputs=case.get("input") or {},
                    programs=programs,
                    events=case.get("events") or {},
                )
                for _ in range(case.get("repetitions") or 1)
            ]
            first = episodes[0]
            errors: list[str] = []
            expected_status = case.get("expected_status")
            if expected_status and first["status"] != expected_status:
                errors.append(f"status:{first['status']}:{expected_status}")
            if "expected_outputs" in case and first["outputs"] != case["expected_outputs"]:
                errors.append("outputs_mismatch")
            decisions = [event["decision"] for event in first["trace"]]
            for decision in case.get("expected_decisions", []):
                if decision not in decisions:
                    errors.append(f"decision_missing:{decision}")
            emitted = [event["event"] for event in first["emitted_events"]]
            for event in case.get("expected_emitted_events", []):
                if event not in emitted:
                    errors.append(f"emitted_event_missing:{event}")
            if len({episode["trace_digest"] for episode in episodes}) != 1:
                errors.append("trace_nondeterministic")
            if len({episode["output_digest"] for episode in episodes}) != 1:
                errors.append("output_nondeterministic")
            results.append(
                {
                    "id": case["id"],
                    "passed": not errors,
                    "status": "passed" if not errors else "failed",
                    "trace_digest": first["trace_digest"],
                    "output_digest": first["output_digest"],
                    "errors": errors,
                }
            )
        except Exception as error:  # noqa: BLE001 - corpus reports failures as data
            results.append(
                {
                    "id": case.get("id", "unknown"),
                    "passed": False,
                    "status": "failed",
                    "errors": [str(error)],
                }
            )

    failed = sum(not item["passed"] for item in results)
    return {
        "contract_version": "1.0.0",
        "corpus_id": corpus["id"],
        "corpus_digest": digest_value(corpus),
        "implementation": "python_independent",
        "status": "failed" if failed else "passed",
        "passed": len(results) - failed,
        "failed": failed,
        "cases": results,
    }


def compare_results(reference: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    differences: list[str] = []
    for field in ("contract_version", "corpus_id", "corpus_digest", "status", "passed", "failed"):
        if reference.get(field) != candidate.get(field):
            differences.append(f"result:{field}:{reference.get(field)}:{candidate.get(field)}")
    reference_cases = {item["id"]: item for item in reference.get("cases", [])}
    candidate_cases = {item["id"]: item for item in candidate.get("cases", [])}
    for case_id in sorted(reference_cases.keys() | candidate_cases.keys()):
        if case_id not in reference_cases:
            differences.append(f"case_unexpected:{case_id}")
            continue
        if case_id not in candidate_cases:
            differences.append(f"case_missing:{case_id}")
            continue
        left, right = reference_cases[case_id], candidate_cases[case_id]
        for field in ("passed", "status", "trace_digest", "output_digest", "errors"):
            if left.get(field) != right.get(field):
                differences.append(f"case:{case_id}:{field}")
    return {
        "contract_version": "1.0.0",
        "corpus_id": reference.get("corpus_id") or candidate.get("corpus_id"),
        "reference_implementation": reference.get("implementation"),
        "candidate_implementation": candidate.get("implementation"),
        "status": "match" if not differences else "mismatch",
        "differences": differences,
    }


def write_json(path: str | Path, value: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
