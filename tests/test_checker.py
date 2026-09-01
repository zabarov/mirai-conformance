from __future__ import annotations

import copy
import os
import unittest
from pathlib import Path

from mirai_conformance.canonical import digest_value, program_digest
from mirai_conformance.corpus import compare_results, run_corpus
from mirai_conformance.expression import evaluate
from mirai_conformance.graph_native import check_graph_native
from mirai_conformance.runtime import validate_pure_episode, validate_sanitized_evidence
from mirai_conformance.project import check_project
from mirai_conformance.validator import load_json, validate_program


MIRAI = Path(os.environ.get("MIRAI_REPO", Path(__file__).resolve().parents[2] / "mirai-graph")).resolve()
CORPUS = MIRAI / "conformance/corpus/pure/corpus.json"
PROGRAM_SCHEMA = MIRAI / "schemas/mirai-program.schema.json"
PURE_EPISODE_SCHEMA = MIRAI / "schemas/mirai-pure-episode.schema.json"
SANITIZED_EVIDENCE_SCHEMA = MIRAI / "schemas/mirai-sanitized-evidence.schema.json"
ACTIVATION_PLAN_SCHEMA = MIRAI / "schemas/activation-plan.schema.json"
ACTIVATION_RUN_SCHEMA = MIRAI / "schemas/activation-run-result.schema.json"


class CheckerTests(unittest.TestCase):
    def test_project_capsule_passes_independently(self) -> None:
        result = check_project(MIRAI, MIRAI / "schemas")
        self.assertEqual(result["status"], "passed", result)

    def test_project_capsule_start_tampering_is_rejected(self) -> None:
        import tempfile
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "project"
            shutil.copytree(MIRAI / "mirai", target / "mirai")
            shutil.copy2(MIRAI / "graph.json", target / "graph.json")
            with (target / "mirai/START.md").open("a", encoding="utf-8") as stream:
                stream.write("tampered\n")
            result = check_project(target, MIRAI / "schemas")
            self.assertEqual(result["status"], "failed")
            self.assertIn("start:generated_content_mismatch", result["errors"])

    def test_project_capsule_accepts_crlf_portable_text(self) -> None:
        import tempfile
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "project"
            shutil.copytree(MIRAI / "mirai", target / "mirai")
            shutil.copy2(MIRAI / "graph.json", target / "graph.json")
            objects = target / "mirai/graph/specs/project.json"
            normalized = objects.read_bytes().replace(b"\r\n", b"\n")
            objects.write_bytes(normalized.replace(b"\n", b"\r\n"))
            result = check_project(target, MIRAI / "schemas")
            self.assertEqual(result["status"], "passed", result)
    def test_canonical_digest_matches_known_value(self) -> None:
        self.assertEqual(
            digest_value({"b": 2, "a": [True, "x"]}),
            "sha256:5161b6416bbdbfa51011a348b24247323398c24451cf13c2af7ca728a8a145bb",
        )

    def test_program_digest_ignores_source_map(self) -> None:
        program = load_json(MIRAI / "conformance/corpus/pure/ir/add.mirai.json")
        self.assertEqual(program_digest(program), program["digest"])
        program["source_map"]["calculate"]["line"] = 999
        self.assertEqual(program_digest(program), program["digest"])

    def test_expression_ast(self) -> None:
        scope = {"input": {"value": 4}, "state": {"limit": 3}, "local": {}}
        self.assertTrue(
            evaluate(
                {
                    "op": "and",
                    "left": {"op": "gt", "left": {"op": "ref", "path": "input.value"}, "right": {"op": "ref", "path": "state.limit"}},
                    "right": {"op": "not", "value": {"op": "literal", "value": False}},
                },
                scope,
            )
        )

    def test_invalid_programs_fail_semantically(self) -> None:
        schema = load_json(PROGRAM_SCHEMA)
        loop = load_json(MIRAI / "conformance/corpus/pure/ir/invalid-unbounded-foreach.mirai.json")
        effect = load_json(MIRAI / "conformance/corpus/pure/ir/invalid-unknown-effect.mirai.json")
        self.assertTrue(any("unbounded_foreach" in item for item in validate_program(loop, schema)))
        self.assertTrue(any("unknown_effect" in item for item in validate_program(effect, schema)))

    def test_shared_corpus_passes(self) -> None:
        result = run_corpus(CORPUS, PROGRAM_SCHEMA)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["passed"], 13)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["corpus_digest"], "sha256:d78eddd364e95feeb99a377702f1ac92f0c5aa72124ff84826c0433de13df5cc")

    def test_compare_ignores_implementation_name_only(self) -> None:
        result = run_corpus(CORPUS, PROGRAM_SCHEMA)
        reference = {**result, "implementation": "typescript_reference"}
        comparison = compare_results(reference, result)
        self.assertEqual(comparison["status"], "match")

    def test_public_pure_episode_is_self_consistent(self) -> None:
        episode = load_json(MIRAI / "pilots/mirai-2-beta-federation/results/episode.json")
        schema = load_json(PURE_EPISODE_SCHEMA)
        program = load_json(MIRAI / "pilots/mirai-2-beta-federation/programs/results/program.mirai.json")
        self.assertEqual(validate_pure_episode(episode, schema, program), [])

    def test_pure_episode_digest_tampering_is_rejected(self) -> None:
        episode = load_json(MIRAI / "pilots/mirai-2-beta-ai-employee/results/episode.json")
        tampered = copy.deepcopy(episode)
        tampered["outputs"]["verdict"] = "accepted_without_recalculation"
        errors = validate_pure_episode(tampered, load_json(PURE_EPISODE_SCHEMA))
        self.assertIn("episode:output_digest_mismatch", errors)

    def test_sanitized_runtime_evidence_is_cross_checked(self) -> None:
        evidence = load_json(MIRAI / "pilots/mirai-2-beta-larena/results/mirai-evidence.json")
        self.assertEqual(
            validate_sanitized_evidence(evidence, load_json(SANITIZED_EVIDENCE_SCHEMA)),
            [],
        )

    def test_receipt_summary_mismatch_is_rejected(self) -> None:
        evidence = load_json(MIRAI / "pilots/mirai-2-beta-larena/results/mirai-evidence.json")
        tampered = copy.deepcopy(evidence)
        tampered["episode"]["effect_summaries"][0]["status"] = "compensated"
        errors = validate_sanitized_evidence(tampered, load_json(SANITIZED_EVIDENCE_SCHEMA))
        self.assertTrue(any("effect_summary" in item and "status_mismatch" in item for item in errors))

    def test_graph_native_activation_plan_and_run_pass_independently(self) -> None:
        pilot = MIRAI / "pilots/mirai-2.1-beta-federation"
        snapshot = load_json(pilot / "graph-snapshot.json")
        plan = load_json(pilot / "results/activation-plan.json")
        run = load_json(pilot / "results/activation-run-result.json")
        plan_result = check_graph_native(
            "activation-plan", plan, load_json(ACTIVATION_PLAN_SCHEMA), graph_snapshot=snapshot
        )
        run_result = check_graph_native(
            "activation-run-result", run, load_json(ACTIVATION_RUN_SCHEMA), activation_plan=plan
        )
        self.assertEqual(plan_result["status"], "passed", plan_result)
        self.assertEqual(run_result["status"], "passed", run_result)

    def test_graph_native_trace_tampering_is_rejected(self) -> None:
        pilot = MIRAI / "pilots/mirai-2.1-beta-federation"
        plan = load_json(pilot / "results/activation-plan.json")
        run = load_json(pilot / "results/activation-run-result.json")
        tampered = copy.deepcopy(run)
        tampered["path_results"][0]["output_digest"] = f"sha256:{'0' * 64}"
        result = check_graph_native(
            "activation-run-result", tampered, load_json(ACTIVATION_RUN_SCHEMA), activation_plan=plan
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("activation_run:aggregate_trace_digest_mismatch", result["errors"])

    def test_graph_native_component_and_relation_contracts_pass(self) -> None:
        pilot = MIRAI / "pilots/mirai-2.1-beta-federation"
        snapshot = load_json(pilot / "graph-snapshot.json")
        component_result = check_graph_native(
            "component-package", snapshot["components"], load_json(MIRAI / "schemas/component-package.schema.json")
        )
        relation_result = check_graph_native(
            "relation-fact", snapshot["relation_facts"][0], load_json(MIRAI / "schemas/relation-fact.schema.json")
        )
        self.assertEqual(component_result["status"], "passed", component_result)
        self.assertEqual(relation_result["status"], "passed", relation_result)

    def test_graph_native_ambiguous_dispatch_is_rejected(self) -> None:
        snapshot = load_json(MIRAI / "pilots/mirai-2.1-beta-federation/graph-snapshot.json")
        package = copy.deepcopy(snapshot["components"])
        package["contextual_bindings"].append({**package["contextual_bindings"][0], "id": "binding.duplicate"})
        result = check_graph_native(
            "component-package", package, load_json(MIRAI / "schemas/component-package.schema.json")
        )
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("ambiguous_dispatch" in item for item in result["errors"]))


if __name__ == "__main__":
    unittest.main()
