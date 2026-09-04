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
from mirai_conformance.autonomic import check_autonomic
from mirai_conformance.validator import load_json, validate_program
from mirai_conformance.retrieval import check_retrieval, validate_federated_result


MIRAI = Path(os.environ.get("MIRAI_REPO", Path(__file__).resolve().parents[2] / "mirai-graph")).resolve()
CORPUS = MIRAI / "conformance/corpus/pure/corpus.json"
PROGRAM_SCHEMA = MIRAI / "schemas/mirai-program.schema.json"
PURE_EPISODE_SCHEMA = MIRAI / "schemas/mirai-pure-episode.schema.json"
SANITIZED_EVIDENCE_SCHEMA = MIRAI / "schemas/mirai-sanitized-evidence.schema.json"
ACTIVATION_PLAN_SCHEMA = MIRAI / "schemas/activation-plan.schema.json"
ACTIVATION_RUN_SCHEMA = MIRAI / "schemas/activation-run-result.schema.json"
AUTONOMIC = MIRAI / "examples/mirai-autonomic-fabric-minimal/results"


class CheckerTests(unittest.TestCase):
    def test_retrieval_artifacts_pass_independently(self) -> None:
        results = MIRAI / "examples/mirai-retrieval-minimal/results"
        cases = [
            ("index-descriptor", "index-descriptor.json", "retrieval-index-descriptor.schema.json"),
            ("plan", "plan.json", "retrieval-plan.schema.json"),
            ("evidence-bundle", "evidence-bundle.json", "retrieval-evidence-bundle.schema.json"),
            ("evaluation", "evaluation.json", "retrieval-evaluation.schema.json"),
        ]
        for kind, artifact, schema in cases:
            result = check_retrieval(kind, load_json(results / artifact), load_json(MIRAI / "schemas" / schema))
            self.assertEqual(result["status"], "passed", result)
        answer = check_retrieval(
            "answer", load_json(results / "answer.json"), load_json(MIRAI / "schemas/retrieval-answer.schema.json"),
            evidence=load_json(results / "evidence-bundle.json"),
        )
        self.assertEqual(answer["status"], "passed", answer)

    def test_retrieval_claim_without_evidence_is_rejected(self) -> None:
        answer = load_json(MIRAI / "examples/mirai-retrieval-minimal/results/answer.json")
        tampered = copy.deepcopy(answer)
        tampered["claims"][0]["evidence_refs"] = []
        tampered["digest"] = digest_value({key: value for key, value in tampered.items() if key != "digest"})
        result = check_retrieval("answer", tampered, load_json(MIRAI / "schemas/retrieval-answer.schema.json"))
        self.assertEqual(result["status"], "failed")

    def test_retrieval_semantic_binding_is_complete(self) -> None:
        descriptor = load_json(MIRAI / "examples/mirai-retrieval-minimal/results/index-descriptor.json")
        semantic = copy.deepcopy(descriptor)
        semantic.update({
            "semantic_status": "ready",
            "semantic_model": "model.demo",
            "semantic_revision": None,
            "semantic_files_digest": None,
            "dimensions": 384,
        })
        semantic["digest"] = digest_value({key: value for key, value in semantic.items() if key not in {"digest", "built_at"}})
        result = check_retrieval(
            "index-descriptor", semantic,
            load_json(MIRAI / "schemas/retrieval-index-descriptor.schema.json"),
        )
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("semantic_revision" in error or "semantic_files_digest" in error for error in result["errors"]), result)

    def test_federated_retrieval_rejects_out_of_scope_hits_and_budget_overrun(self) -> None:
        envelope = {
            "id": "query.demo", "requester": {"source_refs": ["source.allowed"], "scopes": ["scope.allowed"]},
            "token_budget": 10, "cost_budget": 1,
        }
        evidence = {
            "contract_version": "1.0.0", "query_digest": "sha256:" + "a" * 64,
            "index_digest": "sha256:" + "b" * 64, "graph_digest": None,
            "policy_digest": "sha256:" + "c" * 64,
            "hits": [{"document_id": "forbidden", "source_ref": "source.forbidden", "scope": "scope.forbidden", "evidence_refs": ["evidence.demo"], "instructions_authorized": False}],
            "source_refs": ["source.forbidden"], "conflicts": [], "limitations": [], "partial": False,
            "instructions_authorized": False, "canonical_write_allowed": False,
        }
        evidence["digest"] = digest_value(evidence)
        result = {
            "query_id": "query.demo", "query_digest": evidence["query_digest"], "policy_digest": evidence["policy_digest"],
            "evidence_bundle": evidence, "usage": {"tokens_used": 11, "cost_used": 0, "duration_ms": 1},
            "instructions_authorized": False, "canonical_write_allowed": False,
        }
        result["digest"] = digest_value(result)
        errors = validate_federated_result(result, envelope)
        self.assertIn("federated_result:source_scope_violation", errors)
        self.assertIn("federated_result:hit_scope_violation:forbidden", errors)
        self.assertIn("federated_result:budget_exceeded", errors)

    def test_autonomic_fabric_artifacts_pass_independently(self) -> None:
        cases = [
            ("source-snapshot", "source-snapshot.json", "source-snapshot.schema.json"),
            ("knowledge-proposal", "knowledge-proposal.json", "knowledge-proposal.schema.json"),
            ("autonomy-envelope", "autonomy-envelope.json", "autonomy-envelope.schema.json"),
            ("evolution-proposal", "evolution-proposal.json", "evolution-proposal.schema.json"),
            ("autonomic-cycle", "autonomic-cycle.json", "autonomic-cycle.schema.json"),
        ]
        for kind, artifact, schema in cases:
            result = check_autonomic(kind, load_json(AUTONOMIC / artifact), load_json(MIRAI / "schemas" / schema))
            self.assertEqual(result["status"], "passed", result)
        observations = load_json(AUTONOMIC / "process-observations.json")["observations"]
        candidates = load_json(AUTONOMIC / "process-candidates.json")["candidates"]
        for value in observations:
            result = check_autonomic("process-observation", value, load_json(MIRAI / "schemas/process-observation.schema.json"))
            self.assertEqual(result["status"], "passed", result)
        for value in candidates:
            result = check_autonomic("process-candidate", value, load_json(MIRAI / "schemas/process-candidate.schema.json"))
            self.assertEqual(result["status"], "passed", result)

    def test_autonomic_decision_rejects_unsafe_automatic_promotion(self) -> None:
        proposal = load_json(AUTONOMIC / "evolution-proposal.json")
        envelope = load_json(AUTONOMIC / "autonomy-envelope.json")
        decision = load_json(AUTONOMIC / "evolution-decision.json")
        unsafe = copy.deepcopy(proposal)
        payload = {"self_grant": True}
        unsafe["changes"] = [{
            "id": "change.protected", "kind": "protected_invariant",
            "target_ref": "system/protected/safety", "stratum": "system_protected",
            "operation": "upsert", "payload": payload, "payload_digest": digest_value(payload),
            "risk": "critical", "confidence": 1, "reversible": False, "effectful": True,
            "evidence_refs": [], "successful_replay_refs": [], "conflict_refs": [],
        }]
        unsafe["digest"] = digest_value({key: value for key, value in unsafe.items() if key != "digest"})
        forged = copy.deepcopy(decision)
        forged["proposal_digest"] = unsafe["digest"]
        forged["change_decisions"] = [{"change_id": "change.protected", "verdict": "allow_automatic", "reason_codes": []}]
        forged["verdict"] = "automatic_promotion_allowed"
        forged["digest"] = digest_value({key: value for key, value in forged.items() if key != "digest"})
        result = check_autonomic(
            "evolution-decision", forged, load_json(MIRAI / "schemas/evolution-decision.schema.json"),
            proposal=unsafe, envelope=envelope,
        )
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("decision_mismatch" in item for item in result["errors"]))

    def test_autonomic_decision_rejects_budget_and_identity_bypasses(self) -> None:
        proposal = load_json(AUTONOMIC / "evolution-proposal.json")
        envelope = load_json(AUTONOMIC / "autonomy-envelope.json")
        decision = load_json(AUTONOMIC / "evolution-decision.json")
        payload = {"relation_ref": "relation.budget"}
        change = {
            "id": "change.budget", "kind": "derived_navigation",
            "target_ref": "adaptive/navigation/budget", "stratum": "adaptive_canonical",
            "operation": "upsert", "payload": payload, "payload_digest": digest_value(payload),
            "risk": "low", "confidence": 1, "reversible": True, "effectful": False,
            "evidence_refs": ["evidence:fixture"], "successful_replay_refs": [], "conflict_refs": [],
        }
        oversized = copy.deepcopy(proposal)
        oversized["changes"] = [change]
        oversized["digest"] = digest_value({key: value for key, value in oversized.items() if key != "digest"})
        tiny = copy.deepcopy(envelope)
        tiny["change_budget"] = {"max_changes": 1, "max_payload_bytes": 1}
        tiny["digest"] = digest_value({key: value for key, value in tiny.items() if key != "digest"})
        forged = copy.deepcopy(decision)
        forged["proposal_id"] = oversized["id"]
        forged["proposal_digest"] = oversized["digest"]
        forged["envelope_id"] = tiny["id"]
        forged["envelope_digest"] = tiny["digest"]
        forged["change_decisions"] = [{"change_id": "change.budget", "verdict": "allow_automatic", "reason_codes": []}]
        forged["verdict"] = "automatic_promotion_allowed"
        forged["digest"] = digest_value({key: value for key, value in forged.items() if key != "digest"})
        result = check_autonomic(
            "evolution-decision", forged, load_json(MIRAI / "schemas/evolution-decision.schema.json"),
            proposal=oversized, envelope=tiny,
        )
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("decision_mismatch" in item or "aggregate_verdict_mismatch" in item for item in result["errors"]))

        unsafe_id = copy.deepcopy(oversized)
        unsafe_id["id"] = "../../../outside"
        unsafe_id["digest"] = digest_value({key: value for key, value in unsafe_id.items() if key != "digest"})
        invalid = check_autonomic(
            "evolution-proposal", unsafe_id, load_json(MIRAI / "schemas/evolution-proposal.schema.json")
        )
        self.assertEqual(invalid["status"], "failed")
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

    def test_technology_qualification_and_hybrid_plan_pass_independently(self) -> None:
        root = MIRAI / "examples/mirai-technology-qualification-minimal"
        qualification = load_json(root / "qualification-result.json")
        hybrid = load_json(root / "hybrid-technology-plan.json")
        qualification_result = check_graph_native(
            "technology-qualification", qualification,
            load_json(MIRAI / "schemas/technology-qualification.schema.json")
        )
        hybrid_result = check_graph_native(
            "hybrid-technology-plan", hybrid,
            load_json(MIRAI / "schemas/hybrid-technology-plan.schema.json")
        )
        self.assertEqual(qualification_result["status"], "passed", qualification_result)
        self.assertEqual(hybrid_result["status"], "passed", hybrid_result)

    def test_technology_qualification_authority_tampering_is_rejected(self) -> None:
        root = MIRAI / "examples/mirai-technology-qualification-minimal"
        qualification = load_json(root / "qualification-result.json")
        tampered = copy.deepcopy(qualification)
        tampered["activation_allowed"] = True
        result = check_graph_native(
            "technology-qualification", tampered,
            load_json(MIRAI / "schemas/technology-qualification.schema.json")
        )
        self.assertEqual(result["status"], "failed")

    def test_shadow_differential_passes_and_false_green_is_rejected(self) -> None:
        artifact = load_json(MIRAI / "examples/mirai-shadow-differential-minimal/shadow-result.json")
        schema = load_json(MIRAI / "schemas/shadow-differential-result.schema.json")
        passing = check_graph_native("shadow-differential-result", artifact, schema)
        self.assertEqual(passing["status"], "passed", passing)
        tampered = copy.deepcopy(artifact)
        tampered["mandatory_closure"]["missing_step_ids"] = ["step.required"]
        tampered["digest"] = digest_value({key: value for key, value in tampered.items() if key != "digest"})
        failing = check_graph_native("shadow-differential-result", tampered, schema)
        self.assertEqual(failing["status"], "failed")
        self.assertIn("shadow:blocker_summary_mismatch", failing["errors"])


if __name__ == "__main__":
    unittest.main()
