from __future__ import annotations
import copy
import json
import os
import unittest
from pathlib import Path

from mirai_conformance.canonical import digest_value
from mirai_conformance.organization import check_bundle
from mirai_conformance.validator import validate_program
from mirai_conformance.canonical import program_digest


class OrganizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("MIRAI_ORGANIZATION_BUNDLE")
        if not value:
            raise unittest.SkipTest("Set MIRAI_ORGANIZATION_BUNDLE to the local pilot corpus")
        cls.bundle = json.loads(Path(value).read_text())
        cls.schemas = Path(os.environ["MIRAI_REPO"]) / "schemas"

    def check(self, bundle):
        return check_bundle(bundle, self.schemas)

    def test_positive_no_authority_claim(self):
        result = self.check(self.bundle)
        self.assertTrue(result["valid"])
        self.assertFalse(result["authority_verified"])
        self.assertEqual(result["provider_calls"], 0)

    def test_chronological_history_cannot_skip_or_relabel_execution(self):
        value = copy.deepcopy(self.bundle)
        self.assertIn("history_record", value, "Regenerate the bounded pilot corpus")
        value["record"] = value["history_record"]
        self.assertTrue(self.check(value)["valid"])
        for mode in ["omit", "reorder", "relabel"]:
            changed = copy.deepcopy(value)
            events = changed["record"]["ledger"]["history"]
            if mode == "omit":
                events.clear()
            elif mode == "reorder":
                events.reverse()
            else:
                events[0]["kind"] = "verify"
                events[0]["digest"] = digest_value({k: v for k, v in events[0].items() if k != "digest"})
            changed["record"]["digest"] = digest_value({k: v for k, v in changed["record"].items() if k != "digest"})
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.check(changed)

    def test_scoped_keys_bind_the_parent_execution(self):
        value = copy.deepcopy(self.bundle)
        ledger = value["record"]["ledger"]
        ledger["contract_version"] = "1.1.0"
        ledger["execution_scope"] = digest_value("synthetic.parent.one")
        for task_id, task in ledger["tasks"].items():
            task["idempotency_key"] = digest_value({"plan": ledger["plan"]["digest"], "task": task_id,
                "request": task["request_digest"], "execution_scope": ledger["execution_scope"]})
        def reseal():
            value["record"]["digest"] = digest_value({k: v for k, v in value["record"].items() if k != "digest"})
        reseal()
        self.assertTrue(self.check(value)["valid"])
        ledger["execution_scope"] = digest_value("synthetic.parent.two")
        reseal()
        with self.assertRaises(ValueError):
            self.check(value)
        ledger["contract_version"] = "1.0.0"
        reseal()
        with self.assertRaises(ValueError):
            self.check(value)

    def test_cluster_incorrect_membership_is_not_fixed_by_a_new_hash(self):
        value = copy.deepcopy(self.bundle)
        value["clusters"]["groups"][0]["member_ids"] = ["unclassified"]
        body = {k: v for k, v in value["clusters"].items() if k != "digest"}
        value["clusters"]["digest"] = digest_value(body)
        with self.assertRaises(ValueError):
            self.check(value)

    def test_forged_completion_and_acceptance_fail_closed(self):
        for field, invalid in [("receipt_state", "uncertain"), ("result_digest", digest_value("fake")), ("idempotency_key", digest_value("fake"))]:
            value = copy.deepcopy(self.bundle)
            task = next(iter(value["record"]["ledger"]["tasks"].values()))
            task[field] = invalid
            value["record"]["digest"] = digest_value({k: v for k, v in value["record"].items() if k != "digest"})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(value)

    def test_self_acceptance_and_missing_evidence_fail(self):
        for mode in ["self", "evidence"]:
            value = copy.deepcopy(self.bundle)
            task = next(iter(value["record"]["ledger"]["tasks"].values()))
            if mode == "self":
                task["acceptance_receipt"]["reviewer"] = task["request"]["receiver_id"]
            else:
                task["result"]["evidence"] = []
                task["result_digest"] = digest_value(task["result"])
            value["record"]["digest"] = digest_value({k: v for k, v in value["record"].items() if k != "digest"})
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.check(value)

    def test_context_digest_cannot_be_replaced_by_an_outer_hash(self):
        value = copy.deepcopy(self.bundle)
        next(iter(value["record"]["ledger"]["tasks"].values()))["input_snapshot_digest"] = digest_value("different context")
        value["record"]["digest"] = digest_value({k: v for k, v in value["record"].items() if k != "digest"})
        with self.assertRaisesRegex(ValueError, "context_snapshot_binding"):
            self.check(value)

    def test_sensitive_property_names_fail_at_graph_admission(self):
        value = copy.deepcopy(self.bundle)
        value["graph"]["objects"][0]["metadata"] = {
            "nested": {"ghp_1234567890abcdefghij": "redacted"}
        }
        value["graph"]["digest"] = digest_value({
            key: item for key, item in value["graph"].items() if key != "digest"
        })
        with self.assertRaisesRegex(ValueError, "sensitive_content_rejected"):
            self.check(value)

    def test_program_task_binding_requires_version_effect_and_capability(self):
        program = json.loads((self.schemas.parent / "examples/mirai-task-runtime-minimal/main.mirai.json").read_text())
        schema = json.loads((self.schemas / "mirai-program.schema.json").read_text())
        self.assertEqual(validate_program(program, schema, catalog=self.bundle["catalog"]), [])
        for mode in ("capability", "effect", "version", "catalog"):
            changed = copy.deepcopy(program)
            if mode == "capability":
                changed["nodes"][0].pop("capability")
            elif mode == "effect":
                changed["nodes"][0]["effects"] = ["pure"]
            elif mode == "version":
                changed["contract_version"] = "1.0.0"
                changed.pop("operation_catalog")
            else:
                changed["operation_catalog"]["digest"] = digest_value("wrong")
            changed["digest"] = program_digest(changed)
            with self.subTest(mode=mode):
                self.assertTrue(validate_program(changed, schema, catalog=self.bundle["catalog"]))
