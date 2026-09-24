from __future__ import annotations

import copy
import json
import unittest

from checker.independent_checker import CheckFailure, check_certificate
from pathseal.generator import make_program
from pathseal.model import execute_segment, field_order
from pathseal.producer import (
    baseline_metrics,
    produce_certificate,
    projection_metrics,
    rejection_certificate,
)


class PathSealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = make_program("unit", "small", 19)
        cls.certificate = produce_certificate(cls.program, include_rejections=True)

    def test_checker_accepts_producer_certificate(self):
        report = check_certificate(self.certificate)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["stages"], len(self.program["path"]))

    def test_generator_is_deterministic(self):
        self.assertEqual(self.program, make_program("unit", "small", 19))

    def test_dead_field_is_removed_from_minimum_keys(self):
        for stage in self.certificate["stages"]:
            self.assertNotIn("dead0", stage["key_fields"])

    def test_pathseal_projection_is_exact(self):
        for stage in self.certificate["stages"]:
            metrics = projection_metrics(
                self.program,
                stage["segment"],
                stage["domain"],
                stage["out_fields"],
                stage["key_fields"],
            )
            self.assertTrue(metrics["exact"])
            self.assertEqual(metrics["error_states"], 0)

    def test_call_context_projection_has_counterexample(self):
        stage = self.certificate["stages"][0]
        fields = ["ctx", "sp", "stk0", "stk1"]
        rejection = rejection_certificate(
            self.program, stage["segment"], stage["domain"], stage["out_fields"], fields
        )
        self.assertFalse(rejection["exact"])
        self.assertIsNotNone(rejection["witness"])
        self.assertTrue(rejection["repair_fields"])

    def test_support_baseline_is_exact(self):
        rows = baseline_metrics(self.program, self.certificate)
        support = [row for row in rows if row["baseline"] == "support"]
        self.assertTrue(support)
        self.assertTrue(all(row["exact"] for row in support))

    def test_push_pop_success_and_mismatch(self):
        state = dict(self.program["initial_domain"][0])
        source = execute_segment(self.program, "source", state)
        self.assertEqual(source.status, "ok")
        self.assertEqual(source.state["sp"], 1)
        good = execute_segment(self.program, "return", source.state)
        self.assertEqual(good.status, "ok")
        changed = dict(source.state)
        changed["ctx"] = (changed["ctx"] + 1) % 4
        bad = execute_segment(self.program, "return", changed)
        self.assertEqual(bad.status, "stack_error")

    def test_table_mutation_is_rejected(self):
        mutated = copy.deepcopy(self.certificate)
        entry = mutated["stages"][-1]["entries"][0]
        entry["result"]["events"][0][0] = "mutated"
        with self.assertRaises(CheckFailure):
            check_certificate(mutated)

    def test_minimum_key_mutation_is_rejected(self):
        mutated = copy.deepcopy(self.certificate)
        mutated["stages"][0]["key_fields"].append("dead0")
        with self.assertRaises(CheckFailure):
            check_certificate(mutated)

    def test_support_receipt_mutation_is_rejected(self):
        mutated = copy.deepcopy(self.certificate)
        mutated["stages"][0]["support_fields"].append("dead0")
        with self.assertRaises(CheckFailure):
            check_certificate(mutated)

    def test_unknown_top_level_field_is_rejected(self):
        mutated = copy.deepcopy(self.certificate)
        mutated["unexpected"] = 1
        with self.assertRaises(CheckFailure):
            check_certificate(mutated)

    def test_unknown_stage_field_is_rejected(self):
        mutated = copy.deepcopy(self.certificate)
        mutated["stages"][0]["unexpected"] = 1
        with self.assertRaises(CheckFailure):
            check_certificate(mutated)

    def test_rejection_label_swap_is_rejected(self):
        mutated = copy.deepcopy(self.certificate)
        rejections = mutated["stages"][0]["rejections"]
        rejections["empty"], rejections["call-context"] = (
            rejections["call-context"],
            rejections["empty"],
        )
        with self.assertRaises(CheckFailure):
            check_certificate(mutated)

    def test_json_round_trip(self):
        encoded = json.dumps(self.certificate, sort_keys=True)
        decoded = json.loads(encoded)
        self.assertEqual(check_certificate(decoded)["status"], "PASS")

    def test_field_order_is_stable(self):
        order = field_order(self.program)
        self.assertEqual(order[0], "input")
        self.assertEqual(order[-1], "dead0")


if __name__ == "__main__":
    unittest.main()
