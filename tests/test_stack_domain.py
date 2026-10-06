"""Boundary regressions for the declared finite stack carrier."""
import unittest

from pathseal.model import ModelError, execute_segment, validate_program
from checker.independent_checker import CheckFailure, _segment, _validate_program
from checker.independent_checker import check_certificate
from pathseal.producer import produce_certificate


def program(pointer_size=3, depth=0, ops=None):
    return {
        "name": "stack-domain-boundary",
        "fields": [
            {"name": "sp", "size": pointer_size, "role": "stack"},
            {"name": "s0", "size": 2, "role": "stack"},
            {"name": "s1", "size": 2, "role": "stack"},
        ],
        "stack": {"pointer": "sp", "slots": ["s0", "s1"]},
        "segments": [{"id": "s", "ops": ops or []}],
        "path": ["s"],
        "initial_domain": [{"sp": depth, "s0": 0, "s1": 0}],
        "final_fields": ["sp", "s0", "s1"],
    }


class StackDomainTests(unittest.TestCase):
    def check_both(self, subject):
        validate_program(subject)
        _validate_program(subject)
        initial = subject["initial_domain"][0]
        producer = execute_segment(subject, "s", initial)
        consumer = _segment(subject, "s", initial)
        self.assertEqual(producer.status, consumer["status"])
        self.assertEqual(producer.state, consumer["state"])
        self.assertEqual(
            [[name, list(values)] for name, values in producer.events],
            consumer["events"],
        )
        return producer

    def test_declaration_requires_exact_pointer_carrier(self):
        for size in (2, 4, 5):
            with self.subTest(size=size):
                subject = program(pointer_size=size)
                with self.assertRaises(ModelError):
                    validate_program(subject)
                with self.assertRaises(CheckFailure):
                    _validate_program(subject)

    def test_out_of_carrier_initial_depth_is_rejected(self):
        subject = program(depth=3)
        with self.assertRaises(ModelError):
            validate_program(subject)
        with self.assertRaises(CheckFailure):
            _validate_program(subject)

    def test_all_declared_depths_have_defined_stack_results(self):
        for depth in range(3):
            for op in ("push", "pop"):
                with self.subTest(depth=depth, op=op):
                    result = self.check_both(program(depth=depth, ops=[{"op": op, "expr": 0}]))
                    failing = (op == "push" and depth == 2) or (op == "pop" and depth == 0)
                    self.assertEqual(result.status, "stack_error" if failing else "ok")
                    self.assertEqual(result.state["sp"], depth if failing else depth + (1 if op == "push" else -1))

    def test_pointer_writes_stay_in_declared_carrier(self):
        for value in range(-6, 10):
            with self.subTest(value=value):
                result = self.check_both(program(ops=[
                    {"op": "set", "field": "sp", "expr": value},
                    {"op": "pop", "expr": 0},
                ]))
                depth = value % 3
                self.assertEqual(result.status, "stack_error" if depth == 0 else "ok")
                self.assertEqual(result.state["sp"], 0 if depth == 0 else depth - 1)

    def test_mismatched_top_token_is_a_defined_error(self):
        result = self.check_both(program(depth=2, ops=[{"op": "pop", "expr": 1}]))
        self.assertEqual(result.status, "stack_error")
        self.assertEqual(result.state["sp"], 2)

    def test_pop_normalizes_a_legal_out_of_carrier_constant(self):
        subject = program(ops=[{"op": "push", "expr": 1}, {"op": "pop", "expr": 3}])
        result = self.check_both(subject)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.state, {"sp": 0, "s0": 0, "s1": 0})
        certificate = produce_certificate(subject)
        self.assertEqual(check_certificate(certificate)["status"], "PASS")
        self.assertEqual(certificate["whole_entries"][0]["result"]["out"], result.state)

    def test_pop_rejects_a_different_normalized_token(self):
        subject = program(ops=[{"op": "push", "expr": 1}, {"op": "pop", "expr": 2}])
        result = self.check_both(subject)
        self.assertEqual(result.status, "stack_error")
        self.assertEqual(result.state, {"sp": 1, "s0": 1, "s1": 0})
        certificate = produce_certificate(subject)
        self.assertEqual(check_certificate(certificate)["status"], "PASS")
        self.assertEqual(certificate["whole_entries"][0]["result"]["out"], {})

    def test_each_pop_uses_its_selected_slot_modulus(self):
        subject = program(ops=[
            {"op": "push", "expr": -1}, {"op": "push", "expr": 2},
            {"op": "pop", "expr": 5}, {"op": "pop", "expr": 3},
        ])
        subject["fields"][2]["size"] = 3
        result = self.check_both(subject)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.state, {"sp": 0, "s0": 0, "s1": 0})
        self.assertEqual(check_certificate(produce_certificate(subject))["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
