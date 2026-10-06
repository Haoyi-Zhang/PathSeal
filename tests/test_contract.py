"""Benign finite regressions for observations and typed certificate values."""
import copy
import json
import unittest

from checker.independent_checker import CheckFailure, _same_json, check_certificate
from pathseal.model import execute_segment, validate_program
from pathseal.producer import produce_certificate


def program(ops=None):
    return {
        "name": "finite-contract-regression",
        "fields": [
            {"name": "x", "size": 2, "role": "source"},
            {"name": "sp", "size": 3, "role": "stack"},
            {"name": "s0", "size": 2, "role": "stack"},
            {"name": "s1", "size": 2, "role": "stack"},
        ],
        "stack": {"pointer": "sp", "slots": ["s0", "s1"]},
        "segments": [{"id": "s", "ops": ops if ops is not None else [
            {"op": "emit", "event": "seen", "args": [{"field": "x"}]},
        ]}],
        "path": ["s"],
        "initial_domain": [{"x": x, "sp": 0, "s0": 0, "s1": 0} for x in range(2)],
        "final_fields": ["x", "sp", "s0", "s1"],
    }


class ObservationTests(unittest.TestCase):
    def test_success_keeps_the_existing_helper_tuple(self):
        subject = program()
        validate_program(subject)
        result = execute_segment(subject, "s", subject["initial_domain"][1])
        self.assertEqual(result.observable(["x"]), ("ok", (("seen", (1,)),), (("x", 1),)))

    def check_failed_observations(self, failing_op, status):
        subject = program([{"op": "emit", "event": "prefix", "args": [7]}, failing_op])
        validate_program(subject)
        results = [execute_segment(subject, "s", state) for state in subject["initial_domain"]]
        self.assertNotEqual(results[0].state["x"], results[1].state["x"])
        for result in results:
            self.assertEqual(result.observable(["x"]), (status, (("prefix", (7,)),), None))
            self.assertEqual(result.observable([])[2], None)
            self.assertEqual(result.as_json(["x"])["out"], {})
        self.assertEqual(results[0].observable(["x"]), results[1].observable(["x"]))
        self.assertEqual(check_certificate(produce_certificate(subject))["status"], "PASS")

    def test_infeasible_observations_hide_failure_state(self):
        self.check_failed_observations({"op": "assume", "expr": 0}, "infeasible")

    def test_stack_error_observations_hide_failure_state(self):
        self.check_failed_observations({"op": "pop", "expr": 0}, "stack_error")


class CertificateTypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificate = produce_certificate(program(), include_rejections=True)

    def check_integer_paths(self, paths):
        for path in paths:
            original = self.certificate
            for component in path:
                original = original[component]
            self.assertIs(type(original), int)
            replacements = [float(original)]
            if original in (0, 1):
                replacements.append(bool(original))
            for value in replacements:
                with self.subTest(path=path, replacement_type=type(value).__name__):
                    subject = copy.deepcopy(self.certificate)
                    target = subject
                    for component in path[:-1]:
                        target = target[component]
                    target[path[-1]] = value
                    with self.assertRaises(CheckFailure):
                        check_certificate(subject)

    def test_typed_certificate_and_boolean_verdicts_are_accepted(self):
        self.assertEqual(check_certificate(self.certificate)["status"], "PASS")
        verdicts = self.certificate["stages"][0]["rejections"]
        self.assertIs(verdicts["security-surface"]["exact"], True)
        self.assertIs(verdicts["empty"]["exact"], False)

    def test_json_round_trip_preserves_accepted_types(self):
        subject = json.loads(json.dumps(self.certificate))
        self.assertTrue(_same_json(subject, self.certificate))
        self.assertEqual(check_certificate(subject)["status"], "PASS")

    def test_recursive_comparison_distinguishes_scalar_and_container_types(self):
        self.assertTrue(_same_json({"values": [0, True, None]}, {"values": [0, True, None]}))
        self.assertTrue(_same_json({"b": 1, "a": 0}, {"a": 0, "b": 1}))
        self.assertFalse(_same_json({"values": [False]}, {"values": [0]}))
        self.assertFalse(_same_json([1.0], [1]))
        self.assertFalse(_same_json((1,), [1]))
        self.assertFalse(_same_json([0], []))
        self.assertFalse(_same_json({"extra": 0}, {}))

    def test_stage_index_and_domain_values_are_integers(self):
        self.check_integer_paths([
            ("stages", 0, "index"), ("stages", 0, "domain", 0, "x"),
        ])

    def test_local_keys_outputs_and_event_arguments_are_integers(self):
        self.check_integer_paths([
            ("stages", 0, "entries", 0, "key", "x"),
            ("stages", 0, "entries", 0, "result", "out", "x"),
            ("stages", 0, "entries", 0, "result", "events", 0, 1, 0),
        ])

    def test_collision_count_is_an_integer(self):
        self.check_integer_paths([("stages", 0, "minimality", "collision_masks")])

    def test_whole_keys_outputs_and_event_arguments_are_integers(self):
        self.check_integer_paths([
            ("whole_entries", 0, "key", "x"),
            ("whole_entries", 0, "result", "out", "x"),
            ("whole_entries", 0, "result", "events", 0, 1, 0),
        ])

    def test_production_counts_are_integers(self):
        self.check_integer_paths([
            ("production", "programs"), ("production", "stages"), ("production", "domain_states"),
        ])

    def test_witness_states_and_results_are_typed(self):
        prefix = ("stages", 0, "rejections", "empty", "witness")
        self.check_integer_paths([
            prefix + ("left", "x"), prefix + ("right", "x"),
            prefix + ("left_result", "out", "x"),
            prefix + ("right_result", "out", "x"),
            prefix + ("left_result", "events", 0, 1, 0),
            prefix + ("right_result", "events", 0, 1, 0),
        ])

    def test_legitimate_empty_query_and_failure_tables_are_accepted(self):
        subject = program([{"op": "assume", "expr": 0}])
        subject["final_fields"] = []
        self.assertEqual(check_certificate(produce_certificate(subject))["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
