"""Portable finite checks for masks-only synthesis; no saved-result dependencies."""
from __future__ import annotations

import copy
import itertools
import json
import unittest
from unittest.mock import patch

from checker import independent_checker as checker
from pathseal import model, producer
from pathseal.generator import make_program


def scan_pair_reference(states, signatures, fields, restrict_equal_on=None, **_options):
    """Direct unordered-pair reference, always collecting records.

    This deliberately separate scan is a local comparison reference, not an
    original-version equivalence claim. The optional collection request is
    ignored so certificate comparisons also exercise discarded pair records.
    """
    pairs = []
    for (i, left), (j, right) in itertools.combinations(enumerate(states), 2):
        if signatures[i] == signatures[j]:
            continue
        if any(left[name] != right[name] for name in (restrict_equal_on or ())):
            continue
        difference = sum(2**pos for pos, name in enumerate(fields) if left[name] != right[name])
        if difference == 0:
            raise producer.CertificateError("determinism violated: identical states have different results")
        pairs.append((i, j, difference))
    return {difference for _, _, difference in pairs}, pairs


def exact_partition(states, observations, key):
    """Definition-level oracle: each projected fiber has one observation."""
    fibers = {}
    for state, observation in zip(states, observations, strict=True):
        projected = tuple(state[name] for name in key)
        if projected in fibers and fibers[projected] != observation:
            return False
        fibers[projected] = observation
    return True


def partition_minimum(states, observations, fields, fixed=()):
    allowed = [name for name in fields if name not in fixed]
    for width in range(len(allowed) + 1):
        for chosen in itertools.combinations(allowed, width):
            if exact_partition(states, observations, (*fixed, *chosen)):
                return list(chosen)
    raise AssertionError("finite deterministic observations must admit the full key")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def finite_fixtures():
    """Complete 108-state Cartesian carrier; no implicit input pruning."""
    fields = [
        {"name": "x", "size": 2, "role": "source"},
        {"name": "y", "size": 3, "role": "context"},
        {"name": "sp", "size": 3, "role": "stack"},
        {"name": "s0", "size": 2, "role": "stack"},
        {"name": "s1", "size": 3, "role": "stack"},
    ]
    names = [field["name"] for field in fields]
    domain = [dict(zip(names, values, strict=True))
              for values in itertools.product(*(range(field["size"]) for field in fields))]
    emit_x = {"op": "emit", "event": "a", "args": [{"field": "x"}]}
    emit_y = {"op": "emit", "event": "b", "args": [{"field": "y"}]}
    cases = [
        ("constant-empty-key", [], False, []),
        ("ordered-repeat", [emit_x, emit_y, emit_x], True, ["y"]),
        ("empty-successor", [emit_x, {"op": "assume", "expr": 0}, emit_y], True, names),
        ("mixed-status", [emit_y, {"op": "assume", "expr": {"field": "x"}},
                          {"op": "pop", "expr": {"field": "y"}}, emit_x], False, names),
        ("heterogeneous-stack", [{"op": "push", "expr": -1}, {"op": "push", "expr": 2},
                                 {"op": "pop", "expr": 5}, {"op": "pop", "expr": 3},
                                 emit_x], False, names),
        ("negative-pointer-write", [{"op": "set", "field": "sp", "expr": -1},
                                    {"op": "pop", "expr": 4}, emit_y], False, names),
        ("different-event-order", [emit_y, emit_x, emit_x], True, ["y"]),
    ]
    for name, ops, repeated, output in cases:
        yield {
            "name": name, "fields": copy.deepcopy(fields),
            "stack": {"pointer": "sp", "slots": ["s0", "s1"]},
            "segments": [{"id": "s", "ops": copy.deepcopy(ops)}],
            "path": ["s", "s"] if repeated else ["s"],
            "initial_domain": copy.deepcopy(list(reversed(domain))),
            "final_fields": list(output),
        }


def regression_programs():
    yield from finite_fixtures()
    for tier in ("small", "medium", "large"):
        for seed in (0, 1, 19):
            yield make_program(f"masks-{tier}-{seed}", tier, seed)


def reference_metrics(states, observations, fields, key):
    groups = {}
    errors = 0
    for state, observation in zip(states, observations, strict=True):
        projected = tuple(state[name] for name in key)
        if projected not in groups:
            groups[projected] = observation
        elif groups[projected] != observation:
            errors += 1
    masks, pairs = scan_pair_reference(states, observations, fields, key)
    return {
        "key_fields": list(key), "key_width": len(key), "distinct_keys": len(groups),
        "error_states": errors, "collision_pairs": len(pairs), "exact": not pairs,
        "reuse_factor": len(states) / max(1, len(groups)), "collision_masks": len(masks),
    }


class MasksOnlyTests(unittest.TestCase):
    def test_three_bit_complete_function_and_restriction_census(self):
        fields = ["a", "b", "c"]
        states = [dict(zip(fields, values, strict=True))
                  for values in itertools.product((0, 1), repeat=3)]
        for function in range(256):
            observations = [(function >> index) & 1 for index in range(8)]
            masks, pairs = scan_pair_reference(states, observations, fields)
            self.assertEqual(producer._minimum_hitting_set(masks, fields),
                             partition_minimum(states, observations, fields))
            for selection in range(8):
                key = [name for pos, name in enumerate(fields) if selection & (1 << pos)]
                expected = scan_pair_reference(states, observations, fields, key)
                self.assertEqual(producer._pair_masks(states, observations, fields, key), expected)
                self.assertEqual(
                    producer._pair_masks(states, observations, fields, key, collect_pairs=False),
                    (expected[0], []),
                )
                self.assertEqual(exact_partition(states, observations, key), not expected[1])
            self.assertEqual(producer._pair_masks(states, observations, fields), (masks, pairs))

    def test_minimum_omits_records_and_rejections_preserve_default(self):
        program = next(item for item in finite_fixtures() if item["name"] == "ordered-repeat")
        original = producer._pair_masks
        calls = []

        def observed(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append((kwargs.copy(), len(result[1])))
            return result

        with patch.object(producer, "_pair_masks", side_effect=observed):
            producer.minimum_exact_key(program, "s", program["initial_domain"], ["y"])
            producer.rejection_certificate(program, "s", program["initial_domain"], ["y"], [])
        self.assertEqual(calls[0], ({"collect_pairs": False}, 0))
        self.assertEqual(calls[1][0], {"restrict_equal_on": []})
        self.assertGreater(calls[1][1], 0)

    def test_complete_certificates_receipts_baselines_and_checker_reports(self):
        for program in regression_programs():
            untouched = copy.deepcopy(program)
            with self.subTest(program=program["name"]):
                for rejections in (False, True):
                    current = producer.produce_certificate(program, rejections)
                    with patch.object(producer, "_pair_masks", side_effect=scan_pair_reference):
                        reference = producer.produce_certificate(program, rejections)
                    self.assertEqual(current, reference)
                    self.assertEqual(encoded(current), encoded(reference))
                    self.assertEqual(checker.check_certificate(current),
                                     checker.check_certificate(reference))
                    self.assertEqual(producer.baseline_metrics(program, current),
                                     producer.baseline_metrics(program, reference))
                self.assertEqual(program, untouched)

    def test_cartesian_minimum_repairs_witnesses_and_baseline_oracle(self):
        for program in finite_fixtures():
            certificate = producer.produce_certificate(program)
            fields = [item["name"] for item in program["fields"]]
            for stage in certificate["stages"]:
                states = stage["domain"]
                observations = [checker._render_result(checker._segment(program, "s", state),
                                                       stage["out_fields"]) for state in states]
                minimum, results, masks = producer.minimum_exact_key(
                    program, "s", states, stage["out_fields"])
                self.assertEqual(minimum, partition_minimum(states, observations, fields))
                self.assertEqual([item.as_json(stage["out_fields"]) for item in results], observations)
                self.assertEqual(masks, scan_pair_reference(states, observations, fields)[0])
                for rejection in stage["rejections"].values():
                    fixed = rejection["candidate_fields"]
                    self.assertEqual(rejection["exact"], exact_partition(states, observations, fixed))
                    self.assertEqual(rejection["repair_fields"],
                                     partition_minimum(states, observations, fields, fixed))
                    _, pairs = scan_pair_reference(states, observations, fields, fixed)
                    if not pairs:
                        self.assertIsNone(rejection["witness"])
                        continue
                    i, j = min(((i, j) for i, j, _ in pairs), key=lambda pair: (
                        sum(states[pair[0]][name] != states[pair[1]][name] for name in fields),
                        tuple(states[pair[0]][name] for name in fields),
                        tuple(states[pair[1]][name] for name in fields),
                    ))
                    witness = rejection["witness"]
                    self.assertEqual(witness, {
                        "left": states[i], "right": states[j], "left_result": observations[i],
                        "right_result": observations[j], "criterion": "minimum-hamming-then-lexicographic",
                    })
                for row in producer.baseline_metrics(program, certificate):
                    if row["stage"] != stage["index"]:
                        continue
                    expected = reference_metrics(states, observations, fields, row["key_fields"])
                    expected.update(stage=stage["index"], segment="s", baseline=row["baseline"],
                                    domain_size=len(states))
                    self.assertEqual(row, expected)

    def test_empty_domain_constant_result_determinism_and_input_boundaries(self):
        for collect in (False, True):
            self.assertEqual(producer._pair_masks([], [], ["x"], collect_pairs=collect), (set(), []))
            self.assertEqual(producer._pair_masks([{"x": 0}, {"x": 1}], [0, 0], ["x"],
                                                 collect_pairs=collect), (set(), []))
            with self.assertRaisesRegex(producer.CertificateError, "determinism violated"):
                producer._pair_masks([{"x": 0}, {"x": 0}], [0, 1], ["x"], collect_pairs=collect)
        program = next(finite_fixtures())
        self.assertEqual(producer.minimum_exact_key(program, "s", [], []), ([], [], set()))
        for bad in (True, 1.0, -1, 2):
            altered = copy.deepcopy(program)
            altered["initial_domain"][0]["x"] = bad
            with self.assertRaises(model.ModelError):
                producer.produce_certificate(altered)
            with self.assertRaises(checker.CheckFailure):
                checker._validate_program(altered)
        for bad in ([], program["initial_domain"] + program["initial_domain"][:1]):
            altered = copy.deepcopy(program)
            altered["initial_domain"] = bad
            with self.assertRaises(model.ModelError):
                producer.produce_certificate(altered)
            with self.assertRaises(checker.CheckFailure):
                checker._validate_program(altered)

    def test_event_order_failure_interfaces_and_corruptions(self):
        programs = {item["name"]: item for item in finite_fixtures()}
        repeated = producer.produce_certificate(programs["ordered-repeat"])
        changed_order = producer.produce_certificate(programs["different-event-order"])
        self.assertNotEqual(repeated["whole_entries"], changed_order["whole_entries"])
        events = repeated["whole_entries"][0]["result"]["events"]
        self.assertEqual([event[0] for event in events], ["a", "b", "a", "a", "b", "a"])
        failed = producer.produce_certificate(programs["empty-successor"])
        self.assertEqual(failed["stages"][1]["domain"], [])
        self.assertEqual(failed["stages"][1]["entries"], [])
        self.assertEqual(failed["stages"][1]["key_fields"], [])
        self.assertTrue(all(entry["result"]["out"] == {} for entry in failed["whole_entries"]))
        status_program = programs["mixed-status"]
        self.assertEqual({model.execute_path(status_program, state).status
                          for state in status_program["initial_domain"]},
                         {"ok", "infeasible", "stack_error"})
        for corruption in range(6):
            candidate = copy.deepcopy(repeated)
            if corruption == 0:
                candidate["production"]["domain_states"] += 1
            elif corruption == 1:
                candidate["stages"][0]["minimality"]["collision_masks"] += 1
            elif corruption == 2:
                events = candidate["whole_entries"][0]["result"]["events"]
                events[0], events[1] = events[1], events[0]
            elif corruption == 3:
                candidate["stages"][0]["rejections"]["empty"]["repair_fields"] = []
            elif corruption == 4:
                candidate["stages"][0]["entries"][0]["key"]["x"] = False
            else:
                candidate["stages"][0]["rejections"]["empty"]["witness"]["criterion"] = "changed"
            with self.subTest(corruption=corruption), self.assertRaises(checker.CheckFailure):
                checker.check_certificate(candidate)


if __name__ == "__main__":
    unittest.main()
