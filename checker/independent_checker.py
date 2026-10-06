"""Independent checker for PathSeal certificates.

This file intentionally duplicates the finite semantics instead of importing the
producer.  It uses only the Python standard library.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


class CheckFailure(ValueError):
    pass


def _same_json(actual: Any, expected: Any) -> bool:
    """Compare JSON trees without coercing Boolean, integer, or float scalars."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            _same_json(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same_json(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple((key, _freeze(value[key])) for key in sorted(value))
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _fields(program: Mapping[str, Any]) -> list[str]:
    return [item["name"] for item in program["fields"]]


def _specs(program: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {item["name"]: item for item in program["fields"]}


def _segments(program: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {item["id"]: item for item in program["segments"]}


def _validate_expr(expr: Any, names: set[str]) -> None:
    if isinstance(expr, int) and not isinstance(expr, bool):
        return
    if not isinstance(expr, dict):
        raise CheckFailure("expression is not finite syntax")
    if "field" in expr:
        if set(expr) != {"field"} or expr["field"] not in names:
            raise CheckFailure("invalid field expression")
        return
    tag = expr.get("op")
    if tag == "not":
        if set(expr) != {"op", "arg"}:
            raise CheckFailure("bad not expression")
        _validate_expr(expr["arg"], names)
    elif tag in {"and", "or", "xor", "eq", "neq", "lt"}:
        if set(expr) != {"op", "args"} or not isinstance(expr["args"], list) or len(expr["args"]) != 2:
            raise CheckFailure(f"bad {tag} expression")
        for arg in expr["args"]:
            _validate_expr(arg, names)
    elif tag == "addmod":
        if set(expr) != {"op", "args", "mod"} or not isinstance(expr["args"], list) or len(expr["args"]) != 2:
            raise CheckFailure("bad addmod expression")
        if not isinstance(expr["mod"], int) or expr["mod"] < 2:
            raise CheckFailure("bad modulus")
        for arg in expr["args"]:
            _validate_expr(arg, names)
    elif tag == "ite":
        if set(expr) != {"op", "cond", "then", "else"}:
            raise CheckFailure("bad ite expression")
        _validate_expr(expr["cond"], names)
        _validate_expr(expr["then"], names)
        _validate_expr(expr["else"], names)
    else:
        raise CheckFailure("unsupported expression operator")


def _validate_state(state: Mapping[str, Any], specs: Mapping[str, Mapping[str, Any]]) -> None:
    if not isinstance(state, dict) or set(state) != set(specs):
        raise CheckFailure("state shape mismatch")
    for name, spec in specs.items():
        value = state[name]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < int(spec["size"]):
            raise CheckFailure(f"state value out of range: {name}")


def _validate_program(program: Mapping[str, Any]) -> None:
    if not isinstance(program, dict):
        raise CheckFailure("program is not an object")
    expected = {"name", "fields", "stack", "segments", "path", "initial_domain", "final_fields"}
    if set(program) != expected:
        raise CheckFailure("program keys mismatch")
    if not isinstance(program["name"], str) or not program["name"]:
        raise CheckFailure("program name missing")

    names: list[str] = []
    specs: dict[str, Mapping[str, Any]] = {}
    for spec in program["fields"]:
        if not isinstance(spec, dict) or set(spec) != {"name", "size", "role"}:
            raise CheckFailure("field declarations require exactly name, size, and role")
        name = spec["name"]
        if not isinstance(name, str) or not name or name in specs:
            raise CheckFailure("duplicate or invalid field name")
        if not isinstance(spec["size"], int) or isinstance(spec["size"], bool) or spec["size"] < 2:
            raise CheckFailure("field domain must be finite and nontrivial")
        if not isinstance(spec["role"], str) or not spec["role"]:
            raise CheckFailure("field role must be a nonempty string")
        names.append(name)
        specs[name] = spec

    stack = program["stack"]
    if not isinstance(stack, dict) or set(stack) != {"pointer", "slots"}:
        raise CheckFailure("invalid stack declaration")
    if stack["pointer"] not in specs or not isinstance(stack["slots"], list) or not stack["slots"]:
        raise CheckFailure("invalid stack fields")
    if len(set(stack["slots"])) != len(stack["slots"]):
        raise CheckFailure("duplicate stack slot")
    if any(slot not in specs for slot in stack["slots"]):
        raise CheckFailure("undeclared stack slot")
    if specs[stack["pointer"]]["size"] != len(stack["slots"]) + 1:
        raise CheckFailure("stack pointer domain must equal capacity plus one")

    seen_segments: set[str] = set()
    for segment in program["segments"]:
        if not isinstance(segment, dict) or set(segment) != {"id", "ops"}:
            raise CheckFailure("malformed segment")
        sid = segment["id"]
        if not isinstance(sid, str) or not sid or sid in seen_segments:
            raise CheckFailure("duplicate segment id")
        seen_segments.add(sid)
        if not isinstance(segment["ops"], list):
            raise CheckFailure("segment operations missing")
        for op in segment["ops"]:
            if not isinstance(op, dict):
                raise CheckFailure("operation must be an object")
            kind = op.get("op")
            if kind == "set":
                if set(op) != {"op", "field", "expr"} or op["field"] not in specs:
                    raise CheckFailure("bad set operation")
                _validate_expr(op["expr"], set(names))
            elif kind == "assume":
                if set(op) != {"op", "expr"}:
                    raise CheckFailure("bad assume operation")
                _validate_expr(op["expr"], set(names))
            elif kind == "emit":
                if set(op) != {"op", "event", "args"} or not isinstance(op["event"], str) or not isinstance(op["args"], list):
                    raise CheckFailure("bad emit operation")
                for expr in op["args"]:
                    _validate_expr(expr, set(names))
            elif kind in {"push", "pop"}:
                if set(op) != {"op", "expr"}:
                    raise CheckFailure("bad stack operation")
                _validate_expr(op["expr"], set(names))
            else:
                raise CheckFailure("unknown operation")

    if not isinstance(program["path"], list) or not program["path"] or any(sid not in seen_segments for sid in program["path"]):
        raise CheckFailure("invalid path")
    if not isinstance(program["final_fields"], list) or len(set(program["final_fields"])) != len(program["final_fields"]):
        raise CheckFailure("invalid final field list")
    if any(name not in specs for name in program["final_fields"]):
        raise CheckFailure("unknown final field")
    if program["final_fields"] != [name for name in names if name in program["final_fields"]]:
        raise CheckFailure("final fields must follow declaration order")
    if not isinstance(program["initial_domain"], list) or not program["initial_domain"]:
        raise CheckFailure("initial domain missing")
    seen_states: set[tuple[int, ...]] = set()
    for state in program["initial_domain"]:
        _validate_state(state, specs)
        key = tuple(state[name] for name in names)
        if key in seen_states:
            raise CheckFailure("duplicate initial state")
        seen_states.add(key)


def _eval(expr: Any, state: Mapping[str, int]) -> int:
    if isinstance(expr, int) and not isinstance(expr, bool):
        return expr
    if "field" in expr:
        return state[expr["field"]]
    tag = expr["op"]
    if tag == "not":
        return int(not _eval(expr["arg"], state))
    if tag == "ite":
        return _eval(expr["then"], state) if _eval(expr["cond"], state) else _eval(expr["else"], state)
    left = _eval(expr["args"][0], state)
    right = _eval(expr["args"][1], state)
    if tag == "and":
        return int(bool(left) and bool(right))
    if tag == "or":
        return int(bool(left) or bool(right))
    if tag == "xor":
        return int(bool(left)) ^ int(bool(right))
    if tag == "eq":
        return int(left == right)
    if tag == "neq":
        return int(left != right)
    if tag == "lt":
        return int(left < right)
    if tag == "addmod":
        return (left + right) % int(expr["mod"])
    raise CheckFailure("unreachable expression")


def _segment(program: Mapping[str, Any], segment_id: str, initial: Mapping[str, int]) -> dict[str, Any]:
    specs = _specs(program)
    _validate_state(initial, specs)
    state = dict(initial)
    events: list[list[Any]] = []
    status = "ok"
    pointer = program["stack"]["pointer"]
    slots = list(program["stack"]["slots"])
    segment = _segments(program)[segment_id]

    for operation in segment["ops"]:
        tag = operation["op"]
        if tag == "set":
            target = operation["field"]
            state[target] = _eval(operation["expr"], state) % int(specs[target]["size"])
        elif tag == "assume":
            if not _eval(operation["expr"], state):
                status = "infeasible"
                break
        elif tag == "emit":
            events.append([operation["event"], [_eval(arg, state) for arg in operation["args"]]])
        elif tag == "push":
            depth = state[pointer]
            if depth >= len(slots):
                status = "stack_error"
                break
            slot = slots[depth]
            state[slot] = _eval(operation["expr"], state) % int(specs[slot]["size"])
            state[pointer] = depth + 1
        elif tag == "pop":
            depth = state[pointer]
            if depth == 0:
                status = "stack_error"
                break
            slot = slots[depth - 1]
            expected = _eval(operation["expr"], state) % int(specs[slot]["size"])
            if state[slot] != expected:
                status = "stack_error"
                break
            state[pointer] = depth - 1
            state[slot] = 0
        else:
            raise CheckFailure("unsupported operation at execution")
    return {"status": status, "state": state, "events": events}


def _render_result(result: Mapping[str, Any], out_fields: Sequence[str]) -> dict[str, Any]:
    return {
        "status": result["status"],
        "events": result["events"],
        "out": ({name: result["state"][name] for name in out_fields} if result["status"] == "ok" else {}),
    }


def _path(program: Mapping[str, Any], initial: Mapping[str, int]) -> dict[str, Any]:
    state = dict(initial)
    events: list[list[Any]] = []
    status = "ok"
    for sid in program["path"]:
        result = _segment(program, sid, state)
        state = result["state"]
        events.extend(result["events"])
        if result["status"] != "ok":
            status = result["status"]
            break
    return {"status": status, "state": state, "events": events}


def _state_key(state: Mapping[str, int], names: Sequence[str]) -> tuple[int, ...]:
    return tuple(state[name] for name in names)


def _unique(states: Sequence[Mapping[str, int]], names: Sequence[str]) -> list[dict[str, int]]:
    table = {_state_key(state, names): dict(state) for state in states}
    return [table[key] for key in sorted(table)]


def _exact(program: Mapping[str, Any], sid: str, domain: Sequence[Mapping[str, int]], key_fields: Sequence[str], out_fields: Sequence[str]) -> bool:
    seen: dict[tuple[int, ...], Any] = {}
    for state in domain:
        key = _state_key(state, key_fields)
        signature = _freeze(_render_result(_segment(program, sid, state), out_fields))
        if key in seen and seen[key] != signature:
            return False
        seen[key] = signature
    return True



def _collision_masks_from_results(
    program: Mapping[str, Any],
    domain: Sequence[Mapping[str, int]],
    results: Sequence[Mapping[str, Any]],
    out_fields: Sequence[str],
) -> set[int]:
    names = _fields(program)
    signatures = [_freeze(_render_result(result, out_fields)) for result in results]
    masks: set[int] = set()
    for i in range(len(domain)):
        for j in range(i + 1, len(domain)):
            if signatures[i] == signatures[j]:
                continue
            mask = 0
            for position, name in enumerate(names):
                if domain[i][name] != domain[j][name]:
                    mask |= 1 << position
            if mask == 0:
                raise CheckFailure("determinism violated by equal states")
            masks.add(mask)
    return masks


def _minimum_key_from_results(
    program: Mapping[str, Any],
    domain: Sequence[Mapping[str, int]],
    results: Sequence[Mapping[str, Any]],
    out_fields: Sequence[str],
    counter: list[int],
) -> tuple[list[str], int]:
    names = _fields(program)
    masks = _collision_masks_from_results(program, domain, results, out_fields)
    if not masks:
        counter[0] += 1
        return [], 0
    for width in range(len(names) + 1):
        for positions in itertools.combinations(range(len(names)), width):
            counter[0] += 1
            candidate = 0
            for position in positions:
                candidate |= 1 << position
            if all(candidate & edge for edge in masks):
                chosen = set(positions)
                return [name for position, name in enumerate(names) if position in chosen], len(masks)
    raise CheckFailure("all fields failed to hit the collision hypergraph")


def _entries_from_results(
    domain: Sequence[Mapping[str, int]],
    results: Sequence[Mapping[str, Any]],
    key_fields: Sequence[str],
    out_fields: Sequence[str],
) -> list[dict[str, Any]]:
    table: dict[tuple[int, ...], dict[str, Any]] = {}
    for state, raw_result in zip(domain, results, strict=True):
        key = _state_key(state, key_fields)
        result = _render_result(raw_result, out_fields)
        item = {"key": {name: value for name, value in zip(key_fields, key, strict=True)}, "result": result}
        if key in table and _freeze(table[key]["result"]) != _freeze(result):
            raise CheckFailure("certificate key is not exact")
        table[key] = item
    return [table[key] for key in sorted(table)]

def _minimum_key(program: Mapping[str, Any], sid: str, domain: Sequence[Mapping[str, int]], out_fields: Sequence[str], counter: list[int]) -> list[str]:
    names = _fields(program)
    for width in range(len(names) + 1):
        for positions in itertools.combinations(range(len(names)), width):
            candidate = [names[pos] for pos in positions]
            counter[0] += 1
            if _exact(program, sid, domain, candidate, out_fields):
                return candidate
    raise CheckFailure("all fields failed to form an exact key")


def _entries(program: Mapping[str, Any], sid: str, domain: Sequence[Mapping[str, int]], key_fields: Sequence[str], out_fields: Sequence[str]) -> list[dict[str, Any]]:
    table: dict[tuple[int, ...], dict[str, Any]] = {}
    for state in domain:
        key = _state_key(state, key_fields)
        result = _render_result(_segment(program, sid, state), out_fields)
        item = {"key": {name: value for name, value in zip(key_fields, key, strict=True)}, "result": result}
        if key in table and _freeze(table[key]["result"]) != _freeze(result):
            raise CheckFailure("certificate key is not exact")
        table[key] = item
    return [table[key] for key in sorted(table)]


def _expr_reads(expr: Any) -> set[str]:
    if isinstance(expr, int) and not isinstance(expr, bool):
        return set()
    if "field" in expr:
        return {expr["field"]}
    tag = expr["op"]
    if tag == "not":
        return _expr_reads(expr["arg"])
    if tag == "ite":
        return _expr_reads(expr["cond"]) | _expr_reads(expr["then"]) | _expr_reads(expr["else"])
    reads: set[str] = set()
    for argument in expr["args"]:
        reads |= _expr_reads(argument)
    return reads


def _conservative_support(program: Mapping[str, Any], sid: str, out_fields: Sequence[str]) -> list[str]:
    names = _fields(program)
    pointer = program["stack"]["pointer"]
    slots = set(program["stack"]["slots"])
    reads: set[str] = set()
    written: set[str] = set()
    for operation in _segments(program)[sid]["ops"]:
        tag = operation["op"]
        if tag == "set":
            reads |= _expr_reads(operation["expr"])
            written.add(operation["field"])
        elif tag == "assume":
            reads |= _expr_reads(operation["expr"])
        elif tag == "emit":
            for expression in operation["args"]:
                reads |= _expr_reads(expression)
        elif tag in {"push", "pop"}:
            reads |= _expr_reads(operation["expr"])
            reads.add(pointer)
            reads |= slots
            written.add(pointer)
            written |= slots
        else:
            raise CheckFailure("unsupported operation while computing support")
    for name in out_fields:
        if name not in written:
            reads.add(name)
    return [name for name in names if name in reads]


def _forward_domains(program: Mapping[str, Any]) -> list[list[dict[str, int]]]:
    names = _fields(program)
    domains = [_unique(program["initial_domain"], names)]
    for sid in program["path"]:
        successor: list[dict[str, int]] = []
        for state in domains[-1]:
            result = _segment(program, sid, state)
            if result["status"] == "ok":
                successor.append(result["state"])
        domains.append(_unique(successor, names))
    return domains


def _candidate_collisions(program: Mapping[str, Any], sid: str, domain: Sequence[Mapping[str, int]], candidate: Sequence[str], out_fields: Sequence[str]) -> list[tuple[dict[str, int], dict[str, int]]]:
    results = [_freeze(_render_result(_segment(program, sid, state), out_fields)) for state in domain]
    pairs: list[tuple[dict[str, int], dict[str, int]]] = []
    for i in range(len(domain)):
        for j in range(i + 1, len(domain)):
            if _state_key(domain[i], candidate) == _state_key(domain[j], candidate) and results[i] != results[j]:
                pairs.append((dict(domain[i]), dict(domain[j])))
    return pairs


def _canonical_witness(program: Mapping[str, Any], pairs: Sequence[tuple[Mapping[str, int], Mapping[str, int]]]) -> tuple[dict[str, int], dict[str, int]]:
    names = _fields(program)
    def rank(pair: tuple[Mapping[str, int], Mapping[str, int]]) -> tuple[Any, ...]:
        left, right = pair
        left_key = _state_key(left, names)
        right_key = _state_key(right, names)
        distance = sum(a != b for a, b in zip(left_key, right_key, strict=True))
        return distance, left_key, right_key
    left, right = min(pairs, key=rank)
    return dict(left), dict(right)


def _minimum_repair(program: Mapping[str, Any], sid: str, domain: Sequence[Mapping[str, int]], candidate: Sequence[str], out_fields: Sequence[str], counter: list[int]) -> list[str]:
    names = _fields(program)
    remaining = [name for name in names if name not in set(candidate)]
    for width in range(len(remaining) + 1):
        for subset in itertools.combinations(remaining, width):
            trial_set = set(candidate) | set(subset)
            trial = [name for name in names if name in trial_set]
            counter[0] += 1
            if _exact(program, sid, domain, trial, out_fields):
                return [name for name in names if name in set(subset)]
    raise CheckFailure("no repair exists")



def _minimum_repair_from_pairs(
    program: Mapping[str, Any],
    pairs: Sequence[tuple[Mapping[str, int], Mapping[str, int]]],
    candidate: Sequence[str],
    counter: list[int],
) -> list[str]:
    names = _fields(program)
    candidate_set = set(candidate)
    remaining_positions = [index for index, name in enumerate(names) if name not in candidate_set]
    masks: set[int] = set()
    for left, right in pairs:
        mask = 0
        for position in remaining_positions:
            name = names[position]
            if left[name] != right[name]:
                mask |= 1 << position
        if mask == 0:
            raise CheckFailure("an inexact candidate has no available repair field")
        masks.add(mask)
    for width in range(len(remaining_positions) + 1):
        for positions in itertools.combinations(remaining_positions, width):
            counter[0] += 1
            candidate_mask = 0
            for position in positions:
                candidate_mask |= 1 << position
            if all(candidate_mask & edge for edge in masks):
                selected = set(positions)
                return [name for position, name in enumerate(names) if position in selected]
    raise CheckFailure("no repair exists")

def _check_rejection(program: Mapping[str, Any], stage: Mapping[str, Any], rejection: Mapping[str, Any], counter: list[int]) -> int:
    if not isinstance(rejection, dict) or set(rejection) != {"candidate_fields", "exact", "witness", "repair_fields"}:
        raise CheckFailure("rejection object has unknown or missing fields")
    names = _fields(program)
    candidate = rejection.get("candidate_fields")
    if not isinstance(candidate, list) or candidate != [name for name in names if name in set(candidate)]:
        raise CheckFailure("candidate projection is malformed or out of order")
    pairs = _candidate_collisions(program, stage["segment"], stage["domain"], candidate, stage["out_fields"])
    replayed = len(stage["domain"])
    if not pairs:
        if rejection.get("exact") is not True or rejection.get("witness") is not None or rejection.get("repair_fields") != []:
            raise CheckFailure("exact candidate encoded as rejection")
        return replayed
    if rejection.get("exact") is not False:
        raise CheckFailure("inexact candidate encoded as exact")
    witness = rejection.get("witness")
    if not isinstance(witness, dict) or set(witness) != {"left", "right", "left_result", "right_result", "criterion"}:
        raise CheckFailure("collision witness has unknown or missing fields")
    expected_left, expected_right = _canonical_witness(program, pairs)
    if not _same_json(witness.get("left"), expected_left) or not _same_json(witness.get("right"), expected_right):
        raise CheckFailure("collision witness is not canonical")
    if witness.get("criterion") != "minimum-hamming-then-lexicographic":
        raise CheckFailure("unknown witness order")
    left_result = _render_result(_segment(program, stage["segment"], expected_left), stage["out_fields"])
    right_result = _render_result(_segment(program, stage["segment"], expected_right), stage["out_fields"])
    if not _same_json(witness.get("left_result"), left_result) or not _same_json(witness.get("right_result"), right_result):
        raise CheckFailure("witness result mismatch")
    expected_repair = _minimum_repair_from_pairs(program, pairs, candidate, counter)
    if rejection.get("repair_fields") != expected_repair:
        raise CheckFailure("repair is not minimum-cardinality canonical")
    return replayed + 2


def _summary_compose(certificate: Mapping[str, Any], initial: Mapping[str, int]) -> dict[str, Any]:
    stages = certificate["stages"]
    current = _state_key(initial, stages[0]["key_fields"])
    accumulated: list[list[Any]] = []
    status = "ok"
    final_out: dict[str, int] = {}
    for position, stage in enumerate(stages):
        table = {
            tuple(entry["key"][name] for name in stage["key_fields"]): entry["result"]
            for entry in stage["entries"]
        }
        if current not in table:
            raise CheckFailure("summary composition reached an absent key")
        local = table[current]
        accumulated.extend(local["events"])
        if local["status"] != "ok":
            status = local["status"]
            final_out = {}
            break
        if position + 1 < len(stages):
            next_fields = stages[position + 1]["key_fields"]
            if set(local["out"]) != set(next_fields):
                raise CheckFailure("stage output is not the next input interface")
            current = tuple(local["out"][name] for name in next_fields)
        else:
            final_out = dict(local["out"])
    return {"status": status, "events": accumulated, "out": final_out}


def check_certificate(certificate: Mapping[str, Any]) -> dict[str, Any]:
    certificate_keys = {"schema", "program", "field_order", "stages", "whole_key_fields", "whole_entries", "production"}
    if not isinstance(certificate, dict) or set(certificate) != certificate_keys:
        raise CheckFailure("certificate has unknown or missing top-level fields")
    if certificate.get("schema") != "pathseal-certificate":
        raise CheckFailure("unsupported certificate schema")
    program = certificate.get("program")
    _validate_program(program)
    names = _fields(program)
    if not _same_json(certificate.get("field_order"), names):
        raise CheckFailure("field order mismatch")

    stages = certificate.get("stages")
    if not isinstance(stages, list) or len(stages) != len(program["path"]):
        raise CheckFailure("stage count mismatch")
    domains = _forward_domains(program)
    subset_counter = [0]
    execution_obligations = 0

    for index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            raise CheckFailure("stage must be an object")
        base_keys = {"index", "segment", "domain", "key_fields", "out_fields", "entries", "minimality", "support_fields"}
        permitted_stage_keys = (base_keys, base_keys | {"rejections"})
        if set(stage) not in permitted_stage_keys:
            raise CheckFailure("stage has unknown or missing fields")
        if not _same_json(stage["index"], index) or stage["segment"] != program["path"][index]:
            raise CheckFailure("stage ordering mismatch")
        if not _same_json(stage["domain"], domains[index]):
            raise CheckFailure("stage domain is not the reachable concrete domain")
        key_fields = stage["key_fields"]
        out_fields = stage["out_fields"]
        if key_fields != [name for name in names if name in set(key_fields)]:
            raise CheckFailure("key fields are duplicated, unknown, or out of order")
        if out_fields != [name for name in names if name in set(out_fields)]:
            raise CheckFailure("output fields are duplicated, unknown, or out of order")
        expected_out = program["final_fields"] if index + 1 == len(stages) else stages[index + 1]["key_fields"]
        if out_fields != expected_out:
            raise CheckFailure("stage interface does not chain to successor")

        stage_results = [_segment(program, stage["segment"], state) for state in stage["domain"]]
        execution_obligations += len(stage["domain"])
        expected_key, expected_mask_count = _minimum_key_from_results(
            program, stage["domain"], stage_results, out_fields, subset_counter
        )
        if key_fields != expected_key:
            raise CheckFailure("stage key is not minimum-cardinality canonical")
        expected_entries = _entries_from_results(
            stage["domain"], stage_results, key_fields, out_fields
        )
        if not _same_json(stage["entries"], expected_entries):
            raise CheckFailure("summary table mismatch")
        minimality = stage["minimality"]
        if not isinstance(minimality, dict) or set(minimality) != {"criterion", "collision_masks"}:
            raise CheckFailure("minimality record has unknown or missing fields")
        if minimality.get("criterion") != "minimum-cardinality-then-declaration-order":
            raise CheckFailure("minimality criterion mismatch")
        if not _same_json(minimality.get("collision_masks"), expected_mask_count):
            raise CheckFailure("collision-mask count mismatch")
        expected_support = _conservative_support(program, stage["segment"], out_fields)
        if stage["support_fields"] != expected_support:
            raise CheckFailure("conservative support mismatch")
        if "rejections" in stage:
            roles = {item["name"]: item["role"] for item in program["fields"]}
            expected_candidates = {
                "empty": [],
                "call-context": [name for name in names if roles[name] in {"context", "stack"}],
                "security-surface": [
                    name for name in names if roles[name] in {"taint", "sanitizer", "alias", "source"}
                ],
            }
            if not isinstance(stage["rejections"], dict) or set(stage["rejections"]) != set(expected_candidates):
                raise CheckFailure("rejection labels mismatch")
            for label, expected_candidate in expected_candidates.items():
                rejection = stage["rejections"][label]
                if rejection.get("candidate_fields") != expected_candidate:
                    raise CheckFailure("named rejection candidate mismatch")
                execution_obligations += _check_rejection(program, stage, rejection, subset_counter)

    if not _same_json(certificate.get("whole_key_fields"), stages[0]["key_fields"]):
        raise CheckFailure("whole key mismatch")
    expected_whole: dict[tuple[int, ...], dict[str, Any]] = {}
    for state in program["initial_domain"]:
        key = _state_key(state, stages[0]["key_fields"])
        direct = _render_result(_path(program, state), program["final_fields"])
        composed = _summary_compose(certificate, state)
        execution_obligations += len(program["path"]) + 1
        if not _same_json(direct, composed):
            raise CheckFailure("summary composition differs from concrete path semantics")
        item = {"key": {name: value for name, value in zip(stages[0]["key_fields"], key, strict=True)}, "result": direct}
        if key in expected_whole and _freeze(expected_whole[key]["result"]) != _freeze(direct):
            raise CheckFailure("whole key is not exact")
        expected_whole[key] = item
    whole_entries = [expected_whole[key] for key in sorted(expected_whole)]
    if not _same_json(certificate.get("whole_entries"), whole_entries):
        raise CheckFailure("whole summary table mismatch")

    production = certificate.get("production")
    if not isinstance(production, dict) or set(production) != {"programs", "stages", "domain_states"}:
        raise CheckFailure("production receipt has unknown or missing fields")
    if not _same_json(production.get("programs"), 1) or not _same_json(production.get("stages"), len(stages)):
        raise CheckFailure("production counts mismatch")
    if not _same_json(production.get("domain_states"), sum(len(domain) for domain in domains[:-1])):
        raise CheckFailure("production domain count mismatch")

    return {
        "status": "PASS",
        "stages": len(stages),
        "initial_states": len(program["initial_domain"]),
        "reachable_stage_states": sum(len(domain) for domain in domains[:-1]),
        "subset_obligations": subset_counter[0],
        "execution_obligations": execution_obligations,
        "whole_keys": len(whole_entries),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a PathSeal certificate")
    parser.add_argument("certificate", type=Path)
    args = parser.parse_args(argv)
    try:
        certificate = json.loads(args.certificate.read_text(encoding="utf-8"))
        report = check_certificate(certificate)
    except (OSError, json.JSONDecodeError, CheckFailure, KeyError, TypeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
