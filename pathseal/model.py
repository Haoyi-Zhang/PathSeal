"""Finite segment semantics used by the PathSeal certificate producer.

The independent checker deliberately does not import this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence


class ModelError(ValueError):
    """Raised when an input program or state violates the finite model."""


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    state: dict[str, int]
    events: tuple[tuple[str, tuple[int, ...]], ...]

    def observable(self, fields: Sequence[str]) -> tuple[Any, ...]:
        return (
            self.status,
            self.events,
            tuple((name, self.state[name]) for name in fields),
        )

    def as_json(self, fields: Sequence[str]) -> dict[str, Any]:
        return {
            "status": self.status,
            "events": [[name, list(values)] for name, values in self.events],
            "out": ({name: self.state[name] for name in fields} if self.status == "ok" else {}),
        }


def field_specs(program: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["name"]: dict(item) for item in program["fields"]}


def field_order(program: Mapping[str, Any]) -> list[str]:
    return [item["name"] for item in program["fields"]]


def validate_program(program: Mapping[str, Any]) -> None:
    required = {"name", "fields", "stack", "segments", "path", "initial_domain", "final_fields"}
    missing = required - set(program)
    if missing:
        raise ModelError(f"program missing fields: {sorted(missing)}")

    specs: dict[str, dict[str, Any]] = {}
    for item in program["fields"]:
        if not isinstance(item, Mapping) or set(item) != {"name", "size", "role"}:
            raise ModelError("field declarations require exactly name, size, and role")
        name = item.get("name")
        size = item.get("size")
        role = item.get("role")
        if not isinstance(name, str) or not name:
            raise ModelError("field name must be a nonempty string")
        if name in specs:
            raise ModelError(f"duplicate field {name}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 2:
            raise ModelError(f"field {name} has invalid size")
        if not isinstance(role, str) or not role:
            raise ModelError(f"field {name} has invalid role")
        specs[name] = dict(item)

    stack = program["stack"]
    if set(stack) != {"pointer", "slots"}:
        raise ModelError("stack must have pointer and slots")
    if stack["pointer"] not in specs:
        raise ModelError("stack pointer field is undeclared")
    slots = stack["slots"]
    if not isinstance(slots, list) or not slots or len(set(slots)) != len(slots):
        raise ModelError("stack slots must be a nonempty unique list")
    for slot in slots:
        if slot not in specs:
            raise ModelError(f"stack slot {slot} is undeclared")
    if specs[stack["pointer"]]["size"] != len(slots) + 1:
        raise ModelError("stack pointer domain must equal capacity plus one")

    segment_ids: set[str] = set()
    for seg in program["segments"]:
        sid = seg.get("id")
        if not isinstance(sid, str) or not sid or sid in segment_ids:
            raise ModelError("segments require unique nonempty ids")
        segment_ids.add(sid)
        ops = seg.get("ops")
        if not isinstance(ops, list):
            raise ModelError(f"segment {sid} has no op list")
        for op in ops:
            validate_op(op, specs, stack)

    if not isinstance(program["path"], list) or not program["path"]:
        raise ModelError("path must be nonempty")
    for sid in program["path"]:
        if sid not in segment_ids:
            raise ModelError(f"path references unknown segment {sid}")

    for name in program["final_fields"]:
        if name not in specs:
            raise ModelError(f"unknown final field {name}")
    if len(set(program["final_fields"])) != len(program["final_fields"]):
        raise ModelError("duplicate final fields")
    if program["final_fields"] != [name for name in specs if name in program["final_fields"]]:
        raise ModelError("final fields must follow declaration order")

    if not isinstance(program["initial_domain"], list) or not program["initial_domain"]:
        raise ModelError("initial domain must be a nonempty list")
    seen: set[tuple[int, ...]] = set()
    order = list(specs)
    for state in program["initial_domain"]:
        validate_state(state, specs)
        key = tuple(state[name] for name in order)
        if key in seen:
            raise ModelError("initial domain contains duplicate states")
        seen.add(key)


def validate_state(state: Mapping[str, Any], specs: Mapping[str, Mapping[str, Any]]) -> None:
    if set(state) != set(specs):
        missing = set(specs) - set(state)
        extra = set(state) - set(specs)
        raise ModelError(f"state fields mismatch missing={sorted(missing)} extra={sorted(extra)}")
    for name, spec in specs.items():
        value = state[name]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ModelError(f"state field {name} must be an integer")
        if not 0 <= value < int(spec["size"]):
            raise ModelError(f"state field {name} out of domain")


def validate_expr(expr: Any, specs: Mapping[str, Mapping[str, Any]]) -> None:
    if isinstance(expr, int) and not isinstance(expr, bool):
        return
    if not isinstance(expr, Mapping):
        raise ModelError(f"invalid expression {expr!r}")
    if "field" in expr:
        if set(expr) != {"field"} or expr["field"] not in specs:
            raise ModelError("invalid field expression")
        return
    op = expr.get("op")
    if op in {"not"}:
        if set(expr) != {"op", "arg"}:
            raise ModelError(f"malformed {op} expression")
        validate_expr(expr["arg"], specs)
    elif op in {"and", "or", "xor", "eq", "neq", "lt"}:
        if set(expr) != {"op", "args"} or not isinstance(expr["args"], list) or len(expr["args"]) != 2:
            raise ModelError(f"malformed {op} expression")
        for arg in expr["args"]:
            validate_expr(arg, specs)
    elif op == "addmod":
        if set(expr) != {"op", "args", "mod"} or not isinstance(expr["args"], list) or len(expr["args"]) != 2:
            raise ModelError("malformed addmod expression")
        if not isinstance(expr["mod"], int) or expr["mod"] < 2:
            raise ModelError("invalid addmod modulus")
        for arg in expr["args"]:
            validate_expr(arg, specs)
    elif op == "ite":
        if set(expr) != {"op", "cond", "then", "else"}:
            raise ModelError("malformed ite expression")
        validate_expr(expr["cond"], specs)
        validate_expr(expr["then"], specs)
        validate_expr(expr["else"], specs)
    else:
        raise ModelError(f"unsupported expression operator {op!r}")


def validate_op(op: Mapping[str, Any], specs: Mapping[str, Mapping[str, Any]], stack: Mapping[str, Any]) -> None:
    kind = op.get("op")
    if kind == "set":
        if set(op) != {"op", "field", "expr"} or op["field"] not in specs:
            raise ModelError("malformed set operation")
        validate_expr(op["expr"], specs)
    elif kind == "assume":
        if set(op) != {"op", "expr"}:
            raise ModelError("malformed assume operation")
        validate_expr(op["expr"], specs)
    elif kind == "emit":
        if set(op) != {"op", "event", "args"}:
            raise ModelError("malformed emit operation")
        if not isinstance(op["event"], str) or not op["event"]:
            raise ModelError("event name must be nonempty")
        if not isinstance(op["args"], list):
            raise ModelError("event arguments must be a list")
        for expr in op["args"]:
            validate_expr(expr, specs)
    elif kind in {"push", "pop"}:
        expected = {"op", "expr"}
        if set(op) != expected:
            raise ModelError(f"malformed {kind} operation")
        validate_expr(op["expr"], specs)
        if stack["pointer"] not in specs:
            raise ModelError("invalid stack configuration")
    else:
        raise ModelError(f"unsupported operation {kind!r}")


def eval_expr(expr: Any, state: Mapping[str, int]) -> int:
    if isinstance(expr, int) and not isinstance(expr, bool):
        return expr
    if "field" in expr:
        return state[expr["field"]]
    op = expr["op"]
    if op == "not":
        return 0 if eval_expr(expr["arg"], state) else 1
    if op == "ite":
        branch = expr["then"] if eval_expr(expr["cond"], state) else expr["else"]
        return eval_expr(branch, state)
    a = eval_expr(expr["args"][0], state)
    b = eval_expr(expr["args"][1], state)
    if op == "and":
        return 1 if (a and b) else 0
    if op == "or":
        return 1 if (a or b) else 0
    if op == "xor":
        return (1 if a else 0) ^ (1 if b else 0)
    if op == "eq":
        return 1 if a == b else 0
    if op == "neq":
        return 1 if a != b else 0
    if op == "lt":
        return 1 if a < b else 0
    if op == "addmod":
        return (a + b) % int(expr["mod"])
    raise ModelError(f"unsupported expression operator {op!r}")


def segment_map(program: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {seg["id"]: seg for seg in program["segments"]}


def execute_segment(program: Mapping[str, Any], segment_id: str, initial: Mapping[str, int]) -> ExecutionResult:
    specs = field_specs(program)
    validate_state(initial, specs)
    segments = segment_map(program)
    if segment_id not in segments:
        raise ModelError(f"unknown segment {segment_id}")
    state = dict(initial)
    events: list[tuple[str, tuple[int, ...]]] = []
    status = "ok"
    pointer = program["stack"]["pointer"]
    slots: list[str] = list(program["stack"]["slots"])

    for op in segments[segment_id]["ops"]:
        kind = op["op"]
        if kind == "set":
            target = op["field"]
            state[target] = eval_expr(op["expr"], state) % int(specs[target]["size"])
        elif kind == "assume":
            if not eval_expr(op["expr"], state):
                status = "infeasible"
                break
        elif kind == "emit":
            values = tuple(eval_expr(expr, state) for expr in op["args"])
            events.append((op["event"], values))
        elif kind == "push":
            depth = state[pointer]
            if depth >= len(slots):
                status = "stack_error"
                break
            token = eval_expr(op["expr"], state) % int(specs[slots[depth]]["size"])
            state[slots[depth]] = token
            state[pointer] = depth + 1
        elif kind == "pop":
            depth = state[pointer]
            if depth <= 0:
                status = "stack_error"
                break
            slot = slots[depth - 1]
            expected = eval_expr(op["expr"], state) % int(specs[slot]["size"])
            if state[slot] != expected:
                status = "stack_error"
                break
            state[pointer] = depth - 1
            state[slot] = 0
        else:  # validation should make this unreachable
            raise ModelError(f"unsupported operation {kind!r}")

    return ExecutionResult(status=status, state=state, events=tuple(events))


def execute_path(program: Mapping[str, Any], initial: Mapping[str, int]) -> ExecutionResult:
    state = dict(initial)
    events: list[tuple[str, tuple[int, ...]]] = []
    status = "ok"
    for segment_id in program["path"]:
        result = execute_segment(program, segment_id, state)
        state = result.state
        events.extend(result.events)
        if result.status != "ok":
            status = result.status
            break
    return ExecutionResult(status=status, state=state, events=tuple(events))


def project(state: Mapping[str, int], fields: Sequence[str]) -> tuple[int, ...]:
    return tuple(state[name] for name in fields)


def canonical_state_key(state: Mapping[str, int], order: Sequence[str]) -> tuple[int, ...]:
    return tuple(state[name] for name in order)


def unique_states(states: Iterable[Mapping[str, int]], order: Sequence[str]) -> list[dict[str, int]]:
    table: dict[tuple[int, ...], dict[str, int]] = {}
    for state in states:
        key = canonical_state_key(state, order)
        table[key] = dict(state)
    return [table[key] for key in sorted(table)]


def expr_reads(expr: Any) -> set[str]:
    if isinstance(expr, int) and not isinstance(expr, bool):
        return set()
    if "field" in expr:
        return {expr["field"]}
    op = expr["op"]
    if op == "not":
        return expr_reads(expr["arg"])
    if op == "ite":
        return expr_reads(expr["cond"]) | expr_reads(expr["then"]) | expr_reads(expr["else"])
    reads: set[str] = set()
    for arg in expr["args"]:
        reads |= expr_reads(arg)
    return reads


def conservative_support(program: Mapping[str, Any], segment_id: str, out_fields: Sequence[str]) -> list[str]:
    """Return a conservative input support for a segment result.

    The support is intentionally simple: all fields read by operations, plus any
    requested output field not definitely overwritten before use. It is a sound
    but often non-minimal exact-key baseline for this straight-line language.
    """

    order = field_order(program)
    segment = segment_map(program)[segment_id]
    pointer = program["stack"]["pointer"]
    slots = set(program["stack"]["slots"])
    reads: set[str] = set()
    written: set[str] = set()
    for op in segment["ops"]:
        kind = op["op"]
        if kind == "set":
            reads |= expr_reads(op["expr"])
            written.add(op["field"])
        elif kind == "assume":
            reads |= expr_reads(op["expr"])
        elif kind == "emit":
            for expr in op["args"]:
                reads |= expr_reads(expr)
        elif kind in {"push", "pop"}:
            reads |= expr_reads(op["expr"])
            reads.add(pointer)
            reads |= slots
            written.add(pointer)
            written |= slots
    for field in out_fields:
        if field not in written:
            reads.add(field)
    return [name for name in order if name in reads]
