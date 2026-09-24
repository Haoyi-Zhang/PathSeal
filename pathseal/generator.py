"""Deterministic generated programs for PathSeal evaluation."""
from __future__ import annotations

import random
from typing import Any


def fld(name: str) -> dict[str, str]:
    return {"field": name}


def unary(op: str, arg: Any) -> dict[str, Any]:
    return {"op": op, "arg": arg}


def binary(op: str, left: Any, right: Any) -> dict[str, Any]:
    return {"op": op, "args": [left, right]}


def addmod(left: Any, right: Any, modulus: int = 4) -> dict[str, Any]:
    return {"op": "addmod", "args": [left, right], "mod": modulus}


def ite(cond: Any, then: Any, otherwise: Any) -> dict[str, Any]:
    return {"op": "ite", "cond": cond, "then": then, "else": otherwise}


def _field_declarations(tier: str) -> list[dict[str, Any]]:
    fields = [
        {"name": "input", "size": 2, "role": "source"},
        {"name": "taint", "size": 2, "role": "taint"},
        {"name": "san", "size": 2, "role": "sanitizer"},
        {"name": "alias", "size": 4, "role": "alias"},
        {"name": "guard", "size": 2, "role": "path"},
        {"name": "mode", "size": 4, "role": "path"},
        {"name": "ctx", "size": 4, "role": "context"},
        {"name": "tmp", "size": 4, "role": "value"},
        {"name": "flag", "size": 2, "role": "path"},
        {"name": "sp", "size": 3, "role": "stack"},
        {"name": "stk0", "size": 4, "role": "stack"},
        {"name": "stk1", "size": 4, "role": "stack"},
    ]
    if tier in {"medium", "large"}:
        fields.append({"name": "aux0", "size": 4, "role": "auxiliary"})
    if tier == "large":
        fields.extend(
            [
                {"name": "aux1", "size": 4, "role": "auxiliary"},
                {"name": "noise", "size": 2, "role": "auxiliary"},
            ]
        )
    # Semantically dead fields come last so the canonical declaration-order
    # tie-breaker never prefers a correlated dead proxy over an equally small
    # live key.  Each core still contains all four dead-field variants.
    fields.append({"name": "dead0", "size": 4, "role": "auxiliary"})
    if tier == "large":
        fields.append({"name": "dead1", "size": 4, "role": "auxiliary"})
    return fields


def _domain(fields: list[dict[str, Any]], count: int, seed: int) -> list[dict[str, int]]:
    rng = random.Random(seed)
    names = [item["name"] for item in fields]
    sizes = {item["name"]: item["size"] for item in fields}
    dead = [name for name in names if name.startswith("dead")]
    live = [name for name in names if name not in dead]
    cores_needed = (count + 3) // 4
    cores: dict[tuple[int, ...], dict[str, int]] = {}

    seeds = [
        {"input": 0, "san": 0, "alias": 0, "guard": 1, "mode": 0, "ctx": 0, "flag": 0},
        {"input": 1, "san": 0, "alias": 3, "guard": 1, "mode": 1, "ctx": 2, "flag": 1},
        {"input": 1, "san": 1, "alias": 2, "guard": 0, "mode": 2, "ctx": 1, "flag": 0},
        {"input": 0, "san": 1, "alias": 1, "guard": 0, "mode": 3, "ctx": 3, "flag": 1},
    ]
    for base in seeds:
        state = {name: 0 for name in names}
        state.update({name: value % sizes[name] for name, value in base.items() if name in sizes})
        state["taint"] = state["input"]
        state["tmp"] = (state["alias"] + state["mode"]) % 4
        if "aux0" in state:
            state["aux0"] = (state["alias"] + state["ctx"]) % 4
        if "aux1" in state:
            state["aux1"] = (state["mode"] + 1) % 4
        if "noise" in state:
            state["noise"] = state["flag"]
        cores[tuple(state[name] for name in live)] = state

    while len(cores) < cores_needed:
        state = {name: 0 for name in names}
        for name in live:
            if name in {"sp", "stk0", "stk1", "taint", "tmp"}:
                continue
            state[name] = rng.randrange(sizes[name])
        state["taint"] = state["input"]
        state["tmp"] = (state["alias"] + state["mode"]) % 4
        state["sp"] = 0
        state["stk0"] = 0
        state["stk1"] = 0
        cores[tuple(state[name] for name in live)] = state

    states: list[dict[str, int]] = []
    for core_index, core_key in enumerate(sorted(cores)):
        core = cores[core_key]
        for variant in range(4):
            state = dict(core)
            if "dead0" in state:
                state["dead0"] = variant
            if "dead1" in state:
                state["dead1"] = variant
            states.append(state)
            if len(states) == count:
                return states
    return states


def _segments(tier: str, variant: int) -> tuple[list[dict[str, Any]], list[str]]:
    parity = variant % 2
    pivot = variant % 4
    source_taint = binary("xor", fld("input"), fld("flag") if parity else 0)
    source = {
        "id": "source",
        "ops": [
            {"op": "set", "field": "taint", "expr": source_taint},
            {"op": "emit", "event": "source", "args": [fld("input"), fld("ctx")]},
            {"op": "push", "expr": fld("ctx")},
        ],
    }
    propagate = {
        "id": "propagate",
        "ops": [
            {"op": "set", "field": "tmp", "expr": addmod(fld("alias"), fld("mode"))},
            {"op": "set", "field": "alias", "expr": ite(fld("flag"), fld("tmp"), fld("alias"))},
            {"op": "emit", "event": "flow", "args": [fld("taint"), fld("alias")]},
        ],
    }
    sanitize = {
        "id": "sanitize",
        "ops": [
            {"op": "set", "field": "taint", "expr": binary("and", fld("taint"), unary("not", fld("san")))},
            {"op": "emit", "event": "sanitize", "args": [fld("san"), fld("taint")]},
        ],
    }
    branch = {
        "id": "branch",
        "ops": [
            {"op": "assume", "expr": binary("or", fld("guard"), binary("neq", fld("mode"), pivot))},
            {"op": "set", "field": "taint", "expr": binary("xor", fld("taint"), binary("eq", fld("alias"), (pivot + 1) % 4))},
            {"op": "emit", "event": "branch", "args": [fld("guard"), fld("mode"), fld("taint")]},
        ],
    }
    ret = {"id": "return", "ops": [{"op": "pop", "expr": fld("ctx")}]}
    sink = {
        "id": "sink",
        "ops": [
            {"op": "emit", "event": "sink", "args": [fld("taint"), fld("alias"), fld("ctx"), fld("sp")]},
            {"op": "set", "field": "tmp", "expr": addmod(fld("alias"), fld("taint"))},
        ],
    }

    segments = [source, propagate]
    path = ["source", "propagate"]

    if tier in {"medium", "large"}:
        helper = {
            "id": "helper",
            "ops": [
                {"op": "set", "field": "mode", "expr": addmod(fld("mode"), fld("aux0"))},
                {
                    "op": "set",
                    "field": "ctx",
                    "expr": ite(fld("guard"), fld("ctx"), addmod(fld("ctx"), 1)),
                },
                {"op": "emit", "event": "helper", "args": [fld("mode"), fld("ctx")]},
            ],
        }
        nested_call = {
            "id": "nested-call",
            "ops": [
                {"op": "push", "expr": addmod(fld("ctx"), fld("aux0"))},
                {"op": "emit", "event": "call", "args": [fld("ctx"), fld("aux0")]},
            ],
        }
        nested_return = {
            "id": "nested-return",
            "ops": [
                {
                    "op": "set",
                    "field": "aux0",
                    "expr": ite(fld("flag"), addmod(fld("aux0"), 1), fld("aux0")),
                },
                {"op": "pop", "expr": addmod(fld("ctx"), fld("aux0"))},
            ],
        }
        segments.extend([helper, nested_call, nested_return])
        path.extend(["helper", "nested-call", "nested-return"])

    if tier == "large":
        alias_gate = {
            "id": "alias-gate",
            "ops": [
                {"op": "assume", "expr": binary("or", unary("not", fld("noise")), binary("neq", fld("aux1"), pivot))},
                {
                    "op": "set",
                    "field": "alias",
                    "expr": ite(binary("eq", fld("aux1"), fld("mode")), addmod(fld("alias"), fld("aux1")), fld("alias")),
                },
                {"op": "emit", "event": "alias", "args": [fld("alias"), fld("aux1")]},
            ],
        }
        context_fold = {
            "id": "context-fold",
            "ops": [
                {
                    "op": "set",
                    "field": "ctx",
                    "expr": ite(fld("noise"), addmod(fld("ctx"), fld("aux1")), fld("ctx")),
                },
                {"op": "emit", "event": "context", "args": [fld("ctx"), fld("noise")]},
            ],
        }
        segments.extend([alias_gate, context_fold])
        path.extend(["alias-gate", "context-fold"])

    segments.extend([sanitize, branch, ret, sink])
    path.extend(["sanitize", "branch", "return", "sink"])
    return segments, path


def make_program(case_id: str, tier: str, seed: int) -> dict[str, Any]:
    if tier not in {"small", "medium", "large"}:
        raise ValueError("tier must be small, medium, or large")
    fields = _field_declarations(tier)
    count = {"small": 48, "medium": 96, "large": 160}[tier]
    segments, path = _segments(tier, seed)
    return {
        "name": case_id,
        "fields": fields,
        "stack": {"pointer": "sp", "slots": ["stk0", "stk1"]},
        "segments": segments,
        "path": path,
        "initial_domain": _domain(fields, count, seed),
        "final_fields": ["taint", "alias", "mode", "ctx", "sp"],
    }


def campaign() -> list[dict[str, Any]]:
    programs: list[dict[str, Any]] = []
    plan = [("small", 60), ("medium", 40), ("large", 20)]
    offset = 0
    for tier, count in plan:
        for index in range(count):
            seed = 7001 + offset + index * 37
            programs.append(make_program(f"{tier}-{index:03d}", tier, seed))
        offset += count * 101
    return programs
