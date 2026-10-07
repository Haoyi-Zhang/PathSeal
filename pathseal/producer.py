"""Certificate production for the finite PathSeal model."""
from __future__ import annotations

import itertools
import json
from collections import defaultdict
from typing import Any, Iterable, Mapping, Sequence

from .model import (
    ExecutionResult,
    canonical_state_key,
    conservative_support,
    execute_path,
    execute_segment,
    field_order,
    project,
    unique_states,
    validate_program,
)


class CertificateError(ValueError):
    """Raised when certificate construction encounters an invalid condition."""


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple((key, _freeze(value[key])) for key in sorted(value))
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _result_json(result: ExecutionResult, out_fields: Sequence[str]) -> dict[str, Any]:
    return result.as_json(out_fields)


def _result_signature(result: ExecutionResult, out_fields: Sequence[str]) -> Any:
    return _freeze(_result_json(result, out_fields))


def _pair_masks(
    states: Sequence[Mapping[str, int]],
    signatures: Sequence[Any],
    fields: Sequence[str],
    restrict_equal_on: Sequence[str] | None = None,
    *,
    collect_pairs: bool = True,
) -> tuple[set[int], list[tuple[int, int, int]]]:
    masks: set[int] = set()
    pairs: list[tuple[int, int, int]] = []
    restrict = tuple(restrict_equal_on or ())
    restricted_keys = [project(state, restrict) for state in states]
    for i in range(len(states)):
        for j in range(i + 1, len(states)):
            if signatures[i] == signatures[j]:
                continue
            if restrict and restricted_keys[i] != restricted_keys[j]:
                continue
            mask = 0
            for index, name in enumerate(fields):
                if states[i][name] != states[j][name]:
                    mask |= 1 << index
            if mask == 0:
                raise CertificateError("determinism violated: identical states have different results")
            masks.add(mask)
            if collect_pairs:
                pairs.append((i, j, mask))
    return masks, pairs


def _minimum_hitting_set(masks: Iterable[int], fields: Sequence[str], allowed: Sequence[str] | None = None) -> list[str]:
    unique_masks = tuple(sorted(set(masks)))
    if not unique_masks:
        return []
    allowed_names = list(fields if allowed is None else allowed)
    index = {name: i for i, name in enumerate(fields)}
    allowed_positions = [index[name] for name in allowed_names]
    for width in range(len(allowed_positions) + 1):
        for combination in itertools.combinations(allowed_positions, width):
            candidate = 0
            for pos in combination:
                candidate |= 1 << pos
            if all(candidate & edge for edge in unique_masks):
                chosen = {fields[pos] for pos in combination}
                return [name for name in fields if name in chosen]
    raise CertificateError("no hitting set exists inside allowed fields")


def minimum_exact_key(
    program: Mapping[str, Any],
    segment_id: str,
    domain: Sequence[Mapping[str, int]],
    out_fields: Sequence[str],
) -> tuple[list[str], list[ExecutionResult], set[int]]:
    order = field_order(program)
    results = [execute_segment(program, segment_id, state) for state in domain]
    signatures = [_result_signature(result, out_fields) for result in results]
    masks, _ = _pair_masks(domain, signatures, order, collect_pairs=False)
    key = _minimum_hitting_set(masks, order)
    return key, results, masks


def _summary_entries(
    domain: Sequence[Mapping[str, int]],
    results: Sequence[ExecutionResult],
    key_fields: Sequence[str],
    out_fields: Sequence[str],
) -> list[dict[str, Any]]:
    entries: dict[tuple[int, ...], dict[str, Any]] = {}
    for state, result in zip(domain, results, strict=True):
        key = project(state, key_fields)
        item = {
            "key": {name: value for name, value in zip(key_fields, key, strict=True)},
            "result": _result_json(result, out_fields),
        }
        previous = entries.get(key)
        if previous is not None and _freeze(previous["result"]) != _freeze(item["result"]):
            raise CertificateError("attempted to summarize an inexact key")
        entries[key] = item
    return [entries[key] for key in sorted(entries)]


def _projection_metrics_from_results(
    program: Mapping[str, Any],
    domain: Sequence[Mapping[str, int]],
    results: Sequence[ExecutionResult],
    out_fields: Sequence[str],
    key_fields: Sequence[str],
) -> dict[str, Any]:
    signatures = [_result_signature(result, out_fields) for result in results]
    groups: dict[tuple[int, ...], list[int]] = defaultdict(list)
    representatives: dict[tuple[int, ...], Any] = {}
    error_states = 0
    for index, (state, signature) in enumerate(zip(domain, signatures, strict=True)):
        key = project(state, key_fields)
        groups[key].append(index)
        if key not in representatives:
            representatives[key] = signature
        elif representatives[key] != signature:
            error_states += 1

    order = field_order(program)
    masks: set[int] = set()
    collision_pairs = 0
    for indices in groups.values():
        for left_pos in range(len(indices)):
            left = indices[left_pos]
            for right_pos in range(left_pos + 1, len(indices)):
                right = indices[right_pos]
                if signatures[left] == signatures[right]:
                    continue
                collision_pairs += 1
                mask = 0
                for position, name in enumerate(order):
                    if domain[left][name] != domain[right][name]:
                        mask |= 1 << position
                masks.add(mask)
    return {
        "key_fields": list(key_fields),
        "key_width": len(key_fields),
        "distinct_keys": len(representatives),
        "error_states": error_states,
        "collision_pairs": collision_pairs,
        "exact": collision_pairs == 0,
        "reuse_factor": len(domain) / max(1, len(representatives)),
        "collision_masks": len(masks),
    }


def projection_metrics(
    program: Mapping[str, Any],
    segment_id: str,
    domain: Sequence[Mapping[str, int]],
    out_fields: Sequence[str],
    key_fields: Sequence[str],
) -> dict[str, Any]:
    results = [execute_segment(program, segment_id, state) for state in domain]
    return _projection_metrics_from_results(program, domain, results, out_fields, key_fields)


def rejection_certificate(
    program: Mapping[str, Any],
    segment_id: str,
    domain: Sequence[Mapping[str, int]],
    out_fields: Sequence[str],
    candidate_fields: Sequence[str],
) -> dict[str, Any]:
    order = field_order(program)
    results = [execute_segment(program, segment_id, state) for state in domain]
    signatures = [_result_signature(result, out_fields) for result in results]
    masks, pairs = _pair_masks(domain, signatures, order, restrict_equal_on=candidate_fields)
    if not pairs:
        return {
            "candidate_fields": list(candidate_fields),
            "exact": True,
            "witness": None,
            "repair_fields": [],
        }

    def state_tuple(index: int) -> tuple[int, ...]:
        return canonical_state_key(domain[index], order)

    ranked: list[tuple[Any, int, int]] = []
    for i, j, mask in pairs:
        ranked.append(((mask.bit_count(), state_tuple(i), state_tuple(j)), i, j))
    _, left_index, right_index = min(ranked)
    remaining = [name for name in order if name not in set(candidate_fields)]
    repair = _minimum_hitting_set(masks, order, allowed=remaining)
    return {
        "candidate_fields": list(candidate_fields),
        "exact": False,
        "witness": {
            "left": dict(domain[left_index]),
            "right": dict(domain[right_index]),
            "left_result": _result_json(results[left_index], out_fields),
            "right_result": _result_json(results[right_index], out_fields),
            "criterion": "minimum-hamming-then-lexicographic",
        },
        "repair_fields": repair,
    }


def forward_domains(program: Mapping[str, Any]) -> list[list[dict[str, int]]]:
    order = field_order(program)
    domains: list[list[dict[str, int]]] = [unique_states(program["initial_domain"], order)]
    for segment_id in program["path"]:
        next_states = []
        for state in domains[-1]:
            result = execute_segment(program, segment_id, state)
            if result.status == "ok":
                next_states.append(result.state)
        domains.append(unique_states(next_states, order))
    return domains


def _whole_entries(program: Mapping[str, Any], key_fields: Sequence[str]) -> list[dict[str, Any]]:
    table: dict[tuple[int, ...], dict[str, Any]] = {}
    for state in program["initial_domain"]:
        result = execute_path(program, state)
        key = project(state, key_fields)
        item = {
            "key": {name: value for name, value in zip(key_fields, key, strict=True)},
            "result": _result_json(result, program["final_fields"]),
        }
        previous = table.get(key)
        if previous is not None and _freeze(previous["result"]) != _freeze(item["result"]):
            raise CertificateError("stage keys do not induce an exact whole-path summary")
        table[key] = item
    return [table[key] for key in sorted(table)]


def produce_certificate(program: Mapping[str, Any], include_rejections: bool = True) -> dict[str, Any]:
    validate_program(program)
    order = field_order(program)
    domains = forward_domains(program)
    stages_reversed: list[dict[str, Any]] = []
    required = list(program["final_fields"])

    for stage_index in range(len(program["path"]) - 1, -1, -1):
        segment_id = program["path"][stage_index]
        domain = domains[stage_index]
        key_fields, results, masks = minimum_exact_key(program, segment_id, domain, required)
        support = conservative_support(program, segment_id, required)
        stage: dict[str, Any] = {
            "index": stage_index,
            "segment": segment_id,
            "domain": domain,
            "key_fields": key_fields,
            "out_fields": list(required),
            "entries": _summary_entries(domain, results, key_fields, required),
            "minimality": {
                "criterion": "minimum-cardinality-then-declaration-order",
                "collision_masks": len(masks),
            },
            "support_fields": support,
        }
        if include_rejections:
            roles = {item["name"]: item.get("role", "value") for item in program["fields"]}
            candidates = {
                "empty": [],
                "call-context": [
                    name for name in order if roles[name] in {"context", "stack"}
                ],
                "security-surface": [
                    name for name in order if roles[name] in {"taint", "sanitizer", "alias", "source"}
                ],
            }
            stage["rejections"] = {
                label: rejection_certificate(program, segment_id, domain, required, fields)
                for label, fields in candidates.items()
            }
        stages_reversed.append(stage)
        required = key_fields

    stages = list(reversed(stages_reversed))
    certificate = {
        "schema": "pathseal-certificate",
        "program": json.loads(json.dumps(program)),
        "field_order": order,
        "stages": stages,
        "whole_key_fields": stages[0]["key_fields"],
        "whole_entries": _whole_entries(program, stages[0]["key_fields"]),
        "production": {
            "programs": 1,
            "stages": len(stages),
            "domain_states": sum(len(domain) for domain in domains[:-1]),
        },
    }
    return certificate


def baseline_metrics(program: Mapping[str, Any], certificate: Mapping[str, Any]) -> list[dict[str, Any]]:
    order = field_order(program)
    roles = {item["name"]: item.get("role", "value") for item in program["fields"]}
    rows: list[dict[str, Any]] = []
    for stage in certificate["stages"]:
        domain = stage["domain"]
        stage_results = [execute_segment(program, stage["segment"], state) for state in domain]
        candidates = {
            "exact-state": order,
            "support": stage["support_fields"],
            "pathseal": stage["key_fields"],
            "call-context": [name for name in order if roles[name] in {"context", "stack"}],
            "security-surface": [
                name for name in order if roles[name] in {"taint", "sanitizer", "alias", "source"}
            ],
            "syntax-only": [],
        }
        for label, key_fields in candidates.items():
            metrics = _projection_metrics_from_results(
                program, domain, stage_results, stage["out_fields"], key_fields
            )
            metrics.update(
                {
                    "stage": stage["index"],
                    "segment": stage["segment"],
                    "baseline": label,
                    "domain_size": len(domain),
                }
            )
            rows.append(metrics)
    return rows
