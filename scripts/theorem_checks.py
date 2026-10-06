#!/usr/bin/env python3
"""Executable finite checks for the paper's combinatorial results."""
from __future__ import annotations

import itertools
import json
from pathlib import Path


OUT = Path(__file__).resolve().parents[1] / "results" / "theorem_checks.json"


def projections(width: int):
    for mask in range(1 << width):
        yield tuple(i for i in range(width) if mask & (1 << i))


def key(state: tuple[int, ...], projection: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(state[i] for i in projection)


def exact_for_function(states, outputs, projection):
    table = {}
    for state, output in zip(states, outputs, strict=True):
        k = key(state, projection)
        if k in table and table[k] != output:
            return False
        table[k] = output
    return True


def collision_edges(states, outputs):
    edges = set()
    for i in range(len(states)):
        for j in range(i + 1, len(states)):
            if outputs[i] == outputs[j]:
                continue
            edge = frozenset(k for k, (a, b) in enumerate(zip(states[i], states[j], strict=True)) if a != b)
            edges.add(edge)
    return edges


def hits(projection, edges):
    p = set(projection)
    return all(p & set(edge) for edge in edges)


def minimum_projection(states, outputs):
    width = len(states[0])
    for size in range(width + 1):
        for projection in itertools.combinations(range(width), size):
            if exact_for_function(states, outputs, projection):
                return projection
    raise AssertionError("full state must be exact")


def check_hitting_set_characterization():
    states = tuple(itertools.product((0, 1), repeat=3))
    equivalence_obligations = 0
    minimum_obligations = 0
    for truth_table in range(1 << len(states)):
        outputs = tuple((truth_table >> i) & 1 for i in range(len(states)))
        edges = collision_edges(states, outputs)
        for projection in projections(3):
            equivalence_obligations += 1
            if exact_for_function(states, outputs, projection) != hits(projection, edges):
                raise AssertionError((truth_table, projection, edges))
        brute = minimum_projection(states, outputs)
        candidates = [p for p in projections(3) if hits(p, edges)]
        hyper = min(candidates, key=lambda p: (len(p), p))
        minimum_obligations += 1
        if brute != hyper:
            raise AssertionError((truth_table, brute, hyper))
    return {
        "boolean_functions": 1 << len(states),
        "projection_equivalence_obligations": equivalence_obligations,
        "minimum_key_obligations": minimum_obligations,
    }


def check_hitting_set_reduction():
    """Exhaustively instantiate the NP-hardness reduction on three fields.

    For every hypergraph over the seven nonempty subsets of three fields, the
    constructed labeled state table contains the all-zero state with result 0
    and one characteristic-vector state per hyperedge with result 1.  Its
    collision hypergraph must be exactly the source hypergraph, and its
    canonical minimum exact projection must equal the canonical minimum
    hitting set.
    """
    width = 3
    possible_edges = tuple(
        frozenset(i for i in range(width) if mask & (1 << i))
        for mask in range(1, 1 << width)
    )
    instances = 0
    edge_obligations = 0
    minimum_obligations = 0
    for family_mask in range(1 << len(possible_edges)):
        family = tuple(
            possible_edges[index]
            for index in range(len(possible_edges))
            if family_mask & (1 << index)
        )
        states = [(0,) * width]
        outputs = [0]
        for edge in family:
            states.append(tuple(1 if i in edge else 0 for i in range(width)))
            outputs.append(1)
        states = tuple(states)
        outputs = tuple(outputs)
        observed = collision_edges(states, outputs)
        if observed != set(family):
            raise AssertionError((family, observed))
        edge_obligations += len(family)
        candidates = [p for p in projections(width) if hits(p, family)]
        expected = min(candidates, key=lambda item: (len(item), item))
        actual = minimum_projection(states, outputs)
        if actual != expected:
            raise AssertionError((family, expected, actual))
        minimum_obligations += 1
        instances += 1
    return {
        "boolean_fields": width,
        "hypergraph_instances": instances,
        "source_edges_checked": edge_obligations,
        "minimum_key_obligations": minimum_obligations,
    }


def all_transforms():
    # A transform over two Boolean fields is represented by four output-state
    # indices, one for each input state.
    for outputs in itertools.product(range(4), repeat=4):
        yield outputs


def bits(index: int) -> tuple[int, int]:
    return (index >> 1) & 1, index & 1


def apply(transform, state):
    index = (state[0] << 1) | state[1]
    return bits(transform[index])


def local_summary(transform, out_projection):
    states = tuple(itertools.product((0, 1), repeat=2))
    outputs = tuple(key(apply(transform, state), out_projection) for state in states)
    projection = minimum_projection(states, outputs)
    table = {}
    for state, output in zip(states, outputs, strict=True):
        table[key(state, projection)] = output
    return projection, table


def check_composition():
    states = tuple(itertools.product((0, 1), repeat=2))
    transforms = tuple(all_transforms())
    obligations = 0
    # The final query observes the first component.  The second stage's minimal
    # key is computed first, then used as the first stage's output interface.
    final_projection = (0,)
    for first in transforms:
        for second in transforms:
            second_key, second_table = local_summary(second, final_projection)
            first_key, first_table = local_summary(first, second_key)
            for state in states:
                direct = key(apply(second, apply(first, state)), final_projection)
                middle = first_table[key(state, first_key)]
                composed = second_table[middle]
                obligations += 1
                if direct != composed:
                    raise AssertionError((first, second, state, direct, composed))
    return {
        "two_bit_transforms": len(transforms),
        "transform_pairs": len(transforms) ** 2,
        "composition_obligations": obligations,
    }


def main() -> int:
    result = {
        "status": "PASS",
        "hitting_set": check_hitting_set_characterization(),
        "hardness_reduction": check_hitting_set_reduction(),
        "composition": check_composition(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
