#!/usr/bin/env python3
"""Mutation campaign against the independent checker."""
from __future__ import annotations

import copy
import csv
import json
from pathlib import Path
from typing import Any, Callable

from checker.independent_checker import CheckFailure, check_certificate
from pathseal.generator import make_program
from pathseal.producer import produce_certificate


ROOT = Path(__file__).resolve().parents[1]
CSV_OUT = ROOT / "results" / "mutation_results.csv"
JSON_OUT = ROOT / "results" / "mutation_summary.json"


def stage(cert: dict[str, Any], index: int) -> dict[str, Any]:
    return cert["stages"][index % len(cert["stages"])]


def entry(cert: dict[str, Any], index: int) -> dict[str, Any]:
    items = stage(cert, index)["entries"]
    return items[index % len(items)]


def flip(value: int, modulus: int = 4) -> int:
    return (value + 1) % modulus


def mutate_drop_stage(cert, i):
    cert["stages"].pop(i % len(cert["stages"]))


def mutate_swap_stage(cert, i):
    cert["stages"][0], cert["stages"][1] = cert["stages"][1], cert["stages"][0]


def mutate_add_key(cert, i):
    s = stage(cert, i)
    if "dead0" not in s["key_fields"]:
        s["key_fields"].append("dead0")
    else:
        s["key_fields"].append("input")


def mutate_drop_key(cert, i):
    s = next(item for item in cert["stages"] if item["key_fields"])
    s["key_fields"].pop(0)


def mutate_event(cert, i):
    e = entry(cert, i)
    if e["result"]["events"]:
        e["result"]["events"][0][0] += "-changed"
    else:
        e["result"]["events"].append(["changed", []])


def mutate_status(cert, i):
    e = entry(cert, i)
    e["result"]["status"] = "stack_error" if e["result"]["status"] == "ok" else "ok"


def mutate_out(cert, i):
    e = next(entry for s in cert["stages"] for entry in s["entries"] if entry["result"]["out"])
    name = next(iter(e["result"]["out"]))
    e["result"]["out"][name] = flip(e["result"]["out"][name])


def mutate_delete_entry(cert, i):
    s = stage(cert, i)
    s["entries"].pop(i % len(s["entries"]))


def mutate_duplicate_entry(cert, i):
    s = stage(cert, i)
    s["entries"].append(copy.deepcopy(s["entries"][0]))


def mutate_domain_value(cert, i):
    s = stage(cert, i)
    target = s["domain"][i % len(s["domain"])]
    target["dead0"] = flip(target["dead0"])


def mutate_drop_domain(cert, i):
    s = stage(cert, i)
    s["domain"].pop(i % len(s["domain"]))


def mutate_add_domain(cert, i):
    s = stage(cert, i)
    new_state = copy.deepcopy(s["domain"][0])
    new_state["dead0"] = flip(new_state["dead0"])
    s["domain"].append(new_state)


def mutate_segment(cert, i):
    s = stage(cert, i)
    s["segment"] = cert["program"]["path"][(s["index"] + 1) % len(cert["program"]["path"])]


def mutate_out_fields(cert, i):
    s = stage(cert, i)
    s["out_fields"] = list(reversed(s["out_fields"]))


def mutate_whole_key(cert, i):
    cert["whole_key_fields"] = cert["whole_key_fields"] + ["dead0"]


def mutate_whole_entry(cert, i):
    e = cert["whole_entries"][i % len(cert["whole_entries"])]
    e["result"]["events"].append(["forged", [i]])


def mutate_operation(cert, i):
    op = cert["program"]["segments"][0]["ops"][0]
    op["expr"] = {"field": "guard"}


def mutate_path(cert, i):
    cert["program"]["path"][0], cert["program"]["path"][1] = cert["program"]["path"][1], cert["program"]["path"][0]


def mutate_initial_domain(cert, i):
    target = cert["program"]["initial_domain"][i % len(cert["program"]["initial_domain"])]
    target["dead0"] = flip(target["dead0"])


def mutate_repair(cert, i):
    rejection = cert["stages"][0]["rejections"]["empty"]
    if rejection["repair_fields"]:
        rejection["repair_fields"] = rejection["repair_fields"][1:]
    else:
        rejection["repair_fields"] = ["dead0"]


def mutate_support(cert, i):
    s = stage(cert, i)
    if "dead0" in s["support_fields"]:
        s["support_fields"].remove("dead0")
    else:
        s["support_fields"].append("dead0")


def mutate_rejection_label(cert, i):
    rejections = stage(cert, i)["rejections"]
    rejections["empty"], rejections["call-context"] = rejections["call-context"], rejections["empty"]


def mutate_rejection_candidate(cert, i):
    rejection = stage(cert, i)["rejections"]["call-context"]
    rejection["candidate_fields"] = []


def mutate_top_level_extra(cert, i):
    cert["unexpected"] = i


def mutate_stage_extra(cert, i):
    stage(cert, i)["unexpected"] = i


def mutate_field_role(cert, i):
    cert["program"]["fields"][0]["role"] = "context"


def mutate_production(cert, i):
    cert["production"]["domain_states"] += 1


def mutate_minimality(cert, i):
    stage(cert, i)["minimality"]["collision_masks"] += 1


MUTATORS: list[tuple[str, Callable[[dict[str, Any], int], None]]] = [
    ("drop-stage", mutate_drop_stage),
    ("swap-stage", mutate_swap_stage),
    ("add-key-field", mutate_add_key),
    ("drop-key-field", mutate_drop_key),
    ("change-event", mutate_event),
    ("change-status", mutate_status),
    ("change-output", mutate_out),
    ("delete-entry", mutate_delete_entry),
    ("duplicate-entry", mutate_duplicate_entry),
    ("change-domain-value", mutate_domain_value),
    ("drop-domain-state", mutate_drop_domain),
    ("add-domain-state", mutate_add_domain),
    ("change-segment", mutate_segment),
    ("change-output-interface", mutate_out_fields),
    ("change-whole-key", mutate_whole_key),
    ("change-whole-entry", mutate_whole_entry),
    ("change-program-operation", mutate_operation),
    ("change-program-path", mutate_path),
    ("change-initial-domain", mutate_initial_domain),
    ("change-repair", mutate_repair),
    ("change-support", mutate_support),
    ("swap-rejection-labels", mutate_rejection_label),
    ("change-rejection-candidate", mutate_rejection_candidate),
    ("add-top-level-field", mutate_top_level_extra),
    ("add-stage-field", mutate_stage_extra),
    ("change-field-role", mutate_field_role),
    ("change-production-receipt", mutate_production),
    ("change-minimality-receipt", mutate_minimality),
]


def main() -> int:
    base = produce_certificate(make_program("mutation-base", "small", 31337), include_rejections=True)
    if check_certificate(base)["status"] != "PASS":
        raise SystemExit("base certificate did not pass")

    rows: list[dict[str, Any]] = []
    accepted = 0
    for label, mutator in MUTATORS:
        for index in range(10):
            candidate = copy.deepcopy(base)
            mutator(candidate, index)
            rejected = False
            reason = ""
            try:
                check_certificate(candidate)
            except (CheckFailure, KeyError, TypeError, ValueError, IndexError) as exc:
                rejected = True
                reason = type(exc).__name__
            if not rejected:
                accepted += 1
            rows.append({"mutation": label, "variant": index, "rejected": int(rejected), "reason": reason})

    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    with CSV_OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["mutation", "variant", "rejected", "reason"])
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "status": "PASS" if accepted == 0 else "FAIL",
        "mutation_operators": len(MUTATORS),
        "variants": len(rows),
        "rejected": len(rows) - accepted,
        "accepted": accepted,
    }
    JSON_OUT.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0 if accepted == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
