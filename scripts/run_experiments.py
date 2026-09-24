#!/usr/bin/env python3
"""Run the bounded PathSeal evaluation campaign.

The campaign is deterministic except for elapsed-time measurements.  All semantic
counts are regenerated from the program generator and independently checked.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from checker.independent_checker import check_certificate
from pathseal.generator import campaign, make_program
from pathseal.model import execute_path
from pathseal.producer import baseline_metrics, produce_certificate

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
EXAMPLES = ROOT / "examples"


def percentile(values: Iterable[float], q: float) -> float:
    xs = sorted(float(value) for value in values)
    if not xs:
        return 0.0
    if len(xs) == 1:
        return xs[0]
    position = (len(xs) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return xs[lower]
    fraction = position - lower
    return xs[lower] * (1.0 - fraction) + xs[upper] * fraction


def mean(values: Iterable[float]) -> float:
    xs = [float(value) for value in values]
    return statistics.fmean(xs) if xs else 0.0


def median(values: Iterable[float]) -> float:
    xs = [float(value) for value in values]
    return statistics.median(xs) if xs else 0.0


def rounded(value: float, digits: int = 3) -> float:
    return round(float(value), digits)


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def tier_of(program: dict[str, Any]) -> str:
    return program["name"].split("-", 1)[0]


def run_campaign(limit: int | None = None) -> dict[str, Any]:
    programs = campaign()
    if limit is not None:
        programs = programs[:limit]
    if not programs:
        raise ValueError("campaign selection is empty")

    RESULTS.mkdir(parents=True, exist_ok=True)
    EXAMPLES.mkdir(parents=True, exist_ok=True)

    program_rows: list[dict[str, Any]] = []
    stage_rows: list[dict[str, Any]] = []
    baseline_rows: list[dict[str, Any]] = []
    certificates: dict[str, dict[str, Any]] = {}
    key_field_frequency: Counter[str] = Counter()
    key_role_frequency: Counter[str] = Counter()
    terminal_status: Counter[str] = Counter()

    for ordinal, program in enumerate(programs, start=1):
        tier = tier_of(program)

        producer_start = time.perf_counter()
        certificate = produce_certificate(program, include_rejections=False)
        producer_ms = (time.perf_counter() - producer_start) * 1000.0

        checker_start = time.perf_counter()
        check = check_certificate(certificate)
        checker_ms = (time.perf_counter() - checker_start) * 1000.0
        if check["status"] != "PASS":
            raise RuntimeError(f"checker failed for {program['name']}")

        metrics = baseline_metrics(program, certificate)
        for row in metrics:
            enriched = dict(row)
            enriched.update({"program": program["name"], "tier": tier})
            baseline_rows.append(enriched)

        roles = {item["name"]: item.get("role", "value") for item in program["fields"]}
        for stage in certificate["stages"]:
            for field in stage["key_fields"]:
                key_field_frequency[field] += 1
                key_role_frequency[roles[field]] += 1
        for state in program["initial_domain"]:
            terminal_status[execute_path(program, state).status] += 1

        per_stage = defaultdict(dict)
        for row in metrics:
            per_stage[int(row["stage"])][row["baseline"]] = row

        for stage in certificate["stages"]:
            index = int(stage["index"])
            selected = per_stage[index]
            pathseal = selected["pathseal"]
            support = selected["support"]
            exact_state = selected["exact-state"]
            stage_rows.append(
                {
                    "program": program["name"],
                    "tier": tier,
                    "stage": index,
                    "segment": stage["segment"],
                    "domain_size": len(stage["domain"]),
                    "field_count": len(program["fields"]),
                    "pathseal_key_width": pathseal["key_width"],
                    "support_key_width": support["key_width"],
                    "exact_state_key_width": exact_state["key_width"],
                    "pathseal_keys": pathseal["distinct_keys"],
                    "support_keys": support["distinct_keys"],
                    "exact_state_keys": exact_state["distinct_keys"],
                    "pathseal_reuse": rounded(pathseal["reuse_factor"], 6),
                    "support_reuse": rounded(support["reuse_factor"], 6),
                    "exact_state_reuse": rounded(exact_state["reuse_factor"], 6),
                    "collision_masks": stage["minimality"]["collision_masks"],
                }
            )

        pathseal_entries = sum(len(stage["entries"]) for stage in certificate["stages"])
        exact_entries = sum(len(stage["domain"]) for stage in certificate["stages"])
        support_entries = sum(per_stage[index]["support"]["distinct_keys"] for index in per_stage)
        program_rows.append(
            {
                "program": program["name"],
                "tier": tier,
                "fields": len(program["fields"]),
                "segments": len(program["path"]),
                "initial_states": len(program["initial_domain"]),
                "reachable_stage_states": check["reachable_stage_states"],
                "pathseal_entries": pathseal_entries,
                "support_entries": support_entries,
                "exact_state_entries": exact_entries,
                "whole_keys": check["whole_keys"],
                "subset_obligations": check["subset_obligations"],
                "execution_obligations": check["execution_obligations"],
                "producer_ms": rounded(producer_ms, 3),
                "checker_ms": rounded(checker_ms, 3),
                "certificate_bytes": len(json.dumps(certificate, sort_keys=True, separators=(",", ":")).encode("utf-8")),
            }
        )

        # Retain a compact sample certificate for each tier.  These samples add
        # named rejection witnesses and can be checked by the standalone CLI.
        if tier not in certificates:
            sample = produce_certificate(program, include_rejections=True)
            if check_certificate(sample)["status"] != "PASS":
                raise RuntimeError("sample certificate failed independent replay")
            certificates[tier] = sample
            (EXAMPLES / f"{tier}-program.json").write_text(
                json.dumps(program, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (EXAMPLES / f"{tier}-certificate.json").write_text(
                json.dumps(sample, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )

        if ordinal % 10 == 0 or ordinal == len(programs):
            print(f"checked {ordinal}/{len(programs)} programs", flush=True)

    write_csv(
        RESULTS / "program_results.csv",
        program_rows,
        [
            "program", "tier", "fields", "segments", "initial_states",
            "reachable_stage_states", "pathseal_entries", "support_entries",
            "exact_state_entries", "whole_keys", "subset_obligations",
            "execution_obligations", "producer_ms", "checker_ms", "certificate_bytes",
        ],
    )
    write_csv(
        RESULTS / "stage_results.csv",
        stage_rows,
        [
            "program", "tier", "stage", "segment", "domain_size", "field_count",
            "pathseal_key_width", "support_key_width", "exact_state_key_width",
            "pathseal_keys", "support_keys", "exact_state_keys", "pathseal_reuse",
            "support_reuse", "exact_state_reuse", "collision_masks",
        ],
    )
    write_csv(
        RESULTS / "baseline_results.csv",
        baseline_rows,
        [
            "program", "tier", "stage", "segment", "baseline", "domain_size",
            "key_fields", "key_width", "distinct_keys", "error_states",
            "collision_pairs", "exact", "reuse_factor", "collision_masks",
        ],
    )

    by_tier: dict[str, dict[str, Any]] = {}
    for tier in ("small", "medium", "large"):
        selected_programs = [row for row in program_rows if row["tier"] == tier]
        selected_stages = [row for row in stage_rows if row["tier"] == tier]
        if not selected_programs:
            continue
        by_tier[tier] = {
            "programs": len(selected_programs),
            "fields": sorted({row["fields"] for row in selected_programs}),
            "segments": sorted({row["segments"] for row in selected_programs}),
            "initial_states": sorted({row["initial_states"] for row in selected_programs}),
            "producer_ms_median": rounded(median(row["producer_ms"] for row in selected_programs)),
            "producer_ms_p95": rounded(percentile((row["producer_ms"] for row in selected_programs), 0.95)),
            "checker_ms_median": rounded(median(row["checker_ms"] for row in selected_programs)),
            "checker_ms_p95": rounded(percentile((row["checker_ms"] for row in selected_programs), 0.95)),
            "certificate_bytes_median": int(median(row["certificate_bytes"] for row in selected_programs)),
            "pathseal_reuse_mean": rounded(mean(row["pathseal_reuse"] for row in selected_stages)),
            "pathseal_key_width_mean": rounded(mean(row["pathseal_key_width"] for row in selected_stages)),
            "support_key_width_mean": rounded(mean(row["support_key_width"] for row in selected_stages)),
            "exact_state_key_width_mean": rounded(mean(row["exact_state_key_width"] for row in selected_stages)),
        }

    baseline_summary: dict[str, Any] = {}
    for baseline in sorted({row["baseline"] for row in baseline_rows}):
        rows = [row for row in baseline_rows if row["baseline"] == baseline]
        baseline_summary[baseline] = {
            "stages": len(rows),
            "exact_stages": sum(bool(row["exact"]) for row in rows),
            "inexact_stages": sum(not bool(row["exact"]) for row in rows),
            "error_states": sum(int(row["error_states"]) for row in rows),
            "collision_pairs": sum(int(row["collision_pairs"]) for row in rows),
            "mean_key_width": rounded(mean(row["key_width"] for row in rows)),
            "mean_reuse_factor": rounded(mean(row["reuse_factor"] for row in rows)),
            "distinct_keys": sum(int(row["distinct_keys"]) for row in rows),
        }

    segment_summary: dict[str, Any] = {}
    for segment in sorted({row["segment"] for row in stage_rows}):
        rows = [row for row in stage_rows if row["segment"] == segment]
        segment_summary[segment] = {
            "stages": len(rows),
            "domain_size_mean": rounded(mean(row["domain_size"] for row in rows)),
            "key_width_mean": rounded(mean(row["pathseal_key_width"] for row in rows)),
            "reuse_mean": rounded(mean(row["pathseal_reuse"] for row in rows)),
        }
    key_width_distribution = Counter(int(row["pathseal_key_width"]) for row in stage_rows)
    dead_key_occurrences = sum(
        count for name, count in key_field_frequency.items() if name.startswith("dead")
    )

    pathseal_stages = baseline_summary["pathseal"]["stages"]
    status = "PASS"
    if baseline_summary["pathseal"]["inexact_stages"]:
        status = "FAIL"
    if baseline_summary["support"]["inexact_stages"] or baseline_summary["exact-state"]["inexact_stages"]:
        status = "FAIL"
    if not any(baseline_summary[name]["inexact_stages"] for name in ("call-context", "security-surface", "syntax-only")):
        status = "FAIL"
    if dead_key_occurrences != 0:
        status = "FAIL"

    total_execution = sum(int(row["execution_obligations"]) for row in program_rows)
    total_subset = sum(int(row["subset_obligations"]) for row in program_rows)
    summary = {
        "status": status,
        "campaign": {
            "programs": len(program_rows),
            "tiers": dict(Counter(row["tier"] for row in program_rows)),
            "stages": len(stage_rows),
            "initial_states": sum(int(row["initial_states"]) for row in program_rows),
            "reachable_stage_states": sum(int(row["reachable_stage_states"]) for row in program_rows),
            "subset_obligations": total_subset,
            "execution_obligations": total_execution,
            "checked_semantic_obligations": total_subset + total_execution,
            "pathseal_exact_stages": baseline_summary["pathseal"]["exact_stages"],
            "pathseal_stage_count": pathseal_stages,
        },
        "tier_summary": by_tier,
        "baseline_summary": baseline_summary,
        "segment_summary": segment_summary,
        "key_width_distribution": {str(key): value for key, value in sorted(key_width_distribution.items())},
        "key_field_frequency": dict(sorted(key_field_frequency.items())),
        "key_role_frequency": dict(sorted(key_role_frequency.items())),
        "terminal_status": dict(sorted(terminal_status.items())),
        "dead_key_occurrences": dead_key_occurrences,
        "aggregate": {
            "pathseal_entry_reduction_vs_exact_state_percent": rounded(
                100.0 * (1.0 - sum(row["pathseal_entries"] for row in program_rows) / sum(row["exact_state_entries"] for row in program_rows))
            ),
            "pathseal_entry_reduction_vs_support_percent": rounded(
                100.0 * (1.0 - sum(row["pathseal_entries"] for row in program_rows) / sum(row["support_entries"] for row in program_rows))
            ),
            "pathseal_key_width_reduction_vs_exact_state_percent": rounded(
                100.0 * (1.0 - mean(row["pathseal_key_width"] for row in stage_rows) / mean(row["exact_state_key_width"] for row in stage_rows))
            ),
            "pathseal_key_width_reduction_vs_support_percent": rounded(
                100.0 * (1.0 - mean(row["pathseal_key_width"] for row in stage_rows) / mean(row["support_key_width"] for row in stage_rows))
            ),
            "producer_ms_total": rounded(sum(row["producer_ms"] for row in program_rows)),
            "checker_ms_total": rounded(sum(row["checker_ms"] for row in program_rows)),
            "checker_obligations_per_second": rounded(
                1000.0 * (total_execution + total_subset) / max(1e-9, sum(row["checker_ms"] for row in program_rows))
            ),
        },
    }
    (RESULTS / "experiment_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, sort_keys=True))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the bounded PathSeal experiment campaign")
    parser.add_argument("--limit", type=int, default=None, help="run only the first N generated programs")
    args = parser.parse_args()
    summary = run_campaign(args.limit)
    return 0 if summary["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
