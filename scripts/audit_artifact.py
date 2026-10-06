#!/usr/bin/env python3
"""Fail-closed structural audit for the self-contained PathSeal artifact."""
from __future__ import annotations

import ast
import csv
import json
import math
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "artifact_audit.json"


def check_finite(value: Any, location: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"non-finite number at {location}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            check_finite(item, f"{location}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            check_finite(item, f"{location}.{key}")


def audit_csv(path: Path) -> tuple[list[str], int]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    if not rows or not rows[0]:
        raise ValueError(f"empty CSV: {path.relative_to(ROOT)}")
    width = len(rows[0])
    for line, row in enumerate(rows[1:], 2):
        if len(row) != width:
            raise ValueError(f"ragged CSV {path.relative_to(ROOT)} line {line}")
    return rows[0], max(0, len(rows) - 1)


def main() -> int:
    python_files = sorted(path for path in ROOT.rglob("*.py") if "__pycache__" not in path.parts)
    for path in python_files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    json_files = sorted(list((ROOT / "results").glob("*.json")) + list((ROOT / "examples").glob("*.json")))
    for path in json_files:
        value = json.loads(path.read_text(encoding="utf-8"))
        check_finite(value, str(path.relative_to(ROOT)))

    csv_files = sorted(list((ROOT / "results").glob("*.csv")) + [
        ROOT / "claim_evidence_ledger.csv",
        ROOT / "external_resources.csv",
    ])
    csv_rows: dict[str, int] = {}
    headers: dict[str, list[str]] = {}
    for path in csv_files:
        header, count = audit_csv(path)
        headers[path.name] = header
        csv_rows[path.name] = count

    required_claim = {
        "claim_id", "claim", "theorem_or_lemma", "source_or_test",
        "experiment_or_figure", "raw_result_path", "maturity_state",
        "fresh_self_recheck_status", "scope_limit",
    }
    if set(headers["claim_evidence_ledger.csv"]) != required_claim:
        raise ValueError("claim-evidence ledger schema mismatch")
    with (ROOT / "claim_evidence_ledger.csv").open(newline="", encoding="utf-8") as handle:
        claims = list(csv.DictReader(handle))
    if not claims or any(not all(row.values()) for row in claims):
        raise ValueError("claim-evidence ledger has an empty cell")
    for row in claims:
        status = row["fresh_self_recheck_status"]
        if row["maturity_state"] == "proved":
            if status != "PROOF_REVIEWED":
                raise ValueError("theoretical claim must identify proof review rather than executable evidence")
        elif status != "PASS":
            raise ValueError("executable claim-evidence ledger contains an unchecked claim")

    required_external = {
        "resource", "stable_location", "license_or_terms", "access_date",
        "resource_type", "acquisition_method", "integration_mode",
        "supported_claim", "internals_modified",
    }
    if set(headers["external_resources.csv"]) != required_external:
        raise ValueError("external-resource ledger schema mismatch")
    with (ROOT / "external_resources.csv").open(newline="", encoding="utf-8") as handle:
        resources = list(csv.DictReader(handle))
    if not resources or any(not all(row.values()) for row in resources):
        raise ValueError("external-resource ledger has an empty cell")

    report = {
        "status": "PASS",
        "python_files_parsed": len(python_files),
        "json_files_checked": len(json_files),
        "csv_files_checked": len(csv_files),
        "claim_rows": len(claims),
        "external_resource_rows": len(resources),
        "csv_data_rows": csv_rows,
    }
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
