#!/usr/bin/env python3
"""Authoritative bounded reproduction entry point for the PathSeal artifact."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(label: str, arguments: list[str]) -> None:
    print(f"== {label} ==", flush=True)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    process = subprocess.Popen(
        [sys.executable, *arguments],
        cwd=ROOT,
        env=environment,
        text=True,
        start_new_session=True,
    )
    try:
        returncode = process.wait(timeout=180)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise SystemExit(f"{label} exceeded the 180-second bound")
    completed = subprocess.CompletedProcess(process.args, returncode)
    if completed.returncode != 0:
        raise SystemExit(f"{label} failed with exit status {completed.returncode}")


def require_pass(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("status") != "PASS":
        raise SystemExit(f"{path.relative_to(ROOT)} does not record PASS")
    return value


def main() -> int:
    run("unit tests", ["-m", "unittest", "discover", "-s", "tests", "-v"])
    run("finite theorem checks", ["scripts/theorem_checks.py"])
    run("certificate mutation tests", ["scripts/mutation_tests.py"])
    run("generated campaign", ["scripts/run_experiments.py"])
    for tier in ("small", "medium", "large"):
        run(
            f"standalone checker ({tier})",
            ["-m", "checker.independent_checker", f"examples/{tier}-certificate.json"],
        )
    run("artifact structural audit", ["scripts/audit_artifact.py"])

    theorem = require_pass(ROOT / "results" / "theorem_checks.json")
    mutation = require_pass(ROOT / "results" / "mutation_summary.json")
    experiment = require_pass(ROOT / "results" / "experiment_summary.json")
    require_pass(ROOT / "results" / "artifact_audit.json")
    if mutation.get("accepted") != 0:
        raise SystemExit("a certificate mutation was accepted")
    if experiment["campaign"]["pathseal_exact_stages"] != experiment["campaign"]["pathseal_stage_count"]:
        raise SystemExit("not every PathSeal stage was exact")
    if theorem["composition"]["composition_obligations"] != 262144:
        raise SystemExit("the finite composition census is incomplete")
    if theorem["hardness_reduction"]["hypergraph_instances"] != 128:
        raise SystemExit("the finite hardness-reduction census is incomplete")
    if experiment.get("dead_key_occurrences") != 0:
        raise SystemExit("a declared dead field appeared in a minimum key")
    if experiment["campaign"]["programs"] != 120 or experiment["campaign"]["stages"] != 940:
        raise SystemExit("the frozen campaign cardinality changed")
    if mutation.get("mutation_operators") != 28 or mutation.get("variants") != 280:
        raise SystemExit("the frozen mutation campaign is incomplete")

    print("FULL_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
