#!/usr/bin/env python3
"""Export stable LaTeX tables and plot data from the aggregate result JSON."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fmt(value, digits=1):
    if isinstance(value, int):
        return f"{value:,}"
    return f"{float(value):.{digits}f}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "paper-data")
    args = parser.parse_args()
    summary = json.loads((ROOT / "results" / "experiment_summary.json").read_text(encoding="utf-8"))
    theorem = json.loads((ROOT / "results" / "theorem_checks.json").read_text(encoding="utf-8"))
    mutation = json.loads((ROOT / "results" / "mutation_summary.json").read_text(encoding="utf-8"))
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    campaign = summary["campaign"]
    aggregate = summary["aggregate"]
    b = summary["baseline_summary"]
    macros = {
        "CampaignPrograms": campaign["programs"],
        "CampaignStages": campaign["stages"],
        "CampaignInitialStates": campaign["initial_states"],
        "ReachableStageStates": campaign["reachable_stage_states"],
        "SemanticObligations": campaign["checked_semantic_obligations"],
        "SubsetObligations": campaign["subset_obligations"],
        "ExecutionObligations": campaign["execution_obligations"],
        "PathSealExactStages": campaign["pathseal_exact_stages"],
        "MutationOperators": mutation["mutation_operators"],
        "MutationVariants": mutation["variants"],
        "MutationRejected": mutation["rejected"],
        "BooleanFunctions": theorem["hitting_set"]["boolean_functions"],
        "ProjectionObligations": theorem["hitting_set"]["projection_equivalence_obligations"],
        "HardnessInstances": theorem["hardness_reduction"]["hypergraph_instances"],
        "HardnessEdges": theorem["hardness_reduction"]["source_edges_checked"],
        "CompositionPairs": theorem["composition"]["transform_pairs"],
        "CompositionObligations": theorem["composition"]["composition_obligations"],
        "EntryReductionExact": f"{aggregate['pathseal_entry_reduction_vs_exact_state_percent']:.1f}",
        "KeyReductionExact": f"{aggregate['pathseal_key_width_reduction_vs_exact_state_percent']:.1f}",
        "KeyReductionSupport": f"{aggregate['pathseal_key_width_reduction_vs_support_percent']:.1f}",
        "CheckerThroughput": f"{aggregate['checker_obligations_per_second']:.0f}",
        "CallContextInexact": b["call-context"]["inexact_stages"],
        "SurfaceInexact": b["security-surface"]["inexact_stages"],
        "SyntaxInexact": b["syntax-only"]["inexact_stages"],
        "CallContextCollisions": b["call-context"]["collision_pairs"],
        "SurfaceCollisions": b["security-surface"]["collision_pairs"],
        "SyntaxCollisions": b["syntax-only"]["collision_pairs"],
        "TerminalOK": summary["terminal_status"].get("ok", 0),
        "TerminalInfeasible": summary["terminal_status"].get("infeasible", 0),
        "TerminalStackError": summary["terminal_status"].get("stack_error", 0),
        "DeadKeyOccurrences": summary.get("dead_key_occurrences", 0),
        "WidthOne": summary["key_width_distribution"].get("1", 0),
        "WidthTwo": summary["key_width_distribution"].get("2", 0),
        "WidthThree": summary["key_width_distribution"].get("3", 0),
        "WidthFour": summary["key_width_distribution"].get("4", 0),
        "WidthFive": summary["key_width_distribution"].get("5", 0),
        "SmallProducerMs": f"{summary['tier_summary']['small']['producer_ms_median']:.1f}",
        "SmallCheckerMs": f"{summary['tier_summary']['small']['checker_ms_median']:.1f}",
        "MediumProducerMs": f"{summary['tier_summary']['medium']['producer_ms_median']:.1f}",
        "MediumCheckerMs": f"{summary['tier_summary']['medium']['checker_ms_median']:.1f}",
        "LargeProducerMs": f"{summary['tier_summary']['large']['producer_ms_median']:.1f}",
        "LargeCheckerMs": f"{summary['tier_summary']['large']['checker_ms_median']:.1f}",
        "SmallCertBytes": summary['tier_summary']['small']['certificate_bytes_median'],
        "MediumCertBytes": summary['tier_summary']['medium']['certificate_bytes_median'],
        "LargeCertBytes": summary['tier_summary']['large']['certificate_bytes_median'],
    }
    lines = ["% Generated from artifact results; do not edit by hand."]
    for name, value in macros.items():
        if isinstance(value, int):
            rendered = f"{value:,}"
        else:
            rendered = str(value)
        lines.append(f"\\newcommand{{\\{name}}}{{{rendered}}}")
    (out / "macros.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")

    tier_lines = [
        "\\begin{tabular}{lrrrrrr}",
        "\\toprule",
        "Tier & Programs & Fields & Segments & Inputs & Producer med. (ms) & Checker med. (ms)\\\\",
        "\\midrule",
    ]
    key_lines = [
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "Tier & Full state & Support & PathSeal & Reuse\\\\",
        "\\midrule",
    ]
    key_dat = ["tier full support pathseal reuse"]
    runtime_dat = ["tier producer checker producerp95 checkerp95"]
    for tier in ("small", "medium", "large"):
        row = summary["tier_summary"][tier]
        tier_lines.append(
            f"{tier.title()} & {row['programs']} & {row['fields'][0]} & {row['segments'][0]} & {row['initial_states'][0]} & "
            f"{row['producer_ms_median']:.1f} & {row['checker_ms_median']:.1f}\\\\"
        )
        key_lines.append(
            f"{tier.title()} & {row['exact_state_key_width_mean']:.1f} & {row['support_key_width_mean']:.1f} & "
            f"{row['pathseal_key_width_mean']:.1f} & {row['pathseal_reuse_mean']:.2f}$\\times$\\\\"
        )
        key_dat.append(
            f"{tier} {row['exact_state_key_width_mean']:.6f} {row['support_key_width_mean']:.6f} "
            f"{row['pathseal_key_width_mean']:.6f} {row['pathseal_reuse_mean']:.6f}"
        )
        runtime_dat.append(
            f"{tier} {row['producer_ms_median']:.6f} {row['checker_ms_median']:.6f} "
            f"{row['producer_ms_p95']:.6f} {row['checker_ms_p95']:.6f}"
        )
    tier_lines.extend(["\\bottomrule", "\\end{tabular}"])
    key_lines.extend(["\\bottomrule", "\\end{tabular}"])
    (out / "tier-table.tex").write_text("\n".join(tier_lines) + "\n", encoding="utf-8")
    (out / "key-table.tex").write_text("\n".join(key_lines) + "\n", encoding="utf-8")
    (out / "key-widths.dat").write_text("\n".join(key_dat) + "\n", encoding="utf-8")
    (out / "runtime.dat").write_text("\n".join(runtime_dat) + "\n", encoding="utf-8")

    baseline_order = ["exact-state", "support", "pathseal", "call-context", "security-surface", "syntax-only"]
    baseline_lines = [
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "Projection & Mean width & Exact stages & Inexact stages & Collision pairs\\\\",
        "\\midrule",
    ]
    baseline_dat = ["name inexact errors collisions width"]
    labels = {
        "exact-state": "Exact state",
        "support": "Syntactic support",
        "pathseal": "PathSeal",
        "call-context": "Call context",
        "security-surface": "Security surface",
        "syntax-only": "Empty/syntax only",
    }
    for name in baseline_order:
        row = b[name]
        baseline_lines.append(
            f"{labels[name]} & {row['mean_key_width']:.2f} & {row['exact_stages']:,} & "
            f"{row['inexact_stages']:,} & {row['collision_pairs']:,}\\\\"
        )
        baseline_dat.append(
            f"{name.replace('-', '')} {row['inexact_stages']} {row['error_states']} {row['collision_pairs']} {row['mean_key_width']:.6f}"
        )
    baseline_lines.extend(["\\bottomrule", "\\end{tabular}"])
    (out / "baseline-table.tex").write_text("\n".join(baseline_lines) + "\n", encoding="utf-8")
    (out / "baselines.dat").write_text("\n".join(baseline_dat) + "\n", encoding="utf-8")

    segment_lines = [
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "Segment & Instances & Mean domain & Mean key & Mean reuse\\\\",
        "\\midrule",
    ]
    for segment, row in summary["segment_summary"].items():
        label = segment.replace("-", "\\mbox{-}")
        segment_lines.append(
            f"{label} & {row['stages']} & {row['domain_size_mean']:.1f} & "
            f"{row['key_width_mean']:.2f} & {row['reuse_mean']:.2f}$\\times$\\\\"
        )
    segment_lines.extend(["\\bottomrule", "\\end{tabular}"])
    (out / "segment-table.tex").write_text("\n".join(segment_lines) + "\n", encoding="utf-8")

    role_lines = [
        "\\begin{tabular}{lrr}",
        "\\toprule",
        "Field role & Key occurrences & Share (\\%)\\\\",
        "\\midrule",
    ]
    total_role = sum(summary["key_role_frequency"].values())
    for role, count in sorted(summary["key_role_frequency"].items(), key=lambda item: (-item[1], item[0])):
        role_lines.append(f"{role.title()} & {count:,} & {100.0 * count / total_role:.1f}\\\\")
    role_lines.extend(["\\bottomrule", "\\end{tabular}"])
    (out / "role-table.tex").write_text("\n".join(role_lines) + "\n", encoding="utf-8")

    width_dat = ["width stages"]
    for width, count in sorted(summary["key_width_distribution"].items(), key=lambda item: int(item[0])):
        width_dat.append(f"{width} {count}")
    (out / "width-distribution.dat").write_text("\n".join(width_dat) + "\n", encoding="utf-8")

    example_path = ROOT / "examples" / "small-certificate.json"
    if example_path.exists():
        example = json.loads(example_path.read_text(encoding="utf-8"))
        example_lines = [
            "\\begin{tabular}{lrrp{0.24\\linewidth}p{0.25\\linewidth}}",
            "\\toprule",
            "Segment & $|D_i|$ & Entries & Input key $K_i$ & Output interface $O_i$\\\\",
            "\\midrule",
        ]
        rejection_lines = [
            "\\begin{tabular}{lp{0.30\\linewidth}p{0.36\\linewidth}}",
            "\\toprule",
            "Segment & Call-context candidate & Minimum repair\\\\",
            "\\midrule",
        ]
        for stage in example["stages"]:
            k = ", ".join(stage["key_fields"]) or "$\\emptyset$"
            o = ", ".join(stage["out_fields"]) or "$\\emptyset$"
            example_lines.append(
                f"{stage['segment'].replace('-', '\\mbox{-}')} & {len(stage['domain'])} & {len(stage['entries'])} & "
                f"\\texttt{{{k}}} & \\texttt{{{o}}}\\\\"
            )
            rejection = stage.get("rejections", {}).get("call-context")
            if rejection is not None:
                candidate = ", ".join(rejection["candidate_fields"]) or "$\\emptyset$"
                repair = ", ".join(rejection["repair_fields"]) or "$\\emptyset$"
                verdict = "exact" if rejection["exact"] else "inexact"
                rejection_lines.append(
                    f"{stage['segment'].replace('-', '\\mbox{-}')} & \\texttt{{{candidate}}} ({verdict}) & \\texttt{{{repair}}}\\\\"
                )
        example_lines.extend(["\\bottomrule", "\\end{tabular}"])
        rejection_lines.extend(["\\bottomrule", "\\end{tabular}"])
        (out / "example-table.tex").write_text("\n".join(example_lines) + "\n", encoding="utf-8")
        (out / "rejection-table.tex").write_text("\n".join(rejection_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
