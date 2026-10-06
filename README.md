# PathSeal artifact

PathSeal is a self-contained executable artifact for a finite, deterministic
interprocedural segment language.  It computes minimum exact boundary
projections, emits proof-carrying summary tables, reports canonical splice
counterexamples for unsafe projections, and checks every certificate with an
independently implemented semantics.

The artifact uses only the Python standard library and does not download data,
invoke a model, contact a service, or inspect a real codebase.

## Reproduce everything

From this directory, run:

```bash
python3 run_all.py
```

A successful run ends with `FULL_PASS`.  The command executes the unit tests,
three finite theorem checks (exactness, hardness reduction, and composition), 280 certificate mutations from 28 operators, the 120-program
campaign, independent replay of one retained certificate from each scale, and a structural audit of Python, JSON, CSV, and evidence-ledger surfaces.
It regenerates all files under `results/` and the sample programs and
certificates under `examples/`.

The runner supports Windows and POSIX systems. Each command is limited to
180 seconds, and timeout cleanup stops only that command's owned process tree.
The current tests include four runner regressions in addition to the twenty
semantics and certificate tests.

## Main components

- `pathseal/model.py` defines the producer-side finite semantics.
- `pathseal/producer.py` computes exact projections, summaries, repairs, and
  certificates.
- `checker/independent_checker.py` reimplements the semantics and proof
  obligations without importing the producer.
- `pathseal/generator.py` constructs the frozen deterministic campaign.
- `scripts/theorem_checks.py` exhaustively checks the collision-hypergraph characterization, the Boolean hardness-reduction construction, and two-stage composition on complete small universes.
- `scripts/mutation_tests.py` applies 28 classes of certificate corruption, including schema, receipt, support, witness, table, program, and composition mutations.
- `scripts/run_experiments.py` generates and checks the main experimental data.
- `scripts/audit_artifact.py` checks source parsing, finite JSON values, CSV structure, and evidence-ledger completeness.
- `tests/test_core.py` covers the executable contracts directly.

## Interpreting the results

`results/experiment_summary.json` is the authoritative aggregate.  The CSV
files retain one row per program, stage, or baseline.  Runtime values are
observations and may vary across machines; program counts, domains, keys,
proof obligations, exactness outcomes, and mutation outcomes are deterministic.

The retained runtime measurements use CPython 3.12.14 on Windows 11 on an
Intel Family 6, Model 151 processor, with one worker. Both the generated paper
tables and numerical plots use these same observations.

The current Linux Python 3.12 run passed 40 unit tests and reproduced 120
programs, 940 exact stages, and 785,251 semantic obligations; all 280 mutation trials
were rejected. Non-timing CSV fields match the retained campaign. New raw
outputs are in `results/current/`, with larger JSON/CSV files compressed
losslessly as `.gz`. The updated producer and checker aggregate times were
8.53 and 9.46 seconds on that host; they do not replace the historical
Windows timing distributions above.

The certificates establish facts only for the embedded finite program and
explicit input domain.  They are not proofs about full C or C++, exploitability,
production vulnerability detection, unrestricted pointers, concurrency,
reflection, native code, or inputs omitted from the certificate.
