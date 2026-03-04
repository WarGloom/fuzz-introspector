# DIAG-00 Wall-Time Diagnostic - 2026-03-04

Fresh benchmark run:
- Result JSON: `.work/benchmarks/cgserver-full/results/run_20260304_190241.json`
- Runs: 3
- Wall time avg: `115.06s`
- Peak RSS avg: `6131.26MB`
- Output hash: `3e0a44d44abbf1d3968e2d3e2223045618ffeeb3e37776a6b75c1c9853c2061b`

Reference comparison:
- Versus current reference (`run_20260304_170857.json`, `112.31s / 6127.37MB`):
  - Wall: `+2.75s` (`+2.45%`)
  - RSS: `+3.89MB` (`+0.06%`)
- Versus graduation baseline (`99.03s / 6386.69MB`):
  - Wall: `+16.03s` (`+16.19%`)
  - RSS: `-255.43MB` (`-4.00%`)

Diagnostic readout:
- Wall-time regression is reproducible relative to both reference points.
- Memory remains stable vs current reference and better than graduation baseline.
- Hash parity remains stable across all 3 runs.

Next-step recommendation:
- Run a stage-marker-enabled paired benchmark (baseline vs candidate) and gate `optional_analyses`, `report_generation`, and `type_correlation` to isolate regressed phases before starting MIG-01.
- Blocker for phase isolation in this DIAG-00 run: stage marker logs were not emitted by `.work/scripts/run_benchmark.sh` output artifacts.
