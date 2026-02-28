# Native correlator/overlay gate evidence (2026-02-28)

## Scope
- Objective: re-evaluate native correlator/overlay rollout gates after commit
  `87ab82c761eb49981aefdddb58dbe26d249e8593` on the local introtest dataset.
- Environment: local dev host, repo checkout at `fuzz-introspector`.
- Evidence workspace: `.work/benchmarks`.
- Dataset:
  - Correlator input: `/home/nikita/work/Projects/cg/introtest` (8 type files,
    8 function files).
  - Overlay input:
    `/home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector`.

## Latest artifacts (post-fix)
- Correlator orchestrated compare:
  - `.work/benchmarks/correlator_compare_introtest_aliasflow_fix.json`
  - `.work/benchmarks/correlator_compare_introtest_aliasflow_fix.log`
  - `.work/benchmarks/correlator_compare_introtest_aliasflow_fix.time`
- Overlay strict shadow checks:
  - `.work/benchmarks/overlay_rust_strict_shadow_aliasflow_fix.log`
  - `.work/benchmarks/overlay_rust_strict_shadow_aliasflow_fix.time`
  - `.work/benchmarks/overlay_go_strict_shadow_aliasflow_fix.log`
  - `.work/benchmarks/overlay_go_strict_shadow_aliasflow_fix.time`

## Commands

### Correlator benchmark (orchestrated benchmark tooling)
```bash
TMPDIR=/home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks \
/usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' \
  -o .work/benchmarks/correlator_compare_introtest_aliasflow_fix.time \
  python3 benchmarks/compare_correlator_backends.py \
  --introspector-dir /home/nikita/work/Projects/cg/introtest \
  --backends python,rust,go \
  --output-json .work/benchmarks/correlator_compare_introtest_aliasflow_fix.json \
  > .work/benchmarks/correlator_compare_introtest_aliasflow_fix.log 2>&1
```

### Overlay strict shadow checks (rust/go)
Run `src/main.py report` with strict+shadow enabled for each backend and save
output to:
- `.work/benchmarks/overlay_rust_strict_shadow_aliasflow_fix.{log,time}`
- `.work/benchmarks/overlay_go_strict_shadow_aliasflow_fix.{log,time}`

## Results

### Correlator (`benchmarks/compare_correlator_backends.py` on introtest)
- Parsed counts now match Python for all backends (`parsed_types=2529`,
  `parsed_functions=1808`).
- Digest parity is closed on this local dataset:
  `af54bbec12d42dd80ae6aba3e61ad2a086a1feb289a5afac5dabeeb7571dfc5a`
  for python/rust/go.
- Performance/default-switch gate is still not met in orchestrated compare:
  - python: `total_s=1.375`, `max_rss_mb=31.12`.
  - rust: `total_s=1.418`, `max_rss_mb=33.62`, speedup `0.97x` vs python.
  - go: `total_s=1.398`, `max_rss_mb=35.64`, speedup `0.984x` vs python.

### Overlay strict shadow parity (`report` on introtest inspector dataset)
- Rust strict-shadow run reports zero parity diagnostics:
  `overlay_nodes_values=0` and `branch_*_values=0`.
- Go strict-shadow run reports zero parity diagnostics:
  `overlay_nodes_values=0` and `branch_*_values=0`.
- Runtime remains in the same range as python baseline in local runs
  (`elapsed=0.39` rust, `elapsed=0.42` go in strict-shadow runs).

## Gate decision
- Decision (explicit): parity gates are **closed on the current local dataset**,
  but performance/default-switch gate is **not met**.
- Policy outcome: keep Python as authoritative default for correlator and
  overlay until stronger performance evidence is available.

## Limitations
- Evidence here is local-host and introtest-scoped; no larger container-scale
  dataset was exercised in this pass.
