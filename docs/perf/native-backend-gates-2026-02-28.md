# Native correlator/overlay gate evidence (2026-02-28, refreshed 2026-03-01)

## Scope
- Objective: execute fresh Task 2 and Task 3 benchmark runs with explicit
  `--skip-html-report` overlay checks and a 3-run correlator matrix.
- Environment: local dev host, repo checkout at `fuzz-introspector`.
- Evidence workspace: `.work/benchmarks`.
- Dataset:
  - Correlator input: `/home/nikita/work/Projects/cg/introtest`.
  - Overlay input:
    `/home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector`.

## Exact commands executed

### Task 2: overlay strict-shadow matrix (3x rust, 3x go)
```bash
for backend in rust go; do
  for run in 1 2 3; do
    logf=".work/benchmarks/overlay_${backend}_run${run}_skiphtml.log"
    timef=".work/benchmarks/overlay_${backend}_run${run}_skiphtml.time"
    if [ "$backend" = "rust" ]; then
      bin="/home/nikita/work/Projects/cg/fuzz-introspector/tools/native_overlay_backend_rust/target/release/native_overlay_backend_rust"
    else
      bin="/home/nikita/work/Projects/cg/fuzz-introspector/tools/native_overlay_backend_go/native_overlay_backend_go"
    fi

    FI_OVERLAY_BACKEND="$backend" \
    FI_OVERLAY_NATIVE_BIN="$bin" \
    FI_OVERLAY_STRICT=1 \
    FI_OVERLAY_SHADOW=1 \
    FI_CALLTREE_BITMAP_MAX_NODES=0 \
    /usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' -o "$timef" \
      python3 src/main.py report \
        --target-dir /home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector \
        --analyses OptimalTargets \
        --skip-html-report \
      > "$logf" 2>&1
  done
done
```

### Task 3: correlator matrix (python,rust,go) x3
```bash
for run in 1 2 3; do
  jsonf=".work/benchmarks/correlator_matrix_run${run}_python_rust_go.json"
  logf=".work/benchmarks/correlator_matrix_run${run}_python_rust_go.log"
  timef=".work/benchmarks/correlator_matrix_run${run}_python_rust_go.time"

  /usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' -o "$timef" \
    python3 benchmarks/compare_correlator_backends.py \
      --introspector-dir /home/nikita/work/Projects/cg/introtest \
      --backends python,rust,go \
      --output-json "$jsonf" \
    > "$logf" 2>&1
done
```

## Artifact paths

### Matrix index
- `.work/benchmarks/gate_matrix_introtest_2026-03-01.json`

### Task 2 overlay artifacts
- Rust:
  - `.work/benchmarks/overlay_rust_run1_skiphtml.log`
  - `.work/benchmarks/overlay_rust_run1_skiphtml.time`
  - `.work/benchmarks/overlay_rust_run2_skiphtml.log`
  - `.work/benchmarks/overlay_rust_run2_skiphtml.time`
  - `.work/benchmarks/overlay_rust_run3_skiphtml.log`
  - `.work/benchmarks/overlay_rust_run3_skiphtml.time`
- Go:
  - `.work/benchmarks/overlay_go_run1_skiphtml.log`
  - `.work/benchmarks/overlay_go_run1_skiphtml.time`
  - `.work/benchmarks/overlay_go_run2_skiphtml.log`
  - `.work/benchmarks/overlay_go_run2_skiphtml.time`
  - `.work/benchmarks/overlay_go_run3_skiphtml.log`
  - `.work/benchmarks/overlay_go_run3_skiphtml.time`

### Task 3 correlator artifacts
- Run 1:
  - `.work/benchmarks/correlator_matrix_run1_python_rust_go.json`
  - `.work/benchmarks/correlator_matrix_run1_python_rust_go.log`
  - `.work/benchmarks/correlator_matrix_run1_python_rust_go.time`
- Run 2:
  - `.work/benchmarks/correlator_matrix_run2_python_rust_go.json`
  - `.work/benchmarks/correlator_matrix_run2_python_rust_go.log`
  - `.work/benchmarks/correlator_matrix_run2_python_rust_go.time`
- Run 3:
  - `.work/benchmarks/correlator_matrix_run3_python_rust_go.json`
  - `.work/benchmarks/correlator_matrix_run3_python_rust_go.log`
  - `.work/benchmarks/correlator_matrix_run3_python_rust_go.time`

## Results

### Task 2: overlay strict-shadow with `--skip-html-report`
- All 6 runs succeed with `rc=0`.
- All 6 logs include `[+] Skipping HTML report generation`.
- All parity diagnostics are clean in each run (`overlay_nodes_values=0`,
  `branch_blockers_values=0`, `branch_complexities_values=0`).
- Timings (seconds):
  - Rust runs: `0.29`, `0.29`, `0.29` (avg `0.29`).
  - Go runs: `0.27`, `0.30`, `0.27` (avg `0.28`).

### Task 3: correlator python/rust/go matrix
- Digest parity is clean across all runs (rust/go digest matches python each run).
- Parsed count parity is stable (`parsed_types=2529`, `parsed_functions=1808`).
- Per-run totals (seconds):
  - Run 1: python `1.365`, rust `1.347`, go `1.421`.
  - Run 2: python `1.391`, rust `1.316`, go `1.339`.
  - Run 3: python `1.265`, rust `1.323`, go `1.358`.
- Aggregate trend:
  - Avg total: python `1.340`, rust `1.329`, go `1.373`.
  - Run wins by total time: rust `2`, python `1`, go `0`.
  - Avg max RSS MB: python `31.23`, rust `33.96`, go `35.36`.

## Gate decision and recommendation
- Gate decision: keep Python as default.
- Recommendation: do not switch defaults yet.
- Rationale:
  - Overlay stability gate is now closed for strict-shadow with
    `--skip-html-report` (3/3 rust and 3/3 go green).
  - Correlator parity is clean, but native performance gain is mixed and small.
  - Native backends still show a consistent memory penalty vs python.

## Refresh entry: 2026-03-01 gate cycle
- Artifact directory:
  `.work/benchmarks/gate_cycle_20260301_025947`
- Overlay authoritative perf averages:
  - python: elapsed `0.263s`, max RSS `38.68 MB`
  - rust: elapsed `0.277s`, max RSS `38.64 MB`
- Overlay strict-shadow parity:
  - rust: `3/3` pass
  - go: `3/3` pass
  - total: `6/6` pass
- Correlator matrix averages:
  - python: total `1.318s`, max RSS `30.79 MB`
  - rust: total `1.378s`, max RSS `34.04 MB`
  - go: total `1.417s`, max RSS `35.34 MB`
  - digest parity: all `3/3` vs python
- Correlator rust strict-shadow canary: `3/3` pass.
- Decision rationale: keep Python default (no switch). Latest cycle keeps
  parity green, but does not show a native total-time or memory advantage over
  python at gate-switch threshold.

## Validation tests
- Executed:
  - `cd src && pytest -q test/test_backend_loaders.py test/test_overlay_backend.py test/test_debug_info_loader.py test/test_analysis_plugin_matrix.py test/test_debug_correlator_backend.py`
- Result: latest refresh validation in this cycle: `119 passed`.
