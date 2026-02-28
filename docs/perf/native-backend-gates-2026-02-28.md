# Native correlator/overlay gate evidence (2026-02-28)

## Scope
- Objective: close remaining rollout-decision gaps for native correlator/overlay
  defaults with stronger local evidence.
- Environment: local dev host, repo checkout at `fuzz-introspector`.
- Evidence workspace: `.work/benchmarks` (all logs/results/time files for this
  pass).
- Dataset selection:
  - `tests/` contains only one local debug pair
    (`tests/simple-example-0/*debug_all_{types,functions}`).
  - `/home/nikita/work/Projects/cg/cgserver/build-coverage/fuzzing-corpus/coverage/latest/textcov_reports`
    exists but has no `*.debug_all_types`/`*.debug_all_functions`.
  - Larger local dataset found and used:
    `/home/nikita/work/Projects/cg/introtest` (8 debug type files + 8 debug
    function files).
  - Overlay benchmark target: 
    `/home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector`
    with correlation file
    `/home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector/exe_to_fuzz_introspector_logs.yaml`.

## Commands

### Correlator benchmark (orchestrated benchmark tooling)
```bash
TMPDIR=/home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks \
/usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' \
  -o .work/benchmarks/correlator_compare_introtest.time \
  python3 benchmarks/compare_correlator_backends.py \
  --introspector-dir /home/nikita/work/Projects/cg/introtest \
  --backends python,rust,go \
  --output-json .work/benchmarks/correlator_compare_introtest_2026-02-28.json \
  > .work/benchmarks/correlator_compare_introtest.log 2>&1
```

### Correlator benchmark (native direct comparator)
```bash
TMPDIR=/home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks \
/usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' \
  -o .work/benchmarks/native_correlator_compare_introtest.time \
  python3 benchmarks/compare_native_correlators.py \
  --introspector-dir /home/nikita/work/Projects/cg/introtest \
  --output-json .work/benchmarks/native_correlator_compare_introtest_2026-02-28.json \
  > .work/benchmarks/native_correlator_compare_introtest.log 2>&1
```

### Overlay benchmark (python/rust/go paths)
```bash
go build -o native_overlay_backend_go .
# run from tools/native_overlay_backend_go

TMPDIR=/home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks \
/usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' \
  -o .work/benchmarks/overlay_python_introtest.time sh -c \
  'env PYTHONPATH=/home/nikita/work/Projects/cg/fuzz-introspector/src \
   FI_OVERLAY_BACKEND=python FI_CALLTREE_BITMAP_MAX_NODES=0 \
   python3 /home/nikita/work/Projects/cg/fuzz-introspector/src/main.py report \
   --target-dir /home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector \
   --correlation-file /home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector/exe_to_fuzz_introspector_logs.yaml \
   --name overlay-bench-python-introtest --language c-cpp \
   --analyses OptimalTargets RuntimeCoverageAnalysis \
   > /home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks/overlay_python_introtest.log 2>&1'

TMPDIR=/home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks \
/usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' \
  -o .work/benchmarks/overlay_rust_introtest.time sh -c \
  'env PYTHONPATH=/home/nikita/work/Projects/cg/fuzz-introspector/src \
   FI_OVERLAY_BACKEND=rust \
   FI_OVERLAY_RUST_BIN=/home/nikita/work/Projects/cg/fuzz-introspector/tools/native_overlay_backend_rust/target/release/native_overlay_backend_rust \
   FI_CALLTREE_BITMAP_MAX_NODES=0 \
   python3 /home/nikita/work/Projects/cg/fuzz-introspector/src/main.py report \
   --target-dir /home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector \
   --correlation-file /home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector/exe_to_fuzz_introspector_logs.yaml \
   --name overlay-bench-rust-introtest --language c-cpp \
   --analyses OptimalTargets RuntimeCoverageAnalysis \
   > /home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks/overlay_rust_introtest.log 2>&1'

TMPDIR=/home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks \
/usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' \
  -o .work/benchmarks/overlay_go_introtest.time sh -c \
  'env PYTHONPATH=/home/nikita/work/Projects/cg/fuzz-introspector/src \
   FI_OVERLAY_BACKEND=go \
   FI_OVERLAY_GO_BIN=/home/nikita/work/Projects/cg/fuzz-introspector/tools/native_overlay_backend_go/native_overlay_backend_go \
   FI_CALLTREE_BITMAP_MAX_NODES=0 \
   python3 /home/nikita/work/Projects/cg/fuzz-introspector/src/main.py report \
   --target-dir /home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector \
   --correlation-file /home/nikita/work/Projects/cg/introtest/artifacts/introspector/inspector/exe_to_fuzz_introspector_logs.yaml \
   --name overlay-bench-go-introtest --language c-cpp \
   --analyses OptimalTargets RuntimeCoverageAnalysis \
   > /home/nikita/work/Projects/cg/fuzz-introspector/.work/benchmarks/overlay_go_introtest.log 2>&1'
```

## Results

### Correlator (`benchmarks/compare_correlator_backends.py` on introtest)
- python pass: `total_s=1.396`, `max_rss_mb=30.82`, digest
  `af54bbec12d42dd80ae6aba3e61ad2a086a1feb289a5afac5dabeeb7571dfc5a`.
- rust strict run: fails with `FI_CORR_SCHEMA_ERROR` from shard coverage mismatch
  (`expected=1808`, `updated=577`).
- go strict run: same failure mode (`FI_CORR_SCHEMA_ERROR`, coverage mismatch
  `expected=1808`, `updated=577`) and logs
  `FI_DEBUG_CORRELATOR_BACKEND=go currently runs in shadow-only mode`.
- benchmark command wall summary (`correlator_compare_introtest.time`):
  `elapsed=3.24`, `rss_kb=37372`, `rc=1`.

### Correlator native-direct (`benchmarks/compare_native_correlators.py`)
- dataset size: `type_files=8`, `function_files=8`.
- rust: `elapsed_s=0.020`, `max_rss_mb=16.10`, digest
  `01d47291ecaca97ff9cff01cde1dcb9f9a996fc043f41d5c527c4a3207740ef2`.
- go: `elapsed_s=0.038`, `max_rss_mb=23.97`, digest
  `01d47291ecaca97ff9cff01cde1dcb9f9a996fc043f41d5c527c4a3207740ef2`.
- native parity: rust/go digest match (`True`) to each other, but both update
  only 577 rows; orchestrated strict parity against python remains failing.

### Overlay (`report` on introtest inspector dataset)
- python baseline: `elapsed=0.36`, `rss_kb=47224`, `rc=0`.
- rust backend: `elapsed=0.40`, `rss_kb=47444`, `rc=0`; no
  `FI_OVERLAY_PARITY_MISMATCH` signal in this run.
- go backend: `elapsed=0.40`, `rss_kb=47000`, `rc=0`; explicit probe/shadow
  enforcement plus repeated `FI_OVERLAY_PARITY_MISMATCH` diagnostics
  (`overlay_nodes_values=2` and `overlay_nodes_values=3`).

## Gate decision
- Decision (explicit): **ROLL-OUT GAPS REMAIN OPEN**; keep Python authoritative
  default for both correlator and overlay.
- Rationale:
  - Correlator strict parity gate fails on larger local dataset for both rust
    and go orchestrated paths (`FI_CORR_SCHEMA_ERROR` coverage mismatch).
  - Native-direct correlator speedups do not satisfy rollout criteria because
    orchestrated strict correctness gate is failing.
  - Overlay go path still fails strict parity (`FI_OVERLAY_PARITY_MISMATCH`) and
    remains probe/shadow-only by policy.
  - Overlay rust path did not show parity mismatch in this run, but did not
    demonstrate required performance headroom to justify default switch.

## Limitations
- No heavy container-scale dataset was available in this repo checkout; results
  are stronger than the tiny fixture run but still local-host evidence.
- `compare_correlator_backends.py` currently aborts on first strict backend
  failure, so complete python/rust/go table output is not produced in one run.
- No dedicated overlay benchmark harness exists under `benchmarks/`; overlay
  evidence still relies on `report` runs plus log parity diagnostics.
