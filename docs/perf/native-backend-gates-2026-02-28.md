# Native correlator/overlay gate evidence (2026-02-28)

## Scope
- Objective: close rollout-decision gaps for native correlator/overlay defaults.
- Environment: local dev host, repo checkout at `fuzz-introspector`.
- Fixture: `tests/simple-example-0` (smallest reproducible local dataset with
  checked-in `*.debug_all_types` and `*.debug_all_functions`).

## Commands

### Correlator benchmark (available benchmark tooling)
```bash
python3 benchmarks/compare_correlator_backends.py \
  --introspector-dir tests/simple-example-0 \
  --limit-types 1 \
  --limit-functions 1 \
  --backends python,go \
  --output-json benchmarks/results/correlator_compare_2026-02-28_simple_example.json
```

### Overlay probe benchmark (no dedicated benchmark script exists)
```bash
go build -o native_overlay_backend_go .
# run from tools/native_overlay_backend_go

/usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' sh -c \
  'env PYTHONPATH=/home/nikita/work/Projects/cg/fuzz-introspector/src \
   FI_OVERLAY_BACKEND=python FI_CALLTREE_BITMAP_MAX_NODES=0 \
   python3 /home/nikita/work/Projects/cg/fuzz-introspector/src/main.py report \
   --target-dir /home/nikita/work/Projects/cg/fuzz-introspector/tests/simple-example-0 \
   --correlation-file /home/nikita/work/Projects/cg/fuzz-introspector/tests/simple-example-0/work/exe_to_fuzz_introspector_logs.yaml \
   --name overlay-bench-python --language c-cpp \
   --analyses OptimalTargets RuntimeCoverageAnalysis >/tmp/overlay_bench_python.log 2>&1'

/usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P rc=%x' sh -c \
  'env PYTHONPATH=/home/nikita/work/Projects/cg/fuzz-introspector/src \
   FI_OVERLAY_BACKEND=go \
   FI_OVERLAY_GO_BIN=/home/nikita/work/Projects/cg/fuzz-introspector/tools/native_overlay_backend_go/native_overlay_backend_go \
   FI_CALLTREE_BITMAP_MAX_NODES=0 \
   python3 /home/nikita/work/Projects/cg/fuzz-introspector/src/main.py report \
   --target-dir /home/nikita/work/Projects/cg/fuzz-introspector/tests/simple-example-0 \
   --correlation-file /home/nikita/work/Projects/cg/fuzz-introspector/tests/simple-example-0/work/exe_to_fuzz_introspector_logs.yaml \
   --name overlay-bench-go --language c-cpp \
   --analyses OptimalTargets RuntimeCoverageAnalysis >/tmp/overlay_bench_go.log 2>&1'
```

## Results

### Correlator (`benchmarks/compare_correlator_backends.py`)
- python: `total_s=0.003`, `max_rss_mb=24.20`, digest
  `610b91f397eda48471a186dbdda4fa950c90df0603fb3557ffe014d7283290e1`
- go: `total_s=0.014`, `max_rss_mb=24.18`, digest
  `610b91f397eda48471a186dbdda4fa950c90df0603fb3557ffe014d7283290e1`
- parity: digest match (`True`) on this fixture.
- relative speed: go is `0.214x` of python (slower on this fixture).

### Overlay probe (`report` run with `FI_OVERLAY_BACKEND=go`)
- python authoritative run: `elapsed=0.17`, `rss_kb=39152`, `rc=0`.
- go probe/shadow run: `elapsed=0.19`, `rss_kb=39788`, `rc=0`.
- runtime logs show explicit policy and parity state:
  - `FI_OVERLAY_BACKEND=go currently runs in probe/shadow-only mode; forcing Python authoritative output`.
  - `FI_OVERLAY_PARITY_MISMATCH` with details including
    `overlay_nodes_values=15`.

## Gate decision
- Decision: keep Python authoritative default for both correlator and overlay.
- Rationale:
  - Correlator gates are not met on this local evidence (no speed gain; memory
    effectively neutral on this tiny fixture).
  - Overlay strict-parity gate is not met (`FI_OVERLAY_PARITY_MISMATCH` in go
    probe/shadow run).

## Limitations
- Only the smallest checked-in fixture was available locally; this is useful as
  a smoke signal, not a heavy-host gate substitute.
- Rust correlator binary was not present in this environment for this pass, so
  correlator benchmark coverage here is `python` vs `go` only.
- No dedicated overlay benchmark script currently exists under `benchmarks/`;
  overlay evidence used a constrained `report` benchmark command.
