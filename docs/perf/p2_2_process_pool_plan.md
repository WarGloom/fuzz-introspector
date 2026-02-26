# P2.2 Implementation Plan: Optional Process-Pool Correlation Backend

## Scope and objective
Implement an optional process-pool backend for `correlate_debugged_function_to_debug_types(...)` in `src/fuzz_introspector/debug_info.py` to improve CPU-bound correlation throughput on large inputs, while preserving output parity, deterministic merge behavior, and safe fallback semantics.

Constraints:
- Off by default.
- No report schema or artifact contract changes.
- Existing thread/serial behavior remains default and rollback path.

## 1) Current architecture analysis and why process pool is non-trivial

### Current execution path
1. `AnalysisProject.load_debug_report(...)` in `src/fuzz_introspector/analysis.py` calls:
   - `debug_info.load_debug_all_yaml_files(...)` for types/functions YAML.
   - `debug_info.correlate_debugged_function_to_debug_types(...)` for signature correlation.
2. `correlate_debugged_function_to_debug_types(...)`:
   - builds `debug_type_dictionary` indexed by int address.
   - calls `create_friendly_debug_types(...)` (optional file dump side effect).
   - computes correlation worker settings from:
     - `FI_DEBUG_CORRELATE_PARALLEL` (bool),
     - `FI_DEBUG_CORRELATE_WORKERS` (int).
   - processes `all_debug_functions` in-place via a local `_process_slice(...)` that calls `extract_debugged_function_signature(...)` and mutates each function dict with:
     - `func_signature_elems`
     - `source`
3. Current parallel mode uses `ThreadPoolExecutor` and chunked list slices; fallback is serial if any chunk fails.

### Why process pool is non-trivial
1. Pickle boundary incompatibility with current closure:
   - `_process_slice(...)` is nested inside `correlate_debugged_function_to_debug_types(...)` and is not process-pickle-safe under `spawn`.
2. Large shared state:
   - `debug_type_dictionary` can be very large; naive per-task pickling will replicate memory and create heavy serialization overhead.
3. In-place mutation contract:
   - current path mutates original `all_debug_functions` dicts in threads.
   - processes cannot mutate parent memory directly, so explicit result envelopes + merge are required.
4. Cross-platform process-start behavior:
   - `fork` may share memory copy-on-write on Linux, but `spawn` requires full serialization and stricter picklability.
   - backend must stay correct regardless of start method.
5. Determinism requirements:
   - current observable output is deterministic because each input function gets exactly one correlated payload.
   - process merge must preserve index-based assignment and avoid race-dependent ordering artifacts.
6. Failure semantics:
   - process pool has additional failure modes (initializer failure, worker crash, broken process pool, task deserialization exceptions) requiring explicit rollback logic.

## 2) Design options and tradeoffs

### Option A: Stateless task shipping (simple but expensive)
Design:
- Submit per-function (or per-small-chunk) tasks containing both function payload and `debug_type_dictionary`.
- Worker returns correlated fields.

Tradeoffs:
- Data sharing/memory model:
  - no shared state; every task carries type dictionary or large subset.
  - worst memory duplication.
- Serialization overhead:
  - highest; repeated pickle/unpickle of large objects.
- Determinism guarantees:
  - easy if using `(index, result)` envelope and deterministic merge by index.
- Failure/rollback:
  - straightforward to detect future failures and fallback to thread/serial.
- Verdict:
  - not recommended due to high overhead on realistic datasets.

### Option B: Worker-initialized shared dictionary + indexed slices (recommended)
Design:
- Promote worker entrypoints to module-level functions:
  - initializer receives one serialized `debug_type_dictionary` per worker process.
  - task payload is only `(chunk_index, start_offset, function_slice_minimal)`.
- Worker returns `(chunk_index, start_offset, correlated_rows)` where rows are small envelopes with computed fields.
- Parent merges by absolute function index.

Tradeoffs:
- Data sharing/memory model:
  - one dictionary copy per process (spawn) or COW-friendly (fork).
  - bounded by worker count.
- Serialization overhead:
  - moderate; task payload excludes giant type dictionary.
- Determinism guarantees:
  - strong with index-based deterministic merge independent of completion order.
- Failure/rollback:
  - can fail fast and fallback to existing thread path then serial.
- Verdict:
  - best balance of speed, complexity, and compatibility.

### Option C: Disk-backed type dictionary (JSON/mmap/shared memory)
Design:
- Pre-serialize type dictionary to file/shared segment and load lazily in workers.

Tradeoffs:
- Data sharing/memory model:
  - potentially low RAM duplication.
- Serialization overhead:
  - startup and parsing overhead shifts to file I/O.
- Determinism guarantees:
  - manageable with index-based merge.
- Failure/rollback:
  - introduces file lifecycle/corruption concerns and cleanup complexity.
- Verdict:
  - defer; too much complexity/risk for P2.2.

## 3) Recommended design and phased migration (P0-P3)

### Recommended design summary
Adopt Option B: add a process backend that reuses existing chunking/tuning logic, moves worker functions to module scope, returns immutable result envelopes, merges deterministically by index, and falls back to thread then serial on any process-path failure.

### P0: Refactor for backend abstraction (no behavior change)
Goals:
- Separate correlation orchestration from execution backend.

Code touch points:
- `src/fuzz_introspector/debug_info.py`
  - `correlate_debugged_function_to_debug_types(...)`
  - add module-level helpers:
    - `_correlate_slice(...)` (pure function for one slice)
    - `_correlate_merge_results(...)`

Actions:
1. Replace nested `_process_slice(...)` with module-level helper to make it process-safe.
2. Keep current thread backend as default; preserve current env behavior.
3. Add unit tests confirming no output drift in serial/thread paths.

Compatibility behavior:
- No new default behavior.
- Existing env knobs unchanged.

### P1: Add optional process backend (off-by-default)
Goals:
- Introduce process execution path with deterministic merge.

Code touch points:
- `src/fuzz_introspector/debug_info.py`
  - new module-global worker state for type dictionary (process-local).
  - new initializer and process worker entrypoint.
  - backend selector in `correlate_debugged_function_to_debug_types(...)`.
- `src/test/test_debug_info_loader.py`
  - add process-path smoke and fallback tests.

Actions:
1. Add env knob:
   - `FI_DEBUG_CORRELATE_USE_PROCESS_POOL` (default `false`).
2. Add optional knob:
   - `FI_DEBUG_CORRELATE_MAX_TASKS_PER_CHILD` (default `0`, disabled).
3. Implement `ProcessPoolExecutor` path with:
   - initializer wiring,
   - chunk task submission,
   - deterministic merge by absolute function index.
4. On any process backend exception:
   - log warning,
   - fallback to thread backend,
   - if thread fails, fallback to serial.

Compatibility behavior:
- Default remains thread/serial.
- Process backend only when explicitly enabled.

### P2: Hardening, determinism, telemetry
Goals:
- Make process backend operationally safe and measurable.

Code touch points:
- `src/fuzz_introspector/debug_info.py`
  - backend telemetry logs.
- `src/fuzz_introspector/analysis.py`
  - tune hints in `_get_debug_stage_tuning_hint(...)` for new correlate process knob.
- `README.md`
  - add opt-in process correlation tuning section.

Actions:
1. Add correlation telemetry log fields:
   - backend (`serial|thread|process`),
   - workers,
   - chunks,
   - fallback reason (if any).
2. Enforce deterministic merge assertions in tests (stable index mapping).
3. Add malformed input behavior tests (missing `type_arguments`, malformed `file_location`) parity across backends.

Compatibility behavior:
- Output parity required across serial/thread/process.
- In case of backend mismatch or exception, automatic fallback preserves functionality.

### P3: Controlled enablement policy (still optional)
Goals:
- Enable process backend for targeted environments without global default flip.

Code touch points:
- Documentation only for policy and ops runbook:
  - `docs/perf/p2_2_process_pool_plan.md` (this doc, updated post-implementation with observed results)
  - `README.md` runtime presets.

Actions:
1. Canary enablement on large datasets only.
2. Keep repo default `FI_DEBUG_CORRELATE_USE_PROCESS_POOL=false` until acceptance thresholds are repeatedly met.
3. Define rollback SOP (single env toggle).

Compatibility behavior:
- No forced migration.
- Existing CI jobs remain on default path unless explicitly configured.

## 4) Environment knobs and compatibility matrix

### Existing knobs reused
- `FI_DEBUG_CORRELATE_PARALLEL` (`true|false`)
- `FI_DEBUG_CORRELATE_WORKERS` (int >= 1)

### New knobs for P2.2
- `FI_DEBUG_CORRELATE_USE_PROCESS_POOL` (`false` default)
  - `false`: current thread/serial behavior.
  - `true`: try process backend first, then fallback.
- `FI_DEBUG_CORRELATE_MAX_TASKS_PER_CHILD` (`0` default, optional)
  - `0`: executor default.
  - `>0`: recycle workers to reduce leak amplification in very large runs.

### Backend selection behavior
1. If `FI_DEBUG_CORRELATE_PARALLEL=false` or workers=1 -> serial.
2. Else if `FI_DEBUG_CORRELATE_USE_PROCESS_POOL=true` -> process backend attempt.
3. On process failure -> thread backend attempt.
4. On thread failure -> serial fallback.

## 5) Risk register, mitigations, and tests

| Risk | Impact | Mitigation | Test strategy |
|---|---|---|---|
| Process worker not pickle-safe (local closures, non-serializable payloads) | Immediate backend failure | Use module-level worker funcs and minimal task envelopes | Unit test that process path executes with `spawn` context and returns parity |
| Serialization overhead outweighs CPU gain on small inputs | Performance regression | Keep off-by-default; size-aware canary only | Benchmark D1/D2; assert no default regression since default path unchanged |
| Memory amplification with many processes | OOM or heavy paging | Cap workers, optional `max_tasks_per_child`, keep fallback | Stress test with large fixture and worker matrix |
| Non-deterministic merge ordering | Output drift/flaky tests | Merge strictly by original function index | Determinism tests: compare canonicalized output across repeated runs/backends |
| Worker crashes / BrokenProcessPool | Pipeline failure | Catch backend exceptions and fallback thread->serial | Fault-injection tests (mock worker raise/crash path) |
| Behavior drift in malformed function records | Hidden correctness regressions | Keep existing signature extraction logic unchanged | Parametrized parity tests for malformed/edge inputs |

## 6) Benchmark protocol and acceptance thresholds

### Datasets
- D1: small unit-test-sized dataset (sanity).
- D2: medium real project dataset.
- D3: large high-cardinality dataset currently stressing type correlation.

### Run matrix
For each dataset, run 5 repetitions and report median + p95:
1. Serial baseline:
   - `FI_DEBUG_CORRELATE_PARALLEL=false`
2. Thread baseline:
   - `FI_DEBUG_CORRELATE_PARALLEL=true`
   - `FI_DEBUG_CORRELATE_USE_PROCESS_POOL=false`
3. Process candidate:
   - `FI_DEBUG_CORRELATE_PARALLEL=true`
   - `FI_DEBUG_CORRELATE_USE_PROCESS_POOL=true`

Collect:
- `type_correlation` elapsed (from `[debug-load]` logs in `analysis.py`).
- Process RSS peak (external sampler or stage RSS if enabled).
- Backend fallback count (new telemetry field).
- Output parity hash of `debug_all_functions` relevant fields.

### Acceptance thresholds
Process backend is accepted for canary use when all hold:
1. Correctness:
   - 100% parity of correlated fields (`func_signature_elems`, `source`) vs thread baseline on D1/D2/D3.
2. Stability:
   - 0 unexpected fallback events on D2/D3 across 5 runs each.
3. Performance:
   - D3 `type_correlation` median improvement >= 20% over thread baseline.
   - D2 no worse than 5% regression vs thread baseline.
4. Memory:
   - Peak RSS increase <= 25% vs thread baseline on D3.

If thresholds fail, keep backend experimental only and do not widen rollout.

## 7) Rollout plan (off-by-default, canary, rollback)

### Phase R0: Ship dark
- Land implementation with `FI_DEBUG_CORRELATE_USE_PROCESS_POOL=false` default.
- CI continues exercising serial/thread tests; process tests run in targeted suite only.

### Phase R1: Canary opt-in
- Enable process backend only in selected perf jobs or one internal workload lane.
- Suggested canary criteria:
  - dataset size above configurable threshold,
  - Linux host with >=8 CPUs,
  - no prior fallback events.

### Phase R2: Expand canary footprint
- Increase usage to additional large workloads if thresholds continue to pass for one release cycle.
- Keep docs explicit that backend is optional/experimental.

### Rollback
- Immediate rollback toggle:
  - `FI_DEBUG_CORRELATE_USE_PROCESS_POOL=false`
- No data migration needed.
- If severe issues occur, revert to thread backend only by policy without code revert.

## 8) Concrete implementation checklist

1. Refactor correlation worker into module-level process-safe helpers in `src/fuzz_introspector/debug_info.py`.
2. Add process backend selector and fallback chain in `correlate_debugged_function_to_debug_types(...)`.
3. Add new env knob parsing and logging.
4. Add/extend tests in:
   - `src/test/test_debug_info_loader.py`
   - `src/test/test_debug_info.py`
5. Update tuning hints in `src/fuzz_introspector/analysis.py` and docs in `README.md`.
6. Run targeted tests and perf protocol; gate canary rollout on thresholds.

