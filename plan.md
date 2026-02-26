# Debug-Info Remediation Execution Plan

## Objective
Fix the current root-cause pattern: debug-info processing is memory-heavy and parallel speedup is poor (slow shard progress, high RSS, weak core utilization scaling).

## Current Task State
- [x] Baseline monitor active for running container (`build-introspector-full-generate-report`)
- [x] P0 foundation already landed (spill/cap knobs, profile backend, staged telemetry)
- [x] P1.1 Bounded in-flight shard scheduling (`FI_DEBUG_MAX_INFLIGHT_SHARDS`)
- [x] P1.2 Spill candidate policy under pressure (`FI_DEBUG_SPILL_POLICY`)
- [x] P1.3 Stage RSS snapshots in debug-load orchestration (`FI_DEBUG_STAGE_RSS`)
- [x] P2.1 Size-aware shard strategy (`FI_DEBUG_SHARD_STRATEGY`)
- [ ] P2.2 Optional process-pool correlation (`FI_DEBUG_CORRELATE_USE_PROCESS_POOL`)
- [x] P2.3 Adaptive worker downshift (`FI_DEBUG_ADAPTIVE_WORKERS`)
- [x] P3.1 Performance guardrail warnings (`FI_DEBUG_PERF_WARN`)
- [x] P3.2 Regression/perf invariants in tests
- [ ] P3.3 README preset finalization from benchmark data
- [ ] Final benchmark + comparison report

## Review Loop
- Every implementation track ends with:
  - targeted tests,
  - lint for touched files,
  - regression check on ordering/output parity.
- Reviewer gate after each P-level:
  - no data-loss regression,
  - no config compatibility break,
  - deterministic output order preserved.

## Execution Order
1. P1 memory controls (stability first).
2. P2 parallel efficiency improvements.
3. P3 guardrails + docs hardening.
4. Final benchmark report against active container workloads.

## Background Subagent Ownership

### SA-MEM (high effort)
- Scope:
  - `src/fuzz_introspector/debug_info.py`
  - `src/test/test_debug_info.py`
- Owns:
  - P1.1, P1.2

### SA-OBS (medium effort)
- Scope:
  - `src/fuzz_introspector/analysis.py`
  - `src/fuzz_introspector/debug_info.py` (diagnostic hooks only)
  - tests as needed
- Owns:
  - P1.3, P3.1

### SA-PAR (high effort)
- Scope:
  - `src/fuzz_introspector/debug_info.py`
  - tests in `src/test/test_debug_info.py`
- Owns:
  - P2.1, P2.2, P2.3

### SA-REL (medium effort)
- Scope:
  - regression/perf tests + docs
  - `README.md`
- Owns:
  - P3.2, P3.3

## Implementation Detail Checklist

### P1.1 Bounded in-flight shard scheduling
- Add `FI_DEBUG_MAX_INFLIGHT_SHARDS` parser.
- Submit limited futures at a time; refill as futures complete.
- Keep shard-index deterministic merge order unchanged.
- Acceptance:
  - reduced concurrent shard memory,
  - no order regression.

### P1.2 Spill candidate policy
- Add `FI_DEBUG_SPILL_POLICY` (`oldest` default; `largest` optional).
- Use existing size estimate to select spill candidate for `largest`.
- Acceptance:
  - fewer spill iterations under pressure on large runs.

### P1.3 Stage RSS snapshots
- Add optional RSS log fields to debug-load stage logs in `analysis.py`.
- Controlled by `FI_DEBUG_STAGE_RSS`.
- Acceptance:
  - logs show stage elapsed + RSS when enabled.

### P2.1 Size-aware shards
- Add strategy knob `FI_DEBUG_SHARD_STRATEGY=fixed_count|size_balanced`.
- Implement size-balanced shard builder using file-size stats.
- Acceptance:
  - improved shard tail ratio (`max shard time / median`) on large datasets.

### P2.2 Correlation process backend
- Add `FI_DEBUG_CORRELATE_USE_PROCESS_POOL`.
- Keep thread mode default.
- Preserve deterministic function mutation semantics.
- Acceptance:
  - measurable speedup on large datasets without output drift.

### P2.3 Adaptive worker downshift
- Add `FI_DEBUG_ADAPTIVE_WORKERS`.
- Heuristic: reduce active workers when spill/thrash indicators exceed threshold.
- Acceptance:
  - improved stability in long runs with reduced stall windows.

### P3.1 Guardrail warnings
- Add `FI_DEBUG_PERF_WARN` and stage-threshold warnings.
- Emit actionable knob hints in logs.
- Acceptance:
  - clear operator hints when perf thresholds exceeded.

### P3.2 Tests
- Add invariant tests for:
  - deterministic ordering,
  - strategy equivalence,
  - fallback compatibility.

### P3.3 README
- Update final recommendations only after benchmark pass.

## Benchmark Protocol
- Datasets: Small, Medium, Large (current container workload).
- Compare before/after:
  - peak RSS,
  - debug-load stage time,
  - shard telemetry tail ratio,
  - no-progress warning count,
  - output parity.

## Done Criteria
- All checkboxes complete.
- No open P1/P2 review findings.
- Large-run benchmark demonstrates:
  - memory reduction and/or stabilized peak,
  - improved effective progress rate in debug shard stage.
