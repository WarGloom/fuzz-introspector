# Native Rewrite Execution Plan - 2026-03-04

## Ordered Board

| Order | Item | Priority | Short description |
|---|---|---|---|
| 1 | DIAG-00 | P0 | Rebaseline current branch with fresh 3-run benchmark and isolate likely regressed stages. |
| 2 | MIG-00 | P0 | Confirm benchmark harness and parity guardrails before code migration work. |
| 3 | MIG-01 | P0 | Trim native plugin payloads to required fields only. |
| 4 | MIG-02 | P0 | Split Rust plugin input parsing by plugin to cut startup allocations. |
| 5 | MIG-03 | P1 | Reduce optional analysis/report intermediate materialization in Python path. |
| 6 | MIG-04 | P1 | Tighten correlator memory behavior by reducing clone-heavy fan-out. |
| 7 | MIG-05 | P1 | Add stage-marker regression gate wiring for recurring perf checks. |
| 8 | FINAL-GATE | P0 | Validate performance, parity, and CI health before merge/rollout. |

## Progress Log

### MIG-00 (Completed)

- Guardrail tightening implemented: default stages now include `type_correlation` in `benchmarks/run_stage_marker_gate.py`.
- Tests updated and passing: `src/test/test_run_stage_marker_gate.py` now has 3 passing tests.
- Code review status: pass with minor follow-ups (compat guidance and stronger integration test suggestions).

### MIG-02 (Slice completed)

- Function-table plugin now has a plugin-specific compact parse path in `tools/native_analysis_plugins_rust/src/main.rs`.
- Full-function parsing is now gated to known plugins only.
- Mixed requests derive `function_table` entries from parsed full functions to avoid reparsing.
- Tests passing in `native_analysis_plugins_rust` crate (43 passed).
- Code review status: pass with minor hardening follow-ups (metadata drift risk noted).

### MIG-04 (Slice completed)

- Correlator dedupe switched to an index-based plan (no cloned `FunctionEntry` fan-out) in `tools/native_debug_correlator_rust/src/main.rs`.
- Added index-order and determinism tests.
- Tests passing in `native_debug_correlator_rust` crate (5 passed).
- Code review status: approve with warnings (invariants documented; test hardening suggested).

### MIG-03 (Slice completed)

- Hidden optional-analysis HTML fragments are dropped from envelopes when `display_html=False`.
- UI artifacts (TOC/table IDs/conclusions) are now suppressed for hidden analyses in both merge/envelope mode and `worker_count=1` serial mode.
- Merge coordinator now gates UI artifact merging on `display_html`, while keeping merge intents unconditional.
- Tests added/updated in `src/test/test_html_serial_compatibility.py` and `src/test/test_pr6_merge_safety.py`.
- Targeted tests passing (serial compatibility and merge safety).
- Code review verdict: pass/approve with minor follow-up suggestions for additional parity integration tests.

### FINAL-GATE (Validation status: feasible checks passed)

- Python regression tests passing for stage-marker coverage, serial compatibility, merge safety, and function-table matrix subset.
- Rust crate tests passing for `native_analysis_plugins_rust` and `native_debug_correlator_rust`.
- `./code_checks.sh` passing after formatting fixes.
- Stage-marker gate smoke passing across default stages, including `type_correlation`.
- Optional hardening remains: add cross-mode parity integration test.

### Next up

- Optional hardening: add cross-mode parity integration test.
- Optional confidence pass: rerun benchmark/parity checks before merge if desired.

## DIAG-00 Procedure

1. Run a fresh 3-run Rust benchmark on cgserver corpus from repo root.
2. Record measured averages (wall time, peak RSS, hash).
3. Compare against current reference `112.31s / 6127.37MB` (`run_20260304_170857.json`).
4. Compare against graduation baseline `99.03s / 6386.69MB` (`docs/perf/native_migration_graduation_2026-03.md`).
5. If wall time regresses, identify candidate regressed stages from available stage markers; if missing, flag as blocker and request stage-marker-enabled rerun.
6. Publish a short diagnostic note with deltas and next action.

## FINAL-GATE Acceptance Criteria

- Fresh 3-run benchmark recorded and wall-time trend acceptable vs current target.
- Output hash parity holds across repeated runs (no drift).
- CI is green for touched scope (tests/lint checks passing).
