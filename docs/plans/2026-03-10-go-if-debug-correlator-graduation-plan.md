# Go IF Debug Correlator Graduation Plan

## Goal

Remove the forced Python-authoritative shadow mode for `FI_IF_DEBUG_CORRELATOR=go` on C/C++ only after the Go backend produces the same signature and source-correlation output as the Python path on representative real-world inputs.

## Current State

- `src/fuzz_introspector/analysis.py` currently forces shadow mode for `FI_IF_DEBUG_CORRELATOR=go` when `proj_lang == "c-cpp"`.
- The forced shadow was added because real CGServer runs showed large `function_signature` drift from Go relative to Python/Rust.
- The existing report-stage tests in `src/test/test_analysis_hotspots.py` now verify that Go stays Python-authoritative for C/C++.
- The deeper correlator backend tests do not yet validate Go against Python the same way Rust is validated.
- Coverage parity and report-stage correlation are separate concerns. This plan is only for graduating the Go `FI_IF_DEBUG_CORRELATOR` report-stage correlator.

## Evidence Behind the Plan

1. Real CGServer report comparisons previously showed large `function_signature` drift in Go while Rust stayed much closer to Python.
2. The report-stage Go path is now intentionally shadow-only for C/C++ because the native result is not yet trusted to be authoritative.
3. Existing tests prove the current policy, but they do not prove Go parity:
   - `src/test/test_analysis_hotspots.py` verifies forced shadow behavior.
   - `src/test/test_debug_correlator_backend.py` validates backend contract handling, but Go needs stronger parity coverage in the matrix.
4. The native Go correlator implementation lives in `tools/native_debug_correlator_go/main.go`, so the fixes likely belong there, not in the Python fallback path.

## Non-Goals

- Do not change the Rust correlator behavior.
- Do not mix this work with the LLVM coverage loader parity work.
- Do not remove Python fallback for missing binaries or schema failures.

## Plan

### Phase 1: Build an explicit Go-vs-Python parity harness

1. Extend correlator parity coverage so Go is included anywhere Rust is already checked for correlator output parity.
2. Capture mismatches at the `function_updates` level, not just aggregate counts.
3. Run the Go correlator in full-sample shadow mode on representative C/C++ projects and save mismatch artifacts for inspection.

Deliverables:
- Test coverage that includes Go in the correlator parity matrix.
- A repeatable local command/documented workflow for collecting full mismatch output.

### Phase 2: Classify mismatch patterns

For each mismatch bucket, determine whether the problem is:
- missing return type reconstruction,
- missing parameter reconstruction,
- weaker source-line/source-file matching,
- lost qualifiers/typedef expansion,
- or row-matching instability.

Prioritize the buckets by how many rows they affect and whether they change downstream report semantics.

Deliverables:
- A short mismatch taxonomy with counts and representative examples.
- A ranked backlog of Go correlator fixes.

### Phase 3: Fix the Go native correlator

Implement the smallest native fixes in `tools/native_debug_correlator_go/main.go` and its tests to close the highest-impact parity gaps.

Likely work areas:
- type argument extraction and friendly signature rendering,
- source location extraction,
- row matching and stable update keys,
- preserving enough data to reconstruct Python-equivalent signatures.

Deliverables:
- Native Go correlator fixes with targeted unit tests.
- Fewer or zero mismatches in full-sample shadow runs.

### Phase 4: Add a graduation gate

Before removing forced shadow mode:
- require zero parity mismatches on the chosen C/C++ fixture set, or an explicitly documented and approved allowlist with rationale,
- run the gate in CI or a reproducible local benchmark script,
- verify the report-stage `function_signature` and `debug_function_info` outputs match Python on representative projects.

Deliverables:
- A documented gate command.
- A test or benchmark artifact proving Go parity is acceptable.

### Phase 5: Remove forced shadow mode

Only after Phase 4 passes:
1. remove `_if_debug_correlator_backend_forces_shadow_mode()` for Go C/C++,
2. update tests so Go becomes authoritative on native success,
3. keep optional explicit shadow mode available for future debugging,
4. update README / rollout docs to reflect the new status.

Deliverables:
- Removal of forced shadow mode.
- Updated tests and docs.

## Success Criteria

Go `FI_IF_DEBUG_CORRELATOR` can graduate out of Python-authoritative shadow mode when all of the following are true:

- Go passes the correlator parity matrix against Python on the maintained fixture set.
- Real-project shadow runs show no unexplained `function_signature` or `debug_function_info` mismatches.
- The report-stage Go output is acceptable for downstream consumers that rely on signatures and source metadata.
- Forced shadow mode is no longer needed to avoid known fidelity regressions.

## Suggested First Implementation Slice

The smallest next slice is:
1. add Go to the correlator parity matrix tests,
2. add tooling to dump concrete row-level mismatches during shadow runs,
3. fix the highest-frequency Go signature gap in `tools/native_debug_correlator_go/main.go`.
