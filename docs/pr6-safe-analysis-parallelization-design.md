# PR6 Design: Safe Analysis Parallelization

## Status
- State: design approved for implementation planning.
- Scope: PR6 only (safe parallelization for optional analyses).
- Related plan: `docs/perf-plan-next-p3-p5.md`.

## Context and Problem Statement
Current optional analyses run in a single process loop in `src/fuzz_introspector/html_report.py:790` through `src/fuzz_introspector/html_report.py:818`.

This loop passes shared mutable state (`table_of_contents`, `tables`, `conclusions`, project profiles, and `out_dir`) directly into each `analysis_func(...)` call. Some analyses also write report artifacts through `src/fuzz_introspector/json_report.py` helpers and analysis-specific file writes.

Naively running existing `analysis_func(...)` implementations in parallel is unsafe because it can cause:
- races on shared in-memory collections,
- nondeterministic output ordering,
- file write collisions/overwrites,
- flaky report content and hard-to-reproduce CI behavior.

PR6 goal is to add parallel execution only after defining a strict deterministic worker contract and a main-process merge model.

## Non-Goals
- Rewriting all analyses in one PR.
- Changing report schema or existing user-facing report semantics.
- Parallelizing core profile loading/merging logic outside optional analyses.
- Adding runtime benchmarking requirements to the acceptance gate.

## Deterministic Worker Output Contract

### Contract Principles
- Each worker runs one analysis in isolation and returns a pure result envelope.
- Workers must not mutate shared report state directly.
- Worker outputs must be self-contained and mergeable without execution-order dependence.

### Result Envelope (v1)
Each worker returns a dictionary with the following required keys:

| Key | Type | Notes |
| --- | --- | --- |
| `schema_version` | `int` | Must be `1` for PR6 v1. |
| `analysis_name` | `str` | Must match `AnalysisInterface.get_name()`. |
| `analysis_order` | `int` | Canonical order index from `analyses.all_analyses`. |
| `status` | `str` | `success`, `retryable_error`, or `fatal_error`. |
| `html_fragment` | `str` | Analysis HTML payload. Empty string allowed for JSON-only runs. |
| `json_payload` | `dict` | JSON data that would otherwise be written via `json_report`. |
| `conclusions` | `list[dict]` | Normalized conclusion objects emitted by the analysis. |
| `table_specs` | `list[dict]` | Declarative table metadata, not preassigned global IDs. |
| `artifact_writes` | `list[dict]` | File write intents (`relative_path`, `content_sha256`, `bytes`). |
| `diagnostics` | `list[str]` | Non-fatal warnings and execution notes. |

Optional keys for observability:
- `duration_ms`
- `worker_pid`
- `retry_count`

### Contract Rules
- No absolute paths in artifacts; only `out_dir`-relative paths.
- `analysis_name` must be unique in one report run.
- `table_specs` must be local-only descriptors; table IDs are assigned during merge.
- `json_payload` must be JSON-serializable with stable key ordering.
- `artifact_writes` content hash must match payload bytes before merge commit.

## Merge Strategy and Conflict Rules

### Single-Writer Merge
- Only the main process performs final mutation of report state and filesystem writes.
- Workers return envelopes to a merge coordinator.

### Deterministic Merge Order
- Merge strictly by `analysis_order` from `src/fuzz_introspector/analyses/__init__.py:34` through `src/fuzz_introspector/analyses/__init__.py:49`.
- Completion order of workers is ignored.

### Conflict Rules
- Duplicate `analysis_name` envelopes: fail run (configuration/programming error).
- Same target artifact path with different `content_sha256`: fail run.
- Same target artifact path with same `content_sha256`: allow (idempotent).
- JSON key collision under the same analysis namespace: fail run unless exact-value match.
- Invalid envelope shape/schema: fail run; include worker diagnostics.

### Merge Outputs
- Reconstruct `tables` and `table_of_contents` in canonical order during merge.
- Append normalized conclusions only in merge phase.
- Write `summary.json` once per run after all successful merges.

## Ordering Guarantees and Reproducibility Constraints
- Canonical analysis order is registry order in `analyses.all_analyses`.
- Report output content must not depend on worker scheduling.
- Any list emitted by worker payloads that represents set-like data must be sorted before merge.
- JSON output serialization for merged files must use stable key ordering.
- Temporary worker artifacts must use per-analysis isolated temp directories.
- Timestamps, PID values, and nondeterministic data are not included in user-facing output files.

Recommended determinism guardrails for CI lane when PR6 is implemented:
- `PYTHONHASHSEED=0`
- run same fixture twice and compare SHA-256 of report output files that are expected stable.

## Failure Handling and Retries

### Error Classes
- `retryable_error`: worker crash/timeout/intermittent IPC failure.
- `fatal_error`: schema violation, deterministic merge conflict, analysis logic failure.

### Retry Policy
- At most one retry per failed analysis worker in PR6 v1.
- Retry uses a fresh process and clean temp directory.
- If retry still fails, fail the report run with explicit analysis name and diagnostics.

### Partial Output Safety
- Worker writes only to isolated temp paths.
- Main process promotes merged artifacts atomically at end of successful merge.
- No partial merged report files should remain on fatal failure.

## Testing Strategy

### Unit Tests
- Envelope schema validation (required keys/types/status values).
- Deterministic merge ordering independent of completion order.
- Conflict detection (duplicate analysis, artifact hash mismatch, JSON collision).
- Retry policy behavior (single retry, then hard fail).

### Integration Tests
- End-to-end optional analyses run in serial compatibility mode (parallel framework enabled, worker count forced to 1) with output parity against current baseline.
- Multi-worker run on fixture set with at least 3 analyses enabled; verify complete report generation and expected artifact set.

### Determinism Tests
- Run same report generation input N=3 times with parallel workers.
- Compare hashes of deterministic artifacts (for example summary report and analysis JSON outputs).
- Require byte-identical outputs for deterministic files.

## Incremental Rollout Phases and Acceptance Criteria

### Phase 0: Contract and Coordinator Scaffolding (No Behavior Change)
- Deliverables:
  - Envelope datamodel and validator.
  - Merge coordinator in serial mode only.
  - Feature flag wiring (default off).
- Acceptance criteria:
  - Existing test suite for untouched areas remains green.
  - Serial mode output parity with baseline fixtures.

### Phase 1: Worker Contract in Serial Compatibility Mode
- Deliverables:
  - Refactor selected analyses to emit envelope output through adapter.
  - Main process merges envelopes while running one worker at a time.
  - Conflict detection and retry scaffolding implemented.
- Acceptance criteria:
  - No schema changes in generated public report artifacts.
  - Determinism tests pass in serial compatibility mode.
  - Unit tests cover conflict and retry logic.

### Phase 2: Limited Parallel Execution Behind Flag
- Deliverables:
  - Enable multi-worker execution for a vetted subset of analyses.
  - Keep unsafe/non-migrated analyses in serial path.
- Acceptance criteria:
  - Integration tests pass with workers `=2` and `=4`.
  - Determinism tests remain byte-identical.
  - No artifact collision failures in vetted fixture corpus.

### Phase 3: Expand Coverage and Default-On Decision
- Deliverables:
  - Migrate remaining analyses or explicitly mark serial-only.
  - Decide on default enablement based on CI stability.
- Acceptance criteria:
  - CI stability over agreed burn-in window.
  - Documented final compatibility matrix (parallel-safe vs serial-only analyses).

## Phase 1 Implementation Slice (Exact Next Steps)
1. Add `AnalysisWorkerResult` envelope schema + validation utility and tests.
2. Add merge coordinator that consumes envelopes and reconstructs report sections in registry order.
3. Create adapter path for optional analyses in `html_report.create_section_optional_analyses(...)` to use envelope production even with worker count `=1`.
4. Route all analysis-originated JSON/report writes through merge intents (no direct multi-writer writes).
5. Add deterministic parity tests on stable fixture outputs and retry/conflict unit tests.

## Risks and Open Questions
- Some analyses may implicitly depend on shared mutable objects and require local refactors before envelope extraction is clean.
- Analyses that generate large HTML payloads may increase IPC overhead; if needed, use temp-file handoff with hash verification while keeping the same contract.
- Standalone analyses (`standalone_analyses`) remain out of scope for PR6 v1 unless they share the optional report path.
