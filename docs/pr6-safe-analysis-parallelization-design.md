# PR6 Design: Safe Analysis Parallelization

## Status
- State: ready for phased implementation.
- Scope: PR6 only (safe parallelization for optional analyses).
- Determinism scope: JSON artifacts only (not HTML byte equality).
- Related plan: `docs/perf-plan-next-p3-p5.md`.

## Context and Problem Statement
Current optional analyses run in a single-process loop in
`src/fuzz_introspector/html_report.py:790` through
`src/fuzz_introspector/html_report.py:818`.

This loop passes shared mutable state (`table_of_contents`, `tables`,
`conclusions`, project profiles, and `out_dir`) directly into each
`analysis_func(...)` call. Some analyses also write report artifacts through
`src/fuzz_introspector/json_report.py` helpers and analysis-specific file writes.

Naively running existing `analysis_func(...)` implementations in parallel is
unsafe because it can cause:
- races on shared in-memory collections,
- nondeterministic output ordering,
- file write collisions/overwrites,
- flaky report content and hard-to-reproduce CI behavior.

PR6 goal is to add parallel execution only after defining a strict deterministic
worker contract and a main-process merge model.

## Non-Goals
- Rewriting all analyses in one PR.
- Changing report schema or existing user-facing report semantics.
- Parallelizing core profile loading/merging logic outside optional analyses.
- Requiring runtime benchmark thresholds in the acceptance gate.
- Requiring HTML byte-level determinism.

## Deterministic Worker Output Contract

### Contract Principles
- Each worker runs one analysis in isolation and returns a pure result envelope.
- Workers must not mutate shared report state directly.
- Worker outputs must be self-contained and mergeable without
  execution-order dependence.
- Envelopes must be JSON-serializable end-to-end.

### Result Envelope (v1)
Each worker returns a dictionary with the following required keys:

| Key | Type | Notes |
| --- | --- | --- |
| `schema_version` | `int` | Must be `1` for PR6 v1. Unknown version is fatal. |
| `analysis_name` | `str` | Must match `AnalysisInterface.get_name()`. |
| `status` | `str` | `success`, `retryable_error`, or `fatal_error`. |
| `display_html` | `bool` | Whether this analysis contributes HTML in this run. |
| `html_fragment` | `str` | Analysis HTML payload. Empty string allowed. |
| `conclusions` | `list[dict]` | Normalized conclusion objects emitted by analysis. |
| `table_specs` | `list[dict]` | Declarative table metadata, no global IDs assigned. |
| `merge_intents` | `list[dict]` | JSON upserts and artifact writes for main-process merge. |
| `diagnostics` | `list[str]` | Non-fatal warnings and execution notes. |

Optional keys for observability:
- `duration_ms`
- `worker_pid`
- `retry_count`

### Merge Intent Types (v1)
`merge_intents` entries are one of:

- `json_upsert`:
  - `target_path`: one of
    - `analyses.<analysis_name>`
    - `project.<key>`
    - `fuzzers.<fuzzer_id>.<key>`
  - `value`: JSON-serializable payload.

- `artifact_write`:
  - `relative_path`: output path relative to `out_dir`.
  - `content_sha256`: hex digest of content.
  - exactly one of:
    - `content_b64`: base64 content string, or
    - `temp_file_ref`: worker temp file path promoted by merge coordinator.

### Contract Rules
- No raw `bytes` in envelope payloads.
- No absolute paths in artifact intents; only `out_dir`-relative paths.
- Reject paths containing traversal (`..`) or escaping via symlink resolution.
- `analysis_name` must be unique in one report run.
- `table_specs` must be local descriptors; global table IDs assigned during merge.
- `merge_intents` must be deterministic for identical inputs.

## Merge Strategy and Conflict Rules

### Single-Writer Merge
- Only the main process mutates report state and performs final file writes.
- Workers return envelopes to a merge coordinator.

### Canonical Merge Order
- Compute canonical order by projecting requested analyses onto
  `src/fuzz_introspector/analyses/__init__.py:34` through
  `src/fuzz_introspector/analyses/__init__.py:49`.
- Merge strictly in canonical order; worker completion order is ignored.
- Unknown `analysis_name` in envelope is fatal.

### Conflict Rules
- Duplicate envelope for same `analysis_name`: fatal error.
- `json_upsert` same `target_path` with different values: fatal error.
- `json_upsert` same `target_path` with identical value: allowed (idempotent).
- `artifact_write` same `relative_path` with different `content_sha256`: fatal.
- `artifact_write` same `relative_path` with same `content_sha256`: allowed.
- Invalid envelope shape/schema: fatal error with diagnostics.

### Merge Outputs
- Reconstruct `tables` and `table_of_contents` in canonical analysis order.
- Append conclusions only in merge phase.
- Write summary/report JSON once after successful full merge.
- Promote artifacts atomically at end of merge.

## Ordering Guarantees and Reproducibility Constraints
- Canonical analysis order is registry order filtered by requested analyses.
- Output must not depend on worker scheduling.
- Any set-like list emitted by workers must be sorted before merge.
- JSON output serialization for merged files must use stable key ordering.
- Temporary worker artifacts must use per-analysis isolated temp directories.

Determinism guardrails for CI lane:
- set `PYTHONHASHSEED=0`.
- run same fixture input N=3 times.
- compare SHA-256 only for deterministic JSON artifacts.

Deterministic JSON artifact allowlist (initial):
- `summary.json`
- `all-fuzz-introspector-functions.json`
- `all-fuzz-introspector-jvm-constructor.json` (when present)
- branch blocker JSON output
- analysis JSON payload outputs written through merge intents

HTML determinism policy:
- HTML byte equality is out of scope.
- validate HTML via semantic parity (sections present, expected anchors/tables,
  and stable key report values), not byte hash.

## Failure Handling and Retries

### Error Classes
- `retryable_error`: worker crash, timeout, or IPC transport failure.
- `fatal_error`: schema violation, merge conflict, path safety violation, or
  analysis logic failure.

### Retry Policy
- At most one retry per failed analysis worker in PR6 v1.
- Retry only for `retryable_error` class.
- Retry runs in a fresh process with a clean temp directory.
- No retry for schema/merge/logic failures.
- If retry fails, fail run with explicit analysis name and diagnostics.

### Partial Output Safety
- Worker writes only to isolated temp paths.
- Main process promotes merged artifacts atomically after full success.
- No partial merged report files remain on fatal failure.

## Testing Strategy

### Unit Tests
- Envelope schema validation (required keys/types/status values).
- Canonical merge ordering independent of completion order.
- Conflict detection:
  - duplicate analysis envelope,
  - artifact hash mismatch on same path,
  - JSON target-path collision with different values.
- Retry policy behavior (single retry, then hard fail).
- Path safety checks (`..`, absolute paths, symlink escapes).

### Integration Tests
- End-to-end optional analyses run in serial compatibility mode
  (worker count forced to `1`) with parity against current baseline.
- Multi-worker run on fixture set with at least three analyses enabled;
  verify complete report generation and expected artifact set.

### JSON Determinism Tests
- Run same report generation input N=3 times with parallel workers.
- Compare hashes for deterministic JSON artifact allowlist only.
- Require byte-identical JSON outputs in the allowlist.

## Staged Implementation Plan

### Stage 0: Spec Hardening (Docs Only)
- Deliverables:
  - Finalize v1 envelope schema and merge-intent definitions.
  - Lock JSON-only determinism scope.
- Acceptance criteria:
  - No ambiguity about HTML determinism requirements.
  - Conflict and retry semantics are explicit.

### Stage 1: Contract and Validator (No Behavior Change)
- Deliverables:
  - `AnalysisWorkerResult` datamodel and validator.
  - Canonical-order resolver from analysis registry + requested set.
- Acceptance criteria:
  - Existing report flow unchanged.
  - Unit tests for schema/order pass.

### Stage 2: Serial Compatibility Adapter
- Deliverables:
  - Adapter path in `create_section_optional_analyses(...)` producing envelopes
    with worker count `=1`.
  - Main-process merge coordinator in serial mode.
- Acceptance criteria:
  - No schema changes in public report artifacts.
  - JSON parity tests pass in serial compatibility mode.

### Stage 3: Side-Effect Capture and Safety
- Deliverables:
  - Route analysis-originated JSON/report writes through merge intents.
  - Enforce artifact path safety and conflict checks.
- Acceptance criteria:
  - No direct multi-writer file writes in adapter path.
  - Conflict/path safety tests pass.

### Stage 4: Limited Parallel Execution Behind Flag
- Deliverables:
  - Enable workers `>1` behind a feature flag for vetted analyses only.
  - Keep non-migrated analyses on serial path.
- Acceptance criteria:
  - Integration tests pass with workers `=2` and `=4`.
  - JSON determinism tests remain byte-identical.

### Stage 5: Expand Coverage and Decide Default
- Deliverables:
  - Migrate additional analyses or mark explicitly serial-only.
  - Document compatibility matrix and rollout decision.
- Acceptance criteria:
  - CI stability over agreed burn-in window.
  - Documented final matrix (parallel-safe vs serial-only analyses).

## PR6 Stage 5 Compatibility Matrix (Optional Analyses)

Status is based on `parallel_safe_analyses` in
`src/fuzz_introspector/analyses/__init__.py:51`. Serial-only entries require
envelope/merge-intent migration before worker parallelization.

| Analysis (registry order) | Status | Serial-only rationale |
| --- | --- | --- |
| `OptimalTargets` | serial-only | Mutates merged profile state in place and writes analysis artifacts directly to `out_dir` (JSON/JS). |
| `EngineInput` | serial-only | Writes shared JSON output and `ENGINE_INPUT_FILE` directly; not routed through merge intents. |
| `RuntimeCoverageAnalysis` | parallel-safe | n/a |
| `DriverSynthesizer` | parallel-safe | n/a |
| `BugDigestor` | parallel-safe | n/a |
| `FilePathAnalysis` | parallel-safe | n/a |
| `ThirdPartyAPICoverageAnalyser` | parallel-safe | n/a |
| `MetadataAnalysis` | parallel-safe | n/a |
| `SinkCoverageAnalyser` | serial-only | Writes calltree HTML artifacts and analysis JSON directly to `out_dir`. |
| `FuzzAnnotatedCFG` | parallel-safe | n/a |
| `SourceCodeLineAnalyser` | serial-only | Standalone-style output writes `functions.json` directly to `out_dir`. |
| `FarReachLowCoverageAnalyser` | serial-only | Standalone-style output writes `result.json` directly to `out_dir`. |
| `PublicCandidateAnalyser` | serial-only | Standalone-style output writes `result.json` directly to `out_dir`. |
| `FrontendAnalyser` | serial-only | Runs a second frontend and writes `all_tests.json`/`all_tests_with_xreference.json` directly to `out_dir`. |

## Phase 1 Execution Checklist (Exact Next Steps)
1. Add `AnalysisWorkerResult` envelope schema + validation utility and tests.
2. Add merge coordinator that consumes envelopes and rebuilds optional-analysis
   sections in canonical registry order.
3. Add adapter path in `html_report.create_section_optional_analyses(...)`
   producing envelopes with worker count `=1`.
4. Add merge-intent plumbing for analysis-originated JSON/report writes
   (`json_upsert` and `artifact_write`).
5. Add serial-compat parity tests and retry/conflict/path-safety unit tests.

## Suggested Workstream Split (Parallelizable)
- Workstream A: schema + validator + canonical ordering.
- Workstream B: adapter + merge coordinator in serial mode.
- Workstream C: JSON/report side-effect capture and path-safety enforcement.
- Workstream D: parity, JSON determinism, and merge-conflict tests.
- Workstream E: CI enablement, polling, and rollout gating.

## Risks and Open Questions
- Some analyses may rely on shared mutable objects and need local refactors
  before clean envelope extraction.
- Large HTML payloads can increase IPC overhead; if needed, use temp-file
  handoff with hash verification while keeping the same envelope contract.
- Standalone analyses (`standalone_analyses`) remain out of scope for PR6 v1
  unless they are routed through optional-analysis report flow.
