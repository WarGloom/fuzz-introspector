# Performance Plan Next (P3-P5: Hotspots + Python 3.14)

## Context
P1 and P2 from `docs/perf-plan-p1-p2.md` are complete in this branch.

This plan covers the next work items:
- remove remaining CPU and I/O hotspots still visible in code paths,
- move active CI/runtime baseline to Python 3.14,
- compare Python 3.14 execution options (default vs JIT) as a non-blocking lane,
- defer unsafe parallel-analysis execution until deterministic merge rules exist.

## Already done (reference)
- Figure lifecycle fix in `src/fuzz_introspector/html_helpers.py`.
- Optimal-target deepcopy hot-path removal in `src/fuzz_introspector/analyses/optimal_targets.py`.
- Test-file extraction cleanup in `src/fuzz_introspector/analysis.py`.

## Progress status (memory-improvements)
- [x] PR0: report-phase exclusion plumbing and tests landed.
- [x] PR1: verify fixture-level `test-files.json` parity checks.
  - Added regression coverage for report-phase extraction parity/exclusions.
  - Added extraction fast-path to skip content reads for files already
    selected via filename (`"test" in filename`) inside inspiration roots.
- [~] PR2: second slice landed.
  - first slice: precomputed uses/depth caches in C++/Go/JVM/Rust report generation paths.
  - second slice: Go `FunctionMethod` now caches zero-valued `function_uses` and
    `function_depth` results (avoids repeated recomputation for leaf/unreferenced functions),
    with regression tests in `src/test/test_frontends_go.py`.
- [x] PR3: cache-finalization slices landed.
  - `CoverageProfile` key-resolution now short-circuits direct-key hits before
    demangle/normalization work.
  - Added covmap-size-aware negative miss cache to avoid repeated transform
    chain work for unresolved names.
  - Added focused regression tests in `src/test/test_code_coverage.py`.
  - `resolve_coverage_link(...)` Python path now caches discovered
    `html_status.json` index path to avoid repeated tree scans.
  - Added refresh/invalidation regressions in
    `src/test/test_utils_coverage_cache.py` for repeated hit and
    deleted-index-file refresh behavior.
  - Added Go coverage option-cache regressions in
    `src/test/test_utils_coverage_cache.py` for cache re-use and
    file-change refresh behavior.
- [x] PR4: Python 3.14 baseline rollout completed.
  - Active Python jobs in `testing.yml`, `mypy.yml`,
    `webapp-api-test.yml`, and `webapp-mypy.yml` now use Python 3.14.
  - Package floor moved to `requires-python = ">=3.14"`.
  - Python version references updated in README and tool docs.
  - Read the Docs build runtime moved to Python 3.14.
- [x] PR5: non-blocking JIT lane added.
  - `testing.yml` now includes a baseline lane (`PYTHON_JIT=0`) and
    an experimental JIT lane (`PYTHON_JIT=1`) with `continue-on-error`.
  - JIT lane has availability guard and explicit skip output when the
    interpreter build does not expose runtime JIT support.

## Remaining hotspot inventory (not fully solved yet)
1. `src/fuzz_introspector/analysis.py`
   - `correlate_introspection_functions_to_debug_info(...)`: repeated header scanning.
   - `extract_tests_from_directories(...)`: still multi-walk over overlapping directory sets.
2. `src/fuzz_introspector/frontends/frontend_c_cpp.py`
   - per-function repeated usage/depth computation in report generation.
3. `src/fuzz_introspector/frontends/frontend_go.py`
   - repeated function-uses/depth scans in `FunctionMethod` methods.
4. `src/fuzz_introspector/frontends/frontend_jvm.py`
   - per-method repeated uses/depth scans.
5. `src/fuzz_introspector/frontends/frontend_rust.py`
   - per-function repeated uses/depth scans.
6. `src/fuzz_introspector/code_coverage.py`
   - repeated demangle/normalize lookup chain for coverage-key resolution.
7. `src/fuzz_introspector/utils.py`
   - `resolve_coverage_link(...)` re-reads/parses coverage helper files repeatedly.
8. Report-phase config exclusion gap (tracked bug)
   - Bug report: `docs/config-exclusion-not-applied-in-report-phase.md`
   - `FILES_TO_AVOID` from `FUZZ_INTROSPECTOR_CONFIG` is honored in LLVM instrumentation, but not in report-phase test extraction.
   - Current report scan still relies on hardcoded substring filters in `extract_tests_from_directories(...)`.

## Verification: bug status in current code
- Verdict: still actual.
- Evidence (report phase):
  - `src/fuzz_introspector/html_report.py:849` calls `analysis.extract_test_information(...)` with no exclusion/config argument.
  - `src/fuzz_introspector/analysis.py:1155` defines `extract_tests_from_directories(...)` without any config input; `src/fuzz_introspector/analysis.py:1195` uses fixed `to_avoid` values only.
  - `src/fuzz_introspector/analysis.py:1236` performs `os.walk(...)` over seed directories and only prunes hidden dirs (`dirs[:] = [d for d in dirs if not d.startswith('.')]`), not config-driven patterns.
  - `src/fuzz_introspector/commands.py:167` triggers report creation without loading `FUZZ_INTROSPECTOR_CONFIG` or forwarding `FILES_TO_AVOID`.
- Evidence (build phase parity baseline):
  - `frontends/llvm/lib/Transforms/FuzzIntrospector/FuzzIntrospector.cpp:428` reads config via `FUZZ_INTROSPECTOR_CONFIG`.
  - `frontends/llvm/lib/Transforms/FuzzIntrospector/FuzzIntrospector.cpp:444` loads `FILES_TO_AVOID` entries.
  - `frontends/llvm/lib/Transforms/FuzzIntrospector/FuzzIntrospector.cpp:1549` applies file-avoid regexes in `shouldAvoidFunction(...)`.

## Implementation plan

### PR0 - P3A0: report-phase config exclusion parity (new tracked bugfix)
- Target files:
  - `src/fuzz_introspector/analysis.py`
  - `src/fuzz_introspector/commands.py`
  - `src/fuzz_introspector/html_report.py`
  - `src/fuzz_introspector/cli.py` (only if CLI flag path is selected)
- Changes:
  - Add exclusion-pattern plumbing for report generation so report phase can consume `FILES_TO_AVOID` semantics.
  - Preferred implementation path:
    - load report exclusion patterns from config/env in `commands.py` (parity with `FUZZ_INTROSPECTOR_CONFIG` usage),
    - pass patterns through `html_report.create_html_report(...)` -> `analysis.extract_test_information(...)` -> `extract_tests_from_directories(...)`,
    - prune `os.walk` traversal with pattern-aware directory filtering before scanning files.
  - Keep existing hardcoded `to_avoid` list as fallback defaults; merge config patterns additively.
  - Keep report outputs/schema unchanged (focus on traversal scope and runtime).
- Ordered implementation steps:
  1. Add a small config parser/helper for `FILES_TO_AVOID` in Python report path (env-driven).
  2. Extend report-phase call chain signatures to accept `exclude_patterns`.
  3. Apply exclusion checks both at directory-prune time (`dirs[:]`) and file-candidate check to avoid regressions.
  4. Add targeted tests for exclusion propagation and directory-skip behavior.
  5. Validate generated report artifacts remain structurally identical except expected `test-files.json` reductions for excluded trees.
- Risk:
  - subtle mismatch between LLVM regex semantics and Python matching semantics.
- Validation:
  - `cd src && pytest -vv test/ -k "analysis or report or frontend_analyser"`
  - fixture comparison for `test-files.json` where excluded directories are present.

### PR1 - P3A: `analysis.py` hotspot cleanup
- Target files:
  - `src/fuzz_introspector/analysis.py`
- Changes:
  - Build one header-content index once, reuse it while correlating debug functions.
  - Collapse `extract_tests_from_directories(...)` into one walk pass per seed directory:
    - keep hidden-dir pruning,
    - evaluate inspiration and filename heuristics in one traversal,
    - preserve existing path filters and language extension behavior.
- Risk:
  - changing test-file extraction can alter discovered test sets.
- Validation:
  - `cd src && pytest -vv test/test_url.py test/test_html_generation.py`
  - compare generated `test-files.json` on `src/test/data/TestReport` fixture before/after.

### PR2 - P3B: frontend O(F^2) reductions
- Target files:
  - `src/fuzz_introspector/frontends/frontend_c_cpp.py`
  - `src/fuzz_introspector/frontends/frontend_go.py`
  - `src/fuzz_introspector/frontends/frontend_jvm.py`
  - `src/fuzz_introspector/frontends/frontend_rust.py`
- Changes:
  - Precompute reverse call graph (`callee -> use count`) once per project.
  - Precompute depth with memoization once, then read cached values while building report dictionaries.
  - Avoid changing function naming/matching semantics.
- Risk:
  - recursion/cycle handling can drift if visited-set logic is altered incorrectly.
- Validation:
  - `cd src && pytest -vv test/test_frontends_cpp.py test/test_frontends_go.py test/test_frontends_jvm.py test/test_frontends_rust.py`

### PR3 - P4: coverage lookup and coverage-link caches
- Target files:
  - `src/fuzz_introspector/code_coverage.py`
  - `src/fuzz_introspector/utils.py`
- Changes:
  - Add one shared cached coverage-key resolver in `CoverageProfile` and reuse it for `get_hit_details(...)` and `get_hit_summary(...)`.
  - Cache parsed helper inputs used by `resolve_coverage_link(...)`:
    - python `html_status.json`,
    - go `index.html` option mapping.
  - Keep output URL format identical.
- Risk:
  - stale cache if files change mid-run (acceptable for current single-run report model).
- Validation:
  - `cd src && pytest -vv test/test_code_coverage.py test/test_utils.py test/test_url.py`

### PR4 - P5A: move baseline to Python 3.14
- Target files:
  - `.github/workflows/testing.yml`
  - `.github/workflows/mypy.yml`
  - `.github/workflows/webapp-api-test.yml`
  - `.github/workflows/webapp-mypy.yml`
  - `src/pyproject.toml`
  - `README.md`
  - `tools/web-fuzzing-introspection/README.md`
  - `tools/syz-introspector/README.md`
  - `.readthedocs.yaml`
- Changes:
  - Move active jobs to 3.14.
  - Set package floor to `>=3.14` (older users dropped as requested).
  - Align docs and setup examples to 3.14.
- Risk:
  - dependency/tool incompatibilities on CI images.
- Validation:
  - run workflow-equivalent checks locally where possible,
  - confirm CI green on PR.

### PR5 - P5B: compare Python 3.14 options (non-blocking JIT)
- Target files:
  - `.github/workflows/testing.yml` (or dedicated optional workflow)
- Changes:
  - Add a non-blocking lane with `PYTHON_JIT=1` and availability guard.
  - Keep default lane blocking with JIT off.
  - Compare correctness/stability outputs (no runtime benchmarking required).
- Risk:
  - JIT option may have intermittent compatibility failures.
- Validation:
  - parity checks over deterministic test/report fixtures.

### PR6 - optional, after above: safe analysis parallelization design
- Target files:
  - `src/fuzz_introspector/html_report.py`
  - `src/fuzz_introspector/json_report.py`
  - selected analysis modules under `src/fuzz_introspector/analyses/`
- Changes:
  - Do not run current analyses in parallel directly.
  - First define worker contract for isolated analysis outputs,
  - then deterministic merge in main process.
- Reason:
  - current analyses share mutable structures and shared files; naive parallelization is race-prone.

## Acceptance criteria
- Report phase honors config-driven directory/file exclusions (from `FILES_TO_AVOID` or equivalent passed patterns) during test extraction traversal.
- Report generation no longer scans excluded trees for `extract_tests_from_directories(...)`.
- Report schema/output contracts remain unchanged (except expected omission of excluded-path test-file artifacts).
- Hotspot PRs do not change report schema or generated-link semantics.
- Frontend and coverage-related tests pass for touched modules.
- Python baseline is 3.14 in active CI and project metadata.
- JIT lane exists as non-blocking and reports status without gating merges.

## Immediate next 3 steps
1. Monitor CI stability for Python 3.14 baseline and the non-blocking JIT lane.
2. Keep report-phase exclusion parity (PR0) and extraction hot paths under regression tests as adjacent features evolve.
3. Revisit optional PR6 only after deterministic analysis merge contracts are implemented.
