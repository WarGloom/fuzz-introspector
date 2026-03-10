# Line Identity Import Design

## Goal

Store exact line-level identities during introspector and coverage import so analytics can compute:
- exact unique repo contribution by line union across fuzzers,
- exact reachable-code-covered percentages by line,
- exact function-to-line and fuzzer-to-line joins without relying on function-level percentages.

## What exists today

The current web import pipeline stores:
- per-project function rows in `all-functions-db-{PROJ}.json`, built by `extract_and_refine_functions()` in `tools/web-fuzzing-introspection/app/static/assets/db/web_db_creator_from_summary.py`,
- aggregate coverage totals in `coverage-data-dict['line_coverage']`, built by `prepare_code_coverage_data()` in the same file,
- per-fuzzer coverage summaries only as totals in `project_timestamp['per-fuzzer-coverage-data']`, not line identities,
- function source ranges (`src_begin`, `src_end`) but not executable line sets.

So the importer already knows:
- per-function reached fuzzers,
- per-function runtime-covered fuzzers,
- aggregate covered/total line counts,
- but not exact covered lines or exact executable lines.

## Exact source availability

### 1. Per-fuzzer covered line identities

Exact source exists for local imports if the importer can read raw coverage artifacts instead of only summary files.

Best source:
- per-fuzzer `.covreport` files, parsed through `src/fuzz_introspector/code_coverage.py::load_llvm_coverage(target_dir, target_name=<fuzzer>)`

Why this is exact:
- `CoverageProfile.covmap` already stores `(line_number, hit_count)` tuples per function from `.covreport` parsing.

Current gap:
- `tools/web-fuzzing-introspection` only imports per-fuzzer `summary.json` totals from `reports-by-target/.../summary.json` for remote OSS-Fuzz data.
- Those totals are insufficient for exact line identities.

Conclusion:
- exact per-fuzzer covered lines are implementable for local imports now,
- remote OSS-Fuzz imports need richer artifact fetching (coverage HTML or raw covreport-like input) before they can be exact.

### 2. Per-function executable line identities

Exact source exists for local imports.

Best source:
- merged `.covreport` parsed by `load_llvm_coverage()` into `CoverageProfile.covmap`

Why this is exact:
- each function entry contains the executable lines seen by llvm-cov for that function,
- this is better than `source_line_begin`/`source_line_end`, which are only spans.

Current gap:
- importer currently persists only function spans and percentages, not executable line sets.

Conclusion:
- exact per-function executable lines are implementable for local imports now,
- remote OSS-Fuzz imports need richer artifact fetching if exact executable lines are required.

### 3. Per-fuzzer statically reachable line identities

There is no direct line-level reachability artifact today.

What exists:
- per-function static reachability via `Reached by Fuzzers` in `all-fuzz-introspector-functions.json`

Exact derivation available now:
- derive reachable line identities as:
  - `(fuzzer, function)` static reachability
  - joined with that function's executable line identities

This is the best exact representation available from current FI data because FI reachability is function-granular, not per-basic-block or per-line.

Conclusion:
- no standalone source artifact exists,
- but exact line identities for reachable functions can be derived at import time by joining reached functions with executable lines.

## Recommended storage model

Do not extend the existing per-function row JSON with huge embedded line arrays. That will make project JSONs too large and slow to load.

Store line identities as separate sharded artifacts under the existing project DB area:

`tools/web-fuzzing-introspection/app/static/assets/db/db-projects/{project}/line-identities/`

### A. Per-fuzzer covered lines

Store one file per coverage snapshot and fuzzer:

`db-projects/{project}/line-identities/coverage/{coverage_snapshot_id}/{fuzzer_name}.json`

Record shape:

```json
{
  "fuzzer_name": "test_AESDecrypt_Fuzzer",
  "filename": "/src/foo/bar.cc",
  "line_number": 123,
  "hit_count": 7,
  "coverage_snapshot_id": "cov-2026-03-10-...",
  "pipeline_id": "optional",
  "commit_sha": "optional"
}
```

### B. Per-function executable lines

Store one file per introspector report snapshot:

`db-projects/{project}/line-identities/functions/{introspector_report_id}.json`

Record shape:

```json
{
  "function_key": "<stable composite key>",
  "raw_function_name": "_ZN...",
  "filename": "/src/foo/bar.cc",
  "line_number": 123,
  "introspector_report_id": "if-2026-03-10-..."
}
```

### C. Per-fuzzer statically reachable lines

Store one file per introspector report snapshot and fuzzer:

`db-projects/{project}/line-identities/reachable/{introspector_report_id}/{fuzzer_name}.json`

Record shape:

```json
{
  "fuzzer_name": "test_AESDecrypt_Fuzzer",
  "function_key": "<stable composite key>",
  "filename": "/src/foo/bar.cc",
  "line_number": 123,
  "introspector_report_id": "if-2026-03-10-..."
}
```

## Identity keys

### function_key

Use a stable composite key built from the current function row fields:
- `raw_function_name`
- normalized `filename`
- `source_line_begin`

Recommended format:

`{raw_function_name}|{filename}|{source_line_begin}`

Reason:
- current FI exports do not provide a single canonical function id,
- this composite is already stable enough for report-to-report joins in the current system.

### coverage_snapshot_id / introspector_report_id

Store them explicitly in metadata and embed them into output paths.

Recommended rule:
- if upstream provides a stable pipeline/build id, use it,
- otherwise derive a deterministic id from project + import date + artifact fingerprint.

Also persist snapshot metadata in manifest files:

- `db-projects/{project}/line-identities/coverage/{coverage_snapshot_id}/manifest.json`
- `db-projects/{project}/line-identities/functions/{introspector_report_id}.manifest.json`

Manifest fields should include:
- project
- created_at
- source_kind (`local-report`, `local-oss-fuzz`, `remote-oss-fuzz`)
- commit_sha if available
- pipeline_id if available
- source paths / URLs used
- record counts

## Import flow

### Local imports (implement first)

This is the cleanest first slice because the necessary artifacts are already available locally.

1. Load `all-fuzz-introspector-functions.json`
2. Build function rows as today
3. Parse merged coverage with `code_coverage.load_llvm_coverage(report_dir)`
4. Build per-function executable lines from merged `covmap`
5. Parse per-fuzzer coverage with `load_llvm_coverage(report_dir, target_name=fuzzer)` for each fuzzer if per-fuzzer `.covreport` exists
6. Build per-fuzzer covered line identities from each per-fuzzer `covmap`
7. Build per-fuzzer reachable lines by joining:
   - `Reached by Fuzzers` from FI function rows
   - executable lines for the matched `function_key`
8. Persist the three sharded datasets plus manifests

### Remote OSS-Fuzz imports (second phase)

Current remote fetches are not sufficient for exact line identities.

To support exact remote imports, add one of:
- fetchable raw `.covreport` artifacts, or
- a dedicated per-line coverage JSON artifact, or
- a robust coverage HTML scraper for per-file/per-fuzzer line hit counts.

Without one of those, remote import can only continue storing totals, not exact line identities.

## Where implementation should go

### Extraction

Primary implementation points:
- `tools/web-fuzzing-introspection/app/static/assets/db/web_db_creator_from_summary.py`
- `tools/web-fuzzing-introspection/app/static/assets/db/oss_fuzz.py`

Add helpers such as:
- `extract_function_executable_lines(...)`
- `extract_per_fuzzer_covered_lines(...)`
- `derive_per_fuzzer_reachable_lines(...)`
- `save_line_identity_report(...)`

### Loading

If the webapp needs to query these datasets, add lazy readers in:
- `tools/web-fuzzing-introspection/app/webapp/data_storage.py`

Do not preload all line identity files into memory at startup.

## Implementation sequence

### Phase 1

Implement local-import support only.

Deliverables:
- exact per-function executable lines for local reports,
- exact per-fuzzer covered lines for local reports,
- derived per-fuzzer reachable lines for local reports.

### Phase 2

Add read APIs/helpers for analytics queries.

Deliverables:
- functions to load snapshot manifests,
- functions to load specific fuzzer line sets,
- helper to compute unions/intersections efficiently.

### Phase 3

Add remote OSS-Fuzz exact line import only after richer remote artifacts are available.

## Why this design matches the need

- exact unique repo contribution becomes a line-set union across `coverage/{snapshot}/{fuzzer}.json`
- exact reachable covered percent becomes:
  - union of reachable line identities across chosen fuzzers
  - intersected with covered line identities
  - divided by total unique reachable lines
- exact function metrics remain available from existing function rows, while line-level metrics stop depending on coarse function spans or percentages

## Recommendation

Implement local line-identity import first and keep remote OSS-Fuzz line identity import explicitly out of scope until the importer fetches richer artifacts than summary totals.
