# Line Identity Artifacts

This document describes the new sidecar JSON artifacts emitted by core `fuzz-introspector` for external consumers that need exact line-level data.

## Output location

These files are written into the main report output directory alongside existing artifacts such as:
- `summary.json`
- `all-fuzz-introspector-functions.json`
- `branch-blockers.json`

If your pipeline copies report artifacts into an `artifacts/` folder, the new files appear there as:
- `per-function-executable-lines.json`
- `per-fuzzer-covered-lines.json`
- `per-fuzzer-statically-reachable-lines.json`

## Exactness rule

These artifacts are exact-only.

A record is emitted only when `fuzz-introspector` can match a function row to a unique function name in coverage data and has a real source filename and starting line. Ambiguous matches are skipped instead of guessed.

## File: `per-function-executable-lines.json`

This file contains exact executable line identities for functions whose executable lines can be derived from the merged runtime coverage map.

Each record has this format:

```json
{
  "function_key": "<raw_function_name>|<filename>|<source_line_begin>",
  "raw_function_name": "_ZN...",
  "filename": "/src/path/to/file.cc",
  "line_number": 123,
  "introspector_report_id": "introspector-<snapshot>"
}
```

Field meanings:
- `function_key`: stable composite identifier used for joins
- `raw_function_name`: frontend/raw symbol name
- `filename`: source file path from the introspector function row
- `line_number`: executable line in that function
- `introspector_report_id`: identifier for the introspector report snapshot that produced the record

## File: `per-fuzzer-covered-lines.json`

This file contains exact per-fuzzer covered line identities from per-fuzzer coverage profiles.

Each record has this format:

```json
{
  "fuzzer_name": "test_AESDecrypt_Fuzzer",
  "filename": "/src/path/to/file.cc",
  "line_number": 123,
  "hit_count": 7,
  "coverage_snapshot_id": "coverage-<snapshot>",
  "pipeline_id": "<optional pipeline id>",
  "commit_sha": "<optional commit sha>"
}
```

Field meanings:
- `fuzzer_name`: fuzz target identifier
- `filename`: source file path for the covered line
- `line_number`: covered source line
- `hit_count`: maximum observed hit count for that fuzzer/file/line tuple
- `coverage_snapshot_id`: identifier for the coverage snapshot that produced the record
- `pipeline_id`: CI/build pipeline identifier if available, otherwise empty string
- `commit_sha`: commit SHA if available, otherwise empty string

Notes:
- Only lines with `hit_count > 0` are emitted.
- Duplicate `(fuzzer_name, filename, line_number)` entries are deduplicated by keeping the highest hit count.
- If a matching per-fuzzer coverage report is missing for a fuzz target, no covered-line records are emitted for that fuzzer. Fuzz Introspector does not widen missing per-fuzzer coverage to merged/global coverage.

## File: `per-fuzzer-statically-reachable-lines.json`

This file contains derived per-fuzzer statically reachable line identities.

Each record has this format:

```json
{
  "fuzzer_name": "test_AESDecrypt_Fuzzer",
  "function_key": "<raw_function_name>|<filename>|<source_line_begin>",
  "filename": "/src/path/to/file.cc",
  "line_number": 123,
  "introspector_report_id": "introspector-<snapshot>"
}
```

Field meanings:
- `fuzzer_name`: fuzz target identifier
- `function_key`: stable function identity used for joins
- `filename`: source file path for the reachable line
- `line_number`: line in the function's executable-line set
- `introspector_report_id`: identifier for the introspector report snapshot that produced the record

How it is derived:
- take each function row's `Reached by Fuzzers`
- resolve that function to its executable line identities
- emit one reachable-line record for each `(fuzzer, function, line)` combination

## Relationship between the files

These files are designed to support exact line-level set operations:
- unique covered lines per fuzzer from `per-fuzzer-covered-lines.json`
- unique executable lines per function from `per-function-executable-lines.json`
- unique statically reachable lines per fuzzer from `per-fuzzer-statically-reachable-lines.json`

Typical joins:
- covered lines joined by `(filename, line_number)`
- reachable lines joined to functions by `function_key`
- function rows joined to executable/reachable lines by `function_key`

## Availability

These artifacts are emitted by the core report writer when `dump_files` is enabled.

They are currently intended for exact line-level consumers. If a function cannot be matched exactly, no guessed line-identity records are emitted for that function.
