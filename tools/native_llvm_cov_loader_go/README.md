# Native LLVM Coverage Loader (Go)

This binary implements the external loader protocol used by:

- `FI_LLVM_COV_LOADER=go`
- `FI_LLVM_COV_LOADER_GO_BIN=/abs/path/to/native_llvm_cov_loader_go`

## Build

```bash
cd tools/native_llvm_cov_loader_go
GOCACHE=/tmp/go-cache go build -o native_llvm_cov_loader_go .
```

## Runtime protocol

- Input: JSON via `stdin`
  - `{"coverage_reports":["/path/a.covreport","/path/b.covreport"]}`
- Output: JSON via `stdout`
  - `{"covmap": {...}, "branch_cov_map": {...}, "coverage_files": [...]}`

## Parser performance notes

The protocol stays on `encoding/json`, but `.covreport` scan-path work is reduced:

- no `strings.Split` for coverage columns; parsing uses `IndexByte` offsets.
- regex checks are candidate-gated with cheap substring checks first.
- branch location parsing avoids temporary split/replace allocations.
- function-line appends use a local slice and flush to map on function boundaries.
- `case` tracking map is reused with `clear(...)` instead of reallocating.
- scanner buffer is explicitly sized to avoid small default token limits.

## Example

```bash
export FI_LLVM_COV_LOADER=go
export FI_LLVM_COV_LOADER_GO_BIN="$PWD/tools/native_llvm_cov_loader_go/native_llvm_cov_loader_go"
```

Then run normal report generation; python will delegate `.covreport` parsing to this binary.

## Python parity notes

- Function markers now follow python `load_llvm_coverage` extraction semantics:
  for lines like `file:function:`, key uses only `function`.
- Function markers reset the function coverage slice each time, matching python.
- Switch, case, and branch detection now follow the same regex-style matching
  used by the python parser.
- Switch branch aggregation behavior matches python, including the fallback shape
  `[true_hit, false_hit, true_hit]` when case branches are present but switch
  branch data is missing.
- Remaining mismatch: python applies C++/Rust demangling during function-key
  extraction; this Go loader currently keeps raw names.
