# Native LLVM Coverage Loader (C++)

Prototype C++ binary for the external LLVM coverage loader protocol.

## Build

Requires RapidJSON headers to be installed (for example, `rapidjson-dev` on
Debian/Ubuntu or `rapidjson` via Homebrew on macOS).

```bash
cd tools/native_llvm_cov_loader_cpp
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o native_llvm_cov_loader_cpp main.cpp
```

## Runtime protocol

- Input via `stdin`:
  - `{"coverage_reports":["/path/a.covreport","/path/b.covreport"]}`
- Output via `stdout`:
  - `{"covmap": {...}, "branch_cov_map": {...}, "coverage_files": [...]}`

The binary is deterministic:
- `coverage_files` preserves input order.
- `covmap` and `branch_cov_map` keys are emitted in sorted order.

## Use with fuzz-introspector

```bash
export FI_LLVM_COV_LOADER=cpp
export FI_LLVM_COV_LOADER_CPP_BIN="$PWD/tools/native_llvm_cov_loader_cpp/native_llvm_cov_loader_cpp"
```

## Smoke test

```bash
printf '{"coverage_reports":["/tmp/sample.covreport"]}\n' \
  | ./native_llvm_cov_loader_cpp
```
