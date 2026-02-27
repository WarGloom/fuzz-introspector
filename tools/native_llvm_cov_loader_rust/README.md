# Native LLVM Coverage Loader (Rust)

Prototype Rust binary for the external LLVM coverage loader protocol.

## Build

```bash
cd tools/native_llvm_cov_loader_rust
cargo check
cargo build --release
```

## Runtime protocol

- Input via `stdin`:
  - `{"coverage_reports":["/path/a.covreport","/path/b.covreport"]}`
- Output via `stdout`:
  - `{"covmap": {...}, "branch_cov_map": {...}, "coverage_files": [...]}`

## Use with fuzz-introspector

```bash
export FI_LLVM_COV_LOADER=rust
export FI_LLVM_COV_LOADER_RUST_BIN="$PWD/tools/native_llvm_cov_loader_rust/target/release/native_llvm_cov_loader_rust"
```

The binary is deterministic: it preserves input report order in `coverage_files`
and emits sorted JSON object keys for map fields.

## Implementation notes

- Input/output JSON is parsed/serialized with `serde_json`.
- Coverage pattern parsing uses precompiled `regex` expressions for:
  - switch-line detection,
  - case-line detection,
  - branch hit extraction (`Branch (line:col): [True: X, False: Y]`).
- Determinism is preserved with `BTreeMap` for `covmap` and `branch_cov_map`.
