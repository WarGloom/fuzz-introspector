# Plugin/Backend Decision Matrix

## Scope
- Branch: `plugin-perf-backends`
- Date: 2026-02-26
- Focus: non-LLVM-plugin backend paths (`debug_yaml`, profile YAML, LLVM
  `.covreport` parser selection surface).

## Implemented backend selection points
- `FI_DEBUG_YAML_LOADER`: wired (python/go/rust/cpp selector + fallback).
- `FI_PROFILE_YAML_LOADER`: wired (python/go/rust/cpp selector + fallback).
- `FI_LLVM_COV_LOADER`: wired (python/go/rust/cpp selector + fallback).
- Shared protocol: JSON stdin/stdout external loader adapter in
  `src/fuzz_introspector/backend_loaders.py`.

## Concrete non-Python implementation
- Go external loader for LLVM `.covreport` parsing:
  - `tools/native_llvm_cov_loader_go/main.go`
  - Selected with:
    - `FI_LLVM_COV_LOADER=go`
    - `FI_LLVM_COV_LOADER_GO_BIN=/abs/path/native_llvm_cov_loader_go`

## Benchmarks (micro, `.covreport` parsing path)
Dataset:
- `/home/nikita/work/Projects/cg/cgserver/build-coverage/fuzzing-corpus/coverage/latest/textcov_reports`
- 48 `.covreport` files

Python loader:
- funcs=7214, branches=12179, files=48
- elapsed=5.71s, rss=42220 KB, cpu=99%

Go loader:
- funcs=7234, branches=12223, files=48
- elapsed=0.91s, rss=163688 KB, cpu=123%

## Interpretation
- Go backend is significantly faster for this path.
- Go backend currently uses substantially more memory.
- Go backend still has parity deltas vs Python (`funcs`/`branches` count
  mismatch), so it should remain opt-in and not default yet.

## Recommendation
1. Keep default backends as `python`.
2. Use Go LLVM coverage backend as optional performance mode where slight
   parity deltas are acceptable.
3. Next parity hardening target: exact function header normalization and branch
   edge matching against Python parser semantics.
