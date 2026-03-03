# Native Rewrite Plan - March 2026

## Context (Post-function_table)

Recent findings on `memory-improvements` indicate:
- Native backend already graduated with production-scale gains (6.94x wall-time, -42.5% RSS on cgserver).
- The post-`function_table` change alone improved Rust baseline by **-20.81% wall** and **-4.10% RSS**, proving report-path rewrites still have high leverage.
- Stage marker instrumentation exists but is not yet used as a CI performance gate.
- Plugin-level native parallel tuning is explicitly called out as follow-on work.

## Next Native Rewrite Backlog (Post-function_table)

### Prioritized Top 10 Candidates

| Priority | Candidate | File path | Why now |
|---|---|---|---|
| P0-1 | Slim payload v2 for native plugins | `src/fuzz_introspector/analysis.py` | `_serialize_project_for_native(...)` still sends broad per-function payloads; reducing fields/chunking cuts JSON serialization + peak memory. |
| P0-2 | Plugin-specific input parsing in Rust | `tools/native_analysis_plugins_rust/src/main.rs` | Current dispatcher parses broad function data for all plugins; per-plugin parsers reduce allocation and startup latency. |
| P0-3 | Native-first optional analysis merge path | `src/fuzz_introspector/html_report.py` | `_create_section_optional_analyses_impl(...)` still builds and merges large HTML fragments in Python; memory spikes scale with plugin count. |
| P1-4 | Function table adjacent tables to native ordering/output | `src/fuzz_introspector/html_report.py` | `create_all_function_table(...)` win shows report-table work is high ROI; extend same pattern to next heavy tables. |
| P1-5 | Correlator dedup/cache memory reduction pass | `tools/native_debug_correlator_rust/src/main.rs` | `correlate_chunk_with_cache(...)` still clones signature/source per row; arena/indexed reuse should lower RSS. |
| P1-6 | YAML debug-load spill protocol hardening | `src/fuzz_introspector/debug_info.py` | Shard/spill path works but remains Python object heavy; tighten spill thresholds + typed fast path for large shards. |
| P1-7 | LLVM coverage merge streaming v2 | `tools/native_llvm_cov_loader_rust/src/main.rs` | Per-file outputs are materialized then merged; bounded merge windows can lower peak memory on multi-report corpora. |
| P2-8 | Native profile YAML batch loader | `src/fuzz_introspector/data_loader.py` | Profile loading remains mostly per-file Python object flow; batched native path can reduce parse overhead and startup time. |
| P2-9 | Stage marker perf gate + regression detector | `src/fuzz_introspector/stage_markers.py` | Instrumentation exists; adding automated regression checks turns findings into enforceable guardrails. |
| P2-10 | Remaining CPU-heavy analyses native migration | `src/fuzz_introspector/analyses/far_reach_low_coverage_analyser.py` | Still Python-only and graph-heavy; likely next compute hotspot after current native plugin set. |

### Quick Wins (1-2 days)

1. **Payload trimming for native plugin calls** (`src/fuzz_introspector/analysis.py`): remove non-essential fields for each requested plugin key.
2. **Stage marker CI smoke gate** (`src/fuzz_introspector/stage_markers.py` + test harness): fail CI when key stage deltas regress above agreed threshold.
3. **Correlator clone minimization (targeted)** (`tools/native_debug_correlator_rust/src/main.rs`): replace obvious per-row string clone paths in cached record fan-out.

### Bigger Bets

1. **Streaming HTML/report assembly** (`src/fuzz_introspector/html_report.py`): move from giant in-memory string/fragment merges to staged writer model.
2. **Plugin framework protocol v2** (`src/fuzz_introspector/analysis.py`, `tools/native_analysis_plugins_rust/src/main.rs`): plugin-specific schemas + chunked IPC.
3. **Coverage+debug unified native data plane** (`tools/native_llvm_cov_loader_rust/src/main.rs`, `src/fuzz_introspector/debug_info.py`): reduce Python mediation between native loaders and analysis execution.

## Recommended Next 3 (Execution Order + Validation)

1. **Native plugin payload v2 (P0-1 + P0-2)**
   - Deliverable: per-plugin minimal schema + Rust parser split.
   - Validate:
     - `python -m pytest -vv src/test/test_analysis_plugin_matrix.py`
      - `python -m pytest -vv src/test/test_analysis_hotspots.py`
     - Compare stage-marker `optional_analyses` duration before/after on cgserver run.

2. **Optional analysis memory path hardening (P0-3 + P1-4)**
   - Deliverable: reduce intermediate HTML/table materialization and extend native table ordering approach.
   - Validate:
      - `python -m pytest -vv src/test/test_html_generation.py`
     - `python -m pytest -vv src/test/test_analysis_plugin_matrix.py -k function_table`
     - `/usr/bin/time -v` delta on report generation peak RSS.

3. **Correlator + loader memory tightening (P1-5 + P1-7)**
   - Deliverable: clone reduction in correlator and bounded merge in LLVM loader.
   - Validate:
     - `python -m pytest -vv src/test/test_backend_loaders.py`
     - `python -m pytest -vv src/test/test_debug_info_loader.py`
     - Hash parity check of `summary.json` across Python vs Rust backends.
