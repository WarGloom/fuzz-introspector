# Debug-Info Remediation Plan: Memory-Heavy Processing with Poor Effective Parallel Speedup

## Goal
Reduce peak memory and improve end-to-end debug-info throughput in report generation without changing report schema/output semantics.

## Scope and code touch targets
- Primary: `src/fuzz_introspector/debug_info.py`
- Related call sites: `src/fuzz_introspector/analysis.py` (`AnalysisProject.load_debug_report` stage orchestration/logging)
- No API/CLI surface change required for first rollout.

## 1) Problem decomposition from runtime signatures

### A. Memory bottleneck signatures
- Signature: high elapsed time and/or instability at `[debug-load] stage=debug_types_yaml` and `stage=debug_functions_yaml` when large YAML sets are loaded.
- Signature: repeated `Spilled shard ...` logs from `_load_yaml_collections(...)` and high merge time afterward.
- Signature: low-memory profile needs `FI_DEBUG_SPILL_MB`/`FI_DEBUG_MAX_INMEM_MB` tuning to avoid OOM/regressions.
- Interpretation: shard materialization plus full-list merge creates high resident footprint; spill reduces OOM risk but can shift cost to disk I/O and merge overhead.

### B. Parallelism bottleneck signatures
- Signature: `Parallel shard telemetry ... start/end/elapsed ...` shows long tail shards with weak overlap benefit.
- Signature: wall-clock does not improve proportionally when `FI_DEBUG_MAX_WORKERS` or `FI_DEBUG_CORRELATE_WORKERS` increases.
- Signature: fallback warnings (`falling back to serial`) erase gains when one chunk fails or executor init fails.
- Interpretation: effective speedup is limited by skewed shard sizes, Python-level per-item work (GIL-sensitive sections), and merge/coordination overhead.

### C. Coupled bottleneck
- More workers can increase concurrent in-memory shard payload and spill pressure, which then reduces or negates speedup.

## 2) Ordered fix tracks (P1/P2/P3)

## P1: Stabilize memory first (default-safe)

| Step | Concrete implementation steps | Expected impact | Risk | Compatibility concerns | Rollback |
|---|---|---|---|---|---|
| P1.1 | In `debug_info.py::_load_yaml_collections`, add bounded in-flight scheduling for parallel shards (submit at most `N` futures at a time where `N <= worker_count`) so completed shard results are merged/spilled before queuing all remaining work. | Lower peak RSS during large YAML loads; fewer spill cascades. | Medium: scheduler bugs can starve or reorder processing. | Keep deterministic merge order by shard index (already present); preserve output list order semantics. | Guard by new env knob `FI_DEBUG_MAX_INFLIGHT_SHARDS` defaulting to current behavior; set to legacy mode to disable. |
| P1.2 | In `_record_shard_items`, switch spill candidate policy from "oldest index" only to "largest estimated shard first" under memory pressure. | Faster memory recovery per spill event; fewer spill operations. | Low-medium: estimation may be imperfect. | No schema impact; only spill strategy changes. | Env flag `FI_DEBUG_SPILL_POLICY=oldest` restores current policy. |
| P1.3 | In `analysis.py::load_debug_report`, add optional stage-level memory telemetry log fields (RSS snapshots) next to existing `[debug-load] stage=... elapsed` lines. | Makes regressions measurable and tuning repeatable. | Low. | Requires optional dependency-safe RSS read path; fallback if unavailable. | Disable by env flag `FI_DEBUG_STAGE_RSS=0`. |

## P2: Recover real parallel speedup

| Step | Concrete implementation steps | Expected impact | Risk | Compatibility concerns | Rollback |
|---|---|---|---|---|---|
| P2.1 | In `_load_yaml_collections`, improve shard construction: compute file-size-aware shards instead of fixed file-count (`FI_DEBUG_SHARD_FILES`) so per-shard work is more balanced. | Better parallel utilization; reduced long-tail shard completion time. | Medium: filesystem stat cost and shard heuristic tuning. | Keep existing fixed-count path as default fallback for portability. | Env knob `FI_DEBUG_SHARD_STRATEGY=fixed_count` keeps old behavior. |
| P2.2 | In `correlate_debugged_function_to_debug_types`, add a process-pool option for correlation path (similar to loader’s `FI_DEBUG_USE_PROCESS_POOL`) for CPU-heavy signature extraction; keep thread mode default. | Potential speedup on high-core hosts for large function sets. | Medium-high: payload serialization overhead and copy cost may dominate on small inputs. | Keep deterministic chunk merge and identical function mutation semantics. | Default remains thread/serial; env `FI_DEBUG_CORRELATE_USE_PROCESS_POOL=0` returns to old path. |
| P2.3 | Add adaptive worker downshift: if observed per-shard elapsed variance is high or spill rate crosses threshold, reduce active workers for subsequent shards in the same run. | Protects against self-thrashing and improves effective throughput stability. | Medium: control loop can over-correct. | Must only affect performance knobs, not data outputs. | Env `FI_DEBUG_ADAPTIVE_WORKERS=0` disables and restores static workers. |

## P3: Hardening and operational guardrails

| Step | Concrete implementation steps | Expected impact | Risk | Compatibility concerns | Rollback |
|---|---|---|---|---|---|
| P3.1 | Add explicit perf guardrail warnings: when stage elapsed or peak RSS crosses configured thresholds, log actionable tuning hints referencing existing knobs (`FI_DEBUG_MAX_WORKERS`, `FI_DEBUG_SPILL_MB`, etc.). | Faster operator diagnosis; fewer blind retries. | Low. | Log-only change; no output artifact changes. | Disable with `FI_STAGE_WARN_SECONDS=0` and new `FI_DEBUG_PERF_WARN=0`. |
| P3.2 | Add targeted regression/perf tests in `src/test/test_debug_info.py` for bounded in-flight scheduling, shard balancing deterministic ordering, and fallback equivalence. | Prevents performance fixes from breaking correctness. | Medium: tests may be timing-sensitive if not designed carefully. | Prefer invariant-based assertions (order/content parity), not strict runtime numbers. | Mark new perf-sensitive tests optional/slow and keep core behavior tests always-on. |
| P3.3 | Document recommended presets update in `README.md` only after thresholds are validated by benchmark protocol below. | Safer rollout and less misconfiguration. | Low. | Keep current presets until validated. | Revert doc-only changes. |

## 3) Implementation order
1. P1.1 -> P1.2 -> P1.3
2. P2.1 -> P2.2 -> P2.3
3. P3.1 -> P3.2 -> P3.3

Rationale: first prevent memory amplification, then optimize speedup, then lock in operational safety.

## 4) Instrumentation and benchmark protocol

## Metrics to measure
- Stage wall time from existing logs:
  - `[debug-load] stage=debug_report`
  - `[debug-load] stage=debug_types_yaml`
  - `[debug-load] stage=debug_functions_yaml`
  - `[debug-load] stage=type_correlation`
- Shard telemetry from `Parallel shard telemetry ...`:
  - per-shard elapsed distribution (p50/p95/max)
  - tail ratio (`max / median`)
- Memory:
  - peak RSS for whole process
  - optional per-stage RSS snapshots (if P1.3 implemented)
- Spill behavior:
  - spill count
  - spill bytes (if added)
  - spill merge elapsed

## Datasets
- `D1 Small`: local/CI-sized project with low YAML count (sanity baseline).
- `D2 Medium`: representative OSS-Fuzz project with moderate debug YAML size.
- `D3 Large`: worst-case/high-cardinality project used in perf triage.

Store dataset IDs and exact input artifact paths in benchmark notes for reproducibility.

## Run matrix (before/after)
- Baseline config: current recommended “Large host” and “Low-memory CI” presets from `README.md`.
- Candidate configs:
  - memory-safe: low workers + spill enabled
  - throughput: higher workers + process-pool experiment (where enabled)
- For each dataset/config pair: run at least 3 times, report median and worst.

## Acceptance thresholds
- Memory:
  - `D3` peak RSS reduced by >=20% vs baseline, or OOM eliminated in low-memory CI profile.
- Throughput:
  - Combined YAML load stages (`debug_types_yaml + debug_functions_yaml`) improve >=15% median on `D2/D3`.
  - `type_correlation` improves >=10% median on `D3` when parallel enabled.
- Parallel efficiency:
  - shard tail ratio (`max/median`) improves by >=25% on `D3`.
- Correctness:
  - no diff in produced debug function/type counts for same input.

## 5) Subagent handoff map

| Workstream | Owner subagent | Deliverables | Exit criteria |
|---|---|---|---|
| Memory control track (P1.1/P1.2) | `DebugInfo-Core` | bounded in-flight scheduler, spill-policy implementation, env knobs + docs in code comments | RSS and spill metrics meet memory threshold on `D3` with parity on outputs |
| Correlation/load parallel tuning (P2.1/P2.2/P2.3) | `Parallelism-Perf` | size-aware sharding, optional correlate process-pool path, adaptive worker prototype | throughput and tail-ratio thresholds met on `D2/D3` |
| Telemetry + benchmark harness (P1.3 + protocol execution) | `Perf-Observability` | stage RSS logs, benchmark scripts/config matrix, before/after report | reproducible benchmark report with medians/worst-case and config capture |
| Regression and rollout safety (P3.1/P3.2/P3.3) | `QA-Reliability` | invariant tests, perf warning guardrails, rollout checklist | tests green; rollback toggles verified; docs updated only after benchmark signoff |

## Rollout policy
- Ship P1 behind opt-in knobs, then flip defaults only after benchmark acceptance.
- Ship P2 experimental paths off-by-default first.
- Keep all rollback knobs for at least one release cycle after default changes.
