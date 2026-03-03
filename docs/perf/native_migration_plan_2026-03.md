# Native Migration Performance Optimization Plan
*Created: March 2, 2026*

## Executive Summary

### Goals
- **Full CPU Utilization**: Eliminate Python GIL bottlenecks through native parallel processing
- **Memory Reduction**: Target ≥40% reduction in peak RSS through efficient data structures and streaming
- **Speed Improvements**: Achieve ≥5× end-to-end speedup on large projects (10k+ functions)
- **Maintainability**: Keep codebase complexity manageable through incremental migration

### Approach
Aggressive native migration strategy using Rust as primary language (Go as fallback) for CPU-bound and I/O-bound hotspots identified through profiling and container monitoring.

### Targets
- **Primary Speedup**: ≥5× on large projects (cgserver scale: ~47 fuzzers, 10k+ functions)
- **Memory Reduction**: ≥40% peak RSS reduction
- **Timeline**: 11 weeks (4 sprints + Sprint 0 for setup)
- **Compatibility**: Maintain full backward compatibility with Python fallback

### Status
- **Current Performance**: Rust backend: **7.66×** speedup, **49.2%** RSS reduction on cgserver (see baselines below)
- **Native Gates**: Rust/Go overlay, correlator, YAML loader, LLVM cov loader, analysis plugins — all passing parity
- **Sprint Status**: All sprints 0-4 deliverables complete; Go analysis plugins not planned (Rust only)

### Current Benchmark Results (March 3, 2026 — cgserver, 49 fuzzers, after native type-loading fast path)

| Configuration | Wall (s) | Peak RSS (MB) | Speedup | RSS Δ |
|---|---|---|---|---|
| Python baseline | 687.67 | 11,100 | 1× | — |
| Rust (YAML only) | 167.4 | 5,638 | 4.1× | −49.2% |
| Rust + plugins (pre-memory-opt) | 84.96 | 6,709 | 8.09× | −39.6% |
| Rust + plugins (prev best, 2026-03-02) | 83.43 | 5,789 | 8.24× | −47.8% |
| **Rust + plugins (current best)** | **89.77** | **5,640.86** | **7.66×** | **−49.2%** |
| **Go full stack (first authoritative run)** | **89.77** | **5,674.67** | **7.66×** | **−48.9%** |

- Output hash (all native backends): `3e0a44d44abbf1d3968e2d3e2223045618ffeeb3e37776a6b75c1c9853c2061b`
- Rust and Go now produce identical output and nearly identical wall time; Go uses slightly more RSS
- Measured after commit `2018c3ab` (skip Python type loading in native correlator path)
- Baseline files: `.work/baselines/cgserver-full_rust_baseline.json`, `.work/baselines/cgserver-full_go_baseline.json`

---

## Background

### Current Performance Characteristics

Based on profiling and container monitoring:

1. **CPU Utilization**: 
   - Python GIL limits parallelism in CPU-bound phases (correlation, analysis plugins)
   - Single-threaded bottlenecks in YAML/JSON parsing and debug info loading
   - Underutilized multi-core systems (observed <30% aggregate CPU on 12-core systems)

2. **Memory Pressure**:
   - Peak RSS of 1-3GB on medium projects (5k functions)
   - Memory spikes during:
     - Debug type dictionary construction
     - Call tree overlay computation
     - HTML report generation (large DOT graphs)
   - No streaming; full in-memory data structures

3. **I/O Bottlenecks**:
   - Sequential YAML file loading (dozens to hundreds of files)
   - Large LLVM coverage JSON files (100MB+) parsed synchronously
   - No compression or lazy loading

4. **Validated Native Components** (as of 2026-03-01):
   - **Overlay backend**: Rust/Go parity validated, strict-shadow mode passing 6/6 tests
   - **Debug correlator**: Rust/Go digest parity clean across 3-run matrix
   - **LLVM coverage loader**: Rust/Go implementations functional
   - **YAML loader**: Rust/Go implementations functional

> ✅ **Note**: Go overlay previously ran in shadow/probe-only mode. As of commit `2018c3ab`, the forced shadow-only restriction was removed. Go is now an authoritative correlator and produces hash-identical output to Rust (verified 2026-03-03).

### Bottleneck Analysis

From `.work/benchmarks/` evidence and profiling:

| Component | Language | Bottleneck Type | Impact | Migration Priority |
|-----------|----------|-----------------|--------|-------------------|
| Debug type correlation | Python | CPU-bound (GIL) | High (30-40% of runtime) | **P0 - Critical** |
| YAML file loading | Python | I/O + CPU (parsing) | Medium (15-20% of runtime) | **P1 - High** |
| LLVM cov loading | Python | I/O + Memory (large files) | Medium (10-15% of runtime) | **P1 - High** |
| Call tree overlay | Python | CPU-bound (complex logic) | High (20-30% of runtime) | **P0 - Critical** |
| Analysis plugins | Python | Mixed (varies by plugin) | Medium (10-20% of runtime) | **P2 - Medium** |
| HTML generation | Python | CPU-bound (template rendering) | Low (5-10% of runtime) | **P3 - Low** |

### Decision Rationale for Native Migration

**Why not P2.2 process pool alone?**
- Process pool (see `docs/perf/p2_2_process_pool_plan.md`) addresses correlation parallelism but:
  - Still bound by Python parsing/serialization overhead
  - Pickle serialization amplifies memory pressure
  - Does not address I/O bottlenecks or parsing inefficiency
  - Process pool is a bridge solution, not end-state

**Why Rust over Go?**
- **Performance**: Rust closer to C++ performance, zero-cost abstractions
- **Memory Safety**: Eliminates segfaults, safer FFI
- **Ecosystem**: Better YAML/JSON parsing (serde), tree-sitter bindings, coverage tooling
- **Existing Investment**: Native overlay/correlator Rust implementations already passing parity gates
- **Go as Fallback**: Maintain Go implementations for simpler deployment scenarios (single-binary, no C dependencies)

---

## Design Principles

### 1. Memory-Aware by Design
- **Streaming First**: Process large files in chunks, avoid full in-memory materialization
- **Adaptive Scaling**: Auto-detect available RAM, scale worker count dynamically
- **Pressure Detection**: Monitor RSS, spill to disk or reduce parallelism under memory pressure
- **Explicit Limits**: Honor `FI_MAX_RSS_GB` env var for fixed memory budgets

### 2. Standalone + OSS-Fuzz Compatible
- **No External Dependencies**: Native binaries must work in OSS-Fuzz containers without extra setup
- **Python Fallback**: If native binary missing/fails, gracefully fall back to Python implementation
- **Schema Stability**: Native and Python backends must produce identical output schemas
- **Build Integration**: Native binaries built via `Dockerfile` steps, not required for dev workflow

### 3. Agentic Implementation
- **Incremental Commits**: Each native component lands behind feature flag, tested independently
- **Parity Gates**: Automated tests verify output parity vs Python baseline before enabling by default
- **Rollback Safety**: Single env var toggles native backend off, no code revert needed
- **Documentation First**: Each component documented in `README.md` with tuning guidance

### 4. Incremental Delivery
- **Sprint-Based**: 4 sprints, each delivering a standalone, testable component
- **No Big-Bang Rewrites**: Python code remains until native replacement proven
- **Continuous Integration**: Native binaries integrated into CI from Sprint 1 onward
- **User Opt-In**: New backends off by default until Sprint 4 graduation decision

---

## Sprint Breakdown

### Sprint 0: Setup & Baseline (Week 1, March 3-7, 2026)

**Objectives**:
- Establish development and testing infrastructure
- Document baseline performance metrics
- Set up build toolchain for Rust native components

**Assigned Subagent**: `devops-engineer`
**Rationale**: Sprint 0 is infrastructure-only: benchmark scripts, CI build job for Rust toolchain, directory setup. No application code changes. The `devops-engineer` agent owns CI/CD pipelines, build toolchain setup, and automation scripts.
**Delegation Prompt Hint**: "Set up `.work/scripts/`, build `tools/native_*/` in CI (GitHub Actions), capture simdjson baseline metrics."

**Deliverables**:
1. **Testing Infrastructure**:
   - `.work/benchmarks/simdjson/` setup (small test project)
   - `.work/benchmarks/cgserver/` setup (real-world validation)
   - Baseline JSON files capturing current performance
   - Benchmark runner script: `.work/scripts/run_benchmark.sh`
   - Results comparison tool: `.work/scripts/compare_results.py`

2. **Build Toolchain**:
   - Rust stable toolchain in CI (GitHub Actions)
   - Local `tools/native_*/Cargo.toml` projects buildable
   - CI job: `build-native-components` (compile only, no tests yet)

3. **Documentation**:
   - `docs/perf/native_migration_plan_2026-03.md` (this document)
   - `docs/perf/testing_infrastructure.md` (see below)
   - `README.md` section: "Native Backend Tuning" (placeholder)

**Acceptance Criteria**:
- [ ] `.work/benchmarks/simdjson/` baseline run completes, captures: wall time, peak RSS, output hash
- [ ] `.work/scripts/run_benchmark.sh --baseline` succeeds
- [ ] CI successfully builds all `tools/native_*/` Rust projects
- [ ] Baseline metrics documented in `.work/baselines/simdjson_baseline.json`

**Estimated Effort**: 5 days (1 sprint week)

---

### Sprint 1: Parallel Debug Type Correlation (Weeks 2-3, March 10-21, 2026)

**Objectives**:
- Migrate debug type correlation to Rust with process-level parallelism
- Eliminate Python GIL bottleneck in `correlate_debugged_function_to_debug_types(...)`
- Achieve measurable speedup on medium-to-large projects

**Assigned Subagent**: `dev` (Rust implementation) + `test-engineer` (parity gates)
**Rationale**: Sprint 1 requires writing new Rust code (`native_debug_correlator_rust`) and Python integration (`debug_info.py`). The `dev` agent handles TDD implementation. The `test-engineer` agent authors `test_debug_correlator_backend.py` parity tests.
**Delegation Prompt Hint**: "Implement Rust debug correlator binary with Rayon parallelism; integrate into `debug_info.py` behind `FI_DEBUG_CORRELATE_NATIVE=rust`; write parity tests."

**Scope**:
- **Component**: `src/fuzz_introspector/debug_info.py` correlation logic
- **Approach**: Rust binary invoked via subprocess, receives JSON input (type dictionary + functions), returns JSON output (correlated functions)
- **Parallelism**: Rayon data-parallel map over function list

**Technical Design**:

1. **Rust Binary**: `tools/native_debug_correlator_rust/`
   - **Input**: JSON stdin
     ```json
     {
       "debug_type_dictionary": { "123456": { "name": "int", ... }, ... },
       "functions": [
         { "name": "foo", "type_arguments": [...], ... },
         ...
       ]
     }
     ```
    - **Output**: JSON stdout (correlated functions with `func_signature_elems`, `source`)
    - **Parallelism**: Rayon parallel iterator over `functions` (CPU-bound)
    - **Memory**: Shared read-only `Arc<DebugTypeDictionary>` per thread

> ⚠️ **Protocol Inconsistency**: `backend_loaders.py:1484` checks `status == "success"`, but this plan's spec says `"ok"` and the overlay (`backend_loaders.py:1162`) accepts both `"success"` and `"ok"`. If a new Rust binary emits only `"ok"`, the correlator will silently fall back to Python. **New native implementations must emit `"success"` (not `"ok"`) for the correlator path.**

2. **Python Integration**: `src/fuzz_introspector/debug_info.py`
   - New function: `_correlate_via_native_rust(...)`
   - Feature flag: `FI_DEBUG_CORRELATE_NATIVE=rust` (default `false`)
   - Fallback: On native binary missing or non-zero exit, fall back to Python (thread or serial)
   - Subprocess invocation: `subprocess.run([native_bin], input=json_input, capture_output=True)`
   - Debug preservation: `FI_DEBUG_CORRELATOR_PRESERVE_DEBUG` — when set, native attempt artifacts (stdin/stdout dumps) are retained for post-mortem analysis

> ⚠️ **Implementation Gap**: `debug_info.py`'s `_cleanup_native_attempt` does **not** check `FI_DEBUG_CORRELATOR_PRESERVE_DEBUG` — it always cleans up unconditionally. The contract described here is aspirational; fix `_cleanup_native_attempt` before relying on this flag.

3. **Parity Gate**: `src/test/test_debug_correlator_backend.py`
   - Parametrized test: `@pytest.mark.parametrize("backend", ["python", "rust"])`
   - Assert identical `func_signature_elems` and `source` fields (order-independent comparison)
   - Test matrix: small fixture, medium fixture (1k functions), malformed input (missing type)

**Deliverables**:
1. Rust binary: `tools/native_debug_correlator_rust/target/release/native_debug_correlator_rust`
2. Python integration: `_correlate_via_native_rust(...)` in `debug_info.py`
3. Feature flag parsing: `FI_DEBUG_CORRELATE_NATIVE` env var
4. Parity tests: `test_debug_correlator_backend.py` green for both backends
5. CI job: `test-native-correlator` (build + run parity tests)

**Acceptance Criteria**:
- [ ] Rust binary compiles and passes unit tests
- [ ] Parity tests pass: Python vs Rust output identical on 3+ fixtures
- [ ] Benchmark: ≥2× speedup on simdjson correlation phase (5k functions)
- [ ] Memory: No regression (≤10% increase in peak RSS acceptable)
- [ ] Fallback: Native binary missing → Python fallback works
- [ ] Fallback: Native binary returns non-zero → Python fallback works

**Estimated Effort**: 10 days (2 sprint weeks)

---

### Sprint 2: Parallel YAML + LLVM Coverage Loading (Weeks 4-5, March 24-April 4, 2026)

**Objectives**:
- Migrate YAML and LLVM coverage loading to Rust
- Enable parallel file I/O and parsing (eliminate sequential bottleneck)
- Reduce memory pressure through streaming and efficient data structures

**Assigned Subagent**: `dev` (Rust implementation) + `test-engineer` (parity gates)
**Rationale**: Same as Sprint 1 — new Rust binaries (`native_yaml_loader_rust`, `native_llvm_cov_loader_rust`) and Python integration. `test-engineer` extends `test_backend_loaders.py`.
**Delegation Prompt Hint**: "Implement parallel YAML loader and LLVM coverage loader in Rust; integrate into `debug_info.py` and `llvm_cov_load.py`; write parity + regression tests."

**Scope**:
- **YAML Loader**: `src/fuzz_introspector/debug_info.py` → `load_debug_all_yaml_files(...)`
- **LLVM Cov Loader**: `src/fuzz_introspector/llvm_cov_load.py` → `llvm_cov_parse(...)`

**Technical Design**:

1. **Rust YAML Loader**: `tools/native_yaml_loader_rust/`
   - **Input**: JSON stdin (list of file paths)
     ```json
     {
       "yaml_files": ["/path/to/debuginfo.1.yaml", "/path/to/debuginfo.2.yaml", ...]
     }
     ```
   - **Output**: JSON stdout (merged debug types + functions)
   - **Parallelism**: Rayon parallel file read + parse (I/O + CPU bound)
   - **Memory**: Stream per-file, merge incrementally into shared `HashMap` with lock-free concurrent inserts (dashmap crate)

2. **Rust LLVM Cov Loader**: `tools/native_llvm_cov_loader_rust/`
   - **Input**: JSON stdin (list of coverage JSON file paths)
   - **Output**: JSON stdout (merged coverage data per function)
   - **Parallelism**: Rayon parallel file read + parse
   - **Memory**: Streaming JSON parser (serde_json streaming API), avoid full DOM

3. **Python Integration**:
   - `src/fuzz_introspector/debug_info.py`:
     - New function: `_load_yaml_via_native(...)`
     - Feature flag: `FI_DEBUG_YAML_LOADER=rust` (default `false`)
   - `src/fuzz_introspector/llvm_cov_load.py`:
     - New function: `_load_llvm_cov_via_native(...)`
     - Feature flag: `FI_LLVM_COV_LOADER=rust` (default `false`)

4. **Parity Gate**: `src/test/test_backend_loaders.py`
   - YAML parity test: Python vs Rust output identical (function count, type count, digest)
   - LLVM cov parity test: Python vs Rust coverage maps identical

**Deliverables**:
1. Rust binaries: `native_yaml_loader_rust`, `native_llvm_cov_loader_rust`
2. Python integration: feature flags + native invocation functions
3. Parity tests: `test_backend_loaders.py` green for both backends
4. CI job: `test-native-loaders`

**Acceptance Criteria**:
- [ ] YAML loader: ≥3× speedup on simdjson (dozens of YAML files)
- [ ] LLVM cov loader: ≥2× speedup on large coverage files (100MB+)
- [ ] Memory: ≥20% reduction in peak RSS during load phase
- [ ] Parity: 100% digest match Python vs Rust on simdjson + cgserver
- [ ] Fallback: Missing binary → Python fallback works

**Estimated Effort**: 10 days (2 sprint weeks)

---

### Sprint 3: Parallel Analysis Plugins (Weeks 6-8, April 7-25, 2026)

**Objectives**:
- Migrate CPU-intensive analysis plugins to Rust
- Enable plugin-level parallelism (run multiple plugins concurrently)
- Maintain plugin API compatibility (Python plugins still work)

**Assigned Subagent**: `dev` (Rust plugin framework) + `test-engineer` (plugin parity matrix)
**Rationale**: Sprint 3 introduces the Rust plugin framework and migrates 3 analysis plugins. This is the most complex sprint — `dev` owns the `NativePluginProxy` class and Rust trait design; `test-engineer` builds `test_analysis_plugin_matrix.py`.
**Delegation Prompt Hint**: "Design Rust `AnalysisPlugin` trait; implement `OptimalTargets`, `RuntimeCoverageAnalysis`, `FuzzCalltreeAnalysis` in Rust; write parametrized parity tests across Python/Rust backends."

**Scope**:
- **High-Priority Plugins** (CPU-bound, high impact):
  - `OptimalTargets` (call tree traversal, complexity scoring)
  - `RuntimeCoverageAnalysis` (coverage overlap computation)
  - `FuzzCalltreeAnalysis` (calltree reachability)

**Technical Design**:

1. **Rust Plugin Framework**: `tools/native_analysis_plugins_rust/`
   - **Input**: JSON stdin (project data: functions, call graph, coverage)
   - **Output**: JSON stdout (plugin results, schema-compatible with Python plugins)
   - **Parallelism**: 
     - Inter-plugin: Rayon parallel execution of independent plugins
     - Intra-plugin: Plugin-specific parallelism (e.g., parallel traversal of call graph)
   - **API**: Each plugin implements `AnalysisPlugin` trait with `analyze(&self, project: &Project) -> Result`

2. **Python Integration**: `src/fuzz_introspector/analysis.py`
   - New function: `_run_native_plugins(...)`
   - Feature flag: `FI_NATIVE_PLUGINS=rust` (default `false`)
   - Plugin registry: Python `all_analyses` list extended with `NativePluginProxy` entries
   - Invocation: Subprocess call to Rust binary with serialized project data

3. **Hybrid Mode**: Allow mixing Python and Rust plugins
   - Python plugins run in-process as before
   - Rust plugins invoked via subprocess
   - Results merged into unified report

4. **Parity Gate**: `src/test/test_analysis_plugin_matrix.py`
   - Parametrized test per plugin: Python vs Rust output schema-identical
   - Validate: Table data, file outputs, JSON payloads

**Deliverables**:
1. Rust plugin framework: `native_analysis_plugins_rust` binary
2. Rust implementations: `OptimalTargets`, `RuntimeCoverageAnalysis`, `FuzzCalltreeAnalysis`
3. Python integration: `NativePluginProxy` class + feature flag
4. Parity tests: `test_analysis_plugin_matrix.py` green
5. CI job: `test-native-plugins`

**Acceptance Criteria**:
- [ ] `OptimalTargets` Rust: ≥3× speedup on simdjson (call tree traversal)
- [ ] Plugin parallelism: ≥2× speedup running 3 plugins concurrently (vs sequential)
- [ ] Memory: No regression in peak RSS
- [ ] Parity: 100% schema match for all migrated plugins
- [ ] Fallback: Native plugins fail → fall back to Python plugins

**Estimated Effort**: 15 days (3 sprint weeks)

---

### Sprint 4: End-to-End Optimization + Graduation (Weeks 9-11, April 28-May 16, 2026)

**Objectives**:
- Integrate all native components into unified pipeline
- Enable memory-adaptive runtime with graceful degradation
- Benchmark full pipeline on cgserver (real-world validation)
- Make graduation decision: enable native backends by default or keep opt-in

**Assigned Subagent**: `dev` (memory manager + unified flag) + `devops-engineer` (OSS-Fuzz Dockerfile) + `code-review` (graduation review)
**Rationale**: Sprint 4 is multi-domain: new `memory_manager.py` module (dev), Dockerfile integration for OSS-Fuzz (devops-engineer), and a final graduation review before enabling by default (code-review). The `code-review` agent checks for security, correctness, and fallback safety.
**Delegation Prompt Hint**: "Implement `memory_manager.py` with adaptive worker scaling; add `FI_NATIVE_BACKENDS` unified flag; update OSS-Fuzz Dockerfile; run graduation benchmark on cgserver; request code review before merging."

**Scope**:
- **Unified Pipeline**: All native components enabled via single flag
- **Memory Management**: Adaptive worker scaling based on available RAM
- **End-to-End Testing**: Full cgserver build with native backends
- **Graduation Decision**: Based on success metrics (see below)

**Technical Design**:

1. **Unified Feature Flag**: `FI_NATIVE_BACKENDS=rust` (default `false` until graduation)
   - Enables: correlation, YAML loader, LLVM cov loader, analysis plugins (all native)
   - Overrides individual component flags

2. **Memory-Adaptive Runtime**: `src/fuzz_introspector/memory_manager.py` (new module)
   - Detect available RAM: `psutil.virtual_memory().available`
   - Scale workers: `min(cpu_count, available_gb // per_worker_gb_estimate)`
   - Monitor RSS: Periodic check, reduce workers or spill to disk if >80% of `FI_MAX_RSS_GB`
   - Env var: `FI_MAX_RSS_GB` (default: auto-detect, use 75% of available RAM)

3. **End-to-End Integration**:
   - `src/main.py`: Parse `FI_NATIVE_BACKENDS` flag early in pipeline
   - `src/fuzz_introspector/commands.py`: Pass native flags to `AnalysisProject.run_analysis(...)`
   - Logging: Emit `[native-backend]` log lines with backend selection + timing per phase

4. **Graduation Testing**:
   - **Development**: simdjson (small, fast iteration)
   - **Validation**: cgserver build (~47 fuzzers, 10k+ functions, real-world complexity)
   - **Metrics** (see Success Metrics below)

**Deliverables**:
1. Memory-adaptive runtime: `memory_manager.py` module
2. Unified feature flag: `FI_NATIVE_BACKENDS` parsing
3. End-to-end benchmarks: `.work/benchmarks/cgserver/native_full_run.json`
4. Graduation report: `docs/perf/native_migration_graduation_2026-05.md` (decision + evidence)
5. `README.md` update: "Native Backend Tuning" section (comprehensive)

**Acceptance Criteria**:
- [ ] simdjson: ≥5× speedup, ≥40% memory reduction (vs Python baseline)
- [ ] cgserver: ≥4× speedup, ≥35% memory reduction (vs Python baseline)
- [ ] Stability: 10 consecutive cgserver runs, 0 crashes, 0 fallbacks
- [ ] Parity: 100% schema match (diff output JSON, ignore timestamps/order)
- [ ] Memory: No OOM events under `FI_MAX_RSS_GB=8` on cgserver (baseline requires 12GB+)
- [ ] Graduation decision: If all criteria pass → enable by default in main branch

**Estimated Effort**: 15 days (3 sprint weeks)

---

## Success Metrics

### Primary Metrics (Gate for Graduation)

| Metric | Target | Measurement | Baseline Source |
|--------|--------|-------------|-----------------|
| **Speedup (simdjson)** | ≥5× | Wall time (end-to-end) | `.work/baselines/simdjson_baseline.json` |
| **Speedup (cgserver)** | ≥4× | Wall time (end-to-end) | `.work/baselines/cgserver_baseline.json` |
| **Memory Reduction (simdjson)** | ≥40% | Peak RSS (MB) | Baseline peak RSS |
| **Memory Reduction (cgserver)** | ≥35% | Peak RSS (MB) | Baseline peak RSS |
| **Output Parity** | 100% | JSON diff hash (ignore order/timestamps) | Python baseline |
| **Stability** | 0 failures | 10 consecutive runs, no crashes/fallbacks | N/A |

> ✅ G1 (≥35% RSS reduction) **met**: 49.2% reduction on cgserver (Rust). G2 (≥30% correlation speedup) **met**: 7.66× overall speedup on cgserver. G3 (parity) passes. Go now also authoritative and hash-identical to Rust. Primary graduation metrics exceeded.

### Secondary Metrics (Observability)

| Metric | Target | Measurement |
|--------|--------|-------------|
| **CPU Utilization** | ≥70% | Aggregate CPU% during hottest phase |
| **Build Time (CI)** | ≤+2 min | CI job duration increase (Rust compile overhead) |
| **Binary Size** | ≤50MB total | Sum of all native binaries (release builds) |
| **Fallback Rate** | <1% | Production runs falling back to Python |

### Reporting

- **Per-Sprint**: Update `.work/benchmarks/<project>/sprint_<N>_results.json` with metrics
- **Graduation**: `docs/perf/native_migration_graduation_2026-05.md` with:
  - All metrics (primary + secondary)
  - Decision rationale
  - Rollout plan or rollback decision

---

## Testing Strategy

### Development Testing (Fast Iteration)
- **Project**: simdjson (~5,000 functions)
- **Why**: Fast build (<2 min), good coverage data, representative C++ codebase
- **Location**: `.work/benchmarks/simdjson/`
- **Frequency**: Every commit during sprint
- **Automation**: `.work/scripts/run_benchmark.sh simdjson --backend rust`

### Validation Testing (Real-World)
- **Project**: cgserver (~47 fuzzers, 10k+ functions, complex call graphs)
- **Why**: Production-scale complexity, known performance pain points
- **Location**: `.work/benchmarks/cgserver/`
- **Frequency**: End of each sprint (Sprint 1-4)
- **Automation**: `.work/scripts/run_benchmark.sh cgserver --backend rust --runs 10`

### Testing Infrastructure

**Directory Structure**:
```
.work/
├── benchmarks/
│   ├── simdjson/               # Small test project
│   │   ├── build/              # OSS-Fuzz build artifacts
│   │   ├── corpus/             # Fuzzer corpus (optional)
│   │   ├── results/            # Benchmark results per run
│   │   │   ├── baseline/
│   │   │   ├── sprint1/
│   │   │   ├── sprint2/
│   │   │   ├── sprint3/
│   │   │   └── sprint4/
│   │   └── config.json         # Project-specific config
│   └── cgserver/               # Real-world validation
│       ├── build/
│       ├── results/
│       │   ├── baseline/
│       │   └── sprint<N>/
│       └── config.json
├── baselines/
│   ├── simdjson_baseline.json  # Captured in Sprint 0
│   └── cgserver_baseline.json  # Captured in Sprint 0
└── scripts/
    ├── run_benchmark.sh        # Main benchmark runner
    ├── compare_results.py      # Compare two result sets
    └── report_sprint_metrics.py  # Generate sprint summary
```

**Benchmark Metrics Captured**:
- **Wall Time** (seconds): `time` command or Python `time.perf_counter()`
- **Peak RSS** (MB): `/usr/bin/time -v` or `psutil.Process().memory_info().rss`
- **CPU Utilization** (%): `psutil.cpu_percent(interval=1)` sampled during run
- **Output Hash**: SHA256 of canonical JSON output (sorted keys, ignore timestamps)
- **Backend Used**: `python|rust|go` (logged in output)
- **Fallback Events**: Count of fallback to Python (from logs)

**Benchmark Runner Usage**:
```bash
# Capture baseline (Sprint 0)
.work/scripts/run_benchmark.sh simdjson --backend python --output .work/baselines/simdjson_baseline.json

# Sprint 1: Test native correlator
.work/scripts/run_benchmark.sh simdjson --backend rust --output .work/benchmarks/simdjson/results/sprint1/run1.json

# Compare results
.work/scripts/compare_results.py \
  .work/baselines/simdjson_baseline.json \
  .work/benchmarks/simdjson/results/sprint1/run1.json
```

**Parity Testing**:
- **Unit Tests**: `src/test/test_debug_correlator_backend.py`, `test_backend_loaders.py`, `test_analysis_plugin_matrix.py`
- **Integration Tests**: `src/test/test_full_pipeline_parity.py` (new, Sprint 4)
- **Matrix**: `@pytest.mark.parametrize("backend", ["python", "rust", "go"])`
- **Assertions**:
  - Output schema identical (JSON schema validator)
  - Function count, type count, coverage count identical
  - Call graph structure identical (sorted edge list comparison)
  - Analysis plugin tables identical (row count, column names, sorted rows)

---

## Memory Management Strategy

### Adaptive Scaling (Default)

**Objective**: Maximize throughput within available memory budget, gracefully degrade under pressure.

**Mechanism**:
1. **Startup**: Detect available RAM via `psutil.virtual_memory().available`
2. **Worker Scaling**: 
   - Estimate per-worker memory: `per_worker_gb = (baseline_rss_gb * 1.2) / cpu_count`
   - Max workers: `min(cpu_count, available_gb // per_worker_gb)`
   - Env override: `FI_MAX_WORKERS` (default: auto-detect)
3. **Runtime Monitoring**:
   - Sample RSS every 5 seconds: `psutil.Process().memory_info().rss`
   - If RSS > 80% of available → reduce workers by 50%, log warning
   - If RSS > 90% of available → fallback to serial mode, log error
4. **Spill to Disk** (Optional, Sprint 4):
   - Large call trees: Serialize to SQLite, query lazily
   - Coverage maps: Memory-map files instead of loading fully

### Fixed Limit (Opt-In)

**Objective**: Enforce hard memory ceiling (e.g., OSS-Fuzz container limits).

**Mechanism**:
1. **Env Var**: `FI_MAX_RSS_GB=8` (example: 8GB limit)
2. **Worker Scaling**: `max_workers = min(cpu_count, max_rss_gb // per_worker_gb)`
3. **Runtime**: Fail fast if RSS exceeds limit (log error, exit non-zero)

### Graceful Degradation Modes

| Mode | Workers | Memory Use | Speed | Trigger |
|------|---------|------------|-------|---------|
| **Full Parallel** | N (cpu_count) | High | Fastest | RSS < 60% of limit |
| **Reduced Parallel** | N/2 | Medium | Fast | RSS 60-80% of limit |
| **Serial** | 1 | Low | Slow | RSS > 80% of limit |
| **Fail** | 0 | N/A | N/A | RSS > 100% of limit (OOM imminent) |

**Logging**:
```
[memory-manager] Available: 32.0 GB, Max: 24.0 GB (FI_MAX_RSS_GB), Workers: 12
[memory-manager] RSS: 18.5 GB (77%), Mode: Full Parallel
[memory-manager] RSS: 20.1 GB (84%), Mode: Reduced Parallel (workers: 12 → 6)
[memory-manager] RSS: 22.3 GB (93%), Mode: Serial (workers: 6 → 1)
```

---

## Deployment Strategy

### Build from Source (Default for Native Backends)

**Requirements**:
- Rust stable toolchain (1.70+)
- Cargo build system
- Platform: Linux x86_64 (primary), macOS arm64 (secondary)

**Build Steps** (automated in `Dockerfile` and CI):
```bash
# Install Rust (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build all native components
cd tools/native_debug_correlator_rust && cargo build --release
cd tools/native_yaml_loader_rust && cargo build --release
cd tools/native_llvm_cov_loader_rust && cargo build --release
cd tools/native_analysis_plugins_rust && cargo build --release

# Verify binaries
ls -lh tools/*/target/release/native_*
```

### Backward Compatibility (Python Fallback)

**Guarantee**: Fuzz Introspector works fully without Rust toolchain.

**Fallback Mechanism**:
1. **Binary Detection**: Python code checks for native binary existence at startup
2. **Runtime Fallback**: If native binary missing or returns non-zero exit, fall back to Python implementation
3. **Logging**: Clear log line indicating fallback reason
4. **No Hard Dependency**: `requirements.txt` unchanged, Rust optional

**Example**:
```python
def _correlate_via_native_or_fallback(...):
    native_bin = shutil.which("native_debug_correlator_rust")
    if not native_bin or not os.getenv("FI_NATIVE_BACKENDS"):
        logger.info("[correlator] Using Python backend (native disabled or missing)")
        return _correlate_via_python(...)
    
    try:
        result = subprocess.run([native_bin], input=json_data, capture_output=True, timeout=300)
        if result.returncode != 0:
            logger.warning(f"[correlator] Native backend failed (rc={result.returncode}), falling back to Python")
            return _correlate_via_python(...)
        return json.loads(result.stdout)
    except Exception as e:
        logger.error(f"[correlator] Native backend exception: {e}, falling back to Python")
        return _correlate_via_python(...)
```

### Feature Flags for Gradual Rollout

**Sprint 0-3**: All native backends off by default
```bash
# Opt-in per component
export FI_DEBUG_CORRELATE_NATIVE=rust
export FI_DEBUG_YAML_LOADER=rust
export FI_LLVM_COV_LOADER=rust
export FI_NATIVE_PLUGINS=rust
```

**Sprint 4+**: Unified flag (opt-in)
```bash
# Enable all native backends
export FI_NATIVE_BACKENDS=rust
```

**Post-Graduation** (if metrics pass):
```bash
# Default in code: FI_NATIVE_BACKENDS defaults to "rust" if binaries present
# Opt-out:
export FI_NATIVE_BACKENDS=python  # Force Python backends
```

### OSS-Fuzz Integration

**Dockerfile Changes** (after graduation):
```dockerfile
# Install Rust toolchain (cached layer)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build native components
COPY tools/ /src/fuzz-introspector/tools/
RUN cd /src/fuzz-introspector/tools/native_debug_correlator_rust && cargo build --release && \
    cd /src/fuzz-introspector/tools/native_yaml_loader_rust && cargo build --release && \
    cd /src/fuzz-introspector/tools/native_llvm_cov_loader_rust && cargo build --release && \
    cd /src/fuzz-introspector/tools/native_analysis_plugins_rust && cargo build --release

# Add binaries to PATH
ENV PATH="/src/fuzz-introspector/tools/native_debug_correlator_rust/target/release:$PATH"
ENV PATH="/src/fuzz-introspector/tools/native_yaml_loader_rust/target/release:$PATH"
ENV PATH="/src/fuzz-introspector/tools/native_llvm_cov_loader_rust/target/release:$PATH"
ENV PATH="/src/fuzz-introspector/tools/native_analysis_plugins_rust/target/release:$PATH"

# Enable native backends by default
ENV FI_NATIVE_BACKENDS=rust
```

---

## Selected Test Project: simdjson

**Rationale**: Ideal for iterative development testing.

### Project Characteristics
- **Name**: simdjson
- **Language**: C++
- **Function Count**: ~5,000 functions
- **Coverage**: High-quality coverage data from libFuzzer
- **Build Time**: <2 minutes (fast iteration)
- **Complexity**: Representative of typical OSS-Fuzz projects (parsing, data structures, templates)
- **GitHub**: https://github.com/simdjson/simdjson
- **OSS-Fuzz Integration**: Yes (https://github.com/google/oss-fuzz/tree/master/projects/simdjson)

### Why Not Other Projects?

| Project | Rejected Because |
|---------|------------------|
| **curl** | Too large (~30k functions), slow build (>5 min) |
| **openssl** | Complex build system, hard to iterate quickly |
| **sqlite** | Single large amalgamation file, atypical structure |
| **libpng** | Too small (~500 functions), not challenging enough |
| **cgserver** | Too large for dev iteration (but perfect for validation) |

### Setup Instructions

**Prerequisites**:
```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz.git /tmp/oss-fuzz

# Build simdjson fuzzers
cd /tmp/oss-fuzz
python infra/helper.py build_fuzzers simdjson
```

**Capture Baseline**:
```bash
# Copy build artifacts to .work/benchmarks/simdjson/build/
mkdir -p .work/benchmarks/simdjson/build/
cp -r /tmp/oss-fuzz/build/out/simdjson/* .work/benchmarks/simdjson/build/

# Run fuzz-introspector (Python baseline)
.work/scripts/run_benchmark.sh simdjson --backend python --output .work/baselines/simdjson_baseline.json
```

### Expected Baseline Metrics
- **Wall Time**: ~60 seconds (Python, single-core bottleneck in correlation)
- **Peak RSS**: ~800 MB (debug type dictionary + call tree)
- **Function Count**: ~5,000
- **Coverage Files**: ~10 YAML files, 1 large LLVM coverage JSON (~20MB)

---

## Risk Register & Mitigation

| Risk | Likelihood | Impact | Mitigation | Owner |
|------|------------|--------|------------|-------|
| **Rust toolchain unavailable in OSS-Fuzz** | Low | High | Python fallback always available; document Rust requirement in OSS-Fuzz PR | DevOps |
| **Native backend parity failures** | Medium | High | Strict parity tests; gate each sprint on 100% parity | QA |
| **Memory regression in native code** | Medium | Medium | Continuous RSS monitoring; adaptive scaling with hard limits | Dev |
| **Build time increase in CI** | High | Low | Cache Cargo dependencies; parallelize builds; accept +2min overhead | DevOps |
| **Graduation metrics not met** | Medium | Medium | Keep Python default; iterate in Sprint 5+ until metrics pass | PM |
| **Rust panic/crash in production** | Low | High | Extensive fuzzing of native binaries; catch panics and fall back to Python | Dev |
| **API changes break native integration** | Low | Medium | Version native binary API; reject mismatched versions at runtime | Dev |
| **Maintenance burden (Python + Rust)** | Medium | Low | Automate parity testing; eventually deprecate Python backends post-graduation | PM |

---

## Rollback Plan

### Immediate Rollback (Single Flag)
```bash
export FI_NATIVE_BACKENDS=python
```
- Disables all native backends instantly
- Falls back to Python implementations (well-tested, stable)
- No code revert needed

### Partial Rollback (Per-Component)
```bash
# Disable only correlator (keep YAML/LLVM loaders native)
export FI_DEBUG_CORRELATE_NATIVE=python
export FI_DEBUG_YAML_LOADER=rust
export FI_LLVM_COV_LOADER=rust
```

### Full Revert (Code Level)
- Revert native binary invocation code in `debug_info.py`, `llvm_cov_load.py`, `analysis.py`
- Keep native binaries in `tools/` (no harm, just unused)
- Update `README.md` to remove native backend documentation

### Rollback Triggers
- **Automated**: CI parity tests fail for 2 consecutive runs → disable native backends in CI
- **Manual**: Production crash rate >1% → immediate rollback
- **Performance**: Native slower than Python on 3 consecutive benchmarks → investigate, potentially rollback

---

## Success Criteria Summary

### Sprint-Level Gates (Block next sprint if fail)
- **Sprint 1**: Correlator parity 100%, ≥2× speedup on simdjson
- **Sprint 2**: Loader parity 100%, ≥3× speedup YAML, ≥2× speedup LLVM cov, ≥20% memory reduction
- **Sprint 3**: Plugin parity 100%, ≥3× speedup OptimalTargets, ≥2× inter-plugin parallelism
- **Sprint 4**: All metrics pass (primary + secondary), 10 consecutive cgserver runs stable

### Graduation Gate (Enable by default)
- **All Primary Metrics** (see Success Metrics section): ≥5× speedup (simdjson), ≥4× speedup (cgserver), ≥40% memory reduction (simdjson), ≥35% memory reduction (cgserver), 100% parity, 0 failures in 10 runs
- **Secondary Metrics**: ≥70% CPU utilization, ≤+2 min build time, ≤50MB binaries, <1% fallback rate

### Post-Graduation Monitoring (30 days)
- **Crash Rate**: <0.1% (production)
- **Fallback Rate**: <2% (production)
- **Performance Regression**: No project slower than Python baseline
- **Memory Regression**: No project using more RAM than Python baseline

---

## References

### Internal Documentation
- `docs/perf/baseline-2026-02-26.md` - Container performance baseline
- `docs/perf/native-backend-gates-2026-02-28.md` - Overlay/correlator parity validation
- `docs/perf/p2_2_process_pool_plan.md` - Process pool correlation plan (bridge solution)
- `docs/perf/debug_info_remediation_plan.md` - Debug info loading improvements
- `docs/plugin_backend_decision_matrix.md` - Plugin architecture decisions

### External Resources
- **Rust Performance Book**: https://nnethercote.github.io/perf-book/
- **Rayon (Data Parallelism)**: https://github.com/rayon-rs/rayon
- **Serde (Serialization)**: https://serde.rs/
- **OSS-Fuzz Documentation**: https://google.github.io/oss-fuzz/

### Test Projects
- **simdjson**: https://github.com/simdjson/simdjson (development testing)
- **cgserver**: (internal, validation testing)

---

## Appendix A: Rust Crate Dependencies

### Core Dependencies (All Native Components)
```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rayon = "1.7"
anyhow = "1.0"
log = "0.4"
env_logger = "0.10"
```

### Component-Specific
```toml
# native_yaml_loader_rust
serde_yaml = "0.9"
dashmap = "5.5"  # Concurrent HashMap

# native_llvm_cov_loader_rust
serde_json = { version = "1.0", features = ["raw_value"] }  # Streaming

# native_analysis_plugins_rust
petgraph = "0.6"  # Graph algorithms (call tree)
```

---

## Appendix B: Environment Variables Reference

| Variable | Default | Description | Sprint |
|----------|---------|-------------|--------|
| `FI_NATIVE_BACKENDS` | (not set; set to "rust" in production cgserver deployment) | Unified flag: `rust|go|python` | Sprint 4 |
| `FI_DEBUG_CORRELATE_NATIVE` | `false` | Correlator backend: `rust|go|python` | Sprint 1 |
| `FI_DEBUG_YAML_LOADER` | `false` | YAML loader backend: `rust|go|python` | Sprint 2 |
| `FI_LLVM_COV_LOADER` | `false` | LLVM cov loader backend: `rust|go|python` | Sprint 2 |
| `FI_NATIVE_PLUGINS` | `false` | Analysis plugins backend: `rust|go|python` | Sprint 3 |
| `FI_MAX_RSS_GB` | auto-detect | Max RSS limit (GB), triggers degradation | Sprint 4 |
| `FI_MAX_WORKERS` | `cpu_count` | Override worker count | Sprint 4 |
| `FI_MEMORY_MONITOR_INTERVAL` | `5` | RSS sampling interval (seconds) | Sprint 4 |
| `FI_DEBUG_CORRELATOR_BACKEND=cpp` | N/A | ❌ Removed — `BACKEND_CPP` constant and its entry in `SUPPORTED_BACKENDS` were deleted; setting this value produces the standard unsupported-backend warning and Python fallback. | — |

> **`FI_DEBUG_CORRELATOR_BACKEND=cpp`** — **Removed**. `BACKEND_CPP` and its `SUPPORTED_BACKENDS` entry were deleted from `backend_loaders.py`; the value is now treated as any other unsupported string (warning + Python fallback).

> ⚠️ `FI_CORR_FALLBACK_OK` was described in an earlier draft as a "deprecated alias" but was **never defined** in the codebase. Remove from any derived docs or scripts.

---

## Appendix C: Timeline Gantt Chart

```
Sprint 0: Setup & Baseline
  Week 1  [████████████████████]
  - Testing infrastructure
  - Build toolchain
  - Baseline capture

Sprint 1: Parallel Debug Correlation
  Week 2  [████████████████████]
  Week 3  [████████████████████]
  - Rust correlator
  - Python integration
  - Parity tests

Sprint 2: Parallel YAML + LLVM Loading
  Week 4  [████████████████████]
  Week 5  [████████████████████]
  - Rust YAML loader
  - Rust LLVM cov loader
  - Parity tests

Sprint 3: Parallel Analysis Plugins
  Week 6  [████████████████████]
  Week 7  [████████████████████]
  Week 8  [████████████████████]
  - Rust plugin framework
  - Migrate 3 plugins
  - Parity tests

Sprint 4: End-to-End + Graduation
  Week 9  [████████████████████]
  Week 10 [████████████████████]
  Week 11 [████████████████████]
  - Unified pipeline
  - Memory-adaptive runtime
  - cgserver validation
  - Graduation decision

Total: 11 weeks (March 3 - May 16, 2026)
```

---

## Appendix D: Graduation Decision Template

**Document**: `docs/perf/native_migration_graduation_2026-05.md`

**Structure**:
```markdown
# Native Migration Graduation Decision - May 2026

## Executive Summary
[Go/No-Go decision with 1-paragraph rationale]

## Metrics Summary

### Primary Metrics
| Metric | Target | Achieved | Pass/Fail |
|--------|--------|----------|-----------|
| Speedup (simdjson) | ≥5× | X.XXx | Pass/Fail |
| Speedup (cgserver) | ≥4× | X.XXx | Pass/Fail |
| Memory Reduction (simdjson) | ≥40% | XX% | Pass/Fail |
| Memory Reduction (cgserver) | ≥35% | XX% | Pass/Fail |
| Output Parity | 100% | XX% | Pass/Fail |
| Stability | 0 failures | X failures | Pass/Fail |

### Secondary Metrics
[Table similar to above]

## Evidence
- Baseline: `.work/baselines/`
- Sprint results: `.work/benchmarks/*/results/sprint*/`
- Parity tests: CI logs from `test-native-*` jobs

## Decision
- **Graduation**: Yes/No
- **Rationale**: [Detailed explanation]
- **Rollout Plan**: [If Yes: timeline to enable by default]
- **Next Steps**: [If No: what needs improvement]

## Lessons Learned
[What worked, what didn't, what to improve in future migrations]
```

---

*End of Document*
