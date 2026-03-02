# Performance Testing Infrastructure

*Created: March 2, 2026*  
*Related: `native_migration_plan_2026-03.md`*

## Overview

This document describes the testing infrastructure for performance benchmarking and validation during the native migration project (March-May 2026). The infrastructure supports:

- **Baseline Capture**: Record Python baseline performance for comparison
- **Sprint Validation**: Measure native backend performance improvements per sprint
- **Parity Verification**: Ensure output correctness (Python vs Rust/Go)
- **Regression Detection**: Alert on performance or memory regressions
- **Graduation Testing**: Real-world validation on large projects

---

## Directory Structure

All testing artifacts live in `.work/` (excluded from git via `.gitignore`).

```
.work/
├── benchmarks/                     # Benchmark execution and results
│   ├── simdjson/                  # Small test project (development)
│   │   ├── build/                 # OSS-Fuzz build artifacts
│   │   │   ├── coverage/         # LLVM coverage JSON files
│   │   │   ├── fuzz-*.yaml       # Debug info YAML files
│   │   │   └── inspector/        # Introspector metadata
│   │   ├── corpus/                # Optional: fuzzer corpus for completeness
│   │   ├── results/               # Benchmark results per run
│   │   │   ├── baseline/
│   │   │   │   ├── run1.json
│   │   │   │   ├── run2.json
│   │   │   │   ├── run3.json
│   │   │   │   └── summary.json  # Median + p95 aggregation
│   │   │   ├── sprint1/           # Native correlator
│   │   │   │   ├── run1.json
│   │   │   │   ├── run2.json
│   │   │   │   ├── run3.json
│   │   │   │   └── summary.json
│   │   │   ├── sprint2/           # Native YAML + LLVM loaders
│   │   │   ├── sprint3/           # Native analysis plugins
│   │   │   └── sprint4/           # Unified native pipeline
│   │   └── config.json            # Project-specific config
│   └── cgserver/                  # Real-world validation project
│       ├── build/
│       ├── results/
│       │   ├── baseline/
│       │   └── sprint<N>/
│       └── config.json
├── baselines/                      # Canonical baseline files (Sprint 0)
│   ├── simdjson_baseline.json     # Captured from baseline/summary.json
│   └── cgserver_baseline.json
└── scripts/                        # Automation scripts
    ├── run_benchmark.sh           # Main benchmark runner
    ├── compare_results.py         # Compare two result sets
    ├── report_sprint_metrics.py  # Generate sprint summary
    └── validate_parity.py         # JSON diff for parity checks
```

---

## Benchmark Metrics

Each benchmark run captures the following metrics:

### Performance Metrics

| Metric | Unit | Measurement Method | Purpose |
|--------|------|-------------------|---------|
| **Wall Time** | seconds | `time.perf_counter()` (Python) or `/usr/bin/time -f '%e'` | End-to-end speed |
| **User Time** | seconds | `/usr/bin/time -f '%U'` | CPU time in user space |
| **System Time** | seconds | `/usr/bin/time -f '%S'` | CPU time in kernel space |
| **Peak RSS** | MB | `/usr/bin/time -f '%M'` (KB) → MB or `psutil.Process().memory_info().rss` | Max memory usage |
| **CPU Utilization** | % | `psutil.cpu_percent(interval=1)` sampled every 1s during run | Multi-core efficiency |

### Correctness Metrics

| Metric | Type | Measurement Method | Purpose |
|--------|------|-------------------|---------|
| **Output Hash** | SHA256 | Canonical JSON hash (sorted keys, no timestamps) | Detect output drift |
| **Function Count** | int | Count of `debug_all_functions` list | Sanity check |
| **Type Count** | int | Count of `debug_type_dictionary` keys | Sanity check |
| **Coverage Count** | int | Count of coverage entries | Sanity check |
| **Parity Status** | bool | `output_hash == baseline_hash` | Pass/fail correctness |

### Observability Metrics

| Metric | Type | Measurement Method | Purpose |
|--------|------|-------------------|---------|
| **Backend Used** | enum | Extract from logs: `[native-backend] Using rust` | Confirm backend selection |
| **Fallback Events** | int | Count log lines: `falling back to Python` | Detect native failures |
| **Phase Timings** | dict | Extract from logs: `[debug-load] elapsed=X.XXs` | Identify bottlenecks |
| **Worker Count** | int | Extract from logs: `workers=N` | Confirm parallelism |
| **Memory Mode** | enum | Extract from logs: `Mode: Full Parallel|Reduced|Serial` | Confirm adaptive scaling |

---

## Result File Format

Each benchmark run produces a JSON file with the following schema:

```json
{
  "metadata": {
    "timestamp": "2026-03-03T10:15:30Z",
    "project": "simdjson",
    "backend": "rust",
    "sprint": "sprint1",
    "run_id": "run1",
    "hostname": "dev-machine",
    "fuzz_introspector_commit": "abc123def456",
    "native_binary_version": "0.1.0"
  },
  "config": {
    "env_vars": {
      "FI_NATIVE_BACKENDS": "rust",
      "FI_DEBUG_CORRELATE_NATIVE": "rust",
      "FI_MAX_RSS_GB": "auto",
      "FI_MAX_WORKERS": "12"
    },
    "cli_args": [
      "report",
      "--target-dir", ".work/benchmarks/simdjson/build/inspector",
      "--analyses", "OptimalTargets,RuntimeCoverageAnalysis"
    ]
  },
  "performance": {
    "wall_time_seconds": 12.345,
    "user_time_seconds": 45.678,
    "system_time_seconds": 2.345,
    "peak_rss_mb": 456.78,
    "cpu_utilization_percent": 72.3
  },
  "correctness": {
    "output_hash": "sha256:abc123...",
    "function_count": 5042,
    "type_count": 1234,
    "coverage_count": 4567,
    "parity_status": true
  },
  "observability": {
    "backend_used": "rust",
    "fallback_events": 0,
    "phase_timings": {
      "yaml_load": 1.234,
      "llvm_cov_load": 2.345,
      "type_correlation": 3.456,
      "overlay_computation": 2.345,
      "analysis_plugins": 1.234,
      "html_generation": 1.731
    },
    "worker_count": 12,
    "memory_mode": "Full Parallel"
  },
  "logs": {
    "stdout_file": ".work/benchmarks/simdjson/results/sprint1/run1.stdout",
    "stderr_file": ".work/benchmarks/simdjson/results/sprint1/run1.stderr"
  }
}
```

---

## Benchmark Runner Script

**Location**: `.work/scripts/run_benchmark.sh`

### Usage

```bash
# Capture baseline (Sprint 0)
.work/scripts/run_benchmark.sh simdjson --backend python --output .work/baselines/simdjson_baseline.json

# Sprint 1: Test native correlator (single run)
.work/scripts/run_benchmark.sh simdjson --backend rust --output .work/benchmarks/simdjson/results/sprint1/run1.json

# Sprint 1: Multiple runs for statistical confidence
.work/scripts/run_benchmark.sh simdjson --backend rust --runs 5 --output-dir .work/benchmarks/simdjson/results/sprint1/

# Validation: cgserver (10 runs, Sprint 4)
.work/scripts/run_benchmark.sh cgserver --backend rust --runs 10 --output-dir .work/benchmarks/cgserver/results/sprint4/
```

### Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `<project>` | Yes | - | Project name: `simdjson` or `cgserver` |
| `--backend <python\|rust\|go>` | Yes | - | Backend to test |
| `--output <file>` | No | stdout | Single run: output JSON file path |
| `--output-dir <dir>` | No | - | Multiple runs: directory for `run1.json`, `run2.json`, etc. |
| `--runs <N>` | No | 1 | Number of benchmark runs |
| `--analyses <list>` | No | All | Comma-separated analysis plugins to run |
| `--skip-html` | No | false | Skip HTML report generation (faster) |
| `--env-file <file>` | No | - | Source additional env vars from file |

### Example Output (stdout)

```
[run_benchmark.sh] Project: simdjson, Backend: rust, Runs: 3
[run_benchmark.sh] Config: .work/benchmarks/simdjson/config.json
[run_benchmark.sh] Output dir: .work/benchmarks/simdjson/results/sprint1/

[run_benchmark.sh] Run 1/3...
  [+] Wall time: 12.34s, Peak RSS: 456MB, CPU: 72%
  [+] Output hash: sha256:abc123...
  [+] Parity: PASS (matches baseline)
  [+] Written: .work/benchmarks/simdjson/results/sprint1/run1.json

[run_benchmark.sh] Run 2/3...
  [+] Wall time: 12.45s, Peak RSS: 458MB, CPU: 71%
  [+] Output hash: sha256:abc123...
  [+] Parity: PASS (matches baseline)
  [+] Written: .work/benchmarks/simdjson/results/sprint1/run2.json

[run_benchmark.sh] Run 3/3...
  [+] Wall time: 12.38s, Peak RSS: 457MB, CPU: 73%
  [+] Output hash: sha256:abc123...
  [+] Parity: PASS (matches baseline)
  [+] Written: .work/benchmarks/simdjson/results/sprint1/run3.json

[run_benchmark.sh] Summary:
  Wall time: median=12.38s, p95=12.45s
  Peak RSS: median=457MB, p95=458MB
  CPU: median=72%, p95=73%
  Parity: 3/3 PASS
  Written: .work/benchmarks/simdjson/results/sprint1/summary.json
```

---

## Results Comparison Tool

**Location**: `.work/scripts/compare_results.py`

### Usage

```bash
# Compare Sprint 1 vs Baseline
.work/scripts/compare_results.py \
  .work/baselines/simdjson_baseline.json \
  .work/benchmarks/simdjson/results/sprint1/summary.json

# Compare two specific runs
.work/scripts/compare_results.py \
  .work/benchmarks/simdjson/results/baseline/run1.json \
  .work/benchmarks/simdjson/results/sprint1/run1.json

# Generate report for all sprints
.work/scripts/compare_results.py \
  --baseline .work/baselines/simdjson_baseline.json \
  --sprint1 .work/benchmarks/simdjson/results/sprint1/summary.json \
  --sprint2 .work/benchmarks/simdjson/results/sprint2/summary.json \
  --sprint3 .work/benchmarks/simdjson/results/sprint3/summary.json \
  --sprint4 .work/benchmarks/simdjson/results/sprint4/summary.json \
  --output docs/perf/sprint_comparison_report.md
```

### Example Output

```
=== Benchmark Comparison: simdjson ===

Baseline: .work/baselines/simdjson_baseline.json
  Backend: python
  Wall time: 60.12s
  Peak RSS: 812MB
  CPU: 23%
  Output hash: sha256:abc123...

Sprint 1: .work/benchmarks/simdjson/results/sprint1/summary.json
  Backend: rust (correlator only)
  Wall time: 32.45s (1.85× faster)
  Peak RSS: 798MB (1.7% reduction)
  CPU: 68%
  Output hash: sha256:abc123... (MATCH)
  Parity: PASS

Sprint 1 vs Baseline:
  ✓ Speedup: 1.85× (target: ≥2×) - NEEDS IMPROVEMENT
  ✓ Memory: -1.7% (target: no regression) - PASS
  ✓ CPU utilization: +45% (better parallelism) - PASS
  ✓ Parity: PASS

Phase-level breakdown:
  | Phase              | Baseline | Sprint 1 | Delta   | Note                      |
  |--------------------|----------|----------|---------|---------------------------|
  | yaml_load          | 8.23s    | 8.20s    | -0.4%   | Not migrated yet          |
  | llvm_cov_load      | 12.34s   | 12.30s   | -0.3%   | Not migrated yet          |
  | type_correlation   | 24.56s   | 7.12s    | -71.0%  | ✓ Native correlator wins  |
  | overlay_computation| 10.12s   | 10.10s   | -0.2%   | Not migrated yet          |
  | analysis_plugins   | 3.45s    | 3.40s    | -1.4%   | Not migrated yet          |
  | html_generation    | 1.42s    | 1.43s    | +0.7%   | Not migrated yet          |
```

---

## Parity Validation Tool

**Location**: `.work/scripts/validate_parity.py`

### Purpose

Verify output correctness by comparing JSON outputs from Python and native backends.

### Usage

```bash
# Compare two output files
.work/scripts/validate_parity.py \
  --baseline .work/benchmarks/simdjson/results/baseline/run1.json \
  --candidate .work/benchmarks/simdjson/results/sprint1/run1.json

# Detailed diff (show differences)
.work/scripts/validate_parity.py \
  --baseline baseline_output.json \
  --candidate native_output.json \
  --show-diff

# Ignore timestamp fields
.work/scripts/validate_parity.py \
  --baseline baseline_output.json \
  --candidate native_output.json \
  --ignore-fields timestamp,generated_at,runtime_seconds
```

### Example Output

```
[validate_parity.py] Comparing outputs...

Structure:
  ✓ Both files valid JSON
  ✓ Root keys match: ['project', 'functions', 'coverage', 'analyses', 'metadata']

Metadata:
  ✓ function_count: 5042 == 5042
  ✓ type_count: 1234 == 1234
  ✓ coverage_count: 4567 == 4567
  ~ timestamp: '2026-03-03T10:15:30Z' != '2026-03-03T10:16:42Z' (IGNORED)

Functions:
  ✓ Count: 5042 == 5042
  ✓ Function names (sorted): MATCH
  ✓ Signature elements: MATCH (checked 5042 functions)
  ✓ Source locations: MATCH (checked 5042 functions)

Coverage:
  ✓ Count: 4567 == 4567
  ✓ Coverage map (sorted): MATCH

Analyses:
  ✓ OptimalTargets table: MATCH (124 rows, 8 columns)
  ✓ RuntimeCoverageAnalysis table: MATCH (87 rows, 6 columns)

Parity: PASS
Hash (canonical, no timestamps):
  Baseline: sha256:abc123def456...
  Candidate: sha256:abc123def456... (MATCH)
```

---

## Sprint Metrics Report Generator

**Location**: `.work/scripts/report_sprint_metrics.py`

### Purpose

Generate a summary report for sprint reviews and graduation decision.

### Usage

```bash
# Generate report for Sprint 1
.work/scripts/report_sprint_metrics.py \
  --project simdjson \
  --sprint 1 \
  --baseline .work/baselines/simdjson_baseline.json \
  --output docs/perf/sprint1_metrics_report.md

# Generate graduation report (all sprints)
.work/scripts/report_sprint_metrics.py \
  --project simdjson \
  --sprint all \
  --baseline .work/baselines/simdjson_baseline.json \
  --output docs/perf/native_migration_graduation_2026-05.md
```

### Example Output (Sprint 1 Report)

```markdown
# Sprint 1 Metrics Report: Native Debug Correlator
*Project: simdjson*  
*Sprint: 1 (March 10-21, 2026)*

## Objectives
- Migrate debug type correlation to Rust
- Achieve ≥2× speedup on correlation phase
- Maintain 100% output parity

## Results

### Performance Metrics

| Metric | Baseline | Sprint 1 | Delta | Target | Status |
|--------|----------|----------|-------|--------|--------|
| Wall time (total) | 60.12s | 32.45s | **-46.0%** (1.85×) | ≥2× | ⚠️ NEEDS IMPROVEMENT |
| Wall time (correlation) | 24.56s | 7.12s | **-71.0%** (3.45×) | ≥2× | ✅ PASS |
| Peak RSS | 812MB | 798MB | -1.7% | No regression | ✅ PASS |
| CPU utilization | 23% | 68% | +45% | ≥50% | ✅ PASS |

### Correctness Metrics

| Metric | Status | Notes |
|--------|--------|-------|
| Output parity | ✅ PASS | 100% match (5/5 runs) |
| Function count | ✅ PASS | 5042 == 5042 |
| Signature elements | ✅ PASS | All 5042 functions identical |
| Source locations | ✅ PASS | All 5042 functions identical |

### Observability

| Metric | Value | Notes |
|--------|-------|-------|
| Backend used | rust | Confirmed via logs |
| Fallback events | 0 | No fallbacks in 5 runs |
| Worker count | 12 | Full parallelism |
| Memory mode | Full Parallel | No pressure detected |

## Analysis

**Correlation Phase**: Exceeded target with 3.45× speedup (target ≥2×). Rust parallelism (Rayon) + zero-cost abstractions eliminated Python GIL bottleneck.

**End-to-End**: Below target at 1.85× (target ≥2×). Other phases (YAML load, LLVM cov load, overlay) remain Python bottlenecks. Expected; these phases addressed in Sprint 2.

**Parity**: Clean. Zero drift across 5 runs. Correlator logic faithfully ported.

**Memory**: Slight reduction (-1.7%). Not Sprint 1 focus; expect larger reduction in Sprint 2 (streaming loaders).

## Decision

**Sprint 1 Gate: PASS** (with caveat)

- Correlation phase target met (3.45× > 2×)
- Parity 100%
- End-to-end below target, but expected (other phases not migrated yet)

**Recommendation**: Proceed to Sprint 2 (YAML + LLVM loaders). Expect end-to-end speedup to reach 3-4× after Sprint 2.

## Next Steps (Sprint 2)

- Migrate YAML loader to Rust (target: ≥3× speedup)
- Migrate LLVM cov loader to Rust (target: ≥2× speedup)
- Target cumulative speedup: ≥3× end-to-end
```

---

## Project Configuration Files

Each benchmark project has a `config.json` describing its setup.

### Example: `.work/benchmarks/simdjson/config.json`

```json
{
  "project_name": "simdjson",
  "language": "cpp",
  "function_count": 5042,
  "oss_fuzz_url": "https://github.com/google/oss-fuzz/tree/master/projects/simdjson",
  "github_url": "https://github.com/simdjson/simdjson",
  "build": {
    "command": "python /tmp/oss-fuzz/infra/helper.py build_fuzzers simdjson",
    "time_seconds": 120,
    "output_dir": "/tmp/oss-fuzz/build/out/simdjson"
  },
  "introspector": {
    "target_dir": ".work/benchmarks/simdjson/build/inspector",
    "analyses": ["OptimalTargets", "RuntimeCoverageAnalysis", "FuzzCalltreeAnalysis"],
    "skip_html": true
  },
  "baseline": {
    "file": ".work/baselines/simdjson_baseline.json",
    "captured_at": "2026-03-03T10:00:00Z",
    "backend": "python",
    "commit": "abc123def456"
  }
}
```

---

## Continuous Integration Integration

### CI Jobs (GitHub Actions)

```yaml
# .github/workflows/native-benchmark.yml

name: Native Backend Benchmarks

on:
  pull_request:
    paths:
      - 'tools/native_*/**'
      - 'src/fuzz_introspector/debug_info.py'
      - 'src/fuzz_introspector/llvm_cov_load.py'
      - 'src/fuzz_introspector/analysis.py'
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday 2am UTC

jobs:
  build-native-components:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Build native binaries
        run: |
          cd tools/native_debug_correlator_rust && cargo build --release
          cd tools/native_yaml_loader_rust && cargo build --release
          cd tools/native_llvm_cov_loader_rust && cargo build --release
          cd tools/native_analysis_plugins_rust && cargo build --release
      - name: Upload binaries
        uses: actions/upload-artifact@v3
        with:
          name: native-binaries
          path: tools/*/target/release/native_*

  benchmark-simdjson:
    runs-on: ubuntu-latest
    needs: build-native-components
    strategy:
      matrix:
        backend: [python, rust]
    steps:
      - uses: actions/checkout@v3
      - name: Download native binaries
        if: matrix.backend == 'rust'
        uses: actions/download-artifact@v3
        with:
          name: native-binaries
          path: tools/
      - name: Setup simdjson
        run: |
          # Clone OSS-Fuzz, build simdjson
          # (Omitted for brevity; see Sprint 0 setup)
      - name: Run benchmark
        run: |
          .work/scripts/run_benchmark.sh simdjson \
            --backend ${{ matrix.backend }} \
            --runs 3 \
            --output-dir .work/benchmarks/simdjson/results/ci-${{ matrix.backend }}/
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results-${{ matrix.backend }}
          path: .work/benchmarks/simdjson/results/ci-${{ matrix.backend }}/

  compare-results:
    runs-on: ubuntu-latest
    needs: benchmark-simdjson
    steps:
      - uses: actions/checkout@v3
      - name: Download all results
        uses: actions/download-artifact@v3
      - name: Compare Python vs Rust
        run: |
          .work/scripts/compare_results.py \
            benchmark-results-python/summary.json \
            benchmark-results-rust/summary.json \
            --output benchmark-comparison.md
      - name: Post comment on PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('benchmark-comparison.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });
```

---

## Best Practices

### 1. Multiple Runs for Statistical Confidence
- Always run ≥3 iterations per configuration
- Report median (robust to outliers) and p95 (worst-case)
- Discard first run if system "warming up" (cache effects)

### 2. Parity Checks Before Performance
- Never optimize without correctness
- Always run parity validation before comparing speed
- Use canonical JSON hashing (sorted keys, ignore timestamps)

### 3. Incremental Validation
- Test each native component individually before integration
- Use small fixtures (unit tests) before large projects (integration tests)
- Keep Python fallback functional throughout migration

### 4. Documented Anomalies
- If benchmark anomalous (e.g., 10× faster than expected), investigate:
  - Caching effects (run multiple times)
  - Incomplete work (output smaller than expected)
  - Measurement error (check logs, timestamps)
- Document all anomalies in sprint reports

### 5. Reproducible Environments
- Pin OSS-Fuzz commit for project builds
- Record system specs (CPU, RAM, OS) in result metadata
- Use same machine for baseline and sprint comparisons (avoid cross-machine comparison)

---

## Troubleshooting

### Issue: Benchmark runs fail with "native binary not found"

**Cause**: Native binaries not built or not in PATH.

**Fix**:
```bash
# Build all native components
cd tools/native_debug_correlator_rust && cargo build --release
cd tools/native_yaml_loader_rust && cargo build --release
cd tools/native_llvm_cov_loader_rust && cargo build --release
cd tools/native_analysis_plugins_rust && cargo build --release

# Add to PATH
export PATH="$PWD/tools/native_debug_correlator_rust/target/release:$PATH"
export PATH="$PWD/tools/native_yaml_loader_rust/target/release:$PATH"
export PATH="$PWD/tools/native_llvm_cov_loader_rust/target/release:$PATH"
export PATH="$PWD/tools/native_analysis_plugins_rust/target/release:$PATH"
```

### Issue: Parity check fails ("output hash mismatch")

**Cause**: Native backend producing different output than Python.

**Fix**:
```bash
# Run detailed diff
.work/scripts/validate_parity.py \
  --baseline baseline_output.json \
  --candidate native_output.json \
  --show-diff

# Investigate differences (likely: ordering, float precision, timestamps)
# Ensure canonical comparison ignores non-semantic fields
```

### Issue: Benchmark slower than baseline

**Cause**: Possible reasons:
- Native binary not optimized (debug build instead of release)
- Serialization overhead (subprocess JSON I/O)
- Insufficient parallelism (worker count too low)

**Fix**:
```bash
# Verify release build
ls -lh tools/*/target/release/native_*

# Check logs for parallelism
grep "workers=" .work/benchmarks/simdjson/results/sprint1/run1.stderr

# Profile native binary (Linux perf)
perf record -g tools/native_debug_correlator_rust/target/release/native_debug_correlator_rust < input.json
perf report
```

### Issue: Out of memory during benchmark

**Cause**: Project too large for available RAM.

**Fix**:
```bash
# Enable memory limit
export FI_MAX_RSS_GB=8

# Reduce worker count
export FI_MAX_WORKERS=4

# Run benchmark again
.work/scripts/run_benchmark.sh simdjson --backend rust
```

---

## Appendix A: Script Templates

### A.1 Benchmark Runner Skeleton

**Location**: `.work/scripts/run_benchmark.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

PROJECT="$1"
BACKEND="$2"
RUNS="${3:-1}"
OUTPUT_DIR="${4:-.work/benchmarks/$PROJECT/results/}"

CONFIG=".work/benchmarks/$PROJECT/config.json"
TARGET_DIR=$(jq -r '.introspector.target_dir' "$CONFIG")
ANALYSES=$(jq -r '.introspector.analyses | join(",")' "$CONFIG")

for i in $(seq 1 "$RUNS"); do
  RUN_JSON="$OUTPUT_DIR/run$i.json"
  
  echo "[run_benchmark.sh] Run $i/$RUNS..."
  
  # Run fuzz-introspector with timing
  /usr/bin/time -f 'elapsed=%e rss_kb=%M cpu=%P' -o "$OUTPUT_DIR/run$i.time" \
    python3 src/main.py report \
      --target-dir "$TARGET_DIR" \
      --analyses "$ANALYSES" \
      --skip-html-report \
    > "$OUTPUT_DIR/run$i.stdout" 2> "$OUTPUT_DIR/run$i.stderr"
  
  # Extract metrics and create JSON
  # (Implementation details omitted)
done

# Generate summary.json (median + p95)
python3 .work/scripts/summarize_runs.py "$OUTPUT_DIR" > "$OUTPUT_DIR/summary.json"
```

### A.2 Parity Validator Skeleton

**Location**: `.work/scripts/validate_parity.py`

```python
#!/usr/bin/env python3
import json, sys, hashlib

def canonical_hash(data):
    """Compute SHA256 of canonical JSON (sorted, no timestamps)"""
    if isinstance(data, dict):
        data = {k: canonical_hash(v) for k, v in sorted(data.items()) if k not in ['timestamp', 'generated_at']}
    elif isinstance(data, list):
        data = [canonical_hash(item) for item in data]
    json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(json_str.encode()).hexdigest()

baseline = json.load(open(sys.argv[1]))
candidate = json.load(open(sys.argv[2]))

baseline_hash = canonical_hash(baseline)
candidate_hash = canonical_hash(candidate)

if baseline_hash == candidate_hash:
    print("Parity: PASS")
    sys.exit(0)
else:
    print("Parity: FAIL")
    sys.exit(1)
```

---

## Appendix B: Example Baseline Capture Session

```bash
# Sprint 0: Capture simdjson baseline

# Step 1: Build simdjson in OSS-Fuzz
cd /tmp
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz
python infra/helper.py build_fuzzers simdjson

# Step 2: Copy artifacts to .work
cd /path/to/fuzz-introspector
mkdir -p .work/benchmarks/simdjson/build/inspector
cp -r /tmp/oss-fuzz/build/out/simdjson/* .work/benchmarks/simdjson/build/inspector/

# Step 3: Run baseline (Python, 3 runs)
.work/scripts/run_benchmark.sh simdjson python 3 .work/benchmarks/simdjson/results/baseline/

# Step 4: Generate summary
python3 .work/scripts/summarize_runs.py .work/benchmarks/simdjson/results/baseline/ \
  > .work/baselines/simdjson_baseline.json

# Step 5: Verify
cat .work/baselines/simdjson_baseline.json
# Expected output:
# {
#   "wall_time_seconds": 60.12,
#   "peak_rss_mb": 812,
#   "cpu_utilization_percent": 23,
#   "output_hash": "sha256:abc123...",
#   "function_count": 5042,
#   ...
# }

echo "✅ Baseline captured successfully"
```

---

*End of Document*
