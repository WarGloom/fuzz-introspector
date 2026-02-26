# Debug Loader Benchmarks

This directory contains research harnesses for `research/native-loader-eval`
Phase 1/2:

- `run_debug_loader_bench.py`: microbenchmarks debug YAML loading through
  existing loader code (`fuzz_introspector.debug_info.load_debug_all_yaml_files`).
- `collect_report_metrics.sh`: extracts debug-load timing and shard cadence
  metrics from a report log.

All artifacts are written under `benchmarks/results/` by default.

## Prerequisites

Run from repository root. Use one of:

- installed package (`cd src && pip install -e .`)
- or direct source import (the benchmark script adds `src/` to `sys.path`)

## 1) Microbenchmark debug YAML loader

### Target-dir discovery mode

```bash
python3 benchmarks/run_debug_loader_bench.py \
  --target-dir /path/to/introspector-artifacts \
  --dataset both \
  --mode all \
  --iterations 5 \
  --warmup 1 \
  --max-workers 8 \
  --process-workers 4 \
  --shard-files 4
```

### Explicit file mode

```bash
python3 benchmarks/run_debug_loader_bench.py \
  --input-file /path/to/one.debug_all_types \
  --input-file /path/to/two.debug_all_types \
  --mode process \
  --iterations 3 \
  --output-prefix manual_debug_types
```

### Output artifacts

For prefix `debug_loader_bench_<timestamp>`:

- `benchmarks/results/debug_loader_bench_<timestamp>_runs.csv`
- `benchmarks/results/debug_loader_bench_<timestamp>_runs.json`

### `*_runs.csv` schema

| Column | Meaning |
| --- | --- |
| `started_utc` | Run start timestamp (UTC ISO-8601). |
| `dataset` | `types`, `functions`, or `custom`. |
| `mode` | `serial`, `thread`, or `process`. |
| `iteration` | Measured run index (1-based). |
| `file_count` | Number of debug YAML files passed to loader. |
| `item_count` | Number of parsed items returned by loader. |
| `wall_time_sec` | End-to-end load wall time (seconds). |
| `rss_before_mb` | Best-effort RSS snapshot before run (`/proc/self/statm`). |
| `rss_after_mb` | Best-effort RSS snapshot after run (`/proc/self/statm`). |
| `rss_delta_mb` | `rss_after_mb - rss_before_mb` when both are available. |
| `maxrss_before_mb` | Best-effort process max RSS snapshot before run. |
| `maxrss_after_mb` | Best-effort process max RSS snapshot after run. |
| `status` | `ok` or `error`. |
| `error` | Exception text when `status=error`. |
| `shard_files` | Effective `FI_DEBUG_SHARD_FILES`. |
| `max_workers` | Effective `FI_DEBUG_MAX_WORKERS`. |
| `process_workers` | Effective `FI_DEBUG_PROCESS_WORKERS`. |
| `max_inflight_shards` | Effective `FI_DEBUG_MAX_INFLIGHT_SHARDS` (0 = unset). |
| `shard_strategy` | Effective `FI_DEBUG_SHARD_STRATEGY`. |

### `*_runs.json` schema

Top-level keys:

- `created_utc`: artifact creation timestamp
- `script`: absolute path of the benchmark script
- `datasets`: dataset-to-file-list mapping used for the run
- `modes`: executed mode sequence
- `config`: harness settings (iterations, warmup, worker/shard knobs)
- `records`: per-run records (same fields as CSV)
- `summary`: grouped stats by `dataset:mode`

## 2) Collect report log metrics

Run report and capture a log:

```bash
python3 src/main.py report --target-dir /path/to/introspector-artifacts \
  --language c-cpp 2>&1 | tee /tmp/fuzz_report.log
```

Extract metrics:

```bash
benchmarks/collect_report_metrics.sh /tmp/fuzz_report.log
```

Optional output directory:

```bash
benchmarks/collect_report_metrics.sh /tmp/fuzz_report.log \
  benchmarks/results/manual_report_metrics
```

### Collector outputs

- `debug_load_stages.csv`
- `shard_progress_cadence.csv`
- `summary.md`

### `debug_load_stages.csv` schema

| Column | Meaning |
| --- | --- |
| `line_no` | Log line number in source file. |
| `timestamp` | Parsed log timestamp if present. |
| `stage` | Stage name from `[debug-load] stage=<name>`. |
| `elapsed_sec` | Stage elapsed seconds. |
| `files` | Files count when emitted by stage log. |
| `types` | Type item count when emitted by stage log. |
| `functions` | Function item count when emitted by stage log. |
| `rss_mb` | Stage RSS metric when emitted by stage log. |

### `shard_progress_cadence.csv` schema

| Column | Meaning |
| --- | --- |
| `line_no` | Log line number in source file. |
| `timestamp` | Parsed log timestamp if present. |
| `category` | Loader category from `Shard load progress for <category>`. |
| `loaded` | Current loaded shard count. |
| `total` | Total shard count. |
| `delta_since_prev_sec` | Delta from previous progress event for same category. |

## 3) Native loader parity flow (Rust vs Python)

Build the Rust native loader:

```bash
RUST_LOADER_DIR=/path/to/native-debug-loader-rs
cargo build --release --manifest-path "${RUST_LOADER_DIR}/Cargo.toml"
RUST_LOADER_CMD="${RUST_LOADER_DIR}/target/release/<native-loader-binary>"
```

`FI_DEBUG_NATIVE_LOADER_CMD` should point to a command that prints the report
JSON payload to stdout (fuzz-introspector appends debug file paths).

Generate baseline and native reports in separate output folders:

```bash
REPO_ROOT="$(pwd)"
TARGET_DIR=/path/to/introspector-artifacts
PARITY_ROOT=/tmp/fi-native-loader-parity
mkdir -p "${PARITY_ROOT}/python" "${PARITY_ROOT}/rust"

(
  cd "${PARITY_ROOT}/python" && \
  python3 "${REPO_ROOT}/src/main.py" report \
    --target-dir "${TARGET_DIR}" \
    --language c-cpp
)

(
  cd "${PARITY_ROOT}/rust" && \
  FI_DEBUG_NATIVE_LOADER=rust \
  FI_DEBUG_NATIVE_LOADER_CMD="${RUST_LOADER_CMD}" \
  python3 "${REPO_ROOT}/src/main.py" report \
    --target-dir "${TARGET_DIR}" \
    --language c-cpp
)
```

Run semantic parity check with the existing equivalence script:

```bash
python3 "${REPO_ROOT}/scripts/check_report_equivalence.py" \
  "${PARITY_ROOT}/python" \
  "${PARITY_ROOT}/rust" \
  --ignore-report-date \
  --markdown-report benchmarks/results/native_loader_equivalence.md
```

If only list ordering differs, re-run with targeted list normalization:

```bash
python3 "${REPO_ROOT}/scripts/check_report_equivalence.py" \
  "${PARITY_ROOT}/python" \
  "${PARITY_ROOT}/rust" \
  --ignore-report-date \
  --sort-lists-at all_functions.js:$ \
  --markdown-report benchmarks/results/native_loader_equivalence.md
```

## 4) Native loader parity flow (Go vs Python)

Build the Go native loader:

```bash
GO_LOADER_DIR=/tmp/fuzz-introspector-research/tools/native_debug_loader_go
go build -C "${GO_LOADER_DIR}"
GO_LOADER_CMD="${GO_LOADER_DIR}/native_debug_loader_go"
```

Run native report generation:

```bash
PARITY_ROOT=/tmp/fi-native-loader-go-parity
mkdir -p "${PARITY_ROOT}/python" "${PARITY_ROOT}/go"

(
  cd "${PARITY_ROOT}/python" && \
  python3 "${REPO_ROOT}/src/main.py" report \
    --target-dir "${TARGET_DIR}" \
    --language c-cpp
)

(
  cd "${PARITY_ROOT}/go" && \
  FI_DEBUG_NATIVE_LOADER=go \
  FI_DEBUG_NATIVE_LOADER_CMD="${GO_LOADER_CMD}" \
  python3 "${REPO_ROOT}/src/main.py" report \
    --target-dir "${TARGET_DIR}" \
    --language c-cpp
)
```

Compare outputs:

```bash
python3 "${REPO_ROOT}/scripts/check_report_equivalence.py" \
  "${PARITY_ROOT}/python" \
  "${PARITY_ROOT}/go" \
  --ignore-report-date \
  --markdown-report benchmarks/results/native_loader_go_equivalence.md
```
