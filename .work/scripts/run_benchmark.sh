#!/usr/bin/env bash
# Benchmark runner for fuzz-introspector performance testing.
# Usage: run_benchmark.sh [--backend python|rust|go] [--output <path>] [--runs N] [--clean]
# Example: .work/scripts/run_benchmark.sh --backend python --output .work/baselines/cgserver-full_baseline.json --runs 3
#
# Data source: defaults to /home/nikita/work/Projects/cg/cgserver/build-introspector-full-2/introspector/
# Override with: FI_BENCH_DATA_DIR=/path/to/introspector .work/scripts/run_benchmark.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${REPO_ROOT}/.venv/bin/python"

DATA_DIR="${FI_BENCH_DATA_DIR:-/home/nikita/work/Projects/cg/cgserver/build-introspector-full-2/introspector/}"
PROJECT="cgserver-full"
BACKEND="python"
RUNS=1
OUTPUT=""
CLEAN=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--backend)
		BACKEND="$2"
		shift 2
		;;
	--output)
		OUTPUT="$2"
		shift 2
		;;
	--runs)
		RUNS="$2"
		shift 2
		;;
	--clean)
		CLEAN=1
		shift
		;;
	--keep-rundir)
		CLEAN=0
		shift
		;;
	*)
		echo "Unknown argument: $1" >&2
		exit 1
		;;
	esac
done

if [[ ! -f "$PYTHON" ]]; then
	echo "Venv python not found: $PYTHON" >&2
	echo "Run: uv venv .venv && source .venv/bin/activate && uv pip install -r requirements.txt && cd src && uv pip install -e . && cd .." >&2
	exit 1
fi

if [[ ! -d "$DATA_DIR" ]]; then
	echo "Data dir not found: $DATA_DIR" >&2
	echo "Set FI_BENCH_DATA_DIR to override." >&2
	exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT="${OUTPUT:-${REPO_ROOT}/.work/benchmarks/${PROJECT}/results/run_${TIMESTAMP}.json}"
mkdir -p "$(dirname "$OUTPUT")"
mkdir -p "${REPO_ROOT}/.work/runs"

# Set env vars based on backend
case "$BACKEND" in
rust)
	export FI_NATIVE_BACKENDS=rust
	export FI_NATIVE_PLUGINS=rust
	# Add plugin binary dir to PATH so NativePluginProxy.find_binary() can find it
	PLUGIN_BIN_DIR="${REPO_ROOT}/tools/native_analysis_plugins_rust/target/release"
	export PATH="${PLUGIN_BIN_DIR}:${PATH}"
	# Set explicit binary paths for each Rust backend component
	export FI_PROFILE_YAML_LOADER_RUST_BIN="${REPO_ROOT}/tools/native_yaml_loader_rust/target/release/native_yaml_loader_rust"
	export FI_DEBUG_YAML_LOADER_RUST_BIN="${REPO_ROOT}/tools/native_yaml_loader_rust/target/release/native_yaml_loader_rust"
	export FI_LLVM_COV_LOADER_RUST_BIN="${REPO_ROOT}/tools/native_llvm_cov_loader_rust/target/release/native_llvm_cov_loader_rust"
	export FI_DEBUG_CORRELATOR_RUST_BIN="${REPO_ROOT}/tools/native_debug_correlator_rust/target/release/native_debug_correlator_rust"
	# Reachability transitive-closure binary
	export FI_REACHABILITY_BACKEND=rust
	export FI_REACHABILITY_RUST_BIN="${REPO_ROOT}/tools/native_reachability_rust/target/release/native_reachability_rust"
	;;
go)
	export FI_NATIVE_BACKENDS=go
	export FI_NATIVE_PLUGINS=rust
	# Add plugin binary dir to PATH so NativePluginProxy.find_binary() can find it
	PLUGIN_BIN_DIR="${REPO_ROOT}/tools/native_analysis_plugins_rust/target/release"
	export PATH="${PLUGIN_BIN_DIR}:${PATH}"
	# Go binaries for all four loaders
	export FI_PROFILE_YAML_LOADER_GO_BIN="${REPO_ROOT}/tools/native_yaml_loader_go/native_yaml_loader_go"
	export FI_DEBUG_YAML_LOADER_GO_BIN="${REPO_ROOT}/tools/native_yaml_loader_go/native_yaml_loader_go"
	export FI_LLVM_COV_LOADER_GO_BIN="${REPO_ROOT}/tools/native_llvm_cov_loader_go/native_llvm_cov_loader_go"
	export FI_DEBUG_CORRELATOR_GO_BIN="${REPO_ROOT}/tools/native_debug_correlator_go/native_debug_correlator_go"
	export FI_OVERLAY_BACKEND=native
	export FI_OVERLAY_BIN="${REPO_ROOT}/tools/native_overlay_backend_go/native_overlay_backend_go"
	;;
python)
	unset FI_NATIVE_BACKENDS FI_DEBUG_CORRELATE_NATIVE FI_DEBUG_YAML_LOADER FI_NATIVE_PLUGINS 2>/dev/null || true
	# FI_LLVM_COV_LOADER defaults to rust inside code_coverage.py even when
	# FI_NATIVE_BACKENDS is unset; force python explicitly to suppress spurious
	# "No command configured for backend rust" warnings.
	export FI_LLVM_COV_LOADER=python
	;;
*)
	echo "Unknown backend: $BACKEND (use python, rust, or go)" >&2
	exit 1
	;;
esac

TOTAL_WALL=0
TOTAL_RSS=0
LAST_HASH=""

for i in $(seq 1 "$RUNS"); do
	echo "Run $i/$RUNS (backend=$BACKEND, project=$PROJECT)..."

	RUNDIR="${REPO_ROOT}/.work/runs/${PROJECT}_${TIMESTAMP}_${BACKEND}_run${i}"
	mkdir -p "$RUNDIR"
	TIMELOG="${RUNDIR}/time.log"

	# cd into RUNDIR so all fuzz-introspector output lands there, not repo root
	(
		cd "$RUNDIR"
		/usr/bin/time -v "$PYTHON" -m fuzz_introspector.cli report \
			--target-dir "$DATA_DIR" 2>"$TIMELOG" || true
	)

	WALL=$(grep "Elapsed (wall clock)" "$TIMELOG" | awk '{print $NF}' | awk -F: '{if(NF==3) print $1*3600+$2*60+$3; else print $1*60+$2}')
	RSS=$(grep "Maximum resident set size" "$TIMELOG" | awk '{print $NF/1024}') # kB to MB

	if [[ -f "${RUNDIR}/summary.json" ]]; then
		HASH=$(sha256sum "${RUNDIR}/summary.json" | awk '{print $1}')
	else
		HASH="N/A"
	fi

	echo "  Wall: ${WALL}s  RSS: ${RSS}MB  Hash: ${HASH}"

	TOTAL_WALL=$(echo "$TOTAL_WALL + $WALL" | bc)
	TOTAL_RSS=$(echo "$TOTAL_RSS + $RSS" | bc)
	LAST_HASH="$HASH"

	if [[ "$CLEAN" -eq 1 ]]; then
		rm -rf "$RUNDIR"
		echo "  Cleaned up: $RUNDIR"
	else
		echo "  Run dir: $RUNDIR"
	fi
done

AVG_WALL=$(echo "scale=2; $TOTAL_WALL / $RUNS" | bc)
AVG_RSS=$(echo "scale=2; $TOTAL_RSS / $RUNS" | bc)

# Write output from REPO_ROOT so relative paths resolve correctly
cd "$REPO_ROOT"

cat >"$OUTPUT" <<JSON
{
  "project": "$PROJECT",
  "backend": "$BACKEND",
  "runs": $RUNS,
  "wall_time_s": $AVG_WALL,
  "peak_rss_mb": $AVG_RSS,
  "output_hash": "$LAST_HASH",
  "timestamp": "$TIMESTAMP",
  "data_dir": "$DATA_DIR"
}
JSON

echo "Results written to: $OUTPUT"
echo "Wall time: ${AVG_WALL}s, Peak RSS: ${AVG_RSS}MB, Hash: $LAST_HASH"
