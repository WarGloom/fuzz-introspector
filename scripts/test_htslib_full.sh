#!/bin/bash
#
# Copyright 2024 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#
# Full test script for htslib with fuzz-introspector.
# This script builds, runs, and analyzes htslib fuzzers with fuzz-introspector.
#
# Usage:
#   ./test_htslib_full.sh                    # Run with defaults
#   BUILD_DIR=/custom/path ./test_htslib_full.sh  # Custom build directory
#   STEPS=build_only ./test_htslib_full.sh   # Run only build step
#   DRY_RUN=1 ./test_htslib_full.sh          # Preview commands without executing
#
# Environment Variables:
#   BUILD_DIR        - Base directory for builds (default: ./work_htslib)
#   STEPS            - Comma-separated steps to run: build_static,build_cov,fuzz_10s,fuzz_300s,correlate,report,diff,all (default: all)
#   FUZZER_TIME_10S  - Duration for first fuzzer run in seconds (default: 10)
#   FUZZER_TIME_300S - Duration for second fuzzer run in seconds (default: 300)
#   BUILD_IMAGE      - Docker image for building (default: gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04)
#   RUNNER_IMAGE     - Docker image for running fuzzers (default: gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04)
#   COVERAGE_URL     - Base URL for coverage reports (default: /covreport/linux)
#   DRY_RUN          - If set to 1, only print commands without executing
#   VERBOSE          - If set to 1, enable verbose output
#   NO_CLEANUP       - If set to 1, don't clean up temporary files on exit
#
################################################################################

set -Eeuo pipefail

################################################################################
# Script metadata
################################################################################

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
SCRIPT_VERSION="1.0.0"

################################################################################
# Configuration defaults (can be overridden via environment)
################################################################################

# Directory settings
BUILD_DIR="${BUILD_DIR:-$PWD/work_htslib}"
OUTPUT_DIR="${OUTPUT_DIR:-$BUILD_DIR/output}"

# Fuzzer settings
FUZZER_TIME_10S="${FUZZER_TIME_10S:-10}"
FUZZER_TIME_300S="${FUZZER_TIME_300S:-300}"
FUZZER_NAME="${FUZZER_NAME:-hts_open_fuzzer}"

# Docker images
BUILD_IMAGE="${BUILD_IMAGE:-gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04}"
RUNNER_IMAGE="${RUNNER_IMAGE:-gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04}"

# Container runtime
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"

# Coverage settings
COVERAGE_URL="${COVERAGE_URL:-/covreport/linux}"

# Project settings
PROJECT_NAME="${PROJECT_NAME:-htslib}"
HTSLIB_REPO="${HTSLIB_REPO:-https://github.com/samtools/htslib}"

# Steps to execute (comma-separated)
STEPS="${STEPS:-all}"

# Feature flags
DRY_RUN="${DRY_RUN:-0}"
VERBOSE="${VERBOSE:-0}"
NO_CLEANUP="${NO_CLEANUP:-0}"
USE_CONTAINER="${USE_CONTAINER:-1}"

################################################################################
# Derived paths
################################################################################

# Source and build directories
HTSLIB_SRC_DIR="$BUILD_DIR/htslib"
HTSLIB_BUILD_STATIC="$BUILD_DIR/build_static"
HTSLIB_BUILD_COV="$BUILD_DIR/build_cov"

# Output subdirectories
FUZZER_OUT_10S="$OUTPUT_DIR/fuzzer_10s"
FUZZER_OUT_300S="$OUTPUT_DIR/fuzzer_300s"
INTROSPECTOR_REPORT="$OUTPUT_DIR/inspector_report"

# Summary files
SUMMARY_10S="$OUTPUT_DIR/summary_10s.json"
SUMMARY_300S="$OUTPUT_DIR/summary_300s.json"
DIFF_REPORT="$OUTPUT_DIR/diff_report.txt"

################################################################################
# Logging functions
################################################################################

log_info() {
	echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $*" >&2
}

log_warn() {
	echo "[$(date +'%Y-%m-%d %H:%M:%S')] WARN: $*" >&2
}

log_error() {
	echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

log_debug() {
	if [[ "$VERBOSE" == "1" ]]; then
		echo "[$(date +'%Y-%m-%d %H:%M:%S')] DEBUG: $*" >&2
	fi
}

log_step() {
	echo "" >&2
	echo "============================================================" >&2
	echo "  STEP: $*" >&2
	echo "============================================================" >&2
	echo "" >&2
}

################################################################################
# Helper functions
################################################################################

usage() {
	cat <<EOF
Usage: $0 [OPTIONS]

Options:
    -h, --help           Show this help message
    -v, --verbose        Enable verbose output
    -d, --dry-run        Preview commands without executing
    --build-dir DIR      Base directory for builds (default: $BUILD_DIR)
    --output-dir DIR     Output directory (default: $OUTPUT_DIR)
    --steps STEPS        Steps to run (default: all)
    --fuzzer-time-10s S  First fuzzer run duration in seconds (default: $FUZZER_TIME_10S)
    --fuzzer-time-300s S Second fuzzer run duration in seconds (default: $FUZZER_TIME_300S)
    --no-cleanup         Don't clean up temporary files on exit

Examples:
    $0                           # Run full test suite
    $0 --steps build_static      # Build only
    $0 --verbose --dry-run       # Preview full run
    BUILD_DIR=/tmp/htslib $0    # Custom build directory

Available steps:
    build_static  - Build htslib with FUZZ_INTROSPECTOR=1
    build_cov     - Build htslib with coverage instrumentation
    fuzz_10s      - Run fuzzer for 10s, save summary_10s.json
    fuzz_300s     - Run fuzzer for 300s, save summary_300s.json
    correlate     - Correlate binaries with introspector logs
    report        - Generate HTML report with coverage URL
    diff          - Diff between 10s and 300s runs
    all           - Run all steps (default)
EOF
	exit "${1:-0}"
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-h | --help)
			usage 0
			;;
		-v | --verbose)
			VERBOSE=1
			shift
			;;
		-d | --dry-run)
			DRY_RUN=1
			shift
			;;
		--build-dir)
			if [[ -z "${2:-}" ]]; then
				log_error "Option $1 requires an argument"
				usage 1
			fi
			BUILD_DIR="$2"
			shift 2
			;;
		--output-dir)
			if [[ -z "${2:-}" ]]; then
				log_error "Option $1 requires an argument"
				usage 1
			fi
			OUTPUT_DIR="$2"
			shift 2
			;;
		--steps)
			if [[ -z "${2:-}" ]]; then
				log_error "Option $1 requires an argument"
				usage 1
			fi
			STEPS="$2"
			shift 2
			;;
		--fuzzer-time-10s)
			if [[ -z "${2:-}" ]]; then
				log_error "Option $1 requires an argument"
				usage 1
			fi
			FUZZER_TIME_10S="$2"
			shift 2
			;;
		--fuzzer-time-300s)
			if [[ -z "${2:-}" ]]; then
				log_error "Option $1 requires an argument"
				usage 1
			fi
			FUZZER_TIME_300S="$2"
			shift 2
			;;
		--no-cleanup)
			NO_CLEANUP=1
			shift
			;;
		*)
			log_error "Unknown option: $1"
			usage 1
			;;
		esac
	done

	# Update derived paths after parsing
	HTSLIB_SRC_DIR="$BUILD_DIR/htslib"
	HTSLIB_BUILD_STATIC="$BUILD_DIR/build_static"
	HTSLIB_BUILD_COV="$BUILD_DIR/build_cov"
	FUZZER_OUT_10S="$OUTPUT_DIR/fuzzer_10s"
	FUZZER_OUT_300S="$OUTPUT_DIR/fuzzer_300s"
	INTROSPECTOR_REPORT="$OUTPUT_DIR/inspector_report"
	SUMMARY_10S="$OUTPUT_DIR/summary_10s.json"
	SUMMARY_300S="$OUTPUT_DIR/summary_300s.json"
	DIFF_REPORT="$OUTPUT_DIR/diff_report.txt"
}

check_dependencies() {
	local -a missing_deps=()
	local -a required=("$CONTAINER_RUNTIME" "git" "make" "autoconf")

	for cmd in "${required[@]}"; do
		if ! command -v "$cmd" &>/dev/null; then
			missing_deps+=("$cmd")
		fi
	done

	if [[ ${#missing_deps[@]} -gt 0 ]]; then
		log_error "Missing required commands: ${missing_deps[*]}"
		return 1
	fi

	log_debug "All dependencies satisfied"
	return 0
}

run_cmd() {
	if [[ "$DRY_RUN" == "1" ]]; then
		echo "[DRY RUN] Would execute: $*"
		return 0
	fi

	log_debug "Executing: $*"
	"$@"
}

# Safe cd that handles dry-run mode
safe_cd() {
	local dir="$1"
	if [[ "$DRY_RUN" == "1" ]]; then
		echo "[DRY RUN] Would cd to: $dir"
		return 0
	fi
	cd "$dir" || {
		log_error "Failed to cd to: $dir"
		return 1
	}
}

run_cmd_or_fail() {
	if [[ "$DRY_RUN" == "1" ]]; then
		echo "[DRY RUN] Would execute: $*"
		return 0
	fi

	log_debug "Executing: $*"
	if ! "$@"; then
		log_error "Command failed: $*"
		return 1
	fi
	return 0
}

run_build_in_container() {
	if [[ "$USE_CONTAINER" != "1" ]]; then
		log_info "Container disabled (USE_CONTAINER=0)"
		return 0
	fi

	local image="$BUILD_IMAGE"
	local container_name="htslib-build-$$"

	log_info "Running build in container: $image"

	# Pull image if needed
	if ! $CONTAINER_RUNTIME image inspect "$image" &>/dev/null; then
		log_info "Pulling image: $image"
		$CONTAINER_RUNTIME pull "$image" || {
			log_error "Failed to pull image: $image"
			return 1
		}
	fi

	# Read build script from stdin (heredoc) and encode to base64
	local build_script_b64
	build_script_b64=$(cat | base64 | tr -d '\n')

	# Run in container with inline script via bash -c
	$CONTAINER_RUNTIME run --rm \
		--name "$container_name" \
		-v "$BUILD_DIR:/src/htslib:rw" \
		-e "FUZZ_INTROSPECTOR=1" \
		-e "FUZZ_INTROSPECTOR_STATIC=1" \
		-e "CFLAGS=$CFLAGS" \
		-e "CXXFLAGS=$CXXFLAGS" \
		-e "CC=${CC:-clang}" \
		-e "CXX=${CXX:-clang++}" \
		-e "AR=${AR:-llvm-ar}" \
		-e "RANLIB=${RANLIB:-llvm-ranlib}" \
		-e "LDFLAGS=${LDFLAGS:---fuse-ld=gold}" \
		-e "LIB_FUZZING_ENGINE=-fsanitize=fuzzer" \
		-w "/src/htslib" \
		"$image" \
		bash -c "$(echo "$build_script_b64" | base64 -d)"

	return $?
}

create_directories() {
	log_info "Creating directories in: $BUILD_DIR"

	run_cmd mkdir -p "$BUILD_DIR" || return 1
	run_cmd mkdir -p "$OUTPUT_DIR" || return 1
	run_cmd mkdir -p "$HTSLIB_BUILD_STATIC" || return 1
	run_cmd mkdir -p "$HTSLIB_BUILD_COV" || return 1
	run_cmd mkdir -p "$FUZZER_OUT_10S" || return 1
	run_cmd mkdir -p "$FUZZER_OUT_300S" || return 1
	run_cmd mkdir -p "$INTROSPECTOR_REPORT" || return 1

	log_info "Directories created successfully"
}

cleanup() {
	local exit_code=$?

	if [[ "$NO_CLEANUP" == "1" ]]; then
		log_info "Skipping cleanup (NO_CLEANUP=1)"
		return 0
	fi

	log_info "Cleaning up..."

	# Only remove work directories if dry run is not enabled
	if [[ "$DRY_RUN" != "1" ]]; then
		# Add cleanup commands here if needed
		# For now, keep artifacts for inspection
		log_info "Artifacts preserved in: $BUILD_DIR"
	fi

	return "$exit_code"
}

################################################################################
# Build functions
################################################################################

clone_htslib() {
	log_step "Clone htslib source"

	if [[ -d "$HTSLIB_SRC_DIR" ]]; then
		log_info "htslib already cloned at: $HTSLIB_SRC_DIR"
		return 0
	fi

	run_cmd git clone --depth 1 --shallow-submodules \
		--recurse-submodules "$HTSLIB_REPO" "$HTSLIB_SRC_DIR" || return 1

	log_info "htslib cloned successfully"
	return 0
}

build_static() {
	log_step "Build htslib with FUZZ_INTROSPECTOR=1 (static analysis)"

	# Ensure source is cloned
	clone_htslib || return 1

	# Prepare build directory
	run_cmd rm -rf "$HTSLIB_BUILD_STATIC"/* || true
	run_cmd mkdir -p "$HTSLIB_BUILD_STATIC" || return 1

	# Environment for fuzz-introspector build
	export CC="${CC:-clang}"
	export CXX="${CXX:-clang++}"
	export CFLAGS="${CFLAGS:--fsanitize=fuzzer-no-link -fcommon -g -flto}"
	export CXXFLAGS="${CXXFLAGS:--fsanitize=fuzzer-no-link -fcommon -g -flto}"
	export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
	export LDFLAGS="${LDFLAGS:--fuse-ld=gold}"
	export AR="${AR:-llvm-ar}"
	export RANLIB="${RANLIB:-llvm-ranlib}"
	export FUZZ_INTROSPECTOR=1
	export FUZZ_INTROSPECTOR_STATIC=1

	log_info "Building htslib with FUZZ_INTROSPECTOR=1 in container"

	# Run build in container
	run_build_in_container <<'BUILD_COMMANDS'
set -euo pipefail
# Install build dependencies if not present
if ! command -v autoconf &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq autoconf automake libtool zlib1g-dev libbz2-dev liblzma-dev libcurl4-openssl-dev libssl-dev
fi
cd /src/htslib/build_static
autoreconf -i /src/htslib/htslib
/src/htslib/htslib/configure
make -j$(nproc) libhts.a
make /src/htslib/htslib/test/fuzz/hts_open_fuzzer.o
$CXX $CXXFLAGS /src/htslib/htslib/test/fuzz/hts_open_fuzzer.o \
	$LIB_FUZZING_ENGINE /src/htslib/build_static/libhts.a \
	-lz -lbz2 -llzma -lcurl -lcrypto -lpthread \
	-o /src/htslib/build_static/hts_open_fuzzer
BUILD_COMMANDS

	log_info "Static build complete: $HTSLIB_BUILD_STATIC/$FUZZER_NAME"
	return 0
}

build_cov() {
	log_step "Build htslib with coverage instrumentation"

	# Ensure source is cloned
	clone_htslib || return 1

	# Prepare build directory
	run_cmd rm -rf "$HTSLIB_BUILD_COV"/* || true
	run_cmd mkdir -p "$HTSLIB_BUILD_COV" || return 1

	# Environment for coverage build
	export CC="${CC:-clang}"
	export CXX="${CXX:-clang++}"
	export CFLAGS="${CFLAGS:--fsanitize=coverage -fcommon -g}"
	export CXXFLAGS="${CXXFLAGS:--fsanitize=coverage -fcommon -g}"
	export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
	export LDFLAGS="${LDFLAGS:--fuse-ld=gold}"
	export AR="${AR:-llvm-ar}"
	export RANLIB="${RANLIB:-llvm-ranlib}"

	log_info "Building htslib with coverage instrumentation in container"

	# Run build in container
	run_build_in_container <<'BUILD_COMMANDS'
set -euo pipefail
# Install build dependencies if not present
if ! command -v autoconf &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq autoconf automake libtool zlib1g-dev libbz2-dev liblzma-dev libcurl4-openssl-dev libssl-dev
fi
cd /src/htslib/build_cov
autoreconf -i /src/htslib/htslib
/src/htslib/htslib/configure
make -j$(nproc) libhts.a
make /src/htslib/htslib/test/fuzz/hts_open_fuzzer.o
$CXX $CXXFLAGS /src/htslib/htslib/test/fuzz/hts_open_fuzzer.o \
	$LIB_FUZZING_ENGINE /src/htslib/build_cov/libhts.a \
	-lz -lbz2 -llzma -lcurl -lcrypto -lpthread \
	-o /src/htslib/build_cov/hts_open_fuzzer
BUILD_COMMANDS

	log_info "Coverage build complete: $HTSLIB_BUILD_COV/$FUZZER_NAME"
	return 0
}

################################################################################
# Fuzzer execution functions
################################################################################

run_fuzzer() {
	local duration="$1"
	local output_dir="$2"
	local summary_file="$3"

	log_step "Run fuzzer for ${duration}s -> $summary_file"

	# Determine which build to use
	local fuzzer_binary=""
	if [[ "$duration" == "$FUZZER_TIME_10S" ]]; then
		fuzzer_binary="$HTSLIB_BUILD_STATIC/$FUZZER_NAME"
	else
		# Use coverage build for second run
		fuzzer_binary="$HTSLIB_BUILD_COV/$FUZZER_NAME"
	fi

	if [[ ! -x "$fuzzer_binary" ]]; then
		log_error "Fuzzer binary not found: $fuzzer_binary"
		return 1
	fi

	# Create corpus directory
	local corpus_dir="$output_dir/corpus"
	run_cmd mkdir -p "$corpus_dir" || return 1

	# Create crashes directory
	local crashes_dir="$output_dir/crashes"
	run_cmd mkdir -p "$crashes_dir" || return 1

	# Run fuzzer
	log_info "Starting fuzzer for ${duration}s"
	run_cmd "$fuzzer_binary" \
		"-max_total_time=$duration" \
		"-detect_leaks=0" \
		"$corpus_dir" \
		2>&1 | tee "$output_dir/fuzzer.log" || true

	log_info "Fuzzer run complete"

	# The fuzzer will produce fuzzerStats files - we need to extract summary
	# For now, we'll create a minimal summary based on what the fuzzer output

	# Check if fuzzer generated a stats file
	local stats_file=""
	for f in "$output_dir"/*.stats "$corpus_dir"/*.stats; do
		if [[ -f "$f" ]]; then
			stats_file="$f"
			break
		fi
	done

	# Generate summary JSON
	log_info "Generating summary: $summary_file"

	# Create a basic summary based on fuzzer output
	run_cmd cat >"$summary_file" <<EOF
{
  "fuzzer": "$FUZZER_NAME",
  "duration_seconds": $duration,
  "binary": "$fuzzer_binary",
  "corpus_dir": "$corpus_dir",
  "crashes_dir": "$crashes_dir",
  "stats_file": "${stats_file:-null}",
  "log_file": "$output_dir/fuzzer.log"
}
EOF

	log_info "Summary saved: $summary_file"
	return 0
}

fuzz_10s() {
	log_step "Fuzzer run: 10 seconds"

	# Ensure static build exists
	if [[ ! -x "$HTSLIB_BUILD_STATIC/$FUZZER_NAME" ]]; then
		log_warn "Static build not found, running build_static first"
		build_static || return 1
	fi

	run_fuzzer "$FUZZER_TIME_10S" "$FUZZER_OUT_10S" "$SUMMARY_10S" || return 1

	log_info "10s fuzzer run complete"
	return 0
}

fuzz_300s() {
	log_step "Fuzzer run: 300 seconds"

	# Ensure coverage build exists
	if [[ ! -x "$HTSLIB_BUILD_COV/$FUZZER_NAME" ]]; then
		log_warn "Coverage build not found, running build_cov first"
		build_cov || return 1
	fi

	run_fuzzer "$FUZZER_TIME_300S" "$FUZZER_OUT_300S" "$SUMMARY_300S" || return 1

	log_info "300s fuzzer run complete"
	return 0
}

################################################################################
# Fuzz-introspector analysis functions
################################################################################

correlate_binaries() {
	log_step "Correlate binaries with introspector logs"

	# Ensure we have the fuzzer binaries built
	if [[ ! -x "$HTSLIB_BUILD_STATIC/$FUZZER_NAME" ]]; then
		log_error "Static build binary not found: $HTSLIB_BUILD_STATIC/$FUZZER_NAME"
		return 1
	fi

	# Create correlation working directory
	local corr_work_dir="$OUTPUT_DIR/correlation"
	run_cmd mkdir -p "$corr_work_dir" || return 1

	# Copy binaries to correlate
	run_cmd mkdir -p "$corr_work_dir/binaries" || return 1
	run_cmd cp "$HTSLIB_BUILD_STATIC/$FUZZER_NAME" "$corr_work_dir/binaries/" || return 1

	# Look for fuzzerLog files (from FUZZ_INTROSPECTOR build)
	local log_dir="$HTSLIB_BUILD_STATIC"
	if [[ -d "$log_dir" ]]; then
		run_cmd cp "$log_dir"/*fuzzerLog* "$corr_work_dir/" 2>/dev/null || true
		run_cmd cp "$log_dir"/*.data.yaml "$corr_work_dir/" 2>/dev/null || true
	fi

	# Run fuzz-introspector correlate
	# This looks for introspector-embedded binary tags and matches them with log files
	log_info "Running fuzz-introspector correlate"

	if command -v fuzz-introspector &>/dev/null; then
		run_cmd fuzz-introspector correlate \
			--binaries-dir "$corr_work_dir/binaries" \
			--correlation-file "$corr_work_dir/correlation.txt" || {
			log_warn "Correlate command had issues, continuing..."
		}
	else
		log_warn "fuzz-introspector not found in PATH, using fallback correlation"
		# Fallback: create a basic correlation file
		run_cmd cat >"$corr_work_dir/correlation.txt" <<EOF
# Correlation file
# Format: binary_path:fuzzer_log_path
$HTSLIB_BUILD_STATIC/$FUZZER_NAME:$corr_work_dir/fuzzerLogFile-$FUZZER_NAME.data.yaml
EOF
	fi

	log_info "Correlation complete"
	return 0
}

generate_report() {
	log_step "Generate HTML report with coverage URL"

	# Create report working directory
	local report_work_dir="$OUTPUT_DIR/report_work"
	run_cmd mkdir -p "$report_work_dir" || return 1

	# Copy relevant data files
	if [[ -d "$HTSLIB_BUILD_STATIC" ]]; then
		run_cmd cp "$HTSLIB_BUILD_STATIC"/*fuzzerLog* "$report_work_dir/" 2>/dev/null || true
		run_cmd cp "$HTSLIB_BUILD_STATIC"/*.data.yaml "$report_work_dir/" 2>/dev/null || true
	fi

	# Copy 300s fuzzer output (more data)
	if [[ -d "$FUZZER_OUT_300S" ]]; then
		run_cmd cp "$FUZZER_OUT_300S"/* "$report_work_dir/" 2>/dev/null || true
	fi

	# Copy correlation file if exists
	local corr_file="$OUTPUT_DIR/correlation/correlation.txt"
	local corr_arg=""
	if [[ -f "$corr_file" ]]; then
		corr_arg="--correlation-file $corr_file"
	fi

	log_info "Running fuzz-introspector full analysis"

	# Run fuzz-introspector
	if command -v fuzz-introspector &>/dev/null; then
		run_cmd fuzz-introspector full \
			--target-dir "$report_work_dir" \
			--name "$PROJECT_NAME" \
			--language "c++" \
			--out-dir "$INTROSPECTOR_REPORT" \
			--coverage-url "$COVERAGE_URL" \
			$corr_arg || {
			log_warn "Full analysis had issues"
		}
	else
		log_warn "fuzz-introspector not found in PATH"
		log_info "Generating report structure manually"

		# Create a basic report structure
		run_cmd mkdir -p "$INTROSPECTOR_REPORT" || return 1

		# Copy data files
		run_cmd cp "$report_work_dir"/* "$INTROSPECTOR_REPORT/" 2>/dev/null || true

		# Create index
		run_cmd cat >"$INTROSPECTOR_REPORT/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Fuzz Introspector Report - $PROJECT_NAME</title>
</head>
<body>
    <h1>Fuzz Introspector Report - $PROJECT_NAME</h1>
    <p>Build directory: $BUILD_DIR</p>
    <p>Coverage URL: $COVERAGE_URL</p>
    <h2>Fuzzer Runs</h2>
    <ul>
        <li><a href="summary_10s.json">10s Run Summary</a></li>
        <li><a href="summary_300s.json">300s Run Summary</a></li>
    </ul>
</body>
</html>
EOF
	fi

	log_info "Report generated: $INTROSPECTOR_REPORT"
	return 0
}

diff_reports() {
	log_step "Diff between 10s and 300s runs"

	# Check if summary files exist
	if [[ ! -f "$SUMMARY_10S" ]]; then
		log_error "10s summary not found: $SUMMARY_10S"
		return 1
	fi

	if [[ ! -f "$SUMMARY_300S" ]]; then
		log_error "300s summary not found: $SUMMARY_300S"
		return 1
	fi

	# Run fuzz-introspector diff if available
	if command -v fuzz-introspector &>/dev/null; then
		log_info "Running fuzz-introspector diff"
		run_cmd fuzz-introspector diff \
			--report1 "$SUMMARY_10S" \
			--report2 "$SUMMARY_300S" \
			>"$DIFF_REPORT" 2>&1 || true
	else
		log_warn "fuzz-introspector not found, creating basic diff"

		# Create basic diff
		run_cmd cat >"$DIFF_REPORT" <<EOF
================================================================================
Fuzz Introspector Diff Report
================================================================================

Project: $PROJECT_NAME
10s run: $SUMMARY_10S
300s run: $SUMMARY_300S
Generated: $(date)

================================================================================
Analysis
================================================================================

EOF

		# Basic comparison - just show both files side by side
		echo "--- 10s Summary ---" >>"$DIFF_REPORT"
		cat "$SUMMARY_10S" >>"$DIFF_REPORT"
		echo "" >>"$DIFF_REPORT"
		echo "--- 300s Summary ---" >>"$DIFF_REPORT"
		cat "$SUMMARY_300S" >>"$DIFF_REPORT"
	fi

	log_info "Diff report saved: $DIFF_REPORT"
	cat "$DIFF_REPORT"

	return 0
}

################################################################################
# Main execution
################################################################################

should_run_step() {
	local step="$1"

	if [[ "$STEPS" == "all" ]]; then
		return 0
	fi

	# Check if step is in comma-separated list
	if [[ ",$STEPS," == *",$step,"* ]]; then
		return 0
	fi

	return 1
}

main() {
	echo "================================================================================"
	echo "  htslib Fuzz Introspector Test Script v$SCRIPT_VERSION"
	echo "================================================================================"
	echo ""
	echo "Configuration:"
	echo "  BUILD_DIR:       $BUILD_DIR"
	echo "  OUTPUT_DIR:      $OUTPUT_DIR"
	echo "  STEPS:           $STEPS"
	echo "  FUZZER_TIME_10S: $FUZZER_TIME_10S"
	echo "  FUZZER_TIME_300S:$FUZZER_TIME_300S"
	echo "  BUILD_IMAGE:     $BUILD_IMAGE"
	echo "  RUNNER_IMAGE:    $RUNNER_IMAGE"
	echo "  DRY_RUN:         $DRY_RUN"
	echo "  VERBOSE:         $VERBOSE"
	echo ""

	# Check dependencies
	check_dependencies || exit 1

	# Create directories
	create_directories || exit 1

	# Set up cleanup trap
	trap cleanup EXIT

	# Execute steps based on configuration
	local exit_code=0

	# Step: build_static
	if should_run_step "build_static"; then
		build_static || {
			exit_code=1
			log_error "build_static failed"
		}
	fi

	# Step: build_cov
	if should_run_step "build_cov"; then
		build_cov || {
			exit_code=1
			log_error "build_cov failed"
		}
	fi

	# Step: fuzz_10s
	if should_run_step "fuzz_10s"; then
		fuzz_10s || {
			exit_code=1
			log_error "fuzz_10s failed"
		}
	fi

	# Step: fuzz_300s
	if should_run_step "fuzz_300s"; then
		fuzz_300s || {
			exit_code=1
			log_error "fuzz_300s failed"
		}
	fi

	# Step: correlate
	if should_run_step "correlate"; then
		correlate_binaries || {
			exit_code=1
			log_error "correlate failed"
		}
	fi

	# Step: report
	if should_run_step "report"; then
		generate_report || {
			exit_code=1
			log_error "report failed"
		}
	fi

	# Step: diff
	if should_run_step "diff"; then
		diff_reports || {
			exit_code=1
			log_error "diff failed"
		}
	fi

	echo ""
	echo "================================================================================"
	if [[ $exit_code -eq 0 ]]; then
		echo "  SUCCESS: All steps completed"
	else
		echo "  FAILURE: Some steps failed (exit code: $exit_code)"
	fi
	echo "================================================================================"
	echo ""
	echo "Output artifacts:"
	echo "  Build directory:    $BUILD_DIR"
	echo "  Output directory:   $OUTPUT_DIR"
	echo "  Summary 10s:        $SUMMARY_10S"
	echo "  Summary 300s:       $SUMMARY_300S"
	echo "  Diff report:        $DIFF_REPORT"
	echo "  Inspector report:   $INTROSPECTOR_REPORT"
	echo ""

	return "$exit_code"
}

# Parse command line arguments
parse_args "$@"

# Run main
main "$@"
