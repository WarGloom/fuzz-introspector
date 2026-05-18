#!/bin/bash
# Copyright 2025 Fuzz Introspector Authors
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
# Native backend build script for OSS-Fuzz integration.
# Builds Rust native binaries and sets FI_NATIVE_BACKENDS=rust.
# See docs/perf/native_rewrite_execution_plan_2026-03-04.md for execution details.

set -euo pipefail

# ---------------------------------------------------------------------------
# 1. OSS-Fuzz clone / reuse (unchanged from build_post_processing.sh)
# ---------------------------------------------------------------------------

if [ -d "oss-fuzz" ]; then
	echo "OSS-Fuzz directory exists. Reusing existing one"
else
	echo "Cloning oss-fuzz"
	git clone https://github.com/google/oss-fuzz
	echo "Applying diffs"
	cd oss-fuzz
	git apply --ignore-space-change --ignore-whitespace ../oss-fuzz-patches.diff
	echo "Done"
	cd ../

	echo "Pulling latest base-clang OSS-Fuzz image."
	docker pull gcr.io/oss-fuzz-base/base-clang:latest
fi

# ---------------------------------------------------------------------------
# 2. Install Rust toolchain if not already present
# ---------------------------------------------------------------------------

if command -v cargo >/dev/null 2>&1; then
	echo "Rust toolchain already present: $(cargo --version)"
else
	echo "Installing Rust toolchain via rustup (non-interactive, no PATH modification)"
	rustup_init="$(mktemp)"
	curl --proto '=https' --tlsv1.2 -sSf \
		"https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init" \
		-o "${rustup_init}"
	printf '%s  %s\n' \
		"20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c" \
		"${rustup_init}" | sha256sum -c -
	chmod +x "${rustup_init}"
	"${rustup_init}" -y --no-modify-path --profile minimal --default-toolchain stable
	rm -f "${rustup_init}"
fi

# Ensure cargo is on PATH for the remainder of this script.
export PATH="${HOME}/.cargo/bin:${PATH}"

# ---------------------------------------------------------------------------
# 3. Build Rust native tools
#    Binary destination: /opt/fuzz-introspector/bin (on PATH inside the image)
# ---------------------------------------------------------------------------

NATIVE_BIN_DIR="/opt/fuzz-introspector/bin"
mkdir -p "${NATIVE_BIN_DIR}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS_DIR="${REPO_ROOT}/tools"

# List of (tool_dir, binary_name) pairs to build and install.
# The binary name must match the [[bin]] name in Cargo.toml.
RUST_TOOLS=(
	"native_yaml_loader_rust:native_yaml_loader_rust"
	"native_llvm_cov_loader_rust:native_llvm_cov_loader_rust"
	"native_debug_correlator_rust:native_debug_correlator_rust"
	"native_overlay_backend_rust:native_overlay_backend_rust"
	"native_analysis_plugins_rust:native_analysis_plugins_rust"
	"native_reachability_rust:native_reachability_rust"
	"native_filter_functions_rust:native_filter_functions_rust"
	"native_calltree_bitmap_rust:native_calltree_bitmap_rust"
)

for entry in "${RUST_TOOLS[@]}"; do
	tool_dir="${entry%%:*}"
	bin_name="${entry##*:}"
	src="${TOOLS_DIR}/${tool_dir}"

	if [ ! -d "${src}" ]; then
		echo "WARNING: ${src} not found, skipping"
		continue
	fi

	echo "Building ${tool_dir} ..."
	(cd "${src}" && cargo build --release)

	dest="${NATIVE_BIN_DIR}/${bin_name}"
	src_bin="${src}/target/release/${bin_name}"
	if [ -f "${src_bin}" ]; then
		cp "${src_bin}" "${dest}"
		echo "  Installed ${bin_name} -> ${dest}"
	else
		echo "ERROR: expected binary not found at ${src_bin}" >&2
		exit 1
	fi
done

# ---------------------------------------------------------------------------
# 4. Export environment variables consumed by fuzz-introspector Python code
#    (mirrors what build_with_fixes.sh injects into Dockerfiles)
# ---------------------------------------------------------------------------

export FI_NATIVE_BACKENDS=rust

export FI_DEBUG_YAML_LOADER=rust
export FI_PROFILE_YAML_LOADER=rust
export FI_LLVM_COV_LOADER=rust

export FI_YAML_LOADER_RUST_BIN="${NATIVE_BIN_DIR}/native_yaml_loader_rust"
export FI_DEBUG_YAML_LOADER_RUST_BIN="${NATIVE_BIN_DIR}/native_yaml_loader_rust"
export FI_PROFILE_YAML_LOADER_RUST_BIN="${NATIVE_BIN_DIR}/native_yaml_loader_rust"
export FI_LLVM_COV_LOADER_RUST_BIN="${NATIVE_BIN_DIR}/native_llvm_cov_loader_rust"
export FI_DEBUG_CORRELATOR_RUST_BIN="${NATIVE_BIN_DIR}/native_debug_correlator_rust"
export FI_DEBUG_CORRELATOR_BIN="${NATIVE_BIN_DIR}/native_debug_correlator_rust"
export FI_IF_DEBUG_CORRELATOR_RUST_BIN="${NATIVE_BIN_DIR}/native_debug_correlator_rust"
export FI_IF_DEBUG_CORRELATOR_BIN="${NATIVE_BIN_DIR}/native_debug_correlator_rust"
export FI_OVERLAY_NATIVE_BIN="${NATIVE_BIN_DIR}/native_overlay_backend_rust"
export FI_OVERLAY_RUST_BIN="${NATIVE_BIN_DIR}/native_overlay_backend_rust"

export FI_REACHABILITY_BACKEND=rust
export FI_REACHABILITY_RUST_BIN="${NATIVE_BIN_DIR}/native_reachability_rust"
export FI_FILTER_BACKEND=rust
export FI_FILTER_RUST_BIN="${NATIVE_BIN_DIR}/native_filter_functions_rust"
export FI_CALLTREE_BITMAP_BACKEND=rust
export FI_CALLTREE_BITMAP_RUST_BIN="${NATIVE_BIN_DIR}/native_calltree_bitmap_rust"

# Performance observability: emit stage-marker timestamps and RSS to logs so
# the container monitor can attribute wall-time to individual pipeline phases.
export FI_DEBUG_STAGE_RSS=1
export FI_DEBUG_PERF_WARN=1
export FI_STAGE_WARN_SECONDS=30
export FI_DEBUG_STAGE_WARN_RSS_MB=4096

# native_analysis_plugins_rust is resolved via shutil.which; ensure it is on PATH.
export PATH="${NATIVE_BIN_DIR}:${PATH}"

echo "Native backends built and environment configured."
echo "  FI_NATIVE_BACKENDS=${FI_NATIVE_BACKENDS}"
echo "  NATIVE_BIN_DIR=${NATIVE_BIN_DIR}"
ls -lh "${NATIVE_BIN_DIR}"

# ---------------------------------------------------------------------------
# 5. Build and push OSS-Fuzz Docker images with native backend support
# ---------------------------------------------------------------------------

echo "Building base-build, base-builder-python and base-runner for fuzz introspector"
# This script should be run from the fuzz-introspector/oss_fuzz_integration folder
# Copy over new post-processing and native loader sources.
rm -rf ./oss-fuzz/infra/base-images/base-builder/src
cp -rf ../src ./oss-fuzz/infra/base-images/base-builder/src

rm -rf ./oss-fuzz/infra/base-images/base-builder/frontends
cp -rf ../frontends ./oss-fuzz/infra/base-images/base-builder/frontends

# Newer OSS-Fuzz Dockerfiles in this repo expect fuzz-introspector as a single
# subtree at the base-builder context root.
rm -rf ./oss-fuzz/infra/base-images/base-builder/fuzz-introspector
mkdir -p ./oss-fuzz/infra/base-images/base-builder/fuzz-introspector
cp -rf ../src ./oss-fuzz/infra/base-images/base-builder/fuzz-introspector/src
cp -rf ../frontends ./oss-fuzz/infra/base-images/base-builder/fuzz-introspector/frontends
cp -rf ../tools ./oss-fuzz/infra/base-images/base-builder/fuzz-introspector/tools

cd oss-fuzz
docker build -t gcr.io/oss-fuzz-base/base-builder infra/base-images/base-builder
docker build -t gcr.io/oss-fuzz-base/base-runner infra/base-images/base-runner
