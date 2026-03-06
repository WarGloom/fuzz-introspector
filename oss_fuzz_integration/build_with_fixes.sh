#!/usr/bin/env bash

# Build script for fuzz-introspector with tree-sitter 0.25+ compatibility
# Run from the fuzz-introspector root directory

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OSS_FUZZ_DIR="$SCRIPT_DIR/oss_fuzz_integration/oss-fuzz"
OSS_FUZZ_PATCHES_DIR="$SCRIPT_DIR/oss_fuzz_integration"

# Use ubuntu-24-04 tag for consistency
IMAGE_TAG="${IMAGE_TAG:-ubuntu-24-04}"

# Detect container runtime
if command -v podman &>/dev/null; then
	CONTAINER_RUNTIME="podman"
else
	CONTAINER_RUNTIME="docker"
fi

echo "=== Building fuzz-introspector with tree-sitter 0.25+ compatibility ==="
echo "Container runtime: ${CONTAINER_RUNTIME}"
echo "Image tag: ${IMAGE_TAG}"

# Step 1: Clone OSS-Fuzz if not present
if [ ! -d "$OSS_FUZZ_DIR" ]; then
	echo "Cloning OSS-Fuzz..."
	cd "$OSS_FUZZ_PATCHES_DIR"
	git clone https://github.com/google/oss-fuzz

	# Apply any existing patches if available
	if [ -f "$OSS_FUZZ_PATCHES_DIR/oss-fuzz-patches.diff" ]; then
		cd "$OSS_FUZZ_DIR"
		git apply --ignore-space-change --ignore-whitespace "$OSS_FUZZ_PATCHES_DIR/oss-fuzz-patches.diff"
		cd "$SCRIPT_DIR"
	fi
fi

# Step 1b: Update OSS-Fuzz to latest
echo "Updating OSS-Fuzz..."
cd "$OSS_FUZZ_DIR"
stashed_changes=0
if ! git diff --quiet || ! git diff --cached --quiet; then
	git stash push -m "build_with_fixes.sh auto-stash before pull"
	stashed_changes=1
else
	echo "No local tracked changes to stash before pull"
fi

if ! git pull origin master; then
	echo "ERROR: Failed to update OSS-Fuzz via git pull origin master" >&2
	exit 1
fi

if [ "$stashed_changes" -eq 1 ]; then
	if ! git stash pop; then
		echo "ERROR: git stash pop failed (likely merge conflicts). Resolve conflicts manually." >&2
		exit 1
	fi
fi
cd "$SCRIPT_DIR"

# Step 2: Pull base-clang:ubuntu-24-04 first (has LLVM with introspector pass)
echo "Pulling base-clang:${IMAGE_TAG} image..."
$CONTAINER_RUNTIME pull "gcr.io/oss-fuzz-base/base-clang:${IMAGE_TAG}"

# Step 3: Copy fuzz-introspector source to where the container expects it
echo "Copying fuzz-introspector source..."
mkdir -p "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector"
cp -rf "$SCRIPT_DIR/src" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/"
cp -rf "$SCRIPT_DIR/frontends" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/"
mkdir -p "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools"

OPTIONAL_NATIVE_RUST_TOOLS=(
	"native_analysis_plugins_rust"
	"native_reachability_rust"
	"native_filter_functions_rust"
	"native_calltree_bitmap_rust"
)

if command -v rsync &>/dev/null; then
	RSYNC_EXCLUDES=(
		--exclude='target/'
		--exclude='build/'
		--exclude='dist/'
		--exclude='native_*_go'
	)
	rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/native_yaml_loader_go/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_yaml_loader_go/"
	rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/native_yaml_loader_rust/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_yaml_loader_rust/"
	rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/native_llvm_cov_loader_go/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_llvm_cov_loader_go/"
	rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/native_llvm_cov_loader_rust/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_llvm_cov_loader_rust/"
	rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/native_debug_correlator_go/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_debug_correlator_go/"
	rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/native_debug_correlator_rust/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_debug_correlator_rust/"
	rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/native_overlay_backend_go/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_overlay_backend_go/"
	rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/native_overlay_backend_rust/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_overlay_backend_rust/"
	for tool_dir in "${OPTIONAL_NATIVE_RUST_TOOLS[@]}"; do
		if [ -d "$SCRIPT_DIR/tools/$tool_dir" ]; then
			rsync -a "${RSYNC_EXCLUDES[@]}" "$SCRIPT_DIR/tools/$tool_dir/" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/$tool_dir/"
		fi
	done
else
	echo "rsync not found, falling back to cp -rf for native tools"
	cp -rf "$SCRIPT_DIR/tools/native_yaml_loader_go" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
	cp -rf "$SCRIPT_DIR/tools/native_yaml_loader_rust" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
	cp -rf "$SCRIPT_DIR/tools/native_llvm_cov_loader_go" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
	cp -rf "$SCRIPT_DIR/tools/native_llvm_cov_loader_rust" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
	cp -rf "$SCRIPT_DIR/tools/native_debug_correlator_go" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
	cp -rf "$SCRIPT_DIR/tools/native_debug_correlator_rust" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
	cp -rf "$SCRIPT_DIR/tools/native_overlay_backend_go" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
	cp -rf "$SCRIPT_DIR/tools/native_overlay_backend_rust" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
	for tool_dir in "${OPTIONAL_NATIVE_RUST_TOOLS[@]}"; do
		if [ -d "$SCRIPT_DIR/tools/$tool_dir" ]; then
			cp -rf "$SCRIPT_DIR/tools/$tool_dir" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/"
		fi
	done
fi
rm -rf "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_yaml_loader_rust/target"
rm -rf "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_llvm_cov_loader_rust/target"
rm -rf "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_debug_correlator_rust/target"
rm -rf "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_overlay_backend_rust/target"
for tool_dir in "${OPTIONAL_NATIVE_RUST_TOOLS[@]}"; do
	rm -rf "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/$tool_dir/target"
done
rm -f "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_yaml_loader_go/native_yaml_loader_go"
rm -f "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_llvm_cov_loader_go/native_llvm_cov_loader_go"
rm -f "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_debug_correlator_go/native_debug_correlator_go"
rm -f "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/tools/native_overlay_backend_go/native_overlay_backend_go"
cp "$SCRIPT_DIR/requirements.txt" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/"

# Step 4: Update requirements.txt to use tree-sitter >= 0.25.0
echo "Updating requirements.txt for tree-sitter 0.25+..."
cat >"$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/requirements.txt" <<'EOF'
beautifulsoup4==4.10.0
cxxfilt==0.3.0
lxml==5.3.0
matplotlib==3.10.0
numpy==2.1.0
PyYAML==6.0.2
soupsieve==2.2.1
yapf==0.32.0
pylint==3.0.0
flake8
pep8
mypy
toml
psutil
pytest
sphinx==6.0.0
sphinx_rtd_theme
configparser
coverage
setuptools>=65.5.1
tqdm
rust-demangler
tree-sitter>=0.25.0,<0.26.0
tree-sitter-cpp
tree-sitter-go
tree-sitter-java
tree-sitter-python
tree-sitter-rust
EOF

# Step 5: Update Dockerfile to copy fuzz-introspector and wire native loaders
echo "Updating Dockerfile..."
DOCKERFILE="$OSS_FUZZ_DIR/infra/base-images/base-builder/Dockerfile"
if ! grep -q "COPY fuzz-introspector /fuzz-introspector" "$DOCKERFILE"; then
	sed -i '/^CMD \["compile"\]$/i\
# Copy local fuzz-introspector with our changes\
COPY fuzz-introspector /fuzz-introspector' "$DOCKERFILE"
fi

# Always remove any previously generated native-loader section (old or new)
# and re-insert a canonical block. This keeps reruns idempotent and allows
# updating broken prior inserts.
tmp_dockerfile="${DOCKERFILE}.tmp"
awk '
/^# Fuzz Introspector native loader backends \(auto-generated by build_with_fixes\.sh\)$/ {
  skip = 1
  next
}
/^CMD \["compile"\]$/ {
  skip = 0
}
skip == 0 {
  print
}
' "$DOCKERFILE" >"$tmp_dockerfile"
mv "$tmp_dockerfile" "$DOCKERFILE"

tmp_dockerfile="${DOCKERFILE}.tmp"
awk '
/^CMD \["compile"\]$/ && !inserted {
	print "# Fuzz Introspector native loader backends (auto-generated by build_with_fixes.sh)"
	print "RUN apt-get update && \\"
	print "    apt-get install -y --no-install-recommends ca-certificates curl && \\"
	print "    GO_VERSION=1.22.6 && \\"
	print "    curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -o /tmp/go.tgz && \\"
	print "    rm -rf /usr/local/go && \\"
	print "    tar -C /usr/local -xzf /tmp/go.tgz && \\"
	print "    rm -f /tmp/go.tgz && \\"
	print "    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable && \\"
	print "    rm -rf /var/lib/apt/lists/* && \\"
	print "    mkdir -p /opt/fuzz-introspector/bin && \\"
	print "    cd /fuzz-introspector/tools/native_yaml_loader_rust && /root/.cargo/bin/cargo build --release && \\"
	print "    cp target/release/native_yaml_loader_rust /opt/fuzz-introspector/bin/native_yaml_loader_rust && \\"
	print "    cd /fuzz-introspector/tools/native_llvm_cov_loader_rust && /root/.cargo/bin/cargo build --release && \\"
	print "    cp target/release/native_llvm_cov_loader_rust /opt/fuzz-introspector/bin/native_llvm_cov_loader_rust && \\"
	print "    cd /fuzz-introspector/tools/native_debug_correlator_rust && /root/.cargo/bin/cargo build --release && \\"
	print "    cp target/release/native_debug_correlator_rust /opt/fuzz-introspector/bin/native_debug_correlator_rust && \\"
	print "    cd /fuzz-introspector/tools/native_yaml_loader_go && /usr/local/go/bin/go build -o /opt/fuzz-introspector/bin/native_yaml_loader_go . && \\"
	print "    cd /fuzz-introspector/tools/native_llvm_cov_loader_go && /usr/local/go/bin/go build -o /opt/fuzz-introspector/bin/native_llvm_cov_loader_go . && \\"
	print "    cd /fuzz-introspector/tools/native_debug_correlator_go && /usr/local/go/bin/go build -o /opt/fuzz-introspector/bin/native_debug_correlator_go . && \\"
	print "    cd /fuzz-introspector/tools/native_overlay_backend_go && /usr/local/go/bin/go build -o /opt/fuzz-introspector/bin/native_overlay_backend_go . && \\"
	print "    cd /fuzz-introspector/tools/native_overlay_backend_rust && /root/.cargo/bin/cargo build --release && \\"
	print "    cp target/release/native_overlay_backend_rust /opt/fuzz-introspector/bin/native_overlay_backend_rust && \\"
	print "    if [ -d /fuzz-introspector/tools/native_analysis_plugins_rust ]; then cd /fuzz-introspector/tools/native_analysis_plugins_rust && /root/.cargo/bin/cargo build --release && cp target/release/native_analysis_plugins_rust /opt/fuzz-introspector/bin/native_analysis_plugins_rust; fi && \\"
	print "    if [ -d /fuzz-introspector/tools/native_reachability_rust ]; then cd /fuzz-introspector/tools/native_reachability_rust && /root/.cargo/bin/cargo build --release && cp target/release/native_reachability_rust /opt/fuzz-introspector/bin/native_reachability_rust; fi && \\"
	print "    if [ -d /fuzz-introspector/tools/native_filter_functions_rust ]; then cd /fuzz-introspector/tools/native_filter_functions_rust && /root/.cargo/bin/cargo build --release && cp target/release/native_filter_functions_rust /opt/fuzz-introspector/bin/native_filter_functions_rust; fi && \\"
	print "    if [ -d /fuzz-introspector/tools/native_calltree_bitmap_rust ]; then cd /fuzz-introspector/tools/native_calltree_bitmap_rust && /root/.cargo/bin/cargo build --release && cp target/release/native_calltree_bitmap_rust /opt/fuzz-introspector/bin/native_calltree_bitmap_rust; fi"
	print ""
	print "ENV FI_DEBUG_YAML_LOADER=rust \\"
	print "    FI_PROFILE_YAML_LOADER=rust \\"
	print "    FI_LLVM_COV_LOADER=rust \\"
	print "    FI_NATIVE_BACKENDS=rust \\"
	print "    FI_DEBUG_YAML_LOADER_RUST_BIN=/opt/fuzz-introspector/bin/native_yaml_loader_rust \\"
	print "    FI_PROFILE_YAML_LOADER_RUST_BIN=/opt/fuzz-introspector/bin/native_yaml_loader_rust \\"
	print "    FI_LLVM_COV_LOADER_RUST_BIN=/opt/fuzz-introspector/bin/native_llvm_cov_loader_rust \\"
	print "    FI_DEBUG_CORRELATOR_RUST_BIN=/opt/fuzz-introspector/bin/native_debug_correlator_rust \\"
	print "    FI_DEBUG_CORRELATOR_GO_BIN=/opt/fuzz-introspector/bin/native_debug_correlator_go \\"
	print "    FI_DEBUG_CORRELATOR_BIN=/opt/fuzz-introspector/bin/native_debug_correlator_rust \\"
	print "    FI_DEBUG_YAML_LOADER_GO_BIN=/opt/fuzz-introspector/bin/native_yaml_loader_go \\"
	print "    FI_PROFILE_YAML_LOADER_GO_BIN=/opt/fuzz-introspector/bin/native_yaml_loader_go \\"
	print "    FI_LLVM_COV_LOADER_GO_BIN=/opt/fuzz-introspector/bin/native_llvm_cov_loader_go \\"
	print "    FI_REACHABILITY_RUST_BIN=/opt/fuzz-introspector/bin/native_reachability_rust \\"
	print "    FI_FILTER_RUST_BIN=/opt/fuzz-introspector/bin/native_filter_functions_rust \\"
	print "    FI_CALLTREE_BITMAP_RUST_BIN=/opt/fuzz-introspector/bin/native_calltree_bitmap_rust \\"
	print "    FI_OVERLAY_NATIVE_BIN=/opt/fuzz-introspector/bin/native_overlay_backend_rust \\"
	print "    FI_OVERLAY_RUST_BIN=/opt/fuzz-introspector/bin/native_overlay_backend_rust \\"
	print "    FI_OVERLAY_GO_BIN=/opt/fuzz-introspector/bin/native_overlay_backend_go \\"
	print "    PATH=/opt/fuzz-introspector/bin:${PATH}"
	print ""
	inserted = 1
}
{ print }
' "$DOCKERFILE" >"$tmp_dockerfile"
mv "$tmp_dockerfile" "$DOCKERFILE"

# Step 6: Update compile script to install tree-sitter 0.25+ and use --no-deps
echo "Updating compile script..."
COMPILE_FILE="$OSS_FUZZ_DIR/infra/base-images/base-builder/compile"
if ! grep -q "tree-sitter>=0.25.0,<0.26.0" "$COMPILE_FILE"; then
	# Find the line after "python3 -m pip install --prefer-binary matplotlib"
	# and add the tree-sitter upgrade and --no-deps install
	sed -i '/python3 -m pip install --prefer-binary matplotlib/a\
\
  # Force upgrade tree-sitter to 0.25+ for QueryCursor API\
  python3 -m pip install --upgrade '\''tree-sitter>=0.25.0,<0.26.0'\'' tree-sitter-cpp tree-sitter-go tree-sitter-java tree-sitter-python tree-sitter-rust tree-sitter-languages' "$COMPILE_FILE"

	# Change "pip install -e ." to "pip install -e . --no-deps"
	sed -i 's/python3 -m pip install -e \./python3 -m pip install -e . --no-deps/g' "$COMPILE_FILE"
fi

if ! grep -q "python3 -m pip install --upgrade 'tree-sitter>=0.25.0,<0.26.0'" "$COMPILE_FILE"; then
	echo "ERROR: compile patch verification failed: tree-sitter upgrade command missing" >&2
	exit 1
fi

if ! grep -q "python3 -m pip install -e \. --no-deps" "$COMPILE_FILE"; then
	echo "ERROR: compile patch verification failed: pip editable install with --no-deps missing" >&2
	exit 1
fi

# Step 7: Build the base-builder image
echo "Building base-builder:${IMAGE_TAG} image..."
cd "$OSS_FUZZ_DIR"
# $CONTAINER_RUNTIME build --no-cache -t "gcr.io/oss-fuzz-base/base-builder:${IMAGE_TAG}" infra/base-images/base-builder
$CONTAINER_RUNTIME build -t "gcr.io/oss-fuzz-base/base-builder:${IMAGE_TAG}" infra/base-images/base-builder

# Also tag as latest
$CONTAINER_RUNTIME tag "gcr.io/oss-fuzz-base/base-builder:${IMAGE_TAG}" "gcr.io/oss-fuzz-base/base-builder:latest"

# Step 8: Build other base-builder images (optional, for other languages)
# read -p "Build additional language images? (y/N) " -n 1 -r
# echo
# if [[ $REPLY =~ ^[Yy]$ ]]; then
# 	echo "Building base-builder-python image..."
# 	$CONTAINER_RUNTIME build --no-cache -t "gcr.io/oss-fuzz-base/base-builder-python:${IMAGE_TAG}" infra/base-images/base-builder-python

# 	echo "Building base-builder-jvm image..."
# 	$CONTAINER_RUNTIME build --no-cache -t "gcr.io/oss-fuzz-base/base-builder-jvm:${IMAGE_TAG}" infra/base-images/base-builder-jvm

# 	echo "Building base-builder-rust image..."
# 	$CONTAINER_RUNTIME build --no-cache -t "gcr.io/oss-fuzz-base/base-builder-rust:${IMAGE_TAG}" infra/base-images/base-builder-rust

# 	echo "Building base-builder-go image..."
# 	$CONTAINER_RUNTIME build --no-cache -t "gcr.io/oss-fuzz-base/base-builder-go:${IMAGE_TAG}" infra/base-images/base-builder-go
# fi

echo "Building base-runner image..."
# $CONTAINER_RUNTIME build --no-cache -t "gcr.io/oss-fuzz-base/base-runner:${IMAGE_TAG}" infra/base-images/base-runner
$CONTAINER_RUNTIME build -t "gcr.io/oss-fuzz-base/base-runner:${IMAGE_TAG}" infra/base-images/base-runner
$CONTAINER_RUNTIME tag "gcr.io/oss-fuzz-base/base-runner:${IMAGE_TAG}" "gcr.io/oss-fuzz-base/base-runner:latest"

# Re-tag after base-runner build, because base-runner stages can pull
# repository "latest" tags and overwrite local tag resolution.
$CONTAINER_RUNTIME tag "gcr.io/oss-fuzz-base/base-builder:${IMAGE_TAG}" "gcr.io/oss-fuzz-base/base-builder:latest"
$CONTAINER_RUNTIME tag "gcr.io/oss-fuzz-base/base-runner:${IMAGE_TAG}" "gcr.io/oss-fuzz-base/base-runner:latest"

echo ""
echo "=== Build complete! ==="
echo ""
echo "Images built:"
$CONTAINER_RUNTIME images | grep -E "base-builder|base-runner" | head -10
echo ""
echo "To test with simple-example-0:"
echo "  cd $SCRIPT_DIR/tests/simple-example-0"
echo "  mkdir -p work && cd work"
echo "  $CONTAINER_RUNTIME run --rm -v \$(pwd):/work:z gcr.io/oss-fuzz-base/base-builder:${IMAGE_TAG} bash -c 'cd /work && FUZZ_INTROSPECTOR=1 clang -fsanitize=fuzzer -fuse-ld=gold -flto -g ../fuzzer.c -o fuzzer'"
echo "  $CONTAINER_RUNTIME run --rm -v \$(pwd):/work:z gcr.io/oss-fuzz-base/base-builder:${IMAGE_TAG} bash -c 'pip install -e /fuzz-introspector --no-deps && python3 /fuzz-introspector/src/main.py correlate --binaries-dir=/work'"
echo ""
echo "To run introspector on a project:"
echo "  cd $OSS_FUZZ_DIR"
echo "  python3 infra/helper.py introspector <project_name> --seconds 30"
