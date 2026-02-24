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
git stash || true
git pull origin master || true
git stash pop || true
cd "$SCRIPT_DIR"

# Step 2: Pull base-clang:ubuntu-24-04 first (has LLVM with introspector pass)
echo "Pulling base-clang:${IMAGE_TAG} image..."
$CONTAINER_RUNTIME pull "gcr.io/oss-fuzz-base/base-clang:${IMAGE_TAG}"

# Step 3: Copy fuzz-introspector source to where the container expects it
echo "Copying fuzz-introspector source..."
mkdir -p "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector"
cp -rf "$SCRIPT_DIR/src" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/"
cp -rf "$SCRIPT_DIR/frontends" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/"
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

# Step 5: Update Dockerfile to copy fuzz-introspector
echo "Updating Dockerfile..."
if ! grep -q "COPY fuzz-introspector /fuzz-introspector" "$OSS_FUZZ_DIR/infra/base-images/base-builder/Dockerfile"; then
	sed -i '/^CMD \["compile"\]$/i\
# Copy local fuzz-introspector with our changes\
COPY fuzz-introspector /fuzz-introspector' "$OSS_FUZZ_DIR/infra/base-images/base-builder/Dockerfile"
fi

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
