#!/bin/bash -euo pipefail

# Build script for fuzz-introspector with tree-sitter 0.25+ compatibility
# Run from the fuzz-introspector root directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSS_FUZZ_DIR="$SCRIPT_DIR/oss_fuzz_integration/oss-fuzz"
OSS_FUZZ_PATCHES_DIR="$SCRIPT_DIR/oss_fuzz_integration"

echo "=== Building fuzz-introspector with tree-sitter 0.25+ compatibility ==="

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

	# Pull latest base-clang
	echo "Pulling base-clang image..."
	docker pull gcr.io/oss-fuzz-base/base-clang:latest
fi

# Step 2: Copy fuzz-introspector source to where the container expects it
echo "Copying fuzz-introspector source..."
mkdir -p "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector"
cp -rf "$SCRIPT_DIR/src" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/"
cp -rf "$SCRIPT_DIR/frontends" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/"
cp "$SCRIPT_DIR/requirements.txt" "$OSS_FUZZ_DIR/infra/base-images/base-builder/fuzz-introspector/"

# Step 3: Update requirements.txt to use tree-sitter >= 0.25.0
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
tree-sitter>=0.25.0
tree-sitter-cpp
tree-sitter-go
tree-sitter-java
tree-sitter-python
tree-sitter-rust
EOF

# Step 4: Update Dockerfile to copy fuzz-introspector
echo "Updating Dockerfile..."
if ! grep -q "COPY fuzz-introspector /fuzz-introspector" "$OSS_FUZZ_DIR/infra/base-images/base-builder/Dockerfile"; then
	sed -i '/^CMD \["compile"\]$/i\
# Copy local fuzz-introspector with our changes\
COPY fuzz-introspector /fuzz-introspector' "$OSS_FUZZ_DIR/infra/base-images/base-builder/Dockerfile"
fi

# Step 5: Update compile script to install tree-sitter 0.25+ and use --no-deps
echo "Updating compile script..."
# Add tree-sitter upgrade and fix pip install
COMPILE_FILE="$OSS_FUZZ_DIR/infra/base-images/base-builder/compile"
if ! grep -q "tree-sitter>=0.25.0" "$COMPILE_FILE"; then
	# Find the line after "python3 -m pip install --prefer-binary matplotlib"
	# and add the tree-sitter upgrade and --no-deps install
	sed -i '/python3 -m pip install --prefer-binary matplotlib/a\
\
  # Force upgrade tree-sitter to 0.25+ for QueryCursor API\
  python3 -m pip install --upgrade '\''tree-sitter>=0.25.0'\'' tree-sitter-cpp tree-sitter-go tree-sitter-java tree-sitter-python tree-sitter-rust tree-sitter-languages' "$COMPILE_FILE"

	# Change "pip install -e ." to "pip install -e . --no-deps"
	sed -i 's/python3 -m pip install -e \./python3 -m pip install -e . --no-deps/g' "$COMPILE_FILE"
fi

# Step 6: Build the base-builder image
echo "Building base-builder image..."
cd "$OSS_FUZZ_DIR"
docker build --no-cache -t gcr.io/oss-fuzz-base/base-builder infra/base-images/base-builder

# Step 7: Build other base-builder images
echo "Building base-builder-python image..."
docker build --no-cache -t gcr.io/oss-fuzz-base/base-builder-python infra/base-images/base-builder-python

echo "Building base-builder-jvm image..."
docker build --no-cache -t gcr.io/oss-fuzz-base/base-builder-jvm infra/base-images/base-builder-jvm

echo "Building base-builder-rust image..."
docker build --no-cache -t gcr.io/oss-fuzz-base/base-builder-rust infra/base-images/base-builder-rust

echo "Building base-builder-go image..."
docker build --no-cache -t gcr.io/oss-fuzz-base/base-builder-go infra/base-images/base-builder-go

echo "Building base-runner image..."
docker build --no-cache -t gcr.io/oss-fuzz-base/base-runner infra/base-images/base-runner

echo ""
echo "=== Build complete! ==="
echo ""
echo "To run introspector on a project:"
echo "  cd $OSS_FUZZ_DIR"
echo "  python3 infra/helper.py introspector <project_name> --seconds 30"
echo ""
echo "Example:"
echo "  python3 infra/helper.py introspector htslib --seconds 30"
