#!/bin/bash
# Temporary test runner for verifying no regressions

set -e

echo "========================================"
echo "Running full test suite verification"
echo "========================================"
echo ""

# Activate venv
source .venv/bin/activate

# Run pytest from repo root (critical per AGENTS.md)
echo "Step 1: Running full Python test suite..."
echo "========================================"
python -m pytest -vv src/test/ 2>&1

echo ""
echo "Step 2: Running code checks (linting, formatting, type checking)..."
echo "========================================"
./code_checks.sh 2>&1

echo ""
echo "========================================"
echo "All checks completed!"
echo "========================================"
