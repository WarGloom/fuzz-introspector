#!/bin/bash
# Full test suite runner matching CI behavior

set -e

cd /home/nikita/work/Projects/cg/fuzz-introspector

echo "========================================"
echo "Full Test Suite Verification"
echo "========================================"
echo ""

# Activate venv
source .venv/bin/activate

echo "Python version:"
python --version
echo ""

echo "Pytest version:"
python -m pytest --version
echo ""

echo "========================================"
echo "Step 1: Running Python unit tests with coverage"
echo "========================================"
coverage run -m pytest -vv src/test/

echo ""
echo "========================================"
echo "Step 2: Coverage Report"
echo "========================================"
coverage report -m

echo ""
echo "========================================"
echo "Step 3: Code checks (linting, formatting, type checking)"
echo "========================================"
./code_checks.sh

echo ""
echo "========================================"
echo "✅ ALL CHECKS COMPLETED SUCCESSFULLY!"
echo "========================================"
