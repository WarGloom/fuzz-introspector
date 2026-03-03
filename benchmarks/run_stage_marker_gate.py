#!/usr/bin/env python3
# Copyright 2026 Fuzz Introspector Authors
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
"""Run the stage-marker regression gate with standard benchmark defaults."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_SCRIPT = REPO_ROOT / "benchmarks" / "validate_stage_marker_regression.py"
DEFAULT_STAGES = "optional_analyses,report_generation"
DEFAULT_MAX_REGRESSION_PERCENT = 10.0


def build_validator_command(args: argparse.Namespace) -> list[str]:
    """Build validator invocation command from CLI args."""
    return [
        args.python_bin,
        str(VALIDATOR_SCRIPT),
        "--baseline-log",
        args.baseline_log,
        "--candidate-log",
        args.candidate_log,
        "--stages",
        args.stages,
        "--max-regression-percent",
        str(args.max_regression_percent),
        "--output-json",
        args.output_json,
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-log", required=True)
    parser.add_argument("--candidate-log", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--stages", default=DEFAULT_STAGES)
    parser.add_argument(
        "--max-regression-percent",
        type=float,
        default=DEFAULT_MAX_REGRESSION_PERCENT,
    )
    parser.add_argument("--python-bin", default=sys.executable)
    args = parser.parse_args()

    command = build_validator_command(args)
    process = subprocess.run(command, check=False)
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
