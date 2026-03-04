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
"""Tests for benchmarks/run_stage_marker_gate.py."""

import argparse
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "benchmarks" / "run_stage_marker_gate.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "run_stage_marker_gate", MODULE_PATH
)
assert MODULE_SPEC is not None
assert MODULE_SPEC.loader is not None
run_stage_marker_gate = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(run_stage_marker_gate)


class TestRunStageMarkerGate(unittest.TestCase):
    """Covers command construction and process return code propagation."""

    def test_build_validator_command_uses_standard_defaults(self):
        args = argparse.Namespace(
            python_bin="python3",
            baseline_log="/tmp/baseline.log",
            candidate_log="/tmp/candidate.log",
            stages=run_stage_marker_gate.DEFAULT_STAGES,
            max_regression_percent=run_stage_marker_gate.DEFAULT_MAX_REGRESSION_PERCENT,
            output_json="/tmp/out.json",
        )

        command = run_stage_marker_gate.build_validator_command(args)

        self.assertEqual(command[0], "python3")
        self.assertEqual(command[1], str(run_stage_marker_gate.VALIDATOR_SCRIPT))
        self.assertIn("--baseline-log", command)
        self.assertIn("--candidate-log", command)
        self.assertIn("--stages", command)
        self.assertIn("--max-regression-percent", command)
        self.assertIn("--output-json", command)
        self.assertIn(
            "optional_analyses,report_generation,type_correlation",
            command,
        )
        self.assertIn("10.0", command)

    def test_main_uses_default_stages_when_not_specified(self):
        argv = [
            "run_stage_marker_gate.py",
            "--baseline-log",
            "baseline.log",
            "--candidate-log",
            "candidate.log",
            "--output-json",
            "result.json",
        ]
        completed = subprocess.CompletedProcess(args=["x"], returncode=0)

        with mock.patch.object(sys, "argv", argv):
            with mock.patch.object(
                run_stage_marker_gate.subprocess,
                "run",
                return_value=completed,
            ) as run_mock:
                result = run_stage_marker_gate.main()

        self.assertEqual(result, 0)
        command = run_mock.call_args.args[0]
        self.assertEqual(
            command[command.index("--stages") + 1],
            "optional_analyses,report_generation,type_correlation",
        )

    def test_main_returns_validator_exit_code(self):
        argv = [
            "run_stage_marker_gate.py",
            "--baseline-log",
            "baseline.log",
            "--candidate-log",
            "candidate.log",
            "--output-json",
            "result.json",
        ]
        completed = subprocess.CompletedProcess(args=["x"], returncode=1)

        with mock.patch.object(sys, "argv", argv):
            with mock.patch.object(
                run_stage_marker_gate.subprocess,
                "run",
                return_value=completed,
            ) as run_mock:
                result = run_stage_marker_gate.main()

        self.assertEqual(result, 1)
        self.assertTrue(run_mock.called)


if __name__ == "__main__":
    unittest.main()
