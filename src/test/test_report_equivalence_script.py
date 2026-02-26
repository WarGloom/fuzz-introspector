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
"""Tests for scripts/check_report_equivalence.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest


def _load_script_module() -> types.ModuleType:
    script_path = (Path(__file__).resolve().parents[2] / "scripts" /
                   "check_report_equivalence.py")
    spec = importlib.util.spec_from_file_location("check_report_equivalence",
                                                  script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load check_report_equivalence.py")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.fixture(name="equivalence_script")
def fixture_equivalence_script() -> types.ModuleType:
    return _load_script_module()


def _write_report_dir(
    report_dir: Path,
    summary_payload: dict[str, object],
    html_payload: str,
    all_functions_payload: object,
    fuzzer_table_payload: object,
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "summary.json").write_text(json.dumps(summary_payload),
                                             encoding="utf-8")
    (report_dir / "fuzz_report.html").write_text(html_payload, encoding="utf-8")
    (report_dir / "all_functions.js").write_text(
        "var all_functions_table_data = " +
        json.dumps(all_functions_payload),
        encoding="utf-8",
    )
    (report_dir / "fuzzer_table_data.js").write_text(
        "var fuzzer_table_data = " + json.dumps(fuzzer_table_payload),
        encoding="utf-8",
    )


def test_equivalent_reports_pass_with_default_normalization(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    equivalence_script: types.ModuleType,
) -> None:
    left_dir = tmp_path / "left"
    right_dir = tmp_path / "right"

    _write_report_dir(
        left_dir,
        summary_payload={
            "analyses": {
                "alpha": {
                    "score": 12
                }
            },
            "project": "demo",
        },
        html_payload="<html><body><div>stable content</div></body></html>",
        all_functions_payload=[{
            "Func name": "foo",
            "Complexity": 7
        }],
        fuzzer_table_payload={"fuzzers": ["fuzz-a", "fuzz-b"]},
    )
    _write_report_dir(
        right_dir,
        summary_payload={
            "project": "demo",
            "analyses": {
                "alpha": {
                    "score": 12
                }
            },
        },
        html_payload="""
            <html>
              <body>
                <div>stable content</div>
              </body>
            </html>
        """,
        all_functions_payload=[{
            "Complexity": 7,
            "Func name": "foo"
        }],
        fuzzer_table_payload={"fuzzers": ["fuzz-a", "fuzz-b"]},
    )

    exit_code = equivalence_script.main([str(left_dir), str(right_dir)])
    stdout = capsys.readouterr().out

    assert exit_code == 0
    assert "Result: equivalent" in stdout


def test_list_order_diff_can_be_normalized_with_sort_lists_at(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    equivalence_script: types.ModuleType,
) -> None:
    left_dir = tmp_path / "left"
    right_dir = tmp_path / "right"

    _write_report_dir(
        left_dir,
        summary_payload={"project": "demo"},
        html_payload="<html><body><div>same</div></body></html>",
        all_functions_payload=[{
            "Func name": "a"
        }, {
            "Func name": "b"
        }],
        fuzzer_table_payload={"fuzzers": ["fuzz-a"]},
    )
    _write_report_dir(
        right_dir,
        summary_payload={"project": "demo"},
        html_payload="<html><body><div>same</div></body></html>",
        all_functions_payload=[{
            "Func name": "b"
        }, {
            "Func name": "a"
        }],
        fuzzer_table_payload={"fuzzers": ["fuzz-a"]},
    )

    without_norm = equivalence_script.main([str(left_dir), str(right_dir)])
    assert without_norm == 1

    capsys.readouterr()
    with_norm = equivalence_script.main([
        str(left_dir),
        str(right_dir),
        "--sort-lists-at",
        "all_functions.js:$",
    ])
    stdout = capsys.readouterr().out

    assert with_norm == 0
    assert "Result: equivalent" in stdout


def test_meaningful_diff_emits_markdown_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    equivalence_script: types.ModuleType,
) -> None:
    left_dir = tmp_path / "left"
    right_dir = tmp_path / "right"
    markdown_path = tmp_path / "diffs" / "equivalence.md"

    _write_report_dir(
        left_dir,
        summary_payload={"metrics": {"covered": 10}},
        html_payload="<html><body><div>same</div></body></html>",
        all_functions_payload=[{
            "Func name": "a"
        }],
        fuzzer_table_payload={"fuzzers": ["fuzz-a"]},
    )
    _write_report_dir(
        right_dir,
        summary_payload={"metrics": {"covered": 11}},
        html_payload="<html><body><div>same</div></body></html>",
        all_functions_payload=[{
            "Func name": "a"
        }],
        fuzzer_table_payload={"fuzzers": ["fuzz-a"]},
    )

    exit_code = equivalence_script.main([
        str(left_dir),
        str(right_dir),
        "--markdown-report",
        str(markdown_path),
    ])
    stdout = capsys.readouterr().out

    assert exit_code == 1
    assert "summary.json" in stdout
    assert markdown_path.is_file()
    markdown_content = markdown_path.read_text(encoding="utf-8")
    assert "# Report Equivalence" in markdown_content
    assert "summary.json" in markdown_content
    assert "```diff" in markdown_content


def test_missing_required_artifact_is_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    equivalence_script: types.ModuleType,
) -> None:
    left_dir = tmp_path / "left"
    right_dir = tmp_path / "right"
    _write_report_dir(
        left_dir,
        summary_payload={"project": "demo"},
        html_payload="<html><body><div>same</div></body></html>",
        all_functions_payload=[],
        fuzzer_table_payload={},
    )
    _write_report_dir(
        right_dir,
        summary_payload={"project": "demo"},
        html_payload="<html><body><div>same</div></body></html>",
        all_functions_payload=[],
        fuzzer_table_payload={},
    )
    (right_dir / "fuzz_report.html").unlink()

    exit_code = equivalence_script.main([str(left_dir), str(right_dir)])
    stdout = capsys.readouterr().out

    assert exit_code == 1
    assert "fuzz_report.html" in stdout
    assert "missing in right report directory" in stdout
