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
"""Tests for all-functions row materialization backend boundary."""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import html_helpers  # noqa: E402
from fuzz_introspector import html_report  # noqa: E402


def _make_fake_project_profile() -> SimpleNamespace:
    function_name = "my_func"
    function_data = SimpleNamespace(
        function_name=function_name,
        function_source_file="src/my_file.c",
        function_linenumber=123,
        hitcount=1,
        reached_by_fuzzers=["fuzzA"],
        hitcount_runtime=0,
        reached_by_fuzzers_runtime=[],
        hitcount_combined=0,
        reached_by_fuzzers_combined=[],
        arg_count=1,
        arg_types=["int"],
        function_depth=2,
        i_count=5,
        bb_count=3,
        cyclomatic_complexity=2,
        functions_reached=["child"],
        incoming_references=["parent"],
        total_cyclomatic_complexity=8,
        new_unreached_complexity=1,
        assert_list=[],
        signature="int my_func(int)",
        arg_names=["x"],
        return_type="int",
        raw_function_name=function_name,
        callsite=[],
        function_line_number_end=130,
        is_accessible=True,
        is_jvm_library=False,
        is_enum=False,
        is_static=False,
        need_close=False,
        exceptions=[],
    )
    all_funcs_with_source = {function_name: function_data}
    runtime_coverage = SimpleNamespace(
        get_hit_summary=lambda _name: (4, 3),
        is_func_hit=lambda _name: True,
    )
    return SimpleNamespace(
        target_lang="c-cpp",
        runtime_coverage=runtime_coverage,
        get_all_functions_with_source=lambda: all_funcs_with_source,
        get_func_hit_percentage=lambda _name: 75.0,
        resolve_coverage_report_link=lambda *_args: "coverage-link",
    )


class _RuntimeCoverageSpy:
    def __init__(self, summary_by_name: dict[str, tuple[int | None, int | None]]):
        self.summary_by_name = summary_by_name
        self.get_hit_summary_calls = 0
        self.is_func_hit_calls = 0

    def get_hit_summary(self, function_name: str) -> tuple[int | None, int | None]:
        self.get_hit_summary_calls += 1
        return self.summary_by_name[function_name]

    def is_func_hit(self, _function_name: str) -> bool:
        self.is_func_hit_calls += 1
        raise AssertionError("is_func_hit should not be called")


def _make_multi_function_project_profile(
    runtime_coverage: _RuntimeCoverageSpy,
) -> SimpleNamespace:
    function_names = list(runtime_coverage.summary_by_name.keys())
    all_funcs_with_source = {}
    for idx, function_name in enumerate(function_names):
        all_funcs_with_source[function_name] = SimpleNamespace(
            function_name=function_name,
            function_source_file=f"src/{function_name}.c",
            function_linenumber=100 + idx,
            hitcount=0,
            reached_by_fuzzers=[],
            hitcount_runtime=0,
            reached_by_fuzzers_runtime=[],
            hitcount_combined=0,
            reached_by_fuzzers_combined=[],
            arg_count=0,
            arg_types=[],
            function_depth=1,
            i_count=1,
            bb_count=1,
            cyclomatic_complexity=1,
            functions_reached=[],
            incoming_references=[],
            total_cyclomatic_complexity=1,
            new_unreached_complexity=0,
            assert_list=[],
            signature="",
            arg_names=[],
            return_type="void",
            raw_function_name=function_name,
            callsite=[],
            function_line_number_end=100 + idx,
            is_accessible=True,
            is_jvm_library=False,
            is_enum=False,
            is_static=False,
            need_close=False,
            exceptions=[],
        )
    return SimpleNamespace(
        target_lang="c-cpp",
        runtime_coverage=runtime_coverage,
        get_all_functions_with_source=lambda: all_funcs_with_source,
        resolve_coverage_report_link=lambda *_args: "coverage-link",
    )


def test_parse_all_functions_rows_backend_and_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_ALL_FUNCTIONS_ROWS_BACKEND", raising=False)
    monkeypatch.delenv("FI_ALL_FUNCTIONS_ROWS_SHADOW", raising=False)
    monkeypatch.delenv("FI_ALL_FUNCTIONS_ROWS_STRICT", raising=False)
    assert html_report._parse_all_functions_rows_backend() == "rust"
    assert html_report._parse_all_functions_rows_shadow() is False
    assert html_report._parse_all_functions_rows_strict() is False

    monkeypatch.setenv("FI_ALL_FUNCTIONS_ROWS_BACKEND", "rust")
    monkeypatch.setenv("FI_ALL_FUNCTIONS_ROWS_SHADOW", "yes")
    monkeypatch.setenv("FI_ALL_FUNCTIONS_ROWS_STRICT", "1")
    assert html_report._parse_all_functions_rows_backend() == "rust"
    assert html_report._parse_all_functions_rows_shadow() is True
    assert html_report._parse_all_functions_rows_strict() is True


def test_parse_all_functions_rows_backend_invalid_defaults_to_rust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_ALL_FUNCTIONS_ROWS_BACKEND", "invalid-backend")
    assert html_report._parse_all_functions_rows_backend() == "rust"


def test_create_all_function_table_rust_backend_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("FI_ALL_FUNCTIONS_ROWS_BACKEND", "rust")
    monkeypatch.setattr(
        html_report, "_get_cached_native_function_table_order", lambda _profile: None
    )
    proj_profile = _make_fake_project_profile()

    with caplog.at_level("INFO"):
        _, _, rows_report = html_report.create_all_function_table(
            tables=["t0"],
            proj_profile=proj_profile,
            coverage_url="",
            out_dir="",
            table_id="table_id",
        )

    assert len(rows_report) == 1
    assert rows_report[0]["Func name"] == "my_func"
    assert any("falling back to python" in record.message for record in caplog.records)


def test_create_all_function_table_rust_backend_strict_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted_markers = []

    def _record_emit(out_dir: str, stage: str, event: str, **meta) -> None:
        emitted_markers.append((out_dir, stage, event, meta))

    monkeypatch.setenv("FI_ALL_FUNCTIONS_ROWS_BACKEND", "rust")
    monkeypatch.setenv("FI_ALL_FUNCTIONS_ROWS_STRICT", "1")
    monkeypatch.setattr(html_report.stage_markers, "emit", _record_emit)
    monkeypatch.setattr(
        html_report, "_get_cached_native_function_table_order", lambda _profile: None
    )
    proj_profile = _make_fake_project_profile()

    with pytest.raises(html_report.FuzzIntrospectorError):
        html_report.create_all_function_table(
            tables=["t0"],
            proj_profile=proj_profile,
            coverage_url="",
            out_dir="",
            table_id="table_id",
        )

    assert [event[2] for event in emitted_markers] == ["start", "end"]
    assert emitted_markers[1][3]["status"] == "error"
    assert emitted_markers[1][3]["error_type"] == "FuzzIntrospectorError"


def test_create_all_function_table_emits_materialization_stage_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted_markers = []

    def _record_emit(out_dir: str, stage: str, event: str, **meta) -> None:
        emitted_markers.append((out_dir, stage, event, meta))

    monkeypatch.setattr(html_report.stage_markers, "emit", _record_emit)
    monkeypatch.setattr(
        html_report, "_get_cached_native_function_table_order", lambda _profile: None
    )
    proj_profile = _make_fake_project_profile()

    html_report.create_all_function_table(
        tables=["t0"],
        proj_profile=proj_profile,
        coverage_url="",
        out_dir="/tmp/materialization-markers",
        table_id="table_id",
    )

    assert len(emitted_markers) == 2
    assert emitted_markers[0][0] == "/tmp/materialization-markers"
    assert emitted_markers[0][1] == "all_functions_materialization"
    assert emitted_markers[0][2] == "start"
    assert emitted_markers[0][3]["backend"] == "python"
    assert emitted_markers[0][3]["configured_backend"] == "rust"
    assert emitted_markers[1][1] == "all_functions_materialization"
    assert emitted_markers[1][2] == "end"
    assert emitted_markers[1][3]["configured_backend"] == "rust"
    assert emitted_markers[1][3]["rows"] == 1
    assert emitted_markers[1][3]["status"] == "success"
    assert emitted_markers[1][3]["error_type"] == ""


def test_create_all_function_table_stage_markers_reflect_rust_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted_markers = []

    def _record_emit(out_dir: str, stage: str, event: str, **meta) -> None:
        emitted_markers.append((out_dir, stage, event, meta))

    monkeypatch.setenv("FI_ALL_FUNCTIONS_ROWS_BACKEND", "rust")
    monkeypatch.setattr(html_report.stage_markers, "emit", _record_emit)
    monkeypatch.setattr(
        html_report, "_get_cached_native_function_table_order", lambda _profile: None
    )
    proj_profile = _make_fake_project_profile()

    html_report.create_all_function_table(
        tables=["t0"],
        proj_profile=proj_profile,
        coverage_url="",
        out_dir="/tmp/materialization-markers-rust-fallback",
        table_id="table_id",
    )

    assert emitted_markers[0][2] == "start"
    assert emitted_markers[0][3]["configured_backend"] == "rust"
    assert emitted_markers[0][3]["backend"] == "python"
    assert emitted_markers[1][2] == "end"
    assert emitted_markers[1][3]["configured_backend"] == "rust"
    assert emitted_markers[1][3]["backend"] == "python"
    assert emitted_markers[1][3]["status"] == "success"


def test_create_all_function_table_emits_end_marker_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted_markers = []

    def _record_emit(out_dir: str, stage: str, event: str, **meta) -> None:
        emitted_markers.append((out_dir, stage, event, meta))

    def _raise_runtime_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(html_report.stage_markers, "emit", _record_emit)
    monkeypatch.setattr(
        html_report, "_get_cached_native_function_table_order", lambda _profile: None
    )
    proj_profile = _make_fake_project_profile()
    proj_profile.resolve_coverage_report_link = _raise_runtime_error

    with pytest.raises(RuntimeError, match="boom"):
        html_report.create_all_function_table(
            tables=["t0"],
            proj_profile=proj_profile,
            coverage_url="",
            out_dir="/tmp/materialization-markers-error",
            table_id="table_id",
        )

    assert [event[2] for event in emitted_markers] == ["start", "end"]
    assert emitted_markers[1][3]["status"] == "error"
    assert emitted_markers[1][3]["error_type"] == "RuntimeError"


def test_create_section_all_functions_forwards_out_dir_to_table_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_all_function_table_args = {}

    def _fake_create_all_function_table(
        tables,
        proj_profile,
        coverage_url,
        out_dir,
        table_id,
    ):
        create_all_function_table_args["out_dir"] = out_dir
        return "table", [], []

    monkeypatch.setattr(
        html_report,
        "create_all_function_table",
        _fake_create_all_function_table,
    )

    html_report.create_section_all_functions(
        table_of_contents=html_helpers.HtmlTableOfContents(),
        tables=[],
        proj_profile=_make_fake_project_profile(),
        coverage_url="",
        basefolder="/tmp/base-folder",
        out_dir="/tmp/report-out-dir",
    )

    assert create_all_function_table_args["out_dir"] == "/tmp/report-out-dir"


def test_create_all_function_table_coverage_semantics_preserved() -> None:
    runtime_coverage = _RuntimeCoverageSpy(
        {
            "func_a": (4, 1),
            "func_b": (10, 0),
            "func_c": (None, None),
            "func_d": (0, 0),
            "func_e": (0, 1),
        }
    )
    proj_profile = _make_multi_function_project_profile(runtime_coverage)

    _, _, rows_report = html_report.create_all_function_table(
        tables=["t0"],
        proj_profile=proj_profile,
        coverage_url="",
        out_dir="",
        table_id="table_id",
    )

    rows_by_name = {row["Func name"]: row for row in rows_report}
    assert rows_by_name["func_a"]["Func lines hit %"] == "25.0%"
    assert rows_by_name["func_a"]["Fuzzers runtime hit"] == "yes"
    assert rows_by_name["func_b"]["Func lines hit %"] == "0.0%"
    assert rows_by_name["func_b"]["Fuzzers runtime hit"] == "no"
    assert rows_by_name["func_c"]["Func lines hit %"] == "0.0%"
    assert rows_by_name["func_c"]["Fuzzers runtime hit"] == "no"
    assert rows_by_name["func_d"]["Func lines hit %"] == "0.0%"
    assert rows_by_name["func_d"]["Fuzzers runtime hit"] == "no"
    assert rows_by_name["func_e"]["Func lines hit %"] == "0.0%"
    assert rows_by_name["func_e"]["Fuzzers runtime hit"] == "yes"


def test_create_all_function_table_uses_single_hit_summary_lookup_per_function() -> (
    None
):
    runtime_coverage = _RuntimeCoverageSpy(
        {
            "func_a": (4, 1),
            "func_b": (4, 0),
            "func_c": (4, 2),
        }
    )
    proj_profile = _make_multi_function_project_profile(runtime_coverage)

    html_report.create_all_function_table(
        tables=["t0"],
        proj_profile=proj_profile,
        coverage_url="",
        out_dir="",
        table_id="table_id",
    )

    assert runtime_coverage.get_hit_summary_calls == 3
    assert runtime_coverage.is_func_hit_calls == 0
