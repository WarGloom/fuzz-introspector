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
"""Tests for serial compatibility adapter in HTML report generation."""

from pathlib import Path
from types import SimpleNamespace

from fuzz_introspector import analyses as analyses_registry
from fuzz_introspector import html_helpers
from fuzz_introspector import html_report


def _make_dummy_analysis(name, html_fragment, calls, include_ui_fields=False):

    class DummyAnalysis:
        def __init__(self):
            self.display_html = False

        @classmethod
        def get_name(cls):
            return name

        def analysis_func(self, *args, **kwargs):
            calls.append(name)
            if include_ui_fields:
                table_of_contents = args[0]
                tables = args[1]
                conclusions = args[6]
                table_of_contents.add_entry(
                    f"{name} heading",
                    f"{name}-heading",
                    html_helpers.HTML_HEADING.H2,
                )
                tables.append(f"{name}-table")
                conclusions.append(
                    html_helpers.HTMLConclusion(
                        severity=1,
                        title=f"{name} conclusion",
                        description=f"{name} description",
                    )
                )
            return html_fragment

        def set_display_html(self, value):
            self.display_html = value

    return DummyAnalysis


def _make_project_stub():
    return SimpleNamespace(
        optional_analyses=[],
        proj_profile=SimpleNamespace(basefolder="/tmp", coverage_url=""),
        profiles=[],
    )


def _run_optional_analyses_fixture(monkeypatch, tmp_path: Path, worker_count: int):
    calls = []
    analysis_hidden = _make_dummy_analysis(
        "AnalysisHidden",
        "<div>hidden</div>",
        calls,
        include_ui_fields=True,
    )
    analysis_visible = _make_dummy_analysis(
        "AnalysisVisible",
        "<div>visible</div>",
        calls,
        include_ui_fields=True,
    )

    monkeypatch.setattr(
        html_report.analysis,
        "get_all_analyses",
        lambda: [analysis_hidden, analysis_visible],
    )
    monkeypatch.setattr(
        analyses_registry,
        "all_analyses",
        [analysis_hidden, analysis_visible],
    )
    monkeypatch.setattr(
        analyses_registry,
        "analysis_parallel_compatibility",
        {
            analysis_hidden: analyses_registry.PARALLEL_COMPATIBILITY_SERIAL_ONLY,
            analysis_visible: analyses_registry.PARALLEL_COMPATIBILITY_SERIAL_ONLY,
        },
    )
    monkeypatch.setattr(
        html_report,
        "_parse_parallel_worker_count",
        lambda: worker_count,
    )

    table_of_contents = html_helpers.HtmlTableOfContents()
    tables = []
    conclusions = []
    out_dir = tmp_path / f"workers-{worker_count}"
    out_dir.mkdir(parents=True, exist_ok=True)

    html = html_report.create_section_optional_analyses(
        table_of_contents=table_of_contents,
        analyses_to_run=["AnalysisVisible"],
        output_json=["AnalysisHidden"],
        tables=tables,
        introspection_proj=_make_project_stub(),
        basefolder="/tmp",
        coverage_url="",
        conclusions=conclusions,
        dump_files=False,
        out_dir=str(out_dir),
    )

    return {
        "html": html,
        "calls": calls,
        "toc_titles": [entry.entry_title for entry in table_of_contents.entries],
        "table_ids": tables,
        "conclusion_titles": [conclusion.title for conclusion in conclusions],
    }


def test_serial_adapter_filters_display_html(monkeypatch):
    calls = []
    analysis_a = _make_dummy_analysis("AnalysisA", "<div>A</div>", calls)
    analysis_b = _make_dummy_analysis("AnalysisB", "<div>B</div>", calls)

    monkeypatch.setattr(analyses_registry, "all_analyses", [analysis_a, analysis_b])

    html = html_report.create_section_optional_analyses(
        table_of_contents=html_helpers.HtmlTableOfContents(),
        analyses_to_run=["AnalysisB"],
        output_json=["AnalysisA"],
        tables=[],
        introspection_proj=_make_project_stub(),
        basefolder="/tmp",
        coverage_url="",
        conclusions=[],
        dump_files=False,
        out_dir="/tmp",
    )

    assert calls == ["AnalysisA", "AnalysisB"]
    assert "<div>A</div>" not in html
    assert "<div>B</div>" in html


def test_serial_adapter_preserves_registry_order(monkeypatch):
    calls = []
    analysis_b = _make_dummy_analysis("AnalysisB", "<div>B</div>", calls)
    analysis_a = _make_dummy_analysis("AnalysisA", "<div>A</div>", calls)

    monkeypatch.setattr(analyses_registry, "all_analyses", [analysis_b, analysis_a])

    html = html_report.create_section_optional_analyses(
        table_of_contents=html_helpers.HtmlTableOfContents(),
        analyses_to_run=["AnalysisA", "AnalysisB"],
        output_json=[],
        tables=[],
        introspection_proj=_make_project_stub(),
        basefolder="/tmp",
        coverage_url="",
        conclusions=[],
        dump_files=False,
        out_dir="/tmp",
    )

    assert calls == ["AnalysisB", "AnalysisA"]
    assert "<div>B</div>" in html
    assert "<div>A</div>" in html
    assert html.index("<div>B</div>") < html.index("<div>A</div>")


def test_serial_compat_envelope_drops_hidden_html_fragment(monkeypatch):
    calls = []
    analysis_hidden = _make_dummy_analysis(
        "AnalysisHidden",
        "<div>hidden</div>",
        calls,
        include_ui_fields=True,
    )
    analysis_visible = _make_dummy_analysis(
        "AnalysisVisible", "<div>visible</div>", calls
    )

    monkeypatch.setattr(
        html_report.analysis,
        "get_all_analyses",
        lambda: [analysis_hidden, analysis_visible],
    )
    monkeypatch.setattr(
        analyses_registry, "all_analyses", [analysis_hidden, analysis_visible]
    )
    monkeypatch.setattr(
        analyses_registry,
        "analysis_parallel_compatibility",
        {
            analysis_hidden: analyses_registry.PARALLEL_COMPATIBILITY_SERIAL_ONLY,
            analysis_visible: analyses_registry.PARALLEL_COMPATIBILITY_SERIAL_ONLY,
        },
    )

    captured_envelopes = {}

    class FakeMergeCoordinator:
        def __init__(self, out_dir):
            self.out_dir = out_dir

        def add_analysis_result(self, analysis_name, envelope):
            captured_envelopes[analysis_name] = envelope

        def merge_results(self):
            return True, {
                "conclusions": [],
                "toc_entries": [],
                "table_ids": [],
                "html_fragments": [],
            }

    monkeypatch.setattr(
        html_report.merge_coordinator, "MergeCoordinator", FakeMergeCoordinator
    )
    monkeypatch.setattr(html_report, "_parse_parallel_worker_count", lambda: 2)

    html_report.create_section_optional_analyses(
        table_of_contents=html_helpers.HtmlTableOfContents(),
        analyses_to_run=["AnalysisVisible"],
        output_json=["AnalysisHidden"],
        tables=[],
        introspection_proj=_make_project_stub(),
        basefolder="/tmp",
        coverage_url="",
        conclusions=[],
        dump_files=False,
        out_dir="/tmp",
    )

    assert calls == ["AnalysisHidden", "AnalysisVisible"]
    assert captured_envelopes["AnalysisHidden"]["display_html"] is False
    assert captured_envelopes["AnalysisHidden"]["html_fragment"] == ""
    assert captured_envelopes["AnalysisHidden"]["conclusions"] == []
    assert captured_envelopes["AnalysisHidden"]["toc_entries"] == []
    assert captured_envelopes["AnalysisHidden"]["table_ids"] == []
    assert captured_envelopes["AnalysisVisible"]["display_html"] is True
    assert (
        captured_envelopes["AnalysisVisible"]["html_fragment"] == "<div>visible</div>"
    )


def test_serial_single_worker_keeps_hidden_ui_local(monkeypatch):
    calls = []
    analysis_hidden = _make_dummy_analysis(
        "AnalysisHidden",
        "<div>hidden</div>",
        calls,
        include_ui_fields=True,
    )
    analysis_visible = _make_dummy_analysis(
        "AnalysisVisible",
        "<div>visible</div>",
        calls,
        include_ui_fields=True,
    )

    monkeypatch.setattr(
        html_report.analysis,
        "get_all_analyses",
        lambda: [analysis_hidden, analysis_visible],
    )
    monkeypatch.setattr(
        analyses_registry, "all_analyses", [analysis_hidden, analysis_visible]
    )
    monkeypatch.setattr(html_report, "_parse_parallel_worker_count", lambda: 1)

    table_of_contents = html_helpers.HtmlTableOfContents()
    tables = []
    conclusions = []

    html = html_report.create_section_optional_analyses(
        table_of_contents=table_of_contents,
        analyses_to_run=["AnalysisVisible"],
        output_json=["AnalysisHidden"],
        tables=tables,
        introspection_proj=_make_project_stub(),
        basefolder="/tmp",
        coverage_url="",
        conclusions=conclusions,
        dump_files=False,
        out_dir="/tmp",
    )

    assert calls == ["AnalysisHidden", "AnalysisVisible"]
    assert "<div>hidden</div>" not in html
    assert "<div>visible</div>" in html
    toc_titles = [entry.entry_title for entry in table_of_contents.entries]
    assert "AnalysisHidden heading" not in toc_titles
    assert "AnalysisVisible heading" in toc_titles
    assert tables == ["AnalysisVisible-table"]
    assert len(conclusions) == 1
    assert conclusions[0].title == "AnalysisVisible conclusion"


def test_optional_analyses_hidden_visible_parity_across_worker_modes(
    monkeypatch,
    tmp_path: Path,
):
    serial_result = _run_optional_analyses_fixture(monkeypatch, tmp_path, 1)
    parallel_result = _run_optional_analyses_fixture(monkeypatch, tmp_path, 2)

    assert serial_result["calls"] == ["AnalysisHidden", "AnalysisVisible"]
    assert parallel_result["calls"] == ["AnalysisHidden", "AnalysisVisible"]

    # Hidden analysis must not leak UI artifacts in either mode.
    for mode_result in [serial_result, parallel_result]:
        assert "<div>hidden</div>" not in mode_result["html"]
        assert "AnalysisHidden heading" not in mode_result["toc_titles"]
        assert "AnalysisHidden-table" not in mode_result["table_ids"]
        assert "AnalysisHidden conclusion" not in mode_result["conclusion_titles"]

    # Visible outputs should remain consistent between worker_count=1 and >1.
    assert serial_result["html"].count("<div>visible</div>") == 1
    assert parallel_result["html"].count("<div>visible</div>") == 1

    serial_toc_titles = [
        title
        for title in serial_result["toc_titles"]
        if title != "Analyses and suggestions"
    ]
    parallel_toc_titles = [
        title
        for title in parallel_result["toc_titles"]
        if title != "Analyses and suggestions"
    ]
    assert serial_toc_titles == parallel_toc_titles == ["AnalysisVisible heading"]
    assert (
        serial_result["table_ids"]
        == parallel_result["table_ids"]
        == ["AnalysisVisible-table"]
    )
    assert (
        serial_result["conclusion_titles"]
        == parallel_result["conclusion_titles"]
        == ["AnalysisVisible conclusion"]
    )


def test_parallel_safe_visible_analysis_parity_across_worker_modes(
    monkeypatch,
    tmp_path: Path,
):
    def run_fixture(worker_count: int):
        calls = []
        parallel_safe_visible = _make_dummy_analysis(
            "ParallelSafeVisible",
            "<div>parallel-visible</div>",
            calls,
            include_ui_fields=True,
        )

        monkeypatch.setattr(
            html_report.analysis,
            "get_all_analyses",
            lambda: [parallel_safe_visible],
        )
        monkeypatch.setattr(analyses_registry, "all_analyses", [parallel_safe_visible])
        monkeypatch.setattr(
            analyses_registry,
            "analysis_parallel_compatibility",
            {
                parallel_safe_visible: analyses_registry.PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
            },
        )
        monkeypatch.setattr(
            html_report,
            "_parse_parallel_worker_count",
            lambda: worker_count,
        )
        monkeypatch.setattr(
            html_report,
            "_parse_parallel_backend",
            lambda: "thread",
        )

        table_of_contents = html_helpers.HtmlTableOfContents()
        tables = []
        conclusions = []
        out_dir = tmp_path / f"parallel-safe-workers-{worker_count}"
        out_dir.mkdir(parents=True, exist_ok=True)

        html = html_report.create_section_optional_analyses(
            table_of_contents=table_of_contents,
            analyses_to_run=["ParallelSafeVisible"],
            output_json=[],
            tables=tables,
            introspection_proj=_make_project_stub(),
            basefolder="/tmp",
            coverage_url="",
            conclusions=conclusions,
            dump_files=False,
            out_dir=str(out_dir),
        )

        visible_toc_titles = [
            entry.entry_title
            for entry in table_of_contents.entries
            if entry.entry_title.startswith("ParallelSafeVisible")
        ]

        return {
            "calls": calls,
            "html": html,
            "visible_toc_titles": visible_toc_titles,
            "visible_table_ids": [
                table_id
                for table_id in tables
                if table_id.startswith("ParallelSafeVisible")
            ],
            "visible_conclusion_titles": [
                conclusion.title
                for conclusion in conclusions
                if conclusion.title.startswith("ParallelSafeVisible")
            ],
        }

    single_worker_result = run_fixture(1)
    two_worker_result = run_fixture(2)

    assert single_worker_result["calls"] == ["ParallelSafeVisible"]
    assert two_worker_result["calls"] == ["ParallelSafeVisible"]
    assert single_worker_result["html"].count("<div>parallel-visible</div>") == 1
    assert two_worker_result["html"].count("<div>parallel-visible</div>") == 1
    assert (
        single_worker_result["visible_toc_titles"]
        == two_worker_result["visible_toc_titles"]
        == ["ParallelSafeVisible heading"]
    )
    assert (
        single_worker_result["visible_table_ids"]
        == two_worker_result["visible_table_ids"]
        == ["ParallelSafeVisible-table"]
    )
    assert (
        single_worker_result["visible_conclusion_titles"]
        == two_worker_result["visible_conclusion_titles"]
        == ["ParallelSafeVisible conclusion"]
    )


def test_parallel_safe_multiple_analyses_merge_and_parallel_path(
    monkeypatch,
    tmp_path: Path,
):
    calls = []
    parallel_safe_a = _make_dummy_analysis(
        "ParallelSafeA",
        "<div>parallel-a</div>",
        calls,
        include_ui_fields=True,
    )
    parallel_safe_b = _make_dummy_analysis(
        "ParallelSafeB",
        "<div>parallel-b</div>",
        calls,
        include_ui_fields=True,
    )

    monkeypatch.setattr(
        html_report.analysis,
        "get_all_analyses",
        lambda: [parallel_safe_a, parallel_safe_b],
    )
    monkeypatch.setattr(
        analyses_registry,
        "all_analyses",
        [parallel_safe_a, parallel_safe_b],
    )
    monkeypatch.setattr(
        analyses_registry,
        "analysis_parallel_compatibility",
        {
            parallel_safe_a: analyses_registry.PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
            parallel_safe_b: analyses_registry.PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
        },
    )
    monkeypatch.setattr(html_report, "_parse_parallel_worker_count", lambda: 2)
    monkeypatch.setattr(html_report, "_parse_parallel_backend", lambda: "thread")

    original_run_parallel_analyses = html_report._run_parallel_analyses
    parallel_call_spy = {}

    def _spy_run_parallel_analyses(
        analysis_interfaces,
        analyses_to_run,
        introspection_proj,
        basefolder,
        coverage_url,
        out_dir,
        dump_files,
        worker_count,
        table_id_offsets,
        backend,
    ):
        parallel_call_spy["called"] = True
        parallel_call_spy["analysis_names"] = [
            analysis_interface.get_name() for analysis_interface in analysis_interfaces
        ]
        parallel_call_spy["worker_count"] = worker_count
        parallel_call_spy["backend"] = backend
        return original_run_parallel_analyses(
            analysis_interfaces,
            analyses_to_run,
            introspection_proj,
            basefolder,
            coverage_url,
            out_dir,
            dump_files,
            worker_count,
            table_id_offsets,
            backend,
        )

    monkeypatch.setattr(
        html_report,
        "_run_parallel_analyses",
        _spy_run_parallel_analyses,
    )

    table_of_contents = html_helpers.HtmlTableOfContents()
    tables = []
    conclusions = []
    out_dir = tmp_path / "parallel-safe-multi"
    out_dir.mkdir(parents=True, exist_ok=True)

    html = html_report.create_section_optional_analyses(
        table_of_contents=table_of_contents,
        analyses_to_run=["ParallelSafeA", "ParallelSafeB"],
        output_json=[],
        tables=tables,
        introspection_proj=_make_project_stub(),
        basefolder="/tmp",
        coverage_url="",
        conclusions=conclusions,
        dump_files=False,
        out_dir=str(out_dir),
    )

    assert parallel_call_spy == {
        "called": True,
        "analysis_names": ["ParallelSafeA", "ParallelSafeB"],
        "worker_count": 2,
        "backend": "thread",
    }
    assert sorted(calls) == ["ParallelSafeA", "ParallelSafeB"]
    assert html.count("<div>parallel-a</div>") == 1
    assert html.count("<div>parallel-b</div>") == 1

    visible_toc_titles = {
        entry.entry_title
        for entry in table_of_contents.entries
        if entry.entry_title.startswith("ParallelSafe")
    }
    assert visible_toc_titles == {"ParallelSafeA heading", "ParallelSafeB heading"}

    visible_table_ids = {
        table_id for table_id in tables if table_id.startswith("ParallelSafe")
    }
    assert visible_table_ids == {"ParallelSafeA-table", "ParallelSafeB-table"}

    visible_conclusion_titles = {
        conclusion.title
        for conclusion in conclusions
        if conclusion.title.startswith("ParallelSafe")
    }
    assert visible_conclusion_titles == {
        "ParallelSafeA conclusion",
        "ParallelSafeB conclusion",
    }
