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
