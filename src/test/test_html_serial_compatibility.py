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


def _make_dummy_analysis(name, html_fragment, calls):

    class DummyAnalysis:

        def __init__(self):
            self.display_html = False

        @classmethod
        def get_name(cls):
            return name

        def analysis_func(self, *args, **kwargs):
            calls.append(name)
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

    monkeypatch.setattr(analyses_registry, "all_analyses",
                        [analysis_a, analysis_b])

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

    monkeypatch.setattr(analyses_registry, "all_analyses",
                        [analysis_b, analysis_a])

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
