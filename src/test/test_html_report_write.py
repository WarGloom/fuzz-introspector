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
"""Tests for HTML report writing behavior."""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import constants, html_report, styling  # noqa: E402


def test_write_content_to_html_files_skips_prettify_when_disabled(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:

    def fail_if_prettified(_html_doc: str) -> str:
        raise AssertionError("prettify_html should not be called")

    monkeypatch.setenv("FI_DISABLE_HTML_PRETTIFY", "1")
    monkeypatch.setattr(html_report.html_helpers, "prettify_html",
                        fail_if_prettified)

    html_doc = "<html><body>raw</body></html>"
    html_report.write_content_to_html_files(html_doc, [], {}, str(tmp_path))

    report_path = tmp_path / constants.HTML_REPORT
    assert report_path.read_text(encoding="utf-8") == html_doc


def test_write_content_to_html_files_uses_prettify_by_default(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("FI_DISABLE_HTML_PRETTIFY", raising=False)
    monkeypatch.setenv("FI_PRETTIFY_MAX_DOC_MB", "10")
    monkeypatch.setattr(html_report.html_helpers, "prettify_html",
                        lambda _html_doc: "PRETTY")

    html_report.write_content_to_html_files("<html>ignored</html>", [], {},
                                            str(tmp_path))

    report_path = tmp_path / constants.HTML_REPORT
    assert report_path.read_text(encoding="utf-8") == "PRETTY"


def test_write_content_to_html_files_handles_invalid_prettify_env(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.delenv("FI_DISABLE_HTML_PRETTIFY", raising=False)
    monkeypatch.setenv("FI_PRETTIFY_MAX_DOC_MB", "not-a-number")
    monkeypatch.setattr(html_report.html_helpers, "prettify_html",
                        lambda _html_doc: "PRETTY")

    with caplog.at_level("WARNING"):
        html_report.write_content_to_html_files("<html>ignored</html>", [], {},
                                                str(tmp_path))

    report_path = tmp_path / constants.HTML_REPORT
    assert report_path.read_text(encoding="utf-8") == "PRETTY"
    assert any("Invalid FI_PRETTIFY_MAX_DOC_MB" in record.message
               for record in caplog.records)


def test_get_body_script_tags_does_not_mutate_main_js_list(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FI_INLINE_JS", raising=False)
    original = list(styling.MAIN_JS_FILES)

    html_report.get_body_script_tags([], {})
    html_report.get_body_script_tags([], {})

    assert styling.MAIN_JS_FILES == original


def test_parse_calltree_bitmap_max_nodes_env(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FI_CALLTREE_BITMAP_MAX_NODES", raising=False)
    assert html_report._parse_calltree_bitmap_max_nodes() == 20000

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "123")
    assert html_report._parse_calltree_bitmap_max_nodes() == 123

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "-1")
    assert html_report._parse_calltree_bitmap_max_nodes() == 20000

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "bad")
    assert html_report._parse_calltree_bitmap_max_nodes() == 20000


def test_parse_stage_warn_seconds_env(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FI_STAGE_WARN_SECONDS", raising=False)
    assert html_report._parse_stage_warn_seconds() == 0

    monkeypatch.setenv("FI_STAGE_WARN_SECONDS", "60")
    assert html_report._parse_stage_warn_seconds() == 60

    monkeypatch.setenv("FI_STAGE_WARN_SECONDS", "-5")
    assert html_report._parse_stage_warn_seconds() == 0

    monkeypatch.setenv("FI_STAGE_WARN_SECONDS", "bad")
    assert html_report._parse_stage_warn_seconds() == 0


def test_create_fuzzer_detailed_section_skips_bitmap_for_large_calltree(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        caplog: pytest.LogCaptureFixture) -> None:
    class DummyCalltreeAnalysis:

        def __init__(self):
            self.dump_files = False

        def create_calltree(self, _profile, out_dir):
            return os.path.join(out_dir, "calltree_view_0.html")

    class DummyProfile:
        identifier = "my/fuzzer"
        branch_blockers = []

        def get_callsites(self):
            return [
                SimpleNamespace(cov_color="red"),
                SimpleNamespace(cov_color="green"),
                SimpleNamespace(cov_color="yellow"),
            ]

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "2")
    monkeypatch.setattr(
        "fuzz_introspector.analyses.calltree_analysis.FuzzCalltreeAnalysis",
        DummyCalltreeAnalysis,
    )
    monkeypatch.setattr(
        html_report.html_helpers,
        "create_horisontal_calltree_image",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bitmap generation should be skipped")),
    )

    with caplog.at_level("INFO"):
        html = html_report.create_fuzzer_detailed_section(
            proj_profile=SimpleNamespace(has_coverage_data=lambda: False),
            profile=DummyProfile(),
            table_of_contents=html_report.html_helpers.HtmlTableOfContents(),
            tables=[],
            profile_idx=0,
            conclusions=[],
            extract_conclusion=False,
            fuzzer_table_data={},
            dump_files=True,
            out_dir=str(tmp_path),
        )

    assert "Call tree overview bitmap omitted" in html
    assert '<img class="colormap"' not in html
    assert any("Skipping calltree overview bitmap" in record.message
               for record in caplog.records)
