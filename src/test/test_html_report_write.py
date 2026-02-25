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

import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import constants, html_report  # noqa: E402


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
