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
"""Focused tests for coverage link cache behavior in utils."""

import json
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import utils  # noqa: E402


def test_resolve_coverage_link_python_reuses_cached_html_status_index(
    monkeypatch, tmp_path
):
    utils._PYTHON_HTML_STATUS_CACHE.clear()
    python_html_index_cache = getattr(utils, "_PYTHON_HTML_STATUS_INDEX_CACHE", None)
    if python_html_index_cache is not None:
        python_html_index_cache.clear()

    html_status_path = tmp_path / "html_status.json"
    html_status_path.write_text(
        json.dumps(
            {"files": {"Test": {"index": {"relative_filename": "/src/fuzz_parse.py"}}}}
        ),
        encoding="utf-8",
    )

    scan_calls = {"count": 0}

    def fake_scan(search_root, regex_str):
        del search_root, regex_str
        scan_calls["count"] += 1
        return [str(html_status_path)]

    monkeypatch.setattr(utils, "get_all_files_in_tree_with_regex", fake_scan)

    first = utils.resolve_coverage_link(
        "https://coverage-url.com/", "Class", 13, "fuzz_parse", "python"
    )
    second = utils.resolve_coverage_link(
        "https://coverage-url.com/", "Class", 13, "fuzz_parse", "python"
    )

    assert first == "https://coverage-url.com/Test.html#t13"
    assert second == first
    if python_html_index_cache is not None:
        assert scan_calls["count"] == 1
    else:
        assert scan_calls["count"] == 2


def test_resolve_coverage_link_python_refreshes_index_cache_on_file_removal(
    monkeypatch, tmp_path
):
    utils._PYTHON_HTML_STATUS_CACHE.clear()
    python_html_index_cache = getattr(utils, "_PYTHON_HTML_STATUS_INDEX_CACHE", None)
    if python_html_index_cache is not None:
        python_html_index_cache.clear()

    first_html_status = tmp_path / "first_html_status.json"
    first_html_status.write_text(
        json.dumps(
            {"files": {"First": {"index": {"relative_filename": "/src/fuzz_parse.py"}}}}
        ),
        encoding="utf-8",
    )

    second_html_status = tmp_path / "second_html_status.json"
    second_html_status.write_text(
        json.dumps(
            {
                "files": {
                    "Second": {"index": {"relative_filename": "/src/fuzz_parse.py"}}
                }
            }
        ),
        encoding="utf-8",
    )

    scan_calls = {"count": 0}

    def fake_scan(search_root, regex_str):
        del search_root, regex_str
        scan_calls["count"] += 1
        if scan_calls["count"] == 1:
            return [str(first_html_status)]
        return [str(second_html_status)]

    monkeypatch.setattr(utils, "get_all_files_in_tree_with_regex", fake_scan)

    first = utils.resolve_coverage_link(
        "https://coverage-url.com/", "Class", 13, "fuzz_parse", "python"
    )
    os.remove(first_html_status)
    second = utils.resolve_coverage_link(
        "https://coverage-url.com/", "Class", 13, "fuzz_parse", "python"
    )

    assert first == "https://coverage-url.com/First.html#t13"
    assert second == "https://coverage-url.com/Second.html#t13"
    assert scan_calls["count"] == 2


def test_load_go_coverage_options_reuses_cached_parse_result(monkeypatch, tmp_path):
    utils._GO_COVERAGE_OPTIONS_CACHE.clear()

    report_path = tmp_path / "index.html"
    report_path.write_text(
        """
<html><body>
  <select id=\"files\">
    <option value=\"f0\">pkg/main.go (100.0%)</option>
  </select>
</body></html>
""",
        encoding="utf-8",
    )

    original_beautiful_soup = utils.BeautifulSoup
    parse_calls = {"count": 0}

    def counting_beautiful_soup(*args, **kwargs):
        parse_calls["count"] += 1
        return original_beautiful_soup(*args, **kwargs)

    monkeypatch.setattr(utils, "BeautifulSoup", counting_beautiful_soup)

    first = utils._load_go_coverage_options(str(report_path))
    second = utils._load_go_coverage_options(str(report_path))

    assert first == [("pkg/main.go", "f0")]
    assert second == first
    assert parse_calls["count"] == 1


def test_load_go_coverage_options_refreshes_cache_on_file_change(tmp_path):
    utils._GO_COVERAGE_OPTIONS_CACHE.clear()

    report_path = tmp_path / "index.html"
    report_path.write_text(
        """
<html><body>
  <select id=\"files\">
    <option value=\"f0\">pkg/main.go (100.0%)</option>
  </select>
</body></html>
""",
        encoding="utf-8",
    )
    first = utils._load_go_coverage_options(str(report_path))

    time.sleep(0.001)
    report_path.write_text(
        """
<html><body>
  <select id=\"files\">
    <option value=\"f7\">pkg/main.go (95.1%)</option>
  </select>
</body></html>
""",
        encoding="utf-8",
    )
    second = utils._load_go_coverage_options(str(report_path))

    assert first == [("pkg/main.go", "f0")]
    assert second == [("pkg/main.go", "f7")]
