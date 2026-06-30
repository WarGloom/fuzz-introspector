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

import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import constants, html_helpers, html_report, styling  # noqa: E402


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
    monkeypatch: pytest.MonkeyPatch, ) -> None:
    monkeypatch.delenv("FI_INLINE_JS", raising=False)
    original = list(styling.MAIN_JS_FILES)

    html_report.get_body_script_tags([], {})
    html_report.get_body_script_tags([], {})

    assert styling.MAIN_JS_FILES == original


def test_custom_js_draws_each_fuzzer_runtime_table() -> None:
    custom_js = (Path(styling.__file__).parent / "custom.js").read_text(
        encoding="utf-8")

    assert "table.rows.add(value);\n    table.draw();" in custom_js


def test_parse_calltree_bitmap_max_nodes_env(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FI_CALLTREE_BITMAP_MAX_NODES", raising=False)
    assert html_report._parse_calltree_bitmap_max_nodes() == 999999

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "123")
    assert html_report._parse_calltree_bitmap_max_nodes() == 123

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "-1")
    assert html_report._parse_calltree_bitmap_max_nodes() == 999999

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "bad")
    assert html_report._parse_calltree_bitmap_max_nodes() == 999999


def test_parse_stage_warn_seconds_env(monkeypatch: pytest.MonkeyPatch) -> None:
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
        wrote_stats = False

        def get_callsites(self):
            return [
                SimpleNamespace(cov_color="red"),
                SimpleNamespace(cov_color="green"),
                SimpleNamespace(cov_color="yellow"),
            ]

        def write_stats_to_summary_file(self, _out_dir):
            self.wrote_stats = True

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "2")
    monkeypatch.setattr(
        "fuzz_introspector.analyses.calltree_analysis.FuzzCalltreeAnalysis",
        DummyCalltreeAnalysis,
    )
    monkeypatch.setattr(
        html_report.html_helpers,
        "create_horisontal_calltree_image",
        lambda *_args, **_kwargs:
        (_ for _ in
         ()).throw(AssertionError("bitmap generation should be skipped")),
    )

    with caplog.at_level("INFO"):
        profile = DummyProfile()
        html = html_report.create_fuzzer_detailed_section(
            proj_profile=SimpleNamespace(has_coverage_data=lambda: False),
            profile=profile,
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
    assert profile.wrote_stats is True
    assert any("Skipping calltree overview bitmap" in record.message
               for record in caplog.records)


def test_create_fuzzer_detailed_section_does_not_embed_stale_bitmap_when_skipped(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:

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

        def write_stats_to_summary_file(self, _out_dir):
            return None

    stale_colormap = tmp_path / "my_fuzzer_colormap.png"
    stale_colormap.write_bytes(b"stale")

    monkeypatch.setenv("FI_CALLTREE_BITMAP_MAX_NODES", "2")
    monkeypatch.setattr(
        "fuzz_introspector.analyses.calltree_analysis.FuzzCalltreeAnalysis",
        DummyCalltreeAnalysis,
    )
    monkeypatch.setattr(
        html_report.html_helpers,
        "create_horisontal_calltree_image",
        lambda *_args, **_kwargs:
        (_ for _ in
         ()).throw(AssertionError("bitmap generation should be skipped")),
    )

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


def test_create_runtime_coverage_section_reuses_cov_metrics(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    counter = {"calls": 0}
    cov_metrics = {
        "func-hit": (8, 4, 50.0),
        "func-unknown": (None, None, None),
        "raw-harness-helper": (5, 5, 100.0),
    }

    class DummyProfile:
        identifier = "dummy-fuzzer"
        coverage = SimpleNamespace(covmap={
            "func-hit": object(),
            "raw-harness-helper": object(),
        })
        functions_reached_by_fuzzer = {"func-hit", "func-unknown"}
        functions_reached_by_fuzzer_runtime = {"func-hit"}

        @staticmethod
        def get_target_reachable_functions():
            return {"func-hit", "func-unknown"}

        @staticmethod
        def get_cov_metrics(funcname: str):
            counter["calls"] += 1
            return cov_metrics[funcname]

        @staticmethod
        def get_coverage_blocker_stats():
            return {
                "reachable-funcs": 2,
                "reached-funcs": 1,
                "cov-reach-proportion": 50.0,
            }

    monkeypatch.setattr(
        html_report.json_report,
        "add_fuzzer_key_value_to_report",
        lambda *_args, **_kwargs: None,
    )

    fuzzer_table_data: dict[str, list[dict[str, object]]] = {}
    html = html_report.create_fuzzer_profile_runtime_coverage_section(
        proj_profile=SimpleNamespace(),
        profile=DummyProfile(),
        table_of_contents=html_report.html_helpers.HtmlTableOfContents(),
        profile_idx=0,
        fuzzer_table_data=fuzzer_table_data,
        extract_conclusion=False,
        conclusions=[],
        tables=[],
        out_dir=str(tmp_path),
    )

    assert counter["calls"] == 2
    assert "Covered functions" in html
    assert "Functions that are reachable but not covered" in html
    assert "Reachable functions" in html
    assert "50.0%" in html
    assert fuzzer_table_data["myTable0"] == [
        {
            "Function name": "func-hit",
            "source code lines": 8,
            "source lines hit": 4,
            "percentage hit": "50.0%",
        },
        {
            "Function name": "func-unknown",
            "source code lines": "N/A",
            "source lines hit": "N/A",
            "percentage hit": "N/A",
        },
    ]


def test_runtime_coverage_section_writes_broad_blocker_stats(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    written_stats = {}

    class DummyProfile:
        identifier = "dummy-fuzzer"
        coverage = SimpleNamespace(covmap={
            "target": object(),
            "harness-helper": object(),
            "protobuf-runtime": object(),
        })
        functions_reached_by_fuzzer = {
            "target",
            "missing-target",
            "harness-helper",
        }
        functions_reached_by_fuzzer_runtime = {"target"}

        @staticmethod
        def get_target_reachable_functions():
            return {"target", "missing-target"}

        @staticmethod
        def get_cov_metrics(funcname: str):
            return {
                "target": (4, 4, 100.0),
                "missing-target": (None, None, None),
                "harness-helper": (3, 3, 100.0),
                "protobuf-runtime": (6, 6, 100.0),
            }[funcname]

        @staticmethod
        def get_coverage_blocker_stats():
            return {
                "reachable-funcs": 3,
                "reached-funcs": 2,
                "cov-reach-proportion": 66.66666666666666,
            }

    def capture_stats(_identifier, key, value, _out_dir):
        if key == "coverage-blocker-stats":
            written_stats.update(value)

    monkeypatch.setattr(html_report.json_report,
                        "add_fuzzer_key_value_to_report", capture_stats)

    fuzzer_table_data: dict[str, list[dict[str, object]]] = {}
    html = html_report.create_fuzzer_profile_runtime_coverage_section(
        proj_profile=SimpleNamespace(),
        profile=DummyProfile(),
        table_of_contents=html_report.html_helpers.HtmlTableOfContents(),
        profile_idx=0,
        fuzzer_table_data=fuzzer_table_data,
        extract_conclusion=True,
        conclusions=[],
        tables=[],
        out_dir=str(tmp_path),
    )

    assert written_stats == {
        "reachable-funcs": 3,
        "reached-funcs": 2,
        "cov-reach-proportion": 66.66666666666666,
    }
    assert fuzzer_table_data["myTable0"] == [
        {
            "Function name": "missing-target",
            "source code lines": "N/A",
            "source lines hit": "N/A",
            "percentage hit": "N/A",
        },
        {
            "Function name": "target",
            "source code lines": 4,
            "source lines hit": 4,
            "percentage hit": "100.0%",
        },
    ]
    assert "Covered functions" in html
    assert "Reachable functions" in html


def test_top_summary_warning_uses_runtime_reached_scope() -> None:
    proj_profile = SimpleNamespace(
        reached_func_count=1,
        total_functions=2,
        reached_complexity=1,
        total_complexity=2,
        reached_func_percentage=50.0,
        reached_complexity_percentage=50.0,
        target_lang="c-cpp",
        get_all_runtime_covered_functions=lambda: ["covered_a", "covered_b"],
        get_all_runtime_reached_functions=lambda: ["covered_a"],
        has_coverage_data=lambda: True,
    )

    html = html_report.create_boxed_top_summary_info(proj_profile, [])

    assert "runtime covered functions are larger" not in html


def test_create_horisontal_calltree_image_uses_agg_when_backend_not_set(
    monkeypatch: pytest.MonkeyPatch, ) -> None:
    use_calls: list[str] = []
    fake_matplotlib = ModuleType("matplotlib")
    fake_pyplot = ModuleType("matplotlib.pyplot")
    fake_patches = ModuleType("matplotlib.patches")

    def fake_use(backend: str) -> None:
        use_calls.append(backend)

    fake_matplotlib.use = fake_use
    fake_patches.Rectangle = object

    monkeypatch.delenv("MPLBACKEND", raising=False)
    monkeypatch.setitem(sys.modules, "matplotlib", fake_matplotlib)
    monkeypatch.setitem(sys.modules, "matplotlib.pyplot", fake_pyplot)
    monkeypatch.setitem(sys.modules, "matplotlib.patches", fake_patches)
    monkeypatch.setattr(
        html_helpers,
        "_create_horisontal_calltree_image_impl",
        lambda *_args, **_kwargs: ["green"],
    )

    profile = SimpleNamespace(get_callsites=lambda: [])
    colors = html_helpers.create_horisontal_calltree_image(
        "test.png", profile, False, "/tmp")

    assert colors == ["green"]
    assert use_calls == ["Agg"]


def test_create_horisontal_calltree_image_preserves_explicit_backend(
    monkeypatch: pytest.MonkeyPatch, ) -> None:
    use_calls: list[str] = []
    fake_matplotlib = ModuleType("matplotlib")
    fake_pyplot = ModuleType("matplotlib.pyplot")
    fake_patches = ModuleType("matplotlib.patches")

    def fake_use(backend: str) -> None:
        use_calls.append(backend)

    fake_matplotlib.use = fake_use
    fake_patches.Rectangle = object

    monkeypatch.setenv("MPLBACKEND", "TkAgg")
    monkeypatch.setitem(sys.modules, "matplotlib", fake_matplotlib)
    monkeypatch.setitem(sys.modules, "matplotlib.pyplot", fake_pyplot)
    monkeypatch.setitem(sys.modules, "matplotlib.patches", fake_patches)
    monkeypatch.setattr(
        html_helpers,
        "_create_horisontal_calltree_image_impl",
        lambda *_args, **_kwargs: ["yellow"],
    )

    profile = SimpleNamespace(get_callsites=lambda: [])
    colors = html_helpers.create_horisontal_calltree_image(
        "test.png", profile, False, "/tmp")

    assert colors == ["yellow"]
    assert use_calls == []


def test_render_calltree_bitmaps_native_uses_go_backend(
    monkeypatch: pytest.MonkeyPatch, ) -> None:
    monkeypatch.setattr(
        html_helpers.backend_loaders,
        "resolve_component_backend",
        lambda _env_name: "go",
    )
    monkeypatch.setattr(html_helpers, "_resolve_bitmap_binary",
                        lambda _backend: "/fake/go-bin")

    captured = {}

    def _fake_run(args, input, **kwargs):
        captured["args"] = args
        captured["payload"] = json.loads(input)
        del kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "status":
                "success",
                "results": [{
                    "job_id": "bitmap.png",
                    "status": "ok"
                }],
            }),
            stderr="",
        )

    monkeypatch.setattr(html_helpers.subprocess, "run", _fake_run)

    result = html_helpers.render_calltree_bitmaps_native([
        ("bitmap.png", ["red", "gold"], "/tmp/output")
    ])

    assert captured["args"] == ["/fake/go-bin"]
    assert captured["payload"]["jobs"][0]["output_path"].endswith(
        "/tmp/output/bitmap.png")
    assert result == {"bitmap.png": ["red", "gold"]}


def test_build_line_identity_payloads_exports_expected_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CI_PIPELINE_ID", "pipeline-123")
    monkeypatch.setenv("CI_COMMIT_SHA", "commit-abc")

    proj_profile = SimpleNamespace(
        runtime_coverage=SimpleNamespace(covmap={"foo()": [(10, 1), (11, 0), (12, 3)]}))
    profiles = [
        SimpleNamespace(
            identifier="fuzzA",
            target_lang="c-cpp",
            coverage=SimpleNamespace(covmap={"foo()": [(10, 1), (11, 0), (12, 2)]}),
        ),
        SimpleNamespace(
            identifier="fuzzB",
            target_lang="c-cpp",
            coverage=SimpleNamespace(covmap={"foo()": [(10, 0), (11, 0), (12, 1)]}),
        ),
    ]
    all_functions_json_report = [{
        "Func name": "foo()",
        "raw-function-name": "_Z3foov",
        "Functions filename": "/src/demo.c",
        "source_line_begin": 10,
        "Reached by Fuzzers": ["fuzzA", "fuzzB"],
    }]

    executable, covered, reachable = html_report._build_line_identity_payloads(
        proj_profile,
        profiles,
        all_functions_json_report,
        "/tmp/report-out",
    )

    assert executable == [{
        "function_key": "_Z3foov|/src/demo.c|10",
        "raw_function_name": "_Z3foov",
        "filename": "/src/demo.c",
        "line_number": 10,
        "introspector_report_id": "introspector-pipeline-123",
    }, {
        "function_key": "_Z3foov|/src/demo.c|10",
        "raw_function_name": "_Z3foov",
        "filename": "/src/demo.c",
        "line_number": 11,
        "introspector_report_id": "introspector-pipeline-123",
    }, {
        "function_key": "_Z3foov|/src/demo.c|10",
        "raw_function_name": "_Z3foov",
        "filename": "/src/demo.c",
        "line_number": 12,
        "introspector_report_id": "introspector-pipeline-123",
    }]
    assert covered == [{
        "fuzzer_name": "fuzzA",
        "filename": "/src/demo.c",
        "line_number": 10,
        "hit_count": 1,
        "coverage_snapshot_id": "coverage-pipeline-123",
        "pipeline_id": "pipeline-123",
        "commit_sha": "commit-abc",
    }, {
        "fuzzer_name": "fuzzA",
        "filename": "/src/demo.c",
        "line_number": 12,
        "hit_count": 2,
        "coverage_snapshot_id": "coverage-pipeline-123",
        "pipeline_id": "pipeline-123",
        "commit_sha": "commit-abc",
    }, {
        "fuzzer_name": "fuzzB",
        "filename": "/src/demo.c",
        "line_number": 12,
        "hit_count": 1,
        "coverage_snapshot_id": "coverage-pipeline-123",
        "pipeline_id": "pipeline-123",
        "commit_sha": "commit-abc",
    }]
    assert reachable == [{
        "fuzzer_name": "fuzzA",
        "function_key": "_Z3foov|/src/demo.c|10",
        "filename": "/src/demo.c",
        "line_number": 10,
        "introspector_report_id": "introspector-pipeline-123",
    }, {
        "fuzzer_name": "fuzzA",
        "function_key": "_Z3foov|/src/demo.c|10",
        "filename": "/src/demo.c",
        "line_number": 11,
        "introspector_report_id": "introspector-pipeline-123",
    }, {
        "fuzzer_name": "fuzzA",
        "function_key": "_Z3foov|/src/demo.c|10",
        "filename": "/src/demo.c",
        "line_number": 12,
        "introspector_report_id": "introspector-pipeline-123",
    }, {
        "fuzzer_name": "fuzzB",
        "function_key": "_Z3foov|/src/demo.c|10",
        "filename": "/src/demo.c",
        "line_number": 10,
        "introspector_report_id": "introspector-pipeline-123",
    }, {
        "fuzzer_name": "fuzzB",
        "function_key": "_Z3foov|/src/demo.c|10",
        "filename": "/src/demo.c",
        "line_number": 11,
        "introspector_report_id": "introspector-pipeline-123",
    }, {
        "fuzzer_name": "fuzzB",
        "function_key": "_Z3foov|/src/demo.c|10",
        "filename": "/src/demo.c",
        "line_number": 12,
        "introspector_report_id": "introspector-pipeline-123",
    }]


def test_build_line_identity_payloads_skips_ambiguous_name_matches() -> None:
    proj_profile = SimpleNamespace(
        runtime_coverage=SimpleNamespace(covmap={"dup()": [(10, 1), (11, 1)]}))
    profiles = [
        SimpleNamespace(
            identifier="fuzzA",
            target_lang="c-cpp",
            coverage=SimpleNamespace(covmap={"dup()": [(10, 1), (11, 1)]}),
        )
    ]
    all_functions_json_report = [{
        "Func name": "dup()",
        "raw-function-name": "_Z3dupv",
        "Functions filename": "/src/a.c",
        "source_line_begin": 10,
        "Reached by Fuzzers": ["fuzzA"],
    }, {
        "Func name": "dup()",
        "raw-function-name": "_Z3dupv.1",
        "Functions filename": "/src/b.c",
        "source_line_begin": 20,
        "Reached by Fuzzers": ["fuzzA"],
    }]

    executable, covered, reachable = html_report._build_line_identity_payloads(
        proj_profile,
        profiles,
        all_functions_json_report,
        "/tmp/report-out",
    )

    assert executable == []
    assert covered == []
    assert reachable == []


def test_build_line_identity_payloads_omits_fuzzer_without_exact_coverage() -> None:
    proj_profile = SimpleNamespace(
        runtime_coverage=SimpleNamespace(covmap={"foo()": [(10, 1), (12, 3)]}))
    profiles = [
        SimpleNamespace(
            identifier="fuzzA",
            target_lang="c-cpp",
            coverage=SimpleNamespace(covmap={"foo()": [(10, 1), (12, 2)]}),
        ),
        SimpleNamespace(
            identifier="fuzzB",
            target_lang="c-cpp",
            coverage=SimpleNamespace(covmap={}),
        ),
    ]
    all_functions_json_report = [{
        "Func name": "foo()",
        "raw-function-name": "_Z3foov",
        "Functions filename": "/src/demo.c",
        "source_line_begin": 10,
        "Reached by Fuzzers": ["fuzzA", "fuzzB"],
    }]

    _executable, covered, _reachable = html_report._build_line_identity_payloads(
        proj_profile,
        profiles,
        all_functions_json_report,
        "/tmp/report-out",
    )

    assert covered == [{
        "fuzzer_name": "fuzzA",
        "filename": "/src/demo.c",
        "line_number": 10,
        "hit_count": 1,
        "coverage_snapshot_id": "coverage-report-out",
        "pipeline_id": "",
        "commit_sha": "",
    }, {
        "fuzzer_name": "fuzzA",
        "filename": "/src/demo.c",
        "line_number": 12,
        "hit_count": 2,
        "coverage_snapshot_id": "coverage-report-out",
        "pipeline_id": "",
        "commit_sha": "",
    }]
