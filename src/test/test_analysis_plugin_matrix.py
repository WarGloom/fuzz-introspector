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
"""Plugin matrix tests for analysis registration and selection."""

from typing import Any

from fuzz_introspector import analysis
from fuzz_introspector import cli
from fuzz_introspector import commands


def test_all_registered_analysis_plugins_have_unique_names() -> None:
    plugin_names = [analysis_cls.get_name()
                    for analysis_cls in analysis.get_all_analyses()]

    assert plugin_names
    assert len(plugin_names) == len(set(plugin_names))
    assert all(plugin_name.strip() for plugin_name in plugin_names)


def test_enable_all_analyses_selects_entire_plugin_registry(
    monkeypatch,
    tmp_path,
) -> None:
    captured_analyses: list[str] = []

    class FakeIntrospectionProject:

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

        def load_data_files(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

    def fake_create_html_report(*args: Any, **kwargs: Any) -> None:
        del kwargs
        captured_analyses.extend(args[1])

    monkeypatch.setattr(commands.analysis, "IntrospectionProject",
                        FakeIntrospectionProject)
    monkeypatch.setattr(commands.html_report, "create_html_report",
                        fake_create_html_report)

    exit_code, _ = commands.run_analysis_on_dir(
        target_folder=str(tmp_path),
        coverage_url="",
        analyses_to_run=[],
        correlation_file="",
        enable_all_analyses=True,
        report_name="plugin-matrix-test",
        language="c-cpp",
        output_json=[],
        parallelise=False,
        dump_files=False,
        out_dir=str(tmp_path),
    )

    expected_names = {
        analysis_cls.get_name() for analysis_cls in analysis.get_all_analyses()
    }

    assert exit_code == 0
    assert set(captured_analyses) == expected_names
    assert "FrontendAnalyser" in captured_analyses


def test_cli_report_defaults_include_frontend_analyser() -> None:
    parser = cli.get_cmdline_parser()
    args = parser.parse_args(["report", "--target-dir", "/tmp/fuzz-project"])
    assert "FrontendAnalyser" in args.analyses
