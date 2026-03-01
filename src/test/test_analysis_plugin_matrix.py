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

import pytest

from fuzz_introspector import analysis
from fuzz_introspector import cli
from fuzz_introspector import commands


def test_all_registered_analysis_plugins_have_unique_names() -> None:
    plugin_names = [
        analysis_cls.get_name() for analysis_cls in analysis.get_all_analyses()
    ]

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

    monkeypatch.setattr(
        commands.analysis, "IntrospectionProject", FakeIntrospectionProject
    )
    monkeypatch.setattr(
        commands.html_report, "create_html_report", fake_create_html_report
    )

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
    assert not args.skip_html_report


def test_run_analysis_on_dir_skip_html_report_skips_renderer(
    monkeypatch,
    tmp_path,
) -> None:
    class FakeIntrospectionProject:
        load_data_files_calls = 0

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

        def load_data_files(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs
            self.__class__.load_data_files_calls += 1

    html_calls = []
    monkeypatch.setattr(
        commands.analysis, "IntrospectionProject", FakeIntrospectionProject
    )
    monkeypatch.setattr(
        commands.html_report,
        "create_html_report",
        lambda *_args, **_kwargs: html_calls.append(1),
    )

    exit_code, return_values = commands.run_analysis_on_dir(
        target_folder=str(tmp_path),
        coverage_url="",
        analyses_to_run=[],
        correlation_file="",
        enable_all_analyses=False,
        report_name="skip-html-test",
        language="c-cpp",
        output_json=[],
        parallelise=False,
        dump_files=False,
        out_dir=str(tmp_path),
        skip_html_report=True,
    )

    assert exit_code == 0
    assert FakeIntrospectionProject.load_data_files_calls == 1
    assert html_calls == []
    assert "introspector-project" in return_values


def test_cli_main_report_forwards_skip_html_report(monkeypatch) -> None:
    captured_kwargs = {}

    def _fake_run_analysis_on_dir(*_args: Any, **kwargs: Any):
        captured_kwargs.update(kwargs)
        return 0, {}

    monkeypatch.setattr(cli, "set_logging_level", lambda: None)
    monkeypatch.setattr(cli.commands, "run_analysis_on_dir", _fake_run_analysis_on_dir)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["fuzz-introspector", "report", "--target-dir", "/tmp", "--skip-html-report"],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 0
    assert captured_kwargs["skip_html_report"] is True
