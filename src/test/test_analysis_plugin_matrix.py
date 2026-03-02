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

import json
import subprocess
from typing import Any
from unittest import mock

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


# ── NativePluginProxy tests ───────────────────────────────────────────────────


def _make_fake_proj_profile(function_names=None, target_lang="c-cpp"):
    """Return a minimal fake MergedProjectProfile-like object."""

    class FakeProjProfile:
        all_functions = {name: None for name in (function_names or [])}
        target_lang = "c-cpp"

    obj = FakeProjProfile()
    obj.target_lang = target_lang
    return obj


def _make_native_response(plugin_names, status="success"):
    """Build a plausible native binary response dict."""
    results = {}
    for name in plugin_names:
        results[name] = {
            "tables": {},
            "summary": f"{name} stub",
        }
    return {"schema_version": 1, "status": status, "results": results, "elapsed_ms": 5}


# ── Test 1: FI_NATIVE_PLUGINS=rust routes to NativePluginProxy ───────────────


def test_fi_native_plugins_rust_env_routes_to_native_proxy(monkeypatch) -> None:
    """When FI_NATIVE_PLUGINS=rust and binary exists, NativePluginProxy is invoked."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    plugin_names = ["optimal_targets", "runtime_coverage_analysis"]
    fake_response = _make_native_response(plugin_names)

    fake_proc = mock.MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = json.dumps(fake_response).encode()
    fake_proc.stderr = b""

    proxy = analysis.NativePluginProxy()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run", return_value=fake_proc
        ) as mock_run,
    ):
        result = proxy.run_analysis(
            _make_fake_proj_profile(),
            [],
            plugin_names,
        )

    # subprocess.run was called once with the binary
    mock_run.assert_called_once()
    call_args = mock_run.call_args
    assert call_args[0][0] == ["/usr/bin/native_analysis_plugins_rust"]

    # Results contain both requested plugins
    assert "optimal_targets" in result
    assert "runtime_coverage_analysis" in result


def test_fi_native_plugins_is_enabled_when_env_set(monkeypatch) -> None:
    """NativePluginProxy.is_enabled() returns True only when env var is 'rust'."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")
    assert analysis.NativePluginProxy.is_enabled() is True


def test_fi_native_plugins_not_enabled_by_default(monkeypatch) -> None:
    """NativePluginProxy.is_enabled() returns False when env var is absent."""
    monkeypatch.delenv(analysis.FI_NATIVE_PLUGINS_ENV, raising=False)
    assert analysis.NativePluginProxy.is_enabled() is False


# ── Test 2: Empty native results → Python fallback ───────────────────────────


def test_native_proxy_empty_results_signals_python_fallback(monkeypatch) -> None:
    """When the native binary returns empty results, run_analysis returns {}."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    # Native returns success but results is empty (no plugins handled)
    fake_response = {
        "schema_version": 1,
        "status": "success",
        "results": {},
        "elapsed_ms": 1,
    }
    fake_proc = mock.MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = json.dumps(fake_response).encode()
    fake_proc.stderr = b""

    proxy = analysis.NativePluginProxy()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch("fuzz_introspector.analysis.subprocess.run", return_value=fake_proc),
    ):
        result = proxy.run_analysis(
            _make_fake_proj_profile(),
            [],
            ["optimal_targets"],
        )

    # Empty dict signals callers to run Python plugins for everything
    assert result == {}


# ── Test 3: Native returns valid results → Python plugins would be skipped ───


def test_native_proxy_valid_results_returned_to_caller(monkeypatch) -> None:
    """When native succeeds, results dict is non-empty and caller can skip Python plugins."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    plugin_name = "calltree_analysis"
    fake_response = _make_native_response([plugin_name])
    fake_proc = mock.MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = json.dumps(fake_response).encode()
    fake_proc.stderr = b""

    proxy = analysis.NativePluginProxy()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch("fuzz_introspector.analysis.subprocess.run", return_value=fake_proc),
    ):
        result = proxy.run_analysis(
            _make_fake_proj_profile(),
            [],
            [plugin_name],
        )

    # Caller receives non-empty results and knows it can skip Python for this plugin
    assert plugin_name in result
    assert "summary" in result[plugin_name]


# ── Test 4: Binary missing → Python plugins run normally (no crash) ──────────


def test_native_proxy_missing_binary_returns_empty_no_crash(monkeypatch) -> None:
    """When the Rust binary is not on PATH, run_analysis returns {} without crashing."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    proxy = analysis.NativePluginProxy()

    with mock.patch.object(
        analysis.NativePluginProxy, "find_binary", return_value=None
    ):
        result = proxy.run_analysis(
            _make_fake_proj_profile(),
            [],
            ["optimal_targets", "runtime_coverage_analysis", "calltree_analysis"],
        )

    # No exception raised; empty dict returned so caller runs all Python plugins
    assert result == {}


def test_native_proxy_binary_nonzero_exit_returns_empty(monkeypatch) -> None:
    """When the Rust binary returns a non-zero exit code, run_analysis returns {}."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    fake_proc = mock.MagicMock()
    fake_proc.returncode = 1
    fake_proc.stdout = b""
    fake_proc.stderr = b"internal error"

    proxy = analysis.NativePluginProxy()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch("fuzz_introspector.analysis.subprocess.run", return_value=fake_proc),
    ):
        result = proxy.run_analysis(
            _make_fake_proj_profile(),
            [],
            ["optimal_targets"],
        )

    assert result == {}


def test_native_proxy_malformed_json_returns_empty(monkeypatch) -> None:
    """Malformed binary stdout causes graceful fallback to empty result."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    fake_proc = mock.MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = b"not valid json {"
    fake_proc.stderr = b""

    proxy = analysis.NativePluginProxy()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch("fuzz_introspector.analysis.subprocess.run", return_value=fake_proc),
    ):
        result = proxy.run_analysis(
            _make_fake_proj_profile(),
            [],
            ["optimal_targets"],
        )

    assert result == {}


def test_native_proxy_timeout_returns_empty(monkeypatch) -> None:
    """Subprocess timeout is handled gracefully and returns empty dict."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    proxy = analysis.NativePluginProxy()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd="native_analysis_plugins_rust", timeout=300
            ),
        ),
    ):
        result = proxy.run_analysis(
            _make_fake_proj_profile(),
            [],
            ["optimal_targets"],
        )

    assert result == {}


def test_fi_native_plugins_not_rust_does_not_enable_proxy(monkeypatch) -> None:
    """Setting FI_NATIVE_PLUGINS to a value other than 'rust' leaves proxy disabled."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "python")
    assert analysis.NativePluginProxy.is_enabled() is False

    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "go")
    assert analysis.NativePluginProxy.is_enabled() is False


def test_native_proxy_schema_version_in_request(monkeypatch) -> None:
    """The request payload sent to the native binary contains the correct schema_version."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    fake_response = _make_native_response(["optimal_targets"])
    fake_proc = mock.MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = json.dumps(fake_response).encode()
    fake_proc.stderr = b""

    proxy = analysis.NativePluginProxy()
    captured_input: list[bytes] = []

    def _capture_run(*args, **kwargs):
        captured_input.append(kwargs.get("input", b""))
        return fake_proc

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run", side_effect=_capture_run
        ),
    ):
        proxy.run_analysis(_make_fake_proj_profile(), [], ["optimal_targets"])

    assert captured_input, "subprocess.run was not called"
    request_payload = json.loads(captured_input[0])
    assert (
        request_payload["schema_version"] == analysis.NativePluginProxy.SCHEMA_VERSION
    )
    assert "optimal_targets" in request_payload["plugins"]
    assert "project_data" in request_payload
