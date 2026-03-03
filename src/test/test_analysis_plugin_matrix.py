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
import shutil
import subprocess
import tempfile
from typing import Any
from unittest import mock

import pytest

from fuzz_introspector import analysis
from fuzz_introspector import cli
from fuzz_introspector import commands
from fuzz_introspector import html_report
from fuzz_introspector.analyses import optimal_targets as ot_module
from fuzz_introspector.analyses import runtime_coverage_analysis as rca_module
from fuzz_introspector.analyses import calltree_analysis as ct_module


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
    monkeypatch.delenv("FI_NATIVE_BACKENDS", raising=False)
    assert analysis.NativePluginProxy.is_enabled() is False


def test_native_proxy_not_enabled_for_global_go_backend(monkeypatch) -> None:
    monkeypatch.delenv(analysis.FI_NATIVE_PLUGINS_ENV, raising=False)
    monkeypatch.setenv("FI_NATIVE_BACKENDS", "go")

    assert analysis.NativePluginProxy.is_enabled() is False


def test_native_proxy_enabled_for_global_rust_backend(monkeypatch) -> None:
    monkeypatch.delenv(analysis.FI_NATIVE_PLUGINS_ENV, raising=False)
    monkeypatch.setenv("FI_NATIVE_BACKENDS", "rust")

    assert analysis.NativePluginProxy.is_enabled() is True


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


def test_native_proxy_function_table_uses_slim_payload(monkeypatch) -> None:
    """function_table-only requests send a slim project payload."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    fake_response = _make_native_response(["function_table"])
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
        proxy.run_analysis(
            _make_full_fake_proj_profile(["alpha", "beta"]), [], ["function_table"]
        )

    assert captured_input, "subprocess.run was not called"
    request_payload = json.loads(captured_input[0])
    functions_payload = request_payload["project_data"]["functions"]
    assert functions_payload
    for function_entry in functions_payload:
        assert set(function_entry.keys()) == {"name", "total_cyclomatic_complexity"}


def test_native_proxy_caches_results_for_repeated_calls(monkeypatch) -> None:
    """Repeated requests for same plugin set are served from proxy cache."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    fake_proc = _make_native_proc(
        _make_optimal_targets_native_result(["alpha"]),
    )
    proj_profile = _make_full_fake_proj_profile(["alpha"])
    proxy = analysis.NativePluginProxy()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ) as run_mock,
    ):
        first = proxy.run_analysis(proj_profile, [], ["optimal_targets"])
        second = proxy.run_analysis(proj_profile, [], ["optimal_targets"])

    assert "optimal_targets" in first
    assert "optimal_targets" in second
    assert run_mock.call_count == 1


def test_native_proxy_prefetches_once_and_reuses_cached_plugin_results(
    monkeypatch,
) -> None:
    """First full-plugin call prefetches native plugins and caches follow-up calls."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    fake_proc = _make_native_proc(
        {
            **_make_optimal_targets_native_result(["alpha"]),
            **_make_runtime_cov_native_result(["alpha"]),
            **_make_calltree_native_result(10, 1, 9, 10.0),
        }
    )
    proj_profile = _make_full_fake_proj_profile(["alpha"], has_coverage=True)
    proxy = analysis.NativePluginProxy()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ) as run_mock,
    ):
        first = proxy.run_analysis(proj_profile, [], ["optimal_targets"])
        second = proxy.run_analysis(proj_profile, [], ["runtime_coverage_analysis"])

    assert "optimal_targets" in first
    assert "runtime_coverage_analysis" in second
    assert run_mock.call_count == 1


def test_get_native_plugin_proxy_returns_shared_instance() -> None:
    previous_proxy = analysis._NATIVE_PLUGIN_PROXY
    try:
        analysis._NATIVE_PLUGIN_PROXY = None
        first = analysis.get_native_plugin_proxy()
        second = analysis.get_native_plugin_proxy()
        assert first is second
    finally:
        analysis._NATIVE_PLUGIN_PROXY = previous_proxy


# ── Plugin wiring tests ───────────────────────────────────────────────────────


def _make_fake_func_profile(function_name="some_func"):
    """Return a minimal object that looks like a FunctionProfile."""
    fp = mock.MagicMock()
    fp.function_name = function_name
    # Serialisable numeric/string fields used by _serialize_project_for_native
    fp.hitcount = 0
    fp.arg_count = 1
    fp.cyclomatic_complexity = 10
    fp.total_cyclomatic_complexity = 50
    fp.new_unreached_complexity = 40
    fp.bb_count = 4
    fp.functions_reached = []
    fp.reached_by_fuzzers = []
    fp.cov_init_graph_percentage = 0.0
    fp.function_source_file = "foo.c"
    return fp


def _make_full_fake_proj_profile(function_names=None, has_coverage=False):
    """Full fake proj_profile suitable for analysis_func calls."""
    fp_map = {name: _make_fake_func_profile(name) for name in (function_names or [])}
    pp = mock.MagicMock()
    pp.all_functions = fp_map
    pp.target_lang = "c-cpp"
    pp.has_coverage_data.return_value = has_coverage
    return pp


def _make_native_proc(result_dict, status="success"):
    """Build a fake subprocess.CompletedProcess for the given plugin result."""
    response = {
        "schema_version": 1,
        "status": status,
        "results": result_dict,
        "elapsed_ms": 1,
    }
    proc = mock.MagicMock()
    proc.returncode = 0
    proc.stdout = json.dumps(response).encode()
    proc.stderr = b""
    return proc


def _make_optimal_targets_native_result(function_names):
    """Build a valid native result dict for the optimal_targets plugin."""
    rows = [
        {
            "function_name": name,
            "cyclomatic_complexity": 10,
            "total_cyclomatic_complexity": 50,
            "new_unreached_complexity": 40,
            "functions_reached_count": 5,
            "arg_count": 2,
            "bb_count": 4,
            "source_file": "foo.c",
        }
        for name in function_names
    ]
    return {"optimal_targets": {"tables": {"optimal_targets": rows}, "summary": ""}}


def _make_runtime_cov_native_result(function_names):
    """Build a valid native result dict for the runtime_coverage_analysis plugin."""
    rows = [
        {
            "function_name": name,
            "hitcount": 0,
            "new_unreached_complexity": 40,
            "total_cyclomatic_complexity": 50,
            "reached_by_fuzzers": [],
        }
        for name in function_names
    ]
    return {
        "runtime_coverage_analysis": {
            "tables": {"runtime_coverage": rows},
            "summary": "",
        }
    }


def _make_calltree_native_result(total, reached, unreached, pct):
    """Build a valid native result dict for the calltree_analysis plugin."""
    row = {
        "total_functions": total,
        "reached_functions": reached,
        "unreached_functions": unreached,
        "reach_percentage": pct,
        "target_lang": "c-cpp",
    }
    return {"calltree_analysis": {"tables": {"calltree_nodes": [row]}, "summary": ""}}


# ── OptimalTargets plugin wiring ──────────────────────────────────────────────


def _call_optimal_targets_analysis_func(proj_profile, profiles=None, out_dir=None):
    """Drive OptimalTargets.analysis_func with safe HTML-rendering mocks."""
    instance = ot_module.OptimalTargets()
    instance.dump_files = False

    toc = mock.MagicMock()
    conclusions = []
    tables = []

    if profiles is None:
        fake_profile = mock.MagicMock()
        fake_profile.target_lang = "c-cpp"
        profiles = [fake_profile]

    _cleanup = out_dir is None
    if out_dir is None:
        out_dir = tempfile.mkdtemp()

    try:
        # Patch the heavy HTML-rendering helpers so we don't need a real profile.
        with (
            mock.patch.object(
                instance,
                "get_optimal_target_section",
                return_value="<section/>",
            ),
            mock.patch.object(
                instance,
                "get_consequential_section",
                return_value="<consequential/>",
            ),
            mock.patch(
                "fuzz_introspector.analyses.optimal_targets.html_helpers"
                ".html_add_header_with_link",
                return_value="",
            ),
        ):
            instance.analysis_func(
                toc,
                tables,
                proj_profile,
                profiles,
                basefolder="",
                coverage_url="",
                conclusions=conclusions,
                out_dir=out_dir,
            )
    finally:
        if _cleanup:
            shutil.rmtree(out_dir, ignore_errors=True)

    return instance


def test_optimal_targets_uses_rust_result_and_skips_python(monkeypatch) -> None:
    """When FI_NATIVE_PLUGINS=rust and Rust returns rows, iteratively_get_optimal_targets
    must NOT be called."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    func_names = ["func_a", "func_b"]
    proj_profile = _make_full_fake_proj_profile(func_names)

    native_result = _make_optimal_targets_native_result(func_names)
    fake_proc = _make_native_proc(native_result)

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
        mock.patch.object(
            ot_module.OptimalTargets,
            "iteratively_get_optimal_targets",
        ) as mock_py_heavy,
    ):
        _call_optimal_targets_analysis_func(proj_profile)

    mock_py_heavy.assert_not_called()


def test_optimal_targets_falls_back_to_python_when_rust_returns_empty(
    monkeypatch,
) -> None:
    """When FI_NATIVE_PLUGINS=rust but Rust returns {}, iteratively_get_optimal_targets
    IS called."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    func_names = ["func_a"]
    proj_profile = _make_full_fake_proj_profile(func_names)

    fake_proc = _make_native_proc({})  # empty results
    fake_fp = _make_fake_func_profile("func_a")
    fake_new_profile = _make_full_fake_proj_profile(func_names)

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
        mock.patch.object(
            ot_module.OptimalTargets,
            "iteratively_get_optimal_targets",
            return_value=(fake_new_profile, [fake_fp]),
        ) as mock_py_heavy,
    ):
        _call_optimal_targets_analysis_func(proj_profile)

    mock_py_heavy.assert_called_once()


def test_optimal_targets_python_path_when_native_disabled(monkeypatch) -> None:
    """When FI_NATIVE_PLUGINS is not set, the Python path runs normally."""
    monkeypatch.delenv(analysis.FI_NATIVE_PLUGINS_ENV, raising=False)

    func_names = ["func_a"]
    proj_profile = _make_full_fake_proj_profile(func_names)
    fake_fp = _make_fake_func_profile("func_a")
    fake_new_profile = _make_full_fake_proj_profile(func_names)

    with mock.patch.object(
        ot_module.OptimalTargets,
        "iteratively_get_optimal_targets",
        return_value=(fake_new_profile, [fake_fp]),
    ) as mock_py_heavy:
        _call_optimal_targets_analysis_func(proj_profile)

    mock_py_heavy.assert_called_once()


# ── RuntimeCoverageAnalysis plugin wiring ─────────────────────────────────────


def _call_runtime_cov_analysis_func(proj_profile, profiles=None, out_dir=None):
    """Drive RuntimeCoverageAnalysis.analysis_func with safe mocks."""
    instance = rca_module.RuntimeCoverageAnalysis()

    toc = mock.MagicMock()
    tables = []

    _cleanup = out_dir is None
    if out_dir is None:
        out_dir = tempfile.mkdtemp()

    try:
        with (
            mock.patch(
                "fuzz_introspector.analyses.runtime_coverage_analysis.html_helpers"
                ".html_add_header_with_link",
                return_value="",
            ),
            mock.patch(
                "fuzz_introspector.analyses.runtime_coverage_analysis.html_helpers"
                ".html_create_table_head",
                return_value="",
            ),
            mock.patch(
                "fuzz_introspector.analyses.runtime_coverage_analysis.html_helpers"
                ".html_table_add_row",
                return_value="",
            ),
        ):
            instance.analysis_func(
                toc,
                tables,
                proj_profile,
                profiles or [],
                basefolder="",
                coverage_url="",
                conclusions=[],
                out_dir=out_dir,
            )
    finally:
        if _cleanup:
            shutil.rmtree(out_dir, ignore_errors=True)

    return instance


def test_runtime_cov_uses_rust_result_and_skips_python(monkeypatch) -> None:
    """When FI_NATIVE_PLUGINS=rust and Rust returns rows, get_low_cov_high_line_funcs
    must NOT be called."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    func_names = ["cov_func_a", "cov_func_b"]
    proj_profile = _make_full_fake_proj_profile(func_names, has_coverage=True)
    proj_profile.runtime_coverage.get_hit_summary.return_value = (100, 40)

    native_result = _make_runtime_cov_native_result(func_names)
    fake_proc = _make_native_proc(native_result)

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
        mock.patch.object(
            rca_module.RuntimeCoverageAnalysis,
            "get_low_cov_high_line_funcs",
        ) as mock_py_heavy,
    ):
        _call_runtime_cov_analysis_func(proj_profile)

    mock_py_heavy.assert_not_called()


def test_runtime_cov_falls_back_to_python_when_rust_returns_empty(
    monkeypatch,
) -> None:
    """When FI_NATIVE_PLUGINS=rust but Rust returns {}, get_low_cov_high_line_funcs
    IS called."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    func_names = ["cov_func_a"]
    proj_profile = _make_full_fake_proj_profile(func_names, has_coverage=True)
    proj_profile.runtime_coverage.get_hit_summary.return_value = (100, 40)

    fake_proc = _make_native_proc({})

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
        mock.patch.object(
            rca_module.RuntimeCoverageAnalysis,
            "get_low_cov_high_line_funcs",
            return_value=func_names,
        ) as mock_py_heavy,
    ):
        _call_runtime_cov_analysis_func(proj_profile)

    mock_py_heavy.assert_called_once()


def test_runtime_cov_python_path_when_native_disabled(monkeypatch) -> None:
    """When FI_NATIVE_PLUGINS is not set, the Python path runs normally."""
    monkeypatch.delenv(analysis.FI_NATIVE_PLUGINS_ENV, raising=False)

    func_names = ["cov_func_a"]
    proj_profile = _make_full_fake_proj_profile(func_names, has_coverage=True)
    proj_profile.runtime_coverage.get_hit_summary.return_value = (100, 40)

    with mock.patch.object(
        rca_module.RuntimeCoverageAnalysis,
        "get_low_cov_high_line_funcs",
        return_value=func_names,
    ) as mock_py_heavy:
        _call_runtime_cov_analysis_func(proj_profile)

    mock_py_heavy.assert_called_once()


# ── FuzzCalltreeAnalysis plugin wiring ────────────────────────────────────────


def _call_calltree_analysis_func(proj_profile, profiles=None, out_dir=None):
    """Drive FuzzCalltreeAnalysis.analysis_func with mocked json_report."""
    instance = ct_module.FuzzCalltreeAnalysis()
    instance.dump_files = False

    toc = mock.MagicMock()

    _cleanup = out_dir is None
    if out_dir is None:
        out_dir = tempfile.mkdtemp()

    try:
        with mock.patch(
            "fuzz_introspector.analyses.calltree_analysis.json_report"
            ".add_analysis_json_str_as_dict_to_report"
        ):
            result = instance.analysis_func(
                toc,
                [],
                proj_profile,
                profiles or [],
                basefolder="",
                coverage_url="",
                conclusions=[],
                out_dir=out_dir,
            )
    finally:
        if _cleanup:
            shutil.rmtree(out_dir, ignore_errors=True)

    return instance, result


def test_calltree_uses_rust_result_and_stores_json(monkeypatch) -> None:
    """When FI_NATIVE_PLUGINS=rust and Rust returns a calltree row, json_string_result
    is populated and analysis returns ''."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    proj_profile = _make_full_fake_proj_profile()
    native_result = _make_calltree_native_result(100, 60, 40, 60.0)
    fake_proc = _make_native_proc(native_result)

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
    ):
        instance, result = _call_calltree_analysis_func(proj_profile)

    assert result == ""
    stored = json.loads(instance.json_string_result)
    assert len(stored) == 1
    assert stored[0]["total_functions"] == 100
    assert stored[0]["reached_functions"] == 60
    assert stored[0]["reach_percentage"] == 60.0


def test_calltree_returns_empty_string_when_rust_disabled(monkeypatch) -> None:
    """When FI_NATIVE_PLUGINS is not set, analysis_func returns '' (current behaviour)."""
    monkeypatch.delenv(analysis.FI_NATIVE_PLUGINS_ENV, raising=False)

    proj_profile = _make_full_fake_proj_profile()
    instance, result = _call_calltree_analysis_func(proj_profile)

    assert result == ""
    assert instance.json_string_result == "[]"


def test_calltree_returns_empty_string_when_rust_returns_empty(
    monkeypatch,
) -> None:
    """When FI_NATIVE_PLUGINS=rust but Rust returns {}, analysis_func still returns ''."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    proj_profile = _make_full_fake_proj_profile()
    fake_proc = _make_native_proc({})

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
    ):
        instance, result = _call_calltree_analysis_func(proj_profile)

    assert result == ""
    assert instance.json_string_result == "[]"


# ── FunctionTable native plugin wiring ───────────────────────────────────────


def _make_function_table_native_result(function_names_with_complexity):
    """Build a valid native result dict for the function_table plugin.

    Args:
        function_names_with_complexity: list of (name, total_cyclomatic_complexity) tuples,
            already in the desired sort order.
    """
    rows = [
        {
            "name": name,
            "total_cyclomatic_complexity": cc,
            "cyclomatic_complexity": 5,
            "source_file": "foo.c",
            "arg_count": 1,
            "bb_count": 2,
        }
        for name, cc in function_names_with_complexity
    ]
    return {"function_table": {"tables": {"all_functions_table": rows}, "summary": ""}}


def _make_function_table_native_order_result(function_names):
    return {
        "function_table": {
            "tables": {"ordered_function_names": list(function_names)},
            "summary": "",
        }
    }


def test_function_table_in_native_plugin_names() -> None:
    assert "FunctionTable" in analysis._NATIVE_PLUGIN_NAMES


def test_function_table_in_python_name_to_native_key() -> None:
    assert analysis._PYTHON_NAME_TO_NATIVE_KEY.get("FunctionTable") == "function_table"


def test_get_native_function_table_order_returns_sorted_names(
    monkeypatch,
) -> None:
    """When native is enabled and returns rows, names are returned in order."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    func_data = [("high_cc", 100), ("mid_cc", 50), ("low_cc", 10)]
    fake_proc = _make_native_proc(_make_function_table_native_result(func_data))
    proj_profile = _make_full_fake_proj_profile()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
    ):
        result = html_report._get_native_function_table_order(proj_profile)

    assert result == ["high_cc", "mid_cc", "low_cc"]


def test_get_native_function_table_order_accepts_compact_ordered_names(
    monkeypatch,
) -> None:
    """When native returns compact ordering, names are returned in order."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    fake_proc = _make_native_proc(
        _make_function_table_native_order_result(["high_cc", "mid_cc", "low_cc"])
    )
    proj_profile = _make_full_fake_proj_profile()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
    ):
        result = html_report._get_native_function_table_order(proj_profile)

    assert result == ["high_cc", "mid_cc", "low_cc"]


def test_get_cached_native_function_table_order_caches_per_profile(monkeypatch) -> None:
    """Native ordering is computed once and reused for the same profile."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")
    html_report._NATIVE_FUNCTION_TABLE_ORDER_CACHE.clear()

    proj_profile = _make_full_fake_proj_profile(["one", "two"])

    with mock.patch(
        "fuzz_introspector.html_report._get_native_function_table_order",
        return_value=["one", "two"],
    ) as native_order_mock:
        first = html_report._get_cached_native_function_table_order(proj_profile)
        second = html_report._get_cached_native_function_table_order(proj_profile)

    assert first == ["one", "two"]
    assert second == ["one", "two"]
    assert native_order_mock.call_count == 1


def test_get_native_function_table_order_returns_none_when_disabled(
    monkeypatch,
) -> None:
    """When native plugins are disabled, None is returned."""
    monkeypatch.delenv(analysis.FI_NATIVE_PLUGINS_ENV, raising=False)

    proj_profile = _make_full_fake_proj_profile()
    result = html_report._get_native_function_table_order(proj_profile)

    assert result is None


def test_get_native_function_table_order_returns_none_on_empty_rows(
    monkeypatch,
) -> None:
    """When the native plugin returns an empty table, None is returned."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    # Empty table — no rows
    fake_proc = _make_native_proc(
        {"function_table": {"tables": {"all_functions_table": []}, "summary": ""}}
    )
    proj_profile = _make_full_fake_proj_profile()

    with (
        mock.patch.object(
            analysis.NativePluginProxy,
            "find_binary",
            return_value="/usr/bin/native_analysis_plugins_rust",
        ),
        mock.patch(
            "fuzz_introspector.analysis.subprocess.run",
            return_value=fake_proc,
        ),
    ):
        result = html_report._get_native_function_table_order(proj_profile)

    assert result is None


def test_get_native_function_table_order_returns_none_on_missing_binary(
    monkeypatch,
) -> None:
    """When the native binary is not found, None is returned gracefully."""
    monkeypatch.setenv(analysis.FI_NATIVE_PLUGINS_ENV, "rust")

    proj_profile = _make_full_fake_proj_profile()

    with mock.patch.object(
        analysis.NativePluginProxy,
        "find_binary",
        return_value=None,
    ):
        result = html_report._get_native_function_table_order(proj_profile)

    assert result is None
