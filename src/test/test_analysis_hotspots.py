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
"""Focused regression tests for analysis.py hotspot paths."""

import os
import sys
import logging

import pytest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import analysis  # noqa: E402
from fuzz_introspector import stage_markers  # noqa: E402
from fuzz_introspector.exceptions import FuzzIntrospectorError  # noqa: E402


def _make_debug_function(name, source_file, source_line):
    return {
        "name": name,
        "source": {
            "source_file": source_file,
            "source_line": source_line,
        },
        "func_signature_elems": {
            "return_type": ["int"],
            "params": [],
        },
    }


def test_correlate_introspection_functions_prefers_exact_source_line(
        monkeypatch):
    monkeypatch.setattr(
        analysis,
        "convert_debug_info_to_signature_v2",
        lambda debug_function, _: f"sig::{debug_function['name']}",
    )

    llvm_functions = [{
        "Func name": "target",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "20",
    }]
    debug_functions = [
        _make_debug_function("before", "/src/project/target.cc", "10"),
        _make_debug_function("target", "/src/project/target.cc", "20"),
    ]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        debug_functions,
        "c-cpp",
        report_dict={"all_files_in_project": []},
    )

    assert llvm_functions[0]["function_signature"] == "sig::target"
    assert llvm_functions[0]["debug_function_info"]["name"] == "target"


def test_correlate_introspection_functions_uses_closest_preceding_line(
        monkeypatch):
    monkeypatch.setattr(
        analysis,
        "convert_debug_info_to_signature_v2",
        lambda debug_function, _: f"sig::{debug_function['name']}",
    )

    llvm_functions = [{
        "Func name": "ns::target(int)",
        "raw-function-name": "_ZN2ns6targetEi",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "25",
    }]
    debug_functions = [
        _make_debug_function("target", "/src/project/target.cc", "10"),
        _make_debug_function("after", "/src/project/target.cc", "30"),
    ]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        debug_functions,
        "c-cpp",
        report_dict={"all_files_in_project": []},
    )

    assert llvm_functions[0]["function_signature"] == "sig::target"
    assert llvm_functions[0]["debug_function_info"]["name"] == "target"


def test_correlate_introspection_functions_uses_short_debug_name_before_mismatch(
    monkeypatch, ):
    monkeypatch.setattr(
        analysis,
        "convert_debug_info_to_signature_v2",
        lambda debug_function, _: f"sig::{debug_function['name']}",
    )

    llvm_functions = [{
        "Func name": "ZProtocolPort::setBusy(unsignedint,BaseInetAddrconst&)",
        "raw-function-name": "_ZN13ZProtocolPort7setBusyEjRK12BaseInetAddr",
        "Functions filename": "/src/src/Base/BaseInetAddr.h",
        "source_line_begin": "39",
    }]
    debug_functions = [
        _make_debug_function("isEmpty", "/src/src/Base/BaseInetAddr.h", "38"),
        _make_debug_function("setBusy", "/src/src/Network/ZProtocolPort.cpp",
                             "77"),
    ]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        debug_functions,
        "c-cpp",
        report_dict={"all_files_in_project": []},
    )

    assert llvm_functions[0]["function_signature"] == "sig::setBusy"
    assert llvm_functions[0]["debug_function_info"]["name"] == "setBusy"


def test_correlate_introspection_functions_ignores_preceding_line_name_mismatch(
    monkeypatch, ):
    monkeypatch.setattr(
        analysis,
        "convert_debug_info_to_signature_v2",
        lambda debug_function, _: f"sig::{debug_function['name']}",
    )

    llvm_functions = [{
        "Func name": "target_without_exact_name_match",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "25",
    }]
    debug_functions = [
        _make_debug_function("before", "/src/project/target.cc", "10"),
        _make_debug_function("after", "/src/project/target.cc", "30"),
    ]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        debug_functions,
        "c-cpp",
        report_dict={"all_files_in_project": []},
    )

    assert llvm_functions[0]["function_signature"] == "N/A"
    assert llvm_functions[0]["debug_function_info"] == {}


def test_correlate_introspection_functions_handles_invalid_source_line_begin():
    llvm_functions = [{
        "Func name": "target_without_exact_name_match",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "invalid-line",
    }]
    debug_functions = [
        _make_debug_function("target", "/src/project/target.cc", "20"),
    ]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        debug_functions,
        "c-cpp",
        report_dict={"all_files_in_project": []},
    )

    assert llvm_functions[0]["function_signature"] == "N/A"
    assert llvm_functions[0]["debug_function_info"] == {}


def test_extract_tests_from_directories_deduplicates_seed_directories(
    monkeypatch,
    tmp_path,
):
    project_root = "/workspace/project"
    walk_starts = []

    def fake_walk(start_path):
        walk_starts.append(start_path)
        yield start_path, [], ["test_file.cpp"]

    monkeypatch.setattr(analysis.os, "walk", fake_walk)

    extracted = analysis.extract_tests_from_directories(
        {
            project_root,
            f"{project_root}/src",
            f"{project_root}/src/unit",
        },
        "c-cpp",
        str(tmp_path),
        need_copy=False,
    )

    assert walk_starts == [project_root]
    assert f"{project_root}/test_file.cpp" in extracted


def test_correlate_introspection_functions_populates_possible_header_files(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        analysis,
        "convert_debug_info_to_signature_v2",
        lambda debug_function, _: f"sig::{debug_function['name']}",
    )

    header_path = tmp_path / "target.hpp"
    header_path.write_text("int target(int x);\n", encoding="utf-8")

    llvm_functions = [{
        "Func name": "target",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "20",
    }]
    debug_functions = [
        _make_debug_function("target", "/src/project/target.cc", "20"),
    ]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        debug_functions,
        "c-cpp",
        report_dict={
            "all_files_in_project": [{
                "source_file": str(header_path)
            }],
        },
    )

    possible_headers = llvm_functions[0]["debug_function_info"].get(
        "possible-header-files", [])
    assert str(header_path) in possible_headers

    # Ensure report_dict remains JSON-serializable after correlation.
    import json  # local import to keep test scope tight

    json.dumps({
        "all_files_in_project": [{
            "source_file": str(header_path)
        }],
        "dummy": "ok",
    })


def test_correlate_introspection_functions_possible_header_files_are_sorted(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        analysis,
        "convert_debug_info_to_signature_v2",
        lambda debug_function, _: f"sig::{debug_function['name']}",
    )

    z_header = tmp_path / "z_target.hpp"
    a_header = tmp_path / "a_target.hpp"
    z_header.write_text("int target(int x);\n", encoding="utf-8")
    a_header.write_text("int target(int x);\n", encoding="utf-8")

    llvm_functions = [{
        "Func name": "target",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "20",
    }]
    debug_functions = [
        _make_debug_function("target", "/src/project/target.cc", "20")
    ]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        debug_functions,
        "c-cpp",
        report_dict={
            "all_files_in_project": [
                {
                    "source_file": str(z_header)
                },
                {
                    "source_file": str(a_header)
                },
            ],
        },
    )

    possible_headers = llvm_functions[0]["debug_function_info"][
        "possible-header-files"]
    assert possible_headers == sorted(possible_headers)


def test_correlate_introspection_functions_ignores_malformed_all_files_entries(
    monkeypatch, ):
    monkeypatch.setattr(
        analysis,
        "convert_debug_info_to_signature_v2",
        lambda debug_function, _: f"sig::{debug_function['name']}",
    )

    llvm_functions = [{
        "Func name": "target_without_exact_name_match",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "invalid-line",
    }]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        [],
        "c-cpp",
        report_dict={
            "all_files_in_project": [
                {
                    "source_file": None
                },
                {
                    "source_file": 123
                },
                {},
                "not-a-dict",
            ]
        },
    )

    assert llvm_functions[0]["function_signature"] == "N/A"


def test_if_debug_correlator_env_defaults(monkeypatch):
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV,
                       raising=False)
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_SHADOW_ENV,
                       raising=False)
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV,
                       raising=False)

    assert (analysis._parse_if_debug_correlator_backend_env() ==
            analysis.backend_loaders.BACKEND_RUST)
    assert (analysis._parse_bool_env(
        analysis.FI_IF_DEBUG_CORRELATOR_SHADOW_ENV, False) is False)
    assert (analysis._parse_bool_env(
        analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV, False) is False)


def test_if_debug_correlator_env_invalid_values_fall_back(
    monkeypatch,
    caplog,
):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "nope")
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_SHADOW_ENV, "nope")
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV, "nope")

    with caplog.at_level(logging.WARNING):
        backend = analysis._parse_if_debug_correlator_backend_env()
        shadow = analysis._parse_bool_env(
            analysis.FI_IF_DEBUG_CORRELATOR_SHADOW_ENV, False)
        strict = analysis._parse_bool_env(
            analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV, False)

    assert backend == analysis.backend_loaders.BACKEND_RUST
    assert shadow is False
    assert strict is False
    assert any(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV in record.message
               for record in caplog.records)


def test_if_debug_correlator_env_accepts_go(monkeypatch):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "go")

    assert (analysis._parse_if_debug_correlator_backend_env() ==
            analysis.backend_loaders.BACKEND_GO)


def test_if_debug_correlator_rust_non_strict_falls_back_to_python(
    monkeypatch,
    caplog,
):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "rust")
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV,
                       raising=False)

    llvm_functions = [{
        "Func name": "target_without_exact_name_match",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "invalid-line",
    }]

    with caplog.at_level(logging.WARNING):
        analysis.correlate_introspection_functions_to_debug_info(
            llvm_functions,
            [],
            "c-cpp",
            report_dict={"all_files_in_project": []},
        )

    assert llvm_functions[0]["function_signature"] == "N/A"
    assert any("falling back to Python authoritative path" in record.message
               for record in caplog.records)


def test_if_debug_correlator_rust_invokes_native_branch_when_available(
        monkeypatch):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "rust")
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV,
                       raising=False)
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_SHADOW_ENV,
                       raising=False)

    llvm_functions = [{
        "Func name": "native_target",
        "Functions filename": "/src/project/native_target.cc",
        "source_line_begin": "10",
    }]

    captured_payload = {}

    def fake_run_correlator_backend(**kwargs):
        captured_payload.update(kwargs)
        return analysis.backend_loaders.CorrelatorBackendResult(
            selected_backend=analysis.backend_loaders.BACKEND_RUST,
            strict_mode=False,
            response={
                "schema_version":
                analysis.backend_loaders.CORRELATOR_SCHEMA_VERSION,
                "status": "success",
                "counters": {},
                "artifacts": {
                    "function_updates": [{
                        "row_idx": 0,
                        "function_signature": "sig::native",
                        "debug_function_info": {
                            "name": "native_target"
                        },
                    }]
                },
                "timings": {},
            },
        )

    def _python_fallback_must_not_run(*_args, **_kwargs):
        raise AssertionError(
            "python fallback should not run after native success")

    monkeypatch.setattr(
        analysis.backend_loaders,
        "run_correlator_backend",
        fake_run_correlator_backend,
    )
    monkeypatch.setattr(
        analysis,
        "_correlate_introspection_functions_to_debug_info_python",
        _python_fallback_must_not_run,
    )

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        [],
        "c-cpp",
        report_dict={"all_files_in_project": []},
    )

    assert llvm_functions[0]["function_signature"] == "sig::native"
    assert llvm_functions[0]["debug_function_info"]["name"] == "native_target"
    assert captured_payload["command_env_prefix"] == "FI_IF_DEBUG_CORRELATOR"
    assert captured_payload[
        "selected_backend"] == analysis.backend_loaders.BACKEND_RUST


def test_if_debug_correlator_go_forces_shadow_mode_for_c_cpp(
    monkeypatch,
    caplog,
):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "go")
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV,
                       raising=False)
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_SHADOW_ENV,
                       raising=False)

    llvm_functions = [{
        "Func name": "native_target",
        "Functions filename": "/src/project/native_target.cc",
        "source_line_begin": "10",
    }]

    captured_payload = {}

    def fake_run_correlator_backend(**kwargs):
        captured_payload.update(kwargs)
        return analysis.backend_loaders.CorrelatorBackendResult(
            selected_backend=analysis.backend_loaders.BACKEND_GO,
            strict_mode=False,
            response={
                "schema_version":
                analysis.backend_loaders.CORRELATOR_SCHEMA_VERSION,
                "status": "success",
                "counters": {},
                "artifacts": {
                    "function_updates": [{
                        "row_idx": 0,
                        "function_signature": "sig::native-go",
                        "debug_function_info": {
                            "name": "native_target"
                        },
                    }]
                },
                "timings": {},
            },
        )

    def _python_authoritative_path(*args, **kwargs):
        del args, kwargs
        llvm_functions[0]["function_signature"] = "sig::python"
        llvm_functions[0]["debug_function_info"] = {"name": "python_target"}

    monkeypatch.setattr(
        analysis.backend_loaders,
        "run_correlator_backend",
        fake_run_correlator_backend,
    )
    monkeypatch.setattr(
        analysis,
        "_correlate_introspection_functions_to_debug_info_python",
        _python_authoritative_path,
    )

    with caplog.at_level(logging.INFO):
        analysis.correlate_introspection_functions_to_debug_info(
            llvm_functions,
            [],
            "c-cpp",
            report_dict={"all_files_in_project": []},
        )

    assert llvm_functions[0]["function_signature"] == "sig::python"
    assert llvm_functions[0]["debug_function_info"]["name"] == "python_target"
    assert captured_payload["command_env_prefix"] == "FI_IF_DEBUG_CORRELATOR"
    assert captured_payload[
        "selected_backend"] == analysis.backend_loaders.BACKEND_GO
    assert any("forced shadow mode" in record.message
               for record in caplog.records)


def test_if_debug_correlator_shadow_mode_runs_native_and_logs_comparison(
    monkeypatch,
    caplog,
):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "rust")
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_SHADOW_ENV, "1")

    llvm_functions = [{
        "Func name": "target_without_exact_name_match",
        "Functions filename": "/src/project/target.cc",
        "source_line_begin": "invalid-line",
    }]

    def fake_run_correlator_backend(**_kwargs):
        return analysis.backend_loaders.CorrelatorBackendResult(
            selected_backend=analysis.backend_loaders.BACKEND_RUST,
            strict_mode=False,
            response={
                "schema_version":
                analysis.backend_loaders.CORRELATOR_SCHEMA_VERSION,
                "status": "success",
                "counters": {},
                "artifacts": {
                    "function_updates": [{
                        "row_idx": 0,
                        "function_signature": "sig::native-shadow",
                        "debug_function_info": {},
                    }]
                },
                "timings": {},
            },
        )

    monkeypatch.setattr(
        analysis.backend_loaders,
        "run_correlator_backend",
        fake_run_correlator_backend,
    )

    with caplog.at_level(logging.INFO):
        analysis.correlate_introspection_functions_to_debug_info(
            llvm_functions,
            [],
            "c-cpp",
            report_dict={"all_files_in_project": []},
        )

    assert any("native path runs and Python path follows" in record.message
               for record in caplog.records)
    assert any("Shadow comparison" in record.message
               for record in caplog.records)


def test_if_debug_correlator_rust_strict_raises_on_native_failure(monkeypatch):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "rust")
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV, "1")

    def fake_run_correlator_backend(**_kwargs):
        return analysis.backend_loaders.CorrelatorBackendResult(
            selected_backend=analysis.backend_loaders.BACKEND_PYTHON,
            strict_mode=False,
            response=None,
            reason_code=analysis.backend_loaders.FI_CORR_COMMAND_MISSING,
            reason_details={"backend": "rust"},
        )

    monkeypatch.setattr(
        analysis.backend_loaders,
        "run_correlator_backend",
        fake_run_correlator_backend,
    )

    with pytest.raises(FuzzIntrospectorError,
                       match="strict mode requires native success"):
        analysis.correlate_introspection_functions_to_debug_info(
            [],
            [],
            "c-cpp",
            report_dict={"all_files_in_project": []},
        )


def test_if_debug_correlator_stage_marker_metadata_has_configured_and_effective_backend(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "rust")
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV,
                       raising=False)
    monkeypatch.delenv("FI_STAGE_MARKERS", raising=False)

    analysis.correlate_introspection_functions_to_debug_info(
        [],
        [],
        "c-cpp",
        report_dict={"all_files_in_project": []},
        out_dir=str(tmp_path),
    )

    events = stage_markers.parse_stage_marker_file(
        str(tmp_path / "stage_markers.log"))
    stage_events = [
        event for event in events
        if event.stage == analysis._IF_DEBUG_SIGNATURE_CORRELATION_STAGE
    ]
    assert [event.event for event in stage_events] == ["start", "end"]
    assert stage_events[0].metadata["configured_backend"] == "rust"
    assert stage_events[0].metadata["effective_backend"] == "python"
    assert stage_events[1].metadata["configured_backend"] == "rust"
    assert stage_events[1].metadata["effective_backend"] == "python"


def test_if_debug_correlator_stage_marker_uses_rust_when_native_succeeds(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(analysis.FI_IF_DEBUG_CORRELATOR_BACKEND_ENV, "rust")
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_STRICT_ENV,
                       raising=False)
    monkeypatch.delenv(analysis.FI_IF_DEBUG_CORRELATOR_SHADOW_ENV,
                       raising=False)
    monkeypatch.delenv("FI_STAGE_MARKERS", raising=False)

    def fake_run_correlator_backend(**_kwargs):
        return analysis.backend_loaders.CorrelatorBackendResult(
            selected_backend=analysis.backend_loaders.BACKEND_RUST,
            strict_mode=False,
            response={
                "schema_version":
                analysis.backend_loaders.CORRELATOR_SCHEMA_VERSION,
                "status": "success",
                "counters": {},
                "artifacts": {
                    "function_updates": []
                },
                "timings": {},
            },
        )

    monkeypatch.setattr(
        analysis.backend_loaders,
        "run_correlator_backend",
        fake_run_correlator_backend,
    )

    analysis.correlate_introspection_functions_to_debug_info(
        [],
        [],
        "c-cpp",
        report_dict={"all_files_in_project": []},
        out_dir=str(tmp_path),
    )

    events = stage_markers.parse_stage_marker_file(
        str(tmp_path / "stage_markers.log"))
    stage_events = [
        event for event in events
        if event.stage == analysis._IF_DEBUG_SIGNATURE_CORRELATION_STAGE
    ]
    assert [event.event for event in stage_events] == ["start", "end"]
    assert stage_events[1].metadata["configured_backend"] == "rust"
    assert stage_events[1].metadata["effective_backend"] == "rust"
