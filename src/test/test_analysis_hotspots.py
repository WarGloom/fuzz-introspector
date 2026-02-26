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

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import analysis  # noqa: E402


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
        _make_debug_function("exact", "/src/project/target.cc", "20"),
    ]

    analysis.correlate_introspection_functions_to_debug_info(
        llvm_functions,
        debug_functions,
        "c-cpp",
        report_dict={"all_files_in_project": []},
    )

    assert llvm_functions[0]["function_signature"] == "sig::exact"
    assert llvm_functions[0]["debug_function_info"]["name"] == "exact"


def test_correlate_introspection_functions_uses_closest_preceding_line(
        monkeypatch):
    monkeypatch.setattr(
        analysis,
        "convert_debug_info_to_signature_v2",
        lambda debug_function, _: f"sig::{debug_function['name']}",
    )

    llvm_functions = [{
        "Func name": "target",
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

    assert llvm_functions[0]["function_signature"] == "sig::before"
    assert llvm_functions[0]["debug_function_info"]["name"] == "before"


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
