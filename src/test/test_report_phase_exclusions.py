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
"""Tests for report-phase exclusion handling."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import analysis  # noqa: E402
from fuzz_introspector import commands  # noqa: E402


def test_extract_tests_from_directories_honours_exclude_patterns(monkeypatch):
    project_root = "/workspace/project"
    first_party = "/workspace/project/src/test_main.cpp"
    vendor_file = "/workspace/project/vendor/pkg/test_vendor.cpp"
    dep_file = "/workspace/project/_deps/pkg/test_dep.cpp"
    build_file = "/workspace/project/build123/test_build.cpp"

    tree = {
        project_root: (["src", "vendor", "_deps", "build123"], []),
        "/workspace/project/src": ([], ["test_main.cpp"]),
        "/workspace/project/vendor": (["pkg"], []),
        "/workspace/project/vendor/pkg": ([], ["test_vendor.cpp"]),
        "/workspace/project/_deps": (["pkg"], []),
        "/workspace/project/_deps/pkg": ([], ["test_dep.cpp"]),
        "/workspace/project/build123": ([], ["test_build.cpp"]),
    }

    def fake_walk(start_path):
        stack = [start_path]
        while stack:
            root = stack.pop()
            dirs, files = tree.get(root, ([], []))
            yielded_dirs = list(dirs)
            yield root, yielded_dirs, list(files)
            for directory in reversed(yielded_dirs):
                stack.append(os.path.join(root, directory))

    monkeypatch.setattr(analysis.os, "walk", fake_walk)

    with tempfile.TemporaryDirectory(dir=os.getcwd()) as temp_dir:
        extracted = analysis.extract_tests_from_directories(
            {project_root},
            "c-cpp",
            temp_dir,
            need_copy=False,
            exclude_patterns=[r".*/(vendor|_deps|build[^/]*)/.*"],
        )

    assert first_party in extracted
    assert vendor_file not in extracted
    assert dep_file not in extracted
    assert build_file not in extracted


def test_extract_tests_from_directories_without_patterns_keeps_default_behaviour(
    monkeypatch,
):
    project_root = "/workspace/project"
    first_party = "/workspace/project/src/test_main.cpp"
    vendor_file = "/workspace/project/vendor/pkg/test_vendor.cpp"
    dep_file = "/workspace/project/_deps/pkg/test_dep.cpp"

    tree = {
        project_root: (["src", "vendor", "_deps"], []),
        "/workspace/project/src": ([], ["test_main.cpp"]),
        "/workspace/project/vendor": (["pkg"], []),
        "/workspace/project/vendor/pkg": ([], ["test_vendor.cpp"]),
        "/workspace/project/_deps": (["pkg"], []),
        "/workspace/project/_deps/pkg": ([], ["test_dep.cpp"]),
    }

    def fake_walk(start_path):
        stack = [start_path]
        while stack:
            root = stack.pop()
            dirs, files = tree.get(root, ([], []))
            yielded_dirs = list(dirs)
            yield root, yielded_dirs, list(files)
            for directory in reversed(yielded_dirs):
                stack.append(os.path.join(root, directory))

    monkeypatch.setattr(analysis.os, "walk", fake_walk)

    with tempfile.TemporaryDirectory(dir=os.getcwd()) as temp_dir:
        extracted = analysis.extract_tests_from_directories(
            {project_root}, "c-cpp", temp_dir, need_copy=False
        )

    assert first_party in extracted
    assert vendor_file in extracted
    assert dep_file in extracted


def test_run_analysis_on_dir_loads_and_forwards_report_exclusions(monkeypatch):
    captured_exclusions = {}

    class FakeIntrospectionProject:
        def __init__(self, language, target_folder, coverage_url):
            self.language = language
            self.target_folder = target_folder
            self.coverage_url = coverage_url

        def load_data_files(
            self, parallelise, correlation_file, out_dir, harness_lists
        ):
            del parallelise, correlation_file, out_dir, harness_lists

    def fake_create_html_report(
        introspection_proj,
        analyses_to_run,
        output_json,
        report_name,
        dump_files,
        out_dir="",
        exclude_patterns=None,
    ):
        del introspection_proj, analyses_to_run, output_json
        del report_name, dump_files, out_dir
        captured_exclusions["patterns"] = exclude_patterns

    with tempfile.TemporaryDirectory(dir=os.getcwd()) as temp_dir:
        config_path = Path(temp_dir) / "fuzz_introspector_config.conf"
        config_path.write_text(
            "FUNCS_TO_AVOID\nfoo\nFILES_TO_AVOID\nvendor/.*\n_deps/.*\n",
            encoding="utf-8",
        )

        monkeypatch.setenv("FUZZ_INTROSPECTOR_CONFIG", str(config_path))
        monkeypatch.setattr(
            commands.analysis, "IntrospectionProject", FakeIntrospectionProject
        )
        monkeypatch.setattr(
            commands.html_report, "create_html_report", fake_create_html_report
        )

        commands.run_analysis_on_dir(
            target_folder=temp_dir,
            coverage_url="",
            analyses_to_run=[],
            correlation_file="",
            enable_all_analyses=False,
            report_name="unit-test",
            language="c-cpp",
            output_json=[],
            parallelise=False,
            dump_files=False,
            out_dir=temp_dir,
        )

    assert captured_exclusions["patterns"] == ["vendor/.*", "_deps/.*"]
