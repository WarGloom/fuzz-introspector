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

from io import StringIO
import os
from pathlib import Path
import sys
import tempfile

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
    monkeypatch, ):
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
        extracted = analysis.extract_tests_from_directories({project_root},
                                                            "c-cpp",
                                                            temp_dir,
                                                            need_copy=False)

    assert first_party in extracted
    assert vendor_file in extracted
    assert dep_file in extracted


def test_extract_tests_from_directories_avoids_file_reads_for_test_named_files(
    monkeypatch, ):
    project_root = "/workspace/project"
    sample_dir = "/workspace/project/sample"
    sample_test_file = "/workspace/project/sample/test_case.cpp"

    tree = {
        project_root: (["sample"], []),
        sample_dir: ([], ["test_case.cpp"]),
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

    def fail_on_open(*args, **kwargs):
        del args, kwargs
        raise AssertionError(
            "extract_tests_from_directories unexpectedly read a file")

    monkeypatch.setattr(analysis.os, "walk", fake_walk)
    monkeypatch.setattr("builtins.open", fail_on_open)

    with tempfile.TemporaryDirectory(dir=os.getcwd()) as temp_dir:
        extracted = analysis.extract_tests_from_directories({project_root},
                                                            "c-cpp",
                                                            temp_dir,
                                                            need_copy=False)

    assert sample_test_file in extracted


def test_extract_test_information_uses_cached_source_scan(monkeypatch):
    report_dict = {
        "all_files_in_project": [{
            "source_file":
            "/workspace/project/src/keep/test_alpha.cpp"
        }]
    }
    source_files = {
        "/workspace/project/src/keep/test_alpha.cpp",
        "/workspace/project/src/keep/sample_test.cpp",
        "/workspace/project/other/test_not_in_scan.cpp",
    }

    monkeypatch.setattr(
        analysis.os, "walk", lambda _:
        (_ for _ in ()).throw(AssertionError("unexpected filesystem walk")))
    monkeypatch.setattr(analysis.shutil, "copy",
                        lambda *_args, **_kwargs: None)

    found = analysis.extract_test_information(
        report_dict=report_dict,
        language="c-cpp",
        out_dir="/tmp",
        source_files=source_files,
    )

    assert found == {
        "/workspace/project/src/keep/test_alpha.cpp",
        "/workspace/project/src/keep/sample_test.cpp",
    }


def test_run_analysis_on_dir_loads_and_forwards_report_exclusions(monkeypatch):
    captured_exclusions = {}

    class FakeIntrospectionProject:

        def __init__(self, language, target_folder, coverage_url):
            self.language = language
            self.target_folder = target_folder
            self.coverage_url = coverage_url

        def load_data_files(
            self,
            parallelise,
            correlation_file,
            out_dir,
            harness_lists,
            exclude_patterns,
            exclude_function_patterns,
        ):
            del parallelise, correlation_file, out_dir, harness_lists
            captured_exclusions["patterns"] = exclude_patterns
            captured_exclusions[
                "function_patterns"] = exclude_function_patterns

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
        monkeypatch.setattr(commands.analysis, "IntrospectionProject",
                            FakeIntrospectionProject)
        monkeypatch.setattr(commands.html_report, "create_html_report",
                            fake_create_html_report)

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
    assert captured_exclusions["function_patterns"] == ["foo"]


def test_extract_all_sources_applies_exclude_patterns(monkeypatch):

    def fake_walk(start_path):
        del start_path
        yield "/src", ["keep", "vendor", "_deps"], []
        yield "/src/keep", [], ["a.cc"]
        yield "/src/vendor", [], ["vendor.cc"]
        yield "/src/_deps", [], ["ignore.cc"]

    monkeypatch.setattr(analysis.os, "walk", fake_walk)

    assert analysis.extract_all_sources(
        "c-cpp",
        [r"/src/vendor/.*", r"/src/_deps/.*"],
    ) == {"/src/keep/a.cc"}


def test_is_non_fuzz_harness_reads_file_once_with_bound(monkeypatch):
    big_payload = "a" * (70 * 1024)

    read_limit = {"bytes": 0}

    class TrackingFile(StringIO):

        def read(self, size: int = -1) -> str:
            read_limit["bytes"] = size
            return big_payload[:size]

    def fake_open(*_args, **_kwargs):
        return TrackingFile("")

    def fake_walk(start_path):
        del start_path
        yield "/workspace/project/sample", [], ["sample_source.cpp"]

    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(analysis.os, "walk", fake_walk)

    extracted = analysis.extract_tests_from_directories(
        {"/workspace/project/sample"},
        "c-cpp",
        "/tmp/out",
        need_copy=False,
    )

    assert "/workspace/project/sample/sample_source.cpp" in extracted
    assert read_limit["bytes"] == 64 * 1024


def test_analyse_loads_and_forwards_report_exclusions(monkeypatch):
    captured = {}

    class FakeStandaloneAnalysis:

        @classmethod
        def get_name(cls) -> str:
            return "DummyAnalyser"

        def standalone_analysis(self, *_args, **_kwargs) -> None:
            captured["standalone_called"] = True

    class FakeIntrospectionProject:

        def __init__(self, language, target_folder, coverage_url):
            captured["init"] = (language, target_folder, coverage_url)

        def load_data_files(self,
                            parallelise,
                            correlation_file,
                            out_dir,
                            harness_lists=None,
                            exclude_patterns=None,
                            exclude_function_patterns=None):
            captured["exclude_patterns"] = exclude_patterns
            captured["exclude_function_patterns"] = exclude_function_patterns
            self.proj_profile = {}
            self.profiles = []

    with tempfile.TemporaryDirectory(dir=os.getcwd()) as temp_dir:
        config_path = Path(temp_dir) / "fuzz_introspector_config.conf"
        config_path.write_text(
            "FILES_TO_AVOID\nvendor/.*\n_tmp/.*\nFUNCS_TO_AVOID\nignored_fn\n",
            encoding="utf-8",
        )

        args = type(
            "Args",
            (),
            {
                "language": "c-cpp",
                "target_dir": "/workspace/project",
                "out_dir": temp_dir,
                "analyser": "DummyAnalyser",
                "source_file": "",
                "source_line": 0,
                "exclude_static_functions": False,
                "only_referenced_functions": False,
                "only_header_functions": False,
                "only_interesting_functions": False,
                "only_easy_fuzz_params": False,
                "max_functions": 0,
            },
        )()

        monkeypatch.setenv("FUZZ_INTROSPECTOR_CONFIG", str(config_path))
        monkeypatch.setattr(commands.analysis, "get_all_standalone_analyses",
                            lambda: [FakeStandaloneAnalysis])
        monkeypatch.setattr(commands.analysis, "IntrospectionProject",
                            FakeIntrospectionProject)
        monkeypatch.setattr(commands.oss_fuzz, "analyse_folder",
                            lambda **kwargs: None)

        assert commands.analyse(args) == 0

    assert captured["exclude_patterns"] == ["vendor/.*", "_tmp/.*"]
    assert captured["exclude_function_patterns"] == ["ignored_fn"]
    assert captured["standalone_called"]


def test_load_report_exclusion_patterns_from_config_reads_file_and_function_lists(
):
    with tempfile.TemporaryDirectory(dir=os.getcwd()) as temp_dir:
        config_path = Path(temp_dir) / "fuzz_introspector_config.conf"
        config_path.write_text(
            "FILES_TO_AVOID\nvendor/.*\nFUNCS_TO_AVOID\nfoo::bar\n\n",
            encoding="utf-8",
        )

        file_patterns, function_patterns = (
            commands.load_report_exclusion_patterns_from_config(
                str(config_path)))

    assert file_patterns == ["vendor/.*"]
    assert function_patterns == ["foo::bar"]


def test_load_report_exclusion_patterns_from_config_accepts_header_suffixes():
    with tempfile.TemporaryDirectory(dir=os.getcwd()) as temp_dir:
        config_path = Path(temp_dir) / "fuzz_introspector_config.conf"
        config_path.write_text(
            "FILES_TO_AVOID:\nvendor/.*\nFUNCS_TO_AVOID:\nfoo::bar\n",
            encoding="utf-8",
        )

        file_patterns, function_patterns = (
            commands.load_report_exclusion_patterns_from_config(
                str(config_path)))

    assert file_patterns == ["vendor/.*"]
    assert function_patterns == ["foo::bar"]


def test_load_report_exclusion_patterns_accepts_header_colon_values():
    with tempfile.TemporaryDirectory(dir=os.getcwd()) as temp_dir:
        config_path = Path(temp_dir) / "fuzz_introspector_config.conf"
        config_path.write_text(
            "FILES_TO_AVOID:ignored\nvendor/.*\n"
            "FUNCS_TO_AVOID:ignored\nfoo::bar\n",
            encoding="utf-8",
        )

        file_patterns, function_patterns = (
            commands.load_report_exclusion_patterns_from_config(
                str(config_path)))

    assert file_patterns == ["vendor/.*"]
    assert function_patterns == ["foo::bar"]
