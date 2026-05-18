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
"""Tests for FrontendAnalyser orchestration."""

from types import SimpleNamespace

from fuzz_introspector.analyses import frontend_analyser


def test_frontend_analyser_uses_second_run_artifacts_for_introspection_project(
    monkeypatch,
    tmp_path,
) -> None:
    analyser = frontend_analyser.FrontendAnalyser()
    captured = {}

    def fake_detect_language(path):
        captured["detected_path"] = path
        return "c-cpp"

    def fake_analyse_folder(**kwargs):
        captured["analyse_folder"] = kwargs
        return None, None

    class FakeIntrospectionProject:

        def __init__(self, language, target_folder, coverage_url):
            captured["project_ctor"] = {
                "language": language,
                "target_folder": target_folder,
                "coverage_url": coverage_url,
            }
            self.proj_profile = SimpleNamespace()
            self.profiles = []

        def load_data_files(self, parallelise, correlation_file, out_dir):
            captured["load_data_files"] = {
                "parallelise": parallelise,
                "correlation_file": correlation_file,
                "out_dir": out_dir,
            }

    monkeypatch.setattr(frontend_analyser.utils, "detect_language",
                        fake_detect_language)
    monkeypatch.setattr(frontend_analyser.oss_fuzz, "analyse_folder",
                        fake_analyse_folder)
    monkeypatch.setattr(frontend_analyser.analysis, "IntrospectionProject",
                        FakeIntrospectionProject)
    monkeypatch.setattr(analyser, "standalone_analysis", lambda *args: None)
    monkeypatch.setenv("SRC", "/src/project")

    proj_profile = SimpleNamespace(language="c-cpp")
    analyser.analysis_func(
        table_of_contents=SimpleNamespace(),
        tables=[],
        proj_profile=proj_profile,
        profiles=[],
        basefolder="/ignored",
        coverage_url="",
        conclusions=[],
        out_dir=str(tmp_path),
    )

    expected_temp_dir = str(tmp_path / "second-frontend-run")
    assert captured["detected_path"] == "/src/project"
    assert captured["analyse_folder"]["out"] == expected_temp_dir
    assert captured["project_ctor"]["target_folder"] == expected_temp_dir
    assert captured["project_ctor"]["coverage_url"] == ""
    assert captured["load_data_files"]["correlation_file"] == ""
    assert captured["load_data_files"]["out_dir"] == expected_temp_dir
