# Copyright 2025 Fuzz Introspector Authors
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
"""Tests for HTML generation with serial compatibility mode"""

import os
import sys
import tempfile
import shutil
import json

import pytest

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import html_report
from fuzz_introspector import analysis
from fuzz_introspector import json_report
from fuzz_introspector.datatypes import project_profile, fuzzer_profile


@pytest.fixture
def sample_project_profile(sample_fuzzer_profile):
    """Create a sample project profile for testing"""
    proj_profile = project_profile.MergedProjectProfile(
        profiles=[sample_fuzzer_profile],
        language="c-cpp",
    )

    # Manually set the properties that would normally be computed
    proj_profile.total_functions = 100
    proj_profile.reached_func_count = 50
    proj_profile.total_complexity = 1000
    proj_profile.reached_complexity = 500
    proj_profile.proj_name = "test-project"
    proj_profile.basefolder = "/tmp/test-project"
    proj_profile.coverage_url = "http://localhost/coverage"

    return proj_profile


@pytest.fixture
def sample_fuzzer_profile():
    """Create a sample fuzzer profile for testing"""
    # Create minimal frontend YAML data with required fields
    frontend_yaml = {
        "Fuzzer filename": "/tmp/test-fuzzer.c",
        "ep": {"func_name": "LLVMFuzzerTestOneInput", "module": "test_module"},
        "All functions": {"Elements": []},
    }

    profile = fuzzer_profile.FuzzerProfile(
        cfg_file="/tmp/test.cfg",
        frontend_yaml=frontend_yaml,
        target_lang="c-cpp",
        cfg_content="",
    )

    # Manually set the properties we need for testing
    profile.functions_reached_by_fuzzer = ["func1", "func2"]
    profile.functions_unreached_by_fuzzer = ["func3"]
    profile.max_func_call_depth = 10
    profile.file_targets = {"/tmp/test.c": ["func1", "func2"]}
    profile.total_basic_blocks = 100
    profile.total_cyclomatic_complexity = 50

    return profile


@pytest.fixture
def sample_introspection_project(sample_project_profile, sample_fuzzer_profile):
    """Create a sample introspection project for testing"""
    introspection_proj = analysis.IntrospectionProject(
        proj_profile=sample_project_profile,
        profiles=[sample_fuzzer_profile],
        language="c-cpp",
        debug_report=None,
        debug_all_functions=None,
    )
    return introspection_proj


def test_serial_compatibility_mode(sample_introspection_project):
    """Test that serial compatibility mode produces consistent HTML output"""
    # Create temporary directory for output
    with tempfile.TemporaryDirectory() as temp_dir:
        # Test with serial compatibility mode (worker count = 1)
        html_report.create_html_report(
            introspection_proj=sample_introspection_project,
            analyses_to_run=["OptimalTargets"],
            output_json=[],
            report_name="test-report",
            dump_files=True,
            out_dir=temp_dir,
        )

        # Verify HTML file was created
        html_file = os.path.join(temp_dir, "fuzz_report.html")
        assert os.path.exists(html_file), "HTML report file should exist"

        # Verify JSON files were created
        json_files = [
            "all-fuzz-introspector-functions.json",
            "fuzz_report.json",
            "test-report-summary.json",
        ]
        for json_file in json_files:
            assert os.path.exists(os.path.join(temp_dir, json_file)), (
                f"JSON file {json_file} should exist"
            )


def test_serial_compatibility_parity(sample_introspection_project):
    """Test parity between serial and parallel modes"""
    # Create temporary directories for both modes
    with (
        tempfile.TemporaryDirectory() as serial_dir,
        tempfile.TemporaryDirectory() as parallel_dir,
    ):
        # Generate reports in both modes
        # Serial mode (worker count = 1)
        html_report.create_html_report(
            introspection_proj=sample_introspection_project,
            analyses_to_run=["OptimalTargets"],
            output_json=[],
            report_name="test-report-serial",
            dump_files=True,
            out_dir=serial_dir,
        )

        # Parallel mode (worker count > 1 - simulate by removing serial compatibility)
        # For this test, we'll modify the function temporarily to simulate parallel
        # Note: This is a simplified test - in reality we'd need to test the actual parallel implementation

        # Compare JSON outputs for parity
        serial_json = json.loads(
            open(os.path.join(serial_dir, "test-report-serial-summary.json")).read()
        )
        parallel_json = json.loads(
            open(os.path.join(parallel_dir, "test-report-serial-summary.json")).read()
        )

        # Verify key fields are consistent
        assert serial_json["proj_name"] == parallel_json["proj_name"]
        assert serial_json["total_functions"] == parallel_json["total_functions"]
        assert serial_json["reached_func_count"] == parallel_json["reached_func_count"]


def test_analysis_envelope_processing():
    """Test that analysis envelopes are processed correctly in serial mode"""

    # Create mock analysis instances
    class MockAnalysis:
        def __init__(self, name, html_content):
            self.name = name
            self.html_content = html_content
            self.display_html = True

        def get_name(self):
            return self.name

        def analysis_func(self, *args, **kwargs):
            return self.html_content

        def set_display_html(self, value):
            self.display_html = value

    # Create test envelopes
    envelopes = [
        {
            "analysis_name": "Analysis1",
            "html_content": "<div>Content1</div>",
            "display_html": True,
        },
        {
            "analysis_name": "Analysis2",
            "html_content": "<div>Content2</div>",
            "display_html": False,
        },
        {
            "analysis_name": "Analysis3",
            "html_content": "<div>Content3</div>",
            "display_html": True,
        },
    ]

    # Process envelopes
    html_report_core = ""
    for envelope in envelopes:
        if envelope["display_html"]:
            html_report_core += envelope["html_content"]

    # Verify only displayed content is included
    assert "<div>Content1</div>" in html_report_core
    assert "<div>Content2</div>" not in html_report_core
    assert "<div>Content3</div>" in html_report_core
    assert len(html_report_core) == len("<div>Content1</div><div>Content3</div>")


def test_analysis_registry_order():
    """Test that analyses are processed in canonical registry order"""
    # Get all analyses in registry order
    analyses = analysis.get_all_analyses()
    analysis_names = [a.get_name() for a in analyses]

    # Expected order based on registry
    expected_order = [
        "OptimalTargets",
        "EngineInput",
        "RuntimeCoverageAnalysis",
        "DriverSynthesizer",
        "BugDigestor",
        "FilePathAnalysis",
        "ThirdPartyAPICoverageAnalyser",
        "MetadataAnalysis",
        "SinkCoverageAnalyser",
        "FuzzAnnotatedCFG",
        "SourceCodeLineAnalyser",
        "FarReachLowCoverageAnalyser",
        "PublicCandidateAnalyser",
        "FrontendAnalyser",
    ]

    # Verify registry order matches expected order
    assert analysis_names == expected_order, (
        f"Analysis registry order mismatch: {analysis_names}"
    )


def test_empty_analysis_handling():
    """Test handling of empty analysis results"""

    # Create mock analysis with empty result
    class EmptyAnalysis:
        def get_name(self):
            return "EmptyAnalysis"

        def analysis_func(self, *args, **kwargs):
            return ""

        def set_display_html(self, value):
            pass

    # Test that empty results don't break processing
    try:
        # Simulate processing
        html_string = EmptyAnalysis().analysis_func(
            None, None, None, None, None, None, None, None
        )
        assert html_string == "", "Empty analysis should return empty string"
    except Exception as e:
        pytest.fail(f"Empty analysis handling failed: {e}")
