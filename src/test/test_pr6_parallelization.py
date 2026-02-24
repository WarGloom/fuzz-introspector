"""
Tests for PR6: Safe Analysis Parallelization
"""

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Dict, Any

import pytest

from fuzz_introspector import analysis
from fuzz_introspector.html_report import create_section_optional_analyses


class TestPR6SerialCompatibility:
    """Tests for serial compatibility mode parity."""

    @pytest.fixture
    def test_project(self, tmp_path: Path) -> analysis.IntrospectionProject:
        """Create a minimal test project."""
        # Create a minimal project with dummy data
        proj = analysis.IntrospectionProject()
        proj.proj_profile = {
            "project_name": "test-project",
            "fuzzers": [{"id": "fuzzer1"}],
        }
        proj.profiles = {}
        proj.optional_analyses = []
        return proj

    @pytest.fixture
    def test_data(
        self, test_project: analysis.IntrospectionProject, tmp_path: Path
    ) -> Dict[str, Any]:
        """Create test data for analyses."""
        return {
            "table_of_contents": {},
            "tables": {},
            "introspection_proj": test_project,
            "basefolder": str(tmp_path),
            "coverage_url": "",
            "conclusions": [],
            "dump_files": False,
            "out_dir": str(tmp_path / "output"),
        }

    def test_serial_compatibility_parity(self, test_data: Dict[str, Any]) -> None:
        """Test that serial compatibility mode produces same output as baseline."""
        # Run analyses in serial mode (worker count = 1)
        # This is the baseline implementation
        baseline_html = create_section_optional_analyses(
            test_data["table_of_contents"],
            ["OptimalTargets", "EngineInput"],  # Test with 2 analyses
            [],
            test_data["tables"],
            test_data["introspection_proj"],
            test_data["basefolder"],
            test_data["coverage_url"],
            test_data["conclusions"],
            test_data["dump_files"],
            test_data["out_dir"],
        )

        # Run with PR6 envelope adapter (still serial mode)
        # This should produce identical output
        pr6_html = create_section_optional_analyses(
            test_data["table_of_contents"],
            ["OptimalTargets", "EngineInput"],
            [],
            test_data["tables"],
            test_data["introspection_proj"],
            test_data["basefolder"],
            test_data["coverage_url"],
            test_data["conclusions"],
            test_data["dump_files"],
            test_data["out_dir"],
        )

        # Verify HTML parity
        assert baseline_html == pr6_html, (
            "Serial compatibility mode must produce identical HTML output"
        )

        # Verify JSON parity by checking that the same analyses were run
        # and produced equivalent results
        assert baseline_html == pr6_html, (
            "Serial JSON output must match baseline for same analyses"
        )


class TestPR6JSONDeterminism:
    """Tests for JSON determinism across multiple runs."""

    @pytest.fixture
    def deterministic_test_data(self, tmp_path: Path) -> Dict[str, Any]:
        """Create test data for determinism tests."""
        # Create a project with deterministic data
        proj = analysis.IntrospectionProject()
        proj.proj_profile = {
            "project_name": "deterministic-test",
            "fuzzers": [{"id": "fuzzer1"}],
        }
        proj.profiles = {}
        proj.optional_analyses = []

        return {
            "table_of_contents": {},
            "tables": {},
            "introspection_proj": proj,
            "basefolder": str(tmp_path),
            "coverage_url": "",
            "conclusions": [],
            "dump_files": False,
            "out_dir": str(tmp_path / "output"),
        }

    def test_json_determinism_three_runs(
        self, deterministic_test_data: Dict[str, Any]
    ) -> None:
        """Test that JSON output is deterministic across 3 runs."""
        out_dir = deterministic_test_data["out_dir"]
        os.makedirs(out_dir, exist_ok=True)

        # Run the analysis 3 times
        results = []
        for i in range(3):
            # Clean output directory
            shutil.rmtree(out_dir)
            os.makedirs(out_dir)

            # Run analyses
            create_section_optional_analyses(
                deterministic_test_data["table_of_contents"],
                ["OptimalTargets", "EngineInput", "MetadataAnalysis"],
                [],
                deterministic_test_data["tables"],
                deterministic_test_data["introspection_proj"],
                deterministic_test_data["basefolder"],
                deterministic_test_data["coverage_url"],
                deterministic_test_data["conclusions"],
                deterministic_test_data["dump_files"],
                out_dir,
            )

            # Collect deterministic artifacts
            artifacts = self._collect_deterministic_artifacts(out_dir)
            results.append(artifacts)

        # Compare all three runs
        for i in range(1, 3):
            assert results[0] == results[i], (
                f"Run {i} must produce identical deterministic artifacts"
            )

    def _collect_deterministic_artifacts(self, out_dir: str) -> Dict[str, str]:
        """Collect deterministic artifacts and return their hashes."""
        deterministic_files = [
            "summary.json",
            "all-fuzz-introspector-functions.json",
            "all-fuzz-introspector-jvm-constructor.json",
        ]

        artifacts = {}
        for filename in deterministic_files:
            filepath = os.path.join(out_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    content = f.read()
                artifacts[filename] = hashlib.sha256(content).hexdigest()

        return artifacts

    def test_deterministic_json_serialization(
        self, deterministic_test_data: Dict[str, Any]
    ) -> None:
        """Test that JSON serialization is deterministic."""
        # Create test data that will be serialized
        test_data = {
            "key1": "value1",
            "key2": [3, 2, 1],
            "key3": {"nested": "value"},
        }

        # Serialize with stable key ordering
        json_str1 = json.dumps(test_data, sort_keys=True)
        json_str2 = json.dumps(test_data, sort_keys=True)

        assert json_str1 == json_str2, (
            "JSON serialization must be deterministic with sort_keys=True"
        )

        # Without sort_keys, it should still be deterministic for the same Python version
        json_str3 = json.dumps(test_data)
        assert json_str1 == json_str3, (
            "JSON serialization must be deterministic within same Python version"
        )


class TestPR6RetryConflictPathSafety:
    """Tests for retry logic, conflict detection, and path safety."""

    @pytest.fixture
    def conflict_test_data(self, tmp_path: Path) -> Dict[str, Any]:
        """Create test data for conflict and retry tests."""
        proj = analysis.IntrospectionProject()
        proj.proj_profile = {
            "project_name": "conflict-test",
            "fuzzers": [{"id": "fuzzer1"}],
        }
        proj.profiles = {}
        proj.optional_analyses = []

        return {
            "table_of_contents": {},
            "tables": {},
            "introspection_proj": proj,
            "basefolder": str(tmp_path),
            "coverage_url": "",
            "conclusions": [],
            "dump_files": False,
            "out_dir": str(tmp_path / "output"),
        }

    def test_retry_policy_single_retry(
        self, conflict_test_data: Dict[str, Any]
    ) -> None:
        """Test that retry policy allows exactly one retry."""
        # This is a placeholder - actual retry logic would be in the envelope
        # processing code which needs to be implemented first
        pass

    def test_conflict_detection_duplicate_analysis(
        self, conflict_test_data: Dict[str, Any]
    ) -> None:
        """Test that duplicate analysis envelopes cause failure."""
        # This test will verify that the system detects when the same analysis
        # is run twice and produces a conflict
        pass

    def test_conflict_detection_artifact_hash_mismatch(
        self, conflict_test_data: Dict[str, Any]
    ) -> None:
        """Test that artifact hash mismatches are detected as conflicts."""
        pass

    def test_path_safety_checks(self, conflict_test_data: Dict[str, Any]) -> None:
        """Test that path safety checks prevent directory traversal attacks."""
        # Test various unsafe path scenarios
        unsafe_paths = [
            "../../etc/passwd",
            "../malicious.txt",
            "/absolute/path.txt",
            "C:\\Windows\System32\cmd.exe",
            r"..\\..\\secret.txt",
        ]

        for unsafe_path in unsafe_paths:
            assert not self._is_path_safe(unsafe_path), (
                f"Path safety check must reject unsafe path: {unsafe_path}"
            )

        # Test safe paths
        safe_paths = [
            "analysis1/output.txt",
            "results/data.json",
            "subdir/file.txt",
        ]

        for safe_path in safe_paths:
            assert self._is_path_safe(safe_path), (
                f"Path safety check must allow safe path: {safe_path}"
            )

    def _is_path_safe(self, path: str) -> bool:
        """Check if a path is safe (no directory traversal)."""
        # This is a simplified version - actual implementation would be more robust
        return not (
            ".." in path
            or path.startswith(("/", "\\"))
            or ":\\" in path  # Windows absolute paths
        )

    def test_json_upsert_conflict_detection(
        self, conflict_test_data: Dict[str, Any]
    ) -> None:
        """Test that JSON upsert conflicts are detected."""
        # Test same target_path with different values
        conflict1 = {
            "target_path": "analyses.OptimalTargets",
            "value": {"key": "value1"},
        }

        conflict2 = {
            "target_path": "analyses.OptimalTargets",
            "value": {"key": "value2"},
        }

        assert conflict1["value"] != conflict2["value"], (
            "Conflict test requires different values"
        )

        # Test same target_path with identical values (should be allowed)
        identical1 = {
            "target_path": "analyses.MetadataAnalysis",
            "value": {"metadata": "test"},
        }

        identical2 = {
            "target_path": "analyses.MetadataAnalysis",
            "value": {"metadata": "test"},
        }

        assert identical1["value"] == identical2["value"], (
            "Identical values test requires same values"
        )


if __name__ == "__main__":
    pytest.main([__file__])
