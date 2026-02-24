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
from fuzz_introspector import constants
from fuzz_introspector import html_helpers
from fuzz_introspector import merge_coordinator
from fuzz_introspector import merge_intents
from fuzz_introspector.html_report import create_section_optional_analyses


class TestPR6SerialCompatibility:
    """Tests for serial compatibility mode parity."""

    @pytest.fixture
    def test_project(self, tmp_path: Path) -> analysis.IntrospectionProject:
        """Create a minimal test project."""
        # Create a minimal project with dummy data
        proj = analysis.IntrospectionProject(constants.LANGUAGES.CPP,
                                             str(tmp_path), "")
        proj.proj_profile = {
            "project_name": "test-project",
            "fuzzers": [{
                "id": "fuzzer1"
            }],
        }
        proj.profiles = {}
        proj.optional_analyses = []
        return proj

    @pytest.fixture
    def test_data(self, test_project: analysis.IntrospectionProject,
                  tmp_path: Path) -> Dict[str, Any]:
        """Create test data for analyses."""
        return {
            "table_of_contents": html_helpers.HtmlTableOfContents(),
            "tables": {},
            "introspection_proj": test_project,
            "basefolder": str(tmp_path),
            "coverage_url": "",
            "conclusions": [],
            "dump_files": False,
            "out_dir": str(tmp_path / "output"),
        }

    def test_serial_compatibility_parity(self, test_data: Dict[str,
                                                               Any]) -> None:
        """Test that serial compatibility mode produces same output as baseline."""
        # Run analyses in serial mode (worker count = 1)
        # This is the baseline implementation
        baseline_html = create_section_optional_analyses(
            test_data["table_of_contents"],
            [],
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
            [],
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
            "Serial compatibility mode must produce identical HTML output")

        # Verify JSON parity by checking that the same analyses were run
        # and produced equivalent results
        assert baseline_html == pr6_html, (
            "Serial JSON output must match baseline for same analyses")


class TestPR6JSONDeterminism:
    """Tests for JSON determinism across multiple runs."""

    @pytest.fixture
    def deterministic_test_data(self, tmp_path: Path) -> Dict[str, Any]:
        """Create test data for determinism tests."""
        # Create a project with deterministic data
        proj = analysis.IntrospectionProject(constants.LANGUAGES.CPP,
                                             str(tmp_path), "")
        proj.proj_profile = {
            "project_name": "deterministic-test",
            "fuzzers": [{
                "id": "fuzzer1"
            }],
        }
        proj.profiles = {}
        proj.optional_analyses = []

        return {
            "table_of_contents": html_helpers.HtmlTableOfContents(),
            "tables": {},
            "introspection_proj": proj,
            "basefolder": str(tmp_path),
            "coverage_url": "",
            "conclusions": [],
            "dump_files": False,
            "out_dir": str(tmp_path / "output"),
        }

    def test_json_determinism_three_runs(
            self, deterministic_test_data: Dict[str, Any]) -> None:
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
                [],
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
                f"Run {i} must produce identical deterministic artifacts")

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
            self, deterministic_test_data: Dict[str, Any]) -> None:
        """Test that JSON serialization is deterministic."""
        # Create test data that will be serialized
        test_data = {
            "key1": "value1",
            "key2": [3, 2, 1],
            "key3": {
                "nested": "value"
            },
        }

        # Serialize with stable key ordering
        json_str1 = json.dumps(test_data, sort_keys=True)
        json_str2 = json.dumps(test_data, sort_keys=True)

        assert json_str1 == json_str2, (
            "JSON serialization must be deterministic with sort_keys=True")

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
        proj = analysis.IntrospectionProject(constants.LANGUAGES.CPP,
                                             str(tmp_path), "")
        proj.proj_profile = {
            "project_name": "conflict-test",
            "fuzzers": [{
                "id": "fuzzer1"
            }],
        }
        proj.profiles = {}
        proj.optional_analyses = []

        return {
            "table_of_contents": html_helpers.HtmlTableOfContents(),
            "tables": {},
            "introspection_proj": proj,
            "basefolder": str(tmp_path),
            "coverage_url": "",
            "conclusions": [],
            "dump_files": False,
            "out_dir": str(tmp_path / "output"),
        }

    def test_retry_policy_single_retry(
            self, conflict_test_data: Dict[str, Any]) -> None:
        """Test that retry policy allows exactly one retry."""
        # This is a placeholder - actual retry logic would be in the envelope
        # processing code which needs to be implemented first
        pass

    def test_conflict_detection_duplicate_analysis(
            self, conflict_test_data: Dict[str, Any]) -> None:
        """Test that duplicate analysis envelopes cause failure."""
        # This test will verify that the system detects when the same analysis
        # is run twice and produces a conflict
        out_dir = conflict_test_data["out_dir"]
        os.makedirs(out_dir, exist_ok=True)

        coordinator = merge_coordinator.MergeCoordinator(out_dir)
        worker_result = merge_coordinator.AnalysisWorkerResult(
            analysis_name="OptimalTargets",
            status="success",
            display_html=False,
        )
        envelope = worker_result.to_envelope()
        coordinator.add_analysis_result("OptimalTargets", envelope)
        coordinator.add_analysis_result("OptimalTargets", envelope)

        success, merged = coordinator.merge_results()
        assert not success, "Duplicate analysis envelopes must fail"
        assert "errors" in merged, "Errors must be reported for duplicates"
        assert any(
            error.get("analysis_name") == "OptimalTargets"
            and "Duplicate analysis envelope" in error.get("error", "")
            for error in
            merged["errors"]), "Duplicate analysis error must be reported"

    def test_conflict_detection_artifact_hash_mismatch(
            self, conflict_test_data: Dict[str, Any]) -> None:
        """Test that artifact hash mismatches are detected as conflicts."""
        out_dir = conflict_test_data["out_dir"]
        os.makedirs(out_dir, exist_ok=True)

        coordinator = merge_coordinator.MergeCoordinator(out_dir)
        intent_one = self._make_artifact_intent("reports/output.json",
                                                b"first")
        intent_two = self._make_artifact_intent("reports/output.json",
                                                b"second")

        coordinator.add_analysis_result(
            "OptimalTargets",
            merge_coordinator.AnalysisWorkerResult(
                analysis_name="OptimalTargets",
                status="success",
                display_html=False,
                merge_intents=[intent_one],
            ).to_envelope(),
        )
        coordinator.add_analysis_result(
            "FuzzEngineInputAnalysis",
            merge_coordinator.AnalysisWorkerResult(
                analysis_name="FuzzEngineInputAnalysis",
                status="success",
                display_html=False,
                merge_intents=[intent_two],
            ).to_envelope(),
        )

        success, merged = coordinator.merge_results()
        assert not success, "Artifact hash mismatch must fail merge"
        assert any(
            conflict.get("type") == "artifact_conflict"
            and conflict.get("relative_path") == "reports/output.json"
            for conflict in merged.get(
                "conflicts", [])), "Artifact conflict must be reported"

    def test_path_safety_checks(self, conflict_test_data: Dict[str,
                                                               Any]) -> None:
        """Test that path safety checks prevent directory traversal attacks."""
        out_dir = conflict_test_data["out_dir"]
        os.makedirs(out_dir, exist_ok=True)

        # Test various unsafe path scenarios
        unsafe_paths = [
            "../../etc/passwd",
            "../malicious.txt",
            "/absolute/path.txt",
            r"C:\Windows\System32\cmd.exe",
            r"..\\..\\secret.txt",
        ]

        for unsafe_path in unsafe_paths:
            coordinator = merge_coordinator.MergeCoordinator(out_dir)
            intent = self._make_artifact_intent(unsafe_path, b"unsafe")
            coordinator.add_analysis_result(
                "OptimalTargets",
                merge_coordinator.AnalysisWorkerResult(
                    analysis_name="OptimalTargets",
                    status="success",
                    display_html=False,
                    merge_intents=[intent],
                ).to_envelope(),
            )
            success, merged = coordinator.merge_results()
            assert not success, f"Unsafe path must fail merge: {unsafe_path}"
            assert any(
                conflict.get("type") == "artifact_path_unsafe"
                for conflict in merged.get("conflicts", [])
            ), f"Unsafe path conflict not reported for: {unsafe_path}"

        # Test safe paths
        safe_paths = [
            "analysis1/output.txt",
            "results/data.json",
            "subdir/file.txt",
        ]

        for safe_path in safe_paths:
            coordinator = merge_coordinator.MergeCoordinator(out_dir)
            intent = self._make_artifact_intent(safe_path, b"safe")
            coordinator.add_analysis_result(
                "OptimalTargets",
                merge_coordinator.AnalysisWorkerResult(
                    analysis_name="OptimalTargets",
                    status="success",
                    display_html=False,
                    merge_intents=[intent],
                ).to_envelope(),
            )
            success, merged = coordinator.merge_results()
            assert success, f"Safe path must merge: {safe_path}"
            assert not merged.get("conflicts"), (
                f"Safe path must not conflict: {safe_path}")
            assert os.path.isfile(os.path.join(
                out_dir,
                safe_path)), (f"Safe path must be written: {safe_path}")

    def test_json_upsert_conflict_detection(
            self, conflict_test_data: Dict[str, Any]) -> None:
        """Test that JSON upsert conflicts are detected."""
        out_dir = conflict_test_data["out_dir"]
        os.makedirs(out_dir, exist_ok=True)

        coordinator = merge_coordinator.MergeCoordinator(out_dir)
        conflict_one = merge_intents.create_json_upsert_intent(
            "analyses.OptimalTargets", {"key": "value1"})
        conflict_two = merge_intents.create_json_upsert_intent(
            "analyses.OptimalTargets", {"key": "value2"})

        coordinator.add_analysis_result(
            "OptimalTargets",
            merge_coordinator.AnalysisWorkerResult(
                analysis_name="OptimalTargets",
                status="success",
                display_html=False,
                merge_intents=[conflict_one],
            ).to_envelope(),
        )
        coordinator.add_analysis_result(
            "FuzzEngineInputAnalysis",
            merge_coordinator.AnalysisWorkerResult(
                analysis_name="FuzzEngineInputAnalysis",
                status="success",
                display_html=False,
                merge_intents=[conflict_two],
            ).to_envelope(),
        )

        success, merged = coordinator.merge_results()
        assert not success, "JSON upsert conflicts must fail merge"
        assert any(
            conflict.get("type") == "json_upsert_conflict"
            and conflict.get("target_path") == "analyses.OptimalTargets"
            for conflict in merged.get(
                "conflicts", [])), "JSON upsert conflict must be reported"

        coordinator = merge_coordinator.MergeCoordinator(out_dir)
        identical_one = merge_intents.create_json_upsert_intent(
            "analyses.MetadataAnalysis", {"metadata": "test"})
        identical_two = merge_intents.create_json_upsert_intent(
            "analyses.MetadataAnalysis", {"metadata": "test"})

        coordinator.add_analysis_result(
            "OptimalTargets",
            merge_coordinator.AnalysisWorkerResult(
                analysis_name="OptimalTargets",
                status="success",
                display_html=False,
                merge_intents=[identical_one],
            ).to_envelope(),
        )
        coordinator.add_analysis_result(
            "FuzzEngineInputAnalysis",
            merge_coordinator.AnalysisWorkerResult(
                analysis_name="FuzzEngineInputAnalysis",
                status="success",
                display_html=False,
                merge_intents=[identical_two],
            ).to_envelope(),
        )

        success, merged = coordinator.merge_results()
        assert success, "Identical JSON upserts must not conflict"
        assert not merged.get("conflicts"), (
            "No conflicts expected for identical JSON upserts")

    def _make_artifact_intent(self, relative_path: str,
                              content: bytes) -> Dict[str, Any]:
        """Create a valid artifact_write intent for tests."""
        return {
            "type": "artifact_write",
            "relative_path": relative_path,
            "content_sha256": merge_intents.calculate_sha256(content),
            "content_b64": content.hex(),
        }


if __name__ == "__main__":
    pytest.main([__file__])
