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
"""Merge coordinator for analysis parallelization."""

import hashlib
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from fuzz_introspector import constants
from fuzz_introspector.merge_intents import (
    MergeIntentValidationError,
    PathSafetyError,
    validate_path_safety,
    validate_merge_intent,
)

logger = logging.getLogger(__name__)


class MergeCoordinator:
    """Coordinates merging of analysis results from parallel workers."""

    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        self.merged_content: Dict[str, Any] = {}
        self.merged_json_report: Dict[str, Any] = {}
        self.merged_artifacts: Dict[str, str] = {}
        self.analysis_results: Dict[str, Dict[str, Any]] = {}
        self.conflicts: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self._table_id_set: set[str] = set()

    def add_analysis_result(self, analysis_name: str,
                            result: Dict[str, Any]) -> None:
        """Add a result envelope from an analysis worker."""
        try:
            # Validate the envelope schema
            self._validate_envelope(analysis_name, result)

            # Check for duplicate analysis
            if analysis_name in self.analysis_results:
                raise ValueError(
                    f"Duplicate analysis envelope for {analysis_name}")

            self.analysis_results[analysis_name] = result

        except Exception as e:
            self.errors.append({
                "analysis_name": analysis_name,
                "error": str(e),
                "result": result
            })

    def _validate_envelope(self, analysis_name: str,
                           envelope: Dict[str, Any]) -> None:
        """Validate an analysis result envelope."""
        required_fields = [
            "schema_version",
            "analysis_name",
            "status",
            "display_html",
            "html_fragment",
            "conclusions",
            "table_specs",
            "merge_intents",
            "diagnostics",
        ]

        for field in required_fields:
            if field not in envelope:
                raise ValueError(f"Missing required field: {field}")

        # Validate schema version
        if envelope["schema_version"] != 1:
            raise ValueError(
                f"Unsupported schema version: {envelope['schema_version']}")

        # Validate analysis name matches
        if envelope["analysis_name"] != analysis_name:
            raise ValueError(
                f"Envelope analysis_name {envelope['analysis_name']} "
                f"does not match expected {analysis_name}")

        # Validate status
        valid_statuses = ["success", "retryable_error", "fatal_error"]
        if envelope["status"] not in valid_statuses:
            raise ValueError(f"Invalid status: {envelope['status']}")

        # Validate merge intents
        for intent in envelope.get("merge_intents", []):
            try:
                validate_merge_intent(intent)
            except MergeIntentValidationError as e:
                raise ValueError(f"Invalid merge intent: {str(e)}")

    def merge_results(self) -> Tuple[bool, Dict[str, Any]]:
        """Merge all analysis results into final report structure."""
        if self.errors:
            return False, {"errors": self.errors}

        # Merge in canonical order
        canonical_order = self._get_canonical_order()

        for analysis_name in canonical_order:
            if analysis_name not in self.analysis_results:
                self.errors.append({
                    "analysis_name": analysis_name,
                    "error": "Missing analysis result"
                })
                continue

            result = self.analysis_results[analysis_name]
            self._merge_single_result(analysis_name, result)

        if self.conflicts:
            return False, {"conflicts": self.conflicts, "errors": self.errors}

        # Write merged artifacts
        self._write_merged_artifacts()

        if self.conflicts:
            return False, {"conflicts": self.conflicts, "errors": self.errors}

        # Write merged summary.json updates
        self._write_merged_summary_report()

        if self.errors:
            return False, {"errors": self.errors}

        if self.conflicts:
            return False, {"conflicts": self.conflicts, "errors": self.errors}

        return True, self.merged_content

    def _get_canonical_order(self) -> List[str]:
        """Get canonical analysis order from registry."""
        from fuzz_introspector.analyses import all_analyses

        # Filter analyses that actually ran
        analyses_in_results = set(self.analysis_results.keys())

        canonical_order: List[str] = []
        for analysis_cls in all_analyses:
            analysis_name = analysis_cls.get_name()
            if analysis_name in analyses_in_results:
                canonical_order.append(analysis_name)

        remaining = [
            analysis_name for analysis_name in self.analysis_results.keys()
            if analysis_name not in canonical_order
        ]
        canonical_order.extend(remaining)

        return canonical_order

    def _merge_single_result(self, analysis_name: str,
                             result: Dict[str, Any]) -> None:
        """Merge a single analysis result into the final structure."""
        # Merge JSON upserts
        for intent in result.get("merge_intents", []):
            if intent["type"] == "json_upsert":
                self._merge_json_upsert(intent)

        # Merge conclusions
        if "conclusions" in result:
            if "conclusions" not in self.merged_content:
                self.merged_content["conclusions"] = []
            self.merged_content["conclusions"].extend(result["conclusions"])

        # Store HTML fragment if display_html is True
        if result.get("display_html", False):
            if "html_fragments" not in self.merged_content:
                self.merged_content["html_fragments"] = []
            self.merged_content["html_fragments"].append({
                "analysis_name":
                analysis_name,
                "html":
                result["html_fragment"],
            })

        if "toc_entries" in result:
            if "toc_entries" not in self.merged_content:
                self.merged_content["toc_entries"] = []
            self.merged_content["toc_entries"].extend(result["toc_entries"])

        if "table_ids" in result:
            if "table_ids" not in self.merged_content:
                self.merged_content["table_ids"] = []
            for table_id in result["table_ids"]:
                if table_id in self._table_id_set:
                    self.conflicts.append({
                        "type": "table_id_conflict",
                        "table_id": table_id,
                    })
                    continue
                self._table_id_set.add(table_id)
                self.merged_content["table_ids"].append(table_id)

    def _merge_json_upsert(self, intent: Dict[str, Any]) -> None:
        """Merge a JSON upsert intent."""
        target_path = intent["target_path"]
        value = intent["value"]

        # Navigate to target location
        current = self.merged_json_report
        parts = target_path.split(".")

        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1
            if is_last:
                # Last part: perform the upsert
                if part in current:
                    existing_value = current[part]
                    if existing_value != value:
                        self.conflicts.append({
                            "type": "json_upsert_conflict",
                            "target_path": target_path,
                            "existing_value": existing_value,
                            "new_value": value,
                        })
                        return
                current[part] = value
            else:
                # Navigate deeper
                if part not in current:
                    current[part] = {}
                current = current[part]

    def _write_merged_artifacts(self) -> None:
        """Write all merged artifacts to disk."""
        artifact_intents = self._get_all_artifact_intents()
        planned_artifacts = self._prevalidate_artifact_intents(
            artifact_intents)
        if self.conflicts or self.errors:
            return

        for plan in planned_artifacts.values():
            self._commit_artifact_plan(plan)

    def _write_merged_summary_report(self) -> None:
        """Apply merged json_upsert intents to summary.json."""
        if not self.merged_json_report:
            return

        if not constants.should_dump_files:
            return

        summary_path = os.path.join(self.out_dir, constants.SUMMARY_FILE)
        if os.path.isfile(summary_path):
            try:
                with open(summary_path, "r") as summary_fd:
                    summary_contents = json.load(summary_fd)
            except Exception as exc:
                self.errors.append({
                    "error": f"Failed to read summary.json: {exc}",
                    "path": summary_path,
                })
                return
        else:
            summary_contents = {}

        analyses_updates = self.merged_json_report.get("analyses")
        if analyses_updates:
            summary_contents.setdefault("analyses", {})
            self._merge_nested_dict(summary_contents["analyses"],
                                    analyses_updates)

        project_updates = self.merged_json_report.get("project")
        if project_updates:
            summary_contents.setdefault(constants.JSON_REPORT_KEY_PROJECT, {})
            self._merge_nested_dict(
                summary_contents[constants.JSON_REPORT_KEY_PROJECT],
                project_updates)

        fuzzer_updates = self.merged_json_report.get("fuzzers")
        if fuzzer_updates:
            for fuzzer_name, updates in fuzzer_updates.items():
                summary_contents.setdefault(fuzzer_name, {})
                self._merge_nested_dict(summary_contents[fuzzer_name], updates)

        try:
            with open(summary_path, "w") as summary_fd:
                json.dump(summary_contents, summary_fd)
        except Exception as exc:
            self.errors.append({
                "error": f"Failed to write summary.json: {exc}",
                "path": summary_path,
            })

    def _merge_nested_dict(self, target: Dict[str, Any],
                           updates: Dict[str, Any]) -> None:
        """Recursively merge updates into target dict."""
        for key, value in updates.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                self._merge_nested_dict(target[key], value)
            else:
                target[key] = value

    def _get_all_artifact_intents(self) -> List[Dict[str, Any]]:
        """Get all artifact intents from all analysis results."""
        artifact_intents = []
        for result in self.analysis_results.values():
            for intent in result.get("merge_intents", []):
                if intent["type"] == "artifact_write":
                    artifact_intents.append(intent)
        return artifact_intents

    def _prevalidate_artifact_intents(
            self, intents: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Validate artifact intents and build write plans."""
        planned_artifacts: Dict[str, Dict[str, Any]] = {}

        for intent in intents:
            relative_path = intent["relative_path"]
            content_sha256 = intent["content_sha256"]

            try:
                validate_path_safety(relative_path, self.out_dir)
            except PathSafetyError as exc:
                self.conflicts.append({
                    "type": "artifact_path_unsafe",
                    "relative_path": relative_path,
                    "error": str(exc),
                })
                continue

            if relative_path in planned_artifacts:
                existing_sha256 = planned_artifacts[relative_path][
                    "content_sha256"]
                if existing_sha256 != content_sha256:
                    self.conflicts.append({
                        "type": "artifact_conflict",
                        "relative_path": relative_path,
                        "existing_sha256": existing_sha256,
                        "new_sha256": content_sha256,
                    })
                continue

            plan: Dict[str, Any] = {
                "relative_path": relative_path,
                "content_sha256": content_sha256,
            }

            if "content_b64" in intent:
                try:
                    content = bytes.fromhex(intent["content_b64"])
                except ValueError as exc:
                    self.errors.append({
                        "error": f"Invalid content_b64: {exc}",
                        "relative_path": relative_path,
                    })
                    continue
                calculated_sha256 = hashlib.sha256(content).hexdigest()
                if calculated_sha256 != content_sha256:
                    self.conflicts.append({
                        "type": "artifact_content_hash_mismatch",
                        "relative_path": relative_path,
                        "expected_sha256": content_sha256,
                        "actual_sha256": calculated_sha256,
                    })
                    continue
                plan["content_bytes"] = content
            elif "temp_file_ref" in intent:
                temp_path = intent["temp_file_ref"]
                if not os.path.isfile(temp_path):
                    self.errors.append({
                        "error": f"Temp file not found: {temp_path}",
                        "relative_path": relative_path,
                    })
                    continue

                with open(temp_path, "rb") as file_handle:
                    content = file_handle.read()
                calculated_sha256 = hashlib.sha256(content).hexdigest()
                if calculated_sha256 != content_sha256:
                    self.conflicts.append({
                        "type": "artifact_content_hash_mismatch",
                        "relative_path": relative_path,
                        "expected_sha256": content_sha256,
                        "actual_sha256": calculated_sha256,
                    })
                    continue
                plan["temp_file_ref"] = temp_path

            full_path = os.path.join(self.out_dir, relative_path)
            if os.path.isfile(full_path):
                existing_sha256 = self._hash_existing_file(full_path)
                if existing_sha256 != content_sha256:
                    self.conflicts.append({
                        "type": "artifact_conflict",
                        "relative_path": relative_path,
                        "existing_sha256": existing_sha256,
                        "new_sha256": content_sha256,
                    })
                    continue

            planned_artifacts[relative_path] = plan

        return planned_artifacts

    def _commit_artifact_plan(self, plan: Dict[str, Any]) -> None:
        """Write a validated artifact plan to disk."""
        relative_path = plan["relative_path"]
        content_sha256 = plan["content_sha256"]
        full_path = os.path.join(self.out_dir, relative_path)

        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        if "content_bytes" in plan:
            with open(full_path, "wb") as file_handle:
                file_handle.write(plan["content_bytes"])
        elif "temp_file_ref" in plan:
            os.rename(plan["temp_file_ref"], full_path)

        self.merged_artifacts[relative_path] = content_sha256

    def _hash_existing_file(self, file_path: str) -> str:
        """Calculate SHA256 hash for existing file content."""
        with open(file_path, "rb") as file_handle:
            return hashlib.sha256(file_handle.read()).hexdigest()


class AnalysisWorkerResult:
    """Dataclass for analysis worker results."""

    def __init__(
        self,
        analysis_name: str,
        status: str,
        display_html: bool,
        html_fragment: str = "",
        conclusions: Optional[List[Any]] = None,
        table_specs: Optional[List[Dict[str, Any]]] = None,
        merge_intents: Optional[List[Dict[str, Any]]] = None,
        diagnostics: Optional[List[str]] = None,
        duration_ms: Optional[int] = None,
        worker_pid: Optional[int] = None,
        retry_count: Optional[int] = None,
    ):
        self.analysis_name = analysis_name
        self.status = status
        self.display_html = display_html
        self.html_fragment = html_fragment
        self.conclusions = conclusions or []
        self.table_specs = table_specs or []
        self.merge_intents = merge_intents or []
        self.diagnostics = diagnostics or []
        self.duration_ms = duration_ms
        self.worker_pid = worker_pid
        self.retry_count = retry_count

    def to_envelope(self) -> Dict[str, Any]:
        """Convert to analysis result envelope."""
        envelope = {
            "schema_version": 1,
            "analysis_name": self.analysis_name,
            "status": self.status,
            "display_html": self.display_html,
            "html_fragment": self.html_fragment,
            "conclusions": self.conclusions,
            "table_specs": self.table_specs,
            "merge_intents": self.merge_intents,
            "diagnostics": self.diagnostics,
        }

        # Add optional fields if present
        if self.duration_ms is not None:
            envelope["duration_ms"] = self.duration_ms
        if self.worker_pid is not None:
            envelope["worker_pid"] = self.worker_pid
        if self.retry_count is not None:
            envelope["retry_count"] = self.retry_count

        return envelope
