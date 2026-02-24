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

import json
import os
import logging
from typing import Any, Dict, List, Optional, Tuple

from fuzz_introspector import constants, json_report, utils
from fuzz_introspector.merge_intents import (
    MergeIntentValidationError, 
    validate_merge_intent,
    validate_path_safety
)

logger = logging.getLogger(name=__name__)


class MergeCoordinator:
    """Coordinates merging of analysis results from parallel workers."""
    
    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        self.merged_content = {}
        self.merged_artifacts = {}
        self.analysis_results = {}
        self.conflicts = []
        self.errors = []
        
    def add_analysis_result(self, analysis_name: str, result: Dict[str, Any]) -> None:
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
    
    def _validate_envelope(self, analysis_name: str, envelope: Dict[str, Any]) -> None:
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
            "diagnostics"
        ]
        
        for field in required_fields:
            if field not in envelope:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate schema version
        if envelope["schema_version"] != 1:
            raise ValueError(f"Unsupported schema version: {envelope[\"schema_version\"]}")
        
        # Validate analysis name matches
        if envelope["analysis_name"] != analysis_name:
            raise ValueError(
                f"Envelope analysis_name {envelope[\"analysis_name\"]} "
                f"does not match expected {analysis_name}")
        
        # Validate status
        valid_statuses = ["success", "retryable_error", "fatal_error"]
        if envelope["status"] not in valid_statuses:
            raise ValueError(f"Invalid status: {envelope[\"status\"]}")
        
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
        
        return True, self.merged_content
    
    def _get_canonical_order(self) -> List[str]:
        """Get canonical analysis order from registry."""
        from fuzz_introspector.analyses import all_analyses
        
        # Filter analyses that actually ran
        analyses_in_results = set(self.analysis_results.keys())
        
        canonical_order = []
        for analysis_cls in all_analyses:
            analysis_name = analysis_cls.get_name()
            if analysis_name in analyses_in_results:
                canonical_order.append(analysis_name)
        
        return canonical_order
    
    def _merge_single_result(self, analysis_name: str, result: Dict[str, Any]) -> None:
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
                "analysis_name": analysis_name,
                "html": result["html_fragment"]
            })
    
    def _merge_json_upsert(self, intent: Dict[str, Any]) -> None:
        """Merge a JSON upsert intent."""
        target_path = intent["target_path"]
        value = intent["value"]
        
        # Navigate to target location
        current = self.merged_content
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
                            "new_value": value
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
        for intent in self._get_all_artifact_intents():
            self._write_artifact(intent)
    
    def _get_all_artifact_intents(self) -> List[Dict[str, Any]]:
        """Get all artifact intents from all analysis results."""
        artifact_intents = []
        for result in self.analysis_results.values():
            for intent in result.get("merge_intents", []):
                if intent["type"] == "artifact_write":
                    artifact_intents.append(intent)
        return artifact_intents
    
    def _write_artifact(self, intent: Dict[str, Any]) -> None:
        """Write a single artifact to disk."""
        relative_path = intent["relative_path"]
        content_sha256 = intent["content_sha256"]
        
        # Check for conflicts
        if relative_path in self.merged_artifacts:
            existing_sha256 = self.merged_artifacts[relative_path]
            if existing_sha256 != content_sha256:
                self.conflicts.append({
                    "type": "artifact_conflict",
                    "relative_path": relative_path,
                    "existing_sha256": existing_sha256,
                    "new_sha256": content_sha256
                })
                return
        
        # Write the artifact
        full_path = os.path.join(self.out_dir, relative_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        
        if "content_b64" in intent:
            # Decode from hex (base64 was stored as hex for safety)
            content = bytes.fromhex(intent["content_b64"])
            with open(full_path, "wb") as f:
                f.write(content)
        elif "temp_file_ref" in intent:
            # Promote temp file
            temp_path = intent["temp_file_ref"]
            if not os.path.isfile(temp_path):
                raise FileNotFoundError(f"Temp file not found: {temp_path}")
            
            # Verify content matches
            with open(temp_path, "rb") as f:
                content = f.read()
            calculated_sha256 = hashlib.sha256(content).hexdigest()
            if calculated_sha256 != content_sha256:
                raise ValueError(
                    f"Content mismatch for {relative_path}: 
                    expected {content_sha256}, got {calculated_sha256}")
            
            # Move the file
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            os.rename(temp_path, full_path)
        
        # Record the artifact
        self.merged_artifacts[relative_path] = content_sha256


class AnalysisWorkerResult:
    """Dataclass for analysis worker results."""
    
    def __init__(
        self,
        analysis_name: str,
        status: str,
        display_html: bool,
        html_fragment: str = "",
        conclusions: List[Dict[str, Any]] = None,
        table_specs: List[Dict[str, Any]] = None,
        merge_intents: List[Dict[str, Any]] = None,
        diagnostics: List[str] = None,
        duration_ms: Optional[int] = None,
        worker_pid: Optional[int] = None,
        retry_count: Optional[int] = None
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
            "diagnostics": self.diagnostics
        }
        
        # Add optional fields if present
        if self.duration_ms is not None:
            envelope["duration_ms"] = self.duration_ms
        if self.worker_pid is not None:
            envelope["worker_pid"] = self.worker_pid
        if self.retry_count is not None:
            envelope["retry_count"] = self.retry_count
        
        return envelope