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
"""Merge intent types and path safety utilities for analysis parallelization."""

import contextlib
import contextvars
import hashlib
import os
import re
from typing import Any, Dict, List, Optional, Union


class MergeIntentValidationError(Exception):
    """Raised when a merge intent fails validation."""

    pass


class PathSafetyError(Exception):
    """Raised when a path safety check fails."""

    pass


class MergeIntentCollector:
    """Collects merge intents produced during analysis execution."""

    def __init__(self) -> None:
        self._intents: List[Dict[str, Any]] = []

    def add_intent(self, intent: Dict[str, Any]) -> None:
        """Validate and store a merge intent."""
        validate_merge_intent(intent)
        self._intents.append(intent)

    def get_intents(self) -> List[Dict[str, Any]]:
        """Return collected intents."""
        return list(self._intents)


class TableIdOffsetList(list):
    """List that offsets len() for deterministic table IDs."""

    def __init__(self, base_offset: int) -> None:
        super().__init__()
        self._base_offset = base_offset

    def __len__(self) -> int:
        return self._base_offset + super().__len__()


_MERGE_INTENT_COLLECTOR: contextvars.ContextVar[
    Optional[MergeIntentCollector]] = (contextvars.ContextVar(
        "merge_intent_collector", default=None))


def get_active_merge_intent_collector() -> Optional[MergeIntentCollector]:
    """Return the active merge intent collector, if set."""
    return _MERGE_INTENT_COLLECTOR.get()


@contextlib.contextmanager
def merge_intent_context(collector: MergeIntentCollector):
    """Context manager that activates a merge intent collector."""
    token = _MERGE_INTENT_COLLECTOR.set(collector)
    try:
        yield collector
    finally:
        _MERGE_INTENT_COLLECTOR.reset(token)


def validate_merge_intent(intent: Dict[str, Any]) -> None:
    """Validate a merge intent dictionary."""
    if not isinstance(intent, dict):
        raise MergeIntentValidationError("Merge intent must be a dictionary")

    if "type" not in intent:
        raise MergeIntentValidationError(
            "Merge intent must have a 'type' field")

    intent_type = intent["type"]

    if intent_type == "json_upsert":
        _validate_json_upsert(intent)
    elif intent_type == "artifact_write":
        _validate_artifact_write(intent)
    else:
        raise MergeIntentValidationError(
            f"Unknown merge intent type: {intent_type}")


def _validate_json_upsert(intent: Dict[str, Any]) -> None:
    """Validate a json_upsert merge intent."""
    required_fields = ["type", "target_path", "value"]
    for field in required_fields:
        if field not in intent:
            raise MergeIntentValidationError(
                f"json_upsert intent missing required field: {field}")

    if intent["type"] != "json_upsert":
        raise MergeIntentValidationError("Intent type must be 'json_upsert'")

    if not isinstance(intent["target_path"], str):
        raise MergeIntentValidationError(
            "json_upsert target_path must be a string")

    if not isinstance(intent["value"],
                      (dict, list, str, int, float, bool, type(None))):
        raise MergeIntentValidationError(
            "json_upsert value must be JSON-serializable")

    # Validate target_path format
    valid_prefixes = ["analyses", "project", "fuzzers"]
    if not any(intent["target_path"].startswith(prefix + ".")
               for prefix in valid_prefixes):
        raise MergeIntentValidationError(
            f"json_upsert target_path must start with one of: {valid_prefixes}"
        )


def _validate_artifact_write(intent: Dict[str, Any]) -> None:
    """Validate an artifact_write merge intent."""
    required_fields = ["type", "relative_path", "content_sha256"]
    for field in required_fields:
        if field not in intent:
            raise MergeIntentValidationError(
                f"artifact_write intent missing required field: {field}")

    if intent["type"] != "artifact_write":
        raise MergeIntentValidationError(
            "Intent type must be 'artifact_write'")

    if not isinstance(intent["relative_path"], str):
        raise MergeIntentValidationError(
            "artifact_write relative_path must be a string")

    if not isinstance(intent["content_sha256"], str):
        raise MergeIntentValidationError(
            "artifact_write content_sha256 must be a string")

    # Validate SHA256 format
    if len(intent["content_sha256"]) != 64 or not all(
            c in "0123456789abcdef" for c in intent["content_sha256"]):
        raise MergeIntentValidationError(
            "artifact_write content_sha256 must be a 64-character hex string")

    # Validate content source
    if "content_b64" in intent and "temp_file_ref" in intent:
        raise MergeIntentValidationError(
            "artifact_write must have exactly one of content_b64 or temp_file_ref"
        )

    if "content_b64" in intent:
        if not isinstance(intent["content_b64"], str):
            raise MergeIntentValidationError(
                "artifact_write content_b64 must be a string")
    elif "temp_file_ref" in intent:
        if not isinstance(intent["temp_file_ref"], str):
            raise MergeIntentValidationError(
                "artifact_write temp_file_ref must be a string")
    else:
        raise MergeIntentValidationError(
            "artifact_write must have exactly one of content_b64 or temp_file_ref"
        )


def validate_path_safety(relative_path: str,
                         base_dir: str,
                         resolve_symlinks: bool = True) -> None:
    """Validate that a relative path is safe to write within a base directory."""
    # Check for path traversal attempts
    if ".." in relative_path:
        raise PathSafetyError(f"Path traversal detected in: {relative_path}")

    # Check for absolute paths
    if os.path.isabs(relative_path):
        raise PathSafetyError(f"Absolute path not allowed: {relative_path}")

    # Check for path escapes (including symlink traversal)
    base_norm = os.path.normpath(base_dir)
    full_path = os.path.normpath(os.path.join(base_dir, relative_path))
    if not full_path.startswith(base_norm + os.sep):
        raise PathSafetyError(
            f"Path escapes base directory: {relative_path} -> {full_path}")

    if resolve_symlinks:
        base_real = os.path.realpath(base_dir)
        full_real = os.path.realpath(full_path)
        if not full_real.startswith(base_real + os.sep):
            raise PathSafetyError("Path escapes base directory via symlink: "
                                  f"{relative_path} -> {full_real}")

    # Check for null bytes
    if "\0" in relative_path:
        raise PathSafetyError(f"Null byte detected in path: {relative_path}")

    # Check for suspicious characters
    if re.search(r"[<>:\"\\|?*]", relative_path):
        raise PathSafetyError(f"Invalid characters in path: {relative_path}")


def calculate_sha256(content: Union[str, bytes]) -> str:
    """Calculate SHA256 hash of content."""
    sha256 = hashlib.sha256()
    if isinstance(content, str):
        content = content.encode("utf-8")
    sha256.update(content)
    return sha256.hexdigest()


def create_json_upsert_intent(target_path: str, value: Any) -> Dict[str, Any]:
    """Create a validated json_upsert merge intent."""
    intent = {
        "type": "json_upsert",
        "target_path": target_path,
        "value": value
    }
    validate_merge_intent(intent)
    return intent


def create_artifact_write_intent(relative_path: str, content: Union[str,
                                                                    bytes],
                                 base_dir: str) -> Dict[str, Any]:
    """Create a validated artifact_write merge intent with content_b64."""
    content_sha256 = calculate_sha256(content)

    # Validate path safety
    validate_path_safety(relative_path, base_dir, resolve_symlinks=False)

    intent = {
        "type":
        "artifact_write",
        "relative_path":
        relative_path,
        "content_sha256":
        content_sha256,
        "content_b64":
        content.encode("utf-8").hex()
        if isinstance(content, str) else content.hex(),
    }

    validate_merge_intent(intent)
    return intent


def create_artifact_write_intent_from_file(relative_path: str,
                                           temp_file_path: str,
                                           base_dir: str) -> Dict[str, Any]:
    """Create a validated artifact_write merge intent with temp_file_ref."""
    # Validate file exists
    if not os.path.isfile(temp_file_path):
        raise MergeIntentValidationError(
            f"Temp file does not exist: {temp_file_path}")

    # Calculate SHA256
    with open(temp_file_path, "rb") as f:
        content = f.read()
    content_sha256 = calculate_sha256(content)

    # Validate path safety
    validate_path_safety(relative_path, base_dir, resolve_symlinks=False)

    intent = {
        "type": "artifact_write",
        "relative_path": relative_path,
        "content_sha256": content_sha256,
        "temp_file_ref": temp_file_path,
    }

    validate_merge_intent(intent)
    return intent
