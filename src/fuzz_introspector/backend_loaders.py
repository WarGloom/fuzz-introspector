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
"""Shared helpers for external backend loader selection and invocation."""

import json
import logging
import os
import shlex
import subprocess

from typing import Any, Iterable

logger = logging.getLogger(__name__)

BACKEND_PYTHON = "python"
BACKEND_GO = "go"
BACKEND_RUST = "rust"
BACKEND_CPP = "cpp"
SUPPORTED_BACKENDS = (BACKEND_PYTHON, BACKEND_GO, BACKEND_RUST, BACKEND_CPP)


def parse_backend_env(env_name: str,
                      default: str = BACKEND_PYTHON,
                      supported: Iterable[str] = SUPPORTED_BACKENDS) -> str:
    """Parse backend selector env var with validation."""
    supported_set = {candidate.lower() for candidate in supported}
    raw = os.environ.get(env_name, "").strip().lower()
    if not raw:
        return default
    if raw in supported_set:
        return raw
    logger.warning("Invalid %s=%r; defaulting to %s", env_name, raw, default)
    return default


def resolve_backend_command(command_env_prefix: str,
                            backend: str) -> list[str] | None:
    """Resolve backend command from env vars.

    Lookup order:
    1) <PREFIX>_<BACKEND>_BIN
    2) <PREFIX>_BIN
    """
    candidates = [
        f"{command_env_prefix}_{backend.upper()}_BIN",
        f"{command_env_prefix}_BIN",
    ]
    for env_name in candidates:
        raw_cmd = os.environ.get(env_name, "").strip()
        if not raw_cmd:
            continue
        try:
            cmd_parts = shlex.split(raw_cmd)
        except ValueError as err:
            logger.warning("Invalid command in %s=%r: %s", env_name, raw_cmd,
                           err)
            return None
        if cmd_parts:
            return cmd_parts
    return None


def run_external_json_loader(command: list[str],
                             payload: dict[str, Any],
                             timeout_seconds: int = 0) -> Any | None:
    """Run an external loader process using JSON stdin/stdout protocol."""
    timeout = timeout_seconds if timeout_seconds > 0 else None
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as err:
        logger.warning("External loader execution failed for %s: %s", command,
                       err)
        return None

    if completed.returncode != 0:
        logger.warning("External loader failed for %s (rc=%d): %s", command,
                       completed.returncode,
                       (completed.stderr or "").strip()[:500])
        return None

    stdout = (completed.stdout or "").strip()
    if not stdout:
        logger.warning("External loader returned empty payload for %s", command)
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as err:
        logger.warning("External loader returned invalid JSON for %s: %s",
                       command, err)
        return None


def load_json_with_backend(
    backend_env: str,
    command_env_prefix: str,
    payload: dict[str, Any],
    default_backend: str = BACKEND_PYTHON,
    timeout_env: str = "",
) -> tuple[str, Any | None]:
    """Resolve backend and optionally invoke external JSON loader.

    Returns `(selected_backend, result)` where:
    - selected_backend is the backend requested/effective backend.
    - result is external JSON payload or `None` if backend is python or failed.
    """
    selected_backend = parse_backend_env(backend_env, default_backend)
    if selected_backend == BACKEND_PYTHON:
        return selected_backend, None

    command = resolve_backend_command(command_env_prefix, selected_backend)
    if not command:
        logger.warning(
            "No command configured for backend %s in %s; falling back to python",
            selected_backend,
            command_env_prefix,
        )
        return BACKEND_PYTHON, None

    timeout_seconds = 0
    if timeout_env:
        raw_timeout = os.environ.get(timeout_env, "")
        if raw_timeout:
            try:
                timeout_seconds = int(raw_timeout)
            except ValueError:
                logger.warning("Invalid %s=%r; ignoring timeout", timeout_env,
                               raw_timeout)

    result = run_external_json_loader(command, payload, timeout_seconds)
    if result is None:
        return BACKEND_PYTHON, None
    return selected_backend, result
