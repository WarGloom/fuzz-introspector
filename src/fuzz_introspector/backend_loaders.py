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

from dataclasses import dataclass
import json
import logging
import os
import shlex
import signal
import subprocess
import threading
import time

from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)

BACKEND_PYTHON = "python"
BACKEND_NATIVE = "native"
BACKEND_GO = "go"
BACKEND_RUST = "rust"
BACKEND_CPP = "cpp"
SUPPORTED_BACKENDS = (BACKEND_PYTHON, BACKEND_GO, BACKEND_RUST, BACKEND_CPP)

CORRELATOR_SCHEMA_VERSION = 1
CORRELATOR_REQUIRED_RESPONSE_KEYS = (
    "schema_version",
    "status",
    "counters",
    "artifacts",
    "timings",
)
CORRELATOR_TIMEOUT_GRACE_SECONDS = 10
CORRELATOR_MAX_STDOUT_BYTES = 1024 * 1024
CORRELATOR_MAX_STDERR_BYTES = 16 * 1024

FI_CORR_BACKEND_UNSUPPORTED = "FI_CORR_BACKEND_UNSUPPORTED"
FI_CORR_COMMAND_MISSING = "FI_CORR_COMMAND_MISSING"
FI_CORR_EXECUTION_FAILED = "FI_CORR_EXECUTION_FAILED"
FI_CORR_TIMEOUT = "FI_CORR_TIMEOUT"
FI_CORR_NATIVE_EXIT_NONZERO = "FI_CORR_NATIVE_EXIT_NONZERO"
FI_CORR_EMPTY_STDOUT = "FI_CORR_EMPTY_STDOUT"
FI_CORR_STDOUT_TOO_LARGE = "FI_CORR_STDOUT_TOO_LARGE"
FI_CORR_INVALID_JSON = "FI_CORR_INVALID_JSON"
FI_CORR_SCHEMA_ERROR = "FI_CORR_SCHEMA_ERROR"
FI_CORR_SCHEMA_VERSION_MISMATCH = "FI_CORR_SCHEMA_VERSION_MISMATCH"
FI_CORR_NATIVE_STATUS = "FI_CORR_NATIVE_STATUS"
FI_CORR_PARITY_MISMATCH = "FI_CORR_PARITY_MISMATCH"
# Aliases retained for rollout docs/compatibility.
FI_CORR_SCHEMA_INVALID = FI_CORR_SCHEMA_ERROR
FI_CORR_EXIT_NONZERO = FI_CORR_NATIVE_EXIT_NONZERO

OVERLAY_SCHEMA_VERSION = 1
OVERLAY_REQUIRED_RESPONSE_KEYS = (
    "schema_version",
    "status",
    "counters",
    "artifacts",
    "timings",
)
OVERLAY_REQUIRED_ARTIFACT_KEYS = (
    "overlay_nodes",
    "branch_complexities",
    "branch_blockers",
)
OVERLAY_MAX_STDOUT_BYTES = 1024 * 1024
OVERLAY_MAX_STDERR_BYTES = 16 * 1024

FI_OVERLAY_BACKEND_UNSUPPORTED = "FI_OVERLAY_BACKEND_UNSUPPORTED"
FI_OVERLAY_COMMAND_MISSING = "FI_OVERLAY_COMMAND_MISSING"
FI_OVERLAY_EXECUTION_FAILED = "FI_OVERLAY_EXECUTION_FAILED"
FI_OVERLAY_TIMEOUT = "FI_OVERLAY_TIMEOUT"
FI_OVERLAY_NATIVE_EXIT_NONZERO = "FI_OVERLAY_NATIVE_EXIT_NONZERO"
FI_OVERLAY_EMPTY_STDOUT = "FI_OVERLAY_EMPTY_STDOUT"
FI_OVERLAY_STDOUT_TOO_LARGE = "FI_OVERLAY_STDOUT_TOO_LARGE"
FI_OVERLAY_STDERR_TOO_LARGE = "FI_OVERLAY_STDERR_TOO_LARGE"
FI_OVERLAY_INVALID_JSON = "FI_OVERLAY_INVALID_JSON"
FI_OVERLAY_SCHEMA_ERROR = "FI_OVERLAY_SCHEMA_ERROR"
FI_OVERLAY_SCHEMA_VERSION_MISMATCH = "FI_OVERLAY_SCHEMA_VERSION_MISMATCH"
FI_OVERLAY_NATIVE_STATUS = "FI_OVERLAY_NATIVE_STATUS"
FI_OVERLAY_PARITY_MISMATCH = "FI_OVERLAY_PARITY_MISMATCH"


class CorrelatorBackendError(RuntimeError):
    """Error raised when strict correlator backend mode is enabled."""

    def __init__(
        self, reason_code: str, message: str, details: dict[str, Any] | None = None
    ):
        self.reason_code = reason_code
        self.details = details or {}
        super().__init__(f"{reason_code}: {message}")


@dataclass
class CorrelatorBackendResult:
    selected_backend: str
    strict_mode: bool
    response: dict[str, Any] | None = None
    reason_code: str | None = None
    reason_details: dict[str, Any] | None = None


@dataclass
class OverlayBackendResult:
    selected_backend: str
    strict_mode: bool
    response: dict[str, Any] | None = None
    reason_code: str | None = None
    reason_details: dict[str, Any] | None = None


def parse_backend_env(
    env_name: str,
    default: str = BACKEND_PYTHON,
    supported: Iterable[str] = SUPPORTED_BACKENDS,
) -> str:
    """Parse backend selector env var with validation."""
    supported_set = {candidate.lower() for candidate in supported}
    raw = os.environ.get(env_name, "").strip().lower()
    if not raw:
        return default
    if raw in supported_set:
        return raw
    logger.warning("Invalid %s=%r; defaulting to %s", env_name, raw, default)
    return default


def resolve_backend_command(command_env_prefix: str, backend: str) -> list[str] | None:
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
            logger.warning("Invalid command in %s=%r: %s", env_name, raw_cmd, err)
            return None
        if cmd_parts:
            return cmd_parts
    return None


def run_external_json_loader(
    command: list[str], payload: dict[str, Any], timeout_seconds: int = 0
) -> Any | None:
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
        logger.warning("External loader execution failed for %s: %s", command, err)
        return None

    if completed.returncode != 0:
        logger.warning(
            "External loader failed for %s (rc=%d): %s",
            command,
            completed.returncode,
            (completed.stderr or "").strip()[:500],
        )
        return None

    stdout = (completed.stdout or "").strip()
    if not stdout:
        logger.warning("External loader returned empty payload for %s", command)
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as err:
        logger.warning("External loader returned invalid JSON for %s: %s", command, err)
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
                logger.warning(
                    "Invalid %s=%r; ignoring timeout", timeout_env, raw_timeout
                )

    result = run_external_json_loader(command, payload, timeout_seconds)
    if result is None:
        return BACKEND_PYTHON, None
    return selected_backend, result


def parse_correlator_backend_env(
    env_name: str = "FI_DEBUG_CORRELATOR_BACKEND",
) -> str:
    """Resolve correlator backend selector."""
    raw = os.environ.get(env_name, "").strip().lower()
    if not raw:
        return BACKEND_PYTHON
    if raw in (BACKEND_PYTHON, BACKEND_RUST, BACKEND_GO):
        return raw

    logger.warning(
        "%s: Unsupported %s=%r; falling back to python",
        FI_CORR_BACKEND_UNSUPPORTED,
        env_name,
        raw,
    )
    return BACKEND_PYTHON


def parse_overlay_backend_env(
    env_name: str = "FI_OVERLAY_BACKEND",
) -> str:
    """Resolve overlay backend selector."""
    raw = os.environ.get(env_name, "").strip().lower()
    if not raw:
        return BACKEND_PYTHON
    if raw in (BACKEND_RUST, BACKEND_GO):
        logger.warning(
            "%s=%r is a compatibility alias; using native backend",
            env_name,
            raw,
        )
        return raw
    if raw in (BACKEND_PYTHON, BACKEND_NATIVE):
        return raw

    logger.warning(
        "%s: Unsupported %s=%r; falling back to python",
        FI_OVERLAY_BACKEND_UNSUPPORTED,
        env_name,
        raw,
    )
    return BACKEND_PYTHON


def parse_overlay_strict_mode(
    env_name: str = "FI_OVERLAY_STRICT",
) -> bool:
    """Return strict mode state for overlay backend selection."""
    raw = os.environ.get(env_name, "").strip().lower()
    return raw == "1"


def parse_overlay_shadow_mode(
    env_name: str = "FI_OVERLAY_SHADOW",
) -> bool:
    """Return shadow mode state for overlay backend selection."""
    raw = os.environ.get(env_name, "").strip().lower()
    return raw == "1"


def parse_correlator_strict_mode(
    env_name: str = "FI_DEBUG_CORRELATOR_STRICT",
) -> bool:
    """Return strict mode state for correlator backend selection."""
    raw = os.environ.get(env_name, "").strip().lower()
    return raw == "1"


def _format_reason_details(details: dict[str, Any] | None) -> str:
    if not details:
        return ""
    return json.dumps(details, sort_keys=True, default=str)


def _terminate_process_group(proc: subprocess.Popen[str], grace_seconds: int) -> str:
    if proc.poll() is not None:
        return "already_exited"

    sent_term = False
    process_group_supported = hasattr(os, "killpg")
    pgid: int | None = None

    if process_group_supported:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            sent_term = True
        except ProcessLookupError:
            return "already_exited"
        except OSError:
            sent_term = False

    if not sent_term:
        try:
            proc.terminate()
            sent_term = True
        except OSError:
            return "terminate_failed"

    try:
        proc.wait(timeout=grace_seconds)
        return "terminated"
    except subprocess.TimeoutExpired:
        pass

    try:
        if process_group_supported and pgid is not None:
            os.killpg(pgid, signal.SIGKILL)
        else:
            proc.kill()
        proc.wait(timeout=grace_seconds)
        return "killed"
    except (OSError, subprocess.TimeoutExpired):
        return "kill_failed"


def _parse_timeout_seconds(timeout_env: str) -> int:
    raw_timeout = os.environ.get(timeout_env, "").strip()
    if not raw_timeout:
        return 0
    try:
        timeout_value = int(raw_timeout)
    except ValueError:
        logger.warning("Invalid %s=%r; ignoring timeout", timeout_env, raw_timeout)
        return 0
    if timeout_value <= 0:
        logger.warning(
            "Invalid %s=%r; timeout must be positive", timeout_env, raw_timeout
        )
        return 0
    return timeout_value


def _handle_correlator_failure(
    reason_code: str,
    message: str,
    strict_mode: bool,
    cleanup_hook: Callable[[dict[str, Any] | None, str], str] | None,
    response: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> CorrelatorBackendResult:
    merged_details = dict(details or {})
    if cleanup_hook is not None:
        try:
            cleanup_status = cleanup_hook(response, reason_code)
        except Exception as err:  # pragma: no cover - defensive
            cleanup_status = f"hook_error:{err}"
        merged_details["artifact_cleanup_status"] = cleanup_status

    detail_text = _format_reason_details(merged_details)
    if detail_text:
        logger.warning("%s: %s | details=%s", reason_code, message, detail_text)
    else:
        logger.warning("%s: %s", reason_code, message)

    if strict_mode:
        raise CorrelatorBackendError(reason_code, message, merged_details)

    return CorrelatorBackendResult(
        selected_backend=BACKEND_PYTHON,
        strict_mode=strict_mode,
        reason_code=reason_code,
        reason_details=merged_details,
    )


def _validate_correlator_response(
    response: Any,
) -> tuple[str, str, dict[str, Any]] | None:
    if not isinstance(response, dict):
        return (
            FI_CORR_SCHEMA_ERROR,
            "Correlator response must be a JSON object",
            {"response_type": type(response).__name__},
        )

    missing_keys = [
        key for key in CORRELATOR_REQUIRED_RESPONSE_KEYS if key not in response
    ]
    if missing_keys:
        return (
            FI_CORR_SCHEMA_ERROR,
            "Correlator response missing required metadata keys",
            {"missing_keys": missing_keys},
        )

    schema_version = response.get("schema_version")
    if not isinstance(schema_version, int):
        return (
            FI_CORR_SCHEMA_ERROR,
            "Correlator response schema_version must be an int",
            {"schema_version_type": type(schema_version).__name__},
        )
    if schema_version != CORRELATOR_SCHEMA_VERSION:
        return (
            FI_CORR_SCHEMA_VERSION_MISMATCH,
            "Correlator response schema_version is unsupported",
            {"expected": CORRELATOR_SCHEMA_VERSION, "actual": schema_version},
        )

    if not isinstance(response.get("status"), str):
        return (FI_CORR_SCHEMA_ERROR, "Correlator response status must be a string", {})
    if not isinstance(response.get("counters"), dict):
        return (
            FI_CORR_SCHEMA_ERROR,
            "Correlator response counters must be an object",
            {},
        )
    if not isinstance(response.get("artifacts"), dict):
        return (
            FI_CORR_SCHEMA_ERROR,
            "Correlator response artifacts must be an object",
            {},
        )
    if not isinstance(response.get("timings"), dict):
        return (
            FI_CORR_SCHEMA_ERROR,
            "Correlator response timings must be an object",
            {},
        )
    return None


def _handle_overlay_failure(
    reason_code: str,
    message: str,
    strict_mode: bool,
    details: dict[str, Any] | None = None,
) -> OverlayBackendResult:
    detail_text = _format_reason_details(details)
    if detail_text:
        logger.warning("%s: %s | details=%s", reason_code, message, detail_text)
    else:
        logger.warning("%s: %s", reason_code, message)

    if strict_mode:
        raise CorrelatorBackendError(reason_code, message, details)

    return OverlayBackendResult(
        selected_backend=BACKEND_PYTHON,
        strict_mode=strict_mode,
        reason_code=reason_code,
        reason_details=details,
    )


def _validate_overlay_response(
    response: Any,
) -> tuple[str, str, dict[str, Any]] | None:
    if not isinstance(response, dict):
        return (
            FI_OVERLAY_SCHEMA_ERROR,
            "Overlay response must be a JSON object",
            {"response_type": type(response).__name__},
        )

    missing_keys = [
        key for key in OVERLAY_REQUIRED_RESPONSE_KEYS if key not in response
    ]
    if missing_keys:
        return (
            FI_OVERLAY_SCHEMA_ERROR,
            "Overlay response missing required metadata keys",
            {"missing_keys": missing_keys},
        )

    schema_version = response.get("schema_version")
    if not isinstance(schema_version, int):
        return (
            FI_OVERLAY_SCHEMA_ERROR,
            "Overlay response schema_version must be an int",
            {"schema_version_type": type(schema_version).__name__},
        )
    if schema_version != OVERLAY_SCHEMA_VERSION:
        return (
            FI_OVERLAY_SCHEMA_VERSION_MISMATCH,
            "Overlay response schema_version is unsupported",
            {"expected": OVERLAY_SCHEMA_VERSION, "actual": schema_version},
        )

    status = response.get("status")
    if not isinstance(status, str):
        return (FI_OVERLAY_SCHEMA_ERROR, "Overlay response status must be a string", {})

    if not isinstance(response.get("counters"), dict):
        return (
            FI_OVERLAY_SCHEMA_ERROR,
            "Overlay response counters must be an object",
            {},
        )
    artifacts = response.get("artifacts")
    if not isinstance(artifacts, dict):
        return (
            FI_OVERLAY_SCHEMA_ERROR,
            "Overlay response artifacts must be an object",
            {},
        )
    if not isinstance(response.get("timings"), dict):
        return (
            FI_OVERLAY_SCHEMA_ERROR,
            "Overlay response timings must be an object",
            {},
        )

    invalid_artifact_keys = []
    for key in OVERLAY_REQUIRED_ARTIFACT_KEYS:
        artifact_path = artifacts.get(key)
        if not isinstance(artifact_path, str) or not artifact_path.strip():
            invalid_artifact_keys.append(key)
    if invalid_artifact_keys:
        return (
            FI_OVERLAY_SCHEMA_ERROR,
            "Overlay response artifacts must include non-empty file paths",
            {"invalid_artifact_keys": invalid_artifact_keys},
        )

    return None


class _BoundedStreamReader(threading.Thread):
    def __init__(
        self,
        stream: Any,
        max_bytes: int | None = None,
        name: str = "",
        stop_on_overflow: bool = True,
    ):
        super().__init__(daemon=True, name=name)
        self._stream = stream
        self._max_bytes = max_bytes
        self._stop_on_overflow = stop_on_overflow
        self._chunks: list[bytes] = []
        self.total_bytes = 0
        self.overflowed = False
        self.error: BaseException | None = None

    @property
    def content(self) -> bytes:
        return b"".join(self._chunks)

    def run(self) -> None:
        try:
            while True:
                chunk = self._stream.read(65536)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    data = chunk.encode("utf-8")
                else:
                    data = chunk
                chunk_size = len(data)
                self.total_bytes += chunk_size
                if self._max_bytes is not None and self.total_bytes > self._max_bytes:
                    allowed = self._max_bytes - (self.total_bytes - chunk_size)
                    if allowed > 0:
                        self._chunks.append(data[:allowed])
                    self.overflowed = True
                    if self._stop_on_overflow:
                        return
                    continue
                self._chunks.append(data)
        except BaseException as err:  # pragma: no cover - defensive
            self.error = err


def run_overlay_backend(
    payload: dict[str, Any],
    command_env_prefix: str = "FI_OVERLAY",
    timeout_env: str = "FI_OVERLAY_TIMEOUT_SEC",
    selected_backend: str | None = None,
    strict_mode: bool | None = None,
) -> OverlayBackendResult:
    """Run the native overlay backend with strict/non-strict handling."""
    if strict_mode is None:
        strict_mode = parse_overlay_strict_mode()
    if selected_backend is None:
        selected_backend = parse_overlay_backend_env()
    if selected_backend == BACKEND_PYTHON:
        return OverlayBackendResult(
            selected_backend=selected_backend,
            strict_mode=strict_mode,
        )

    command = resolve_backend_command(command_env_prefix, selected_backend)
    if not command:
        return _handle_overlay_failure(
            FI_OVERLAY_COMMAND_MISSING,
            "No overlay command configured for selected backend",
            strict_mode,
            details={
                "backend": selected_backend,
                "command_env_prefix": command_env_prefix,
            },
        )

    request_payload = dict(payload)
    request_payload["schema_version"] = OVERLAY_SCHEMA_VERSION
    timeout_seconds = _parse_timeout_seconds(timeout_env)
    start = time.perf_counter()
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as err:
        return _handle_overlay_failure(
            FI_OVERLAY_EXECUTION_FAILED,
            "Failed to start overlay backend process",
            strict_mode,
            details={
                "backend": selected_backend,
                "command": command,
                "error": str(err),
            },
        )

    timeout = timeout_seconds if timeout_seconds > 0 else None
    request_bytes = json.dumps(request_payload).encode("utf-8")
    stdout_reader = _BoundedStreamReader(
        proc.stdout,
        max_bytes=OVERLAY_MAX_STDOUT_BYTES,
        name="fi-overlay-stdout-reader",
    )
    stderr_reader = _BoundedStreamReader(
        proc.stderr,
        max_bytes=OVERLAY_MAX_STDERR_BYTES,
        name="fi-overlay-stderr-reader",
        stop_on_overflow=False,
    )
    stdout_reader.start()
    stderr_reader.start()

    try:
        if proc.stdin is not None:
            proc.stdin.write(request_bytes)
            proc.stdin.flush()
            proc.stdin.close()
    except (BrokenPipeError, OSError, ValueError) as err:
        cleanup_status = _terminate_process_group(
            proc, CORRELATOR_TIMEOUT_GRACE_SECONDS
        )
        return _handle_overlay_failure(
            FI_OVERLAY_EXECUTION_FAILED,
            "Overlay backend stdin write failed",
            strict_mode,
            details={
                "backend": selected_backend,
                "command": command,
                "error": str(err),
                "cleanup_status": cleanup_status,
            },
        )

    try:
        while True:
            elapsed = time.perf_counter() - start
            if timeout is not None and elapsed > timeout:
                elapsed_ms = int(elapsed * 1000)
                cleanup_status = _terminate_process_group(
                    proc, CORRELATOR_TIMEOUT_GRACE_SECONDS
                )
                return _handle_overlay_failure(
                    FI_OVERLAY_TIMEOUT,
                    "Overlay backend timed out",
                    strict_mode,
                    details={
                        "backend": selected_backend,
                        "timeout_seconds": timeout_seconds,
                        "elapsed_ms": elapsed_ms,
                        "cleanup_status": cleanup_status,
                    },
                )

            if stdout_reader.overflowed:
                cleanup_status = _terminate_process_group(
                    proc, CORRELATOR_TIMEOUT_GRACE_SECONDS
                )
                return _handle_overlay_failure(
                    FI_OVERLAY_STDOUT_TOO_LARGE,
                    "Overlay backend stdout exceeded metadata-only limit",
                    strict_mode,
                    details={
                        "backend": selected_backend,
                        "stdout_bytes": stdout_reader.total_bytes,
                        "max_stdout_bytes": OVERLAY_MAX_STDOUT_BYTES,
                        "cleanup_status": cleanup_status,
                    },
                )

            if stderr_reader.overflowed:
                cleanup_status = _terminate_process_group(
                    proc, CORRELATOR_TIMEOUT_GRACE_SECONDS
                )
                return _handle_overlay_failure(
                    FI_OVERLAY_STDERR_TOO_LARGE,
                    "Overlay backend stderr exceeded cap; process terminated",
                    strict_mode,
                    details={
                        "backend": selected_backend,
                        "stderr_bytes": stderr_reader.total_bytes,
                        "max_stderr_bytes": OVERLAY_MAX_STDERR_BYTES,
                        "cleanup_status": cleanup_status,
                    },
                )

            if proc.poll() is not None and (
                not stdout_reader.is_alive() and not stderr_reader.is_alive()
            ):
                break

            time.sleep(0.01)

        stdout_reader.join(timeout=0.1)
        stderr_reader.join(timeout=0.1)
    except (OSError, subprocess.SubprocessError) as err:
        return _handle_overlay_failure(
            FI_OVERLAY_EXECUTION_FAILED,
            "Overlay backend communication failed",
            strict_mode,
            details={
                "backend": selected_backend,
                "command": command,
                "error": str(err),
            },
        )

    if stdout_reader.error is not None:
        return _handle_overlay_failure(
            FI_OVERLAY_EXECUTION_FAILED,
            "Overlay backend stdout read failed",
            strict_mode,
            details={
                "backend": selected_backend,
                "error": str(stdout_reader.error),
            },
        )
    if stderr_reader.error is not None:
        return _handle_overlay_failure(
            FI_OVERLAY_EXECUTION_FAILED,
            "Overlay backend stderr read failed",
            strict_mode,
            details={
                "backend": selected_backend,
                "error": str(stderr_reader.error),
            },
        )

    if proc.returncode != 0:
        stderr = stderr_reader.content.decode("utf-8", errors="replace")
        return _handle_overlay_failure(
            FI_OVERLAY_NATIVE_EXIT_NONZERO,
            "Overlay backend returned non-zero exit status",
            strict_mode,
            details={
                "backend": selected_backend,
                "returncode": proc.returncode,
                "stderr": (stderr or "").strip()[:500],
                "stderr_truncated": stderr_reader.overflowed,
            },
        )

    raw_stdout = stdout_reader.content.decode("utf-8", errors="replace")

    raw_stdout = raw_stdout.strip()
    if not raw_stdout:
        return _handle_overlay_failure(
            FI_OVERLAY_EMPTY_STDOUT,
            "Overlay backend returned empty stdout",
            strict_mode,
            details={"backend": selected_backend},
        )

    try:
        response = json.loads(raw_stdout)
    except json.JSONDecodeError as err:
        return _handle_overlay_failure(
            FI_OVERLAY_INVALID_JSON,
            "Overlay backend returned invalid JSON",
            strict_mode,
            details={
                "backend": selected_backend,
                "error": str(err),
            },
        )

    validation_error = _validate_overlay_response(response)
    if validation_error is not None:
        reason_code, message, details = validation_error
        details["backend"] = selected_backend
        return _handle_overlay_failure(reason_code, message, strict_mode, details)

    response_status = response.get("status")
    if response_status not in ("success", "ok"):
        return _handle_overlay_failure(
            FI_OVERLAY_NATIVE_STATUS,
            "Overlay backend status is not success",
            strict_mode,
            details={
                "backend": selected_backend,
                "status": response_status,
            },
        )

    return OverlayBackendResult(
        selected_backend=selected_backend,
        strict_mode=strict_mode,
        response=response,
    )


def run_correlator_backend(
    payload: dict[str, Any],
    cleanup_hook: Callable[[dict[str, Any] | None, str], str] | None = None,
    parity_hook: Callable[[dict[str, Any]], None] | None = None,
    command_env_prefix: str = "FI_DEBUG_CORRELATOR",
    timeout_env: str = "FI_DEBUG_CORRELATOR_TIMEOUT_SEC",
    selected_backend: str | None = None,
    strict_mode: bool | None = None,
) -> CorrelatorBackendResult:
    """Run the native correlator backend with strict/non-strict handling."""
    if strict_mode is None:
        strict_mode = parse_correlator_strict_mode()
    if selected_backend is None:
        selected_backend = parse_correlator_backend_env()
    if selected_backend == BACKEND_PYTHON:
        return CorrelatorBackendResult(
            selected_backend=selected_backend,
            strict_mode=strict_mode,
        )

    command = resolve_backend_command(command_env_prefix, selected_backend)
    if not command:
        return _handle_correlator_failure(
            FI_CORR_COMMAND_MISSING,
            "No correlator command configured for selected backend",
            strict_mode,
            cleanup_hook,
            details={
                "backend": selected_backend,
                "command_env_prefix": command_env_prefix,
            },
        )

    request_payload = dict(payload)
    request_payload["schema_version"] = CORRELATOR_SCHEMA_VERSION
    timeout_seconds = _parse_timeout_seconds(timeout_env)
    start = time.perf_counter()
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as err:
        return _handle_correlator_failure(
            FI_CORR_EXECUTION_FAILED,
            "Failed to start correlator backend process",
            strict_mode,
            cleanup_hook,
            details={
                "backend": selected_backend,
                "command": command,
                "error": str(err),
            },
        )

    timeout = timeout_seconds if timeout_seconds > 0 else None
    request_bytes = json.dumps(request_payload).encode("utf-8")
    stdout_reader = _BoundedStreamReader(
        proc.stdout,
        max_bytes=CORRELATOR_MAX_STDOUT_BYTES,
        name="fi-correlator-stdout-reader",
    )
    stderr_reader = _BoundedStreamReader(
        proc.stderr,
        max_bytes=CORRELATOR_MAX_STDERR_BYTES,
        name="fi-correlator-stderr-reader",
        stop_on_overflow=False,
    )
    stdout_reader.start()
    stderr_reader.start()

    try:
        if proc.stdin is not None:
            proc.stdin.write(request_bytes)
            proc.stdin.flush()
            proc.stdin.close()
    except (BrokenPipeError, OSError, ValueError) as err:
        cleanup_status = _terminate_process_group(
            proc, CORRELATOR_TIMEOUT_GRACE_SECONDS
        )
        return _handle_correlator_failure(
            FI_CORR_EXECUTION_FAILED,
            "Correlator backend stdin write failed",
            strict_mode,
            cleanup_hook,
            details={
                "backend": selected_backend,
                "command": command,
                "error": str(err),
                "cleanup_status": cleanup_status,
            },
        )

    try:
        while True:
            elapsed = time.perf_counter() - start
            if timeout is not None and elapsed > timeout:
                elapsed_ms = int(elapsed * 1000)
                cleanup_status = _terminate_process_group(
                    proc, CORRELATOR_TIMEOUT_GRACE_SECONDS
                )
                return _handle_correlator_failure(
                    FI_CORR_TIMEOUT,
                    "Correlator backend timed out",
                    strict_mode,
                    cleanup_hook,
                    details={
                        "backend": selected_backend,
                        "timeout_seconds": timeout_seconds,
                        "elapsed_ms": elapsed_ms,
                        "cleanup_status": cleanup_status,
                    },
                )

            if stdout_reader.overflowed:
                cleanup_status = _terminate_process_group(
                    proc, CORRELATOR_TIMEOUT_GRACE_SECONDS
                )
                return _handle_correlator_failure(
                    FI_CORR_STDOUT_TOO_LARGE,
                    "Correlator backend stdout exceeded metadata-only limit",
                    strict_mode,
                    cleanup_hook,
                    details={
                        "backend": selected_backend,
                        "stdout_bytes": stdout_reader.total_bytes,
                        "max_stdout_bytes": CORRELATOR_MAX_STDOUT_BYTES,
                        "cleanup_status": cleanup_status,
                    },
                )

            if proc.poll() is not None and (
                not stdout_reader.is_alive() and not stderr_reader.is_alive()
            ):
                break

            time.sleep(0.01)

        stdout_reader.join(timeout=0.1)
        stderr_reader.join(timeout=0.1)
    except (OSError, subprocess.SubprocessError) as err:
        return _handle_correlator_failure(
            FI_CORR_EXECUTION_FAILED,
            "Correlator backend communication failed",
            strict_mode,
            cleanup_hook,
            details={
                "backend": selected_backend,
                "command": command,
                "error": str(err),
            },
        )

    if stdout_reader.error is not None:
        return _handle_correlator_failure(
            FI_CORR_EXECUTION_FAILED,
            "Correlator backend stdout read failed",
            strict_mode,
            cleanup_hook,
            details={
                "backend": selected_backend,
                "error": str(stdout_reader.error),
            },
        )
    if stderr_reader.error is not None:
        return _handle_correlator_failure(
            FI_CORR_EXECUTION_FAILED,
            "Correlator backend stderr read failed",
            strict_mode,
            cleanup_hook,
            details={
                "backend": selected_backend,
                "error": str(stderr_reader.error),
            },
        )

    stderr = stderr_reader.content.decode("utf-8", errors="replace")

    if proc.returncode != 0:
        return _handle_correlator_failure(
            FI_CORR_NATIVE_EXIT_NONZERO,
            "Correlator backend returned non-zero exit status",
            strict_mode,
            cleanup_hook,
            details={
                "backend": selected_backend,
                "returncode": proc.returncode,
                "stderr": (stderr or "").strip()[:500],
                "stderr_truncated": stderr_reader.overflowed,
            },
        )

    raw_stdout = stdout_reader.content.decode("utf-8", errors="replace").strip()
    if not raw_stdout:
        return _handle_correlator_failure(
            FI_CORR_EMPTY_STDOUT,
            "Correlator backend returned empty stdout",
            strict_mode,
            cleanup_hook,
            details={"backend": selected_backend},
        )

    try:
        response = json.loads(raw_stdout)
    except json.JSONDecodeError as err:
        return _handle_correlator_failure(
            FI_CORR_INVALID_JSON,
            "Correlator backend returned invalid JSON",
            strict_mode,
            cleanup_hook,
            details={
                "backend": selected_backend,
                "error": str(err),
            },
        )

    validation_error = _validate_correlator_response(response)
    if validation_error is not None:
        reason_code, message, details = validation_error
        details["backend"] = selected_backend
        return _handle_correlator_failure(
            reason_code, message, strict_mode, cleanup_hook, response, details
        )

    if response.get("status") != "success":
        return _handle_correlator_failure(
            FI_CORR_NATIVE_STATUS,
            "Correlator backend status is not success",
            strict_mode,
            cleanup_hook,
            response=response,
            details={
                "backend": selected_backend,
                "status": response.get("status"),
            },
        )

    if parity_hook is not None:
        try:
            parity_hook(response)
        except Exception as err:
            return _handle_correlator_failure(
                FI_CORR_PARITY_MISMATCH,
                "Correlator parity hook failed",
                strict_mode,
                cleanup_hook,
                response=response,
                details={
                    "backend": selected_backend,
                    "error": str(err),
                },
            )

    return CorrelatorBackendResult(
        selected_backend=selected_backend,
        strict_mode=strict_mode,
        response=response,
    )
