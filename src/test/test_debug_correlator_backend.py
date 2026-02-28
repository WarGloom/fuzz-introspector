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
"""Contract tests for correlator backend strict/non-strict behavior."""

import json
import io
import logging
import subprocess
from typing import Any

import pytest

from fuzz_introspector import backend_loaders
from fuzz_introspector import debug_info


class _FakePopen:
    def __init__(
        self,
        returncode: int | None,
        stdout: str = "",
        stderr: str = "",
    ):
        self.returncode = returncode
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(stdout.encode("utf-8"))
        self.stderr = io.BytesIO(stderr.encode("utf-8"))
        self.pid = 4321

    def poll(self):
        return self.returncode

    def wait(self, timeout: int | None = None):
        del timeout
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake-correlator", timeout=1)
        return self.returncode

    def terminate(self):
        if self.returncode is None:
            self.returncode = -15

    def kill(self):
        if self.returncode is None:
            self.returncode = -9


class _FailingStdin(io.BytesIO):
    def write(self, _data):
        raise BrokenPipeError("broken pipe")


class _CloseTrackingStream(io.BytesIO):
    def __init__(self, payload: bytes = b""):
        super().__init__(payload)
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        return super().close()


class _ReaderSpy:
    instances = []

    def __init__(
        self,
        stream: Any,
        max_bytes: int | None = None,
        name: str = "",
        stop_on_overflow: bool = True,
    ):
        del max_bytes
        del name
        del stop_on_overflow
        self.stream = stream
        self.overflowed = False
        self.total_bytes = 0
        self.error = None
        self._alive = True
        self.join_timeouts = []
        self.__class__.instances.append(self)

    @property
    def content(self) -> bytes:
        return b""

    def start(self):
        return None

    def is_alive(self):
        return self._alive

    def join(self, timeout=None):
        self.join_timeouts.append(timeout)
        self._alive = False


def _valid_metadata_only_response(schema_version: int = 1) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "status": "success",
        "counters": {"updated_functions": 0},
        "artifacts": {},
        "timings": {},
    }


def _run_correlator_with_process(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakePopen,
    *,
    strict_mode: bool,
    timeout_seconds: int = 0,
) -> backend_loaders.CorrelatorBackendResult:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-correlator"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess, "Popen", lambda *_args, **_kwargs: process
    )
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: "terminated",
    )
    if timeout_seconds > 0:
        monkeypatch.setenv("FI_DEBUG_CORRELATOR_TIMEOUT_SEC", str(timeout_seconds))
    else:
        monkeypatch.delenv("FI_DEBUG_CORRELATOR_TIMEOUT_SEC", raising=False)
    return backend_loaders.run_correlator_backend(
        payload={
            "debug_types": [],
            "debug_functions": [],
        },
        selected_backend=backend_loaders.BACKEND_RUST,
        strict_mode=strict_mode,
    )


def test_correlator_backend_go_is_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "go")
    selected_backend = backend_loaders.parse_correlator_backend_env()

    assert selected_backend == backend_loaders.BACKEND_GO


def test_correlator_backend_invalid_value_falls_back_with_warning_code(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "abc")
    with caplog.at_level(logging.WARNING):
        selected_backend = backend_loaders.parse_correlator_backend_env()

    assert selected_backend == backend_loaders.BACKEND_PYTHON
    assert any(
        backend_loaders.FI_CORR_BACKEND_UNSUPPORTED in record.message
        for record in caplog.records
    )


@pytest.mark.parametrize(
    "process,reason_code",
    [
        (
            _FakePopen(returncode=0, stdout='{"invalid": true}'),
            backend_loaders.FI_CORR_SCHEMA_ERROR,
        ),
        (
            _FakePopen(
                returncode=0, stdout=json.dumps(_valid_metadata_only_response(999))
            ),
            backend_loaders.FI_CORR_SCHEMA_VERSION_MISMATCH,
        ),
        (
            _FakePopen(returncode=7, stdout="", stderr="boom"),
            backend_loaders.FI_CORR_NATIVE_EXIT_NONZERO,
        ),
    ],
)
def test_correlator_strict_mode_failures_raise(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakePopen,
    reason_code: str,
) -> None:
    with pytest.raises(backend_loaders.CorrelatorBackendError) as exc_info:
        _run_correlator_with_process(monkeypatch, process, strict_mode=True)
    assert exc_info.value.reason_code == reason_code


def test_correlator_strict_mode_timeout_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakePopen(returncode=None)
    with pytest.raises(backend_loaders.CorrelatorBackendError) as exc_info:
        _run_correlator_with_process(
            monkeypatch,
            process,
            strict_mode=True,
            timeout_seconds=1,
        )
    assert exc_info.value.reason_code == backend_loaders.FI_CORR_TIMEOUT


@pytest.mark.parametrize(
    "process,reason_code",
    [
        (
            _FakePopen(returncode=0, stdout='{"invalid": true}'),
            backend_loaders.FI_CORR_SCHEMA_ERROR,
        ),
        (
            _FakePopen(
                returncode=0, stdout=json.dumps(_valid_metadata_only_response(999))
            ),
            backend_loaders.FI_CORR_SCHEMA_VERSION_MISMATCH,
        ),
        (
            _FakePopen(returncode=7, stdout="", stderr="boom"),
            backend_loaders.FI_CORR_NATIVE_EXIT_NONZERO,
        ),
    ],
)
def test_correlator_non_strict_mode_fallbacks_on_failures(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakePopen,
    reason_code: str,
) -> None:
    result = _run_correlator_with_process(monkeypatch, process, strict_mode=False)
    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == reason_code


def test_correlator_non_strict_mode_timeout_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakePopen(returncode=None)
    result = _run_correlator_with_process(
        monkeypatch,
        process,
        strict_mode=False,
        timeout_seconds=1,
    )
    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_CORR_TIMEOUT


def test_correlator_schema_version_match_proceeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakePopen(
        returncode=0, stdout=json.dumps(_valid_metadata_only_response(1))
    )
    result = _run_correlator_with_process(monkeypatch, process, strict_mode=True)
    assert result.selected_backend == backend_loaders.BACKEND_RUST
    assert result.reason_code is None
    assert result.response == _valid_metadata_only_response(1)


def test_correlator_schema_version_higher_strict_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakePopen(
        returncode=0, stdout=json.dumps(_valid_metadata_only_response(2))
    )
    with pytest.raises(backend_loaders.CorrelatorBackendError) as exc_info:
        _run_correlator_with_process(monkeypatch, process, strict_mode=True)
    assert exc_info.value.reason_code == backend_loaders.FI_CORR_SCHEMA_VERSION_MISMATCH


def test_correlator_schema_version_higher_non_strict_fallbacks_with_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    process = _FakePopen(
        returncode=0, stdout=json.dumps(_valid_metadata_only_response(2))
    )
    with caplog.at_level(logging.WARNING):
        result = _run_correlator_with_process(monkeypatch, process, strict_mode=False)
    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_CORR_SCHEMA_VERSION_MISMATCH
    assert any(
        backend_loaders.FI_CORR_SCHEMA_VERSION_MISMATCH in record.message
        for record in caplog.records
    )


def test_correlator_metadata_only_required_keys_enforced() -> None:
    error = backend_loaders._validate_correlator_response(
        {
            "schema_version": 1,
            "status": "success",
            "counters": {},
            "artifacts": {},
        }
    )
    assert error is not None
    reason_code, _message, details = error
    assert reason_code == backend_loaders.FI_CORR_SCHEMA_ERROR
    assert "timings" in details["missing_keys"]


def test_correlator_metadata_only_contract_accepts_required_keys() -> None:
    assert (
        backend_loaders._validate_correlator_response(_valid_metadata_only_response(1))
        is None
    )


def test_correlator_rejects_oversized_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized_stdout = "x" * (backend_loaders.CORRELATOR_MAX_STDOUT_BYTES + 1)
    process = _FakePopen(returncode=0, stdout=oversized_stdout)
    result = _run_correlator_with_process(monkeypatch, process, strict_mode=False)
    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_CORR_STDOUT_TOO_LARGE


def test_correlator_oversized_stdout_triggers_prebuffer_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized_stdout = "x" * (backend_loaders.CORRELATOR_MAX_STDOUT_BYTES + 1)
    process = _FakePopen(returncode=None, stdout=oversized_stdout)
    terminate_calls = []
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-correlator"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: terminate_calls.append(1) or "terminated",
    )

    result = backend_loaders.run_correlator_backend(
        payload={"debug_types": [], "debug_functions": []},
        selected_backend=backend_loaders.BACKEND_RUST,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_CORR_STDOUT_TOO_LARGE
    assert result.reason_details == {
        "backend": backend_loaders.BACKEND_RUST,
        "stdout_bytes": backend_loaders.CORRELATOR_MAX_STDOUT_BYTES + 1,
        "max_stdout_bytes": backend_loaders.CORRELATOR_MAX_STDOUT_BYTES,
        "cleanup_status": "terminated",
    }
    assert terminate_calls == [1]


def test_correlator_stdin_failure_closes_pipes_and_joins_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-correlator"],
    )
    _ReaderSpy.instances = []

    stdout_stream = _CloseTrackingStream()
    stderr_stream = _CloseTrackingStream()

    tracked_proc = _FakePopen(returncode=None)
    tracked_proc.stdin = _FailingStdin()
    tracked_proc.stdout = stdout_stream
    tracked_proc.stderr = stderr_stream

    monkeypatch.setattr(backend_loaders, "_BoundedStreamReader", _ReaderSpy)
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: tracked_proc,
    )
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: "terminated",
    )

    result = backend_loaders.run_correlator_backend(
        payload={"debug_types": [], "debug_functions": []},
        selected_backend=backend_loaders.BACKEND_RUST,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_CORR_EXECUTION_FAILED
    assert stdout_stream.close_calls >= 1
    assert stderr_stream.close_calls >= 1
    assert len(_ReaderSpy.instances) == 2
    assert all(reader.join_timeouts for reader in _ReaderSpy.instances)


def test_correlator_communication_exception_triggers_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-correlator"],
    )
    terminate_calls = []
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: terminate_calls.append(1) or "terminated",
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(returncode=None),
    )
    monkeypatch.setattr(
        backend_loaders.time,
        "sleep",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("sleep failed")),
    )

    result = backend_loaders.run_correlator_backend(
        payload={"debug_types": [], "debug_functions": []},
        selected_backend=backend_loaders.BACKEND_RUST,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_CORR_EXECUTION_FAILED
    assert result.reason_details == {
        "backend": backend_loaders.BACKEND_RUST,
        "command": ["fake-correlator"],
        "error": "sleep failed",
        "cleanup_status": "terminated",
    }
    assert terminate_calls == [1]


def test_correlator_reader_error_fails_fast_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    class _ReaderErrorSpy:
        def __init__(
            self,
            stream: Any,
            max_bytes: int | None = None,
            name: str = "",
            stop_on_overflow: bool = True,
        ):
            del max_bytes
            del stop_on_overflow
            self._stream = stream
            self._name = name
            self.total_bytes = 0
            self.overflowed = False
            self.error = (
                RuntimeError("stdout reader failed") if "stdout" in name else None
            )
            self._alive = True

        @property
        def content(self) -> bytes:
            return b""

        def start(self):
            return None

        def is_alive(self):
            return self._alive

        def join(self, timeout=None):
            del timeout
            self._alive = False

    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-correlator"],
    )
    terminate_calls = []
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: terminate_calls.append(1) or "terminated",
    )
    monkeypatch.setattr(backend_loaders, "_BoundedStreamReader", _ReaderErrorSpy)
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(returncode=None),
    )
    monkeypatch.setattr(
        backend_loaders.time,
        "sleep",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("sleep should not be reached")
        ),
    )

    result = backend_loaders.run_correlator_backend(
        payload={"debug_types": [], "debug_functions": []},
        selected_backend=backend_loaders.BACKEND_RUST,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_CORR_EXECUTION_FAILED
    assert result.reason_details == {
        "backend": backend_loaders.BACKEND_RUST,
        "error": "stdout reader failed",
        "cleanup_status": "terminated",
    }
    assert terminate_calls == [1]


def test_correlator_shards_require_full_row_coverage(tmp_path) -> None:
    shard_path = tmp_path / "correlated-partial-00000.ndjson"
    shard_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "row_idx": 0,
                        "func_signature_elems": {"return_type": [], "params": []},
                        "source": {"source_file": "a.c", "source_line": "1"},
                    }
                ),
                json.dumps(
                    {
                        "row_idx": 2,
                        "func_signature_elems": {"return_type": [], "params": []},
                        "source": {"source_file": "b.c", "source_line": "2"},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    response = {"artifacts": {"correlated_shards": [str(shard_path)]}}

    with pytest.raises(ValueError, match="coverage mismatch"):
        debug_info._collect_correlator_shard_updates(
            [{}, {}, {}],
            response,
            require_complete_coverage=True,
        )


def test_correlator_shards_keep_one_update_per_original_row(tmp_path) -> None:
    shard_path = tmp_path / "correlated-complete-00000.ndjson"
    repeated_signature = {"return_type": ["N/A"], "params": []}
    repeated_source = {"source_file": "same.c", "source_line": "7"}
    shard_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "row_idx": 0,
                        "func_signature_elems": repeated_signature,
                        "source": repeated_source,
                    }
                ),
                json.dumps(
                    {
                        "row_idx": 1,
                        "func_signature_elems": repeated_signature,
                        "source": repeated_source,
                    }
                ),
                json.dumps(
                    {
                        "row_idx": 2,
                        "func_signature_elems": repeated_signature,
                        "source": repeated_source,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    response = {"artifacts": {"correlated_shards": [str(shard_path)]}}

    updates = debug_info._collect_correlator_shard_updates(
        [{}, {}, {}],
        response,
        require_complete_coverage=True,
    )

    assert [row_idx for row_idx, _sig, _source in updates] == [0, 1, 2]
