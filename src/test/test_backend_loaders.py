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
"""Tests for backend loader selection and external JSON protocol helpers."""

import json
import io
import subprocess

from typing import Any

import pytest

from fuzz_introspector import backend_loaders
from fuzz_introspector import code_coverage
from fuzz_introspector import debug_info


class _FakePopen:
    def __init__(
        self,
        returncode: int | None,
        stdout: str | bytes = "",
        stderr: str | bytes = "",
        stdin: io.BytesIO | None = None,
    ):
        self.returncode = returncode
        stdout_bytes = stdout if isinstance(stdout, bytes) else stdout.encode("utf-8")
        stderr_bytes = stderr if isinstance(stderr, bytes) else stderr.encode("utf-8")
        self.stdin = stdin if stdin is not None else io.BytesIO()
        self.stdout = io.BytesIO(stdout_bytes)
        self.stderr = io.BytesIO(stderr_bytes)
        self.pid = 1234

    def poll(self):
        return self.returncode

    def wait(self, timeout: int | None = None):
        del timeout
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake-overlay", timeout=1)
        return self.returncode

    def terminate(self):
        if self.returncode is None:
            self.returncode = -15
        return None

    def kill(self):
        if self.returncode is None:
            self.returncode = -9
        return None


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
        self._started = False
        self._alive = True
        self.join_timeouts = []
        self.__class__.instances.append(self)

    @property
    def content(self) -> bytes:
        return b""

    def start(self):
        self._started = True

    def is_alive(self):
        return self._alive

    def join(self, timeout=None):
        self.join_timeouts.append(timeout)
        self._alive = False


def test_parse_backend_env_defaults_to_python(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("FI_TEST_BACKEND", raising=False)
    assert backend_loaders.parse_backend_env("FI_TEST_BACKEND") == "python"


def test_parse_backend_env_invalid_value_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("FI_TEST_BACKEND", "invalid-backend")
    assert backend_loaders.parse_backend_env("FI_TEST_BACKEND") == "python"


def test_resolve_backend_command_prefers_backend_specific(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("FI_TEST_BACKEND_GO_BIN", "loader-go --fast")
    monkeypatch.setenv("FI_TEST_BACKEND_BIN", "loader-generic")
    assert backend_loaders.resolve_backend_command("FI_TEST_BACKEND", "go") == [
        "loader-go",
        "--fast",
    ]


def test_load_json_with_backend_invokes_external_process(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("FI_TEST_BACKEND", "go")
    monkeypatch.setenv("FI_TEST_BACKEND_GO_BIN", "loader-go --flag")
    payload = {"paths": ["a", "b"], "mode": "test"}
    captured_input: dict[str, Any] = {}

    def _fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        captured_input.update(json.loads(kwargs["input"]))
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout='{"items":[{"k":"v"}]}',
            stderr="",
        )

    monkeypatch.setattr(backend_loaders.subprocess, "run", _fake_run)

    selected_backend, result = backend_loaders.load_json_with_backend(
        backend_env="FI_TEST_BACKEND",
        command_env_prefix="FI_TEST_BACKEND",
        payload=payload,
    )

    assert selected_backend == "go"
    assert result == {"items": [{"k": "v"}]}
    assert captured_input == payload


def test_load_json_with_backend_falls_back_when_no_binary(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("FI_TEST_BACKEND", "rust")
    monkeypatch.delenv("FI_TEST_BACKEND_RUST_BIN", raising=False)
    monkeypatch.delenv("FI_TEST_BACKEND_BIN", raising=False)

    selected_backend, result = backend_loaders.load_json_with_backend(
        backend_env="FI_TEST_BACKEND",
        command_env_prefix="FI_TEST_BACKEND",
        payload={"key": "value"},
    )

    assert selected_backend == "python"
    assert result is None


def test_load_llvm_coverage_accepts_external_backend_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    covreport_path = tmp_path / "sample.covreport"
    covreport_path.write_text("")

    monkeypatch.setattr(
        backend_loaders,
        "load_json_with_backend",
        lambda **_: (
            "go",
            {
                "covmap": {"funcA": [[10, 1], [11, 0]]},
                "branch_cov_map": {"funcA:10,5": [1, 0]},
                "coverage_files": [str(covreport_path)],
            },
        ),
    )

    cp = code_coverage.load_llvm_coverage(str(tmp_path))
    assert cp.get_type() == "function"
    assert cp.covmap["funcA"] == [(10, 1), (11, 0)]
    assert cp.branch_cov_map["funcA:10,5"] == [1, 0]
    assert cp.coverage_files == [str(covreport_path)]


def test_load_llvm_coverage_demangles_external_backend_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    covreport_path = tmp_path / "sample.covreport"
    covreport_path.write_text("")

    monkeypatch.setattr(
        backend_loaders,
        "load_json_with_backend",
        lambda **_: (
            "go",
            {
                "covmap": {"_Z10LibGMTTimev": [[10, 1], [11, 0]]},
                "branch_cov_map": {"_Z10LibGMTTimev:10,7": [1, 0]},
                "coverage_files": [str(covreport_path)],
            },
        ),
    )

    cp = code_coverage.load_llvm_coverage(str(tmp_path))
    assert cp.covmap["LibGMTTime()"] == [(10, 1), (11, 0)]
    assert cp.branch_cov_map["LibGMTTime():10,7"] == [1, 0]


def test_load_llvm_coverage_uses_python_default_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    covreport_path = tmp_path / "sample.covreport"
    covreport_path.write_text("")

    captured = {}

    def _fake_loader(**kwargs):
        captured["default_backend"] = kwargs.get("default_backend")
        return "python", None

    monkeypatch.setattr(backend_loaders, "load_json_with_backend", _fake_loader)
    monkeypatch.delenv("FI_LLVM_COV_LOADER", raising=False)
    monkeypatch.delenv("FI_NATIVE_BACKENDS", raising=False)

    cp = code_coverage.load_llvm_coverage(str(tmp_path))
    assert captured["default_backend"] == backend_loaders.BACKEND_PYTHON
    assert cp.coverage_files == [str(covreport_path)]


def test_parse_overlay_backend_env_defaults_to_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_OVERLAY_BACKEND", raising=False)
    assert backend_loaders.parse_overlay_backend_env() == backend_loaders.BACKEND_PYTHON


def test_parse_overlay_backend_env_accepts_native(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_OVERLAY_BACKEND", "native")
    assert backend_loaders.parse_overlay_backend_env() == backend_loaders.BACKEND_NATIVE


def test_parse_overlay_backend_env_accepts_rust_compat_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_OVERLAY_BACKEND", "rust")
    assert backend_loaders.parse_overlay_backend_env() == backend_loaders.BACKEND_RUST


def test_parse_overlay_backend_env_accepts_go_compat_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_OVERLAY_BACKEND", "go")
    assert backend_loaders.parse_overlay_backend_env() == backend_loaders.BACKEND_GO


def test_parse_overlay_backend_selection_retains_alias_with_native_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_OVERLAY_BACKEND", "go")

    selection = backend_loaders.parse_overlay_backend_selection()

    assert selection.requested_backend == backend_loaders.BACKEND_GO
    assert selection.execution_backend == backend_loaders.BACKEND_NATIVE


def test_resolve_overlay_command_rust_alias_falls_back_to_native_bin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_OVERLAY_RUST_BIN", raising=False)
    monkeypatch.setenv("FI_OVERLAY_NATIVE_BIN", "overlay-native --json")
    monkeypatch.delenv("FI_OVERLAY_BIN", raising=False)

    assert backend_loaders.resolve_backend_command("FI_OVERLAY", "rust") == [
        "overlay-native",
        "--json",
    ]


def test_resolve_overlay_command_go_alias_falls_back_to_native_bin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_OVERLAY_GO_BIN", raising=False)
    monkeypatch.setenv("FI_OVERLAY_NATIVE_BIN", "overlay-native --json")
    monkeypatch.delenv("FI_OVERLAY_BIN", raising=False)

    assert backend_loaders.resolve_backend_command("FI_OVERLAY", "go") == [
        "overlay-native",
        "--json",
    ]


@pytest.mark.parametrize(
    "requested_backend",
    [backend_loaders.BACKEND_GO, backend_loaders.BACKEND_RUST],
)
def test_run_overlay_backend_alias_uses_native_command_resolution(
    monkeypatch: pytest.MonkeyPatch,
    requested_backend: str,
) -> None:
    resolve_calls = []

    def _capture_resolve(prefix: str, backend: str) -> list[str] | None:
        resolve_calls.append((prefix, backend))
        return None

    monkeypatch.setattr(backend_loaders, "resolve_backend_command", _capture_resolve)
    monkeypatch.setattr(backend_loaders.os.path, "isfile", lambda _path: False)
    monkeypatch.setattr(backend_loaders.os, "access", lambda _path, _mode: False)
    monkeypatch.setattr(backend_loaders.shutil, "which", lambda _name: None)

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=requested_backend,
        strict_mode=False,
    )

    assert resolve_calls == [("FI_OVERLAY", backend_loaders.BACKEND_NATIVE)]
    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_COMMAND_MISSING
    assert result.reason_details is not None
    assert result.reason_details["backend"] == requested_backend
    assert result.reason_details["execution_backend"] == backend_loaders.BACKEND_NATIVE
    assert result.reason_details["command_env_prefix"] == "FI_OVERLAY"
    assert result.reason_details["env_hint"] == (
        "Set FI_OVERLAY_NATIVE_BIN or FI_OVERLAY_BIN"
    )
    assert len(result.reason_details["checked_candidates"]) == 4


def test_parse_overlay_shadow_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_OVERLAY_SHADOW", raising=False)
    assert not backend_loaders.parse_overlay_shadow_mode()
    monkeypatch.setenv("FI_OVERLAY_SHADOW", "1")
    assert backend_loaders.parse_overlay_shadow_mode()


def test_resolve_overlay_command_uses_fi_overlay_bin_when_specific_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_OVERLAY_NATIVE_BIN", raising=False)
    monkeypatch.setenv("FI_OVERLAY_BIN", "overlay-native --json")
    assert backend_loaders.resolve_backend_command(
        "FI_OVERLAY", backend_loaders.BACKEND_NATIVE
    ) == ["overlay-native", "--json"]


def test_overlay_native_command_autodiscovery_uses_repo_rust_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_OVERLAY_NATIVE_BIN", raising=False)
    monkeypatch.delenv("FI_OVERLAY_BIN", raising=False)
    monkeypatch.setattr(backend_loaders.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        backend_loaders.os.path,
        "isfile",
        lambda path: path.endswith(
            "tools/native_overlay_backend_rust/target/release/"
            "native_overlay_backend_rust"
        ),
    )
    monkeypatch.setattr(backend_loaders.os, "access", lambda _path, _mode: True)

    captured_command = {}
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda command, *_args, **_kwargs: (
            captured_command.update({"command": command})
            or _FakePopen(
                returncode=0,
                stdout=(
                    '{"schema_version":1,"status":"success",'
                    '"counters":{},"artifacts":{'
                    '"overlay_nodes":"a.json","branch_complexities":"b.json",'
                    '"branch_blockers":"c.json"},"timings":{}}'
                ),
            )
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_NATIVE
    assert result.response is not None
    assert captured_command["command"][0].endswith(
        "tools/native_overlay_backend_rust/target/release/native_overlay_backend_rust"
    )


def test_overlay_native_command_missing_reports_discovery_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_OVERLAY_NATIVE_BIN", raising=False)
    monkeypatch.delenv("FI_OVERLAY_BIN", raising=False)
    monkeypatch.setattr(backend_loaders.shutil, "which", lambda _name: None)
    monkeypatch.setattr(backend_loaders.os.path, "isfile", lambda _path: False)
    monkeypatch.setattr(backend_loaders.os, "access", lambda _path, _mode: False)

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_COMMAND_MISSING
    assert result.reason_details is not None
    assert set(result.reason_details) == {
        "backend",
        "execution_backend",
        "command_env_prefix",
        "checked_candidates",
        "env_hint",
    }
    assert result.reason_details["env_hint"] == (
        "Set FI_OVERLAY_NATIVE_BIN or FI_OVERLAY_BIN"
    )
    checked_candidates = result.reason_details["checked_candidates"]
    assert len(checked_candidates) == 4
    assert checked_candidates[1]["candidate"] == "native_overlay_backend_rust"
    assert checked_candidates[3]["candidate"] == "native_overlay_backend_go"


def test_resolve_overlay_backend_command_details_use_custom_env_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "_resolve_overlay_native_command_with_fallback",
        lambda *_args, **_kwargs: (None, []),
    )

    _command, details = backend_loaders.resolve_overlay_backend_command_with_details(
        backend_loaders.BACKEND_NATIVE,
        command_env_prefix="FI_ALT_OVERLAY",
    )

    assert details["command_env_prefix"] == "FI_ALT_OVERLAY"
    assert details["env_hint"] == "Set FI_ALT_OVERLAY_NATIVE_BIN or FI_ALT_OVERLAY_BIN"


def test_overlay_native_command_missing_strict_falls_back_with_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Binary absence is a config gap, not a correctness failure.

    strict_mode must NOT raise for COMMAND_MISSING; it should always fall back
    to Python and emit a prominent warning so operators know the binary is missing.
    """
    monkeypatch.delenv("FI_OVERLAY_NATIVE_BIN", raising=False)
    monkeypatch.delenv("FI_OVERLAY_BIN", raising=False)
    monkeypatch.setattr(backend_loaders.shutil, "which", lambda _name: None)
    monkeypatch.setattr(backend_loaders.os.path, "isfile", lambda _path: False)
    monkeypatch.setattr(backend_loaders.os, "access", lambda _path, _mode: False)

    import logging

    with caplog.at_level(logging.WARNING):
        result = backend_loaders.run_overlay_backend(
            payload={"fuzzer": "fuzz_target"},
            selected_backend=backend_loaders.BACKEND_NATIVE,
            strict_mode=True,
        )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_COMMAND_MISSING
    assert set(result.reason_details or {}) == {
        "backend",
        "execution_backend",
        "command_env_prefix",
        "checked_candidates",
        "env_hint",
    }
    assert any(
        backend_loaders.FI_OVERLAY_COMMAND_MISSING in record.message
        for record in caplog.records
    )


def test_overlay_non_strict_invalid_contract_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout='{"invalid": true}',
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_SCHEMA_ERROR


def test_overlay_non_strict_schema_version_mismatch_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout=(
                '{"schema_version":999,"status":"success",'
                '"counters":{},"artifacts":{},"timings":{}}'
            ),
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_SCHEMA_VERSION_MISMATCH


def test_overlay_non_strict_native_status_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout=(
                '{"schema_version":1,"status":"error",'
                '"counters":{},"artifacts":{"overlay_nodes":"a.json",'
                '"branch_complexities":"b.json","branch_blockers":"c.json"},'
                '"timings":{}}'
            ),
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_NATIVE_STATUS


def test_overlay_non_strict_nonzero_exit_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(returncode=5, stderr="boom"),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_NATIVE_EXIT_NONZERO


def test_overlay_non_strict_timeout_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_OVERLAY_TIMEOUT_SEC", "1")
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: "terminated",
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(returncode=None),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_TIMEOUT


def test_overlay_strict_invalid_contract_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout='{"invalid": true}',
        ),
    )

    with pytest.raises(backend_loaders.OverlayBackendError) as exc_info:
        backend_loaders.run_overlay_backend(
            payload={"fuzzer": "fuzz_target"},
            selected_backend=backend_loaders.BACKEND_NATIVE,
            strict_mode=True,
        )

    assert exc_info.value.reason_code == backend_loaders.FI_OVERLAY_SCHEMA_ERROR


def test_overlay_non_strict_oversized_stdout_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    oversized_stdout = "x" * (backend_loaders.OVERLAY_MAX_STDOUT_BYTES + 1)
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout=oversized_stdout,
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_STDOUT_TOO_LARGE


def test_overlay_strict_oversized_stdout_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    oversized_stdout = "x" * (backend_loaders.OVERLAY_MAX_STDOUT_BYTES + 1)
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout=oversized_stdout,
        ),
    )

    with pytest.raises(backend_loaders.OverlayBackendError) as exc_info:
        backend_loaders.run_overlay_backend(
            payload={"fuzzer": "fuzz_target"},
            selected_backend=backend_loaders.BACKEND_NATIVE,
            strict_mode=True,
        )

    assert exc_info.value.reason_code == backend_loaders.FI_OVERLAY_STDOUT_TOO_LARGE


def test_overlay_oversized_stdout_triggers_termination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    oversized_stdout = "x" * (backend_loaders.OVERLAY_MAX_STDOUT_BYTES + 1)
    terminate_calls = []
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: terminate_calls.append(1) or "terminated",
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout=oversized_stdout,
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_OVERLAY_STDOUT_TOO_LARGE
    assert terminate_calls == [1]


def test_overlay_oversized_stderr_triggers_termination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    oversized_stderr = "x" * (backend_loaders.OVERLAY_MAX_STDERR_BYTES + 1)
    terminate_calls = []
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: terminate_calls.append(1) or "terminated",
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout='{"schema_version":1,"status":"success","counters":{},'
            '"artifacts":{"overlay_nodes":"a.json","branch_complexities":"b.json",'
            '"branch_blockers":"c.json"},"timings":{}}',
            stderr=oversized_stderr,
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_OVERLAY_STDERR_TOO_LARGE
    assert result.reason_details == {
        "backend": backend_loaders.BACKEND_NATIVE,
        "stderr_bytes": backend_loaders.OVERLAY_MAX_STDERR_BYTES + 1,
        "max_stderr_bytes": backend_loaders.OVERLAY_MAX_STDERR_BYTES,
        "cleanup_status": "terminated",
    }
    assert terminate_calls == [1]


def test_overlay_stdin_write_failure_triggers_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
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
        lambda *_args, **_kwargs: _FakePopen(
            returncode=None,
            stdin=_FailingStdin(),
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_OVERLAY_EXECUTION_FAILED
    assert result.reason_details == {
        "backend": backend_loaders.BACKEND_NATIVE,
        "command": ["fake-overlay"],
        "error": "broken pipe",
        "cleanup_status": "terminated",
    }
    assert terminate_calls == [1]


def test_overlay_stdin_failure_closes_pipes_and_joins_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    _ReaderSpy.instances = []

    stdout_stream = _CloseTrackingStream()
    stderr_stream = _CloseTrackingStream()

    class _TrackedOverlayPopen(_FakePopen):
        def __init__(self):
            super().__init__(returncode=None, stdin=_FailingStdin())
            self.stdout = stdout_stream
            self.stderr = stderr_stream

    tracked_proc = _TrackedOverlayPopen()
    monkeypatch.setattr(
        backend_loaders,
        "_BoundedStreamReader",
        _ReaderSpy,
    )
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

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_OVERLAY_EXECUTION_FAILED
    assert stdout_stream.close_calls >= 1
    assert stderr_stream.close_calls >= 1
    assert len(_ReaderSpy.instances) == 2
    assert all(reader.join_timeouts for reader in _ReaderSpy.instances)


def test_overlay_communication_exception_triggers_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
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

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_OVERLAY_EXECUTION_FAILED
    assert result.reason_details == {
        "backend": backend_loaders.BACKEND_NATIVE,
        "command": ["fake-overlay"],
        "error": "sleep failed",
        "cleanup_status": "terminated",
    }
    assert terminate_calls == [1]


def test_overlay_reader_error_fails_fast_and_cleans_up(
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
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    terminate_calls = []
    monkeypatch.setattr(
        backend_loaders,
        "_terminate_process_group",
        lambda *_args, **_kwargs: terminate_calls.append(1) or "terminated",
    )
    monkeypatch.setattr(
        backend_loaders,
        "_BoundedStreamReader",
        _ReaderErrorSpy,
    )
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

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.reason_code == backend_loaders.FI_OVERLAY_EXECUTION_FAILED
    assert result.reason_details == {
        "backend": backend_loaders.BACKEND_NATIVE,
        "error": "stdout reader failed",
        "cleanup_status": "terminated",
    }
    assert terminate_calls == [1]


def test_overlay_missing_artifact_key_non_strict_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout=(
                '{"schema_version":1,"status":"success",'
                '"counters":{},"artifacts":{"overlay_nodes":"a.json"},'
                '"timings":{}}'
            ),
        ),
    )

    result = backend_loaders.run_overlay_backend(
        payload={"fuzzer": "fuzz_target"},
        selected_backend=backend_loaders.BACKEND_NATIVE,
        strict_mode=False,
    )

    assert result.selected_backend == backend_loaders.BACKEND_PYTHON
    assert result.reason_code == backend_loaders.FI_OVERLAY_SCHEMA_ERROR
    assert result.reason_details == {
        "invalid_artifact_keys": ["branch_complexities", "branch_blockers"],
        "backend": backend_loaders.BACKEND_NATIVE,
    }


def test_overlay_missing_artifact_key_strict_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_loaders,
        "resolve_backend_command",
        lambda *_args, **_kwargs: ["fake-overlay"],
    )
    monkeypatch.setattr(
        backend_loaders.subprocess,
        "Popen",
        lambda *_args, **_kwargs: _FakePopen(
            returncode=0,
            stdout=(
                '{"schema_version":1,"status":"success",'
                '"counters":{},"artifacts":{"overlay_nodes":"a.json"},'
                '"timings":{}}'
            ),
        ),
    )

    with pytest.raises(backend_loaders.OverlayBackendError) as exc_info:
        backend_loaders.run_overlay_backend(
            payload={"fuzzer": "fuzz_target"},
            selected_backend=backend_loaders.BACKEND_NATIVE,
            strict_mode=True,
        )

    assert exc_info.value.reason_code == backend_loaders.FI_OVERLAY_SCHEMA_ERROR


# ---------------------------------------------------------------------------
# FI_DEBUG_YAML_LOADER parity tests
# ---------------------------------------------------------------------------


def test_fi_debug_yaml_loader_rust_invokes_native_binary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """FI_DEBUG_YAML_LOADER=rust must invoke the native binary via subprocess."""
    monkeypatch.setenv("FI_DEBUG_YAML_LOADER", "rust")
    monkeypatch.setenv("FI_DEBUG_YAML_LOADER_RUST_BIN", "fake-yaml-loader")
    monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")

    captured: dict[str, Any] = {}

    def _fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        captured["command"] = command
        captured["payload"] = json.loads(kwargs["input"])
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout='{"items":[{"k":"v"}]}',
            stderr="",
        )

    monkeypatch.setattr(backend_loaders.subprocess, "run", _fake_run)

    yaml_path = tmp_path / "a.yaml"
    yaml_path.write_text("- k: v\n")
    debug_info.load_debug_all_yaml_files([str(yaml_path)])

    assert captured.get("command") == ["fake-yaml-loader"]
    assert "paths" in captured.get("payload", {})


def test_fi_debug_yaml_loader_valid_json_parsed_correctly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Native YAML loader returning valid JSON must be parsed into items list."""
    monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")

    monkeypatch.setattr(
        backend_loaders,
        "load_json_with_backend",
        lambda **_: ("rust", {"items": [{"func": "foo"}, {"func": "bar"}]}),
    )

    yaml_path = tmp_path / "b.yaml"
    yaml_path.write_text("- func: foo\n")
    items = debug_info.load_debug_all_yaml_files([str(yaml_path)])

    assert items == [{"func": "foo"}, {"func": "bar"}]


def test_fi_debug_yaml_loader_failure_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """When native YAML loader fails (returns None), Python fallback must be used."""
    monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")

    monkeypatch.setattr(
        backend_loaders,
        "load_json_with_backend",
        lambda **_: ("python", None),
    )

    yaml_path = tmp_path / "c.yaml"
    yaml_path.write_text("- idx: 42\n")
    items = debug_info.load_debug_all_yaml_files([str(yaml_path)])

    # Python fallback must parse the YAML file directly.
    assert items == [{"idx": 42}]


# ---------------------------------------------------------------------------
# FI_LLVM_COV_LOADER parity tests
# ---------------------------------------------------------------------------


def test_fi_llvm_cov_loader_rust_invokes_native_binary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """FI_LLVM_COV_LOADER=rust must invoke the native binary via subprocess."""
    monkeypatch.setenv("FI_LLVM_COV_LOADER", "rust")
    monkeypatch.setenv("FI_LLVM_COV_LOADER_RUST_BIN", "fake-llvm-cov-loader")

    covreport = tmp_path / "cov.covreport"
    covreport.write_text("")

    captured: dict[str, Any] = {}

    def _fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        captured["command"] = command
        captured["payload"] = json.loads(kwargs["input"])
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(
                {
                    "covmap": {},
                    "branch_cov_map": {},
                    "coverage_files": [str(covreport)],
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(backend_loaders.subprocess, "run", _fake_run)

    code_coverage.load_llvm_coverage(str(tmp_path))

    assert captured.get("command") == ["fake-llvm-cov-loader"]
    assert "coverage_reports" in captured.get("payload", {})


def test_fi_llvm_cov_loader_valid_payload_applied_correctly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Native LLVM cov loader returning valid {covmap, branch_cov_map} must be applied."""
    covreport = tmp_path / "cov.covreport"
    covreport.write_text("")

    monkeypatch.setattr(
        backend_loaders,
        "load_json_with_backend",
        lambda **_: (
            "rust",
            {
                "covmap": {"funcZ": [[5, 3], [6, 0]]},
                "branch_cov_map": {"funcZ:5,2": [3, 0]},
                "coverage_files": [str(covreport)],
            },
        ),
    )

    cp = code_coverage.load_llvm_coverage(str(tmp_path))

    assert cp.covmap["funcZ"] == [(5, 3), (6, 0)]
    assert cp.branch_cov_map["funcZ:5,2"] == [3, 0]
    assert cp.coverage_files == [str(covreport)]


def test_fi_llvm_cov_loader_failure_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """When native LLVM cov loader fails (returns None), Python fallback must be used."""
    covreport = tmp_path / "cov.covreport"
    covreport.write_text("LLVM\n 0: funcP\n /path/to/file.cpp:\n  10| 2|  doThing();\n")

    monkeypatch.setattr(
        backend_loaders,
        "load_json_with_backend",
        lambda **_: ("python", None),
    )

    # Python fallback runs without raising even if the covreport is minimal.
    cp = code_coverage.load_llvm_coverage(str(tmp_path))
    assert cp.get_type() == "function"
    assert cp.coverage_files == [str(covreport)]
