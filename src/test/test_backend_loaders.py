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


def test_load_llvm_coverage_uses_rust_default_backend(
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

    cp = code_coverage.load_llvm_coverage(str(tmp_path))
    assert captured["default_backend"] == backend_loaders.BACKEND_RUST
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

    with pytest.raises(backend_loaders.CorrelatorBackendError) as exc_info:
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

    with pytest.raises(backend_loaders.CorrelatorBackendError) as exc_info:
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

    with pytest.raises(backend_loaders.CorrelatorBackendError) as exc_info:
        backend_loaders.run_overlay_backend(
            payload={"fuzzer": "fuzz_target"},
            selected_backend=backend_loaders.BACKEND_NATIVE,
            strict_mode=True,
        )

    assert exc_info.value.reason_code == backend_loaders.FI_OVERLAY_SCHEMA_ERROR
