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
import subprocess

from typing import Any

import pytest

from fuzz_introspector import backend_loaders
from fuzz_introspector import code_coverage


def test_parse_backend_env_defaults_to_python(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("FI_TEST_BACKEND", raising=False)
    assert backend_loaders.parse_backend_env("FI_TEST_BACKEND") == "python"


def test_parse_backend_env_invalid_value_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch, ):
    monkeypatch.setenv("FI_TEST_BACKEND", "invalid-backend")
    assert backend_loaders.parse_backend_env("FI_TEST_BACKEND") == "python"


def test_resolve_backend_command_prefers_backend_specific(
    monkeypatch: pytest.MonkeyPatch, ):
    monkeypatch.setenv("FI_TEST_BACKEND_GO_BIN", "loader-go --fast")
    monkeypatch.setenv("FI_TEST_BACKEND_BIN", "loader-generic")
    assert backend_loaders.resolve_backend_command(
        "FI_TEST_BACKEND", "go") == ["loader-go", "--fast"]


def test_load_json_with_backend_invokes_external_process(
    monkeypatch: pytest.MonkeyPatch, ):
    monkeypatch.setenv("FI_TEST_BACKEND", "go")
    monkeypatch.setenv("FI_TEST_BACKEND_GO_BIN", "loader-go --flag")
    payload = {"paths": ["a", "b"], "mode": "test"}
    captured_input: dict[str, Any] = {}

    def _fake_run(command: list[str],
                  **kwargs: Any) -> subprocess.CompletedProcess:
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
    monkeypatch: pytest.MonkeyPatch, ):
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
        lambda **_: ("go", {
            "covmap": {
                "funcA": [[10, 1], [11, 0]]
            },
            "branch_cov_map": {
                "funcA:10,5": [1, 0]
            },
            "coverage_files": [str(covreport_path)],
        }),
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
        lambda **_: ("go", {
            "covmap": {
                "_Z10LibGMTTimev": [[10, 1], [11, 0]]
            },
            "branch_cov_map": {
                "_Z10LibGMTTimev:10,7": [1, 0]
            },
            "coverage_files": [str(covreport_path)],
        }),
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
