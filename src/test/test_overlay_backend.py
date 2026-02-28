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
"""Tests for phase-1 overlay backend plumbing behavior."""

import json
import shlex
import sys
from types import SimpleNamespace

import pytest

from fuzz_introspector import analysis
from fuzz_introspector import backend_loaders
from fuzz_introspector import cfg_load


class _CoverageStub:
    def __init__(self) -> None:
        self.covmap = {"entry": [(1, 1)]}
        self.file_map = {}
        self.branch_cov_map = {}

    def get_type(self) -> str:
        return "function"


class _BranchSideStub:
    def __init__(self, funcs):
        self.pos = "a.c:10,1"
        self.funcs = funcs
        self.unique_not_covered_complexity = 0
        self.unique_reachable_complexity = 0
        self.reachable_complexity = 0
        self.not_covered_complexity = 0


class _BranchProfileStub:
    def __init__(self):
        self.sides = [_BranchSideStub(["entry"])]


class _FunctionStub:
    def __init__(self):
        self.function_source_file = "a.c"
        self.total_cyclomatic_complexity = 10
        self.branch_profiles = {"a.c:10,1": _BranchProfileStub()}


class _ProfileStub(SimpleNamespace):
    def resolve_coverage_link(self, _url, source_file, line, function_name):
        return f"{source_file}:{line}:{function_name}"


def _dummy_profile() -> _ProfileStub:
    root = cfg_load.CalltreeCallsite("entry", "a.c", 0, 1, None)
    return _ProfileStub(
        identifier="fuzzer",
        target_lang="c-cpp",
        fuzzer_callsite_calltree=root,
        coverage=_CoverageStub(),
        dst_to_fd_cache={},
        branch_blockers=[],
    )


def _dummy_project() -> SimpleNamespace:
    return SimpleNamespace(all_functions={"entry": _FunctionStub()})


def _build_two_node_profile() -> _ProfileStub:
    root = cfg_load.CalltreeCallsite("entry", "a.c", 0, 1, None)
    child = cfg_load.CalltreeCallsite("leaf", "a.c", 1, 10, root)
    root.children = [child]
    profile = _ProfileStub(
        identifier="fuzzer",
        target_lang="c-cpp",
        fuzzer_callsite_calltree=root,
        coverage=_CoverageStub(),
        branch_blockers=[],
    )
    profile.dst_to_fd_cache = {
        "entry": SimpleNamespace(
            function_source_file="a.c",
            function_linenumber=1,
            function_name="entry",
        ),
        "leaf": SimpleNamespace(
            function_source_file="a.c",
            function_linenumber=10,
            function_name="leaf",
        ),
    }
    return profile


def test_overlay_default_python_path_does_not_call_native_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FI_OVERLAY_BACKEND", raising=False)
    native_loader_calls = []
    python_overlay_calls = []

    def _fake_run_overlay_backend(**_kwargs):
        native_loader_calls.append(1)
        return backend_loaders.OverlayBackendResult(
            selected_backend=backend_loaders.BACKEND_NATIVE,
            strict_mode=False,
        )

    def _fake_python_overlay(*_args, **_kwargs):
        python_overlay_calls.append(1)

    monkeypatch.setattr(
        backend_loaders, "run_overlay_backend", _fake_run_overlay_backend
    )
    monkeypatch.setattr(
        analysis, "_overlay_calltree_with_coverage_python", _fake_python_overlay
    )

    analysis.overlay_calltree_with_coverage(
        _dummy_profile(),
        _dummy_project(),
        "",
        "",
        "",
    )

    assert native_loader_calls == []
    assert python_overlay_calls == [1]


def test_overlay_native_non_strict_failure_falls_back_to_python_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_OVERLAY_BACKEND", "native")
    monkeypatch.setenv("FI_OVERLAY_STRICT", "0")
    python_overlay_calls = []

    monkeypatch.setattr(
        backend_loaders,
        "run_overlay_backend",
        lambda **_kwargs: backend_loaders.OverlayBackendResult(
            selected_backend=backend_loaders.BACKEND_PYTHON,
            strict_mode=False,
            reason_code=backend_loaders.FI_OVERLAY_SCHEMA_ERROR,
        ),
    )
    monkeypatch.setattr(
        analysis,
        "_overlay_calltree_with_coverage_python",
        lambda *_args, **_kwargs: python_overlay_calls.append(1),
    )

    analysis.overlay_calltree_with_coverage(
        _dummy_profile(),
        _dummy_project(),
        "",
        "",
        "",
    )

    assert python_overlay_calls == [1]


def test_overlay_native_strict_failure_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_OVERLAY_BACKEND", "native")
    monkeypatch.setenv("FI_OVERLAY_STRICT", "1")
    python_overlay_calls = []

    def _raise_strict_failure(**_kwargs):
        raise backend_loaders.CorrelatorBackendError(
            backend_loaders.FI_OVERLAY_SCHEMA_ERROR,
            "Overlay response missing required metadata keys",
            {"missing_keys": ["status"]},
        )

    monkeypatch.setattr(backend_loaders, "run_overlay_backend", _raise_strict_failure)
    monkeypatch.setattr(
        analysis,
        "_overlay_calltree_with_coverage_python",
        lambda *_args, **_kwargs: python_overlay_calls.append(1),
    )

    with pytest.raises(backend_loaders.CorrelatorBackendError):
        analysis.overlay_calltree_with_coverage(
            _dummy_profile(),
            _dummy_project(),
            "",
            "",
            "",
        )

    assert python_overlay_calls == []


def test_overlay_unsupported_language_skips_native_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _dummy_profile()
    profile.target_lang = "python"
    project = _dummy_project()
    native_loader_calls = []
    python_overlay_calls = []

    monkeypatch.setattr(backend_loaders, "parse_overlay_backend_env", lambda: "native")
    monkeypatch.setattr(backend_loaders, "parse_overlay_strict_mode", lambda: False)
    monkeypatch.setattr(backend_loaders, "parse_overlay_shadow_mode", lambda: False)
    monkeypatch.setattr(
        backend_loaders,
        "run_overlay_backend",
        lambda **_kwargs: native_loader_calls.append(1),
    )
    monkeypatch.setattr(
        analysis,
        "_overlay_calltree_with_coverage_python",
        lambda *_args, **_kwargs: python_overlay_calls.append(1),
    )

    analysis.overlay_calltree_with_coverage(profile, project, "", "", "")

    assert native_loader_calls == []
    assert python_overlay_calls == [1]


def test_overlay_go_backend_forces_python_authoritative_shadow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    caplog,
) -> None:
    profile = _dummy_profile()
    project = _dummy_project()
    python_overlay_calls = []
    native_loader_calls = []

    overlay_nodes = tmp_path / "overlay_nodes.json"
    overlay_nodes.write_text(
        json.dumps(
            [
                {
                    "cov_ct_idx": 0,
                    "cov_hitcount": 0,
                    "cov_color": "red",
                    "cov_link": "native-link",
                    "cov_callsite_link": "native-callsite",
                    "cov_forward_reds": 0,
                    "cov_largest_blocked_func": "native-only",
                }
            ]
        ),
        encoding="utf-8",
    )
    branch_complexities = tmp_path / "branch_complexities.json"
    branch_complexities.write_text("[]", encoding="utf-8")
    branch_blockers = tmp_path / "branch_blockers.json"
    branch_blockers.write_text("[]", encoding="utf-8")

    def _python_overlay(profile_arg, *_args, **_kwargs):
        python_overlay_calls.append(1)
        root = cfg_load.extract_all_callsites(profile_arg.fuzzer_callsite_calltree)[0]
        root.cov_ct_idx = 0
        root.cov_hitcount = 77
        root.cov_color = "green"

    script_path = tmp_path / "overlay_success.py"
    script_path.write_text(
        "\n".join(
            [
                "import json",
                "import sys",
                "json.load(sys.stdin)",
                "print(json.dumps({",
                "  'schema_version': 1,",
                "  'status': 'success',",
                "  'counters': {},",
                "  'timings': {},",
                "  'artifacts': {",
                f"    'overlay_nodes': {repr(str(overlay_nodes))},",
                f"    'branch_complexities': {repr(str(branch_complexities))},",
                f"    'branch_blockers': {repr(str(branch_blockers))},",
                "  },",
                "}))",
            ]
        ),
        encoding="utf-8",
    )
    cmd = " ".join([shlex.quote(sys.executable), shlex.quote(str(script_path))])
    monkeypatch.setenv("FI_OVERLAY_BACKEND", "go")
    monkeypatch.setenv("FI_OVERLAY_GO_BIN", cmd)
    monkeypatch.setenv("FI_OVERLAY_STRICT", "0")
    monkeypatch.delenv("FI_OVERLAY_SHADOW", raising=False)
    monkeypatch.setattr(
        analysis, "_overlay_calltree_with_coverage_python", _python_overlay
    )
    original_run_overlay_backend = backend_loaders.run_overlay_backend

    def _counting_run_overlay_backend(*args, **kwargs):
        native_loader_calls.append(1)
        return original_run_overlay_backend(*args, **kwargs)

    monkeypatch.setattr(
        backend_loaders,
        "run_overlay_backend",
        _counting_run_overlay_backend,
    )

    with caplog.at_level("WARNING"):
        analysis.overlay_calltree_with_coverage(profile, project, "", "", str(tmp_path))

    root = cfg_load.extract_all_callsites(profile.fuzzer_callsite_calltree)[0]
    assert native_loader_calls == [1]
    assert python_overlay_calls == [1]
    assert root.cov_hitcount == 77
    assert any("probe/shadow-only mode" in record.message for record in caplog.records)


def test_overlay_native_authoritative_applies_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    profile = _dummy_profile()
    project = _dummy_project()
    python_overlay_calls = []
    written_payload = {}

    overlay_nodes = tmp_path / "overlay_nodes.json"
    overlay_nodes.write_text(
        json.dumps(
            [
                {
                    "cov_ct_idx": 0,
                    "cov_hitcount": 33,
                    "cov_color": "green",
                    "cov_link": "link-a",
                    "cov_callsite_link": "link-b",
                    "cov_forward_reds": 2,
                    "cov_largest_blocked_func": "blocked_func",
                }
            ]
        ),
        encoding="utf-8",
    )
    branch_complexities = tmp_path / "branch_complexities.json"
    branch_complexities.write_text(
        json.dumps(
            [
                {
                    "function_name": "entry",
                    "branch": "a.c:10,1",
                    "side_idx": 0,
                    "reachable_complexity": 7,
                    "not_covered_complexity": 2,
                    "unique_reachable_complexity": 6,
                    "unique_not_covered_complexity": 1,
                }
            ]
        ),
        encoding="utf-8",
    )
    branch_blockers = tmp_path / "branch_blockers.json"
    branch_blockers.write_text(
        json.dumps(
            [
                {
                    "blocked_side": "0",
                    "blocked_unique_not_covered_complexity": 1,
                    "blocked_unique_reachable_complexity": 2,
                    "blocked_unique_functions": ["f1"],
                    "blocked_not_covered_complexity": 3,
                    "blocked_reachable_complexity": 4,
                    "sides_hitcount_diff": 5,
                    "source_file": "a.c",
                    "branch_line_number": "10",
                    "blocked_side_line_numder": "11",
                    "function_name": "entry",
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(backend_loaders, "parse_overlay_backend_env", lambda: "native")
    monkeypatch.setattr(backend_loaders, "parse_overlay_strict_mode", lambda: False)
    monkeypatch.setattr(backend_loaders, "parse_overlay_shadow_mode", lambda: False)
    monkeypatch.setattr(
        backend_loaders,
        "run_overlay_backend",
        lambda **_kwargs: backend_loaders.OverlayBackendResult(
            selected_backend="native",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {},
                "timings": {},
                "artifacts": {
                    "overlay_nodes": str(overlay_nodes),
                    "branch_complexities": str(branch_complexities),
                    "branch_blockers": str(branch_blockers),
                },
            },
        ),
    )
    monkeypatch.setattr(
        analysis,
        "_overlay_calltree_with_coverage_python",
        lambda *_args, **_kwargs: python_overlay_calls.append(1),
    )
    monkeypatch.setattr(
        analysis.json_report,
        "add_branch_blocker_key_value_to_report",
        lambda profile_identifier, key, branch_blockers_list, out_dir: (
            written_payload.update(
                {
                    "profile_identifier": profile_identifier,
                    "key": key,
                    "branch_blockers_list": branch_blockers_list,
                    "out_dir": out_dir,
                }
            )
        ),
    )

    analysis.overlay_calltree_with_coverage(profile, project, "", "", str(tmp_path))

    assert python_overlay_calls == []
    root = cfg_load.extract_all_callsites(profile.fuzzer_callsite_calltree)[0]
    assert root.cov_hitcount == 33
    assert root.cov_forward_reds == 2
    side = project.all_functions["entry"].branch_profiles["a.c:10,1"].sides[0]
    assert side.reachable_complexity == 7
    assert side.not_covered_complexity == 2
    assert len(profile.branch_blockers) == 1
    assert written_payload["profile_identifier"] == "fuzzer"
    assert written_payload["key"] == "branch_blockers"
    assert "blocked_side_line_numder" in written_payload["branch_blockers_list"][0]


def test_overlay_non_strict_unsafe_artifact_path_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    profile = _dummy_profile()
    project = _dummy_project()
    python_overlay_calls = []

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    unsafe_overlay = tmp_path / "../overlay_nodes.json"
    unsafe_overlay.write_text("[]", encoding="utf-8")
    branch_complexities = out_dir / "branch_complexities.json"
    branch_complexities.write_text("[]", encoding="utf-8")
    branch_blockers = out_dir / "branch_blockers.json"
    branch_blockers.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(backend_loaders, "parse_overlay_backend_env", lambda: "native")
    monkeypatch.setattr(backend_loaders, "parse_overlay_strict_mode", lambda: False)
    monkeypatch.setattr(backend_loaders, "parse_overlay_shadow_mode", lambda: False)
    monkeypatch.setattr(
        backend_loaders,
        "run_overlay_backend",
        lambda **_kwargs: backend_loaders.OverlayBackendResult(
            selected_backend="native",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {},
                "timings": {},
                "artifacts": {
                    "overlay_nodes": str(unsafe_overlay),
                    "branch_complexities": str(branch_complexities),
                    "branch_blockers": str(branch_blockers),
                },
            },
        ),
    )
    monkeypatch.setattr(
        analysis,
        "_overlay_calltree_with_coverage_python",
        lambda *_args, **_kwargs: python_overlay_calls.append(1),
    )

    analysis.overlay_calltree_with_coverage(profile, project, "", "", str(out_dir))

    assert python_overlay_calls == [1]


def test_overlay_strict_unsafe_artifact_path_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    profile = _dummy_profile()
    project = _dummy_project()

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    unsafe_overlay = tmp_path / "../overlay_nodes.json"
    unsafe_overlay.write_text("[]", encoding="utf-8")
    branch_complexities = out_dir / "branch_complexities.json"
    branch_complexities.write_text("[]", encoding="utf-8")
    branch_blockers = out_dir / "branch_blockers.json"
    branch_blockers.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(backend_loaders, "parse_overlay_backend_env", lambda: "native")
    monkeypatch.setattr(backend_loaders, "parse_overlay_strict_mode", lambda: True)
    monkeypatch.setattr(backend_loaders, "parse_overlay_shadow_mode", lambda: False)
    monkeypatch.setattr(
        backend_loaders,
        "run_overlay_backend",
        lambda **_kwargs: backend_loaders.OverlayBackendResult(
            selected_backend="native",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {},
                "timings": {},
                "artifacts": {
                    "overlay_nodes": str(unsafe_overlay),
                    "branch_complexities": str(branch_complexities),
                    "branch_blockers": str(branch_blockers),
                },
            },
        ),
    )

    with pytest.raises(backend_loaders.CorrelatorBackendError) as exc_info:
        analysis.overlay_calltree_with_coverage(profile, project, "", "", str(out_dir))

    assert exc_info.value.reason_code == backend_loaders.FI_OVERLAY_SCHEMA_ERROR


def test_overlay_shadow_mode_keeps_python_authoritative(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    caplog,
) -> None:
    profile = _dummy_profile()
    project = _dummy_project()
    python_overlay_calls = []

    overlay_nodes = tmp_path / "overlay_nodes.json"
    overlay_nodes.write_text(
        json.dumps(
            [
                {
                    "cov_ct_idx": 0,
                    "cov_hitcount": 0,
                    "cov_color": "red",
                    "cov_link": "native-link",
                    "cov_callsite_link": "native-callsite",
                    "cov_forward_reds": 0,
                    "cov_largest_blocked_func": "native-only",
                }
            ]
        ),
        encoding="utf-8",
    )
    branch_complexities = tmp_path / "branch_complexities.json"
    branch_complexities.write_text("[]", encoding="utf-8")
    branch_blockers = tmp_path / "branch_blockers.json"
    branch_blockers.write_text("[]", encoding="utf-8")

    def _python_overlay(profile_arg, project_arg, *_args, **_kwargs):
        python_overlay_calls.append(1)
        root = cfg_load.extract_all_callsites(profile_arg.fuzzer_callsite_calltree)[0]
        root.cov_ct_idx = 0
        root.cov_hitcount = 99
        root.cov_color = "green"
        root.cov_link = "python-link"
        root.cov_callsite_link = "python-callsite"
        root.cov_forward_reds = 1
        root.cov_largest_blocked_func = "python-only"
        side = project_arg.all_functions["entry"].branch_profiles["a.c:10,1"].sides[0]
        side.reachable_complexity = 3
        side.not_covered_complexity = 1
        side.unique_reachable_complexity = 2
        side.unique_not_covered_complexity = 1
        profile_arg.branch_blockers = []

    monkeypatch.setattr(backend_loaders, "parse_overlay_backend_env", lambda: "native")
    monkeypatch.setattr(backend_loaders, "parse_overlay_strict_mode", lambda: False)
    monkeypatch.setattr(backend_loaders, "parse_overlay_shadow_mode", lambda: True)
    monkeypatch.setattr(
        backend_loaders,
        "run_overlay_backend",
        lambda **_kwargs: backend_loaders.OverlayBackendResult(
            selected_backend="native",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {},
                "timings": {},
                "artifacts": {
                    "overlay_nodes": str(overlay_nodes),
                    "branch_complexities": str(branch_complexities),
                    "branch_blockers": str(branch_blockers),
                },
            },
        ),
    )
    monkeypatch.setattr(
        analysis, "_overlay_calltree_with_coverage_python", _python_overlay
    )

    with caplog.at_level("WARNING"):
        analysis.overlay_calltree_with_coverage(profile, project, "", "", str(tmp_path))

    root = cfg_load.extract_all_callsites(profile.fuzzer_callsite_calltree)[0]
    assert python_overlay_calls == [1]
    assert root.cov_hitcount == 99
    assert any(
        backend_loaders.FI_OVERLAY_PARITY_MISMATCH in record.message
        for record in caplog.records
    )


def test_overlay_shadow_mode_strict_raises_on_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    profile = _dummy_profile()
    project = _dummy_project()

    overlay_nodes = tmp_path / "overlay_nodes.json"
    overlay_nodes.write_text(
        json.dumps(
            [
                {
                    "cov_ct_idx": 0,
                    "cov_hitcount": 0,
                    "cov_color": "red",
                    "cov_link": "native-link",
                    "cov_callsite_link": "native-callsite",
                    "cov_forward_reds": 0,
                    "cov_largest_blocked_func": "native-only",
                }
            ]
        ),
        encoding="utf-8",
    )
    branch_complexities = tmp_path / "branch_complexities.json"
    branch_complexities.write_text("[]", encoding="utf-8")
    branch_blockers = tmp_path / "branch_blockers.json"
    branch_blockers.write_text("[]", encoding="utf-8")

    def _python_overlay(profile_arg, *_args, **_kwargs):
        root = cfg_load.extract_all_callsites(profile_arg.fuzzer_callsite_calltree)[0]
        root.cov_ct_idx = 0
        root.cov_hitcount = 42
        root.cov_color = "yellow"

    monkeypatch.setattr(backend_loaders, "parse_overlay_backend_env", lambda: "native")
    monkeypatch.setattr(backend_loaders, "parse_overlay_strict_mode", lambda: True)
    monkeypatch.setattr(backend_loaders, "parse_overlay_shadow_mode", lambda: True)
    monkeypatch.setattr(
        backend_loaders,
        "run_overlay_backend",
        lambda **_kwargs: backend_loaders.OverlayBackendResult(
            selected_backend="native",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {},
                "timings": {},
                "artifacts": {
                    "overlay_nodes": str(overlay_nodes),
                    "branch_complexities": str(branch_complexities),
                    "branch_blockers": str(branch_blockers),
                },
            },
        ),
    )
    monkeypatch.setattr(
        analysis, "_overlay_calltree_with_coverage_python", _python_overlay
    )

    with pytest.raises(backend_loaders.CorrelatorBackendError) as exc_info:
        analysis.overlay_calltree_with_coverage(profile, project, "", "", str(tmp_path))

    assert exc_info.value.reason_code == backend_loaders.FI_OVERLAY_PARITY_MISMATCH


def test_overlay_parity_normalization_is_order_stable() -> None:
    native_outputs = {
        "overlay_nodes": analysis._normalize_overlay_nodes(
            [
                {
                    "cov_ct_idx": 2,
                    "cov_hitcount": 0,
                    "cov_color": "red",
                    "cov_link": "b",
                    "cov_callsite_link": "b",
                    "cov_forward_reds": 0,
                    "cov_largest_blocked_func": "",
                },
                {
                    "cov_ct_idx": 1,
                    "cov_hitcount": 1,
                    "cov_color": "green",
                    "cov_link": "a",
                    "cov_callsite_link": "a",
                    "cov_forward_reds": 1,
                    "cov_largest_blocked_func": "x",
                },
            ]
        ),
        "branch_complexities": analysis._normalize_branch_complexities([]),
        "branch_blockers": analysis._normalize_branch_blockers([]),
    }
    python_outputs = {
        "overlay_nodes": analysis._normalize_overlay_nodes(
            [
                {
                    "cov_ct_idx": 1,
                    "cov_hitcount": 1,
                    "cov_color": "green",
                    "cov_link": "a",
                    "cov_callsite_link": "a",
                    "cov_forward_reds": 1,
                    "cov_largest_blocked_func": "x",
                },
                {
                    "cov_ct_idx": 2,
                    "cov_hitcount": 0,
                    "cov_color": "red",
                    "cov_link": "b",
                    "cov_callsite_link": "b",
                    "cov_forward_reds": 0,
                    "cov_largest_blocked_func": "",
                },
            ]
        ),
        "branch_complexities": analysis._normalize_branch_complexities([]),
        "branch_blockers": analysis._normalize_branch_blockers([]),
    }

    mismatch_counts = analysis._compare_overlay_outputs(native_outputs, python_outputs)

    assert sum(mismatch_counts.values()) == 0


def test_overlay_native_payload_includes_python_link_fields() -> None:
    profile = _build_two_node_profile()
    project = _dummy_project()

    payload = analysis._build_overlay_native_payload(
        profile,
        project,
        "https://cov.example",
        "/tmp",
    )

    assert payload["callsites"][0]["cov_link"] == "a.c:1:entry"
    assert payload["callsites"][0]["cov_callsite_link"] == "#"
    assert payload["callsites"][1]["cov_link"] == "a.c:10:leaf"
    assert payload["callsites"][1]["cov_callsite_link"] == "a.c:10:entry"


def test_overlay_parity_detects_forward_red_and_sentinel_drift() -> None:
    native_outputs = {
        "overlay_nodes": analysis._normalize_overlay_nodes(
            [
                {
                    "cov_ct_idx": 0,
                    "cov_hitcount": 200,
                    "cov_color": "lawngreen",
                    "cov_link": "a",
                    "cov_callsite_link": "#",
                    "cov_forward_reds": 0,
                    "cov_largest_blocked_func": "",
                }
            ]
        ),
        "branch_complexities": analysis._normalize_branch_complexities([]),
        "branch_blockers": analysis._normalize_branch_blockers([]),
    }
    python_outputs = {
        "overlay_nodes": analysis._normalize_overlay_nodes(
            [
                {
                    "cov_ct_idx": 0,
                    "cov_hitcount": 200,
                    "cov_color": "lawngreen",
                    "cov_link": "a",
                    "cov_callsite_link": "#",
                    "cov_forward_reds": 0,
                    "cov_largest_blocked_func": "none",
                }
            ]
        ),
        "branch_complexities": analysis._normalize_branch_complexities([]),
        "branch_blockers": analysis._normalize_branch_blockers([]),
    }

    mismatch_counts = analysis._compare_overlay_outputs(native_outputs, python_outputs)

    assert mismatch_counts["overlay_nodes_values"] == 1
