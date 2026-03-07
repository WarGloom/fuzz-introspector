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
"""Tests for profile accumulation orchestration."""

import json
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import analysis  # noqa: E402
from fuzz_introspector.datatypes import fuzzer_profile, project_profile  # noqa: E402
from fuzz_introspector.exceptions import DataLoaderError  # noqa: E402


class _FutureStub:

    def __init__(self, result=None, exc=None):
        self._result = result
        self._exc = exc

    def result(self):
        if self._exc is not None:
            raise self._exc
        return self._result


class _ExecutorStub:

    def __init__(self, *_args, **_kwargs):
        self.futures = []

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        return False

    def submit(self, fn, *args):
        try:
            result = fn(*args)
            future = _FutureStub(result=result)
        except Exception as err:  # pragma: no cover - exercised indirectly
            future = _FutureStub(exc=err)
        self.futures.append(future)
        return future


class _ProfileStub:

    def __init__(self, key: str, should_fail: bool = False):
        self._key = key
        self._should_fail = should_fail
        self.accumulated_with = ""
        self.total_basic_blocks = 0

    def get_key(self):
        return self._key

    def to_worker_payload(self):
        return {
            "fuzzer_source_file": self._key,
            "target_lang": "c-cpp",
            "file_targets": {},
            "all_class_functions": {},
            "all_class_constructors": {},
            "branch_blockers": [],
            "functions_reached_by_fuzzer": [],
            "functions_reached_by_fuzzer_runtime": [],
            "functions_unreached_by_fuzzer": [],
            "exclude_patterns": [],
            "exclude_function_patterns": [],
            "total_basic_blocks": self.total_basic_blocks,
            "total_cyclomatic_complexity": 0,
        }

    def accummulate_profile(self,
                            base_folder,
                            _return_dict,
                            _uniq_id,
                            _semaphore,
                            skip_propagation=False):
        if self._should_fail:
            raise ValueError("boom")
        self.accumulated_with = base_folder
        self.total_basic_blocks = 1


def test_parse_profile_worker_count_default_is_capped(monkeypatch):
    monkeypatch.delenv(analysis.FI_PROFILE_WORKERS_ENV, raising=False)
    monkeypatch.delenv(analysis.FI_REACHABILITY_BACKEND_ENV, raising=False)
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 24)
    assert analysis._parse_profile_worker_count() == 24


def test_parse_profile_worker_count_rust_backend_default_is_three(monkeypatch):
    monkeypatch.delenv(analysis.FI_PROFILE_WORKERS_ENV, raising=False)
    monkeypatch.setenv(analysis.FI_REACHABILITY_BACKEND_ENV, "rust")
    monkeypatch.delenv("FI_NATIVE_BACKENDS", raising=False)
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 24)

    assert analysis._parse_profile_worker_count() == 3


def test_parse_profile_worker_count_rust_backend_default_from_global_env(
        monkeypatch):
    monkeypatch.delenv(analysis.FI_PROFILE_WORKERS_ENV, raising=False)
    monkeypatch.delenv(analysis.FI_REACHABILITY_BACKEND_ENV, raising=False)
    monkeypatch.setenv("FI_NATIVE_BACKENDS", "rust")
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 24)

    assert analysis._parse_profile_worker_count() == 3


def test_parse_profile_worker_count_rust_backend_env_override_respected(
        monkeypatch):
    monkeypatch.setenv(analysis.FI_PROFILE_WORKERS_ENV, "12")
    monkeypatch.setenv(analysis.FI_REACHABILITY_BACKEND_ENV, "rust")
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 24)

    assert analysis._parse_profile_worker_count() == 12


def test_parse_profile_worker_count_env_override_respected(monkeypatch):
    monkeypatch.setenv(analysis.FI_PROFILE_WORKERS_ENV, "4")
    monkeypatch.delenv(analysis.FI_REACHABILITY_BACKEND_ENV, raising=False)
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 24)
    assert analysis._parse_profile_worker_count() == 4

    monkeypatch.setenv(analysis.FI_PROFILE_WORKERS_ENV, "99")
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 6)
    assert analysis._parse_profile_worker_count() == 6


def test_accummulate_profiles_parallel_preserves_input_order(monkeypatch):

    def fake_accummulate_single_profile(profile_index,
                                        profile_payload,
                                        base_folder,
                                        skip_propagation=False):
        profile_payload["total_basic_blocks"] = 1
        profile_payload["introspector_data_file"] = base_folder
        return profile_index, profile_payload

    monkeypatch.setattr(analysis.concurrent.futures, "ProcessPoolExecutor",
                        _ExecutorStub)
    monkeypatch.setattr(analysis.concurrent.futures, "as_completed",
                        lambda futures: list(futures)[::-1])
    monkeypatch.setattr(analysis, "_accummulate_single_profile",
                        fake_accummulate_single_profile)
    monkeypatch.setattr(analysis, "_resolve_profile_worker_count", lambda:
                        (3, False))
    monkeypatch.setattr(fuzzer_profile, "propagate_reachability_native_batch",
                        lambda profiles: False)

    profiles = [
        _ProfileStub("first"),
        _ProfileStub("second"),
        _ProfileStub("third")
    ]
    result_profiles = analysis._accummulate_profiles(profiles,
                                                     "/tmp/base",
                                                     parallelise=True)

    assert [p.get_key()
            for p in result_profiles] == ["first", "second", "third"]
    assert all(p.total_basic_blocks == 1 for p in result_profiles)


def test_accummulate_profiles_parallel_raises_contextual_error(monkeypatch):

    def fake_accummulate_single_profile(profile_index,
                                        profile_payload,
                                        _base_folder,
                                        skip_propagation=False):
        if profile_payload.get("fuzzer_source_file") == "broken":
            raise ValueError("boom")
        return profile_index, profile_payload

    monkeypatch.setattr(analysis.concurrent.futures, "ProcessPoolExecutor",
                        _ExecutorStub)
    monkeypatch.setattr(analysis.concurrent.futures, "as_completed",
                        lambda futures: list(futures))
    monkeypatch.setattr(analysis, "_accummulate_single_profile",
                        fake_accummulate_single_profile)
    monkeypatch.setattr(analysis, "_resolve_profile_worker_count", lambda:
                        (2, False))
    monkeypatch.setattr(fuzzer_profile, "propagate_reachability_native_batch",
                        lambda profiles: False)

    profiles = [_ProfileStub("ok"), _ProfileStub("broken", should_fail=True)]

    with pytest.raises(DataLoaderError, match="broken at index 1"):
        analysis._accummulate_profiles(profiles, "/tmp/base", parallelise=True)


def test_profile_accumulation_parallel_serial_parity(monkeypatch):

    def fake_accummulate_single_profile(profile_index,
                                        profile_payload,
                                        _base_folder,
                                        skip_propagation=False):
        profile_payload["total_basic_blocks"] = 1
        return profile_index, profile_payload

    monkeypatch.setattr(analysis.concurrent.futures, "ProcessPoolExecutor",
                        _ExecutorStub)
    monkeypatch.setattr(analysis.concurrent.futures, "as_completed",
                        lambda futures: list(futures))
    monkeypatch.setattr(analysis, "_accummulate_single_profile",
                        fake_accummulate_single_profile)
    monkeypatch.setattr(analysis, "_resolve_profile_worker_count", lambda:
                        (3, False))
    monkeypatch.setattr(fuzzer_profile, "propagate_reachability_native_batch",
                        lambda profiles: False)

    serial_profiles = [_ProfileStub("first"), _ProfileStub("second")]
    parallel_profiles = [_ProfileStub("first"), _ProfileStub("second")]

    serial_result = analysis._accummulate_profiles(serial_profiles,
                                                   "/tmp/base",
                                                   parallelise=False)
    parallel_result = analysis._accummulate_profiles(parallel_profiles,
                                                     "/tmp/base",
                                                     parallelise=True)

    assert [(p.get_key(), p.total_basic_blocks) for p in serial_result
            ] == [(p.get_key(), p.total_basic_blocks) for p in parallel_result]


def test_target_lang_property_is_cached():

    class _ProfileWithCountingTarget:

        def __init__(self, target_lang: str):
            self._target_lang = target_lang
            self.read_count = 0

        @property
        def target_lang(self):
            self.read_count += 1
            return self._target_lang

    profile = _ProfileWithCountingTarget("c-cpp")
    merged_profile = project_profile.MergedProjectProfile.__new__(
        project_profile.MergedProjectProfile)
    merged_profile.profiles = [profile]
    merged_profile.language = "c-cpp"
    merged_profile._target_lang_cache = None

    assert merged_profile.target_lang == "c-cpp"
    assert merged_profile.target_lang == "c-cpp"
    assert profile.read_count == 1


def test_get_all_functions_with_source_returns_cached_mapping():
    merged_profile = project_profile.MergedProjectProfile.__new__(
        project_profile.MergedProjectProfile)
    merged_profile._all_functions_with_source_cache = None
    merged_profile.all_functions = {
        "keep":
        SimpleNamespace(has_source_file=True, function_linenumber="10"),
        "drop-nosrc":
        SimpleNamespace(has_source_file=False, function_linenumber="20"),
        "drop-noline":
        SimpleNamespace(has_source_file=True, function_linenumber="-1"),
    }

    first_mapping = merged_profile.get_all_functions_with_source()
    second_mapping = merged_profile.get_all_functions_with_source()

    assert first_mapping is second_mapping
    assert list(first_mapping.keys()) == ["keep"]


def test_parse_bool_env_invalid_uses_default(monkeypatch, caplog):
    monkeypatch.setenv(analysis.FI_DEBUG_STAGE_RSS_ENV, "invalid")

    with caplog.at_level("WARNING"):
        parsed_value = analysis._parse_bool_env(
            analysis.FI_DEBUG_STAGE_RSS_ENV, False)

    assert not parsed_value
    assert any("FI_DEBUG_STAGE_RSS" in record.message
               for record in caplog.records)


def test_parse_stage_warn_seconds_invalid_uses_default(monkeypatch, caplog):
    monkeypatch.setenv(analysis.FI_STAGE_WARN_SECONDS_ENV, "-2")

    with caplog.at_level("WARNING"):
        warn_seconds = analysis._parse_stage_warn_seconds()

    assert warn_seconds == analysis.FI_STAGE_WARN_SECONDS_DEFAULT
    assert any("FI_STAGE_WARN_SECONDS" in record.message
               for record in caplog.records)


def test_log_debug_load_stage_includes_rss_field(monkeypatch, caplog):
    monkeypatch.setattr(analysis, "_get_stage_rss_mb", lambda: 42.25)

    with caplog.at_level("INFO"):
        analysis._log_debug_load_stage(
            "debug_types_yaml",
            1.2,
            {
                "files": 4,
                "types": 10
            },
            include_rss=True,
            perf_warn_enabled=False,
            warn_after_seconds=0,
            warn_rss_mb=0,
        )

    assert any("rss_mb=42.25" in record.message for record in caplog.records)


def test_parse_stage_warn_rss_mb_invalid_uses_default(monkeypatch, caplog):
    monkeypatch.setenv(analysis.FI_DEBUG_STAGE_WARN_RSS_MB_ENV, "-1")

    with caplog.at_level("WARNING"):
        warn_rss_mb = analysis._parse_stage_warn_rss_mb()

    assert warn_rss_mb == analysis.FI_DEBUG_STAGE_WARN_RSS_MB_DEFAULT
    assert any("FI_DEBUG_STAGE_WARN_RSS_MB" in record.message
               for record in caplog.records)


def test_log_debug_load_stage_emits_perf_warning(caplog):
    with caplog.at_level("WARNING"):
        analysis._log_debug_load_stage(
            "debug_functions_yaml",
            6.0,
            {"files": 5},
            include_rss=False,
            perf_warn_enabled=True,
            warn_after_seconds=3,
            warn_rss_mb=0,
        )

    warning_messages = [record.message for record in caplog.records]
    assert any("exceeded threshold=3s" in message
               for message in warning_messages)
    assert any("FI_DEBUG_MAX_WORKERS" in message
               for message in warning_messages)


def test_log_debug_load_stage_emits_rss_warning(caplog, monkeypatch):
    monkeypatch.setattr(analysis, "_get_stage_rss_mb", lambda: 4096.0)

    with caplog.at_level("WARNING"):
        analysis._log_debug_load_stage(
            "type_correlation",
            1.5,
            {"types": 5},
            include_rss=False,
            perf_warn_enabled=True,
            warn_after_seconds=0,
            warn_rss_mb=2048,
        )

    warning_messages = [record.message for record in caplog.records]
    assert any("rss threshold=2048MB" in message
               for message in warning_messages)
    assert any("FI_DEBUG_CORRELATE_PARALLEL" in message
               for message in warning_messages)


# ---------------------------------------------------------------------------
# Tests for propagate_reachability_native_batch
# ---------------------------------------------------------------------------


class _FunctionProfileStub:
    """Minimal stand-in for function_profile.FunctionProfile."""

    def __init__(self, name: str, direct_callees: list):
        self.function_name = name
        self.functions_reached = list(direct_callees)
        self.function_depth = 0


class _FuzzerProfileStub:
    """Minimal stand-in for FuzzerProfile used in batch reachability tests."""

    def __init__(self,
                 profile_id: str,
                 functions: dict,
                 profile_key: str | None = None):
        self._identifier = profile_id
        self._profile_key = profile_key or profile_id
        # functions: {name: [direct_callee, ...]}
        self.all_class_functions = {
            name: _FunctionProfileStub(name, callees)
            for name, callees in functions.items()
        }

    @property
    def identifier(self):
        return self._identifier

    def get_key(self):
        return self._profile_key


class _FilterFunctionStub:
    """Minimal function entry for native filter tests."""

    def __init__(self, name: str, source_file: str = "/src/file.cc"):
        self.function_source_file = source_file
        self.function_name = name
        self.raw_function_name = name


class _FilterProfileStub:
    """Minimal profile entry for native filter tests."""

    def __init__(self, identifier: str, profile_key: str, function_name: str):
        self._identifier = identifier
        self._profile_key = profile_key
        self.fuzzer_source_file = f"/{profile_key}.cc"
        self.all_class_functions = {
            function_name: _FilterFunctionStub(function_name),
        }
        self.all_class_constructors = {}

    @property
    def identifier(self):
        return self._identifier

    def get_key(self):
        return self._profile_key


def _make_batch_success_response(profiles_data):
    """Build a JSON string mimicking a successful native binary response."""
    return json.dumps({
        "status": "success",
        "profiles": profiles_data,
    })


def test_batch_returns_false_when_env_not_set(monkeypatch):
    """propagate_reachability_native_batch returns False if env var not 'rust'."""
    monkeypatch.delenv("FI_REACHABILITY_BACKEND", raising=False)
    profiles = [_FuzzerProfileStub("p1", {"f": []})]
    assert fuzzer_profile.propagate_reachability_native_batch(
        profiles) is False


def test_batch_returns_false_when_binary_not_found(monkeypatch):
    """Returns False when the binary cannot be located."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.delenv("FI_REACHABILITY_RUST_BIN", raising=False)
    monkeypatch.setattr(fuzzer_profile, "_resolve_reachability_binary",
                        lambda *_args: "")
    profiles = [_FuzzerProfileStub("p1", {"f": []})]
    assert fuzzer_profile.propagate_reachability_native_batch(
        profiles) is False


def test_batch_uses_go_backend_binary_when_selected(monkeypatch):
    """Batch reachability honors explicit go backend selection."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "go")
    monkeypatch.setenv("FI_REACHABILITY_GO_BIN", "/fake/go-bin")

    captured = {}

    def _fake_run(args, input, **kwargs):
        captured["args"] = args
        captured["payload"] = json.loads(input)
        del kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=_make_batch_success_response([]),
            stderr="",
        )

    monkeypatch.setattr(fuzzer_profile.subprocess, "run", _fake_run)
    profiles = [_FuzzerProfileStub("p1", {"f": []})]

    assert fuzzer_profile.propagate_reachability_native_batch(profiles) is True
    assert captured["args"] == ["/fake/go-bin"]
    assert captured["payload"]["profiles"][0]["profile_id"] == "p1"


def test_batch_returns_false_on_subprocess_os_error(monkeypatch):
    """Returns False when subprocess.run raises OSError."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    def _raise(*args, **kwargs):
        raise OSError("no such file")

    monkeypatch.setattr(fuzzer_profile.subprocess, "run", _raise)
    profiles = [_FuzzerProfileStub("p1", {"f": []})]
    assert fuzzer_profile.propagate_reachability_native_batch(
        profiles) is False


def test_batch_returns_false_on_nonzero_returncode(monkeypatch):
    """Returns False when the binary exits with a non-zero return code."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    monkeypatch.setattr(
        fuzzer_profile.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr=""),
    )
    profiles = [_FuzzerProfileStub("p1", {"f": []})]
    assert fuzzer_profile.propagate_reachability_native_batch(
        profiles) is False


def test_batch_returns_false_on_invalid_json(monkeypatch):
    """Returns False when the binary produces non-JSON output."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    monkeypatch.setattr(
        fuzzer_profile.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout="NOT JSON", stderr=""),
    )
    profiles = [_FuzzerProfileStub("p1", {"f": []})]
    assert fuzzer_profile.propagate_reachability_native_batch(
        profiles) is False


def test_batch_returns_false_on_non_success_status(monkeypatch):
    """Returns False when the binary returns status != 'success'."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    response = json.dumps({
        "status": "error",
        "reason": "something went wrong"
    })
    monkeypatch.setattr(
        fuzzer_profile.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout=response, stderr=""),
    )
    profiles = [_FuzzerProfileStub("p1", {"f": []})]
    assert fuzzer_profile.propagate_reachability_native_batch(
        profiles) is False


def test_batch_applies_results_to_profiles(monkeypatch):
    """On success, functions_reached and function_depth are updated."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    response = _make_batch_success_response([{
        "profile_id":
        "fuzzer_a",
        "results": [
            {
                "name": "foo",
                "functions_reached": ["bar", "baz"],
                "function_depth": 2,
            },
            {
                "name": "bar",
                "functions_reached": ["baz"],
                "function_depth": 1,
            },
        ],
    }])
    monkeypatch.setattr(
        fuzzer_profile.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout=response, stderr=""),
    )

    p = _FuzzerProfileStub("fuzzer_a", {
        "foo": ["bar"],
        "bar": ["baz"],
        "baz": []
    })
    result = fuzzer_profile.propagate_reachability_native_batch([p])

    assert result is True
    assert set(
        p.all_class_functions["foo"].functions_reached) == {"bar", "baz"}
    assert p.all_class_functions["foo"].function_depth == 2
    assert set(p.all_class_functions["bar"].functions_reached) == {"baz"}
    assert p.all_class_functions["bar"].function_depth == 1
    foo_first = p.all_class_functions["foo"].functions_reached[0]
    assert foo_first is sys.intern(foo_first)


def test_deserialize_function_profile_interns_functions_reached():
    reached_name = "::".join(["pkg", "module", "leaf"])
    payload = {
        "function_name": "entry",
        "functions_reached": [reached_name],
        "branch_profiles": {},
    }

    restored = fuzzer_profile.FuzzerProfile._deserialize_function_profile(
        payload)

    assert restored.functions_reached == [reached_name]
    assert restored.functions_reached[0] is sys.intern(reached_name)


def test_batch_handles_multiple_profiles(monkeypatch):
    """Results for multiple profiles are applied to the correct objects."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    response = _make_batch_success_response([
        {
            "profile_id":
            "fuzz1",
            "results": [{
                "name": "a",
                "functions_reached": ["b"],
                "function_depth": 1
            }],
        },
        {
            "profile_id":
            "fuzz2",
            "results": [{
                "name": "x",
                "functions_reached": ["y"],
                "function_depth": 1
            }],
        },
    ])
    monkeypatch.setattr(
        fuzzer_profile.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout=response, stderr=""),
    )

    p1 = _FuzzerProfileStub("fuzz1", {"a": ["b"], "b": []})
    p2 = _FuzzerProfileStub("fuzz2", {"x": ["y"], "y": []})
    result = fuzzer_profile.propagate_reachability_native_batch([p1, p2])

    assert result is True
    assert p1.all_class_functions["a"].functions_reached == ["b"]
    assert p2.all_class_functions["x"].functions_reached == ["y"]


def test_batch_ignores_unknown_profile_ids(monkeypatch):
    """Unknown profile IDs in the response are silently skipped."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    response = _make_batch_success_response([{
        "profile_id":
        "ghost",  # not in the input list
        "results": [{
            "name": "f",
            "functions_reached": ["g"],
            "function_depth": 1
        }],
    }])
    monkeypatch.setattr(
        fuzzer_profile.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout=response, stderr=""),
    )

    p = _FuzzerProfileStub("real_profile", {"f": []})
    result = fuzzer_profile.propagate_reachability_native_batch([p])

    # Still returns True (batch succeeded), but our profile is untouched
    assert result is True
    assert p.all_class_functions["f"].functions_reached == []


def test_batch_sends_correct_payload(monkeypatch):
    """The payload sent to the binary contains all profiles and direct callees."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    captured = {}

    def _fake_run(args, input, **kwargs):
        captured["payload"] = json.loads(input)
        return SimpleNamespace(
            returncode=0,
            stdout=_make_batch_success_response([]),
            stderr="",
        )

    monkeypatch.setattr(fuzzer_profile.subprocess, "run", _fake_run)

    p1 = _FuzzerProfileStub("fuzz_a", {"main": ["helper"], "helper": []})
    p2 = _FuzzerProfileStub("fuzz_b", {"entry": []})
    fuzzer_profile.propagate_reachability_native_batch([p1, p2])

    payload = captured["payload"]
    assert payload["schema_version"] == 1
    profile_ids = [pr["profile_id"] for pr in payload["profiles"]]
    assert "fuzz_a" in profile_ids
    assert "fuzz_b" in profile_ids

    # Check function entries for fuzz_a
    fuzz_a_entry = next(pr for pr in payload["profiles"]
                        if pr["profile_id"] == "fuzz_a")
    func_map = {
        f["name"]: f["direct_callees"]
        for f in fuzz_a_entry["functions"]
    }
    assert func_map["main"] == ["helper"]
    assert func_map["helper"] == []


def test_batch_uses_unique_profile_keys_when_identifiers_collide(monkeypatch):
    """Native batch reachability keys profiles by get_key() instead of identifier."""
    monkeypatch.setenv("FI_REACHABILITY_BACKEND", "rust")
    monkeypatch.setenv("FI_REACHABILITY_RUST_BIN", "/fake/bin")

    captured = {}

    def _fake_run(args, input, **kwargs):
        del args, kwargs
        captured["payload"] = json.loads(input)
        response = _make_batch_success_response([
            {
                "profile_id":
                "dir-one/fuzzer",
                "results": [{
                    "name": "entry_one",
                    "functions_reached": ["shared"],
                    "function_depth": 1,
                }],
            },
            {
                "profile_id":
                "dir-two/fuzzer",
                "results": [{
                    "name": "entry_two",
                    "functions_reached": ["leaf"],
                    "function_depth": 1,
                }],
            },
        ])
        return SimpleNamespace(returncode=0, stdout=response, stderr="")

    monkeypatch.setattr(fuzzer_profile.subprocess, "run", _fake_run)

    p1 = _FuzzerProfileStub("fuzzer", {"entry_one": []},
                            profile_key="dir-one/fuzzer")
    p2 = _FuzzerProfileStub("fuzzer", {"entry_two": []},
                            profile_key="dir-two/fuzzer")

    result = fuzzer_profile.propagate_reachability_native_batch([p1, p2])

    assert result is True
    assert [pr["profile_id"] for pr in captured["payload"]["profiles"]] == [
        "dir-one/fuzzer",
        "dir-two/fuzzer",
    ]
    assert p1.all_class_functions["entry_one"].functions_reached == ["shared"]
    assert p2.all_class_functions["entry_two"].functions_reached == ["leaf"]


def test_filter_profiles_native_uses_unique_profile_keys(monkeypatch):
    """Native filter maps responses back with get_key() when identifiers collide."""
    monkeypatch.delenv(analysis.FI_FILTER_RUST_BIN_ENV, raising=False)
    monkeypatch.setattr(
        analysis.backend_loaders,
        "resolve_component_backend",
        lambda _env_name: "rust",
    )
    monkeypatch.setattr(analysis.shutil, "which", lambda _name: "/fake/bin")

    captured = {}

    def _fake_run(args, input, **kwargs):
        del args, kwargs
        captured["payload"] = json.loads(input)
        response = json.dumps({
            "status":
            "success",
            "profiles": [
                {
                    "profile_id": "dir-one/fuzzer",
                    "excluded": False,
                    "excluded_functions": ["drop-one"],
                    "excluded_constructors": [],
                },
                {
                    "profile_id": "dir-two/fuzzer",
                    "excluded": False,
                    "excluded_functions": ["drop-two"],
                    "excluded_constructors": [],
                },
            ],
        })
        return SimpleNamespace(returncode=0, stdout=response, stderr="")

    monkeypatch.setattr(analysis.subprocess, "run", _fake_run)

    p1 = _FilterProfileStub("fuzzer", "dir-one/fuzzer", "drop-one")
    p2 = _FilterProfileStub("fuzzer", "dir-two/fuzzer", "drop-two")

    filtered = analysis._filter_profiles_native([p1, p2], [], [])

    assert filtered == [p1, p2]
    assert [pr["profile_id"] for pr in captured["payload"]["profiles"]] == [
        "dir-one/fuzzer",
        "dir-two/fuzzer",
    ]
    assert p1.all_class_functions == {}
    assert p2.all_class_functions == {}


def test_filter_profiles_native_uses_go_backend_binary(monkeypatch):
    """Native filter honors explicit go backend selection."""
    monkeypatch.delenv(analysis.FI_FILTER_RUST_BIN_ENV, raising=False)
    monkeypatch.setenv(analysis.FI_FILTER_GO_BIN_ENV, "/fake/go-bin")
    monkeypatch.setattr(
        analysis.backend_loaders,
        "resolve_component_backend",
        lambda _env_name: "go",
    )

    captured = {}

    def _fake_run(args, input, **kwargs):
        captured["args"] = args
        captured["payload"] = json.loads(input)
        del kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "status":
                "success",
                "profiles": [{
                    "profile_id": "dir-one/fuzzer",
                    "excluded": False,
                    "excluded_functions": [],
                    "excluded_constructors": [],
                }],
            }),
            stderr="",
        )

    monkeypatch.setattr(analysis.subprocess, "run", _fake_run)

    p1 = _FilterProfileStub("fuzzer", "dir-one/fuzzer", "drop-one")

    filtered = analysis._filter_profiles_native([p1], [], [])

    assert filtered == [p1]
    assert captured["args"] == ["/fake/go-bin"]
    assert captured["payload"]["profiles"][0]["profile_id"] == "dir-one/fuzzer"


def test_fuzzer_profile_get_key_prefers_stable_full_path():
    """get_key returns the full executable path to avoid basename collisions."""
    profile = fuzzer_profile.FuzzerProfile.__new__(
        fuzzer_profile.FuzzerProfile)
    profile.binary_executable = "/tmp/out/../build/fuzzer"
    profile.fuzzer_source_file = "/src/fuzzer.cc"

    assert profile.get_key() == os.path.normpath("/tmp/out/../build/fuzzer")


# ---------------------------------------------------------------------------
# Tests for skip_propagation flag in _accummulate_profiles
# ---------------------------------------------------------------------------


def test_accummulate_profiles_calls_batch_and_passes_flag(monkeypatch):
    """_accummulate_profiles calls the batch function and passes native_done flag."""
    batch_calls = []

    def fake_batch(profiles):
        batch_calls.append(len(profiles))
        return True  # simulate native success

    monkeypatch.setattr(fuzzer_profile, "propagate_reachability_native_batch",
                        fake_batch)

    accumulated = []

    class _TrackingStub(_ProfileStub):

        def accummulate_profile(self,
                                base_folder,
                                _rd,
                                _uid,
                                _sem,
                                skip_propagation=False):
            accumulated.append(skip_propagation)
            self.accumulated_with = base_folder

    profiles = [_TrackingStub("p1"), _TrackingStub("p2")]
    analysis._accummulate_profiles(profiles, "/tmp/base", parallelise=False)

    assert batch_calls == [2]  # called once for all 2 profiles
    assert all(flag is True for flag in accumulated)  # flag forwarded


def test_accummulate_profiles_passes_false_flag_when_batch_fails(monkeypatch):
    """When batch returns False, skip_propagation=False is forwarded to each profile."""
    monkeypatch.setattr(fuzzer_profile, "propagate_reachability_native_batch",
                        lambda profiles: False)

    accumulated = []

    class _TrackingStub(_ProfileStub):

        def accummulate_profile(self,
                                base_folder,
                                _rd,
                                _uid,
                                _sem,
                                skip_propagation=False):
            accumulated.append(skip_propagation)
            self.accumulated_with = base_folder

    profiles = [_TrackingStub("p1"), _TrackingStub("p2")]
    analysis._accummulate_profiles(profiles, "/tmp/base", parallelise=False)

    assert all(flag is False for flag in accumulated)


def test_accummulate_profiles_skips_batch_in_parallel_multi_worker(
        monkeypatch):
    """Parallel multi-worker mode bypasses batch pre-pass and keeps worker propagation."""
    batch_calls = []

    def fake_batch(_profiles):
        batch_calls.append(True)
        return True

    worker_skip_flags = []

    def fake_accummulate_single_profile(profile_index,
                                        profile_payload,
                                        _base_folder,
                                        skip_propagation=False):
        worker_skip_flags.append(skip_propagation)
        return profile_index, profile_payload

    monkeypatch.setattr(fuzzer_profile, "propagate_reachability_native_batch",
                        fake_batch)
    monkeypatch.setattr(analysis, "_resolve_profile_worker_count", lambda:
                        (2, False))
    monkeypatch.setattr(analysis.concurrent.futures, "ProcessPoolExecutor",
                        _ExecutorStub)
    monkeypatch.setattr(analysis.concurrent.futures, "as_completed",
                        lambda futures: list(futures))
    monkeypatch.setattr(analysis, "_accummulate_single_profile",
                        fake_accummulate_single_profile)

    profiles = [_ProfileStub("p1"), _ProfileStub("p2")]
    analysis._accummulate_profiles(profiles, "/tmp/base", parallelise=True)

    assert batch_calls == []
    assert worker_skip_flags == [False, False]


def test_accummulate_profiles_keeps_batch_for_parallel_single_worker(
        monkeypatch):
    """Parallel single-worker fallback keeps pre-pass and forwards skip_propagation."""
    batch_calls = []

    def fake_batch(profiles):
        batch_calls.append(len(profiles))
        return True

    monkeypatch.setattr(fuzzer_profile, "propagate_reachability_native_batch",
                        fake_batch)
    monkeypatch.setattr(analysis, "_resolve_profile_worker_count", lambda:
                        (1, False))

    accumulated = []

    class _TrackingStub(_ProfileStub):

        def accummulate_profile(self,
                                base_folder,
                                _rd,
                                _uid,
                                _sem,
                                skip_propagation=False):
            accumulated.append(skip_propagation)
            self.accumulated_with = base_folder

    profiles = [_TrackingStub("p1"), _TrackingStub("p2")]
    analysis._accummulate_profiles(profiles, "/tmp/base", parallelise=True)

    assert batch_calls == [2]
    assert accumulated == [True, True]
