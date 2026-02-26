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

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import analysis  # noqa: E402
from fuzz_introspector.datatypes import project_profile  # noqa: E402
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

    def accummulate_profile(self, base_folder, _return_dict, _uniq_id,
                            _semaphore):
        if self._should_fail:
            raise ValueError("boom")
        self.accumulated_with = base_folder
        self.total_basic_blocks = 1


def test_parse_profile_worker_count_default_is_capped(monkeypatch):
    monkeypatch.delenv(analysis.FI_PROFILE_WORKERS_ENV, raising=False)
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 24)
    assert analysis._parse_profile_worker_count() == 24


def test_parse_profile_worker_count_env_override_respected(monkeypatch):
    monkeypatch.setenv(analysis.FI_PROFILE_WORKERS_ENV, "4")
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 24)
    assert analysis._parse_profile_worker_count() == 4

    monkeypatch.setenv(analysis.FI_PROFILE_WORKERS_ENV, "99")
    monkeypatch.setattr(analysis.os, "cpu_count", lambda: 6)
    assert analysis._parse_profile_worker_count() == 6


def test_accummulate_profiles_parallel_preserves_input_order(monkeypatch):

    def fake_accummulate_single_profile(profile_index, profile_payload,
                                        base_folder):
        profile_payload["total_basic_blocks"] = 1
        profile_payload["introspector_data_file"] = base_folder
        return profile_index, profile_payload

    monkeypatch.setattr(analysis.concurrent.futures, "ProcessPoolExecutor",
                        _ExecutorStub)
    monkeypatch.setattr(analysis.concurrent.futures, "as_completed",
                        lambda futures: list(futures)[::-1])
    monkeypatch.setattr(analysis, "_accummulate_single_profile",
                        fake_accummulate_single_profile)
    monkeypatch.setattr(analysis, "_parse_profile_worker_count", lambda: 3)

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

    def fake_accummulate_single_profile(profile_index, profile_payload,
                                        _base_folder):
        if profile_payload.get("fuzzer_source_file") == "broken":
            raise ValueError("boom")
        return profile_index, profile_payload

    monkeypatch.setattr(analysis.concurrent.futures, "ProcessPoolExecutor",
                        _ExecutorStub)
    monkeypatch.setattr(analysis.concurrent.futures, "as_completed",
                        lambda futures: list(futures))
    monkeypatch.setattr(analysis, "_accummulate_single_profile",
                        fake_accummulate_single_profile)
    monkeypatch.setattr(analysis, "_parse_profile_worker_count", lambda: 2)

    profiles = [_ProfileStub("ok"), _ProfileStub("broken", should_fail=True)]

    with pytest.raises(DataLoaderError, match="broken at index 1"):
        analysis._accummulate_profiles(profiles, "/tmp/base", parallelise=True)


def test_profile_accumulation_parallel_serial_parity(monkeypatch):

    def fake_accummulate_single_profile(profile_index, profile_payload,
                                        _base_folder):
        profile_payload["total_basic_blocks"] = 1
        return profile_index, profile_payload

    monkeypatch.setattr(analysis.concurrent.futures, "ProcessPoolExecutor",
                        _ExecutorStub)
    monkeypatch.setattr(analysis.concurrent.futures, "as_completed",
                        lambda futures: list(futures))
    monkeypatch.setattr(analysis, "_accummulate_single_profile",
                        fake_accummulate_single_profile)
    monkeypatch.setattr(analysis, "_parse_profile_worker_count", lambda: 3)

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
