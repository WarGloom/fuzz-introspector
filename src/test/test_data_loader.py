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
"""Tests for data loader profile loading."""

import os
import sys
from typing import Any

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import data_loader  # noqa: E402


class _ProfileStub:
    def __init__(self, name: str):
        self.name = name


class _FutureStub:
    def __init__(self, value: Any):
        self._value = value

    def result(self):
        return self._value


class _ExecutorStubOutOfOrder:
    def __init__(self, *_args, **_kwargs) -> None:
        self.futures = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def submit(self, fn, data_file, language):
        del fn, language
        self.futures.append(data_file)
        return _FutureStub((data_file, _ProfileStub(data_file)))


def _as_completed_out_of_order(futures):
    return list(reversed(futures))


def _fake_profile_data_files(_root: str, pattern: str):
    del _root
    if "fuzzerLogFile" in pattern:
        return ["c.data", "a.data", "b.data"]
    if pattern.endswith("targetCalltree.txt$"):
        return []
    if "fuzzer-calltree-*" in pattern:
        return []
    return []


def test_load_all_profiles_parallel_preserves_file_order(monkeypatch):
    monkeypatch.setattr(data_loader.utils, "get_all_files_in_tree_with_regex",
                        _fake_profile_data_files)

    monkeypatch.delenv(data_loader.FI_PROFILE_BACKEND_ENV, raising=False)
    monkeypatch.setattr(data_loader.concurrent.futures, "ThreadPoolExecutor",
                        _ExecutorStubOutOfOrder)
    monkeypatch.setattr(data_loader.concurrent.futures, "as_completed",
                        _as_completed_out_of_order)

    profiles = data_loader.load_all_profiles("/tmp", "c-cpp", parallelise=True)
    assert [profile.name for profile in profiles] == ["c.data", "a.data", "b.data"]


def test_load_all_profiles_uses_process_backend_when_configured(monkeypatch):
    monkeypatch.setattr(data_loader.utils, "get_all_files_in_tree_with_regex",
                        _fake_profile_data_files)
    monkeypatch.setenv(data_loader.FI_PROFILE_BACKEND_ENV,
                       data_loader.FI_PROFILE_BACKEND_PROCESS)

    selected_backends = []

    class _ProcessExecutorStub(_ExecutorStubOutOfOrder):
        def __init__(self, *_args, **_kwargs) -> None:
            super().__init__(*_args, **_kwargs)
            selected_backends.append("process")

    def _thread_backend_guard(*_args, **_kwargs):
        del _args, _kwargs
        raise AssertionError("ThreadPoolExecutor should not be selected")

    monkeypatch.setattr(data_loader.concurrent.futures, "ProcessPoolExecutor",
                        _ProcessExecutorStub)
    monkeypatch.setattr(data_loader.concurrent.futures, "ThreadPoolExecutor",
                        _thread_backend_guard)
    monkeypatch.setattr(data_loader.concurrent.futures, "as_completed",
                        _as_completed_out_of_order)

    profiles = data_loader.load_all_profiles("/tmp", "c-cpp", parallelise=True)

    assert selected_backends == ["process"]
    assert [profile.name for profile in profiles] == ["c.data", "a.data", "b.data"]


def test_load_all_profiles_invalid_backend_falls_back_to_thread(monkeypatch):
    monkeypatch.setattr(data_loader.utils, "get_all_files_in_tree_with_regex",
                        _fake_profile_data_files)
    monkeypatch.setenv(data_loader.FI_PROFILE_BACKEND_ENV, "invalid-backend")

    selected_backends = []

    class _ThreadExecutorStub(_ExecutorStubOutOfOrder):
        def __init__(self, *_args, **_kwargs) -> None:
            super().__init__(*_args, **_kwargs)
            selected_backends.append("thread")

    def _process_backend_guard(*_args, **_kwargs):
        del _args, _kwargs
        raise AssertionError("ProcessPoolExecutor should not be selected")

    monkeypatch.setattr(data_loader.concurrent.futures, "ThreadPoolExecutor",
                        _ThreadExecutorStub)
    monkeypatch.setattr(data_loader.concurrent.futures, "ProcessPoolExecutor",
                        _process_backend_guard)
    monkeypatch.setattr(data_loader.concurrent.futures, "as_completed",
                        _as_completed_out_of_order)

    profiles = data_loader.load_all_profiles("/tmp", "c-cpp", parallelise=True)

    assert selected_backends == ["thread"]
    assert [profile.name for profile in profiles] == ["c.data", "a.data", "b.data"]


def test_load_all_profiles_fallback_to_serial_on_parallel_failure(monkeypatch):
    def fake_files(_root: str, pattern: str):
        del _root
        if "fuzzerLogFile" in pattern:
            return ["x.data", "y.data"]
        if pattern.endswith("targetCalltree.txt$"):
            return []
        if "fuzzer-calltree-*" in pattern:
            return []
        return []

    monkeypatch.setattr(data_loader.utils, "get_all_files_in_tree_with_regex",
                        fake_files)

    loaded = []

    def fake_load_profile(data_file: str, _language: str):
        loaded.append(data_file)
        return data_file, _ProfileStub(data_file)

    monkeypatch.setattr(data_loader, "_load_profile", fake_load_profile)

    def _boom_executor(*_args, **_kwargs):
        del _args, _kwargs
        raise RuntimeError("parallel disabled")

    monkeypatch.delenv(data_loader.FI_PROFILE_BACKEND_ENV, raising=False)
    monkeypatch.setattr(data_loader.concurrent.futures, "ThreadPoolExecutor",
                        _boom_executor)

    profiles = data_loader.load_all_profiles("/tmp", "c-cpp", parallelise=True)

    assert [profile.name for profile in profiles] == ["x.data", "y.data"]
    assert loaded == ["x.data", "y.data"]
