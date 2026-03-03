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

    def submit(self, fn, data_file, language, *_args):
        del fn, language, _args
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
    monkeypatch.setattr(
        data_loader.utils, "get_all_files_in_tree_with_regex", _fake_profile_data_files
    )

    monkeypatch.delenv(data_loader.FI_PROFILE_BACKEND_ENV, raising=False)
    monkeypatch.setattr(
        data_loader.concurrent.futures, "ThreadPoolExecutor", _ExecutorStubOutOfOrder
    )
    monkeypatch.setattr(
        data_loader.concurrent.futures, "as_completed", _as_completed_out_of_order
    )

    profiles = data_loader.load_all_profiles("/tmp", "c-cpp", parallelise=True)
    assert [profile.name for profile in profiles] == ["c.data", "a.data", "b.data"]


def test_load_all_profiles_uses_process_backend_when_configured(monkeypatch):
    monkeypatch.setattr(
        data_loader.utils, "get_all_files_in_tree_with_regex", _fake_profile_data_files
    )
    monkeypatch.setenv(
        data_loader.FI_PROFILE_BACKEND_ENV, data_loader.FI_PROFILE_BACKEND_PROCESS
    )

    selected_backends = []

    class _ProcessExecutorStub(_ExecutorStubOutOfOrder):
        def __init__(self, *_args, **_kwargs) -> None:
            super().__init__(*_args, **_kwargs)
            selected_backends.append("process")

    def _thread_backend_guard(*_args, **_kwargs):
        del _args, _kwargs
        raise AssertionError("ThreadPoolExecutor should not be selected")

    monkeypatch.setattr(
        data_loader.concurrent.futures, "ProcessPoolExecutor", _ProcessExecutorStub
    )
    monkeypatch.setattr(
        data_loader.concurrent.futures, "ThreadPoolExecutor", _thread_backend_guard
    )
    monkeypatch.setattr(
        data_loader.concurrent.futures, "as_completed", _as_completed_out_of_order
    )

    profiles = data_loader.load_all_profiles("/tmp", "c-cpp", parallelise=True)

    assert selected_backends == ["process"]
    assert [profile.name for profile in profiles] == ["c.data", "a.data", "b.data"]


def test_load_all_profiles_invalid_backend_falls_back_to_thread(monkeypatch):
    monkeypatch.setattr(
        data_loader.utils, "get_all_files_in_tree_with_regex", _fake_profile_data_files
    )
    monkeypatch.setenv(data_loader.FI_PROFILE_BACKEND_ENV, "invalid-backend")

    selected_backends = []

    class _ThreadExecutorStub(_ExecutorStubOutOfOrder):
        def __init__(self, *_args, **_kwargs) -> None:
            super().__init__(*_args, **_kwargs)
            selected_backends.append("thread")

    def _process_backend_guard(*_args, **_kwargs):
        del _args, _kwargs
        raise AssertionError("ProcessPoolExecutor should not be selected")

    monkeypatch.setattr(
        data_loader.concurrent.futures, "ThreadPoolExecutor", _ThreadExecutorStub
    )
    monkeypatch.setattr(
        data_loader.concurrent.futures, "ProcessPoolExecutor", _process_backend_guard
    )
    monkeypatch.setattr(
        data_loader.concurrent.futures, "as_completed", _as_completed_out_of_order
    )

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

    monkeypatch.setattr(
        data_loader.utils, "get_all_files_in_tree_with_regex", fake_files
    )

    loaded = []

    def fake_load_profile(
        data_file: str,
        _language: str,
        _preloaded_yaml: dict[str, Any] | None = None,
    ):
        loaded.append(data_file)
        return data_file, _ProfileStub(data_file)

    monkeypatch.setattr(
        data_loader, "_load_profile_with_preloaded_yaml", fake_load_profile
    )

    def _boom_executor(*_args, **_kwargs):
        del _args, _kwargs
        raise RuntimeError("parallel disabled")

    monkeypatch.delenv(data_loader.FI_PROFILE_BACKEND_ENV, raising=False)
    monkeypatch.setattr(
        data_loader.concurrent.futures, "ThreadPoolExecutor", _boom_executor
    )

    profiles = data_loader.load_all_profiles("/tmp", "c-cpp", parallelise=True)

    assert [profile.name for profile in profiles] == ["x.data", "y.data"]
    assert loaded == ["x.data", "y.data"]


def test_load_all_profiles_uses_batched_yaml_loader_for_multiple_profiles(
    monkeypatch,
    tmp_path,
):
    cfg_a = tmp_path / "fuzzerLogFile-a.data"
    cfg_b = tmp_path / "fuzzerLogFile-b.data"
    cfg_a.write_text("Call tree\n", encoding="utf-8")
    cfg_b.write_text("Call tree\n", encoding="utf-8")
    (tmp_path / "fuzzerLogFile-a.data.yaml").write_text(
        "Fuzzer filename: a.cc\nAll functions:\n  Elements: []\n",
        encoding="utf-8",
    )
    (tmp_path / "fuzzerLogFile-b.data.yaml").write_text(
        "Fuzzer filename: b.cc\nAll functions:\n  Elements: []\n",
        encoding="utf-8",
    )

    def _fake_profile_data_files(_root: str, pattern: str):
        del _root
        if "fuzzerLogFile" in pattern:
            return [str(cfg_a), str(cfg_b)]
        if pattern.endswith("targetCalltree.txt$"):
            return []
        if "fuzzer-calltree-*" in pattern:
            return []
        return []

    monkeypatch.setattr(
        data_loader.utils, "get_all_files_in_tree_with_regex", _fake_profile_data_files
    )

    calls = []

    def _fake_loader(**kwargs):
        calls.append(kwargs.get("payload"))
        payload = kwargs.get("payload", {})
        if "paths" in payload:
            return (
                "rust",
                {
                    "profiles": [
                        {
                            "Fuzzer filename": "a.cc",
                            "All functions": {"Elements": []},
                        },
                        {
                            "Fuzzer filename": "b.cc",
                            "All functions": {"Elements": []},
                        },
                    ]
                },
            )
        raise AssertionError("Per-file YAML load should not run when batch succeeds")

    class _FuzzerProfileStub:
        def __init__(self, cfg_path, yaml_dict, language, cfg_content):
            del yaml_dict, language, cfg_content
            self.name = cfg_path

        def has_entry_point(self):
            return True

    monkeypatch.setattr(
        data_loader.backend_loaders, "load_json_with_backend", _fake_loader
    )
    monkeypatch.setattr(data_loader.fuzzer_profile, "FuzzerProfile", _FuzzerProfileStub)

    profiles = data_loader.load_all_profiles(str(tmp_path), "c-cpp", parallelise=False)

    assert len(calls) == 1
    assert calls[0]["paths"] == [
        str(tmp_path / "fuzzerLogFile-a.data.yaml"),
        str(tmp_path / "fuzzerLogFile-b.data.yaml"),
    ]
    assert [profile.name for profile in profiles] == [str(cfg_a), str(cfg_b)]


def test_load_all_profiles_batch_yaml_failure_falls_back_to_python_loader(
    monkeypatch,
    tmp_path,
):
    cfg_a = tmp_path / "fuzzerLogFile-a.data"
    cfg_b = tmp_path / "fuzzerLogFile-b.data"
    cfg_a.write_text("Call tree\n", encoding="utf-8")
    cfg_b.write_text("Call tree\n", encoding="utf-8")
    yaml_a = tmp_path / "fuzzerLogFile-a.data.yaml"
    yaml_b = tmp_path / "fuzzerLogFile-b.data.yaml"
    yaml_a.write_text(
        "Fuzzer filename: a.cc\nAll functions:\n  Elements: []\n", encoding="utf-8"
    )
    yaml_b.write_text(
        "Fuzzer filename: b.cc\nAll functions:\n  Elements: []\n", encoding="utf-8"
    )

    def _fake_profile_data_files(_root: str, pattern: str):
        del _root
        if "fuzzerLogFile" in pattern:
            return [str(cfg_a), str(cfg_b)]
        if pattern.endswith("targetCalltree.txt$"):
            return []
        if "fuzzer-calltree-*" in pattern:
            return []
        return []

    monkeypatch.setattr(
        data_loader.utils, "get_all_files_in_tree_with_regex", _fake_profile_data_files
    )

    calls = []

    def _fake_loader(**kwargs):
        calls.append(kwargs.get("payload"))
        return "python", None

    yaml_reads = []

    def _fake_yaml_reader(path: str):
        yaml_reads.append(path)
        if path == str(yaml_a):
            return {"Fuzzer filename": "a.cc", "All functions": {"Elements": []}}
        if path == str(yaml_b):
            return {"Fuzzer filename": "b.cc", "All functions": {"Elements": []}}
        return None

    class _FuzzerProfileStub:
        def __init__(self, cfg_path, yaml_dict, language, cfg_content):
            del language, cfg_content
            self.name = yaml_dict["Fuzzer filename"]
            self.cfg = cfg_path

        def has_entry_point(self):
            return True

    monkeypatch.setattr(
        data_loader.backend_loaders, "load_json_with_backend", _fake_loader
    )
    monkeypatch.setattr(data_loader.utils, "data_file_read_yaml", _fake_yaml_reader)
    monkeypatch.setattr(data_loader.fuzzer_profile, "FuzzerProfile", _FuzzerProfileStub)

    profiles = data_loader.load_all_profiles(str(tmp_path), "c-cpp", parallelise=False)

    assert len(calls) == 3
    assert "paths" in calls[0]
    assert calls[1] == {"path": str(yaml_a)}
    assert calls[2] == {"path": str(yaml_b)}
    assert yaml_reads == [str(yaml_a), str(yaml_b)]
    assert [profile.name for profile in profiles] == ["a.cc", "b.cc"]


def test_read_fuzzer_data_file_to_profile_uses_external_yaml_backend(
    monkeypatch,
    tmp_path,
):
    cfg_file = tmp_path / "fuzzerLogFile-sample.data"
    cfg_file.write_text("Call tree\n", encoding="utf-8")

    monkeypatch.setenv("FI_PROFILE_YAML_LOADER", "go")
    monkeypatch.setattr(
        data_loader.backend_loaders,
        "load_json_with_backend",
        lambda **_: (
            "go",
            {
                "Fuzzer filename": "fuzzer.cc",
                "All functions": {"Elements": []},
            },
        ),
    )

    captured_yaml = {}

    class _FuzzerProfileStub:
        def __init__(self, cfg_path, yaml_dict, language, cfg_content):
            del cfg_path, language, cfg_content
            captured_yaml.update(yaml_dict)

        def has_entry_point(self):
            return True

    monkeypatch.setattr(data_loader.fuzzer_profile, "FuzzerProfile", _FuzzerProfileStub)

    profile = data_loader.read_fuzzer_data_file_to_profile(str(cfg_file), "c-cpp")
    assert profile is not None
    assert captured_yaml["Fuzzer filename"] == "fuzzer.cc"


def test_read_fuzzer_data_file_to_profile_uses_python_default_backend(
    monkeypatch,
    tmp_path,
):
    """When no FI_* env vars are set, the default backend must be python (no spurious warning)."""
    cfg_file = tmp_path / "fuzzerLogFile-sample.data"
    cfg_file.write_text("Call tree\n", encoding="utf-8")
    yaml_file = tmp_path / "fuzzerLogFile-sample.data.yaml"
    yaml_file.write_text(
        "Fuzzer filename: fuzzer.cc\nAll functions:\n  Elements: []\n",
        encoding="utf-8",
    )

    captured_backend = {}

    def _fake_loader(**kwargs):
        captured_backend["default_backend"] = kwargs.get("default_backend")
        return "python", None

    captured_yaml = {}

    class _FuzzerProfileStub:
        def __init__(self, cfg_path, yaml_dict, language, cfg_content):
            del cfg_path, language, cfg_content
            captured_yaml.update(yaml_dict)

        def has_entry_point(self):
            return True

    monkeypatch.setattr(
        data_loader.backend_loaders, "load_json_with_backend", _fake_loader
    )
    monkeypatch.setattr(data_loader.fuzzer_profile, "FuzzerProfile", _FuzzerProfileStub)
    # Ensure no FI_ env vars bleed in from the environment.
    for key in list(__import__("os").environ):
        if key.startswith("FI_"):
            monkeypatch.delenv(key, raising=False)

    profile = data_loader.read_fuzzer_data_file_to_profile(str(cfg_file), "c-cpp")
    assert profile is not None
    assert (
        captured_backend["default_backend"]
        == data_loader.backend_loaders.BACKEND_PYTHON
    )
    assert captured_yaml["Fuzzer filename"] == "fuzzer.cc"


def test_read_fuzzer_data_file_to_profile_uses_rust_backend_when_env_set(
    monkeypatch,
    tmp_path,
):
    """When FI_NATIVE_BACKENDS=rust, the default backend for the YAML loader is rust."""
    cfg_file = tmp_path / "fuzzerLogFile-sample.data"
    cfg_file.write_text("Call tree\n", encoding="utf-8")
    yaml_file = tmp_path / "fuzzerLogFile-sample.data.yaml"
    yaml_file.write_text(
        "Fuzzer filename: fuzzer.cc\nAll functions:\n  Elements: []\n",
        encoding="utf-8",
    )

    captured_backend = {}

    def _fake_loader(**kwargs):
        captured_backend["default_backend"] = kwargs.get("default_backend")
        return "python", None

    captured_yaml = {}

    class _FuzzerProfileStub:
        def __init__(self, cfg_path, yaml_dict, language, cfg_content):
            del cfg_path, language, cfg_content
            captured_yaml.update(yaml_dict)

        def has_entry_point(self):
            return True

    monkeypatch.setattr(
        data_loader.backend_loaders, "load_json_with_backend", _fake_loader
    )
    monkeypatch.setattr(data_loader.fuzzer_profile, "FuzzerProfile", _FuzzerProfileStub)
    monkeypatch.setenv("FI_NATIVE_BACKENDS", "rust")

    profile = data_loader.read_fuzzer_data_file_to_profile(str(cfg_file), "c-cpp")
    assert profile is not None
    assert (
        captured_backend["default_backend"] == data_loader.backend_loaders.BACKEND_RUST
    )
    assert captured_yaml["Fuzzer filename"] == "fuzzer.cc"
