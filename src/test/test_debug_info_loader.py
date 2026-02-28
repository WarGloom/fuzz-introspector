# Copyright 2024 Fuzz Introspector Authors
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
"""Tests for debug info YAML loading and parallel fallback behavior."""

import json
import logging
import os
import tempfile

import pytest

from fuzz_introspector import debug_info


def _write_yaml(tmpdir, name, payload):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp)
    return path


def _write_text(tmpdir, name, content):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(content)
    return path


def test_load_debug_all_yaml_files_serial(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        f1 = _write_yaml(tmpdir, "a.yaml", [{"k": 1}])
        f2 = _write_yaml(tmpdir, "b.yaml", [{"k": 2}])
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "1")
        items = debug_info.load_debug_all_yaml_files([f1, f2])
    assert items == [{"k": 1}, {"k": 2}]


def test_load_debug_all_yaml_files_external_backend(monkeypatch):
    monkeypatch.setenv("FI_DEBUG_YAML_LOADER", "go")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "load_json_with_backend",
        lambda **_: ("go", [{"external": True}]),
    )

    items = debug_info.load_debug_all_yaml_files(["/tmp/unused.yaml"])
    assert items == [{"external": True}]


def test_load_debug_all_yaml_files_uses_rust_default_backend(monkeypatch):
    captured = {}

    def _fake_loader(**kwargs):
        captured["default_backend"] = kwargs.get("default_backend")
        return "python", None

    with tempfile.TemporaryDirectory() as tmpdir:
        yaml_path = _write_yaml(tmpdir, "a.yaml", [{"k": 1}])
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")
        monkeypatch.setattr(
            debug_info.backend_loaders, "load_json_with_backend", _fake_loader
        )
        items = debug_info.load_debug_all_yaml_files([yaml_path])

    assert captured["default_backend"] == debug_info.backend_loaders.BACKEND_RUST
    assert items == [{"k": 1}]


def test_load_debug_all_yaml_files_parallel(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        files = []
        for idx in range(4):
            files.append(_write_yaml(tmpdir, f"f{idx}.yaml", [{"idx": idx}]))
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "1")
        monkeypatch.setenv("FI_DEBUG_MAX_WORKERS", "2")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "1")
        items = debug_info.load_debug_all_yaml_files(files)
    assert sorted(i["idx"] for i in items) == [0, 1, 2, 3]


def test_load_debug_all_yaml_files_invalid_env_fallback(monkeypatch, caplog):
    with tempfile.TemporaryDirectory() as tmpdir:
        files = [
            _write_yaml(tmpdir, "f0.yaml", [{"idx": 0}]),
            _write_yaml(tmpdir, "f1.yaml", [{"idx": 1}]),
        ]
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")
        monkeypatch.setenv("FI_DEBUG_MAX_WORKERS", "not-a-number")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "0")
        monkeypatch.setenv("FI_DEBUG_SPILL_MB", "-2")
        with caplog.at_level(logging.WARNING):
            items = debug_info.load_debug_all_yaml_files(files)

    assert items == [{"idx": 0}, {"idx": 1}]
    messages = [record.message for record in caplog.records]
    assert any("FI_DEBUG_MAX_WORKERS" in message for message in messages)
    assert any("FI_DEBUG_SHARD_FILES" in message for message in messages)
    assert any("FI_DEBUG_SPILL_MB" in message for message in messages)


def test_load_debug_all_yaml_files_deterministic_serial_vs_parallel(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        files = [
            _write_yaml(tmpdir, "a.yaml", [{"name": "a"}]),
            _write_yaml(tmpdir, "b.yaml", [{"name": "b"}]),
            _write_yaml(tmpdir, "c.yaml", [{"name": "c"}]),
            _write_yaml(tmpdir, "d.yaml", [{"name": "d"}]),
        ]
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "2")
        serial_items = debug_info.load_debug_all_yaml_files(files)

        monkeypatch.setenv("FI_DEBUG_PARALLEL", "1")
        monkeypatch.setenv("FI_DEBUG_MAX_WORKERS", "2")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "2")
        parallel_items = debug_info.load_debug_all_yaml_files(files)

    assert serial_items == parallel_items
    assert serial_items == [{"name": "a"}, {"name": "b"}, {"name": "c"}, {"name": "d"}]


def test_load_debug_all_yaml_files_parallel_executor_failure_falls_back(monkeypatch):

    class _Future:
        def __init__(self, should_fail):
            self._should_fail = should_fail

        def result(self):
            if self._should_fail:
                raise RuntimeError("forced submit/result failure")
            return []

    class _Executor:
        shutdown_calls = []

        def __init__(self, max_workers):
            del max_workers
            self._submitted = 0

        def submit(self, *_args, **_kwargs):
            future = _Future(should_fail=self._submitted == 0)
            self._submitted += 1
            return future

        def shutdown(self, wait=True, cancel_futures=False):
            self.shutdown_calls.append((wait, cancel_futures))

    def _fake_as_completed(futures):
        return list(futures)

    def _fake_wait(futures, timeout=None, return_when=None):
        del timeout
        del return_when
        return set(futures), set()

    with tempfile.TemporaryDirectory() as tmpdir:
        files = [
            _write_yaml(tmpdir, "f0.yaml", [{"idx": 0}]),
            _write_yaml(tmpdir, "f1.yaml", [{"idx": 1}]),
            _write_yaml(tmpdir, "f2.yaml", [{"idx": 2}]),
        ]
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "1")
        monkeypatch.setenv("FI_DEBUG_MAX_WORKERS", "2")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "1")
        monkeypatch.setenv("FI_DEBUG_USE_PROCESS_POOL", "0")
        monkeypatch.setattr(debug_info, "ThreadPoolExecutor", _Executor)
        monkeypatch.setattr(debug_info, "as_completed", _fake_as_completed)
        monkeypatch.setattr(debug_info, "wait", _fake_wait)
        items = debug_info.load_debug_all_yaml_files(files)

    assert items == [{"idx": 0}, {"idx": 1}, {"idx": 2}]


def test_load_debug_all_yaml_files_parallel_failure_cancels_pending_futures(
    monkeypatch,
):

    class _Future:
        def __init__(self, result_payload=None, result_exc=None):
            self._result_payload = result_payload
            self._result_exc = result_exc
            self.cancel_called = False

        def result(self):
            if self._result_exc is not None:
                raise self._result_exc
            return self._result_payload

        def cancel(self):
            self.cancel_called = True
            return True

    class _Executor:
        instances = []

        def __init__(self, max_workers):
            del max_workers
            self._submitted = 0
            self.futures = []
            self.shutdown_calls = []
            self.__class__.instances.append(self)

        def submit(self, *_args, **_kwargs):
            if self._submitted == 0:
                future = _Future(result_exc=RuntimeError("forced shard failure"))
            else:
                future = _Future(result_payload=[])
            self._submitted += 1
            self.futures.append(future)
            return future

        def shutdown(self, wait=True, cancel_futures=False):
            self.shutdown_calls.append((wait, cancel_futures))

    def _fake_wait(futures, timeout=None, return_when=None):
        del timeout
        del return_when
        futures_list = list(futures)
        return {futures_list[0]}, set(futures_list[1:])

    with tempfile.TemporaryDirectory() as tmpdir:
        files = [
            _write_yaml(tmpdir, "f0.yaml", [{"idx": 0}]),
            _write_yaml(tmpdir, "f1.yaml", [{"idx": 1}]),
            _write_yaml(tmpdir, "f2.yaml", [{"idx": 2}]),
        ]
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "1")
        monkeypatch.setenv("FI_DEBUG_MAX_WORKERS", "2")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "1")
        monkeypatch.setenv("FI_DEBUG_USE_PROCESS_POOL", "0")
        monkeypatch.setattr(debug_info, "ThreadPoolExecutor", _Executor)
        monkeypatch.setattr(debug_info, "wait", _fake_wait)

        items = debug_info.load_debug_all_yaml_files(files)

    assert items == [{"idx": 0}, {"idx": 1}, {"idx": 2}]
    assert _Executor.instances
    first_executor = _Executor.instances[0]
    assert (False, True) in first_executor.shutdown_calls


def test_load_debug_all_yaml_files_spill_activation(monkeypatch):
    spill_count = {"count": 0}
    original_write_spill = debug_info._write_spill

    def _counting_write_spill(items, category):
        spill_count["count"] += 1
        return original_write_spill(items, category)

    with tempfile.TemporaryDirectory() as tmpdir:
        files = [
            _write_yaml(tmpdir, "f0.yaml", [{"idx": 0}]),
            _write_yaml(tmpdir, "f1.yaml", [{"idx": 1}]),
            _write_yaml(tmpdir, "f2.yaml", [{"idx": 2}]),
        ]
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "1")
        monkeypatch.setenv("FI_DEBUG_SPILL_MB", "1")
        monkeypatch.setattr(
            debug_info,
            "_estimate_list_bytes",
            lambda items: 1024 * 1024 if items else 0,
        )
        monkeypatch.setattr(debug_info, "_write_spill", _counting_write_spill)
        items = debug_info.load_debug_all_yaml_files(files)

    assert spill_count["count"] > 0
    assert items == [{"idx": 0}, {"idx": 1}, {"idx": 2}]


def test_spill_roundtrip_jsonl():
    items = [{"idx": 1, "name": "a"}, {"idx": 2, "name": "b"}]
    spill_path, spill_count = debug_info._write_spill(items, "debug-info")
    try:
        loaded_items = list(debug_info._iter_spill_items(spill_path))
    finally:
        os.remove(spill_path)

    assert spill_count == 2
    assert loaded_items == items


def test_iter_spill_items_supports_legacy_json_array(tmp_path):
    legacy_spill = tmp_path / "legacy_spill.json"
    expected_items = [{"idx": 1}, {"idx": 2}]
    with open(legacy_spill, "w", encoding="utf-8") as spill_fp:
        json.dump(expected_items, spill_fp)

    loaded_items = list(debug_info._iter_spill_items(str(legacy_spill)))
    assert loaded_items == expected_items


def test_correlate_debugged_function_to_debug_types_parallel(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [{"type_arguments": [0], "file_location": "/src/a:1"}]
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "1")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_WORKERS", "2")
    debug_info.correlate_debugged_function_to_debug_types(types, funcs, "/tmp", False)
    assert "func_signature_elems" in funcs[0]
    assert "source" in funcs[0]


def test_correlate_debugged_function_to_debug_types_native_shards(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [{"type_arguments": [0], "file_location": "/src/a.c:7"}]
    captured_payload = {}

    def _fake_run_correlator_backend(payload, **_kwargs):
        captured_payload.update(payload)
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-debug-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["void"],
                        "params": [],
                    },
                    "source": {"source_file": "/src/a.c", "source_line": "7"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 1},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "1")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(
        debug_info,
        "create_friendly_debug_types",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("python friendly-type dump should be skipped")
        ),
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        debug_info.correlate_debugged_function_to_debug_types(
            types, funcs, tmpdir, dump_files=False
        )

    assert "debug_types_paths" in captured_payload
    assert "debug_functions_paths" in captured_payload
    assert "debug_types" not in captured_payload
    assert "debug_functions" not in captured_payload
    assert len(captured_payload["debug_types_paths"]) == 1
    assert len(captured_payload["debug_functions_paths"]) == 1
    assert funcs[0]["source"]["source_file"] == "/src/a.c"
    assert funcs[0]["source"]["source_line"] == "7"
    assert funcs[0]["func_signature_elems"]["return_type"] == ["void"]


def test_correlator_native_zero_functions_strict_accepts_empty_shards(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = []

    def _fake_run_correlator_backend(**_kwargs):
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 0},
                "artifacts": {"correlated_shards": []},
                "timings": {},
            },
        )

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "1")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(
        debug_info,
        "create_friendly_debug_types",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("python fallback should be skipped for native success")
        ),
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        debug_info.correlate_debugged_function_to_debug_types(
            types, funcs, tmpdir, dump_files=False
        )

    assert funcs == []


def test_correlator_native_shard_schema_error_non_strict_falls_back_without_partial_mutation(
    monkeypatch, caplog
):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [
        {"type_arguments": [0], "file_location": "/src/a.c:7"},
        {"type_arguments": [0], "file_location": "/src/b.c:9"},
    ]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-malformed-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": [],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "7"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
            json.dump(
                {
                    "row_idx": 1,
                    "func_signature_elems": "invalid-shape",
                    "source": {"source_file": "/native/b.c", "source_line": "9"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 2},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    def _fake_python_correlate(func_slice, _debug_type_dictionary):
        assert all("func_signature_elems" not in dfunc for dfunc in func_slice)
        for debug_func in func_slice:
            debug_func["func_signature_elems"] = {
                "return_type": ["python"],
                "params": [],
            }
            debug_func["source"] = {
                "source_file": "/python/fallback.c",
                "source_line": "1",
            }

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "0")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(debug_info, "_correlate_function_slice", _fake_python_correlate)
    monkeypatch.setattr(
        debug_info,
        "create_friendly_debug_types",
        lambda *_args, **_kwargs: None,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with caplog.at_level(logging.WARNING):
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert funcs[0]["func_signature_elems"]["return_type"] == ["python"]
    assert funcs[1]["func_signature_elems"]["return_type"] == ["python"]
    assert any(
        debug_info.backend_loaders.FI_CORR_SCHEMA_ERROR in record.message
        for record in caplog.records
    )


def test_correlator_native_shard_schema_error_strict_raises(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [{"type_arguments": [0], "file_location": "/src/a.c:7"}]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-malformed-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": "invalid-shape",
                    "source": {"source_file": "/native/a.c", "source_line": "7"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 1},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "1")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(
            debug_info.backend_loaders.CorrelatorBackendError
        ) as exc_info:
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert exc_info.value.reason_code == debug_info.backend_loaders.FI_CORR_SCHEMA_ERROR


def test_correlator_native_cross_shard_error_non_strict_keeps_atomic_updates(
    monkeypatch,
):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [
        {"type_arguments": [0], "file_location": "/src/a.c:7"},
        {"type_arguments": [0], "file_location": "/src/b.c:9"},
    ]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        valid_shard = os.path.join(output_dir, "correlated-valid-00000.ndjson")
        malformed_shard = os.path.join(output_dir, "correlated-malformed-00001.ndjson")
        with open(valid_shard, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": [],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "7"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        with open(malformed_shard, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 1,
                    "func_signature_elems": "invalid-shape",
                    "source": {"source_file": "/native/b.c", "source_line": "9"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 2},
                "artifacts": {"correlated_shards": [valid_shard, malformed_shard]},
                "timings": {},
            },
        )

    def _fake_python_correlate(func_slice, _debug_type_dictionary):
        assert all("func_signature_elems" not in dfunc for dfunc in func_slice)
        for debug_func in func_slice:
            debug_func["func_signature_elems"] = {
                "return_type": ["python"],
                "params": [],
            }
            debug_func["source"] = {
                "source_file": "/python/fallback.c",
                "source_line": "1",
            }

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "0")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(debug_info, "_correlate_function_slice", _fake_python_correlate)
    monkeypatch.setattr(
        debug_info,
        "create_friendly_debug_types",
        lambda *_args, **_kwargs: None,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        debug_info.correlate_debugged_function_to_debug_types(
            types, funcs, tmpdir, dump_files=False
        )

    assert funcs[0]["func_signature_elems"]["return_type"] == ["python"]
    assert funcs[1]["func_signature_elems"]["return_type"] == ["python"]


def test_correlator_native_cross_shard_error_strict_keeps_atomic_updates(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [
        {"type_arguments": [0], "file_location": "/src/a.c:7"},
        {"type_arguments": [0], "file_location": "/src/b.c:9"},
    ]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        valid_shard = os.path.join(output_dir, "correlated-valid-00000.ndjson")
        malformed_shard = os.path.join(output_dir, "correlated-malformed-00001.ndjson")
        with open(valid_shard, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": [],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "7"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        with open(malformed_shard, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 1,
                    "func_signature_elems": "invalid-shape",
                    "source": {"source_file": "/native/b.c", "source_line": "9"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 2},
                "artifacts": {"correlated_shards": [valid_shard, malformed_shard]},
                "timings": {},
            },
        )

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "1")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(
            debug_info.backend_loaders.CorrelatorBackendError
        ) as exc_info:
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert exc_info.value.reason_code == debug_info.backend_loaders.FI_CORR_SCHEMA_ERROR
    assert all("func_signature_elems" not in debug_func for debug_func in funcs)
    assert all("source" not in debug_func for debug_func in funcs)


def test_correlator_native_duplicate_row_idx_strict_raises(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [
        {"type_arguments": [0], "file_location": "/src/a.c:7"},
        {"type_arguments": [0], "file_location": "/src/b.c:9"},
    ]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-duplicate-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": [],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "7"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native-dup"],
                        "params": [],
                    },
                    "source": {
                        "source_file": "/native/a-dup.c",
                        "source_line": "8",
                    },
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 2},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "1")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(
            debug_info.backend_loaders.CorrelatorBackendError
        ) as exc_info:
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert exc_info.value.reason_code == debug_info.backend_loaders.FI_CORR_SCHEMA_ERROR
    assert all("func_signature_elems" not in debug_func for debug_func in funcs)
    assert all("source" not in debug_func for debug_func in funcs)


def test_correlator_native_missing_coverage_non_strict_falls_back(monkeypatch, caplog):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [
        {"type_arguments": [0], "file_location": "/src/a.c:7"},
        {"type_arguments": [0], "file_location": "/src/b.c:9"},
    ]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-partial-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": [],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "7"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 1},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    def _fake_python_correlate(func_slice, _debug_type_dictionary):
        assert all("func_signature_elems" not in dfunc for dfunc in func_slice)
        for debug_func in func_slice:
            debug_func["func_signature_elems"] = {
                "return_type": ["python"],
                "params": [],
            }
            debug_func["source"] = {
                "source_file": "/python/fallback.c",
                "source_line": "1",
            }

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "0")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(debug_info, "_correlate_function_slice", _fake_python_correlate)
    monkeypatch.setattr(
        debug_info,
        "create_friendly_debug_types",
        lambda *_args, **_kwargs: None,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with caplog.at_level(logging.WARNING):
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert funcs[0]["func_signature_elems"]["return_type"] == ["python"]
    assert funcs[1]["func_signature_elems"]["return_type"] == ["python"]
    assert any(
        debug_info.backend_loaders.FI_CORR_SCHEMA_ERROR in record.message
        for record in caplog.records
    )


def test_correlator_shadow_mode_strict_missing_unsampled_rows_raises(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    func_count = debug_info.CORRELATOR_SHADOW_SAMPLE_SIZE_DEFAULT + 20
    funcs = [
        {"type_arguments": [0], "file_location": f"/src/a.c:{idx + 1}"}
        for idx in range(func_count)
    ]
    sampled_indexes = debug_info._build_correlator_shadow_sample_indexes(
        func_count, debug_info.CORRELATOR_SHADOW_SAMPLE_SIZE_DEFAULT
    )

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-shadow-partial-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            for row_idx in sampled_indexes:
                json.dump(
                    {
                        "row_idx": row_idx,
                        "func_signature_elems": {
                            "return_type": ["native"],
                            "params": [],
                        },
                        "source": {
                            "source_file": "/native/a.c",
                            "source_line": str(row_idx + 1),
                        },
                    },
                    shard_fp,
                )
                shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": len(sampled_indexes)},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    def _fail_if_python_correlation_runs(*_args, **_kwargs):
        raise AssertionError(
            "Strict shadow missing coverage must fail before python stage"
        )

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_SHADOW", "1")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "1")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.delenv("FI_DEBUG_CORRELATOR_SHADOW_SAMPLE_SIZE", raising=False)
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(
        debug_info, "_correlate_function_slice", _fail_if_python_correlation_runs
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(
            debug_info.backend_loaders.CorrelatorBackendError
        ) as exc_info:
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert exc_info.value.reason_code == debug_info.backend_loaders.FI_CORR_SCHEMA_ERROR
    assert all("func_signature_elems" not in debug_func for debug_func in funcs)
    assert all("source" not in debug_func for debug_func in funcs)


def test_correlator_shadow_sample_size_zero_keeps_full_compare_opt_in():
    sample_indexes = debug_info._build_correlator_shadow_sample_indexes(5, 0)
    assert sample_indexes == [0, 1, 2, 3, 4]


def test_correlator_shadow_mode_uses_safe_default_sample_size(monkeypatch, caplog):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    func_count = debug_info.CORRELATOR_SHADOW_SAMPLE_SIZE_DEFAULT + 20
    funcs = [
        {"type_arguments": [0], "file_location": f"/src/a.c:{idx + 1}"}
        for idx in range(func_count)
    ]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-shadow-default-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            for row_idx in range(func_count):
                json.dump(
                    {
                        "row_idx": row_idx,
                        "func_signature_elems": {
                            "return_type": ["native"],
                            "params": [],
                        },
                        "source": {
                            "source_file": "/native/a.c",
                            "source_line": str(row_idx + 1),
                        },
                    },
                    shard_fp,
                )
                shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": func_count},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    def _fake_python_correlate(func_slice, _debug_type_dictionary):
        for debug_func in func_slice:
            debug_func["func_signature_elems"] = {
                "return_type": ["python"],
                "params": [],
            }
            debug_func["source"] = {
                "source_file": "/python/a.c",
                "source_line": "1",
            }

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_SHADOW", "1")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "0")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.delenv("FI_DEBUG_CORRELATOR_SHADOW_SAMPLE_SIZE", raising=False)
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(debug_info, "_correlate_function_slice", _fake_python_correlate)
    monkeypatch.setattr(
        debug_info,
        "create_friendly_debug_types",
        lambda *_args, **_kwargs: None,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with caplog.at_level(logging.INFO):
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    expected_fragment = (
        "captured "
        f"{debug_info.CORRELATOR_SHADOW_SAMPLE_SIZE_DEFAULT} sampled native rows"
    )
    assert any(expected_fragment in record.message for record in caplog.records)


def test_correlator_shadow_mode_keeps_python_authoritative_and_logs_mismatch(
    monkeypatch, caplog
):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [{"type_arguments": [0], "file_location": "/src/a.c:7"}]
    captured_payload = {}

    def _fake_run_correlator_backend(payload, **_kwargs):
        captured_payload.update(payload)
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-shadow-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": ["native-param"],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "70"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 1},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    def _fake_python_correlate(func_slice, _debug_type_dictionary):
        for debug_func in func_slice:
            debug_func["func_signature_elems"] = {
                "return_type": ["python"],
                "params": ["python-param"],
            }
            debug_func["source"] = {
                "source_file": "/python/a.c",
                "source_line": "7",
            }

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_SHADOW", "1")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "0")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(debug_info, "_correlate_function_slice", _fake_python_correlate)
    monkeypatch.setattr(
        debug_info, "create_friendly_debug_types", lambda *_args, **_kwargs: None
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with caplog.at_level(logging.WARNING):
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert "debug_types_paths" in captured_payload
    assert "debug_functions_paths" in captured_payload
    assert funcs[0]["func_signature_elems"]["return_type"] == ["python"]
    assert funcs[0]["func_signature_elems"]["params"] == ["python-param"]
    assert funcs[0]["source"]["source_file"] == "/python/a.c"
    assert funcs[0]["source"]["source_line"] == "7"
    assert any(
        debug_info.backend_loaders.FI_CORR_PARITY_MISMATCH in record.message
        for record in caplog.records
    )


def test_correlator_shadow_mode_strict_mismatch_raises(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [{"type_arguments": [0], "file_location": "/src/a.c:7"}]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-shadow-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": [],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "70"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="rust",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 1},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    def _fake_python_correlate(func_slice, _debug_type_dictionary):
        for debug_func in func_slice:
            debug_func["func_signature_elems"] = {
                "return_type": ["python"],
                "params": [],
            }
            debug_func["source"] = {
                "source_file": "/python/a.c",
                "source_line": "7",
            }

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "rust")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_SHADOW", "1")
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "1")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(debug_info, "_correlate_function_slice", _fake_python_correlate)
    monkeypatch.setattr(
        debug_info, "create_friendly_debug_types", lambda *_args, **_kwargs: None
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(
            debug_info.backend_loaders.CorrelatorBackendError
        ) as exc_info:
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert exc_info.value.reason_code == (
        debug_info.backend_loaders.FI_CORR_PARITY_MISMATCH
    )


def test_correlator_go_backend_forces_shadow_mode_when_disabled(monkeypatch, caplog):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [{"type_arguments": [0], "file_location": "/src/a.c:7"}]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(output_dir, "correlated-go-shadow-00000.ndjson")
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": ["native-param"],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "70"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="go",
            strict_mode=False,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 1},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    def _fake_python_correlate(func_slice, _debug_type_dictionary):
        for debug_func in func_slice:
            debug_func["func_signature_elems"] = {
                "return_type": ["python"],
                "params": ["python-param"],
            }
            debug_func["source"] = {
                "source_file": "/python/a.c",
                "source_line": "7",
            }

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "go")
    monkeypatch.delenv("FI_DEBUG_CORRELATOR_SHADOW", raising=False)
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "0")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(debug_info, "_correlate_function_slice", _fake_python_correlate)
    monkeypatch.setattr(
        debug_info, "create_friendly_debug_types", lambda *_args, **_kwargs: None
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with caplog.at_level(logging.WARNING):
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert funcs[0]["func_signature_elems"]["return_type"] == ["python"]
    assert funcs[0]["source"]["source_file"] == "/python/a.c"
    assert any(
        "FI_DEBUG_CORRELATOR_BACKEND=go currently runs in shadow-only mode"
        in record.message
        for record in caplog.records
    )
    assert any(
        debug_info.backend_loaders.FI_CORR_PARITY_MISMATCH in record.message
        for record in caplog.records
    )


def test_correlator_go_backend_strict_forced_shadow_mismatch_raises(monkeypatch):
    types = [{"addr": 0, "tag": "DW_TAG_base_type", "name": "int"}]
    funcs = [{"type_arguments": [0], "file_location": "/src/a.c:7"}]

    def _fake_run_correlator_backend(payload, **_kwargs):
        output_dir = payload["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        shard_path = os.path.join(
            output_dir, "correlated-go-shadow-strict-00000.ndjson"
        )
        with open(shard_path, "w", encoding="utf-8") as shard_fp:
            json.dump(
                {
                    "row_idx": 0,
                    "func_signature_elems": {
                        "return_type": ["native"],
                        "params": [],
                    },
                    "source": {"source_file": "/native/a.c", "source_line": "70"},
                },
                shard_fp,
            )
            shard_fp.write("\n")
        return debug_info.backend_loaders.CorrelatorBackendResult(
            selected_backend="go",
            strict_mode=True,
            response={
                "schema_version": 1,
                "status": "success",
                "counters": {"updated_functions": 1},
                "artifacts": {"correlated_shards": [shard_path]},
                "timings": {},
            },
        )

    def _fake_python_correlate(func_slice, _debug_type_dictionary):
        for debug_func in func_slice:
            debug_func["func_signature_elems"] = {
                "return_type": ["python"],
                "params": [],
            }
            debug_func["source"] = {
                "source_file": "/python/a.c",
                "source_line": "7",
            }

    monkeypatch.setenv("FI_DEBUG_CORRELATOR_BACKEND", "go")
    monkeypatch.delenv("FI_DEBUG_CORRELATOR_SHADOW", raising=False)
    monkeypatch.setenv("FI_DEBUG_CORRELATOR_STRICT", "1")
    monkeypatch.setenv("FI_DEBUG_CORRELATE_PARALLEL", "0")
    monkeypatch.setattr(
        debug_info.backend_loaders,
        "run_correlator_backend",
        _fake_run_correlator_backend,
    )
    monkeypatch.setattr(debug_info, "_correlate_function_slice", _fake_python_correlate)
    monkeypatch.setattr(
        debug_info, "create_friendly_debug_types", lambda *_args, **_kwargs: None
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(
            debug_info.backend_loaders.CorrelatorBackendError
        ) as exc_info:
            debug_info.correlate_debugged_function_to_debug_types(
                types, funcs, tmpdir, dump_files=False
            )

    assert (
        exc_info.value.reason_code == debug_info.backend_loaders.FI_CORR_PARITY_MISMATCH
    )


def test_create_friendly_debug_types_skips_work_when_dump_disabled(monkeypatch):
    called = {"value": False}

    def _fail_if_called(*_args, **_kwargs):
        called["value"] = True
        raise AssertionError("Should not process friendly types when dump is disabled")

    monkeypatch.setattr(
        debug_info, "extract_func_sig_friendly_type_tags", _fail_if_called
    )

    debug_info.create_friendly_debug_types(
        {
            1: {
                "tag": "DW_TAG_structure_type",
                "name": "S",
            },
            2: {
                "tag": "DW_TAG_member",
                "scope": 1,
                "name": "field",
                "base_type_addr": 3,
            },
        },
        "/tmp",
        dump_files=False,
    )

    assert called["value"] is False


def test_extract_all_functions_in_debug_info_single_pass_parser():
    content = """
## Functions defined in module
Subprogram: foo
  details from /src/foo.c:10
  - Operand Type: DW_TAG_const_type, DW_TAG_pointer_type, int
  - Operand Name: {named_arg}
Subprogram: bar
  details from /src/bar.c:20
  - Operand Type: DW_TAG_pointer_type, char
## Global variables
"""
    all_functions = {}
    all_files = {}
    debug_info.extract_all_functions_in_debug_info(content, all_functions, all_files)

    assert "/src/foo.c10" in all_functions
    assert "/src/bar.c20" in all_functions
    assert all_functions["/src/foo.c10"]["args"] == ["named_arg"]
    assert all_functions["/src/bar.c20"]["args"] == ["char *"]
    assert "/src/foo.c" in all_files
    assert "/src/bar.c" in all_files


def test_load_debug_report_parallel_matches_serial(monkeypatch):
    def _canonicalize(report):
        return {
            key: sorted(
                (json.dumps(item, sort_keys=True) for item in report.get(key, []))
            )
            for key in (
                "all_files_in_project",
                "all_functions_in_project",
                "all_global_variables",
                "all_types",
            )
        }

    content_1 = """
Compile unit: c /src/a.c
## Functions defined in module
Subprogram: f1
  details from /src/a.c:11
  - Operand Type: DW_TAG_pointer_type, char
## Global variables
"""
    content_2 = """
Compile unit: c /src/b.c
## Functions defined in module
Subprogram: f2
  details from /src/b.c:22
  - Operand Name: {arg}
## Global variables
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        f1 = _write_text(tmpdir, "d1.debug", content_1)
        f2 = _write_text(tmpdir, "d2.debug", content_2)
        f3 = _write_text(tmpdir, "d3.debug", content_1)  # duplicate content
        files = [f1, f2, f3]

        monkeypatch.setenv("FI_DEBUG_REPORT_PARALLEL", "0")
        serial_report = debug_info.load_debug_report(files)

        monkeypatch.setenv("FI_DEBUG_REPORT_PARALLEL", "1")
        monkeypatch.setenv("FI_DEBUG_REPORT_WORKERS", "2")
        parallel_report = debug_info.load_debug_report(files)

    assert _canonicalize(serial_report) == _canonicalize(parallel_report)
