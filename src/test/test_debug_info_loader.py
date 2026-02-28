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
        monkeypatch.setattr(debug_info.backend_loaders, "load_json_with_backend",
                            _fake_loader)
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
            _write_yaml(tmpdir, "f0.yaml", [{
                "idx": 0
            }]),
            _write_yaml(tmpdir, "f1.yaml", [{
                "idx": 1
            }]),
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


def test_load_debug_all_yaml_files_deterministic_serial_vs_parallel(
        monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        files = [
            _write_yaml(tmpdir, "a.yaml", [{
                "name": "a"
            }]),
            _write_yaml(tmpdir, "b.yaml", [{
                "name": "b"
            }]),
            _write_yaml(tmpdir, "c.yaml", [{
                "name": "c"
            }]),
            _write_yaml(tmpdir, "d.yaml", [{
                "name": "d"
            }]),
        ]
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "2")
        serial_items = debug_info.load_debug_all_yaml_files(files)

        monkeypatch.setenv("FI_DEBUG_PARALLEL", "1")
        monkeypatch.setenv("FI_DEBUG_MAX_WORKERS", "2")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "2")
        parallel_items = debug_info.load_debug_all_yaml_files(files)

    assert serial_items == parallel_items
    assert serial_items == [{
        "name": "a"
    }, {
        "name": "b"
    }, {
        "name": "c"
    }, {
        "name": "d"
    }]


def test_load_debug_all_yaml_files_parallel_executor_failure_falls_back(
        monkeypatch):

    class _Future:

        def __init__(self, should_fail):
            self._should_fail = should_fail

        def result(self):
            if self._should_fail:
                raise RuntimeError("forced submit/result failure")
            return []

    class _Executor:

        def __init__(self, max_workers):
            self._submitted = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def submit(self, *_args, **_kwargs):
            future = _Future(should_fail=self._submitted == 0)
            self._submitted += 1
            return future

    def _fake_as_completed(futures):
        return list(futures)

    def _fake_wait(futures, timeout=None, return_when=None):
        del timeout
        del return_when
        return set(futures), set()

    with tempfile.TemporaryDirectory() as tmpdir:
        files = [
            _write_yaml(tmpdir, "f0.yaml", [{
                "idx": 0
            }]),
            _write_yaml(tmpdir, "f1.yaml", [{
                "idx": 1
            }]),
            _write_yaml(tmpdir, "f2.yaml", [{
                "idx": 2
            }]),
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


def test_load_debug_all_yaml_files_spill_activation(monkeypatch):
    spill_count = {"count": 0}
    original_write_spill = debug_info._write_spill

    def _counting_write_spill(items, category):
        spill_count["count"] += 1
        return original_write_spill(items, category)

    with tempfile.TemporaryDirectory() as tmpdir:
        files = [
            _write_yaml(tmpdir, "f0.yaml", [{
                "idx": 0
            }]),
            _write_yaml(tmpdir, "f1.yaml", [{
                "idx": 1
            }]),
            _write_yaml(tmpdir, "f2.yaml", [{
                "idx": 2
            }]),
        ]
        monkeypatch.setenv("FI_DEBUG_PARALLEL", "0")
        monkeypatch.setenv("FI_DEBUG_SHARD_FILES", "1")
        monkeypatch.setenv("FI_DEBUG_SPILL_MB", "1")
        monkeypatch.setattr(debug_info, "_estimate_list_bytes",
                            lambda items: 1024 * 1024 if items else 0)
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
    debug_info.correlate_debugged_function_to_debug_types(
        types, funcs, "/tmp", False)
    assert "func_signature_elems" in funcs[0]
    assert "source" in funcs[0]


def test_create_friendly_debug_types_skips_work_when_dump_disabled(monkeypatch):
    called = {"value": False}

    def _fail_if_called(*_args, **_kwargs):
        called["value"] = True
        raise AssertionError("Should not process friendly types when dump is disabled")

    monkeypatch.setattr(debug_info, "extract_func_sig_friendly_type_tags",
                        _fail_if_called)

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
    debug_info.extract_all_functions_in_debug_info(content, all_functions,
                                                   all_files)

    assert "/src/foo.c10" in all_functions
    assert "/src/bar.c20" in all_functions
    assert all_functions["/src/foo.c10"]["args"] == ["named_arg"]
    assert all_functions["/src/bar.c20"]["args"] == ["char *"]
    assert "/src/foo.c" in all_files
    assert "/src/bar.c" in all_files


def test_load_debug_report_parallel_matches_serial(monkeypatch):
    def _canonicalize(report):
        return {
            key: sorted((json.dumps(item, sort_keys=True)
                         for item in report.get(key, [])))
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
