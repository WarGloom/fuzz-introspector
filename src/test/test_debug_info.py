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
"""Tests for debug_info module path handling."""

import json
import os
import tempfile
import threading
import time
from unittest import mock

from fuzz_introspector import debug_info


def test_make_path_relative():
    """Test converting absolute paths to relative paths."""
    # Create a temporary directory structure
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = tmpdir
        subdir = os.path.join(base_dir, "project", "src")
        os.makedirs(subdir)

        # Test case 1: File under base_dir
        abs_path = os.path.join(subdir, "file.c")
        result = debug_info._make_path_relative(abs_path, base_dir)
        assert result == "project/src/file.c", (
            f"Expected 'project/src/file.c', got '{result}'"
        )

        # Test case 2: File at base_dir root
        abs_path = os.path.join(base_dir, "main.c")
        result = debug_info._make_path_relative(abs_path, base_dir)
        assert result == "main.c", f"Expected 'main.c', got '{result}'"

        # Test case 3: File outside base_dir - should return original
        abs_path = "/usr/include/stdio.h"
        result = debug_info._make_path_relative(abs_path, base_dir)
        assert result == abs_path, f"Expected original path, got '{result}'"

        # Test case 4: No base_dir provided
        abs_path = "/some/path/file.c"
        result = debug_info._make_path_relative(abs_path, None)
        assert result == abs_path, f"Expected original path, got '{result}'"

        # Test case 5: Empty base_dir
        result = debug_info._make_path_relative(abs_path, "")
        assert result == abs_path, f"Expected original path, got '{result}'"


def test_make_path_absolute():
    """Test converting relative paths to absolute paths."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = tmpdir

        # Test case 1: Relative path
        rel_path = "project/src/file.c"
        result = debug_info._make_path_absolute(rel_path, base_dir)
        expected = os.path.abspath(os.path.join(base_dir, rel_path))
        assert result == expected, f"Expected '{expected}', got '{result}'"

        # Test case 2: Already absolute path
        abs_path = "/usr/include/stdio.h"
        result = debug_info._make_path_absolute(abs_path, base_dir)
        assert result == abs_path, f"Expected original absolute path, got '{result}'"

        # Test case 3: No base_dir provided
        rel_path = "project/src/file.c"
        result = debug_info._make_path_absolute(rel_path, None)
        assert result == rel_path, f"Expected original path, got '{result}'"

        # Test case 4: Empty base_dir
        result = debug_info._make_path_absolute(rel_path, "")
        assert result == rel_path, f"Expected original path, got '{result}'"


def test_dump_debug_report_with_base_dir():
    """Test dump_debug_report with base_dir parameter."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = os.path.join(tmpdir, "output")
        base_dir = os.path.join(tmpdir, "project")
        source_dir = os.path.join(base_dir, "src")
        os.makedirs(source_dir)
        os.makedirs(out_dir)  # Create output directory

        # Create a test source file
        test_file = os.path.join(source_dir, "test.c")
        with open(test_file, "w") as f:
            f.write("int main() { return 0; }")

        # Create report dict with absolute path
        report_dict = {
            "all_files_in_project": [{"source_file": test_file, "language": "c"}],
            "all_functions_in_project": [],
            "all_global_variables": [],
            "all_types": [],
        }

        # Call dump_debug_report with base_dir
        debug_info.dump_debug_report(report_dict, out_dir, base_dir=base_dir)

        # Verify the output
        debug_file = os.path.join(out_dir, "all_debug_info.json")
        assert os.path.isfile(debug_file), "Debug file not created"

        with open(debug_file, "r") as f:
            data = json.load(f)

        # Check that path was converted to relative
        assert len(data["all_files_in_project"]) > 0
        assert data["all_files_in_project"][0]["source_file"] == "src/test.c"

        # Check that path mapping was stored
        assert "_path_mapping" in data
        assert "_base_dir" in data
        assert data["_base_dir"] == base_dir


def test_dump_debug_report_graceful_degradation():
    """Test dump_debug_report handles missing files gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = os.path.join(tmpdir, "output")
        os.makedirs(out_dir)

        # Create report dict with non-existent file
        report_dict = {
            "all_files_in_project": [
                {"source_file": "/nonexistent/path/file.c", "language": "c"}
            ],
            "all_functions_in_project": [],
            "all_global_variables": [],
            "all_types": [],
        }

        # Should not raise exception
        debug_info.dump_debug_report(report_dict, out_dir)

        # Verify the debug file was still created
        debug_file = os.path.join(out_dir, "all_debug_info.json")
        assert os.path.isfile(debug_file), (
            "Debug file should be created even with missing files"
        )


def test_load_debug_report_with_base_dir():
    """Test load_debug_report with base_dir parameter.

    Note: load_debug_report parses LLVM debug text output format,
    not JSON. This test uses the text format.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a debug file in LLVM text format
        debug_file_path = os.path.join(tmpdir, "debug.txt")
        debug_content = """Compile unit: language: c /original/base/project/src/main.c
Function: name: main
Global variable: var1 from /original/base/project/src/main.c:10
"""
        with open(debug_file_path, "w") as f:
            f.write(debug_content)

        # Load with a new base_dir
        new_base = os.path.join(tmpdir, "newproject")
        os.makedirs(new_base)

        result = debug_info.load_debug_report([debug_file_path], base_dir=new_base)

        # The path should be resolved (files should be in the result)
        assert len(result["all_files_in_project"]) > 0


def test_load_debug_report_missing_file():
    """Test load_debug_report handles missing files gracefully.

    Note: load_debug_report parses LLVM debug text output format.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a debug file in LLVM text format with non-existent file
        debug_file_path = os.path.join(tmpdir, "debug.txt")
        debug_content = """Compile unit: language: c /nonexistent/file.c
"""
        with open(debug_file_path, "w") as f:
            f.write(debug_content)

        # Should not raise exception
        result = debug_info.load_debug_report([debug_file_path])

        # Should return the report with the non-existent file
        assert len(result["all_files_in_project"]) == 1
        assert result["all_files_in_project"][0]["source_file"] == "/nonexistent/file.c"


def test_load_yaml_collections_invalid_inmem_cap_env_does_not_spill():
    """Invalid/negative in-memory cap env should behave as disabled cap."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yaml_path = os.path.join(tmpdir, "one.yaml")
        with open(yaml_path, "w") as f:
            f.write(json.dumps([{"id": "one"}]))

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "0",
                    "FI_DEBUG_SHARD_FILES": "1",
                    "FI_DEBUG_SPILL_MB": "0",
                    "FI_DEBUG_MAX_INMEM_MB": "-5",
                }, clear=False):
            with mock.patch.object(debug_info, "_write_spill") as write_spill_mock:
                result = debug_info._load_yaml_collections([yaml_path], "debug-info")

        assert [item["id"] for item in result] == ["one"]
        write_spill_mock.assert_not_called()

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "0",
                    "FI_DEBUG_SHARD_FILES": "1",
                    "FI_DEBUG_SPILL_MB": "0",
                    "FI_DEBUG_MAX_INMEM_MB": "invalid",
                }, clear=False):
            with mock.patch.object(debug_info, "_write_spill") as write_spill_mock:
                result = debug_info._load_yaml_collections([yaml_path], "debug-info")

        assert [item["id"] for item in result] == ["one"]
        write_spill_mock.assert_not_called()


def test_load_yaml_collections_inmem_cap_spills_and_preserves_order():
    """In-memory cap should trigger spills while keeping deterministic output order."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for idx in range(3):
            path = os.path.join(tmpdir, f"shard-{idx}.yaml")
            with open(path, "w") as f:
                f.write(json.dumps([{"id": f"item-{idx}"}]))
            paths.append(path)

        spill_paths = []

        def _tracked_write_spill(items, category):
            fd, spill_path = tempfile.mkstemp(prefix=f"fi-{category}-",
                                              suffix=".json",
                                              dir=tmpdir)
            os.close(fd)
            with open(spill_path, "w") as spill_fp:
                json.dump(items, spill_fp)
            spill_paths.append(spill_path)
            return spill_path, len(items)

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "0",
                    "FI_DEBUG_SHARD_FILES": "1",
                    "FI_DEBUG_SPILL_MB": "0",
                    "FI_DEBUG_MAX_INMEM_MB": "1",
                }, clear=False):
            with mock.patch.object(debug_info,
                                   "_estimate_list_bytes",
                                   return_value=2 * 1024 * 1024):
                with mock.patch.object(debug_info,
                                       "_write_spill",
                                       side_effect=_tracked_write_spill):
                    result = debug_info._load_yaml_collections(paths,
                                                               "debug-info")

        assert [item["id"]
                for item in result] == ["item-0", "item-1", "item-2"]
        assert spill_paths
        for spill_path in spill_paths:
            assert not os.path.exists(spill_path)


def test_load_yaml_collections_size_balanced_strategy_uses_file_size_shards():
    """Size-balanced strategy should derive different shards from file sizes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for idx, payload_size in enumerate([512, 32, 32, 32]):
            path = os.path.join(tmpdir, f"shard-{idx}.yaml")
            payload = json.dumps([{
                "id": f"item-{idx}",
                "filler": "x" * payload_size
            }])
            with open(path, "w") as f:
                f.write(payload)
            paths.append(path)

        seen_shards = []

        def _capture_shard(shard):
            seen_shards.append(tuple(shard))
            return []

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "0",
                    "FI_DEBUG_SHARD_FILES": "2",
                    "FI_DEBUG_SHARD_STRATEGY": "size_balanced",
                }, clear=False):
            with mock.patch.object(debug_info,
                                   "_load_yaml_shard",
                                   side_effect=_capture_shard):
                result = debug_info._load_yaml_collections(paths, "debug-info")

        assert result == []
        assert seen_shards == [(paths[0],), (paths[1], paths[2], paths[3])]


def test_load_yaml_collections_size_balanced_preserves_ordering_parity():
    """Shard strategy should not alter deterministic merged item ordering."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for idx, payload_size in enumerate([800, 32, 32, 32]):
            path = os.path.join(tmpdir, f"shard-{idx}.yaml")
            payload = json.dumps([{
                "id": f"item-{idx}",
                "filler": "x" * payload_size
            }])
            with open(path, "w") as f:
                f.write(payload)
            paths.append(path)

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "0",
                    "FI_DEBUG_SHARD_FILES": "2",
                    "FI_DEBUG_SHARD_STRATEGY": "fixed_count",
                }, clear=False):
            fixed_result = debug_info._load_yaml_collections(paths, "debug-info")

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "0",
                    "FI_DEBUG_SHARD_FILES": "2",
                    "FI_DEBUG_SHARD_STRATEGY": "size_balanced",
                }, clear=False):
            size_balanced_result = debug_info._load_yaml_collections(
                paths, "debug-info")

        assert [item["id"] for item in fixed_result] == [
            "item-0", "item-1", "item-2", "item-3"
        ]
        assert [item["id"] for item in size_balanced_result] == [
            "item-0", "item-1", "item-2", "item-3"
        ]


def test_create_friendly_debug_types_skip_dump_files_avoids_type_walk():
    debug_type_dictionary = {
        1: {
            "tag": "DW_TAG_base_type",
            "name": "int",
            "base_type_addr": 0,
        },
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        with mock.patch.object(debug_info,
                               "extract_func_sig_friendly_type_tags",
                               side_effect=AssertionError("unexpected walk")):
            debug_info.create_friendly_debug_types(debug_type_dictionary,
                                                   tmpdir,
                                                   dump_files=False)

        assert not os.path.exists(
            os.path.join(tmpdir, "all-friendly-debug-types.json"))


def test_create_friendly_debug_types_streaming_dump_writes_valid_json():
    debug_type_dictionary = {
        1: {
            "tag": "DW_TAG_base_type",
            "name": "int",
            "base_type_addr": 0,
            "enum_elems": [],
        },
        2: {
            "tag": "DW_TAG_pointer_type",
            "name": "",
            "base_type_addr": 1,
            "enum_elems": [],
        },
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        debug_info.create_friendly_debug_types(debug_type_dictionary,
                                               tmpdir,
                                               dump_files=True)
        output_path = os.path.join(tmpdir, "all-friendly-debug-types.json")
        assert os.path.exists(output_path)

        with open(output_path, "r") as f:
            dumped = json.load(f)

        assert set(dumped.keys()) == {"1", "2"}
        assert "friendly-info" in dumped["1"]
        assert dumped["1"]["friendly-info"]["string_type"]


def test_load_yaml_collections_largest_spill_policy_spills_largest_shard():
    """Largest spill policy should select the largest in-memory shard first."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for idx in range(3):
            path = os.path.join(tmpdir, f"shard-{idx}.yaml")
            with open(path, "w") as f:
                f.write(json.dumps([{"id": f"item-{idx}", "size": [2, 9, 3][idx]}]))
            paths.append(path)

        spilled_ids = []

        def _tracked_write_spill(items, category):
            spilled_ids.append(items[0]["id"])
            fd, spill_path = tempfile.mkstemp(prefix=f"fi-{category}-",
                                              suffix=".json",
                                              dir=tmpdir)
            os.close(fd)
            with open(spill_path, "w") as spill_fp:
                json.dump(items, spill_fp)
            return spill_path, len(items)

        def _fake_estimate(items):
            return int(items[0]["size"]) * 1024 * 1024

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "0",
                    "FI_DEBUG_SHARD_FILES": "1",
                    "FI_DEBUG_SPILL_MB": "0",
                    "FI_DEBUG_MAX_INMEM_MB": "10",
                    "FI_DEBUG_SPILL_POLICY": "largest",
                }, clear=False):
            with mock.patch.object(debug_info,
                                   "_estimate_list_bytes",
                                   side_effect=_fake_estimate):
                with mock.patch.object(debug_info,
                                       "_write_spill",
                                       side_effect=_tracked_write_spill):
                    result = debug_info._load_yaml_collections(paths,
                                                               "debug-info")

        assert spilled_ids
        assert spilled_ids[0] == "item-1"
        assert [item["id"]
                for item in result] == ["item-0", "item-1", "item-2"]


def test_load_yaml_collections_invalid_spill_policy_defaults_to_oldest():
    """Invalid spill policy should retain default oldest spill selection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for idx in range(3):
            path = os.path.join(tmpdir, f"shard-{idx}.yaml")
            with open(path, "w") as f:
                f.write(json.dumps([{"id": f"item-{idx}", "size": [2, 9, 3][idx]}]))
            paths.append(path)

        spilled_ids = []

        def _tracked_write_spill(items, category):
            spilled_ids.append(items[0]["id"])
            fd, spill_path = tempfile.mkstemp(prefix=f"fi-{category}-",
                                              suffix=".json",
                                              dir=tmpdir)
            os.close(fd)
            with open(spill_path, "w") as spill_fp:
                json.dump(items, spill_fp)
            return spill_path, len(items)

        def _fake_estimate(items):
            return int(items[0]["size"]) * 1024 * 1024

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "0",
                    "FI_DEBUG_SHARD_FILES": "1",
                    "FI_DEBUG_SPILL_MB": "0",
                    "FI_DEBUG_MAX_INMEM_MB": "10",
                    "FI_DEBUG_SPILL_POLICY": "invalid",
                }, clear=False):
            with mock.patch.object(debug_info,
                                   "_estimate_list_bytes",
                                   side_effect=_fake_estimate):
                with mock.patch.object(debug_info,
                                       "_write_spill",
                                       side_effect=_tracked_write_spill):
                    result = debug_info._load_yaml_collections(paths,
                                                               "debug-info")

        assert spilled_ids
        assert spilled_ids[0] == "item-0"
        assert [item["id"]
                for item in result] == ["item-0", "item-1", "item-2"]


def test_load_yaml_collections_max_inflight_shards_limits_parallelism_and_order(
):
    """In-flight cap should bound concurrent shard loading and keep ordering."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for idx in range(8):
            path = os.path.join(tmpdir, f"shard-{idx}.yaml")
            with open(path, "w") as f:
                f.write(json.dumps([{"id": f"item-{idx}"}]))
            paths.append(path)

        active_calls = 0
        max_active_calls = 0
        lock = threading.Lock()

        def _slow_load_yaml_shard(shard):
            nonlocal active_calls
            nonlocal max_active_calls
            with lock:
                active_calls += 1
                max_active_calls = max(max_active_calls, active_calls)
            try:
                time.sleep(0.02)
                path = shard[0]
                idx = int(os.path.basename(path).split("-")[1].split(".")[0])
                return [{"id": f"item-{idx}"}]
            finally:
                with lock:
                    active_calls -= 1

        with mock.patch.dict(
                os.environ, {
                    "FI_DEBUG_PARALLEL": "1",
                    "FI_DEBUG_MAX_WORKERS": "4",
                    "FI_DEBUG_SHARD_FILES": "1",
                    "FI_DEBUG_USE_PROCESS_POOL": "0",
                    "FI_DEBUG_MAX_INFLIGHT_SHARDS": "2",
                }, clear=False):
            with mock.patch.object(debug_info,
                                   "_load_yaml_shard",
                                   side_effect=_slow_load_yaml_shard):
                result = debug_info._load_yaml_collections(paths, "debug-info")

        assert max_active_calls <= 2
        assert [item["id"] for item in result] == [f"item-{idx}" for idx in range(8)]


def test_load_yaml_collections_adaptive_workers_knob_controls_downshift():
    """Adaptive downshift should only activate when the env knob is enabled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for idx in range(6):
            path = os.path.join(tmpdir, f"shard-{idx}.yaml")
            with open(path, "w") as f:
                f.write(json.dumps([{"id": f"item-{idx}"}]))
            paths.append(path)

        def _run_with_adaptive(enabled: bool) -> tuple[list[str], int]:
            env = {
                "FI_DEBUG_PARALLEL": "1",
                "FI_DEBUG_MAX_WORKERS": "4",
                "FI_DEBUG_SHARD_FILES": "1",
                "FI_DEBUG_USE_PROCESS_POOL": "0",
                "FI_DEBUG_MAX_INFLIGHT_SHARDS": "4",
                "FI_DEBUG_SPILL_MB": "0",
                "FI_DEBUG_MAX_INMEM_MB": "1",
                "FI_DEBUG_ADAPTIVE_WORKERS": "1" if enabled else "0",
            }
            with mock.patch.dict(os.environ, env, clear=False):
                with mock.patch.object(debug_info,
                                       "_estimate_list_bytes",
                                       return_value=2 * 1024 * 1024):
                    with mock.patch.object(debug_info.logger,
                                           "info",
                                           wraps=debug_info.logger.info) as info_mock:
                        result = debug_info._load_yaml_collections(
                            paths, "debug-info")
            downshift_count = sum(
                1 for call in info_mock.call_args_list
                if call.args and "Adaptive worker downshift" in call.args[0])
            return [item["id"] for item in result], downshift_count

        ids_disabled, downshifts_disabled = _run_with_adaptive(False)
        ids_enabled, downshifts_enabled = _run_with_adaptive(True)

        assert ids_disabled == [f"item-{idx}" for idx in range(6)]
        assert ids_enabled == [f"item-{idx}" for idx in range(6)]
        assert downshifts_disabled == 0
        assert downshifts_enabled > 0


def test_load_yaml_collections_adaptive_workers_deterministic_output():
    """Adaptive mode should preserve deterministic output and stable behavior."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for idx in range(8):
            path = os.path.join(tmpdir, f"shard-{idx}.yaml")
            with open(path, "w") as f:
                f.write(json.dumps([{"id": f"item-{idx}"}]))
            paths.append(path)

        env = {
            "FI_DEBUG_PARALLEL": "1",
            "FI_DEBUG_MAX_WORKERS": "4",
            "FI_DEBUG_SHARD_FILES": "1",
            "FI_DEBUG_USE_PROCESS_POOL": "0",
            "FI_DEBUG_MAX_INFLIGHT_SHARDS": "4",
            "FI_DEBUG_SPILL_MB": "0",
            "FI_DEBUG_MAX_INMEM_MB": "1",
            "FI_DEBUG_ADAPTIVE_WORKERS": "1",
        }

        def _run_once() -> tuple[list[str], int]:
            with mock.patch.dict(os.environ, env, clear=False):
                with mock.patch.object(debug_info,
                                       "_estimate_list_bytes",
                                       return_value=2 * 1024 * 1024):
                    with mock.patch.object(debug_info.logger,
                                           "info",
                                           wraps=debug_info.logger.info) as info_mock:
                        result = debug_info._load_yaml_collections(
                            paths, "debug-info")
            downshift_count = sum(
                1 for call in info_mock.call_args_list
                if call.args and "Adaptive worker downshift" in call.args[0])
            return [item["id"] for item in result], downshift_count

        ids_run_one, downshifts_run_one = _run_once()
        ids_run_two, downshifts_run_two = _run_once()

        expected_ids = [f"item-{idx}" for idx in range(8)]
        assert ids_run_one == expected_ids
        assert ids_run_two == expected_ids
        assert downshifts_run_one > 0
        assert downshifts_run_one == downshifts_run_two
