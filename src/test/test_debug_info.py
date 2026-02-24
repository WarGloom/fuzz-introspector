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
