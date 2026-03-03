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
"""Tests for the stage_markers module."""

import os
import re
import unittest
from unittest import mock

from fuzz_introspector import stage_markers


class TestEmitWritesLine(unittest.TestCase):
    """emit() writes correctly formatted lines to stage_markers.log."""

    def test_basic_line_written(self, tmp_path=None):
        """A call to emit() creates the file with one correctly-formatted line."""
        import tempfile

        with tempfile.TemporaryDirectory() as out_dir:
            stage_markers.emit(out_dir, "my_stage", "start")
            log_path = os.path.join(out_dir, "stage_markers.log")
            self.assertTrue(os.path.isfile(log_path))
            with open(log_path) as fh:
                lines = fh.readlines()
            self.assertEqual(len(lines), 1)
            line = lines[0]
            # Format: <timestamp> <stage> <event> <json>
            parts = line.strip().split(" ", 3)
            self.assertEqual(len(parts), 4)
            timestamp, stage, event, meta_json = parts
            # Timestamp ends with Z
            self.assertTrue(
                timestamp.endswith("Z"), f"Timestamp should end with Z: {timestamp!r}"
            )
            self.assertEqual(stage, "my_stage")
            self.assertEqual(event, "start")
            import json

            parsed = json.loads(meta_json)
            self.assertEqual(parsed, {})

    def test_line_ends_with_newline(self):
        """Each emitted line ends with a newline character."""
        import tempfile

        with tempfile.TemporaryDirectory() as out_dir:
            stage_markers.emit(out_dir, "s", "e")
            log_path = os.path.join(out_dir, "stage_markers.log")
            with open(log_path) as fh:
                content = fh.read()
            self.assertTrue(content.endswith("\n"))

    def test_metadata_kwargs_serialised_as_compact_json(self):
        """Meta kwargs are rendered as compact JSON in the line."""
        import tempfile
        import json

        with tempfile.TemporaryDirectory() as out_dir:
            stage_markers.emit(out_dir, "stage", "start", files=42, count=7)
            log_path = os.path.join(out_dir, "stage_markers.log")
            with open(log_path) as fh:
                line = fh.readline()
            # Last field is the JSON blob
            meta_json = line.strip().rsplit(" ", 1)[-1]
            parsed = json.loads(meta_json)
            self.assertEqual(parsed.get("files"), 42)
            self.assertEqual(parsed.get("count"), 7)
            # Compact separators: no space after colon or comma
            self.assertNotIn(": ", meta_json)
            self.assertNotIn(", ", meta_json)

    def test_multiple_calls_accumulate(self):
        """Multiple emit() calls append to the same file."""
        import tempfile

        with tempfile.TemporaryDirectory() as out_dir:
            stage_markers.emit(out_dir, "stage", "start")
            stage_markers.emit(out_dir, "stage", "end")
            log_path = os.path.join(out_dir, "stage_markers.log")
            with open(log_path) as fh:
                lines = fh.readlines()
            self.assertEqual(len(lines), 2)
            self.assertIn("start", lines[0])
            self.assertIn("end", lines[1])

    def test_empty_meta_emits_empty_object(self):
        """When no kwargs are given, the JSON field is '{}'."""
        import tempfile

        with tempfile.TemporaryDirectory() as out_dir:
            stage_markers.emit(out_dir, "stage", "event")
            log_path = os.path.join(out_dir, "stage_markers.log")
            with open(log_path) as fh:
                line = fh.readline()
            self.assertTrue(line.strip().endswith("{}"))

    def test_timestamp_matches_iso8601_pattern(self):
        """Timestamp matches ISO-8601 format with trailing Z."""
        import tempfile

        iso_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$")
        with tempfile.TemporaryDirectory() as out_dir:
            stage_markers.emit(out_dir, "s", "e")
            log_path = os.path.join(out_dir, "stage_markers.log")
            with open(log_path) as fh:
                line = fh.readline()
            timestamp = line.split(" ", 1)[0]
            self.assertRegex(timestamp, iso_re)


class TestEmitDisabledByEnv(unittest.TestCase):
    """FI_STAGE_MARKERS=0 suppresses all output."""

    def test_fi_stage_markers_zero_suppresses(self):
        """When FI_STAGE_MARKERS=0, no file is written."""
        import tempfile

        with tempfile.TemporaryDirectory() as out_dir:
            with mock.patch.dict(os.environ, {"FI_STAGE_MARKERS": "0"}):
                stage_markers.emit(out_dir, "stage", "start")
            log_path = os.path.join(out_dir, "stage_markers.log")
            self.assertFalse(os.path.isfile(log_path))

    def test_fi_stage_markers_other_value_does_not_suppress(self):
        """Any value other than '0' does not suppress output."""
        import tempfile

        with tempfile.TemporaryDirectory() as out_dir:
            with mock.patch.dict(os.environ, {"FI_STAGE_MARKERS": "1"}):
                stage_markers.emit(out_dir, "stage", "start")
            log_path = os.path.join(out_dir, "stage_markers.log")
            self.assertTrue(os.path.isfile(log_path))

    def test_fi_stage_markers_unset_enables(self):
        """When FI_STAGE_MARKERS is not set, output is written."""
        import tempfile

        env = {k: v for k, v in os.environ.items() if k != "FI_STAGE_MARKERS"}
        with tempfile.TemporaryDirectory() as out_dir:
            with mock.patch.dict(os.environ, env, clear=True):
                stage_markers.emit(out_dir, "stage", "start")
            log_path = os.path.join(out_dir, "stage_markers.log")
            self.assertTrue(os.path.isfile(log_path))


class TestEmitNoOpOnEmptyOrNoneOutDir(unittest.TestCase):
    """emit() does nothing when out_dir is falsy."""

    def test_none_out_dir_does_nothing(self):
        """emit() with out_dir=None does not raise and writes nothing."""
        # Should not raise
        stage_markers.emit(None, "stage", "start")  # type: ignore[arg-type]

    def test_empty_string_out_dir_does_nothing(self):
        """emit() with out_dir='' does not raise and writes nothing."""
        stage_markers.emit("", "stage", "start")


class TestEmitSilentlyIgnoresIOError(unittest.TestCase):
    """I/O errors are swallowed so observability never breaks the pipeline."""

    def test_oserror_is_ignored(self):
        """When open() raises OSError, emit() does not propagate it."""
        with mock.patch("builtins.open", side_effect=OSError("disk full")):
            # Should not raise
            stage_markers.emit("/some/dir", "stage", "start")


if __name__ == "__main__":
    unittest.main()
