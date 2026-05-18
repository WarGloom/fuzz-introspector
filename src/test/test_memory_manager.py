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
"""Tests for memory_manager module and FI_NATIVE_BACKENDS unified flag."""

import os
import unittest
from unittest import mock

from fuzz_introspector import backend_loaders, memory_manager


class TestGetAvailableMemoryGb(unittest.TestCase):
    """get_available_memory_gb returns a positive float."""

    def test_returns_positive_float(self) -> None:
        result = memory_manager.get_available_memory_gb()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0.0)


class TestGetRecommendedWorkerCount(unittest.TestCase):
    """get_recommended_worker_count honours FI_MAX_WORKERS."""

    def test_fi_max_workers_caps_result(self) -> None:
        with mock.patch.dict(os.environ, {"FI_MAX_WORKERS": "4"}, clear=False):
            # Remove any competing env vars so FI_MAX_WORKERS is the only cap.
            env = {k: v for k, v in os.environ.items() if k != "FI_MAX_RSS_GB"}
            env["FI_MAX_WORKERS"] = "4"
            with mock.patch.dict(os.environ, env, clear=True):
                result = memory_manager.get_recommended_worker_count()
        self.assertLessEqual(result, 4)
        self.assertGreaterEqual(result, 1)

    def test_returns_at_least_one(self) -> None:
        with mock.patch.dict(os.environ, {"FI_MAX_WORKERS": "1"}, clear=False):
            result = memory_manager.get_recommended_worker_count()
        self.assertGreaterEqual(result, 1)


class TestCheckMemoryPressure(unittest.TestCase):
    """check_memory_pressure returns 'critical' when RSS > 80% of ceiling."""

    def test_critical_when_rss_exceeds_ceiling(self) -> None:
        # Set ceiling to 0.1 GB; any real process will exceed it.
        with mock.patch.dict(os.environ, {"FI_MAX_RSS_GB": "0.001"}, clear=False):
            # Force a non-trivial RSS value that exceeds 80% of 0.001 GB.
            with mock.patch.object(
                memory_manager, "_get_process_rss_gb", return_value=0.002
            ):
                result = memory_manager.check_memory_pressure()
        self.assertEqual(result, "critical")

    def test_normal_when_rss_well_below_ceiling(self) -> None:
        with mock.patch.dict(os.environ, {"FI_MAX_RSS_GB": "100.0"}, clear=False):
            with mock.patch.object(
                memory_manager, "_get_process_rss_gb", return_value=0.1
            ):
                result = memory_manager.check_memory_pressure()
        self.assertEqual(result, "normal")

    def test_elevated_band(self) -> None:
        # RSS = 0.7 GB, ceiling = 1.0 GB → 70% → elevated.
        with mock.patch.dict(os.environ, {"FI_MAX_RSS_GB": "1.0"}, clear=False):
            with mock.patch.object(
                memory_manager, "_get_process_rss_gb", return_value=0.7
            ):
                result = memory_manager.check_memory_pressure()
        self.assertEqual(result, "elevated")


class TestParseNativeBackendsEnv(unittest.TestCase):
    """parse_native_backends_env returns the correct backend."""

    def test_rust_when_set(self) -> None:
        with mock.patch.dict(os.environ, {"FI_NATIVE_BACKENDS": "rust"}, clear=False):
            result = backend_loaders.parse_native_backends_env()
        self.assertEqual(result, "rust")

    def test_default_python_when_unset(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "FI_NATIVE_BACKENDS"}
        with mock.patch.dict(os.environ, env, clear=True):
            result = backend_loaders.parse_native_backends_env()
        self.assertEqual(result, "python")

    def test_go_when_set(self) -> None:
        with mock.patch.dict(os.environ, {"FI_NATIVE_BACKENDS": "go"}, clear=False):
            result = backend_loaders.parse_native_backends_env()
        self.assertEqual(result, "go")

    def test_invalid_falls_back_to_python(self) -> None:
        with mock.patch.dict(os.environ, {"FI_NATIVE_BACKENDS": "cobol"}, clear=False):
            result = backend_loaders.parse_native_backends_env()
        self.assertEqual(result, "python")


class TestResolveComponentBackend(unittest.TestCase):
    """resolve_component_backend priority: component > FI_NATIVE_BACKENDS > default."""

    def test_global_flag_used_when_component_unset(self) -> None:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("FI_DEBUG_YAML_LOADER", "FI_NATIVE_BACKENDS")
        }
        env["FI_NATIVE_BACKENDS"] = "rust"
        with mock.patch.dict(os.environ, env, clear=True):
            result = backend_loaders.resolve_component_backend("FI_DEBUG_YAML_LOADER")
        self.assertEqual(result, "rust")

    def test_component_var_overrides_global_flag(self) -> None:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("FI_DEBUG_YAML_LOADER", "FI_NATIVE_BACKENDS")
        }
        env["FI_NATIVE_BACKENDS"] = "rust"
        env["FI_DEBUG_YAML_LOADER"] = "go"
        with mock.patch.dict(os.environ, env, clear=True):
            result = backend_loaders.resolve_component_backend("FI_DEBUG_YAML_LOADER")
        self.assertEqual(result, "go")

    def test_default_used_when_both_unset(self) -> None:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("FI_DEBUG_YAML_LOADER", "FI_NATIVE_BACKENDS")
        }
        with mock.patch.dict(os.environ, env, clear=True):
            result = backend_loaders.resolve_component_backend(
                "FI_DEBUG_YAML_LOADER",
                default_backend=backend_loaders.BACKEND_PYTHON,
            )
        self.assertEqual(result, "python")


class TestMemoryAwareContext(unittest.TestCase):
    """MemoryAwareContext records a positive peak RSS."""

    def test_peak_rss_positive(self) -> None:
        with mock.patch.object(memory_manager, "_get_process_rss_gb", return_value=0.5):
            with memory_manager.MemoryAwareContext("test-block") as ctx:
                pass
        self.assertGreater(ctx.peak_rss_gb, 0.0)

    def test_peak_rss_at_least_entry_rss(self) -> None:
        call_count = [0]

        def _mock_rss() -> float:
            call_count[0] += 1
            # Return increasing RSS values so peak > entry.
            return 0.3 * call_count[0]

        with mock.patch.object(
            memory_manager, "_get_process_rss_gb", side_effect=_mock_rss
        ):
            with memory_manager.MemoryAwareContext("rss-growth") as ctx:
                pass

        self.assertGreaterEqual(ctx.peak_rss_gb, ctx.entry_rss_gb)

    def test_label_stored(self) -> None:
        with memory_manager.MemoryAwareContext("my-label") as ctx:
            pass
        self.assertEqual(ctx.label, "my-label")


if __name__ == "__main__":
    unittest.main()
