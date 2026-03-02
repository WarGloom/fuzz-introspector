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
"""Memory awareness helpers: RAM detection, worker scaling, and RSS monitoring."""

import logging
import os
import time
import types

logger = logging.getLogger(__name__)

# Lazy import so the module loads even without psutil installed.
try:
    import psutil as _psutil

    _PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    _psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False
    logger.warning(
        "psutil is not installed; memory_manager will use conservative "
        "defaults. Install psutil for accurate memory detection."
    )

# Conservative defaults used when psutil is unavailable.
_FALLBACK_AVAILABLE_GB = 2.0
_FALLBACK_TOTAL_GB = 8.0
_FALLBACK_CPU_COUNT = 2

# Pressure thresholds (fraction of ceiling).
_ELEVATED_THRESHOLD = 0.60
_CRITICAL_THRESHOLD = 0.80


def get_available_memory_gb() -> float:
    """Return available system RAM in GB.

    Uses psutil.virtual_memory().available.  Falls back to a conservative
    default (2 GB) if psutil is not installed.
    """
    if not _PSUTIL_AVAILABLE:
        return _FALLBACK_AVAILABLE_GB
    return _psutil.virtual_memory().available / (1024**3)


def _get_total_memory_gb() -> float:
    """Return total system RAM in GB (internal helper)."""
    if not _PSUTIL_AVAILABLE:
        return _FALLBACK_TOTAL_GB
    return _psutil.virtual_memory().total / (1024**3)


def _get_cpu_count() -> int:
    """Return logical CPU count (internal helper)."""
    if _PSUTIL_AVAILABLE:
        count = _psutil.cpu_count(logical=True)
        if count:
            return count
    count = os.cpu_count()
    return count if count else _FALLBACK_CPU_COUNT


def _get_process_rss_gb() -> float:
    """Return current process RSS in GB (internal helper)."""
    if not _PSUTIL_AVAILABLE:
        return 0.0
    try:
        return _psutil.Process().memory_info().rss / (1024**3)
    except _psutil.Error:
        return 0.0


def get_recommended_worker_count(
    per_worker_gb_estimate: float = 1.0,
    max_workers: int | None = None,
) -> int:
    """Return a recommended parallel worker count.

    Resolution order:
    1. ``FI_MAX_WORKERS`` env var (hard override if set and valid).
    2. Minimum of CPU-based and memory-based ceilings.
    3. ``max_workers`` argument acts as an additional upper bound.

    ``FI_MAX_RSS_GB`` is respected: if the effective memory ceiling leaves
    room for fewer workers than the CPU count, the memory ceiling wins.

    Always returns at least 1.
    """
    # FI_MAX_WORKERS env override.
    raw_max_workers = os.environ.get("FI_MAX_WORKERS", "").strip()
    if raw_max_workers:
        try:
            env_limit = int(raw_max_workers)
            if env_limit > 0:
                logger.debug("FI_MAX_WORKERS=%d overrides worker count", env_limit)
                if max_workers is not None:
                    env_limit = min(env_limit, max_workers)
                return max(1, env_limit)
        except ValueError:
            logger.warning("Invalid FI_MAX_WORKERS=%r; ignoring", raw_max_workers)

    # Memory ceiling: use FI_MAX_RSS_GB if set, else 75% of total RAM.
    raw_max_rss = os.environ.get("FI_MAX_RSS_GB", "").strip()
    if raw_max_rss:
        try:
            rss_ceiling_gb = float(raw_max_rss)
        except ValueError:
            logger.warning("Invalid FI_MAX_RSS_GB=%r; ignoring", raw_max_rss)
            rss_ceiling_gb = _get_total_memory_gb() * 0.75
    else:
        rss_ceiling_gb = _get_total_memory_gb() * 0.75

    if per_worker_gb_estimate > 0:
        memory_based = max(1, int(rss_ceiling_gb / per_worker_gb_estimate))
    else:
        memory_based = _get_cpu_count()

    cpu_based = _get_cpu_count()
    recommended = min(cpu_based, memory_based)

    if max_workers is not None:
        recommended = min(recommended, max_workers)

    return max(1, recommended)


def check_memory_pressure() -> str:
    """Return current memory pressure level as a string.

    Levels:
    - ``'normal'``:   current RSS < 60 % of ceiling.
    - ``'elevated'``: current RSS is 60–80 % of ceiling.
    - ``'critical'``: current RSS > 80 % of ceiling.

    The ceiling is ``FI_MAX_RSS_GB`` if set, otherwise 75 % of total RAM.
    """
    raw_max_rss = os.environ.get("FI_MAX_RSS_GB", "").strip()
    if raw_max_rss:
        try:
            ceiling_gb = float(raw_max_rss)
        except ValueError:
            logger.warning("Invalid FI_MAX_RSS_GB=%r; ignoring", raw_max_rss)
            ceiling_gb = _get_total_memory_gb() * 0.75
    else:
        ceiling_gb = _get_total_memory_gb() * 0.75

    current_rss_gb = _get_process_rss_gb()

    if ceiling_gb <= 0:
        return "normal"

    fraction = current_rss_gb / ceiling_gb
    if fraction >= _CRITICAL_THRESHOLD:
        return "critical"
    if fraction >= _ELEVATED_THRESHOLD:
        return "elevated"
    return "normal"


class MemoryAwareContext:
    """Context manager that monitors RSS during a block of code.

    Records peak RSS and logs a warning when memory pressure is elevated
    or critical.

    Usage::

        with MemoryAwareContext("debug-correlation") as ctx:
            run_correlation()
        logger.info("Peak RSS during correlation: %.1f GB", ctx.peak_rss_gb)

    Attributes:
        label: Descriptive label used in log messages.
        peak_rss_gb: Peak RSS (in GB) observed inside the ``with`` block.
        entry_rss_gb: RSS (in GB) at the start of the ``with`` block.
    """

    def __init__(self, label: str = "block") -> None:
        self.label = label
        self.peak_rss_gb: float = 0.0
        self.entry_rss_gb: float = 0.0
        self._start_time: float = 0.0

    def __enter__(self) -> "MemoryAwareContext":
        self.entry_rss_gb = _get_process_rss_gb()
        self.peak_rss_gb = self.entry_rss_gb
        self._start_time = time.perf_counter()
        logger.debug(
            "[memory] %s started; entry RSS=%.3f GB",
            self.label,
            self.entry_rss_gb,
        )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        exit_rss_gb = _get_process_rss_gb()
        self.peak_rss_gb = max(self.peak_rss_gb, exit_rss_gb)
        elapsed = time.perf_counter() - self._start_time

        pressure = check_memory_pressure()
        if pressure == "critical":
            logger.warning(
                "[memory] %s finished in %.2fs; peak RSS=%.3f GB "
                "(CRITICAL memory pressure)",
                self.label,
                elapsed,
                self.peak_rss_gb,
            )
        elif pressure == "elevated":
            logger.warning(
                "[memory] %s finished in %.2fs; peak RSS=%.3f GB "
                "(elevated memory pressure)",
                self.label,
                elapsed,
                self.peak_rss_gb,
            )
        else:
            logger.debug(
                "[memory] %s finished in %.2fs; peak RSS=%.3f GB",
                self.label,
                elapsed,
                self.peak_rss_gb,
            )
