#!/usr/bin/env python3
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
"""Microbenchmark harness for debug-info YAML loading."""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import sys
import time

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

try:
    import resource
except ImportError:  # pragma: no cover - resource is not available on Windows
    resource = None

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
DEFAULT_RESULTS_DIR = REPO_ROOT / "benchmarks" / "results"
SERIAL_MODE = "serial"
THREAD_MODE = "thread"
PROCESS_MODE = "process"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from fuzz_introspector import data_loader, debug_info  # noqa: E402


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=("Benchmark debug-info YAML loading using existing "
                     "fuzz-introspector loader code paths."))
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--target-dir",
        type=Path,
        help=("Directory containing debug artifacts. Uses existing "
              "data_loader.find_all_debug_* helpers."),
    )
    input_group.add_argument(
        "--input-file",
        action="append",
        type=Path,
        default=[],
        help=("Explicit debug YAML file path. Repeat to pass multiple files. "
              "When set, --dataset is ignored."),
    )

    parser.add_argument(
        "--dataset",
        choices=("types", "functions", "both"),
        default="both",
        help="Dataset to benchmark when using --target-dir.",
    )
    parser.add_argument(
        "--mode",
        choices=(SERIAL_MODE, THREAD_MODE, PROCESS_MODE, "all"),
        default="all",
        help="Loader execution mode. 'all' runs serial, thread, then process.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Measured iterations per mode and dataset.",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="Warm-up runs per mode and dataset (excluded from outputs).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=min(os.cpu_count() or 1, 8),
        help="Value for FI_DEBUG_MAX_WORKERS in parallel modes.",
    )
    parser.add_argument(
        "--process-workers",
        type=int,
        default=0,
        help=("Value for FI_DEBUG_PROCESS_WORKERS. Defaults to --max-workers "
              "when unset or <=0."),
    )
    parser.add_argument(
        "--shard-files",
        type=int,
        default=4,
        help="Value for FI_DEBUG_SHARD_FILES.",
    )
    parser.add_argument(
        "--shard-strategy",
        choices=("fixed_count", "size_balanced"),
        default="fixed_count",
        help="Value for FI_DEBUG_SHARD_STRATEGY.",
    )
    parser.add_argument(
        "--max-inflight-shards",
        type=int,
        default=0,
        help=("Value for FI_DEBUG_MAX_INFLIGHT_SHARDS. Disabled if <=0 so "
              "loader default behavior is used."),
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="Directory for benchmark artifacts.",
    )
    parser.add_argument(
        "--output-prefix",
        type=str,
        default="",
        help=("Output file prefix. Defaults to debug_loader_bench_<UTC "
              "timestamp>."),
    )

    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    if args.warmup < 0:
        parser.error("--warmup must be >= 0")
    if args.max_workers < 1:
        parser.error("--max-workers must be >= 1")
    if args.process_workers < 0:
        parser.error("--process-workers must be >= 0")
    if args.shard_files < 1:
        parser.error("--shard-files must be >= 1")
    return args


def _round_optional(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 6)


def _rss_from_proc_statm_mb() -> float | None:
    try:
        with open("/proc/self/statm", "r", encoding="utf-8") as statm_file:
            rss_pages = int(statm_file.read().split()[1])
        page_size = os.sysconf("SC_PAGE_SIZE")
        return rss_pages * page_size / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        return None


def _maxrss_mb() -> float | None:
    if resource is None:
        return None
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
    except (OSError, ValueError, AttributeError):
        return None
    if usage.ru_maxrss > 10**9:
        return usage.ru_maxrss / (1024 * 1024)
    return usage.ru_maxrss / 1024.0


@contextmanager
def _temporary_env(updates: dict[str, str]) -> Iterator[None]:
    sentinel = object()
    previous_values: dict[str, str | object] = {}
    for key, value in updates.items():
        previous_values[key] = os.environ.get(key, sentinel)
        os.environ[key] = value
    try:
        yield
    finally:
        for key, old_value in previous_values.items():
            if old_value is sentinel:
                os.environ.pop(key, None)
            else:
                os.environ[key] = str(old_value)


def _mode_sequence(mode: str) -> list[str]:
    if mode == "all":
        return [SERIAL_MODE, THREAD_MODE, PROCESS_MODE]
    return [mode]


def _discover_datasets(args: argparse.Namespace) -> dict[str, list[str]]:
    if args.input_file:
        explicit_paths = [str(path.resolve()) for path in args.input_file]
        missing_paths = [path for path in explicit_paths if not Path(path).is_file()]
        if missing_paths:
            missing_list = ", ".join(missing_paths)
            raise FileNotFoundError(f"Explicit input file(s) not found: {missing_list}")
        return {"custom": sorted(explicit_paths)}

    target_dir = str(args.target_dir.resolve())
    datasets: dict[str, list[str]] = {}
    if args.dataset in ("types", "both"):
        datasets["types"] = sorted(
            data_loader.find_all_debug_all_types_files(target_dir))
    if args.dataset in ("functions", "both"):
        datasets["functions"] = sorted(
            data_loader.find_all_debug_function_files(target_dir))

    empty_datasets = [name for name, paths in datasets.items() if not paths]
    if empty_datasets:
        joined = ", ".join(empty_datasets)
        raise ValueError(f"No debug YAML files discovered for dataset(s): {joined}")
    return datasets


def _env_for_mode(mode: str, args: argparse.Namespace) -> dict[str, str]:
    env = {
        "FI_DEBUG_SHARD_FILES": str(args.shard_files),
        "FI_DEBUG_SHARD_STRATEGY": args.shard_strategy,
        "FI_DEBUG_MAX_WORKERS": str(args.max_workers),
        "FI_DEBUG_PROCESS_WORKERS": str(
            args.process_workers if args.process_workers > 0 else args.max_workers),
        "FI_DEBUG_ADAPTIVE_WORKERS": "0",
    }
    if args.max_inflight_shards > 0:
        env["FI_DEBUG_MAX_INFLIGHT_SHARDS"] = str(args.max_inflight_shards)

    if mode == SERIAL_MODE:
        env.update({
            "FI_DEBUG_PARALLEL": "0",
            "FI_DEBUG_PARALLEL_BACKEND": THREAD_MODE,
        })
        return env
    if mode == THREAD_MODE:
        env.update({
            "FI_DEBUG_PARALLEL": "1",
            "FI_DEBUG_PARALLEL_BACKEND": THREAD_MODE,
        })
        return env
    if mode == PROCESS_MODE:
        env.update({
            "FI_DEBUG_PARALLEL": "1",
            "FI_DEBUG_PARALLEL_BACKEND": PROCESS_MODE,
        })
        return env
    raise ValueError(f"Unsupported mode: {mode}")


def _execute_one_run(
    dataset_name: str,
    mode: str,
    iteration: int,
    files: list[str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    env = _env_for_mode(mode, args)
    started_utc = datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="milliseconds")
    rss_before_mb = _rss_from_proc_statm_mb()
    maxrss_before_mb = _maxrss_mb()

    with _temporary_env(env):
        wall_started = time.perf_counter()
        status = "ok"
        error_text = ""
        loaded_items_count = 0
        try:
            loaded_items = debug_info.load_debug_all_yaml_files(files)
            loaded_items_count = len(loaded_items)
        except Exception as exc:  # pragma: no cover - defensive
            status = "error"
            error_text = str(exc)
        wall_elapsed = time.perf_counter() - wall_started

    rss_after_mb = _rss_from_proc_statm_mb()
    maxrss_after_mb = _maxrss_mb()
    rss_delta_mb = None
    if rss_before_mb is not None and rss_after_mb is not None:
        rss_delta_mb = rss_after_mb - rss_before_mb

    return {
        "started_utc": started_utc,
        "dataset": dataset_name,
        "mode": mode,
        "iteration": iteration,
        "file_count": len(files),
        "item_count": loaded_items_count,
        "wall_time_sec": _round_optional(wall_elapsed),
        "rss_before_mb": _round_optional(rss_before_mb),
        "rss_after_mb": _round_optional(rss_after_mb),
        "rss_delta_mb": _round_optional(rss_delta_mb),
        "maxrss_before_mb": _round_optional(maxrss_before_mb),
        "maxrss_after_mb": _round_optional(maxrss_after_mb),
        "status": status,
        "error": error_text,
        "shard_files": args.shard_files,
        "max_workers": args.max_workers,
        "process_workers": (
            args.process_workers if args.process_workers > 0 else args.max_workers),
        "max_inflight_shards": args.max_inflight_shards,
        "shard_strategy": args.shard_strategy,
    }


def _summary_by_dataset_mode(records: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        key = (record["dataset"], record["mode"])
        grouped.setdefault(key, []).append(record)

    for (dataset_name, mode), group_records in sorted(grouped.items()):
        ok_records = [record for record in group_records if record["status"] == "ok"]
        wall_times = [record["wall_time_sec"] for record in ok_records]
        item_counts = [record["item_count"] for record in ok_records]
        key = f"{dataset_name}:{mode}"
        summary[key] = {
            "samples": len(group_records),
            "successful_samples": len(ok_records),
            "failed_samples": len(group_records) - len(ok_records),
            "wall_time_sec": {
                "min": min(wall_times) if wall_times else None,
                "max": max(wall_times) if wall_times else None,
                "avg": (sum(wall_times) / len(wall_times)) if wall_times else None,
            },
            "item_count": {
                "min": min(item_counts) if item_counts else None,
                "max": max(item_counts) if item_counts else None,
                "avg": (sum(item_counts) / len(item_counts)) if item_counts else None,
            },
        }
    return summary


def _write_csv(records: list[dict[str, Any]], output_path: Path) -> None:
    fieldnames = [
        "started_utc",
        "dataset",
        "mode",
        "iteration",
        "file_count",
        "item_count",
        "wall_time_sec",
        "rss_before_mb",
        "rss_after_mb",
        "rss_delta_mb",
        "maxrss_before_mb",
        "maxrss_after_mb",
        "status",
        "error",
        "shard_files",
        "max_workers",
        "process_workers",
        "max_inflight_shards",
        "shard_strategy",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(record)


def _write_json(
    records: list[dict[str, Any],
                  ],
    datasets: dict[str, list[str]],
    modes: list[str],
    args: argparse.Namespace,
    output_path: Path,
) -> None:
    payload = {
        "created_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec="seconds"),
        "script": str(Path(__file__).resolve()),
        "datasets": datasets,
        "modes": modes,
        "config": {
            "iterations": args.iterations,
            "warmup": args.warmup,
            "shard_files": args.shard_files,
            "shard_strategy": args.shard_strategy,
            "max_workers": args.max_workers,
            "process_workers": (
                args.process_workers if args.process_workers > 0 else args.max_workers),
            "max_inflight_shards": args.max_inflight_shards,
        },
        "records": records,
        "summary": _summary_by_dataset_mode(records),
    }
    with open(output_path, "w", encoding="utf-8") as json_file:
        json.dump(payload, json_file, indent=2, sort_keys=True)
        json_file.write("\n")


def main() -> int:
    """CLI entrypoint."""
    args = parse_args()
    datasets = _discover_datasets(args)
    modes = _mode_sequence(args.mode)

    output_prefix = args.output_prefix
    if not output_prefix:
        output_prefix = "debug_loader_bench_" + datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    args.results_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.results_dir / f"{output_prefix}_runs.csv"
    json_path = args.results_dir / f"{output_prefix}_runs.json"

    records: list[dict[str, Any]] = []
    for dataset_name, files in sorted(datasets.items()):
        for mode in modes:
            for _ in range(args.warmup):
                _execute_one_run(dataset_name, mode, 0, files, args)
            for iteration in range(1, args.iterations + 1):
                record = _execute_one_run(dataset_name, mode, iteration, files, args)
                records.append(record)
                print(
                    f"dataset={dataset_name} mode={mode} "
                    f"iteration={iteration} status={record['status']} "
                    f"wall_time_sec={(record['wall_time_sec'] or 0.0):.6f} "
                    f"items={record['item_count']}")

    _write_csv(records, csv_path)
    _write_json(records, datasets, modes, args, json_path)

    print(f"Wrote: {csv_path}")
    print(f"Wrote: {json_path}")

    failed_records = [record for record in records if record["status"] != "ok"]
    if failed_records:
        print(f"Runs with errors: {len(failed_records)}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
