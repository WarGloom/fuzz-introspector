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
"""Benchmark analysis plugin runs across loader backend configurations."""

from __future__ import annotations

import argparse
import itertools
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

TIME_MARKER = "__FI_PERF__"
TIME_FORMAT = f"{TIME_MARKER}%e|%M|%P"


@dataclass(frozen=True)
class BackendMatrix:
    debug_yaml_loader: str
    profile_yaml_loader: str
    llvm_cov_loader: str

    def as_env(self) -> dict[str, str]:
        return {
            "FI_DEBUG_YAML_LOADER": self.debug_yaml_loader,
            "FI_PROFILE_YAML_LOADER": self.profile_yaml_loader,
            "FI_LLVM_COV_LOADER": self.llvm_cov_loader,
        }

    def label(self) -> str:
        return (
            f"debug_yaml={self.debug_yaml_loader},"
            f"profile_yaml={self.profile_yaml_loader},"
            f"llvm_cov={self.llvm_cov_loader}"
        )


def _sanitize_name(raw_name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_"
                   for ch in raw_name)


def _default_plugins() -> list[str]:
    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))
    from fuzz_introspector import analysis  # pylint: disable=import-outside-toplevel

    return [analysis_cls.get_name() for analysis_cls in analysis.get_all_analyses()]


def _parse_time_metrics(stderr: str) -> dict[str, Any]:
    for line in stderr.splitlines():
        if not line.startswith(TIME_MARKER):
            continue
        metrics = line[len(TIME_MARKER):].strip().split("|")
        if len(metrics) != 3:
            continue
        elapsed_str, max_rss_kb_str, cpu_percent_str = metrics
        try:
            elapsed_seconds = float(elapsed_str)
        except ValueError:
            elapsed_seconds = None
        try:
            max_rss_kb = int(max_rss_kb_str)
        except ValueError:
            max_rss_kb = None
        cpu_percent = cpu_percent_str.strip()
        return {
            "elapsed_seconds": elapsed_seconds,
            "max_rss_kb": max_rss_kb,
            "cpu_percent": cpu_percent,
        }
    return {
        "elapsed_seconds": None,
        "max_rss_kb": None,
        "cpu_percent": "",
    }


def _build_backend_matrix(
        debug_yaml_loaders: list[str],
        profile_yaml_loaders: list[str],
        llvm_cov_loaders: list[str]) -> list[BackendMatrix]:
    matrix: list[BackendMatrix] = []
    for debug_yaml_loader, profile_yaml_loader, llvm_cov_loader in itertools.product(
            debug_yaml_loaders,
            profile_yaml_loaders,
            llvm_cov_loaders,
    ):
        matrix.append(
            BackendMatrix(
                debug_yaml_loader=debug_yaml_loader,
                profile_yaml_loader=profile_yaml_loader,
                llvm_cov_loader=llvm_cov_loader,
            ))
    return matrix


def _run_single_case(
    python_bin: str,
    target_dir: str,
    coverage_url: str,
    language: str,
    run_out_dir: str,
    report_name: str,
    plugin_name: str,
    backend_matrix: BackendMatrix,
    env_overrides: dict[str, str],
) -> dict[str, Any]:
    target_dir = os.path.abspath(target_dir)
    cmd = [
        "/usr/bin/time",
        "-f",
        TIME_FORMAT,
        python_bin,
        str(SRC_DIR / "main.py"),
        "report",
        "--target-dir",
        target_dir,
        "--coverage-url",
        coverage_url,
        "--language",
        language,
        "--name",
        report_name,
        "--analyses",
        plugin_name,
        "--output-json",
        plugin_name,
    ]

    env = os.environ.copy()
    env.update(backend_matrix.as_env())
    env["PYTHONPATH"] = str(SRC_DIR)
    env.update(env_overrides)

    if os.path.isdir(run_out_dir):
        shutil.rmtree(run_out_dir)
    os.makedirs(run_out_dir, exist_ok=True)

    process = subprocess.run(
        cmd,
        cwd=run_out_dir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    metrics = _parse_time_metrics(process.stderr)
    return {
        "plugin": plugin_name,
        "backend_matrix": backend_matrix.__dict__,
        "return_code": process.returncode,
        "metrics": metrics,
        "stderr_tail": process.stderr.splitlines()[-30:],
        "stdout_tail": process.stdout.splitlines()[-30:],
        "out_dir": run_out_dir,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--language", default="c-cpp")
    parser.add_argument("--coverage-url", default="/covreport/linux")
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument("--work-dir", default=str(REPO_ROOT / "benchmarks" /
                                                  "results"))
    parser.add_argument("--report-name", default="plugin-perf-bench")
    parser.add_argument("--output-json",
                        default=str(REPO_ROOT / "benchmarks" / "results" /
                                    "plugin_backend_perf_results.json"))
    parser.add_argument("--plugins", nargs="+", default=_default_plugins())
    parser.add_argument("--debug-yaml-loaders",
                        nargs="+",
                        default=["python"])
    parser.add_argument("--profile-yaml-loaders",
                        nargs="+",
                        default=["python"])
    parser.add_argument("--llvm-cov-loaders",
                        nargs="+",
                        default=["python"])
    parser.add_argument(
        "--src-dir",
        default="",
        help="Optional SRC environment value passed to benchmark runs.",
    )
    parser.add_argument(
        "--disable-calltree-bitmap",
        action="store_true",
        help="Set FI_CALLTREE_BITMAP_MAX_NODES=0 for benchmark runs.",
    )
    parser.add_argument(
        "--set-env",
        action="append",
        default=[],
        help="Additional KEY=VALUE env override (repeatable).",
    )
    args = parser.parse_args()

    matrix = _build_backend_matrix(args.debug_yaml_loaders,
                                   args.profile_yaml_loaders,
                                   args.llvm_cov_loaders)
    os.makedirs(args.work_dir, exist_ok=True)

    print(f"Plugins: {len(args.plugins)}")
    print(f"Backend combinations: {len(matrix)}")

    env_overrides: dict[str, str] = {}
    if args.src_dir:
        env_overrides["SRC"] = args.src_dir
    if args.disable_calltree_bitmap:
        env_overrides["FI_CALLTREE_BITMAP_MAX_NODES"] = "0"
    for env_kv in args.set_env:
        if "=" not in env_kv:
            raise ValueError(
                f"Invalid --set-env value {env_kv!r}; expected KEY=VALUE")
        key, value = env_kv.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(
                f"Invalid --set-env value {env_kv!r}; key cannot be empty")
        env_overrides[key] = value

    results: list[dict[str, Any]] = []
    total_cases = len(args.plugins) * len(matrix)
    completed = 0
    for plugin_name in args.plugins:
        for backend_matrix in matrix:
            completed += 1
            run_label = _sanitize_name(
                f"{plugin_name}-{backend_matrix.debug_yaml_loader}-"
                f"{backend_matrix.profile_yaml_loader}-"
                f"{backend_matrix.llvm_cov_loader}")
            run_out_dir = os.path.join(args.work_dir, run_label)
            print(f"[{completed}/{total_cases}] {plugin_name} "
                  f"with {backend_matrix.label()}")
            result = _run_single_case(
                python_bin=args.python_bin,
                target_dir=args.target_dir,
                coverage_url=args.coverage_url,
                language=args.language,
                run_out_dir=run_out_dir,
                report_name=args.report_name,
                plugin_name=plugin_name,
                backend_matrix=backend_matrix,
                env_overrides=env_overrides,
            )
            results.append(result)

    with open(args.output_json, "w", encoding="utf-8") as output_file:
        json.dump(results, output_file, indent=2)
    print(f"Saved benchmark results to: {args.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
