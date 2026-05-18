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
"""Validate stage marker regressions between baseline and candidate logs."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fuzz_introspector import stage_markers  # pylint: disable=import-error


def _compute_regression_percent(
    baseline_total_seconds: float,
    candidate_total_seconds: float,
) -> float:
    if baseline_total_seconds <= 0:
        return math.inf if candidate_total_seconds > 0 else 0.0
    return (
        (candidate_total_seconds - baseline_total_seconds) / baseline_total_seconds
    ) * 100.0


def _build_stage_result(
    stage_name: str,
    baseline_metrics: dict[str, float | int],
    candidate_metrics: dict[str, float | int],
    max_regression_percent: float,
) -> dict[str, Any]:
    baseline_total = float(baseline_metrics.get("total_seconds", 0.0))
    candidate_total = float(candidate_metrics.get("total_seconds", 0.0))
    regression_percent = _compute_regression_percent(baseline_total, candidate_total)
    exceeds_threshold = regression_percent > max_regression_percent

    return {
        "stage": stage_name,
        "baseline_total_seconds": baseline_total,
        "candidate_total_seconds": candidate_total,
        "regression_percent": regression_percent,
        "max_regression_percent": max_regression_percent,
        "exceeds_threshold": exceeds_threshold,
        "baseline_count": int(baseline_metrics.get("count", 0)),
        "candidate_count": int(candidate_metrics.get("count", 0)),
        "baseline_missing_starts": int(baseline_metrics.get("missing_starts", 0)),
        "baseline_missing_ends": int(baseline_metrics.get("missing_ends", 0)),
        "candidate_missing_starts": int(candidate_metrics.get("missing_starts", 0)),
        "candidate_missing_ends": int(candidate_metrics.get("missing_ends", 0)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-log", required=True)
    parser.add_argument("--candidate-log", required=True)
    parser.add_argument(
        "--stages",
        required=True,
        help=(
            "Comma-separated stage names to validate, "
            "for example: optional_analyses,report_generation"
        ),
    )
    parser.add_argument("--max-regression-percent", required=True, type=float)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    if not os.path.isfile(args.baseline_log):
        raise FileNotFoundError(args.baseline_log)
    if not os.path.isfile(args.candidate_log):
        raise FileNotFoundError(args.candidate_log)

    stages = [stage.strip() for stage in args.stages.split(",") if stage.strip()]
    if not stages:
        raise ValueError("--stages must contain at least one stage")

    baseline_events = stage_markers.parse_stage_marker_file(args.baseline_log)
    candidate_events = stage_markers.parse_stage_marker_file(args.candidate_log)

    baseline_summary = stage_markers.summarize_stage_metrics(baseline_events, stages)
    candidate_summary = stage_markers.summarize_stage_metrics(candidate_events, stages)

    stage_results: dict[str, dict[str, Any]] = {}
    failed_stages: list[str] = []
    for stage_name in stages:
        baseline_metrics = baseline_summary.get(stage_name, {})
        candidate_metrics = candidate_summary.get(stage_name, {})
        stage_result = _build_stage_result(
            stage_name,
            baseline_metrics,
            candidate_metrics,
            args.max_regression_percent,
        )
        stage_results[stage_name] = stage_result
        if stage_result["exceeds_threshold"]:
            failed_stages.append(stage_name)

    output_payload = {
        "baseline_log": args.baseline_log,
        "candidate_log": args.candidate_log,
        "stages": stages,
        "max_regression_percent": args.max_regression_percent,
        "failed_stages": failed_stages,
        "ok": not failed_stages,
        "results": stage_results,
    }

    output_path = Path(args.output_json)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(output_payload, output_file, indent=2)

    for stage_name in stages:
        stage_result = stage_results[stage_name]
        status = "FAIL" if stage_result["exceeds_threshold"] else "OK"
        regression_percent = stage_result["regression_percent"]
        if math.isinf(regression_percent):
            regression_display = "inf"
        else:
            regression_display = f"{regression_percent:.2f}"
        print(
            f"{stage_name}\t{status}\t"
            f"baseline={stage_result['baseline_total_seconds']:.3f}s\t"
            f"candidate={stage_result['candidate_total_seconds']:.3f}s\t"
            f"regression_pct={regression_display}"
        )

    if failed_stages:
        print(f"Regression threshold exceeded for: {', '.join(failed_stages)}")
        return 1
    print("No stage regressions above threshold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
