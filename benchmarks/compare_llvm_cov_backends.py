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
"""Compare LLVM coverage loader outputs across python/go/rust/cpp backends."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"


def _normalize_python_profile(cov_dir: str) -> dict[str, Any]:
    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))
    from fuzz_introspector import code_coverage  # pylint: disable=import-outside-toplevel

    profile = code_coverage.load_llvm_coverage(cov_dir)
    return {
        "covmap": {
            func_name: [[int(line), int(hit)] for line, hit in entries]
            for func_name, entries in profile.covmap.items()
        },
        "branch_cov_map": {
            branch_key: [int(hit) for hit in hits]
            for branch_key, hits in profile.branch_cov_map.items()
        },
        "coverage_files": list(profile.coverage_files),
    }


def _run_external_loader(binary_path: str,
                         coverage_reports: list[str]) -> dict[str, Any]:
    payload = json.dumps({"coverage_reports": coverage_reports})
    proc = subprocess.run(
        [binary_path],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"{binary_path} failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )
    return json.loads(proc.stdout)


def _compute_map_diff(reference: dict[str, Any],
                      candidate: dict[str, Any]) -> dict[str, int]:
    ref_keys = set(reference.keys())
    cand_keys = set(candidate.keys())
    return {
        "only_reference": len(ref_keys - cand_keys),
        "only_candidate": len(cand_keys - ref_keys),
        "shared": len(ref_keys & cand_keys),
    }


def _compare(reference: dict[str, Any],
             candidate: dict[str, Any]) -> dict[str, Any]:
    ref_covmap = reference.get("covmap", {})
    ref_branch = reference.get("branch_cov_map", {})
    cand_covmap = candidate.get("covmap", {})
    cand_branch = candidate.get("branch_cov_map", {})

    covmap_diff = _compute_map_diff(ref_covmap, cand_covmap)
    branch_diff = _compute_map_diff(ref_branch, cand_branch)

    return {
        "covmap_counts": {
            "reference": len(ref_covmap),
            "candidate": len(cand_covmap),
        },
        "branch_counts": {
            "reference": len(ref_branch),
            "candidate": len(cand_branch),
        },
        "covmap_diff": covmap_diff,
        "branch_diff": branch_diff,
        "coverage_files_count": {
            "reference": len(reference.get("coverage_files", [])),
            "candidate": len(candidate.get("coverage_files", [])),
        },
    }


def _collect_covreports(cov_dir: str, limit: int) -> list[str]:
    report_paths = sorted(
        str(path) for path in Path(cov_dir).glob("*.covreport"))
    if limit > 0:
        return report_paths[:limit]
    return report_paths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cov-dir", required=True)
    parser.add_argument("--go-bin", default="")
    parser.add_argument("--rust-bin", default="")
    parser.add_argument("--cpp-bin", default="")
    parser.add_argument(
        "--limit-reports",
        type=int,
        default=0,
        help="Optional cap on number of .covreport files used (0 means all).",
    )
    parser.add_argument("--output-json", default="")
    args = parser.parse_args()

    coverage_reports = _collect_covreports(args.cov_dir, args.limit_reports)
    if not coverage_reports:
        raise FileNotFoundError(
            f"No .covreport files found in {args.cov_dir!r}")

    python_output = _normalize_python_profile(args.cov_dir)
    summary: dict[str, Any] = {
        "cov_dir": args.cov_dir,
        "report_count": len(coverage_reports),
        "python": {
            "covmap_count": len(python_output.get("covmap", {})),
            "branch_count": len(python_output.get("branch_cov_map", {})),
            "coverage_files_count": len(
                python_output.get("coverage_files", [])),
        },
        "comparisons": {},
    }

    backends = {
        "go": args.go_bin,
        "rust": args.rust_bin,
        "cpp": args.cpp_bin,
    }
    for backend_name, binary_path in backends.items():
        if not binary_path:
            continue
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(binary_path)
        candidate_output = _run_external_loader(binary_path, coverage_reports)
        summary["comparisons"][backend_name] = _compare(
            python_output, candidate_output)

    print(json.dumps(summary, indent=2))
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as output_file:
            json.dump(summary, output_file, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
