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
"""Compare YAML loader backend outputs against Python semantics."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


def _load_python_profile(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as yaml_file:
        return yaml.safe_load(yaml_file)


def _load_python_debug(paths: list[str]) -> tuple[list[Any], list[str]]:
    items: list[Any] = []
    failures: list[str] = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as yaml_file:
                parsed = yaml.safe_load(yaml_file)
            if not parsed:
                continue
            if not isinstance(parsed, list):
                raise TypeError(
                    f"{path}: expected YAML list, got {type(parsed).__name__}"
                )
            items.extend(parsed)
        except Exception as exc:
            failures.append(f"{path}: {exc}")
    return items, failures


def _run_loader(binary: str, payload: dict[str, Any]) -> Any:
    process = subprocess.run(
        [binary],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"{binary} failed (rc={process.returncode}): {process.stderr.strip()}"
        )
    stdout = process.stdout.strip()
    if not stdout:
        return None
    return json.loads(stdout)


def _collect_paths(introspector_dir: str, pattern: str, limit: int) -> list[str]:
    paths = sorted(str(path) for path in Path(introspector_dir).glob(pattern))
    if limit > 0:
        return paths[:limit]
    return paths


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _normalize_debug_items(items: list[Any]) -> Counter[str]:
    # Treat debug items as an order-insensitive multiset.
    # Use stable hash keys to reduce peak memory compared to sorting huge
    # serialized payloads.
    digest_counts: Counter[str] = Counter()
    for item in items:
        canonical = _canonical_json(item).encode("utf-8")
        digest_counts[hashlib.sha256(canonical).hexdigest()] += 1
    return digest_counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--introspector-dir", required=True)
    parser.add_argument("--go-bin", default="")
    parser.add_argument("--rust-bin", default="")
    parser.add_argument("--cpp-bin", default="")
    parser.add_argument("--limit-profile", type=int, default=1)
    parser.add_argument("--limit-debug", type=int, default=0)
    parser.add_argument("--output-json", default="")
    args = parser.parse_args()

    profile_paths = _collect_paths(args.introspector_dir,
                                   "fuzzerLogFile-*.data.yaml",
                                   args.limit_profile)
    debug_paths = _collect_paths(args.introspector_dir, "*.debug_all_types",
                                 args.limit_debug)
    if not profile_paths:
        raise FileNotFoundError(
            f"No profile YAML files found in {args.introspector_dir}")
    if not debug_paths:
        raise FileNotFoundError(
            f"No debug YAML files found in {args.introspector_dir}")

    python_profile = _load_python_profile(profile_paths[0])
    python_debug, debug_load_failures = _load_python_debug(debug_paths)
    if debug_load_failures:
        joined = "\n".join(f"- {item}" for item in debug_load_failures)
        raise RuntimeError(
            f"Failed to parse {len(debug_load_failures)} debug YAML file(s):\n"
            f"{joined}"
        )

    summary: dict[str, Any] = {
        "introspector_dir": args.introspector_dir,
        "profile_sample": profile_paths[0],
        "debug_files": len(debug_paths),
        "python": {
            "profile_type": type(python_profile).__name__,
            "debug_items": len(python_debug),
        },
        "comparisons": {},
    }

    backends = {
        "go": args.go_bin,
        "rust": args.rust_bin,
        "cpp": args.cpp_bin,
    }

    for backend_name, binary in backends.items():
        if not binary:
            continue
        if not os.path.isfile(binary):
            raise FileNotFoundError(binary)

        profile_candidate = _run_loader(binary, {"path": profile_paths[0]})
        debug_candidate = _run_loader(
            binary,
            {
                "paths": debug_paths,
                "category": "debug-info"
            },
        )
        debug_items = []
        if isinstance(debug_candidate, dict):
            debug_items = debug_candidate.get("items", [])
        normalized_candidate_debug = _normalize_debug_items(debug_items)
        normalized_python_debug = _normalize_debug_items(python_debug)

        summary["comparisons"][backend_name] = {
            "profile_equal": profile_candidate == python_profile,
            "debug_equal": normalized_candidate_debug == normalized_python_debug,
            "debug_item_count": len(debug_items),
            "python_debug_item_count": len(python_debug),
        }

    print(json.dumps(summary, indent=2))
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as output_file:
            json.dump(summary, output_file, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
