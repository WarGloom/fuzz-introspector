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
"""Check semantic equivalence of fuzz-introspector report outputs.

Assumptions and scope:
- This comparator intentionally covers key report artifacts only:
  `summary.json`, `fuzz_report.html`, `all_functions.js`,
  `fuzzer_table_data.js`, and optional `analysis_1.js`.
- JavaScript artifacts are expected to follow `var <name> = <json>` format.
- HTML equivalence is text-based with whitespace normalization. This is strict
  enough for generated report HTML without running browser-side JS.
- List-order normalization is opt-in. Enable it only for lists where order is
  known to be non-semantic for your experiment.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import difflib
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence


@dataclass(frozen=True)
class ArtifactSpec:
    relative_path: str
    artifact_kind: str
    required: bool
    expected_js_var: str | None = None


@dataclass(frozen=True)
class ListPathRule:
    file_name: str
    path_tokens: tuple[str, ...]

    def matches(self, file_name: str, path_tokens: tuple[str, ...]) -> bool:
        if self.file_name != "*" and self.file_name != file_name:
            return False
        if len(self.path_tokens) != len(path_tokens):
            return False
        return all(
            expected == "*" or expected == observed
            for expected, observed in zip(self.path_tokens, path_tokens)
        )


@dataclass(frozen=True)
class NormalizationOptions:
    sort_keys: bool
    sort_all_lists: bool
    sort_list_rules: tuple[ListPathRule, ...]
    ignore_report_date: bool
    normalize_html_whitespace: bool


@dataclass(frozen=True)
class Difference:
    relative_path: str
    reason: str
    diff_text: str = ""


@dataclass
class ComparisonResult:
    checked_artifacts: list[str]
    differences: list[Difference]

    @property
    def equivalent(self) -> bool:
        return not self.differences


ARTIFACT_SPECS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec("summary.json", "json", required=True),
    ArtifactSpec("fuzz_report.html", "html", required=True),
    ArtifactSpec(
        "all_functions.js",
        "js_json",
        required=True,
        expected_js_var="all_functions_table_data",
    ),
    ArtifactSpec(
        "fuzzer_table_data.js",
        "js_json",
        required=True,
        expected_js_var="fuzzer_table_data",
    ),
    ArtifactSpec(
        "analysis_1.js",
        "js_json",
        required=False,
        expected_js_var="analysis_1_data",
    ),
)

_JS_ASSIGNMENT_RE = re.compile(
    r"^\s*var\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$",
    re.DOTALL,
)
_REPORT_DATE_RE = re.compile(
    r"(<b>\s*Report generation date:\s*</b>)\s*\d{4}-\d{2}-\d{2}",
)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two fuzz-introspector report directories and fail when "
            "meaningful semantic differences are detected."
        ))
    parser.add_argument("left_report_dir",
                        help="Path to baseline/original report directory.")
    parser.add_argument("right_report_dir",
                        help="Path to candidate report directory.")
    parser.add_argument(
        "--sort-keys",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Sort JSON object keys during normalization (default: enabled).",
    )
    parser.add_argument(
        "--sort-lists",
        action="store_true",
        help="Sort all JSON lists by canonical representation.",
    )
    parser.add_argument(
        "--sort-lists-at",
        action="append",
        default=[],
        metavar="FILE:PATH",
        help=(
            "Sort lists only at selected semantic paths. Use path '$' for root "
            "list, dot notation for nested keys, and '*' wildcard segments."
        ),
    )
    parser.add_argument(
        "--ignore-report-date",
        action="store_true",
        help="Ignore report generation date in fuzz_report.html.",
    )
    parser.add_argument(
        "--markdown-report",
        default="",
        help="Optional path to write a markdown diff report.",
    )
    parser.add_argument(
        "--max-diff-lines",
        type=int,
        default=200,
        help="Maximum lines of unified diff to include per differing artifact.",
    )
    return parser.parse_args(argv)


def _parse_list_rule(raw_rule: str) -> ListPathRule:
    if ":" not in raw_rule:
        raise ValueError(
            f"Invalid --sort-lists-at value '{raw_rule}'. Expected FILE:PATH.")

    file_name, raw_path = raw_rule.split(":", 1)
    file_name = file_name.strip()
    raw_path = raw_path.strip()

    if not file_name:
        raise ValueError(
            f"Invalid --sort-lists-at value '{raw_rule}'. Missing file name.")

    if raw_path == "$" or not raw_path:
        return ListPathRule(file_name=file_name, path_tokens=())

    if raw_path.startswith("$."):
        raw_path = raw_path[2:]
    elif raw_path.startswith("$"):
        raw_path = raw_path[1:]

    path_tokens = tuple(segment.strip() for segment in raw_path.split(".")
                        if segment.strip())
    if not path_tokens:
        raise ValueError(
            f"Invalid --sort-lists-at value '{raw_rule}'. Empty path.")
    return ListPathRule(file_name=file_name, path_tokens=path_tokens)


def _should_sort_list(file_name: str, path_tokens: tuple[str, ...],
                      options: NormalizationOptions) -> bool:
    if options.sort_all_lists:
        return True
    return any(rule.matches(file_name, path_tokens)
               for rule in options.sort_list_rules)


def _json_sort_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _normalize_json_value(
    value: Any,
    file_name: str,
    path_tokens: tuple[str, ...],
    options: NormalizationOptions,
) -> Any:
    if isinstance(value, dict):
        normalized_dict: dict[str, Any] = {}
        keys = sorted(value.keys()) if options.sort_keys else value.keys()
        for key in keys:
            normalized_dict[key] = _normalize_json_value(
                value[key],
                file_name,
                path_tokens + (key, ),
                options,
            )
        return normalized_dict

    if isinstance(value, list):
        normalized_list = [
            _normalize_json_value(item, file_name, path_tokens, options)
            for item in value
        ]
        if _should_sort_list(file_name, path_tokens, options):
            return sorted(normalized_list, key=_json_sort_key)
        return normalized_list

    return value


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_js_json_assignment(path: Path) -> tuple[str, Any]:
    content = path.read_text(encoding="utf-8")
    match = _JS_ASSIGNMENT_RE.fullmatch(content)
    if not match:
        raise ValueError(
            f"{path.name} must be in 'var <name> = <json>' format.")

    variable_name = match.group(1)
    payload = match.group(2)
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as err:
        raise ValueError(
            f"{path.name} contains invalid JSON payload: {err}") from err
    return variable_name, decoded


def _normalize_html(content: str, options: NormalizationOptions) -> str:
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if options.ignore_report_date:
        normalized = _REPORT_DATE_RE.sub(r"\1<DATE>", normalized)
    if options.normalize_html_whitespace:
        normalized = re.sub(r">\s+<", "><", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _build_unified_diff(
    left_label: str,
    right_label: str,
    left_text: str,
    right_text: str,
    max_lines: int,
) -> str:
    diff_lines = list(
        difflib.unified_diff(
            left_text.splitlines(),
            right_text.splitlines(),
            fromfile=left_label,
            tofile=right_label,
            lineterm="",
        ))
    if len(diff_lines) > max_lines:
        diff_lines = diff_lines[:max_lines]
        diff_lines.append(f"... diff truncated after {max_lines} lines ...")
    return "\n".join(diff_lines)


def _compare_json_artifact(
    spec: ArtifactSpec,
    left_path: Path,
    right_path: Path,
    options: NormalizationOptions,
    max_diff_lines: int,
) -> Difference | None:
    try:
        left_payload = _normalize_json_value(_load_json(left_path),
                                             spec.relative_path, (), options)
        right_payload = _normalize_json_value(_load_json(right_path),
                                              spec.relative_path, (), options)
    except (json.JSONDecodeError, OSError, ValueError) as err:
        return Difference(spec.relative_path, f"failed to read JSON: {err}")

    if left_payload == right_payload:
        return None

    left_dump = json.dumps(left_payload,
                           indent=2,
                           sort_keys=True,
                           ensure_ascii=False)
    right_dump = json.dumps(right_payload,
                            indent=2,
                            sort_keys=True,
                            ensure_ascii=False)
    diff_text = _build_unified_diff(
        f"{spec.relative_path} (left)",
        f"{spec.relative_path} (right)",
        left_dump,
        right_dump,
        max_diff_lines,
    )
    return Difference(spec.relative_path, "semantic JSON payload mismatch",
                      diff_text)


def _compare_js_artifact(
    spec: ArtifactSpec,
    left_path: Path,
    right_path: Path,
    options: NormalizationOptions,
    max_diff_lines: int,
) -> Difference | None:
    try:
        left_var, left_payload_raw = _load_js_json_assignment(left_path)
        right_var, right_payload_raw = _load_js_json_assignment(right_path)
    except (OSError, ValueError) as err:
        return Difference(spec.relative_path, f"failed to parse JS artifact: {err}")

    if spec.expected_js_var:
        if left_var != spec.expected_js_var:
            return Difference(
                spec.relative_path,
                f"unexpected left JS variable '{left_var}' "
                f"(expected '{spec.expected_js_var}')",
            )
        if right_var != spec.expected_js_var:
            return Difference(
                spec.relative_path,
                f"unexpected right JS variable '{right_var}' "
                f"(expected '{spec.expected_js_var}')",
            )

    left_payload = _normalize_json_value(left_payload_raw, spec.relative_path,
                                         (), options)
    right_payload = _normalize_json_value(right_payload_raw, spec.relative_path,
                                          (), options)
    if left_payload == right_payload:
        return None

    left_dump = json.dumps(left_payload,
                           indent=2,
                           sort_keys=True,
                           ensure_ascii=False)
    right_dump = json.dumps(right_payload,
                            indent=2,
                            sort_keys=True,
                            ensure_ascii=False)
    diff_text = _build_unified_diff(
        f"{spec.relative_path} (left)",
        f"{spec.relative_path} (right)",
        left_dump,
        right_dump,
        max_diff_lines,
    )
    return Difference(spec.relative_path, "semantic JS JSON payload mismatch",
                      diff_text)


def _compare_html_artifact(
    spec: ArtifactSpec,
    left_path: Path,
    right_path: Path,
    options: NormalizationOptions,
    max_diff_lines: int,
) -> Difference | None:
    try:
        left_text = _normalize_html(left_path.read_text(encoding="utf-8"),
                                    options)
        right_text = _normalize_html(right_path.read_text(encoding="utf-8"),
                                     options)
    except OSError as err:
        return Difference(spec.relative_path, f"failed to read HTML artifact: {err}")

    if left_text == right_text:
        return None

    diff_text = _build_unified_diff(
        f"{spec.relative_path} (left)",
        f"{spec.relative_path} (right)",
        left_text,
        right_text,
        max_diff_lines,
    )
    return Difference(spec.relative_path, "normalized HTML mismatch", diff_text)


def compare_report_directories(
    left_dir: Path,
    right_dir: Path,
    options: NormalizationOptions,
    max_diff_lines: int = 200,
) -> ComparisonResult:
    checked_artifacts: list[str] = []
    differences: list[Difference] = []

    for spec in ARTIFACT_SPECS:
        left_path = left_dir / spec.relative_path
        right_path = right_dir / spec.relative_path
        left_exists = left_path.is_file()
        right_exists = right_path.is_file()

        if not left_exists and not right_exists:
            if spec.required:
                differences.append(
                    Difference(spec.relative_path,
                               "missing in both report directories"))
            continue

        if not left_exists or not right_exists:
            missing_side = "left" if not left_exists else "right"
            differences.append(
                Difference(spec.relative_path,
                           f"missing in {missing_side} report directory"))
            continue

        checked_artifacts.append(spec.relative_path)
        if spec.artifact_kind == "json":
            difference = _compare_json_artifact(spec, left_path, right_path,
                                                options, max_diff_lines)
        elif spec.artifact_kind == "js_json":
            difference = _compare_js_artifact(spec, left_path, right_path,
                                              options, max_diff_lines)
        elif spec.artifact_kind == "html":
            difference = _compare_html_artifact(spec, left_path, right_path,
                                                options, max_diff_lines)
        else:
            difference = Difference(spec.relative_path,
                                    f"unsupported artifact kind {spec.artifact_kind!r}")

        if difference:
            differences.append(difference)

    return ComparisonResult(
        checked_artifacts=sorted(checked_artifacts),
        differences=differences,
    )


def _render_stdout_report(result: ComparisonResult, left_dir: Path,
                          right_dir: Path) -> str:
    lines = [
        f"Left report directory: {left_dir}",
        f"Right report directory: {right_dir}",
        f"Artifacts compared: {', '.join(result.checked_artifacts) or '(none)'}",
    ]

    if result.equivalent:
        lines.append("Result: equivalent")
        return "\n".join(lines)

    lines.append(f"Result: differences found ({len(result.differences)})")
    for idx, difference in enumerate(result.differences, start=1):
        lines.append(f"{idx}. {difference.relative_path}: {difference.reason}")
        if difference.diff_text:
            lines.append(difference.diff_text)
    return "\n".join(lines)


def _render_markdown_report(result: ComparisonResult, left_dir: Path,
                            right_dir: Path) -> str:
    lines = [
        "# Report Equivalence",
        "",
        f"- Left report directory: `{left_dir}`",
        f"- Right report directory: `{right_dir}`",
        f"- Artifacts compared: `{', '.join(result.checked_artifacts) or '(none)'}`",
        "",
    ]

    if result.equivalent:
        lines.append("## Result")
        lines.append("Equivalent")
        return "\n".join(lines) + "\n"

    lines.append("## Result")
    lines.append(f"Differences found: **{len(result.differences)}**")
    lines.append("")
    for idx, difference in enumerate(result.differences, start=1):
        lines.append(f"### {idx}. `{difference.relative_path}`")
        lines.append("")
        lines.append(f"- Reason: {difference.reason}")
        if difference.diff_text:
            lines.append("- Diff:")
            lines.append("")
            lines.append("```diff")
            lines.append(difference.diff_text)
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


def _build_normalization_options(args: argparse.Namespace) -> NormalizationOptions:
    parsed_rules = tuple(_parse_list_rule(raw_rule)
                         for raw_rule in args.sort_lists_at)
    return NormalizationOptions(
        sort_keys=args.sort_keys,
        sort_all_lists=args.sort_lists,
        sort_list_rules=parsed_rules,
        ignore_report_date=args.ignore_report_date,
        normalize_html_whitespace=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    left_dir = Path(args.left_report_dir).resolve()
    right_dir = Path(args.right_report_dir).resolve()

    if not left_dir.is_dir():
        print(f"error: left_report_dir is not a directory: {left_dir}",
              file=sys.stderr)
        return 2
    if not right_dir.is_dir():
        print(f"error: right_report_dir is not a directory: {right_dir}",
              file=sys.stderr)
        return 2

    try:
        options = _build_normalization_options(args)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    result = compare_report_directories(
        left_dir,
        right_dir,
        options=options,
        max_diff_lines=max(1, args.max_diff_lines),
    )

    report_text = _render_stdout_report(result, left_dir, right_dir)
    print(report_text)

    if args.markdown_report:
        markdown_path = Path(args.markdown_report)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(
            _render_markdown_report(result, left_dir, right_dir),
            encoding="utf-8",
        )

    return 0 if result.equivalent else 1


if __name__ == "__main__":
    sys.exit(main())
