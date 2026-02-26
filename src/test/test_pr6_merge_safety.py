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
"""PR6 merge safety regression tests."""

import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from fuzz_introspector import analysis
from fuzz_introspector import analyses as analyses_registry
from fuzz_introspector import constants
from fuzz_introspector import html_helpers
from fuzz_introspector import merge_coordinator
from fuzz_introspector import merge_intents
from fuzz_introspector.html_report import create_section_optional_analyses


class StubAnalysisBase(analysis.AnalysisInterface):

    def get_json_string_result(self) -> str:
        return self.json_string_result

    def set_json_string_result(self, json_string: str) -> None:
        self.json_string_result = json_string


class StubParallelFirst(StubAnalysisBase):
    name = "StubParallelFirst"

    @classmethod
    def get_name(cls):
        return cls.name

    def analysis_func(
        self,
        table_of_contents: html_helpers.HtmlTableOfContents,
        tables: List[str],
        proj_profile: Any,
        profiles: List[Any],
        basefolder: str,
        coverage_url: str,
        conclusions: List[html_helpers.HTMLConclusion],
        out_dir: str,
    ) -> str:
        table_of_contents.add_entry("Parallel First", "parallel-first",
                                    html_helpers.HTML_HEADING.H2)
        tables.append("table-parallel-first")
        return "<div>Parallel First</div>"


class StubSerialMiddle(StubAnalysisBase):
    name = "StubSerialMiddle"

    @classmethod
    def get_name(cls):
        return cls.name

    def analysis_func(
        self,
        table_of_contents: html_helpers.HtmlTableOfContents,
        tables: List[str],
        proj_profile: Any,
        profiles: List[Any],
        basefolder: str,
        coverage_url: str,
        conclusions: List[html_helpers.HTMLConclusion],
        out_dir: str,
    ) -> str:
        table_of_contents.add_entry("Serial Middle", "serial-middle",
                                    html_helpers.HTML_HEADING.H2)
        tables.append("table-serial-middle")
        return "<div>Serial Middle</div>"


class StubParallelLast(StubAnalysisBase):
    name = "StubParallelLast"

    @classmethod
    def get_name(cls):
        return cls.name

    def analysis_func(
        self,
        table_of_contents: html_helpers.HtmlTableOfContents,
        tables: List[str],
        proj_profile: Any,
        profiles: List[Any],
        basefolder: str,
        coverage_url: str,
        conclusions: List[html_helpers.HTMLConclusion],
        out_dir: str,
    ) -> str:
        table_of_contents.add_entry("Parallel Last", "parallel-last",
                                    html_helpers.HTML_HEADING.H2)
        tables.append("table-parallel-last")
        return "<div>Parallel Last</div>"


def _build_project(tmp_path: Path) -> analysis.IntrospectionProject:
    proj = analysis.IntrospectionProject(constants.LANGUAGES.CPP,
                                         str(tmp_path), "")
    proj.proj_profile = {
        "project_name": "merge-safety-test",
        "fuzzers": [{
            "id": "fuzzer1"
        }],
    }
    proj.profiles = {}
    proj.optional_analyses = []
    return proj


def _add_worker_result(
    coordinator: merge_coordinator.MergeCoordinator,
    analysis_name: str,
    merge_intents: List[Dict[str, Any]],
    table_ids: List[str] | None = None,
) -> None:
    worker_result = merge_coordinator.AnalysisWorkerResult(
        analysis_name=analysis_name,
        status="success",
        display_html=False,
        merge_intents=merge_intents,
    )
    envelope = worker_result.to_envelope()
    if table_ids is not None:
        envelope["table_ids"] = list(table_ids)
    coordinator.add_analysis_result(analysis_name, envelope)


def test_pr6_toc_table_canonical_order_serial_parallel_mix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FI_PR6_PARALLEL_ANALYSIS", "1")
    monkeypatch.setenv("FI_PR6_ANALYSIS_WORKERS", "2")
    monkeypatch.setattr(
        analysis,
        "get_all_analyses",
        lambda: [StubParallelFirst, StubSerialMiddle, StubParallelLast],
    )
    monkeypatch.setattr(
        analyses_registry,
        "all_analyses",
        [StubParallelFirst, StubSerialMiddle, StubParallelLast],
    )
    monkeypatch.setattr(
        analyses_registry,
        "analysis_parallel_compatibility",
        {
            StubParallelFirst:
            analyses_registry.PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
            StubSerialMiddle:
            analyses_registry.PARALLEL_COMPATIBILITY_SERIAL_ONLY,
            StubParallelLast:
            analyses_registry.PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
        },
    )

    table_of_contents = html_helpers.HtmlTableOfContents()
    tables: List[str] = []
    conclusions: List[html_helpers.HTMLConclusion] = []
    out_dir = tmp_path / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    project = _build_project(tmp_path)

    create_section_optional_analyses(
        table_of_contents,
        [
            StubParallelFirst.get_name(),
            StubSerialMiddle.get_name(),
            StubParallelLast.get_name(),
        ],
        [],
        tables,
        project,
        str(tmp_path),
        "",
        conclusions,
        False,
        str(out_dir),
    )

    toc_titles = [
        entry.entry_title for entry in table_of_contents.entries
        if entry.entry_title != "Analyses and suggestions"
    ]
    assert toc_titles == [
        "Parallel First",
        "Serial Middle",
        "Parallel Last",
    ], "TOC order must follow canonical analysis order"
    assert tables == [
        "table-parallel-first",
        "table-serial-middle",
        "table-parallel-last",
    ], "Table IDs must follow canonical analysis order"


def test_pr6_table_id_uniqueness_across_parallel_analyses(
    tmp_path: Path, ) -> None:
    out_dir = tmp_path / "merge"
    out_dir.mkdir(parents=True, exist_ok=True)
    coordinator = merge_coordinator.MergeCoordinator(str(out_dir))

    _add_worker_result(
        coordinator,
        "StubParallelFirst",
        [],
        table_ids=["dup-table"],
    )
    _add_worker_result(
        coordinator,
        "StubParallelLast",
        [],
        table_ids=["dup-table"],
    )

    success, merged = coordinator.merge_results()
    assert not success, "Duplicate table IDs must fail merge"
    assert any(
        conflict.get("type") == "table_id_conflict"
        and conflict.get("table_id") == "dup-table" for conflict in merged.get(
            "conflicts", [])), "Duplicate table ID conflict must be reported"


def test_pr6_no_partial_artifact_writes_on_merge_conflict(
    tmp_path: Path, ) -> None:
    out_dir = tmp_path / "artifacts"
    out_dir.mkdir(parents=True, exist_ok=True)
    coordinator = merge_coordinator.MergeCoordinator(str(out_dir))

    intent_one = merge_intents.create_artifact_write_intent(
        "reports/output.json",
        b"first",
        str(out_dir),
    )
    intent_two = merge_intents.create_artifact_write_intent(
        "reports/output.json",
        b"second",
        str(out_dir),
    )

    _add_worker_result(coordinator, "OptimalTargets", [intent_one])
    _add_worker_result(coordinator, "FuzzEngineInputAnalysis", [intent_two])

    success, _merged = coordinator.merge_results()
    assert not success, "Artifact conflicts must fail merge"

    artifact_path = out_dir / "reports" / "output.json"
    assert not artifact_path.exists(), (
        "No artifact should be written when merge conflicts occur")


def test_pr6_content_b64_hash_verification(tmp_path: Path) -> None:
    out_dir = tmp_path / "hash-check"
    out_dir.mkdir(parents=True, exist_ok=True)
    coordinator = merge_coordinator.MergeCoordinator(str(out_dir))

    content = b"expected"
    tampered = b"tampered"
    intent = {
        "type": "artifact_write",
        "relative_path": "reports/hash.json",
        "content_sha256": merge_intents.calculate_sha256(content),
        "content_b64": tampered.hex(),
    }

    _add_worker_result(coordinator, "OptimalTargets", [intent])
    success, merged = coordinator.merge_results()

    assert not success, "Content hash mismatch must fail merge"
    assert any(
        conflict.get("type") == "artifact_content_hash_mismatch"
        and conflict.get("relative_path") == "reports/hash.json"
        for conflict in merged.get(
            "conflicts", [])), "Content hash mismatch must be reported"
    assert not (out_dir / "reports" / "hash.json").exists(), (
        "No artifact should be written on hash mismatch")


def test_pr6_symlink_escape_path_safety_optional(tmp_path: Path) -> None:
    out_dir = tmp_path / "symlink-check"
    out_dir.mkdir(parents=True, exist_ok=True)
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir(parents=True, exist_ok=True)

    symlink_path = out_dir / "escape"
    try:
        os.symlink(outside_dir, symlink_path)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink not supported: {exc}")

    coordinator = merge_coordinator.MergeCoordinator(str(out_dir))
    intent = merge_intents.create_artifact_write_intent(
        "escape/evil.txt",
        b"evil",
        str(out_dir),
    )

    _add_worker_result(coordinator, "OptimalTargets", [intent])
    success, merged = coordinator.merge_results()
    assert not success, "Symlink escape must fail merge"
    assert any(
        conflict.get("type") == "artifact_path_unsafe"
        and conflict.get("relative_path") == "escape/evil.txt"
        for conflict in merged.get(
            "conflicts", [])), "Symlink escape must be reported as unsafe path"
    assert not (outside_dir / "evil.txt").exists(), (
        "Symlink escape must not write outside base directory")
