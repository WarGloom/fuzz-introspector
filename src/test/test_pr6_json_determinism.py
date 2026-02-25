# Copyright 2025 Fuzz Introspector Authors
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
"""PR6 JSON determinism + serial parity tests."""

import json
import hashlib
from pathlib import Path
from typing import Any

import pytest

from fuzz_introspector import analyses as analyses_registry
from fuzz_introspector import constants
from fuzz_introspector import json_report
from fuzz_introspector import merge_coordinator
from fuzz_introspector import merge_intents


class StubDeterminismAlpha:
    name = "StubDeterminismAlpha"

    @classmethod
    def get_name(cls):
        return cls.name


class StubDeterminismBeta:
    name = "StubDeterminismBeta"

    @classmethod
    def get_name(cls):
        return cls.name


class StubDeterminismGamma:
    name = "StubDeterminismGamma"

    @classmethod
    def get_name(cls):
        return cls.name


ANALYSIS_ORDER = [
    StubDeterminismAlpha,
    StubDeterminismBeta,
    StubDeterminismGamma,
]


@pytest.fixture(autouse=True)
def patch_canonical_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(analyses_registry, "all_analyses", ANALYSIS_ORDER)


@pytest.fixture(autouse=True)
def enable_dump_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(constants, "should_dump_files", True)


def _hash_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _build_envelope(
    analysis_name: str,
    out_dir: str,
    summary_payload: dict[str, Any],
    artifact_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    collector = merge_intents.MergeIntentCollector()
    with merge_intents.merge_intent_context(collector):
        json_report.add_analysis_dict_to_json_report(analysis_name,
                                                     summary_payload, out_dir)
        if artifact_payload is not None:
            json_report.create_all_fi_functions_json(artifact_payload, out_dir)

    worker_result = merge_coordinator.AnalysisWorkerResult(
        analysis_name=analysis_name,
        status="success",
        display_html=False,
        merge_intents=collector.get_intents(),
    )
    return worker_result.to_envelope()


def _merge_envelopes(
    out_dir: Path,
    analysis_payloads: dict[str, dict[str, Any]],
    envelope_order: list[str],
    artifact_owner: str | None,
    artifact_payload: dict[str, Any] | None,
) -> None:
    coordinator = merge_coordinator.MergeCoordinator(str(out_dir))
    for analysis_name in envelope_order:
        artifact_data = artifact_payload if analysis_name == artifact_owner else None
        envelope = _build_envelope(analysis_name, str(out_dir),
                                   analysis_payloads[analysis_name],
                                   artifact_data)
        coordinator.add_analysis_result(analysis_name, envelope)

    success, merged = coordinator.merge_results()
    assert success, f"Merge failed: {merged}"


def _baseline_write_summary(
        out_dir: Path, analysis_payloads: dict[str, dict[str, Any]]) -> None:
    for analysis_cls in ANALYSIS_ORDER:
        analysis_name = analysis_cls.get_name()
        json_report.add_analysis_dict_to_json_report(
            analysis_name,
            analysis_payloads[analysis_name],
            str(out_dir),
        )


def _analysis_payloads() -> dict[str, dict[str, Any]]:
    return {
        StubDeterminismAlpha.get_name(): {
            "value": "alpha",
            "metrics": {
                "total": 3,
                "items": ["a", "b", "c"],
            },
        },
        StubDeterminismBeta.get_name(): {
            "value": "beta",
            "metrics": {
                "total": 2,
                "items": ["d", "e"],
            },
        },
        StubDeterminismGamma.get_name(): {
            "value": "gamma",
            "metrics": {
                "total": 1,
                "items": ["f"],
            },
        },
    }


def test_pr6_json_determinism_three_runs_summary_json(tmp_path: Path) -> None:
    analysis_payloads = _analysis_payloads()
    envelope_orders = [
        [
            StubDeterminismAlpha.get_name(),
            StubDeterminismBeta.get_name(),
            StubDeterminismGamma.get_name(),
        ],
        [
            StubDeterminismGamma.get_name(),
            StubDeterminismBeta.get_name(),
            StubDeterminismAlpha.get_name(),
        ],
        [
            StubDeterminismBeta.get_name(),
            StubDeterminismAlpha.get_name(),
            StubDeterminismGamma.get_name(),
        ],
    ]

    summary_hashes = []
    for idx, envelope_order in enumerate(envelope_orders):
        out_dir = tmp_path / f"summary-run-{idx}"
        out_dir.mkdir(parents=True, exist_ok=True)
        _merge_envelopes(out_dir, analysis_payloads, envelope_order, None,
                         None)

        summary_path = out_dir / constants.SUMMARY_FILE
        summary_hashes.append(_hash_file(summary_path))

    assert summary_hashes[0] == summary_hashes[1] == summary_hashes[2]


def test_pr6_json_determinism_three_runs_artifact_json(tmp_path: Path) -> None:
    analysis_payloads = _analysis_payloads()
    artifact_payload = {
        "entries": [
            {
                "function": "alpha",
                "source": "alpha.cc",
            },
            {
                "function": "beta",
                "source": "beta.cc",
            },
        ],
        "total":
        2,
    }

    envelope_orders = [
        [
            StubDeterminismAlpha.get_name(),
            StubDeterminismBeta.get_name(),
            StubDeterminismGamma.get_name(),
        ],
        [
            StubDeterminismGamma.get_name(),
            StubDeterminismAlpha.get_name(),
            StubDeterminismBeta.get_name(),
        ],
        [
            StubDeterminismBeta.get_name(),
            StubDeterminismGamma.get_name(),
            StubDeterminismAlpha.get_name(),
        ],
    ]

    artifact_hashes = []
    for idx, envelope_order in enumerate(envelope_orders):
        out_dir = tmp_path / f"artifact-run-{idx}"
        out_dir.mkdir(parents=True, exist_ok=True)
        _merge_envelopes(
            out_dir,
            analysis_payloads,
            envelope_order,
            StubDeterminismAlpha.get_name(),
            artifact_payload,
        )

        artifact_path = out_dir / constants.ALL_FUNCTIONS_JSON
        artifact_hashes.append(_hash_file(artifact_path))

    assert artifact_hashes[0] == artifact_hashes[1] == artifact_hashes[2]


def test_pr6_json_serial_parity_summary_json(tmp_path: Path) -> None:
    analysis_payloads = _analysis_payloads()
    baseline_dir = tmp_path / "baseline-summary"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    _baseline_write_summary(baseline_dir, analysis_payloads)
    baseline_hash = _hash_file(baseline_dir / constants.SUMMARY_FILE)

    merge_dir = tmp_path / "merge-summary"
    merge_dir.mkdir(parents=True, exist_ok=True)
    envelope_order = [
        StubDeterminismGamma.get_name(),
        StubDeterminismAlpha.get_name(),
        StubDeterminismBeta.get_name(),
    ]
    _merge_envelopes(merge_dir, analysis_payloads, envelope_order, None, None)
    merge_hash = _hash_file(merge_dir / constants.SUMMARY_FILE)

    assert baseline_hash == merge_hash


def test_pr6_json_serial_parity_artifact_json(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "baseline-artifact"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    artifact_payload = {
        "entries": [
            {
                "function": "alpha",
                "source": "alpha.cc",
            },
            {
                "function": "beta",
                "source": "beta.cc",
            },
        ],
        "total":
        2,
    }

    json_report.create_all_fi_functions_json(artifact_payload,
                                             str(baseline_dir))
    baseline_hash = _hash_file(baseline_dir / constants.ALL_FUNCTIONS_JSON)

    merge_dir = tmp_path / "merge-artifact"
    merge_dir.mkdir(parents=True, exist_ok=True)
    analysis_payloads = _analysis_payloads()
    envelope_order = [
        StubDeterminismAlpha.get_name(),
        StubDeterminismGamma.get_name(),
        StubDeterminismBeta.get_name(),
    ]
    _merge_envelopes(
        merge_dir,
        analysis_payloads,
        envelope_order,
        StubDeterminismAlpha.get_name(),
        artifact_payload,
    )
    merge_hash = _hash_file(merge_dir / constants.ALL_FUNCTIONS_JSON)

    assert baseline_hash == merge_hash


def test_json_report_no_dump_preserves_summary_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(constants, "should_dump_files", False)
    out_dir = tmp_path / "report-no-dump"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / constants.SUMMARY_FILE
    baseline_summary = {
        "existing": {
            "marker": "present"
        },
        "analyses": {
            "baseline": {
                "value": 1
            }
        },
    }
    summary_text = json.dumps(baseline_summary)
    summary_path.write_text(summary_text, encoding="utf-8")

    captured: dict[str, Any] = {}

    def capture_summary(contents: dict[Any, Any], _out_dir: str) -> None:
        captured["contents"] = contents

    monkeypatch.setattr(json_report, "_overwrite_report_with_dict",
                        capture_summary)

    json_report.add_analysis_dict_to_json_report("new-analysis", {
        "value": "active"
    }, str(out_dir))

    assert captured["contents"]["analyses"] == {
        "baseline": {
            "value": 1
        },
        "new-analysis": {
            "value": "active"
        },
    }
    assert summary_path.read_text(encoding="utf-8") == summary_text


def test_json_report_no_dump_still_emits_merge_intents(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(constants, "should_dump_files", False)
    out_dir = tmp_path / "intent-no-dump"
    out_dir.mkdir(parents=True, exist_ok=True)

    collector = merge_intents.MergeIntentCollector()
    with merge_intents.merge_intent_context(collector):
        json_report.add_analysis_dict_to_json_report(
            "detached", {
                "value": "analysis"
            }, str(out_dir))
        json_report.add_fuzzer_key_value_to_report(
            "fuzzer",
            "stats",
            {
                "total": 1
            },
            str(out_dir),
        )
        json_report.add_project_key_value_to_report(
            "stats",
            {
                "total": 2
            },
            str(out_dir),
        )

    intents = collector.get_intents()
    assert len(intents) == 3
    assert {
        "analyses.detached",
        "fuzzers.fuzzer.stats",
        "project.stats",
    } == {
        intent["target_path"]
        for intent in intents
    }
    assert not (out_dir / constants.SUMMARY_FILE).is_file()
