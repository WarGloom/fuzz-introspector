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
"""Stage marker writer for pipeline phase observability."""

from collections import defaultdict
from dataclasses import dataclass
import datetime
import json
import logging
import os
import threading
from typing import Any, Iterable, Sequence

logger = logging.getLogger(__name__)

_lock = threading.Lock()

_MARKERS_FILE = "stage_markers.log"
_DISABLE_ENV = "FI_STAGE_MARKERS"


@dataclass(frozen=True)
class StageMarkerEvent:
    """Structured event parsed from a stage marker log line."""

    timestamp: datetime.datetime
    stage: str
    event: str
    metadata: dict[str, Any]


def parse_stage_marker_line(line: str) -> StageMarkerEvent | None:
    """Parse one stage marker line.

    Expected format:
    <ISO-8601-timestamp> <stage> <event> <json_metadata>
    """
    parts = line.strip().split(" ", 3)
    if len(parts) != 4:
        return None

    timestamp_raw, stage, event, metadata_raw = parts
    if not stage or not event:
        return None

    try:
        timestamp = datetime.datetime.fromisoformat(
            timestamp_raw.replace("Z", "+00:00"))
        metadata_obj = json.loads(metadata_raw)
    except (ValueError, json.JSONDecodeError):
        return None

    if not isinstance(metadata_obj, dict):
        return None

    return StageMarkerEvent(
        timestamp=timestamp,
        stage=stage,
        event=event,
        metadata=metadata_obj,
    )


def parse_stage_marker_lines(lines: Iterable[str]) -> list[StageMarkerEvent]:
    """Parse multiple marker lines, ignoring malformed entries."""
    events: list[StageMarkerEvent] = []
    for line in lines:
        event = parse_stage_marker_line(line)
        if event is not None:
            events.append(event)
    return events


def parse_stage_marker_file(path: str) -> list[StageMarkerEvent]:
    """Parse marker events from a stage marker log file path."""
    with open(path, "r", encoding="utf-8") as marker_file:
        return parse_stage_marker_lines(marker_file)


def pair_stage_events(
    events: Sequence[StageMarkerEvent],
    stages: Iterable[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Pair start/end events and compute per-stage durations.

    Returns one record per stage with:
    - durations: list[float] (seconds)
    - missing_starts: unmatched end events
    - missing_ends: unmatched start events
    """
    include_stages = set(stages) if stages is not None else None
    open_starts: dict[str, list[datetime.datetime]] = defaultdict(list)
    paired: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "durations": [],
        "missing_starts": 0,
        "missing_ends": 0,
    })

    for event in events:
        if include_stages is not None and event.stage not in include_stages:
            continue

        stage_record = paired[event.stage]
        if event.event == "start":
            open_starts[event.stage].append(event.timestamp)
        elif event.event == "end":
            if open_starts[event.stage]:
                start_time = open_starts[event.stage].pop()
                duration_seconds = (event.timestamp -
                                    start_time).total_seconds()
                if duration_seconds >= 0:
                    stage_record["durations"].append(duration_seconds)
            else:
                stage_record["missing_starts"] += 1

    for stage_name, pending_starts in open_starts.items():
        if include_stages is not None and stage_name not in include_stages:
            continue
        stage_record = paired[stage_name]
        stage_record["missing_ends"] += len(pending_starts)

    if include_stages is not None:
        for stage_name in include_stages:
            paired.setdefault(
                stage_name,
                {
                    "durations": [],
                    "missing_starts": 0,
                    "missing_ends": 0,
                },
            )

    return dict(paired)


def summarize_stage_metrics(
    events: Sequence[StageMarkerEvent],
    stages: Iterable[str] = ("optional_analyses", "report_generation"),
) -> dict[str, dict[str, float | int]]:
    """Build compact summary metrics for selected stages."""
    paired = pair_stage_events(events, stages)
    summary: dict[str, dict[str, float | int]] = {}
    for stage_name, record in paired.items():
        durations = list(record.get("durations", []))
        duration_count = len(durations)
        total_seconds = float(sum(durations))

        summary[stage_name] = {
            "count":
            duration_count,
            "total_seconds":
            total_seconds,
            "mean_seconds":
            (total_seconds / duration_count) if duration_count else 0.0,
            "max_seconds":
            max(durations) if durations else 0.0,
            "min_seconds":
            min(durations) if durations else 0.0,
            "missing_starts":
            int(record.get("missing_starts", 0)),
            "missing_ends":
            int(record.get("missing_ends", 0)),
        }

    return summary


def emit(out_dir: str, stage: str, event: str, **meta) -> None:
    """Write one marker line to <out_dir>/stage_markers.log.

    Format: <ISO-8601-timestamp> <stage> <event> <json_metadata>
    Example: 2026-03-03T12:34:56.789Z debug_types_yaml start {"files": 42}

    Does nothing if FI_STAGE_MARKERS=0 or out_dir is empty/None.
    Silently ignores I/O errors (observability must not break the pipeline).
    """
    if not out_dir:
        return
    if os.environ.get(_DISABLE_ENV, "").strip() == "0":
        return

    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    meta_json = json.dumps(meta, separators=(",", ":")) if meta else "{}"
    line = f"{timestamp} {stage} {event} {meta_json}\n"

    log_path = os.path.join(out_dir, _MARKERS_FILE)
    try:
        with _lock:
            with open(log_path, "a") as fh:
                fh.write(line)
    except OSError:
        pass
