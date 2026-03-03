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

import datetime
import json
import logging
import os
import threading

logger = logging.getLogger(__name__)

_lock = threading.Lock()

_MARKERS_FILE = "stage_markers.log"
_DISABLE_ENV = "FI_STAGE_MARKERS"


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
