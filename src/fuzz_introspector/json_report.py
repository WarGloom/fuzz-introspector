# Copyright 2022 Fuzz Introspector Authors
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
"""Module for creating JSON reports"""

import logging
import contextlib
import json
import os

from typing import Any, Callable, Dict

from fuzz_introspector import constants, merge_intents

logger = logging.getLogger(name=__name__)

_SUMMARY_BATCHES: Dict[str, Dict[Any, Any]] = {}
_SUMMARY_BATCH_DEPTH: Dict[str, int] = {}


def _load_or_init_summary_buffer(out_dir: str) -> Dict[Any, Any]:
    if out_dir not in _SUMMARY_BATCHES:
        _SUMMARY_BATCHES[out_dir] = _get_summary_dict(out_dir)
    return _SUMMARY_BATCHES[out_dir]


@contextlib.contextmanager
def summary_update_batch(out_dir: str):
    """Buffers summary updates and writes once when the context exits."""
    current_depth = _SUMMARY_BATCH_DEPTH.get(out_dir, 0) + 1
    _SUMMARY_BATCH_DEPTH[out_dir] = current_depth
    _load_or_init_summary_buffer(out_dir)
    try:
        yield
    finally:
        current_depth = _SUMMARY_BATCH_DEPTH[out_dir] - 1
        if current_depth <= 0:
            del _SUMMARY_BATCH_DEPTH[out_dir]
            buffered = _SUMMARY_BATCHES.pop(out_dir, None)
            if buffered is not None:
                _overwrite_report_with_dict(buffered, out_dir)
        else:
            _SUMMARY_BATCH_DEPTH[out_dir] = current_depth


def _get_summary_dict(out_dir) -> Dict[Any, Any]:
    """Returns the current json report on disk as a dictionary."""
    if not os.path.isfile(os.path.join(out_dir, constants.SUMMARY_FILE)):
        existing_contents = dict()
    else:
        with open(os.path.join(out_dir, constants.SUMMARY_FILE),
                  "r") as report_fd:
            existing_contents = json.load(report_fd)

    return existing_contents


def _overwrite_report_with_dict(new_dict: Dict[Any, Any], out_dir) -> None:
    """Writes `new_dict` as contents to the report on disk. Will overwrite any
    contents of the existing report.
    """
    if not constants.should_dump_files:
        return

    # Write back the json file
    with open(os.path.join(out_dir, constants.SUMMARY_FILE), "w") as report_fd:
        json.dump(new_dict, report_fd)


def _update_summary(out_dir: str, mutator: Callable[[Dict[Any, Any]],
                                                    None]) -> None:
    """Update summary either by writing directly or buffering in the active batch."""
    if out_dir in _SUMMARY_BATCHES:
        mutator(_SUMMARY_BATCHES[out_dir])
        return

    contents = _get_summary_dict(out_dir)
    mutator(contents)
    _overwrite_report_with_dict(contents, out_dir)


def add_analysis_dict_to_json_report(analysis_name: str,
                                     dict_to_add: Dict[Any,
                                                       Any], out_dir) -> None:
    """Wraps dictionary into an appropriate format

    Will overwrite the existing key/value pair for the analysis if it already
    exists as an analysis in the report.
    """
    collector = merge_intents.get_active_merge_intent_collector()
    if collector is not None:
        intent = merge_intents.create_json_upsert_intent_from_parts(
            ["analyses", analysis_name], dict_to_add)
        collector.add_intent(intent)
        return

    def _mutate(analysis_target: Dict[Any, Any]) -> None:
        if "analyses" not in analysis_target:
            analysis_target["analyses"] = {}
        analysis_target["analyses"][analysis_name] = dict_to_add

    _update_summary(out_dir, _mutate)


def add_analysis_json_str_as_dict_to_report(analysis_name: str, json_str: str,
                                            out_dir) -> None:
    """Converts a json string to a dictionary and add it to the report.

    Will overwrite the existing key/value pair for the analysis if it already
    exists as an analysis in the report."""
    add_analysis_dict_to_json_report(analysis_name, json.loads(json_str),
                                     out_dir)


def add_fuzzer_key_value_to_report(fuzzer_name: str, key: str, value: Any,
                                   out_dir) -> None:
    """Add the key/value pair to the json report under the fuzzer key.

    Will overwrite the existing key/value pair under the fuzzer if it already
    exists in the report.
    """
    collector = merge_intents.get_active_merge_intent_collector()
    if collector is not None:
        intent = merge_intents.create_json_upsert_intent_from_parts(
            ["fuzzers", fuzzer_name, key], value)
        collector.add_intent(intent)
        return

    def _mutate(fuzzers_target: Dict[Any, Any]) -> None:
        # Update the report accordingly
        if "fuzzers" not in fuzzers_target:
            fuzzers_target["fuzzers"] = {}
        if fuzzer_name not in fuzzers_target["fuzzers"]:
            fuzzers_target["fuzzers"][fuzzer_name] = dict()
        fuzzers_target["fuzzers"][fuzzer_name][key] = value

    _update_summary(out_dir, _mutate)


def add_project_key_value_to_report(key: str, value: Any, out_dir) -> None:
    """Add the key/value pair to the json report under the project key.

    Will overwrite the existing key/value pair if the key already exists in
    the report.
    """
    collector = merge_intents.get_active_merge_intent_collector()
    if collector is not None:
        intent = merge_intents.create_json_upsert_intent_from_parts(
            ["project", key], value)
        collector.add_intent(intent)
        return

    def _mutate(project_target: Dict[Any, Any]) -> None:
        # Update the report accordingly
        if constants.JSON_REPORT_KEY_PROJECT not in project_target:
            project_target[constants.JSON_REPORT_KEY_PROJECT] = dict()
        project_target[constants.JSON_REPORT_KEY_PROJECT][key] = value

    _update_summary(out_dir, _mutate)


def create_all_fi_functions_json(functions_dict, out_dir) -> None:
    if not constants.should_dump_files:
        return

    collector = merge_intents.get_active_merge_intent_collector()
    if collector is not None:
        intent = merge_intents.create_artifact_write_intent(
            constants.ALL_FUNCTIONS_JSON,
            json.dumps(functions_dict),
            out_dir,
        )
        collector.add_intent(intent)
        return

    with open(os.path.join(out_dir, constants.ALL_FUNCTIONS_JSON), "w") as f:
        json.dump(functions_dict, f)


def create_all_jvm_constructor_json(functions_dict, out_dir) -> None:
    if not constants.should_dump_files:
        return

    collector = merge_intents.get_active_merge_intent_collector()
    if collector is not None:
        intent = merge_intents.create_artifact_write_intent(
            constants.ALL_JVM_CONSTRUCTOR_JSON,
            json.dumps(functions_dict),
            out_dir,
        )
        collector.add_intent(intent)
        return

    with open(os.path.join(out_dir, constants.ALL_JVM_CONSTRUCTOR_JSON),
              "w") as f:
        json.dump(functions_dict, f)


def add_branch_blocker_key_value_to_report(profile_identifier, key,
                                           branch_blockers_list, out_dir):
    """Returns the current json report on disk as a dictionary."""
    if not os.path.isfile(os.path.join(out_dir,
                                       constants.BRANCH_BLOCKERS_FILE)):
        existing_contents = dict()
    else:
        with open(os.path.join(out_dir, constants.BRANCH_BLOCKERS_FILE),
                  "r") as report_fd:
            existing_contents = json.load(report_fd)

    existing_contents[profile_identifier] = branch_blockers_list
    with open(os.path.join(out_dir, constants.BRANCH_BLOCKERS_FILE),
              "w") as branch_fd:
        json.dump(existing_contents, branch_fd)
