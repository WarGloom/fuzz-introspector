# Copyright 2021 Fuzz Introspector Authors
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
"""Reads the data output from the fuzz introspector LLVM plugin."""

import concurrent.futures
import json
import logging
import os
from typing import (
    Any,
    Dict,
    List,
    Optional,
)

from fuzz_introspector import backend_loaders
from fuzz_introspector import constants
from fuzz_introspector import utils
from fuzz_introspector.datatypes import fuzzer_profile, bug

logger = logging.getLogger(name=__name__)
FI_PROFILE_BACKEND_ENV = "FI_PROFILE_BACKEND"
FI_PROFILE_BACKEND_THREAD = "thread"
FI_PROFILE_BACKEND_PROCESS = "process"


def _get_profile_executor_backend(
) -> tuple[type[concurrent.futures.ThreadPoolExecutor]
           | type[concurrent.futures.ProcessPoolExecutor], str]:
    """Returns configured parallel backend for profile loading."""
    backend = os.environ.get(FI_PROFILE_BACKEND_ENV,
                             FI_PROFILE_BACKEND_THREAD).strip().lower()

    if backend == FI_PROFILE_BACKEND_PROCESS:
        return concurrent.futures.ProcessPoolExecutor, backend

    if backend and backend != FI_PROFILE_BACKEND_THREAD:
        logger.warning("Invalid %s=%r; defaulting to %s backend",
                       FI_PROFILE_BACKEND_ENV, backend,
                       FI_PROFILE_BACKEND_THREAD)

    return concurrent.futures.ThreadPoolExecutor, FI_PROFILE_BACKEND_THREAD


def read_fuzzer_data_file_to_profile(
        cfg_file: str,
        language: str) -> Optional[fuzzer_profile.FuzzerProfile]:
    """
    For a given .data file (CFG) read the corresponding .yaml file
    This is a bit odd way of doing it and should probably be improved.
    """
    logger.info(" - loading %s", cfg_file)
    target_data_f = cfg_file
    if cfg_file.endswith(".txt"):
        target_data_f = "/".join(cfg_file.split("/")[:-1]) + "/report"

    logger.info("target data f: %s", target_data_f)
    if not os.path.isfile(target_data_f) and not os.path.isfile(target_data_f +
                                                                ".yaml"):
        logger.info("R1")
        return None

    def _load_profile_yaml(yaml_path: str) -> Optional[dict[Any, Any]]:
        selected_backend, backend_payload = backend_loaders.load_json_with_backend(
            backend_env="FI_PROFILE_YAML_LOADER",
            command_env_prefix="FI_PROFILE_YAML_LOADER",
            payload={"path": yaml_path},
            default_backend=backend_loaders.BACKEND_RUST,
            timeout_env="FI_PROFILE_YAML_LOADER_TIMEOUT_SEC",
        )
        if backend_payload is not None:
            if isinstance(backend_payload, dict):
                logger.info("Loaded %s using %s backend", yaml_path,
                            selected_backend)
                return backend_payload
            logger.warning(
                "Backend payload for %s is not a dictionary; falling back to python",
                yaml_path,
            )
        return utils.data_file_read_yaml(yaml_path)

    data_dict_yaml = _load_profile_yaml(target_data_f + ".yaml")

    # Must be  dictionary
    if data_dict_yaml is None or not isinstance(data_dict_yaml, dict):
        logger.info("Found no data yaml file")
        if os.path.isfile("report.yaml"):
            data_dict_yaml = _load_profile_yaml("report.yaml")
            if data_dict_yaml is None or not isinstance(data_dict_yaml, dict):
                logger.info("Report.yaml is not a valid yaml file")
                return None
        else:
            logger.info("Found no module yaml files")
            return None

    try:
        with open(cfg_file, "r") as f:
            cfg_content = f.read()
    except UnicodeDecodeError:
        logger.info("CFG file not valid.")
        return None

    profile = fuzzer_profile.FuzzerProfile(cfg_file,
                                           data_dict_yaml,
                                           language,
                                           cfg_content=cfg_content)

    if not profile.has_entry_point():
        logger.info("Found no entrypoints")

    logger.info("Returning profile")
    return profile


def _load_profile(data_file: str, language: str):
    """Internal function used for parallel profile loading."""
    return data_file, read_fuzzer_data_file_to_profile(data_file, language)


def load_all_debug_files(target_folder: str):
    """Loads all .debug_info files"""
    debug_info_files = utils.get_all_files_in_tree_with_regex(
        target_folder, ".*debug_info$")
    for file in debug_info_files:
        logger.info("debug info file: %s", file)
    return debug_info_files


def find_all_debug_all_types_files(target_folder: str):
    """Loads all .debug_info files"""
    debug_info_files = utils.get_all_files_in_tree_with_regex(
        target_folder, ".*debug_all_types$")
    for file in debug_info_files:
        logger.info("debug info file: %s", file)
    return debug_info_files


def find_all_debug_function_files(target_folder: str):
    """Loads all debug_all_functions files"""
    debug_info_files = utils.get_all_files_in_tree_with_regex(
        target_folder, ".*debug_all_functions$")
    for file in debug_info_files:
        logger.info("debug info file: %s", file)
    return debug_info_files


def load_all_profiles(
        target_folder: str,
        language: str,
        parallelise: bool = True) -> List[fuzzer_profile.FuzzerProfile]:
    """Loads all profiles in target_folder in a multi-threaded manner"""
    logger.info("Loading profiles from %s", target_folder)
    if language == "jvm":
        # Java targets tend to be quite large, so we try to avoid memory
        # exhaustion here.
        worker_count = 3
    else:
        worker_count = 6

    profiles = []
    data_files = utils.get_all_files_in_tree_with_regex(
        target_folder, r"fuzzerLogFile.*\.data$")
    data_files.extend(
        utils.get_all_files_in_tree_with_regex(target_folder,
                                               "fuzzer-calltree-*"))
    target_calltrees = utils.get_all_files_in_tree_with_regex(
        target_folder, "targetCalltree.txt$")
    logger.info(target_calltrees)
    data_files.extend(target_calltrees)

    logger.info(" - found %d profiles to load", len(data_files))
    if parallelise:
        worker_count = max(1, min(worker_count, len(data_files)))
        executor_cls, backend = _get_profile_executor_backend()
        logger.info(
            "Loading profiles in parallel using %s backend (%d workers)",
            backend, worker_count)
        try:
            indexed_profiles: Dict[
                int, Optional[fuzzer_profile.FuzzerProfile]] = {}
            with executor_cls(max_workers=worker_count) as executor:
                future_to_idx = {
                    executor.submit(_load_profile, data_file, language): idx
                    for idx, data_file in enumerate(data_files)
                }
                for future in concurrent.futures.as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        _, loaded_profile = future.result()
                    except Exception as err:
                        logger.error("Failed to load profile at index %d: %s",
                                     idx, err)
                        continue
                    if loaded_profile is None:
                        logger.error("Profile is none")
                        continue
                    indexed_profiles[idx] = loaded_profile

            for idx in range(len(data_files)):
                profile = indexed_profiles.get(idx)
                if profile is not None:
                    profiles.append(profile)
        except (OSError, RuntimeError, ValueError) as err:
            logger.warning(
                "Falling back to serial profile loading after parallel failure: %s",
                err,
            )
            for data_file in data_files:
                _, loaded_profile = _load_profile(data_file, language)
                if loaded_profile is not None:
                    profiles.append(loaded_profile)
    else:
        for data_file in data_files:
            _, loaded_profile = _load_profile(data_file, language)
            if loaded_profile is not None:
                profiles.append(loaded_profile)

    return profiles


def try_load_input_bugs() -> List[bug.Bug]:
    """Loads input bugs as list. Returns empty list if none"""
    if not os.path.isfile(constants.INPUT_BUG_FILE):
        return []
    return load_input_bugs(constants.INPUT_BUG_FILE)


def load_input_bugs(bug_file: str) -> List[bug.Bug]:
    input_bugs: List[bug.Bug] = []
    if not os.path.isfile(bug_file):
        return input_bugs

    # Read file line by line
    with open(bug_file, "r") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        return input_bugs

    if "bugs" not in data:
        return input_bugs

    for bug_dict in data["bugs"]:
        try:
            ib = bug.Bug(
                bug_dict["source_file"],
                bug_dict["source_line"],
                bug_dict["function_name"],
                bug_dict["fuzzer_name"],
                bug_dict["description"],
                bug_dict["bug_type"],
            )
            input_bugs.append(ib)
        except Exception:
            continue

    return input_bugs
