# Copyright 2024 Fuzz Introspector Authors
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
"""Module for handling debug information from LLVM

Debug information extraction utilities for fuzz-introspector.

This module provides functions to parse and extract debug information
from various sources, including DWARF debug info and other debug formats.
"""

import collections
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from concurrent.futures import (FIRST_COMPLETED, ProcessPoolExecutor,
                                ThreadPoolExecutor, as_completed, wait)
from typing import Any, TypeVar
import yaml

logger = logging.getLogger(name=__name__)
_T = TypeVar("_T")
DebugPayload = tuple[str, dict[str, dict[str, str]], dict[str, dict[str, Any]],
                     dict[str, dict[str, Any]], dict[str, dict[str, Any]],
                     dict[str, str], str | None, ]

# Pre-compiled regex patterns for debug info parsing (performance optimization)
# These patterns are used in extract_all_functions_in_debug_info

# Match the functions section: between "## Functions defined in module" and "## Global variables"
FUNCTIONS_SECTION_START = "## Functions defined in module"
FUNCTIONS_SECTION_END = "## Global variables"


def extract_all_compile_units(content, all_files_in_debug_info):
    for line in content.split("\n"):
        # Source code files
        if "Compile unit:" in line:
            split_line = line.split(" ")
            file_dict = {
                "source_file": split_line[-1],
                "language": split_line[2]
            }

            # TODO: (David) remove this hack to frontend
            # LLVM may combine two absolute paths, which causes the
            # filepath to be erroneus.
            # Fix this here
            if "//" in file_dict["source_file"]:
                file_dict["source_file"] = "/" + "/".join(
                    file_dict["source_file"].split("//")[1:])

            all_files_in_debug_info[file_dict["source_file"]] = file_dict


def extract_global_variables(content, global_variables, source_files):
    for line in content.split("\n"):
        if "Global variable: " in line:
            sline = line.replace("Global variable: ", "").split(" from ")
            global_variable_name = sline[0]
            location = sline[-1]
            source_file = location.split(":")[0]
            try:
                source_line = location.split(":")[1]
            except IndexError:
                source_line = "-1"
            global_variables[source_file + source_line] = {
                "name": global_variable_name,
                "source": {
                    "source_file": source_file,
                    "source_line": source_line
                },
            }
            # Add the file to all files in project
            if source_file not in source_files:
                source_files[source_file] = {
                    "source_file": source_file,
                    "language": "N/A",
                }


def extract_types(content, all_types, all_files_in_debug_info):
    current_type = None
    current_struct = None
    types_identifier = "## Types defined in module"
    read_types = False

    for line in content.split("\n"):
        if types_identifier in line:
            read_types = True

        if read_types:
            if "Type: Name:" in line:
                if current_struct is not None:
                    hashkey = (current_struct["source"]["source_file"] +
                               current_struct["source"]["source_line"])
                    all_types[hashkey] = current_struct
                    current_struct = None
                if "DW_TAG_structure" in line:
                    current_struct = dict()
                    struct_name = line.split("{")[-1].split("}")[0].strip()
                    location = line.split("from")[-1].strip().split(" ")[0]
                    source_file = location.split(":")[0]
                    try:
                        source_line = location.split(":")[1]
                    except IndexError:
                        source_line = "-1"
                    current_struct = {
                        "type": "struct",
                        "name": struct_name,
                        "source": {
                            "source_file": source_file,
                            "source_line": source_line,
                        },
                        "elements": [],
                    }
                    # Add the file to all files in project
                    if source_file not in all_files_in_debug_info:
                        all_files_in_debug_info[source_file] = {
                            "source_file": source_file,
                            "language": "N/A",
                        }
                if "DW_TAG_typedef" in line:
                    name = line.split("{")[-1].strip().split("}")[0]
                    location = line.split(" from ")[-1].split(" ")[0]
                    source_file = location.split(":")[0]
                    try:
                        source_line = location.split(":")[1]
                    except IndexError:
                        source_line = "-1"
                    current_type = {
                        "type": "typedef",
                        "name": name,
                        "source": {
                            "source_file": source_file,
                            "source_line": source_line,
                        },
                    }
                    hashkey = (current_type["source"]["source_file"] +
                               current_type["source"]["source_line"])
                    all_types[hashkey] = current_type
                    # Add the file to all files in project
                    if source_file not in all_files_in_debug_info:
                        all_files_in_debug_info[source_file] = {
                            "source_file": source_file,
                            "language": "N/A",
                        }
            if "- Elem " in line:
                # Ensure we have a strcuct
                if current_struct is not None:
                    elem_name = line.split("{")[-1].strip().split(" ")[0]
                    location = line.split("from")[-1].strip().split(" ")[0]
                    source_file = location.split(":")[0]
                    try:
                        source_line = location.split(":")[1]
                    except IndexError:
                        source_line = "-1"

                    current_struct["elements"].append({
                        "name": elem_name,
                        "source": {
                            "source_file": source_file,
                            "source_line": source_line,
                        },
                    })
                    # Add the file to all files in project
                    if source_file not in all_files_in_debug_info:
                        all_files_in_debug_info[source_file] = {
                            "source_file": source_file,
                            "language": "N/A",
                        }


def extract_all_functions_in_debug_info(content, all_functions_in_debug,
                                        all_files_in_debug_info):
    """Extract function information from debug info content.

    Uses a single-pass parser over the functions section to avoid repeated
    section/block regex scans for large debug files.
    """
    section_start_idx = content.find(FUNCTIONS_SECTION_START)
    if section_start_idx == -1:
        logger.debug("No functions section found in debug info")
        return

    section_start_idx += len(FUNCTIONS_SECTION_START)
    if section_start_idx < len(content) and content[section_start_idx] == "\n":
        section_start_idx += 1

    section_end_idx = content.find(FUNCTIONS_SECTION_END, section_start_idx)
    if section_end_idx == -1:
        section_end_idx = len(content)
    functions_section = content[section_start_idx:section_end_idx]

    current_function: dict[str, Any] | None = None
    named_args: list[str] = []
    operand_args: list[str] = []

    def _finalize_current_function() -> None:
        if current_function is None:
            return

        args = named_args if named_args else operand_args
        if args:
            current_function["args"] = args

        if "source" in current_function:
            try:
                hashkey = (current_function["source"]["source_file"] +
                           current_function["source"]["source_line"])
                all_functions_in_debug[hashkey] = current_function
            except KeyError:
                pass

    def _maybe_extract_source_location(line: str) -> tuple[str, str] | None:
        if (" from " not in line or " - Operand" in line or "Elem " in line):
            return None
        location = line.rsplit(" from ", maxsplit=1)[-1].strip()
        source_file, separator, source_line_tail = location.partition(":")
        if separator == "" or source_file == "":
            return None
        digits = []
        for ch in source_line_tail:
            if ch.isdigit():
                digits.append(ch)
            else:
                break
        if not digits:
            return None
        return source_file.strip(), "".join(digits)

    def _maybe_extract_named_arg(line: str) -> str | None:
        marker = "Name: {"
        start_idx = line.find(marker)
        if start_idx == -1:
            return None
        start_idx += len(marker)
        end_idx = line.find("}", start_idx)
        if end_idx == -1:
            return None
        value = line[start_idx:end_idx].strip()
        return value if value else None

    def _maybe_extract_operand_type(line: str) -> str | None:
        if " - Operand" not in line:
            return None

        l1 = (line.replace("Operand Type:", "").replace("Type: ",
                                                        "").replace("-", ""))
        pointer_count = l1.count("DW_TAG_pointer_type")
        const_count = l1.count("DW_TAG_const_type")
        parts = l1.split(",")
        if not parts:
            return None
        base_type = parts[-1].strip()
        end_type = ""
        if const_count > 0:
            end_type += "const "
        end_type += base_type
        if pointer_count > 0:
            end_type += " " + "*" * pointer_count
        return end_type if end_type.strip() else None

    for line in functions_section.splitlines():
        if line.startswith("Subprogram: "):
            _finalize_current_function()
            function_name = line[len("Subprogram: "):].strip()
            current_function = {"name": function_name}
            named_args = []
            operand_args = []
            continue

        if current_function is None:
            continue

        if "source" not in current_function:
            source_location = _maybe_extract_source_location(line)
            if source_location is not None:
                source_file, source_line = source_location
                current_function["source"] = {
                    "source_file": source_file,
                    "source_line": source_line,
                }
                if source_file not in all_files_in_debug_info:
                    all_files_in_debug_info[source_file] = {
                        "source_file": source_file,
                        "language": "N/A",
                    }

        named_arg = _maybe_extract_named_arg(line)
        if named_arg is not None:
            named_args.append(named_arg)
            continue

        operand_type = _maybe_extract_operand_type(line)
        if operand_type is not None:
            operand_args.append(operand_type)

    _finalize_current_function()


def _load_debug_file_payload(debug_file: str) -> DebugPayload:
    with open(debug_file, "rb") as debug_f:
        raw_bytes = debug_f.read()
    raw_content = raw_bytes.decode("utf-8", errors="ignore")
    content_hash = hashlib.md5(raw_bytes).hexdigest()

    path_mapping: dict[str, str] = {}
    original_base_dir: str | None = None
    try:
        report_data = json.loads(raw_content)
        path_mapping = report_data.get("_path_mapping", {})
        original_base_dir = report_data.get("_base_dir", None)
    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    all_files_in_debug_info: dict[str, dict[str, str]] = {}
    all_functions_in_debug: dict[str, dict[str, Any]] = {}
    all_global_variables: dict[str, dict[str, Any]] = {}
    all_types: dict[str, dict[str, Any]] = {}
    extract_all_compile_units(raw_content, all_files_in_debug_info)
    extract_all_functions_in_debug_info(raw_content, all_functions_in_debug,
                                        all_files_in_debug_info)
    extract_global_variables(raw_content, all_global_variables,
                             all_files_in_debug_info)
    extract_types(raw_content, all_types, all_files_in_debug_info)

    return (
        content_hash,
        all_files_in_debug_info,
        all_functions_in_debug,
        all_global_variables,
        all_types,
        path_mapping,
        original_base_dir,
    )


def load_debug_report(debug_files, base_dir=None):
    """Load debug report from files.

    Args:
        debug_files: List of debug report file paths
        base_dir: Optional base directory to resolve relative paths against
                  when loading in a different environment

    Returns:
        Dictionary containing debug information with paths resolved
    """
    all_files_in_debug_info = dict()
    all_functions_in_debug = dict()
    all_global_variables = dict()
    all_types = dict()
    path_mapping = {}
    original_base_dir = None
    seen_hashes = set()  # Track processed content

    def _merge_debug_payload(payload: DebugPayload) -> None:
        nonlocal path_mapping
        nonlocal original_base_dir
        (content_hash, payload_files, payload_functions, payload_globals,
         payload_types, payload_path_mapping, payload_base_dir) = payload
        if content_hash in seen_hashes:
            return
        seen_hashes.add(content_hash)
        if not path_mapping and payload_path_mapping:
            path_mapping = payload_path_mapping
        if original_base_dir is None and payload_base_dir:
            original_base_dir = payload_base_dir
        all_files_in_debug_info.update(payload_files)
        all_functions_in_debug.update(payload_functions)
        all_global_variables.update(payload_globals)
        all_types.update(payload_types)

    parallel_enabled = _parse_bool_env("FI_DEBUG_REPORT_PARALLEL", True)
    max_workers_default = min(os.cpu_count() or 1, 8)
    worker_count = _parse_int_env("FI_DEBUG_REPORT_WORKERS",
                                  max_workers_default, 1)

    if parallel_enabled and worker_count > 1 and len(debug_files) > 1:
        logger.info("Loading %d debug report files with %d workers",
                    len(debug_files), min(worker_count, len(debug_files)))
        indexed_payloads: dict[int, DebugPayload] = {}
        fallback_to_serial = False
        try:
            with ProcessPoolExecutor(
                    max_workers=min(worker_count, len(debug_files))) as ex:
                future_to_idx = {
                    ex.submit(_load_debug_file_payload, debug_file): idx
                    for idx, debug_file in enumerate(debug_files)
                }
                for future in as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        indexed_payloads[idx] = future.result()
                    except Exception as err:
                        logger.warning((
                            "Parallel debug report parsing failed at index %d: "
                            "%s. Falling back to serial parsing."), idx, err)
                        fallback_to_serial = True
                        break
        except (OSError, RuntimeError, ValueError) as err:
            logger.warning(
                "Failed to initialize parallel debug report parsing: %s. "
                "Falling back to serial parsing.", err)
            fallback_to_serial = True
        if not fallback_to_serial:
            for idx in range(len(debug_files)):
                _merge_debug_payload(indexed_payloads[idx])
        else:
            all_files_in_debug_info.clear()
            all_functions_in_debug.clear()
            all_global_variables.clear()
            all_types.clear()
            path_mapping = {}
            original_base_dir = None
            seen_hashes.clear()
            for debug_file in debug_files:
                try:
                    _merge_debug_payload(_load_debug_file_payload(debug_file))
                except (IOError, OSError) as e:
                    logger.warning("Failed to read debug file %s: %s",
                                   debug_file, e)
                    continue
    else:
        for debug_file in debug_files:
            try:
                _merge_debug_payload(_load_debug_file_payload(debug_file))
            except (IOError, OSError) as e:
                logger.warning("Failed to read debug file %s: %s", debug_file,
                               e)
                continue
    if base_dir and (path_mapping or original_base_dir):
        # Remap paths from original base to new base
        for file_dict in all_files_in_debug_info.values():
            original_path = file_dict["source_file"]
            # If we have a path mapping, use it
            if original_path in path_mapping:
                # Path was relative in original, now make it relative to new base
                file_dict["source_file"] = original_path
            elif original_base_dir and os.path.isabs(original_path):
                # Convert absolute path from original base to new base
                try:
                    file_dict["source_file"] = _make_path_absolute(
                        original_path, base_dir)
                except (ValueError, OSError) as e:
                    logger.debug("Failed to resolve path %s: %s",
                                 original_path, e)

    report_dict = {
        "all_files_in_project": list(all_files_in_debug_info.values()),
        "all_functions_in_project": list(all_functions_in_debug.values()),
        "all_global_variables": list(all_global_variables.values()),
        "all_types": list(all_types.values()),
    }

    return report_dict


def _make_path_relative(source_file, base_dir):
    """Convert absolute path to relative path based on base_dir.

    Args:
        source_file: The source file path (absolute or relative)
        base_dir: Base directory to make paths relative to

    Returns:
        Relative path if conversion is possible, otherwise original path
    """
    if not base_dir:
        return source_file

    abs_source = os.path.abspath(source_file)
    abs_base = os.path.abspath(base_dir)

    # Check if source_file is under base_dir
    if abs_source.startswith(abs_base + os.sep) or abs_source == abs_base:
        rel_path = os.path.relpath(abs_source, abs_base)
        # Use forward slashes for portability
        return rel_path.replace(os.sep, "/")

    return source_file


def _make_path_absolute(source_file, base_dir):
    """Convert relative path to absolute path based on base_dir.

    Args:
        source_file: The source file path (relative or absolute)
        base_dir: Base directory to resolve relative paths against

    Returns:
        Absolute path if conversion is possible, otherwise original path
    """
    if not base_dir:
        return source_file

    # If already absolute, return as-is
    if os.path.isabs(source_file):
        return source_file

    # Resolve relative path against base_dir
    abs_path = os.path.abspath(os.path.join(base_dir, source_file))
    return abs_path


def dump_debug_report(report_dict, out_dir, base_dir=None):
    """Dump debug report to output directory.

    Args:
        report_dict: Dictionary containing debug information
        out_dir: Output directory for the debug report
        base_dir: Optional base directory to make source file paths relative to
                  for cross-environment portability
    """
    # Place this import here because it makes it easier to run this module
    # as a main module.
    from fuzz_introspector import constants

    if not os.path.isdir(os.path.join(out_dir, constants.SAVED_SOURCE_FOLDER)):
        os.mkdir(os.path.join(out_dir, constants.SAVED_SOURCE_FOLDER))

    # Track original and remapped paths for the report
    path_mapping = {}

    for file_elem in report_dict["all_files_in_project"]:
        source_file = file_elem["source_file"]

        # Convert to relative path if base_dir is provided
        if base_dir:
            relative_path = _make_path_relative(source_file, base_dir)
            if relative_path != source_file:
                path_mapping[source_file] = relative_path
                source_file = relative_path
            # Update the source_file in the file_elem to the relative path
            file_elem["source_file"] = relative_path

        # Try to locate the file - check both original and relative paths
        actual_file = None
        if os.path.isfile(file_elem["source_file"]):
            actual_file = file_elem["source_file"]
        elif base_dir and os.path.isfile(
                os.path.join(base_dir, file_elem["source_file"])):
            actual_file = os.path.join(base_dir, file_elem["source_file"])

        if actual_file is None:
            logger.debug("No such file: %s (base_dir: %s)",
                         file_elem["source_file"], base_dir)
            continue

        try:
            dst = os.path.join(
                out_dir,
                constants.SAVED_SOURCE_FOLDER + "/" + file_elem["source_file"])
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy(actual_file, dst)
        except (IOError, OSError) as e:
            logger.warning("Failed to copy source file %s: %s", actual_file, e)

    # Add path mapping to report for cross-environment loading
    if path_mapping:
        report_dict["_path_mapping"] = path_mapping
        report_dict["_base_dir"] = base_dir

    with open(os.path.join(out_dir, constants.DEBUG_INFO_DUMP),
              "w") as debug_dump:
        debug_dump.write(json.dumps(report_dict))


def load_debug_all_yaml_files(debug_all_types_files):
    return _load_yaml_collections(debug_all_types_files, "debug-info")


# ------------------------------------------------------------
# YAML loading and correlation helpers (streamed + sharded)
# ------------------------------------------------------------


def _parse_bool_env(var_name: str, default: bool) -> bool:
    raw = os.environ.get(var_name, "")
    if raw == "":
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


def _parse_int_env(var_name: str,
                   default: int,
                   minimum: int = 1,
                   maximum: int | None = None) -> int:
    raw = os.environ.get(var_name, "")
    if raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r; using default %d", var_name, raw,
                       default)
        return default
    if value < minimum:
        logger.warning("Invalid %s=%r; using minimum %d", var_name, raw,
                       minimum)
        return minimum
    if maximum is not None and value > maximum:
        return maximum
    return value


def _chunked(iterable: list[_T], size: int) -> list[list[_T]]:
    if size <= 0:
        return [iterable]
    return [iterable[i:i + size] for i in range(0, len(iterable), size)]


def _safe_file_size(path: str) -> int:
    try:
        file_size = os.path.getsize(path)
    except OSError as exc:
        logger.debug("Could not stat %s for size-balanced sharding: %s", path,
                     exc)
        return 1
    if file_size <= 0:
        return 1
    return file_size


def _build_size_balanced_shards(paths: list[str],
                                shard_size: int) -> list[list[str]]:
    fixed_shards = _chunked(paths, shard_size)
    target_shard_count = len(fixed_shards)
    if target_shard_count <= 1:
        return fixed_shards

    weighted_paths = [(path, _safe_file_size(path)) for path in paths]
    total_size = sum(file_size for _, file_size in weighted_paths)
    if total_size <= 0:
        return fixed_shards

    target_shard_size = total_size / target_shard_count
    shards: list[list[str]] = []
    current_shard: list[str] = []
    current_shard_size = 0
    path_count = len(weighted_paths)

    for idx, (path, file_size) in enumerate(weighted_paths):
        current_shard.append(path)
        current_shard_size += file_size

        completed_shards_after_close = len(shards) + 1
        remaining_shards = target_shard_count - completed_shards_after_close
        remaining_paths = path_count - (idx + 1)
        if remaining_shards <= 0:
            continue

        enough_for_remaining = remaining_paths >= remaining_shards
        must_close_to_fill = remaining_paths == remaining_shards
        meets_target = current_shard_size >= target_shard_size

        if enough_for_remaining and (meets_target or must_close_to_fill):
            shards.append(current_shard)
            current_shard = []
            current_shard_size = 0

    if current_shard:
        shards.append(current_shard)

    if len(shards) != target_shard_count:
        logger.warning(
            "Failed to build size-balanced shards; using fixed-count")
        return fixed_shards
    return shards


def _build_yaml_shards(paths: list[str], shard_size: int) -> list[list[str]]:
    strategy = os.environ.get("FI_DEBUG_SHARD_STRATEGY",
                              "fixed_count").strip().lower() or "fixed_count"
    if strategy == "fixed_count":
        return _chunked(paths, shard_size)
    if strategy == "size_balanced":
        return _build_size_balanced_shards(paths, shard_size)

    logger.warning(
        "Invalid FI_DEBUG_SHARD_STRATEGY=%r; using default "
        "'fixed_count'", strategy)
    return _chunked(paths, shard_size)


def _load_yaml_file(path: str) -> Any:
    with open(path, "r") as yaml_f:
        return yaml.safe_load(yaml_f)


def _load_yaml_shard(paths: list[str]) -> list[Any]:
    shard_items = []
    for path in paths:
        try:
            parsed = _load_yaml_file(path)
            if parsed:
                shard_items.extend(parsed)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to load yaml file %s: %s", path, exc)
    return shard_items


def _write_spill(items: list[Any], category: str) -> tuple[str, int]:
    fd, spill_path = tempfile.mkstemp(prefix=f"fi-{category}-",
                                      suffix=".jsonl")
    os.close(fd)
    try:
        with open(spill_path, "w") as spill_fp:
            json.dump(items, spill_fp)
    except Exception:
        try:
            os.remove(spill_path)
        except OSError:
            pass
        raise
    return spill_path, len(items)


def _estimate_list_bytes(items: list[Any]) -> int:
    if not items:
        return 0

    # Keep this estimate intentionally cheap to avoid large temporary
    # allocations from serializing entire shards.
    sample_size = min(len(items), 32)
    sample = items[:sample_size]
    sample_bytes = sum(sys.getsizeof(item) for item in sample)
    avg_item_bytes = sample_bytes // sample_size if sample_size else 0
    return sys.getsizeof(items) + (avg_item_bytes * len(items))


def _get_process_rss_mb() -> float | None:
    try:
        with open("/proc/self/statm", "r", encoding="utf-8") as statm_file:
            rss_pages = int(statm_file.read().split()[1])
        page_size = os.sysconf("SC_PAGE_SIZE")
        return rss_pages * page_size / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        return None


def _select_debug_parallel_backend(category: str, shard_count: int) -> str:
    legacy_backend_raw = os.environ.get("FI_DEBUG_USE_PROCESS_POOL", "")
    if legacy_backend_raw:
        legacy_process = _parse_bool_env("FI_DEBUG_USE_PROCESS_POOL", False)
        return "process" if legacy_process else "thread"

    configured_backend = (os.environ.get("FI_DEBUG_PARALLEL_BACKEND",
                                         "auto").strip().lower() or "auto")
    if configured_backend not in ("auto", "thread", "process"):
        logger.warning(
            "Invalid FI_DEBUG_PARALLEL_BACKEND=%r; using default 'auto'",
            configured_backend)
        configured_backend = "auto"

    if configured_backend != "auto":
        return configured_backend
    if category == "debug-info" and shard_count > 1:
        return "process"
    return "thread"


def _load_yaml_collections(paths: list[str], category: str) -> list[Any]:
    try:
        yaml.SafeLoader = yaml.CSafeLoader  # type: ignore[assignment, misc]
        logger.info("Set base loader to use CSafeLoader")
    except Exception:
        logger.info("Could not set the CSafeLoader as base loader")

    if not paths:
        return []

    parallel_enabled = _parse_bool_env("FI_DEBUG_PARALLEL", True)
    max_workers_default = min(os.cpu_count() or 1, 8)
    worker_count = _parse_int_env("FI_DEBUG_MAX_WORKERS", max_workers_default,
                                  1)
    shard_size = _parse_int_env("FI_DEBUG_SHARD_FILES", 4, 1)
    spill_mb = _parse_int_env("FI_DEBUG_SPILL_MB", 0, 0)
    max_inmem_mb = _parse_int_env("FI_DEBUG_MAX_INMEM_MB", 0, 0)
    rss_soft_limit_mb = _parse_int_env("FI_DEBUG_RSS_SOFT_LIMIT_MB", 0, 0)
    stall_warn_seconds = _parse_int_env("FI_DEBUG_SHARD_STALL_WARN_SEC", 180,
                                        0)
    shards = _build_yaml_shards(list(paths), shard_size)
    shard_count = len(shards)
    selected_backend = _select_debug_parallel_backend(category, shard_count)
    process_workers_default = min(os.cpu_count() or 1, 4)
    process_worker_count = _parse_int_env("FI_DEBUG_PROCESS_WORKERS",
                                          process_workers_default, 1)
    executor_worker_count = worker_count
    if selected_backend == "process":
        executor_worker_count = min(process_worker_count, worker_count)

    raw_max_inflight = os.environ.get("FI_DEBUG_MAX_INFLIGHT_SHARDS",
                                      "").strip()
    if raw_max_inflight:
        max_inflight_default = shard_count
    elif category == "debug-info":
        max_inflight_default = min(max(1, executor_worker_count), 2,
                                   shard_count)
    else:
        max_inflight_default = shard_count
    max_inflight_shards = _parse_int_env("FI_DEBUG_MAX_INFLIGHT_SHARDS",
                                         max_inflight_default, 1, shard_count)
    adaptive_workers_enabled = _parse_bool_env("FI_DEBUG_ADAPTIVE_WORKERS",
                                               False)
    spill_policy = os.environ.get("FI_DEBUG_SPILL_POLICY",
                                  "oldest").strip().lower() or "oldest"
    if spill_policy not in ("oldest", "largest"):
        logger.warning(
            "Invalid FI_DEBUG_SPILL_POLICY=%r; using default "
            "'oldest'", spill_policy)
        spill_policy = "oldest"
    shard_items_by_idx: dict[int, list[Any]] = {}
    shard_bytes_by_idx: dict[int, int] = {}
    spilled_by_idx: dict[int, str] = {}
    spill_threshold_bytes = spill_mb * 1024 * 1024
    max_inmem_bytes = max_inmem_mb * 1024 * 1024
    current_mem_bytes = 0

    def _should_spill() -> bool:
        if spill_threshold_bytes > 0 and current_mem_bytes >= spill_threshold_bytes:
            return True
        if max_inmem_bytes > 0 and current_mem_bytes >= max_inmem_bytes:
            return True
        return False

    def _record_shard_items(shard_idx: int, items: list[Any]) -> int:
        nonlocal current_mem_bytes
        spill_count = 0
        shard_items_by_idx[shard_idx] = items
        if spill_threshold_bytes <= 0 and max_inmem_bytes <= 0:
            return spill_count

        shard_bytes = _estimate_list_bytes(items)
        shard_bytes_by_idx[shard_idx] = shard_bytes
        current_mem_bytes += shard_bytes
        while _should_spill() and shard_items_by_idx:
            if spill_policy == "largest":
                spill_idx = max(shard_items_by_idx,
                                key=lambda idx:
                                (shard_bytes_by_idx.get(idx, 0), -idx))
            else:
                spill_idx = min(shard_items_by_idx)
            spill_items = shard_items_by_idx[spill_idx]
            spill_bytes = shard_bytes_by_idx.pop(
                spill_idx, _estimate_list_bytes(spill_items))
            spill_path, _ = _write_spill(spill_items, category)
            shard_items_by_idx.pop(spill_idx)
            current_mem_bytes -= spill_bytes
            spilled_by_idx[spill_idx] = spill_path
            spill_count += 1
            logger.info(
                "Spilled shard %d/%d to %s (in-memory: %d bytes)",
                spill_idx + 1,
                shard_count,
                spill_path,
                current_mem_bytes,
            )
        return spill_count

    def _load_serial_shards() -> None:
        for shard_idx, shard in enumerate(shards):
            logger.info("Loading shard %d/%d (%d files)", shard_idx + 1,
                        shard_count, len(shard))
            _record_shard_items(shard_idx, _load_yaml_shard(shard))

    def _reset_parallel_state() -> None:
        nonlocal current_mem_bytes
        shard_items_by_idx.clear()
        shard_bytes_by_idx.clear()
        for spill_path in spilled_by_idx.values():
            try:
                os.remove(spill_path)
            except OSError:
                pass
        spilled_by_idx.clear()
        current_mem_bytes = 0

    def _run_parallel_shards_with_executor(executor_cls: Any,
                                           execution_label: str,
                                           max_workers: int) -> bool:
        run_start = time.perf_counter()
        shard_start_elapsed: dict[int, float] = {}
        shard_end_elapsed: dict[int, float] = {}
        adaptive_inflight_cap = max_inflight_shards
        spill_streak = 0
        tail_latency_streak = 0
        shard_elapsed_seconds: list[float] = []
        rss_relief_streak = 0
        last_progress = run_start
        next_stall_warn = run_start + stall_warn_seconds

        def _log_parallel_shard_telemetry() -> None:
            for shard_idx in sorted(shard_end_elapsed):
                start_elapsed = shard_start_elapsed.get(shard_idx, 0.0)
                end_elapsed = shard_end_elapsed[shard_idx]
                logger.info(
                    ("Parallel shard telemetry for %s %d/%d: start=%.4fs "
                     "end=%.4fs elapsed=%.4fs files=%d"),
                    category,
                    shard_idx + 1,
                    shard_count,
                    start_elapsed,
                    end_elapsed,
                    end_elapsed - start_elapsed,
                    len(shards[shard_idx]),
                )

        try:
            with executor_cls(max_workers=min(max_workers, len(shards))) as ex:
                future_to_idx: dict[Any, int] = {}

                def _submit_shard(shard_idx: int) -> None:
                    shard = shards[shard_idx]
                    shard_start_elapsed[shard_idx] = (time.perf_counter() -
                                                      run_start)
                    future_to_idx[ex.submit(_load_yaml_shard,
                                            shard)] = shard_idx

                next_idx = 0
                initial_inflight = min(adaptive_inflight_cap, len(shards))
                while next_idx < initial_inflight:
                    _submit_shard(next_idx)
                    next_idx += 1
                logger.info(
                    "Submitted %d/%d %s shards to %s pool (max in-flight %d)",
                    len(future_to_idx), len(shards), category, execution_label,
                    max_inflight_shards)
                loaded_count = 0
                while future_to_idx:
                    done_futures, _ = wait(set(future_to_idx),
                                           timeout=1.0,
                                           return_when=FIRST_COMPLETED)
                    if not done_futures:
                        if stall_warn_seconds > 0:
                            now = time.perf_counter()
                            if now >= next_stall_warn:
                                logger.warning(
                                    ("No shard completion for %s in %.1fs "
                                     "(progress: %d/%d, in-flight: %d)"),
                                    category, now - last_progress,
                                    loaded_count, shard_count,
                                    len(future_to_idx))
                                next_stall_warn = now + stall_warn_seconds
                        continue
                    for future in done_futures:
                        idx = future_to_idx.pop(future)
                        shard_end_elapsed[idx] = time.perf_counter(
                        ) - run_start
                        try:
                            items = future.result()
                        except Exception as exc:  # pragma: no cover - defensive
                            _log_parallel_shard_telemetry()
                            logger.warning(
                                ("%s shard %d failed: %s; aborting %s "
                                 "execution"), execution_label.capitalize(),
                                idx, exc, execution_label)
                            return False
                        logger.info("Loaded shard %d/%d (%d files)", idx + 1,
                                    shard_count, len(shards[idx]))
                        spill_count = _record_shard_items(idx, items)
                        loaded_count += 1
                        logger.info("Shard load progress for %s: %d/%d",
                                    category, loaded_count, shard_count)
                        last_progress = time.perf_counter()
                        if stall_warn_seconds > 0:
                            next_stall_warn = last_progress + stall_warn_seconds

                        if rss_soft_limit_mb > 0:
                            rss_mb = _get_process_rss_mb()
                            if rss_mb is not None:
                                if rss_mb > rss_soft_limit_mb:
                                    rss_relief_streak = 0
                                    previous_cap = adaptive_inflight_cap
                                    if rss_mb >= rss_soft_limit_mb * 1.10:
                                        adaptive_inflight_cap = 1
                                    else:
                                        adaptive_inflight_cap = min(
                                            adaptive_inflight_cap, 2)
                                    if adaptive_inflight_cap < previous_cap:
                                        logger.info(
                                            "Memory pressure downshift for %s: "
                                            "rss=%.2fMB limit=%dMB "
                                            "max in-flight %d -> %d", category,
                                            rss_mb, rss_soft_limit_mb,
                                            previous_cap, adaptive_inflight_cap)
                                elif (rss_mb <= rss_soft_limit_mb * 0.85
                                      and adaptive_inflight_cap <
                                      max_inflight_shards):
                                    rss_relief_streak += 1
                                    if rss_relief_streak >= 2:
                                        previous_cap = adaptive_inflight_cap
                                        adaptive_inflight_cap = min(
                                            max_inflight_shards,
                                            adaptive_inflight_cap + 1)
                                        rss_relief_streak = 0
                                        logger.info(
                                            "Memory pressure recovery for %s: "
                                            "rss=%.2fMB limit=%dMB "
                                            "max in-flight %d -> %d", category,
                                            rss_mb, rss_soft_limit_mb,
                                            previous_cap, adaptive_inflight_cap)
                                else:
                                    rss_relief_streak = 0
                        if adaptive_workers_enabled:
                            if spill_count > 0:
                                spill_streak += 1
                            else:
                                spill_streak = 0

                            shard_elapsed = (shard_end_elapsed[idx] -
                                             shard_start_elapsed.get(idx, 0.0))
                            shard_elapsed_seconds.append(shard_elapsed)
                            if len(shard_elapsed_seconds) >= 4:
                                sorted_elapsed = sorted(shard_elapsed_seconds)
                                median_elapsed = sorted_elapsed[
                                    len(sorted_elapsed) // 2]
                                tail_threshold = max(0.2, median_elapsed * 2.5)
                                if shard_elapsed >= tail_threshold:
                                    tail_latency_streak += 1
                                else:
                                    tail_latency_streak = 0

                            pressure_detected = (spill_streak >= 2
                                                 or tail_latency_streak >= 2)
                            if adaptive_inflight_cap > 1 and pressure_detected:
                                previous_cap = adaptive_inflight_cap
                                adaptive_inflight_cap -= 1
                                spill_streak = 0
                                tail_latency_streak = 0
                                logger.info(
                                    ("Adaptive worker downshift for %s: "
                                     "max in-flight %d -> %d"),
                                    category,
                                    previous_cap,
                                    adaptive_inflight_cap,
                                )
                        while (next_idx < len(shards)
                               and len(future_to_idx) < adaptive_inflight_cap):
                            _submit_shard(next_idx)
                            next_idx += 1
                _log_parallel_shard_telemetry()
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning("Failed to initialize %s shard pool: %s",
                           execution_label, exc)
            return False
        return True

    try:
        if parallel_enabled and worker_count > 1 and len(shards) > 1:
            logger.info(
                ("Loading %d %s shards with %d workers "
                 "(backend=%s, pool=%s, max in-flight=%d, "
                 "rss soft limit=%dMB)"),
                len(shards),
                category,
                executor_worker_count,
                selected_backend,
                "process" if selected_backend == "process" else "thread",
                max_inflight_shards,
                rss_soft_limit_mb,
            )
            loaded_in_parallel = False
            if selected_backend == "process":
                loaded_in_parallel = _run_parallel_shards_with_executor(
                    ProcessPoolExecutor, "process", executor_worker_count)
                if not loaded_in_parallel:
                    _reset_parallel_state()
                    logger.info(
                        "Falling back to thread pool for %d %s shards",
                        len(shards),
                        category,
                    )
                    loaded_in_parallel = _run_parallel_shards_with_executor(
                        ThreadPoolExecutor, "thread", worker_count)
            else:
                loaded_in_parallel = _run_parallel_shards_with_executor(
                    ThreadPoolExecutor, "thread", executor_worker_count)

            if not loaded_in_parallel:
                _reset_parallel_state()
                logger.info(
                    "Falling back to serial loading for %d %s shards",
                    len(shards),
                    category,
                )
                _load_serial_shards()
        else:
            logger.info("Loading %d %s files serially (shard size %d)",
                        len(paths), category, shard_size)
            _load_serial_shards()

        results: list[Any] = []
        if spilled_by_idx:
            logger.info("Merging %d spilled shards for %s",
                        len(spilled_by_idx), category)
        merged_count = 0
        for idx in range(shard_count):
            spill_path = spilled_by_idx.pop(idx, None)
            if spill_path is not None:
                logger.info("Merging spilled shard %d/%d from %s", idx + 1,
                            shard_count, spill_path)
                try:
                    with open(spill_path, "r") as spill_fp:
                        items = json.load(spill_fp)
                        results.extend(items)
                finally:
                    try:
                        os.remove(spill_path)
                    except OSError:
                        pass
                merged_count += 1
                logger.info("Shard merge progress for %s: %d/%d", category,
                            merged_count, shard_count)
                continue
            results.extend(shard_items_by_idx.get(idx, []))
            merged_count += 1
            logger.info("Shard merge progress for %s: %d/%d", category,
                        merged_count, shard_count)
        return results
    finally:
        for spill_path in spilled_by_idx.values():
            try:
                os.remove(spill_path)
            except OSError:
                pass


# ------------------------------------------------------------


def extract_func_sig_friendly_type_tags(target_type, debug_type_dictionary):
    """Recursively iterates atomic type elements to construct a friendly
    string representing the type."""
    if int(target_type) == 0:
        return ["void"]

    tags = []
    type_to_query = target_type
    addresses_visited = set()
    while True:
        if type_to_query in addresses_visited:
            tags.append("Infinite loop")
            break

        target_type = debug_type_dictionary.get(int(type_to_query), None)
        if target_type is None:
            tags.append("N/A")
            break

        # Provide the tag
        tags.append(target_type["tag"])
        if "array" in target_type["tag"]:
            tags.append("ARRAY-SIZE: %d" % (target_type["const_size"]))

        name = target_type.get("name", "")
        if name != "":
            tags.append(name)
            break

        base_type_string = target_type.get("base_type_string", "")
        if base_type_string != "":
            tags.append(base_type_string)
            break

        addresses_visited.add(type_to_query)

        type_to_query = target_type.get("base_type_addr", "")
        if int(type_to_query) == 0:
            tags.append("void")
            break

    return tags


def extract_debugged_function_signature(dfunc, debug_type_dictionary):
    """Extract the raw types used by a function."""
    try:
        return_type = extract_func_sig_friendly_type_tags(
            dfunc["type_arguments"][0], debug_type_dictionary)
    except IndexError:
        return_type = "N/A"
    params = []

    if len(dfunc["type_arguments"]) > 1:
        for i in range(1, len(dfunc["type_arguments"])):
            params.append(
                extract_func_sig_friendly_type_tags(dfunc["type_arguments"][i],
                                                    debug_type_dictionary))

    source_file = dfunc["file_location"].split(":")[0]
    try:
        source_line = dfunc["file_location"].split(":")[1]
    except IndexError:
        source_line = "-1"

    function_signature_elements = {
        "return_type": return_type,
        "params": params,
    }
    source_location = {"source_file": source_file, "source_line": source_line}

    return function_signature_elements, source_location


def convert_param_list_to_str_v2(param_list):
    pre = ""
    med = ""
    post = ""
    for param in param_list:
        if param == "DW_TAG_pointer_type":
            post += "*"
        elif param == "DW_TAG_reference_type":
            post += "&"
        elif param == "DW_TAG_structure_type":
            med += " struct "
            continue
        elif param == "DW_TAG_base_type":
            continue
        elif param == "DW_TAG_typedef":
            continue
        elif param == "DW_TAG_class_type":
            continue
        elif param == "DW_TAG_const_type":
            pre += "const "
        elif param == "DW_TAG_enumeration_type":
            continue
        else:
            med += str(param)

    raw_sig = pre.strip() + " " + med + " " + post
    return raw_sig.strip()


def is_struct(param_list):
    for param in param_list:
        if param == "DW_TAG_structure_type":
            return True
    return False


def is_enumeration(param_list):
    for param in param_list:
        if param == "DW_TAG_enumeration_type":
            return True
    return False


def create_friendly_debug_types(debug_type_dictionary,
                                out_dir,
                                dump_files=True):
    """Create an address-indexed json dictionary. The goal is to use this for
    fast iteration over types using e.g. recursive lookups."""
    logging.info("Have to create for %d addresses" %
                 (len(debug_type_dictionary)))

    addr_members = collections.defaultdict(list)
    for elem_addr, elem_val in debug_type_dictionary.items():
        if elem_val["tag"] == "DW_TAG_member":
            elem_dict = {
                "addr":
                elem_addr,
                "elem_name":
                elem_val["name"],
                "elem_friendly_type":
                convert_param_list_to_str_v2(
                    extract_func_sig_friendly_type_tags(
                        elem_val["base_type_addr"], debug_type_dictionary)),
            }
            addr_members[int(elem_val["scope"])].append(elem_dict)

    # Nothing consumes this structure in-memory today; it is only persisted.
    # Avoid large temporary maps and serialize incrementally.
    if not dump_files:
        return

    output_path = os.path.join(out_dir, "all-friendly-debug-types.json")
    with open(output_path, "w") as f:
        f.write("{")
        for idx, addr in enumerate(debug_type_dictionary):
            if idx % 2500 == 0 and idx > 0:
                logging.info("Idx: %d" % (idx))

            friendly_type = extract_func_sig_friendly_type_tags(
                addr, debug_type_dictionary)
            structure_elems = []
            if is_struct(friendly_type):
                structure_elems = addr_members.get(int(addr), [])

            entry = {
                "raw_debug_info": debug_type_dictionary[addr],
                "friendly-info": {
                    "raw-types":
                    friendly_type,
                    "string_type":
                    convert_param_list_to_str_v2(friendly_type),
                    "is-struct":
                    is_struct(friendly_type),
                    "struct-elems":
                    structure_elems,
                    "is-enum":
                    is_enumeration(friendly_type),
                    "enum-elems":
                    debug_type_dictionary[addr].get("enum_elems", []),
                },
            }
            if idx > 0:
                f.write(",")
            f.write(json.dumps(str(addr)))
            f.write(":")
            json.dump(entry, f)
        f.write("}")


def correlate_debugged_function_to_debug_types(all_debug_types,
                                               all_debug_functions,
                                               out_dir,
                                               dump_files=True):
    """Correlate debug information about all functions and all types. The
    result is a lot of atomic debug-information-extracted types are correlated
    to the debug function."""
    # Index debug types by address. We need to do a lot of look ups when
    # refining data types where the address is the key, so a fast
    # look-up mechanism is useful here.
    debug_type_dictionary = dict()
    for debug_type in all_debug_types:
        debug_type_dictionary[int(debug_type["addr"])] = debug_type

    # Create json file with addresses as indexes for type information.
    # This can be used to lookup types fast.
    logger.info("Creating dictionary")
    create_friendly_debug_types(debug_type_dictionary,
                                out_dir,
                                dump_files=dump_files)
    logger.info("Finished creating dictionary")

    parallel_enabled = _parse_bool_env("FI_DEBUG_CORRELATE_PARALLEL", True)
    max_workers_default = min(os.cpu_count() or 1, 8)
    worker_count = _parse_int_env("FI_DEBUG_CORRELATE_WORKERS",
                                  max_workers_default, 1)
    total_funcs = len(all_debug_functions)
    chunk_size = max(1, total_funcs // worker_count) if worker_count > 0 else 1

    def _process_slice(func_slice):
        _correlate_function_slice(func_slice, debug_type_dictionary)

    if parallel_enabled and worker_count > 1 and total_funcs > 1:
        logger.info("Correlating %d debug functions with %d threads",
                    total_funcs, worker_count)
        chunks = _chunked(all_debug_functions, chunk_size)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(_process_slice, chunk): idx
                for idx, chunk in enumerate(chunks)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "Parallel correlation chunk %d failed: %s; "
                        "falling back to serial", idx, exc)
                    _correlate_function_slice(all_debug_functions,
                                              debug_type_dictionary)
                    break
    else:
        logger.info("Correlating %d debug functions serially", total_funcs)
        _correlate_function_slice(all_debug_functions, debug_type_dictionary)


def _correlate_function_slice(func_slice: list[Any],
                              debug_type_dictionary: dict[int, Any]) -> None:
    """Correlate function signatures for a function slice in-place.

    Kept as a module-level helper so correlation execution backends can reuse
    one implementation while preserving current mutation semantics.
    """
    for dfunc in func_slice:
        func_signature_elems, source_location = (
            extract_debugged_function_signature(dfunc, debug_type_dictionary))
        dfunc["func_signature_elems"] = func_signature_elems
        dfunc["source"] = source_location


def extract_syzkaller_type(param_list):
    """Converts the dwarf tag list to a syzkaller type."""
    pre = ""
    med = ""
    post = ""
    syzkaller_tag = ""
    for param in reversed(param_list):
        if param == "DW_TAG_pointer_type":
            syzkaller_tag = "ptr [in, %s]" % (syzkaller_tag)
        elif param == "DW_TAG_reference_type":
            post += "&"
        elif param == "DW_TAG_structure_type":
            continue
        elif param == "DW_TAG_base_type":
            continue
        elif param == "DW_TAG_typedef":
            continue
        elif param == "DW_TAG_class_type":
            continue
        elif param == "DW_TAG_const_type":
            pre += "const "
        elif param == "DW_TAG_enumeration_type":
            continue
        elif "ARRAY-SIZE" in param:
            syzkaller_tag = "%s, %s" % (syzkaller_tag,
                                        param.replace("ARRAY-SIZE:", ""))
        elif "DW_TAG_array" in param:
            syzkaller_tag = "array[%s]" % (syzkaller_tag)
        else:
            # This is a type and we should convert it to the syzkaller type
            if param == "char":
                syzkaller_tag = "int8"
            elif param == "int" or param == "unsigned int":
                syzkaller_tag = "int32"
            elif param == "__i32" or param == "__b32":
                syzkaller_tag = "int32"
            elif param == "__u32" or param == "u32":
                syzkaller_tag = "int32"
            elif param == "__s32" or param == "s32":
                syzkaller_tag = "int32"
            elif param == "__u64" or param == "s64":
                syzkaller_tag = "int64"
            elif param == "unsigned long long":
                syzkaller_tag = "int64"
            elif param == "__u8" or param == "u8" or param == "__s8":
                syzkaller_tag = "int8"
            elif param == "__u16" or param == "u16":
                syzkaller_tag = "int16"
            else:
                # This is a struct, so we name it appropriately
                syzkaller_tag = param

            med += str(param)

    return syzkaller_tag


def get_struct_members(addr, debug_type_dictionary):
    structure_elems = []
    for elem_addr, elem_val in debug_type_dictionary.items():
        if elem_val["tag"] == "DW_TAG_member" and int(
                elem_val["scope"]) == int(addr):
            friendly_type = extract_func_sig_friendly_type_tags(
                elem_val["base_type_addr"], debug_type_dictionary)
            print("name: %s" % (elem_val["name"]))
            print(friendly_type)
            print(convert_param_list_to_str_v2(friendly_type))

            syzkaller_type = extract_syzkaller_type(friendly_type)

            elem_dict = {
                "addr":
                elem_addr,
                "syzkaller_type":
                syzkaller_type,
                "elem_name":
                elem_val["name"],
                "raw":
                elem_val,
                "elem_friendly_type":
                convert_param_list_to_str_v2(
                    extract_func_sig_friendly_type_tags(
                        elem_val["base_type_addr"], debug_type_dictionary)),
                "friendly-info": {
                    "raw-types": friendly_type,
                    "string_type": convert_param_list_to_str_v2(friendly_type),
                    "is-struct": is_struct(friendly_type),
                    "is-enum": is_enumeration(friendly_type),
                },
            }
            structure_elems.append(elem_dict)
    return structure_elems


def create_syzkaller_description_for_type(addr, debug_type_dictionary):
    friendly_type = extract_func_sig_friendly_type_tags(
        addr, debug_type_dictionary)

    if is_struct(friendly_type):
        members = get_struct_members(addr, debug_type_dictionary)
        if len(members) == 0:
            return None

        syzkaller_description = "%s {\n" % (friendly_type[-1])
        for struct_mem in members:
            syzkaller_description += " " * 2 + "{0: <25}".format(
                struct_mem["elem_name"])
            syzkaller_description += " " * 4
            syzkaller_description += struct_mem["syzkaller_type"]
            syzkaller_description += "\n"
        syzkaller_description += "}"
        return syzkaller_description
    if is_enumeration(friendly_type):
        raw_debug_type = debug_type_dictionary[addr]
        enum_type = "%s = %s" % (
            raw_debug_type["name"],
            ", ".join(raw_debug_type["enum_elems"]),
        )
        return enum_type

    return None


def syzkaller_get_struct_type_elems(typename, all_debug_types):
    debug_type_dictionary = dict()
    for debug_type in all_debug_types:
        debug_type_dictionary[int(debug_type["addr"])] = debug_type

    for debug_addr, debug_type in debug_type_dictionary.items():
        if debug_type["name"] == typename:
            friendly_type = extract_func_sig_friendly_type_tags(
                debug_addr, debug_type_dictionary)

            if is_struct(friendly_type):
                members = get_struct_members(debug_addr, debug_type_dictionary)
                return members

    return None


def syzkaller_get_type_implementation(typename, all_debug_types):
    # Index debug types by address. We need to do a lot of look ups when
    # refining data types where the address is the key, so a fast
    # look-up mechanism is useful here.
    debug_type_dictionary = dict()
    for debug_type in all_debug_types:
        debug_type_dictionary[int(debug_type["addr"])] = debug_type

    for debug_addr, debug_type in debug_type_dictionary.items():
        if debug_type["name"] == typename:
            syzkaller_description = create_syzkaller_description_for_type(
                debug_addr, debug_type_dictionary)
            if syzkaller_description:
                print("-" * 45)
                print(syzkaller_description)
                return syzkaller_description
    return None


if __name__ in "__main__":
    type_debug_files = [sys.argv[1]]
    typename = sys.argv[2]

    all_types = load_debug_all_yaml_files(type_debug_files)
    syzkaller_get_type_implementation(typename, all_types)
