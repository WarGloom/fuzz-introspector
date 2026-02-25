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

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, TypeVar
import yaml

logger = logging.getLogger(name=__name__)
_T = TypeVar("_T")

# Pre-compiled regex patterns for debug info parsing (performance optimization)
# These patterns are used in extract_all_functions_in_debug_info

# Match the functions section: between "## Functions defined in module" and "## Global variables"
FUNCTION_SECTION_RE = re.compile(
    r"## Functions defined in module\n(.*?)## Global variables", re.DOTALL)

# Match a function definition: "Subprogram: <function_name>"
SUBPROGRAM_RE = re.compile(r"^Subprogram: (.+)$", re.MULTILINE)

# Match source location line: " ... from <filepath>:<line_number>"
# Conditions: contains " from ", contains ":", does NOT contain "- Operand" or "Elem "
SOURCE_LOCATION_RE = re.compile(
    r"^(?!.*- Operand)(?!.*Elem ).* from\s+([^:]+):(\d+).*$", re.MULTILINE)

# Match argument type: " - Operand" lines
# Two patterns:
# 1. "Name: {<name>}" - named argument
# 2. Otherwise - type information
ARG_TYPE_RE = re.compile(r"Name: \{(.+?)\}")
ARG_TYPE_SIMPLE_RE = re.compile(
    r"- Operand.*?(?:Operand Type:|Type: )(.+?)(?: -|$)")


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

    Optimized version using pre-compiled regex patterns for better performance.
    """
    # Find the functions section using regex (single pass)
    functions_match = FUNCTION_SECTION_RE.search(content)
    if not functions_match:
        logger.debug("No functions section found in debug info")
        return

    functions_section = functions_match.group(1)

    # Find all function definitions in the section
    subprogram_matches = list(SUBPROGRAM_RE.finditer(functions_section))

    for idx, func_match in enumerate(subprogram_matches):
        function_name = func_match.group(1).strip()

        # Get the text after this function name until the next function or end
        start_pos = func_match.end()
        if idx + 1 < len(subprogram_matches):
            end_pos = subprogram_matches[idx + 1].start()
        else:
            end_pos = len(functions_section)

        func_block = functions_section[start_pos:end_pos]

        # Parse the function block
        current_function = {"name": function_name}

        # Find source location in the block
        source_match = SOURCE_LOCATION_RE.search(func_block)
        if source_match:
            source_file = source_match.group(1).strip()
            source_line = source_match.group(2).strip()
            current_function["source"] = {
                "source_file": source_file,
                "source_line": source_line,
            }
            # Add the file to all files in project
            if source_file not in all_files_in_debug_info:
                all_files_in_debug_info[source_file] = {
                    "source_file": source_file,
                    "language": "N/A",
                }

        # Find argument types in the block
        args = []

        # Check for "Name: {<name>}" pattern
        for name_match in ARG_TYPE_RE.finditer(func_block):
            args.append(name_match.group(1).strip())

        # Check for type information (lines with " - Operand")
        if len(args) == 0:
            # No named args, look for type-only lines
            for line in func_block.splitlines():
                if " - Operand" in line:
                    # Extract type info
                    l1 = (line.replace("Operand Type:",
                                       "").replace("Type: ",
                                                   "").replace("-", ""))
                    pointer_count = l1.count("DW_TAG_pointer_type")
                    const_count = l1.count("DW_TAG_const_type")

                    # Get base type (last comma-separated part)
                    parts = l1.split(",")
                    if parts:
                        base_type = parts[-1].strip()
                        end_type = ""
                        if const_count > 0:
                            end_type += "const "
                        end_type += base_type
                        if pointer_count > 0:
                            end_type += " " + "*" * pointer_count
                        args.append(end_type)

        if args:
            current_function["args"] = args

        # Create hashkey and add to all_functions_in_debug
        if "source" in current_function:
            try:
                hashkey = (current_function["source"]["source_file"] +
                           current_function["source"]["source_line"])
                all_functions_in_debug[hashkey] = current_function
            except KeyError:
                pass  # Something went wrong, abandon


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

    # Extract all of the details
    for debug_file in debug_files:
        try:
            with open(debug_file, "r") as debug_f:
                raw_content = debug_f.read()

            # Hash the content to avoid parsing identical debug info files
            content_hash = hashlib.md5(raw_content.encode("utf-8")).hexdigest()
            if content_hash in seen_hashes:
                logger.debug("Skipping identical debug file: %s", debug_file)
                continue
            seen_hashes.add(content_hash)

            # Try to extract path mapping from the debug file
            if not path_mapping:
                try:
                    report_data = json.loads(raw_content)
                    path_mapping = report_data.get("_path_mapping", {})
                    original_base_dir = report_data.get("_base_dir", None)
                except (json.JSONDecodeError, KeyError):
                    # Not a JSON file or no mapping available - that's fine
                    pass

            extract_all_compile_units(raw_content, all_files_in_debug_info)
            extract_all_functions_in_debug_info(raw_content,
                                                all_functions_in_debug,
                                                all_files_in_debug_info)
            extract_global_variables(raw_content, all_global_variables,
                                     all_files_in_debug_info)
            extract_types(raw_content, all_types, all_files_in_debug_info)
        except (IOError, OSError) as e:
            logger.warning("Failed to read debug file %s: %s", debug_file, e)
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
    with open(spill_path, "w") as spill_fp:
        json.dump(items, spill_fp)
    return spill_path, len(items)


def _estimate_list_bytes(items: list[Any]) -> int:
    return len(json.dumps(items))


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
    shards = _chunked(list(paths), shard_size)
    shard_count = len(shards)
    shard_items_by_idx: dict[int, list[Any]] = {}
    spilled_by_idx: dict[int, str] = {}
    spill_threshold_bytes = spill_mb * 1024 * 1024
    current_mem_bytes = 0

    def _record_shard_items(shard_idx: int, items: list[Any]) -> None:
        nonlocal current_mem_bytes
        shard_items_by_idx[shard_idx] = items
        if spill_threshold_bytes <= 0:
            return

        current_mem_bytes += _estimate_list_bytes(items)
        while current_mem_bytes >= spill_threshold_bytes and shard_items_by_idx:
            spill_idx = min(shard_items_by_idx)
            spill_items = shard_items_by_idx.pop(spill_idx)
            current_mem_bytes -= _estimate_list_bytes(spill_items)
            spill_path, _ = _write_spill(spill_items, category)
            spilled_by_idx[spill_idx] = spill_path
            logger.info("Spilled shard %d/%d to %s", spill_idx + 1,
                        shard_count, spill_path)

    def _load_serial_shards() -> None:
        for shard_idx, shard in enumerate(shards):
            logger.info("Loading shard %d/%d (%d files)", shard_idx + 1,
                        shard_count, len(shard))
            _record_shard_items(shard_idx, _load_yaml_shard(shard))

    if parallel_enabled and worker_count > 1 and len(shards) > 1:
        logger.info("Loading %d %s shards with %d workers", len(shards),
                    category, worker_count)
        fallback_to_serial = False
        with ThreadPoolExecutor(
                max_workers=min(worker_count, len(shards))) as ex:
            future_to_idx = {
                ex.submit(_load_yaml_shard, shard): idx
                for idx, shard in enumerate(shards)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    items = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "Parallel shard %d failed: %s; falling back serial",
                        idx, exc)
                    fallback_to_serial = True
                    break
                else:
                    logger.info("Loaded shard %d/%d (%d files)", idx + 1,
                                shard_count, len(shards[idx]))
                    _record_shard_items(idx, items)
        if fallback_to_serial:
            shard_items_by_idx.clear()
            for spill_path in spilled_by_idx.values():
                try:
                    os.remove(spill_path)
                except OSError:
                    pass
            spilled_by_idx.clear()
            current_mem_bytes = 0
            _load_serial_shards()
    else:
        logger.info("Loading %d %s files serially (shard size %d)", len(paths),
                    category, shard_size)
        _load_serial_shards()

    results: list[Any] = []
    if spilled_by_idx:
        logger.info("Merging %d spilled shards for %s", len(spilled_by_idx),
                    category)
    for idx in range(shard_count):
        spill_path = spilled_by_idx.get(idx)
        if spill_path is not None:
            try:
                with open(spill_path, "r") as spill_fp:
                    items = json.load(spill_fp)
                    results.extend(items)
            finally:
                try:
                    os.remove(spill_path)
                except OSError:
                    pass
            continue
        results.extend(shard_items_by_idx.get(idx, []))
    return results


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
    friendly_name_sig = dict()
    logging.info("Have to create for %d addresses" %
                 (len(debug_type_dictionary)))
    idx = 0

    addr_members = dict()
    for elem_addr, elem_val in debug_type_dictionary.items():
        if elem_val["tag"] == "DW_TAG_member":
            current_members = addr_members.get(int(elem_val["scope"]), [])
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
            current_members.append(elem_dict)
            addr_members[int(elem_val["scope"])] = current_members

    for addr in debug_type_dictionary:
        idx += 1
        if idx % 2500 == 0:
            logging.info("Idx: %d" % (idx))
        friendly_type = extract_func_sig_friendly_type_tags(
            addr, debug_type_dictionary)

        # is this a struct?
        # Collect elements
        structure_elems = []
        if is_struct(friendly_type):
            structure_elems = addr_members.get(int(addr), [])

        friendly_name_sig[addr] = {
            "raw_debug_info": debug_type_dictionary[addr],
            "friendly-info": {
                "raw-types": friendly_type,
                "string_type": convert_param_list_to_str_v2(friendly_type),
                "is-struct": is_struct(friendly_type),
                "struct-elems": structure_elems,
                "is-enum": is_enumeration(friendly_type),
                "enum-elems":
                debug_type_dictionary[addr].get("enum_elems", []),
            },
        }

    if dump_files:
        with open(os.path.join(out_dir, "all-friendly-debug-types.json"),
                  "w") as f:
            json.dump(friendly_name_sig, f)


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
        for dfunc in func_slice:
            func_sig, source_location = extract_debugged_function_signature(
                dfunc, debug_type_dictionary)
            dfunc["func_signature_elems"] = func_sig
            dfunc["source"] = source_location

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
                    for dfunc in all_debug_functions:
                        func_sig, source_location = (
                            extract_debugged_function_signature(
                                dfunc, debug_type_dictionary))
                        dfunc["func_signature_elems"] = func_sig
                        dfunc["source"] = source_location
                    break
    else:
        logger.info("Correlating %d debug functions serially", total_funcs)
        for dfunc in all_debug_functions:
            func_signature_elems, source_location = (
                extract_debugged_function_signature(dfunc,
                                                    debug_type_dictionary))
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
    import sys

    type_debug_files = [sys.argv[1]]
    typename = sys.argv[2]

    all_types = load_debug_all_yaml_files(type_debug_files)
    syzkaller_get_type_implementation(typename, all_types)
