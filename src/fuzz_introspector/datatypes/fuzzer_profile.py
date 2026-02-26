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
"""Fuzzer profile"""

import os
import re
import logging

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Pattern,
    Set,
    Tuple,
)

from fuzz_introspector import cfg_load, code_coverage, json_report, utils
from fuzz_introspector.datatypes import branch_profile, function_profile
from fuzz_introspector.exceptions import DataLoaderError

logger = logging.getLogger(name=__name__)


class FuzzerProfile:
    """
    Class for storing information about a given Fuzzer.
    This class essentially holds data corresponding to the output of run of the LLVM
    plugin. That means, the output from the plugin for a single fuzzer.
    """

    def __init__(
        self,
        cfg_file: str,
        frontend_yaml: Dict[Any, Any],
        target_lang: str = "c-cpp",
        cfg_content="",
        exclude_patterns: Optional[List[str]] = None,
        exclude_function_patterns: Optional[List[str]] = None,
    ) -> None:
        # Defaults
        self.binary_executable: str = ""
        self.file_targets: Dict[str, Set[str]] = dict()
        self.coverage: Optional[code_coverage.CoverageProfile] = None
        self.all_class_functions: Dict[
            str, function_profile.FunctionProfile] = dict()
        self.all_class_constructors: Dict[str,
                                          function_profile.FunctionProfile] = (
                                              dict())

        self.branch_blockers: List[Any] = []
        self._target_lang = target_lang
        self.introspector_data_file = cfg_file

        self.functions_reached_by_fuzzer: List[str] = []
        self.functions_reached_by_fuzzer_runtime: List[str] = []

        # Load calltree file
        self.fuzzer_callsite_calltree = cfg_load.data_file_read_calltree(
            cfg_content)

        # Read yaml data (as dictionary) from frontend
        try:
            self.fuzzer_source_file: str = frontend_yaml["Fuzzer filename"]

        except KeyError:
            self.fuzzer_source_file = ""

        # Store exclusion patterns and compiled regexes.
        self.exclude_patterns: List[str] = []
        self.exclude_function_patterns: List[str] = []
        self._exclude_file_regexes: List[Pattern[str]] = []
        self._exclude_function_regexes: List[Pattern[str]] = []
        self.set_exclude_patterns(exclude_patterns, exclude_function_patterns)
        self._covered_files_cache: Dict[str, Set[str]] = {}
        self._covered_files_cache_metadata: Dict[str, Tuple[int, int]] = {}
        self._file_targets_cache_version: int = 0

        # Read entrypoint of fuzzer if this is a Python module
        if target_lang == "python":
            self.entrypoint_fun = frontend_yaml["ep"]["func_name"]
            self.entrypoint_mod = frontend_yaml["ep"]["module"]

        # Read entrypoint of fuzzer if this is a jvm/go module
        if target_lang == "jvm" or target_lang == "go":
            self.entrypoint_method = frontend_yaml.get("Fuzzing method", "")

        self._set_function_list(frontend_yaml, self.exclude_patterns)
        self.dst_to_fd_cache: Dict[str,
                                   function_profile.FunctionProfile] = dict()
        """Language the fuzzer is written in"""

    def _compile_exclude_regexes(
        self,
        patterns: Optional[List[str]],
        scope: str,
    ) -> List[Pattern[str]]:
        compiled_patterns: List[Pattern[str]] = []
        for pattern in patterns or []:
            try:
                compiled_patterns.append(re.compile(pattern))
            except re.error as err:
                logger.warning(
                    "Ignoring invalid %s exclusion pattern %r: %s",
                    scope,
                    pattern,
                    err,
                )
        return compiled_patterns

    def set_exclude_patterns(
        self,
        exclude_patterns: Optional[List[str]],
        exclude_function_patterns: Optional[List[str]],
    ) -> None:
        self.exclude_patterns = list(
            exclude_patterns) if exclude_patterns else []
        self.exclude_function_patterns = (list(exclude_function_patterns)
                                          if exclude_function_patterns else [])
        self._exclude_file_regexes = self._compile_exclude_regexes(
            self.exclude_patterns,
            "file",
        )
        self._exclude_function_regexes = self._compile_exclude_regexes(
            self.exclude_function_patterns,
            "function",
        )

    @property
    def target_lang(self) -> str:
        """The language of the fuzzer"""
        return self._target_lang

    @property
    def entrypoint_function(self):
        """The name of the fuzzer entrypoint"""

        # if set in the evironment use that
        ep_env = os.environ.get("FI_ENTRYPOINT", None)
        if ep_env:
            return ep_env
        if self.target_lang == "c-cpp":
            return "LLVMFuzzerTestOneInput"
        elif self.target_lang == "python":
            return self.entrypoint_fun
        elif self.target_lang == "jvm":
            cname = self.fuzzer_source_file
            mname = self.entrypoint_method
            if not mname:
                return "fuzzerTestOneInput"

            if "]." in mname:
                # For new tree-sitter frontend
                return mname
            else:
                # Backward compatible for old Soot frontend
                return f"[{cname}].{mname}"
        elif self.target_lang == "rust":
            # For rust, there is no entry function
            # Instead, it is wrapped by the fuzz_target
            # macro and we manually considered it as
            # function in the frontend.
            return "fuzz_target"
        elif self.target_lang == "go":
            return self.entrypoint_method
        else:
            return None

    @property
    def identifier(self):
        """Fuzzer identifier"""
        if self._target_lang == "c-cpp":
            if (self.binary_executable != ""
                    and os.path.basename(self.binary_executable) != ""):
                return os.path.basename(self.binary_executable)

        elif self._target_lang == "python":
            return os.path.basename(self.fuzzer_source_file).replace(".py", "")

        elif self._target_lang == "jvm":
            # Class name is used for jvm identifier for old frontend
            return os.path.basename(self.fuzzer_source_file).replace(
                ".java", "")

        elif self._target_lang == "rust":
            return os.path.basename(self.fuzzer_source_file).replace(".rs", "")

        elif self._target_lang == "go":
            fuzzer_base_name = os.path.basename(self.fuzzer_source_file)
            return fuzzer_base_name.replace(".go", "").replace(".cgo", "")

        return self.fuzzer_source_file

    @property
    def max_func_call_depth(self):
        """The maximum depth of all callsites in the fuzzer's calltree."""
        max_depth = 0
        for callsite in cfg_load.extract_all_callsites(
                self.fuzzer_callsite_calltree):
            if callsite.depth > max_depth:
                max_depth = callsite.depth
        return max_depth

    def has_entry_point(self) -> bool:
        """Returns whether an entrypoint is identified"""
        if self.target_lang == "c-cpp" or self.target_lang == "rust":
            return self.entrypoint_function in self.all_class_functions

        elif self.target_lang == "python":
            return self.entrypoint_function is not None

        elif self.target_lang == "jvm":
            for name in self.all_class_functions:
                if name.startswith(self.entrypoint_function):
                    return True

        elif self.target_lang == "go":
            for name in self.all_class_functions:
                if name == self.entrypoint_function:
                    return True

        return False

    def func_is_entrypoint(self, demangled_func_name: str) -> bool:
        if self.target_lang == "jvm":
            return demangled_func_name.startswith(self.entrypoint_function)
        if (demangled_func_name != self.entrypoint_function
                and self.entrypoint_function not in demangled_func_name):
            return False
        return True

    def resolve_coverage_link(self, cov_url: str, source_file: str,
                              lineno: int, function_name: str) -> str:
        """Resolves a link to a coverage report."""
        return utils.resolve_coverage_link(cov_url, source_file, lineno,
                                           function_name, self.target_lang)

    def refine_paths(self, basefolder: str) -> None:
        """Iterate over source files in the calltree and file_targets and remove
        the fuzzer's basefolder from the path.

        The main point for doing this is clearing any prefixed path that may
        exist. This is, for example, the case in OSS-Fuzz projects where most
        files will be prefixed with /src/project_name.
        """
        # Only do this if basefolder is not wrong
        if basefolder == "/":
            return

        # TODO (David): this is an over-approximation? We should not replace all throughout,
        # but only the start of the string.
        self.fuzzer_source_file = self.fuzzer_source_file.replace(
            basefolder, "")

        if self.fuzzer_callsite_calltree is not None:
            all_callsites = cfg_load.extract_all_callsites(
                self.fuzzer_callsite_calltree)
            for cs in all_callsites:
                cs.dst_function_source_file = cs.dst_function_source_file.replace(
                    basefolder, "")

            new_dict = {}
            for key, val in self.file_targets.items():
                new_dict[key.replace(basefolder, "")] = val
            self.file_targets = new_dict
            self._file_targets_cache_version += 1
            self._invalidate_is_file_covered_cache()

    def get_callsites(self):
        return cfg_load.extract_all_callsites(self.fuzzer_callsite_calltree)

    def reaches_file(self,
                     file_name: str,
                     basefolder: Optional[str] = None) -> bool:
        """Identifies if the fuzzer statically reaches a given file

        :param file_name: file to check if fuzzer reaches
        :type file_name: str

        :param basefolder: basefolder path. If not `None` will removed from
                           `file_name` argument.
        :type basefolder: str

        :returns: `True` if the fuzzer statically reaches the file. `False`
                  otherwise.
        :rtype: bool
        """
        if file_name in self.file_targets:
            return True

        # Only some file paths have removed base folder. We must check for
        # both if basefolder is set.
        if basefolder is not None:
            return file_name.replace(basefolder, "") in self.file_targets
        return False

    def reaches_func(self, func_name: str) -> bool:
        """Identifies if the fuzzer statically reaches a given function

        :param func_name: function to check for
        :type func_name: str

        :rtype: bool
        :returns: `True` if the fuzzer statically reaches the function. `False`
                  otherwise.
        """
        return func_name in self.functions_reached_by_fuzzer

    def reaches_func_runtime(self, func_name: str) -> bool:
        """Identifies if the fuzzer dynamically reaches a given function in runtime

        :param func_name: function to check for
        :type func_name: str

        :rtype: bool
        :returns: `True` if the fuzzer reaches the function in runtime. `False`
                  otherwise.
        """
        return func_name in self.functions_reached_by_fuzzer_runtime

    def reaches_func_combined(self, func_name: str) -> bool:
        """Identifies if the fuzzer statically or dynamically reaches a given
        function in runtime

        :param func_name: function to check for
        :type func_name: str

        :rtype: bool
        :returns: `True` if the fuzzer reaches the function statically or in
                  runtime. `False` otherwise.
        """
        return (func_name in self.functions_reached_by_fuzzer
                or self.reaches_func_runtime(func_name))

    def correlate_executable_name(self, correlation_dict) -> None:
        for elem in correlation_dict["pairings"]:
            if (os.path.basename(self.introspector_data_file)
                    in f"{elem['fuzzer_log_file']}.data"):
                self.binary_executable = str(elem["executable_path"])

                lval = os.path.basename(self.introspector_data_file)
                rval = f"{elem['fuzzer_log_file']}.data"
                logger.info(f"Correlated {lval} with {rval}")

    def get_key(self) -> str:
        """Returns the "key" we use to identify this Fuzzer profile."""
        if self.binary_executable != "":
            return os.path.basename(self.binary_executable)

        return self.fuzzer_source_file

    @staticmethod
    def _serialize_branch_side(
            side: branch_profile.BranchSide) -> Dict[str, Any]:
        return {
            "pos": side.pos,
            "unique_not_covered_complexity":
            side.unique_not_covered_complexity,
            "unique_reachable_complexity": side.unique_reachable_complexity,
            "reachable_complexity": side.reachable_complexity,
            "not_covered_complexity": side.not_covered_complexity,
            "hitcount": side.hitcount,
            "funcs": list(side.funcs),
        }

    @staticmethod
    def _deserialize_branch_side(
            payload: Dict[str, Any]) -> branch_profile.BranchSide:
        side = branch_profile.BranchSide()
        side.pos = payload.get("pos", "")
        side.unique_not_covered_complexity = payload.get(
            "unique_not_covered_complexity", -1)
        side.unique_reachable_complexity = payload.get(
            "unique_reachable_complexity", -1)
        side.reachable_complexity = payload.get("reachable_complexity", -1)
        side.not_covered_complexity = payload.get("not_covered_complexity", -1)
        side.hitcount = payload.get("hitcount", -1)
        side.funcs = list(payload.get("funcs", []))
        return side

    @classmethod
    def _serialize_branch_profile(
            cls, profile: branch_profile.BranchProfile) -> Dict[str, Any]:
        return {
            "branch_pos": profile.branch_pos,
            "sides":
            [cls._serialize_branch_side(side) for side in profile.sides],
        }

    @classmethod
    def _deserialize_branch_profile(
            cls, payload: Dict[str, Any]) -> branch_profile.BranchProfile:
        profile = branch_profile.BranchProfile()
        profile.branch_pos = payload.get("branch_pos", "")
        profile.sides = [
            cls._deserialize_branch_side(side_payload)
            for side_payload in payload.get("sides", [])
        ]
        return profile

    @classmethod
    def _serialize_function_profile(
            cls, profile: function_profile.FunctionProfile) -> Dict[str, Any]:
        payload: Dict[str, Any] = dict(profile.__dict__)
        payload["branch_profiles"] = {
            branch_key: cls._serialize_branch_profile(branch_value)
            for branch_key, branch_value in profile.branch_profiles.items()
        }
        return payload

    @classmethod
    def _deserialize_function_profile(
            cls, payload: Dict[str, Any]) -> function_profile.FunctionProfile:
        profile = function_profile.FunctionProfile.__new__(
            function_profile.FunctionProfile)
        profile.__dict__.update(payload)
        profile.branch_profiles = {
            branch_key: cls._deserialize_branch_profile(branch_value)
            for branch_key, branch_value in payload.get("branch_profiles",
                                                        {}).items()
        }
        return profile

    @staticmethod
    def _serialize_coverage_profile(
        coverage: Optional[code_coverage.CoverageProfile],
    ) -> Optional[Dict[str, Any]]:
        if coverage is None:
            return None
        return dict(coverage.__dict__)

    @staticmethod
    def _deserialize_coverage_profile(
        payload: Optional[Dict[str, Any]],
    ) -> Optional[code_coverage.CoverageProfile]:
        if payload is None:
            return None
        coverage = code_coverage.CoverageProfile()
        coverage.__dict__.update(payload)
        return coverage

    @classmethod
    def _serialize_calltree_node(
            cls, node: Optional[cfg_load.CalltreeCallsite]
    ) -> Optional[Dict[str, Any]]:
        if node is None:
            return None
        return {
            "dst_function_name":
            node.dst_function_name,
            "dst_function_source_file":
            node.dst_function_source_file,
            "src_linenumber":
            node.src_linenumber,
            "depth":
            node.depth,
            "src_function_source_file":
            node.src_function_source_file,
            "src_function_name":
            node.src_function_name,
            "cov_ct_idx":
            node.cov_ct_idx,
            "cov_parent":
            node.cov_parent,
            "cov_hitcount":
            node.cov_hitcount,
            "cov_color":
            node.cov_color,
            "hitcount":
            node.hitcount,
            "cov_link":
            node.cov_link,
            "cov_callsite_link":
            node.cov_callsite_link,
            "cov_forward_reds":
            node.cov_forward_reds,
            "cov_largest_blocked_func":
            node.cov_largest_blocked_func,
            "children":
            [cls._serialize_calltree_node(child) for child in node.children],
        }

    @classmethod
    def _deserialize_calltree_node(
        cls,
        payload: Optional[Dict[str, Any]],
        parent: Optional[cfg_load.CalltreeCallsite] = None,
    ) -> Optional[cfg_load.CalltreeCallsite]:
        if payload is None:
            return None
        node = cfg_load.CalltreeCallsite(
            payload.get("dst_function_name", ""),
            payload.get("dst_function_source_file", ""),
            payload.get("depth", 0),
            payload.get("src_linenumber", 0),
            parent,
        )
        node.src_function_source_file = payload.get("src_function_source_file")
        node.src_function_name = payload.get("src_function_name")
        node.cov_ct_idx = payload.get("cov_ct_idx", -1)
        node.cov_parent = payload.get("cov_parent", "")
        node.cov_hitcount = payload.get("cov_hitcount", -1)
        node.cov_color = payload.get("cov_color", "")
        node.hitcount = payload.get("hitcount", 0)
        node.cov_link = payload.get("cov_link", "")
        node.cov_callsite_link = payload.get("cov_callsite_link", "")
        node.cov_forward_reds = payload.get("cov_forward_reds", -1)
        node.cov_largest_blocked_func = payload.get("cov_largest_blocked_func",
                                                    "")
        node.children = []
        for child_payload in payload.get("children", []):
            child_node = cls._deserialize_calltree_node(child_payload, node)
            if child_node is not None:
                node.children.append(child_node)
        return node

    def to_worker_payload(self) -> Dict[str, Any]:
        """Serialize this profile into a payload safe for worker transport."""
        payload: Dict[str, Any] = {
            "binary_executable":
            self.binary_executable,
            "file_targets": {
                filename: sorted(functions)
                for filename, functions in self.file_targets.items()
            },
            "coverage":
            self._serialize_coverage_profile(self.coverage),
            "all_class_functions": {
                function_name: self._serialize_function_profile(function_data)
                for function_name, function_data in
                self.all_class_functions.items()
            },
            "all_class_constructors": {
                function_name: self._serialize_function_profile(function_data)
                for function_name, function_data in
                self.all_class_constructors.items()
            },
            "branch_blockers":
            list(self.branch_blockers),
            "target_lang":
            self._target_lang,
            "introspector_data_file":
            self.introspector_data_file,
            "functions_reached_by_fuzzer":
            list(self.functions_reached_by_fuzzer),
            "functions_reached_by_fuzzer_runtime":
            list(self.functions_reached_by_fuzzer_runtime),
            "fuzzer_callsite_calltree":
            self._serialize_calltree_node(self.fuzzer_callsite_calltree),
            "fuzzer_source_file":
            self.fuzzer_source_file,
            "exclude_patterns":
            list(self.exclude_patterns) if self.exclude_patterns else [],
            "exclude_function_patterns":
            list(self.exclude_function_patterns)
            if self.exclude_function_patterns else [],
            "functions_unreached_by_fuzzer":
            list(getattr(self, "functions_unreached_by_fuzzer", [])),
            "total_basic_blocks":
            getattr(self, "total_basic_blocks", 0),
            "total_cyclomatic_complexity":
            getattr(self, "total_cyclomatic_complexity", 0),
        }
        if hasattr(self, "entrypoint_fun"):
            payload["entrypoint_fun"] = self.entrypoint_fun
        if hasattr(self, "entrypoint_mod"):
            payload["entrypoint_mod"] = self.entrypoint_mod
        if hasattr(self, "entrypoint_method"):
            payload["entrypoint_method"] = self.entrypoint_method
        return payload

    @classmethod
    def from_worker_payload(cls, payload: Dict[str, Any]) -> "FuzzerProfile":
        """Rehydrate a profile from worker payload data."""
        profile = cls.__new__(cls)
        profile.binary_executable = payload.get("binary_executable", "")
        profile.file_targets = {
            filename: set(functions)
            for filename, functions in payload.get("file_targets", {}).items()
        }
        profile.coverage = cls._deserialize_coverage_profile(
            payload.get("coverage"))
        profile.all_class_functions = {
            function_name: cls._deserialize_function_profile(function_data)
            for function_name, function_data in payload.get(
                "all_class_functions", {}).items()
        }
        profile.all_class_constructors = {
            function_name: cls._deserialize_function_profile(function_data)
            for function_name, function_data in payload.get(
                "all_class_constructors", {}).items()
        }
        profile.branch_blockers = list(payload.get("branch_blockers", []))
        profile._target_lang = payload.get("target_lang", "c-cpp")
        profile.introspector_data_file = payload.get("introspector_data_file",
                                                     "")
        profile.functions_reached_by_fuzzer = list(
            payload.get("functions_reached_by_fuzzer", []))
        profile.functions_reached_by_fuzzer_runtime = list(
            payload.get("functions_reached_by_fuzzer_runtime", []))
        profile.fuzzer_callsite_calltree = cls._deserialize_calltree_node(
            payload.get("fuzzer_callsite_calltree"))
        profile.fuzzer_source_file = payload.get("fuzzer_source_file", "")
        profile.exclude_patterns = []
        profile.exclude_function_patterns = []
        profile._exclude_file_regexes = []
        profile._exclude_function_regexes = []
        profile.set_exclude_patterns(
            list(payload.get("exclude_patterns", [])),
            list(payload.get("exclude_function_patterns", [])),
        )
        profile.functions_unreached_by_fuzzer = list(
            payload.get("functions_unreached_by_fuzzer", []))
        profile.total_basic_blocks = payload.get("total_basic_blocks", 0)
        profile.total_cyclomatic_complexity = payload.get(
            "total_cyclomatic_complexity", 0)

        if "entrypoint_fun" in payload:
            profile.entrypoint_fun = payload["entrypoint_fun"]
        if "entrypoint_mod" in payload:
            profile.entrypoint_mod = payload["entrypoint_mod"]
        if "entrypoint_method" in payload:
            profile.entrypoint_method = payload["entrypoint_method"]

        profile.dst_to_fd_cache = dict()
        profile._covered_files_cache = {}
        profile._covered_files_cache_metadata = {}
        profile._file_targets_cache_version = 0
        profile._set_fd_cache()
        return profile

    def _propagate_functions_reached(self) -> None:
        """Accummulates all functions reached by a given fuzzer. This is
        achieved by iterating the outgoing edges of each function recursively
        """
        new_all_class_functions: Dict[
            str, function_profile.FunctionProfile] = dict()

        for func, func_profile in self.all_class_functions.items():
            worklist = []
            max_depth = 0
            for func_reached in func_profile.functions_reached:
                worklist.append((func_reached, 1))
            visited = set()

            while len(worklist) > 0:
                elem, depth = worklist.pop()
                max_depth = max(depth, max_depth)

                if elem in visited:
                    continue
                visited.add(elem)

                # Check if we have done this function already.
                try:
                    fd = new_all_class_functions[elem]
                    visited.update(set(fd.functions_reached))
                    tmp_depth = fd.function_depth + depth
                    max_depth = max(max_depth, tmp_depth)
                    continue
                except KeyError:
                    pass

                # Otherwise traverse the functions reached.
                try:
                    for func_reached2 in self.all_class_functions[
                            elem].functions_reached:
                        worklist.append((func_reached2, depth + 1))
                except KeyError:
                    pass

            # Save the work
            new_all_class_functions[func] = func_profile
            new_all_class_functions[func].functions_reached = list(visited)
            new_all_class_functions[func].function_depth = max_depth
        self.all_class_functions = new_all_class_functions

    def _set_fd_cache(self):
        for _, fd in self.all_class_functions.items():
            self.dst_to_fd_cache[utils.demangle_jvm_func(
                fd.function_source_file, fd.function_name)] = fd
            self.dst_to_fd_cache[utils.normalise_str(fd.function_name)] = fd

    def accummulate_profile(self, target_folder: str, return_dict: None,
                            uniq_id: None, semaphore: None) -> None:
        """Triggers various analyses on the data of the fuzzer. This is used
        after a profile has been initialised to generate more interesting data.
        """
        if semaphore is not None:
            semaphore.acquire()

        logger.info("%s: propagating functions reached", self.identifier)
        self._propagate_functions_reached()
        logger.info("%s: setting reached funcs", self.identifier)
        self._set_all_reached_functions()
        logger.info("%s: setting unreached funcs", self.identifier)
        self._set_all_unreached_functions()
        logger.info("%s: loading coverage", self.identifier)
        self._load_coverage(target_folder)
        logger.info("%s: setting file targets", self.identifier)
        self._set_file_targets()
        logger.info("%s: setting reached funcs in runtime", self.identifier)
        self._set_all_reached_functions_runtime()
        logger.info("%s: pruning exclusion-derived values", self.identifier)
        self._prune_excluded_profile_data()
        logger.info("%s: setting total basic blocks", self.identifier)
        self._set_total_basic_blocks()
        logger.info("%s: setting cyclomatic complexity", self.identifier)
        self._set_total_cyclomatic_complexity()
        logger.info("%s: setting fd cache", self.identifier)
        self._set_fd_cache()
        logger.info("%s: finished accummulating profile", self.identifier)
        if return_dict is not None:
            return_dict[uniq_id] = self
        if semaphore is not None:
            semaphore.release()

    def _prune_excluded_profile_data(self) -> None:
        """Prunes file and function derived data that matches exclude patterns."""
        if not self.exclude_patterns and not self.exclude_function_patterns:
            return

        filtered_file_targets: Dict[str, Set[str]] = {}
        removed_function_names: Set[str] = set()
        for filename, targets in self.file_targets.items():
            if self._matches_exclude_pattern(filename):
                removed_function_names.update(targets)
                continue
            filtered_targets = {
                func
                for func in targets
                if not self._should_exclude_function_name(func)
            }
            removed_function_names.update(targets - filtered_targets)
            if not filtered_targets:
                continue
            filtered_file_targets[filename] = filtered_targets

        self.file_targets = filtered_file_targets
        self._file_targets_cache_version += 1
        self._invalidate_is_file_covered_cache()
        self.functions_reached_by_fuzzer = [
            func for func in self.functions_reached_by_fuzzer
            if not self._should_exclude_function_name(func)
            and func not in removed_function_names
        ]
        self.functions_reached_by_fuzzer_runtime = [
            func for func in self.functions_reached_by_fuzzer_runtime
            if not self._should_exclude_function_name(func)
            and func not in removed_function_names
        ]
        self._set_all_unreached_functions()

    def get_cov_uncovered_reachable_funcs(self) -> List[str]:
        """Gets all functions that are statically reachable but are not
        covered by runtime coverage.

        Returns:
            List with names of all the functions that are reachable but not
            covered.
            If there is no coverage information returns empty list.
        """
        if self.coverage is None:
            return []

        uncovered_funcs = []
        for funcname in self.functions_reached_by_fuzzer:
            total_func_lines, hit_lines, _ = self.get_cov_metrics(funcname)
            if total_func_lines is None:
                uncovered_funcs.append(funcname)
                continue
            if hit_lines == 0:
                uncovered_funcs.append(funcname)
        return uncovered_funcs

    def is_file_covered(self,
                        file_name: str,
                        basefolder: Optional[str] = None) -> bool:
        """Identifies whether a file is covered by runtime code coverage

        :param file_name: file name
        :type file_name: str

        :param basefolder: basefolder to apply on the file name
        :type basefolder: str

        :rtype: bool
        :returns: `True` if the file is covered by runtime code coverage,
                  `False` otherwise.
        """
        cache_key = basefolder if basefolder is not None else ""
        cache_metadata = (
            id(self.coverage),
            self._file_targets_cache_version,
        )
        covered_files = self._covered_files_cache.get(cache_key)
        if (covered_files is None
                or self._covered_files_cache_metadata.get(cache_key)
                != cache_metadata):
            covered_files = self._build_covered_files_index(basefolder)
            self._covered_files_cache[cache_key] = covered_files
            self._covered_files_cache_metadata[cache_key] = cache_metadata

        normalized_file = self._normalize_file_path_for_coverage(
            file_name, basefolder)
        return (file_name in covered_files
                or os.path.abspath(file_name) in covered_files
                or normalized_file in covered_files)

    def _normalize_file_path_for_coverage(self, file_name: str,
                                          basefolder: Optional[str]) -> str:
        normalized_file_name = os.path.abspath(file_name)
        if basefolder is not None and basefolder != "/":
            normalized_file_name = normalized_file_name.replace(basefolder, "")
        return normalized_file_name

    def _invalidate_is_file_covered_cache(self) -> None:
        self._covered_files_cache = {}
        self._covered_files_cache_metadata = {}

    def _build_covered_files_index(self,
                                   basefolder: Optional[str]) -> Set[str]:
        covered_files: Set[str] = set()
        if self.coverage is None:
            return covered_files

        for funcname, func_profile in self.all_class_functions.items():
            func_file_name = func_profile.function_source_file
            if not func_file_name:
                continue

            abs_func_file = os.path.abspath(func_file_name)
            normalized_func_file = self._normalize_file_path_for_coverage(
                func_file_name, basefolder)
            normalized_abs_func_file = self._normalize_file_path_for_coverage(
                abs_func_file, basefolder)
            if (func_file_name not in self.file_targets
                    and normalized_func_file not in self.file_targets
                    and abs_func_file not in self.file_targets
                    and normalized_abs_func_file not in self.file_targets):
                continue

            _, _, hit_percentage = self.get_cov_metrics(funcname)
            if hit_percentage is None or hit_percentage <= 0.0:
                continue

            covered_files.add(func_file_name)
            covered_files.add(abs_func_file)
            covered_files.add(normalized_func_file)
            covered_files.add(normalized_abs_func_file)
        return covered_files

    def get_cov_metrics(
            self, funcname: str
    ) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        """Fethes data points on runtime code coverage for a given function.

        A triplet is returned where the first element is the total number of lines
        in the function, the second element is a list of whether each line was
        covered at runtime or not, and the third element is the percentage of lines
        covered by runtime covevrage.

        :param funcname: function to check for.
        :type funcname: str

        :rtype: Tuple[Optional[int], Optional[int], Optional[float]]
        :returns: Triplet of int, int, float indicated numbers described above. Or,
                  a triplet of `None` in the event an error ocurred.
        """
        if self.coverage is None:
            return None, None, None
        try:
            total_func_lines, hit_lines = self.coverage.get_hit_summary(
                funcname)
            if total_func_lines is None or hit_lines is None:
                return None, None, None
            if total_func_lines == 0:
                return 0, 0, 0
            else:
                hit_percentage = (hit_lines / total_func_lines) * 100.0
                return total_func_lines, hit_lines, hit_percentage
        except Exception:
            return None, None, None

    def write_stats_to_summary_file(self, out_dir) -> None:
        file_target_count = (len(self.file_targets)
                             if self.file_targets is not None else 0)
        json_report.add_fuzzer_key_value_to_report(
            self.identifier,
            "stats",
            {
                "total-basic-blocks": self.total_basic_blocks,
                "total-cyclomatic-complexity":
                self.total_cyclomatic_complexity,
                "file-target-count": file_target_count,
            },
            out_dir,
        )

    def _set_all_reached_functions(self) -> None:
        """Sets self.functions_reached_by_fuzzer to all functions reached by
        the fuzzer. This is based on identifying all functions reached by the
        fuzzer entrypoint function, e.g. LLVMFuzzerTestOneInput in C/C++.
        """
        # Find C/CPP/Rust/Go entry point
        if (self._target_lang == "c-cpp" or self.target_lang == "rust"
                or self.target_lang == "go"):
            if self.entrypoint_function in self.all_class_functions:
                self.functions_reached_by_fuzzer = self.all_class_functions[
                    self.entrypoint_function].functions_reached
                self.functions_reached_by_fuzzer.append(
                    self.entrypoint_function)
                return

        # Find Python entrypoint
        elif self._target_lang == "python":
            ep_key = f"{self.entrypoint_mod}.{self.entrypoint_fun}"
            reached = self.all_class_functions[ep_key].functions_reached
            self.functions_reached_by_fuzzer = reached
            self.functions_reached_by_fuzzer.append(self.entrypoint_function)
            return

        # Find JVM entrypoint
        elif self._target_lang == "jvm":
            entrypoint = None
            for name in self.all_class_functions:
                if name.startswith(self.entrypoint_function):
                    entrypoint = name
                    break
            if entrypoint:
                self.functions_reached_by_fuzzer = self.all_class_functions[
                    entrypoint].functions_reached
                self.functions_reached_by_fuzzer.append(entrypoint)
                return

    def _set_all_unreached_functions(self) -> None:
        """Sets self.functions_unreached_by_fuzzer to all functions that are
        statically unreached. This is computed as the set difference between
        self.all_class_functions and self.functions_reached_by_fuzzer.
        """
        self.functions_unreached_by_fuzzer = [
            f.function_name for f in self.all_class_functions.values()
            if f.function_name not in self.functions_reached_by_fuzzer
        ]

    def _set_all_reached_functions_runtime(self) -> None:
        """Sets self.functions_reached_by_fuzzer_runtime to all functions
        reached by the fuzzer during runtime. This is based on identifying
        all functions reached covered in the runtime coverage report.
        """
        if not self.coverage:
            logger.warning(
                "No coverage report for retrieving runtime reached functions.")
            return

        for func_name in self.coverage.covmap:
            if self.coverage.is_func_hit(func_name):
                self.functions_reached_by_fuzzer_runtime.append(func_name)

    def _load_coverage(self, target_folder: str) -> None:
        """Load coverage data for this profile"""
        logger.info("Loading coverage of type %s", self.target_lang)
        if self.target_lang == "c-cpp":
            if os.getenv("FI_KERNEL_COV", ""):
                self.coverage = code_coverage.load_kernel_cov(
                    os.getenv("FI_KERNEL_COV"))
            else:
                self.coverage = code_coverage.load_llvm_coverage(
                    target_folder, self.identifier)
        elif self.target_lang == "python":
            self.coverage = code_coverage.load_python_json_coverage(
                target_folder)
            if self.coverage is not None:
                self.coverage.correlate_python_functions_with_coverage(
                    self.all_class_functions)
        elif self.target_lang == "jvm":
            self.coverage = code_coverage.load_jvm_coverage(target_folder)
        elif self.target_lang == "rust":
            self.coverage = code_coverage.load_llvm_coverage(
                target_folder, self.identifier, True)
        elif self.target_lang == "go":
            self.coverage = code_coverage.load_go_coverage(
                target_folder, self.all_class_functions)
        else:
            raise DataLoaderError(
                "The profile target has no coverage loading support")
        self._invalidate_is_file_covered_cache()

    def _get_target_fuzzer_filename(self) -> str:
        return (os.path.basename(self.fuzzer_source_file).replace(
            ".cpp", "").replace(".cc", "").replace(".c", ""))

    def _set_file_targets(self) -> None:
        """Sets self.file_targets to be a dictionarty of string to string.
        Each key in the dictionary is a filename and the corresponding value is
        a set of strings containing strings which are the names of the functions
        in the given file that are reached by the fuzzer.
        """
        if self.fuzzer_callsite_calltree is not None:
            all_callsites = cfg_load.extract_all_callsites(
                self.fuzzer_callsite_calltree)
            for cs in all_callsites:
                if cs.dst_function_source_file.replace(" ", "") == "":
                    continue
                if cs.dst_function_source_file not in self.file_targets:
                    self.file_targets[cs.dst_function_source_file] = set()
                self.file_targets[cs.dst_function_source_file].add(
                    cs.dst_function_name)
        self._file_targets_cache_version += 1
        self._invalidate_is_file_covered_cache()

    def _set_total_basic_blocks(self) -> None:
        """Sets self.total_basic_blocks to the sum of basic blocks of all the
        functions reached by this fuzzer.
        """
        total_basic_blocks = 0
        for func in self.functions_reached_by_fuzzer:
            try:
                fd = self.all_class_functions[func]
                total_basic_blocks += fd.bb_count
            except Exception as e:
                logger.debug(e)
        self.total_basic_blocks = total_basic_blocks

    def _set_total_cyclomatic_complexity(self) -> None:
        """Sets self.total_cyclomatic_complexity to the sum of cyclomatic
        complexity of all functions reached by this fuzzer.
        """
        self.total_cyclomatic_complexity = 0
        for func in self.functions_reached_by_fuzzer:
            try:
                fd = self.all_class_functions[func]
                self.total_cyclomatic_complexity += fd.cyclomatic_complexity
            except Exception as e:
                logger.debug(e)

    def _matches_exclude_pattern(self, source_file: str) -> bool:
        """Check if source file matches any exclude pattern."""
        if not source_file or not self._exclude_file_regexes:
            return False
        for pattern in self._exclude_file_regexes:
            if pattern.search(source_file):
                return True
        return False

    def _matches_exclude_function_pattern(self, function_name: str) -> bool:
        """Check if function name matches any function exclusion pattern."""
        if not function_name or not self._exclude_function_regexes:
            return False
        for pattern in self._exclude_function_regexes:
            if pattern.search(function_name):
                return True
        return False

    def _should_exclude_function_profile(
            self, func: function_profile.FunctionProfile) -> bool:
        if self._matches_exclude_pattern(func.function_source_file):
            return True
        if self._matches_exclude_function_pattern(func.function_name):
            return True
        if self._matches_exclude_function_pattern(func.raw_function_name):
            return True
        return False

    def _should_exclude_function_name(self, function_name: str) -> bool:
        if self._matches_exclude_function_pattern(function_name):
            return True
        func_profile = self.all_class_functions.get(function_name)
        if func_profile is None:
            return False
        return self._should_exclude_function_profile(func_profile)

    def _set_function_list(
        self,
        frontend_yaml: Dict[Any, Any],
        exclude_patterns: Optional[List[str]] = None,
    ) -> None:
        """Read all function field from yaml data dictionary into
        instances of FunctionProfile
        """
        for elem in frontend_yaml["All functions"]["Elements"]:
            if self._is_func_name_missing_normalisation(elem["functionName"]):
                logger.info("May have non-normalised function: %s",
                            elem["functionName"])

            func_profile = function_profile.FunctionProfile(elem)
            logger.debug("Adding %s", func_profile.function_name)

            # Skip functions matching exclude patterns
            if self._should_exclude_function_profile(func_profile):
                continue

            # Avoid loading more entrypoints as this will cause issues when
            # propagating reachability. TODO(David): make this more robust.
            if "LLVMFuzzerTestOneInput" in func_profile.function_name:
                if func_profile.function_source_file not in self.fuzzer_source_file:
                    continue

            if self.target_lang == "jvm" and "<init>" in elem["functionName"]:
                # Store JVM constructor separately
                self.all_class_constructors[
                    func_profile.function_name] = func_profile
            else:
                # Store the functions
                self.all_class_functions[
                    func_profile.function_name] = func_profile

    def _is_func_name_missing_normalisation(self, func_name: str) -> bool:
        if "." in func_name:
            split_name = func_name.split(".")
            if split_name[-1].isnumeric():
                return True
        return False
