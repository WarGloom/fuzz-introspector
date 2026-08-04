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
"""Project profile"""

# pylint: disable=line-too-long,missing-function-docstring,unused-variable,invalid-name
# pylint: disable=use-dict-literal,use-list-literal,logging-fstring-interpolation
# pylint: disable=no-else-return,consider-using-f-string,consider-iterating-dictionary
# pylint: disable=redefined-builtin

import collections
import itertools
import os
import logging

from typing import (
    Dict,
    List,
    Tuple,
)

from fuzz_introspector import code_coverage, exceptions, json_report, utils
from fuzz_introspector.datatypes import function_profile, fuzzer_profile

logger = logging.getLogger(name=__name__)


def _safe_line_number_for_merge(line_value) -> int:
    try:
        return int(line_value)
    except (TypeError, ValueError):
        return 1 << 30


def _canonical_profile_merge_key(
        fd: function_profile.FunctionProfile) -> Tuple[int, str, int, str]:
    source_file = os.path.normpath(
        getattr(fd, "function_source_file", "") or "")
    has_source = 0 if source_file else 1
    return (
        has_source,
        source_file,
        _safe_line_number_for_merge(getattr(fd, "function_linenumber", -1)),
        getattr(fd, "raw_function_name", getattr(fd, "function_name", "")),
    )


def _choose_canonical_profile(
    current_fd: function_profile.FunctionProfile,
    candidate_fd: function_profile.FunctionProfile
) -> function_profile.FunctionProfile:
    if _canonical_profile_merge_key(
            candidate_fd) < _canonical_profile_merge_key(current_fd):
        return candidate_fd
    return current_fd


def _build_function_name_alias_map(
        functions: Dict[str,
                        function_profile.FunctionProfile]) -> Dict[str, str]:
    function_aliases: Dict[str, str] = {}
    for function_name, func_profile in functions.items():
        for alias in function_profile.get_function_name_aliases(
                function_name, func_profile.raw_function_name):
            function_aliases.setdefault(alias, function_name)
    return function_aliases


class MergedProjectProfile:
    """
    Class for storing information about all fuzzers combined in a given project.
    This means, it contains data for all fuzzers in a given project, and digests
    the manner in a way that makes sense from a project-scope perspective. For
    example, it does project-wide analysis of reachable/unreachable functions by
    digesting data from all the fuzzers in the project.
    """

    def __init__(self, profiles: List[fuzzer_profile.FuzzerProfile],
                 language: str):
        self.name = None
        self.profiles = profiles
        self.all_functions: Dict[str,
                                 function_profile.FunctionProfile] = dict()
        self.all_constructors: Dict[str,
                                    function_profile.FunctionProfile] = dict()
        self.unreached_functions = set()
        self.functions_reached = set()
        self.coverage_url = "#"
        self.dst_to_fd_cache: Dict[str,
                                   function_profile.FunctionProfile] = dict()
        self._all_functions_with_source_cache: (
            Dict[str, function_profile.FunctionProfile] | None) = None
        self._target_lang_cache: str | None = None
        self.language = language

        logger.info(
            f"Creating merged profile of {len(self.profiles)} profiles")
        # Populate functions reached
        logger.info("Populating functions reached")
        for profile in profiles:
            for func_name in profile.functions_reached_by_fuzzer:
                self.functions_reached.add(func_name)

        # Set all unreached functions
        logger.info("Populating functions unreached")
        for profile in profiles:
            for func_name in profile.functions_unreached_by_fuzzer:
                if func_name not in self.functions_reached:
                    self.unreached_functions.add(func_name)

        # Build once to avoid O(functions * profiles) repeated membership checks.
        static_reached_by_fuzzers: dict[
            str, set[str]] = collections.defaultdict(set)
        runtime_reached_by_fuzzers: dict[
            str, set[str]] = collections.defaultdict(set)
        for profile in profiles:
            profile_id = profile.identifier
            function_aliases = _build_function_name_alias_map(
                profile.all_class_functions)
            # functions_reached_by_fuzzer* are already Set[str]; no copy needed.
            profile_static_reached: set[str] = set()
            for func_name in profile.functions_reached_by_fuzzer:
                canonical_func_name = function_aliases.get(
                    func_name, func_name)
                profile_static_reached.add(canonical_func_name)
                static_reached_by_fuzzers[canonical_func_name].add(profile_id)
            for func_name in profile.functions_reached_by_fuzzer_runtime:
                canonical_func_name = function_aliases.get(
                    func_name, func_name)
                if canonical_func_name in profile_static_reached:
                    runtime_reached_by_fuzzers[canonical_func_name].add(
                        profile_id)

        # Add all functions from the various profiles into the merged profile. Don't
        # add duplicates
        logger.info("Creating all_functions dictionary")
        # Performance Optimization: Use tuple instead of set for faster iteration in hot loop
        excluded_functions = ("sanitizer", "llvm", "LLVMFuzzerTestOneInput")
        for profile in profiles:
            # Handles jvm constructors
            for fd in profile.all_class_constructors.values():
                current_fd = self.all_constructors.get(fd.function_name)
                if current_fd is None:
                    self.all_constructors[fd.function_name] = fd
                else:
                    self.all_constructors[
                        fd.function_name] = _choose_canonical_profile(
                            current_fd, fd)

            # Handles normal functions
            for fd in profile.all_class_functions.values():
                # continue if the function is to be excluded
                # Performance Optimization: Avoid any() generator for O(N) substring checks.
                is_excluded = False
                for to_exclude in excluded_functions:
                    if to_exclude in fd.function_name:
                        is_excluded = True
                        break
                if is_excluded:
                    continue

                current_fd = self.all_functions.get(fd.function_name)
                if current_fd is None:
                    self.all_functions[fd.function_name] = fd
                else:
                    self.all_functions[
                        fd.function_name] = _choose_canonical_profile(
                            current_fd, fd)

                static_reached = static_reached_by_fuzzers.get(
                    fd.function_name, set())
                runtime_reached = runtime_reached_by_fuzzers.get(
                    fd.function_name, set())

                combined = static_reached | runtime_reached
                fd.reached_by_fuzzers = sorted(static_reached)
                fd.reached_by_fuzzers_runtime = sorted(runtime_reached)
                fd.reached_by_fuzzers_combined = sorted(combined)

                # Compute hitcounts from set sizes directly (avoid len of sorted list).
                fd.hitcount = len(static_reached)
                fd.hitcount_runtime = len(runtime_reached)
                fd.hitcount_combined = len(combined)

        # Gather complexity information about each function
        logger.info(
            "Gathering complexity and incoming references of each function")
        all_functions = self.all_functions
        all_constructors = self.all_constructors
        # Resolve once before the loop; target_lang may iterate all profiles
        # on first access if cache is cold.
        _target_lang = self.target_lang
        for fp_obj in itertools.chain(all_functions.values(),
                                      all_constructors.values()):
            total_cyclomatic_complexity = 0
            total_new_complexity = 0

            for reached_func_name in fp_obj.functions_reached:
                if reached_func_name in all_functions:
                    reached_func_obj = all_functions[reached_func_name]
                elif reached_func_name in all_constructors:
                    reached_func_obj = all_constructors[reached_func_name]
                else:
                    if _target_lang == "jvm":
                        logger.debug(
                            "%s not provided within classpath",
                            reached_func_name,
                        )
                    else:
                        logger.debug("Mismatched function name: %s",
                                     reached_func_name)
                    continue
                reached_func_obj.incoming_references.append(
                    fp_obj.function_name)

                # Skip complexity additions if this is a recursive call
                if (fp_obj.function_source_file
                        == reached_func_obj.function_source_file
                        and fp_obj.function_linenumber
                        == reached_func_obj.function_linenumber
                        and fp_obj.function_line_number_end
                        == reached_func_obj.function_line_number_end):
                    continue
                total_cyclomatic_complexity += reached_func_obj.cyclomatic_complexity
                if reached_func_obj.hitcount == 0:
                    total_new_complexity += reached_func_obj.cyclomatic_complexity
            if fp_obj.hitcount == 0:
                fp_obj.new_unreached_complexity = (
                    total_new_complexity + fp_obj.cyclomatic_complexity)
            else:
                fp_obj.new_unreached_complexity = total_new_complexity
            fp_obj.total_cyclomatic_complexity = (total_cyclomatic_complexity +
                                                  fp_obj.cyclomatic_complexity)

        # Accumulate run-time coverage mapping
        self.runtime_coverage = code_coverage.CoverageProfile()
        runtime_covmap = self.runtime_coverage.covmap
        for profile in profiles:
            if profile.coverage is None:
                continue
            for func_name, profile_cov_entries in profile.coverage.covmap.items(
            ):
                existing_entries = runtime_covmap.get(func_name)
                if existing_entries is None:
                    runtime_covmap[func_name] = profile_cov_entries
                else:
                    # Merge by picking highest line numbers. Here we can assume they coverage
                    # maps have the same number of elements with the same line numbers but
                    # different hit counts.
                    new_line_counts = list()
                    profile_entries_len = len(profile_cov_entries)
                    for idx1, (ln1, ht1) in enumerate(existing_entries):
                        if idx1 < profile_entries_len:
                            ln2, ht2 = profile_cov_entries[idx1]
                        else:
                            ln2, ht2 = ln1, ht1
                        # It may be that line numbers are not the same for the same function
                        # name across different fuzzers.
                        # This *could* actually happen, and will often (almost always) happen for
                        # LLVMFuzzerTestOneInput. In this case we just gracefully
                        # continue and ignore issues.
                        if ln1 != ln2:
                            logger.info(
                                f"Line numbers are different in the same function: "
                                f"{func_name}:{ln1}:{ln2}, ignoring")
                            continue
                        new_line_counts.append((ln1, max(ht1, ht2)))
                    runtime_covmap[func_name] = new_line_counts
            # TODO (navidem): will need to merge branch coverages (branch_cov_map) if we need to
            # identify blockers based on all fuzz targets coverage
        self._set_basefolder()
        self._set_fd_cache()
        # Cached complexity/count results (computed lazily on first access)
        self._total_complexity_cache: Tuple[int, int] | None = None
        self._reached_count_cache: int | None = None
        self._unreached_count_cache: int | None = None
        logger.info("Completed creationg of merged profile")

    def get_all_runtime_covered_functions(self) -> List[str]:
        """Gets the name of all functions that are covered by runtime
        code coverage analysis.

        :rtype: List[str]
        :returns: List of strings corresponding to function names
        """
        all_covered_functions = []
        for funcname, func_profile in self.get_all_functions_with_source(
        ).items():
            if func_profile.hitcount == 0:
                continue
            is_covered = False
            coverage_data = self.runtime_coverage.get_hit_details(funcname)
            if len(coverage_data) > 0:
                for linenumber, hitcount in coverage_data:
                    if hitcount > 0:
                        is_covered = True
            if is_covered:
                all_covered_functions.append(funcname)

        return all_covered_functions

    def get_all_runtime_reached_functions(self) -> List[str]:
        return [
            funcname for funcname, func_profile in
            self.get_all_functions_with_source().items()
            if func_profile.hitcount_runtime > 0
        ]

    def get_function_summaries(self) -> Tuple[int, int, int, float, float]:
        """Gets data points summarising data with respect to static reachability of
        all functions in the project.
        """
        reached_func_count = self._get_total_reached_function_count()
        unreached_func_count = self._get_total_unreached_function_count()
        total_functions = reached_func_count + unreached_func_count
        try:
            reached_percentage = (float(reached_func_count) /
                                  float(total_functions)) * 100
        except ZeroDivisionError:
            reached_percentage = 0.0

        try:
            unreached_percentage = (float(unreached_func_count) /
                                    float(total_functions)) * 100
        except ZeroDivisionError:
            unreached_percentage = 0.0
        return (
            total_functions,
            reached_func_count,
            unreached_func_count,
            reached_percentage,
            unreached_percentage,
        )

    def resolve_coverage_report_link(self, coverage_url, function_source_file,
                                     lineno, func_name):

        if self.target_lang == "python":
            return self.profiles[0].resolve_coverage_link(
                coverage_url, function_source_file, lineno, func_name)
        elif self.target_lang == "jvm":
            return self.profiles[0].resolve_coverage_link(
                coverage_url, function_source_file, lineno, func_name)
        else:
            return "%s%s.html#L%d" % (coverage_url, function_source_file,
                                      lineno)

    @property
    def target_lang(self):
        """Language the fuzzers are written in"""
        if self._target_lang_cache is not None:
            return self._target_lang_cache

        set_of_targets = set()
        for profile in self.profiles:
            set_of_targets.add(profile.target_lang)
        if len(set_of_targets) > 1:
            raise exceptions.AnalysisError(
                "Project has fuzzers with multiple targets")
        if not set_of_targets:
            self._target_lang_cache = self.language
            return self._target_lang_cache
        self._target_lang_cache = set_of_targets.pop()
        return self._target_lang_cache

    @property
    def total_complexity(self):
        complexity_reached, complexity_unreached = self._get_total_complexity()
        return complexity_unreached + complexity_reached

    @property
    def reached_complexity(self):
        complexity_reached, _ = self._get_total_complexity()
        return complexity_reached

    @property
    def unreached_complexity(self):
        _, complexity_unreached = self._get_total_complexity()
        return complexity_unreached

    @property
    def reached_complexity_percentage(self):
        complexity_reached, complexity_unreached = self._get_total_complexity()
        total_complexity = complexity_unreached + complexity_reached

        try:
            reached_complexity_percentage = (float(complexity_reached) /
                                             (total_complexity)) * 100.0
        except Exception:
            logger.info("Total complexity is 0")
            reached_complexity_percentage = 0
        return reached_complexity_percentage

    @property
    def unreached_complexity_percentage(self):
        complexity_reached, complexity_unreached = self._get_total_complexity()
        total_complexity = complexity_unreached + complexity_reached

        try:
            unreached_complexity_percentage = (float(complexity_unreached) /
                                               (total_complexity)) * 100.0
        except Exception:
            logger.info("Total complexity is 0")
            unreached_complexity_percentage = 0

        return unreached_complexity_percentage

    @property
    def total_functions(self):
        reached_func_count = self._get_total_reached_function_count()
        unreached_func_count = self._get_total_unreached_function_count()
        total_functions = reached_func_count + unreached_func_count
        return total_functions

    @property
    def reached_func_count(self):
        reached_func_count = self._get_total_reached_function_count()
        return reached_func_count

    @property
    def reached_func_percentage(self):
        reached_func_count = self._get_total_reached_function_count()
        unreached_func_count = self._get_total_unreached_function_count()
        total_functions = reached_func_count + unreached_func_count
        try:
            reached_percentage = (float(reached_func_count) /
                                  float(total_functions)) * 100
        except ZeroDivisionError:
            reached_percentage = 0.0
        return reached_percentage

    def get_profiles_coverage_files(self) -> List[str]:
        all_coverage_files_used = list()
        for profile in self.profiles:
            if profile.coverage is None:
                continue
            all_coverage_files_used += profile.coverage.coverage_files
        return all_coverage_files_used

    def has_coverage_data(self) -> bool:
        return len(self.get_profiles_coverage_files()) != 0

    def get_complexity_summaries(self) -> Tuple[int, int, int, float, float]:
        """Gets data points summarising cyclomatic complexity across the project,
        including total complexity, the amount of complexity that is statically
        reached and the amount of complexity that is statically unreached.
        """
        complexity_reached, complexity_unreached = self._get_total_complexity()
        total_complexity = complexity_unreached + complexity_reached

        try:
            reached_complexity_percentage = (float(complexity_reached) /
                                             (total_complexity)) * 100.0
        except Exception:
            logger.info("Total complexity is 0")
            reached_complexity_percentage = 0

        try:
            unreached_complexity_percentage = (float(complexity_unreached) /
                                               (total_complexity)) * 100.0
        except Exception:
            logger.info("Total complexity is 0")
            unreached_complexity_percentage = 0

        return (
            total_complexity,
            complexity_reached,
            complexity_unreached,
            reached_complexity_percentage,
            unreached_complexity_percentage,
        )

    def get_direct_parent_list(
        self, target_function: function_profile.FunctionProfile
    ) -> Tuple[List[function_profile.FunctionProfile], List[str]]:
        """
        Search through list of parent functions of the
        target function and return a subset of functions
        in list which is the immediate parent function
        calling the target function.
        """
        result_list = []
        result_name_list = []
        for func_name in target_function.incoming_references:
            if func_name in self.all_functions.keys():
                fd = self.all_functions[func_name]
                if target_function.function_name in fd.functions_called:
                    result_list.append(fd)
                    result_name_list.append(func_name)

        return (result_list, result_name_list)

    def get_function_callpaths(
        self,
        target_function: function_profile.FunctionProfile,
        handled_functions: List[function_profile.FunctionProfile],
    ) -> Tuple[List[List[function_profile.FunctionProfile]], List[List[str]]]:
        """
        Recursively resolve the incoming reference of a function
        profile and build up lists of function callpaths from each
        of the incoming functions to the target function.
        """
        if len(target_function.incoming_references) == 0:
            # Outtermost function
            return ([[]], [[]])

        result_list = []
        result_name_list = []
        for func_name in target_function.incoming_references:
            if func_name in self.all_functions.keys():
                fd = self.all_functions[func_name]
                if fd in handled_functions:
                    continue

                if target_function.function_name in fd.functions_called:
                    handled_functions.append(fd)
                    inner_list, inner_name_list = self.get_function_callpaths(
                        fd, handled_functions)
                    for list in inner_list:
                        list.append(fd)
                        result_list.append(list)
                    for name_list in inner_name_list:
                        name_list.append(fd.function_name)
                        result_name_list.append(name_list)
        return (result_list, result_name_list)

    def write_stats_to_summary_file(self, out_dir) -> None:
        (
            total_complexity,
            complexity_reached,
            complexity_unreached,
            reached_complexity_percentage,
            unreached_complexity_percentage,
        ) = self.get_complexity_summaries()

        (
            total_functions,
            reached_func_count,
            unreached_func_count,
            reached_func_percentage,
            unreached_func_percentage,
        ) = self.get_function_summaries()

        covered_funcs = self.get_all_runtime_covered_functions()
        runtime_reached_funcs = self.get_all_runtime_reached_functions()
        try:
            cov_percentage = round(len(covered_funcs) / total_functions,
                                   2) * 100.0
        except ZeroDivisionError:
            cov_percentage = 0.0

        json_report.add_project_key_value_to_report(
            "stats",
            {
                "total-complexity": total_complexity,
                "complexity-reached": complexity_reached,
                "complexity-unreached": complexity_unreached,
                "reached-complexity-percentage": reached_complexity_percentage,
                "unreached-complexity-percentage":
                unreached_complexity_percentage,
                "total-functions": total_functions,
                "harness-count": len(self.profiles),
                "reached-function-count": reached_func_count,
                "unreached-function-count": unreached_func_count,
                "reached-function-percentage": reached_func_percentage,
                "unreached-function-percentage": unreached_func_percentage,
                "code-coverage-function-count": len(covered_funcs),
                "code-coverage-function-percentage": cov_percentage,
                "runtime-reached-function-count": len(runtime_reached_funcs),
            },
            out_dir,
        )
        json_report.add_project_key_value_to_report(
            "overview", {"language": self.target_lang}, out_dir)

    def _set_basefolder(self) -> None:
        """Identifies a common path-prefix amongst source files in. This is
        used to remove locations within a host system to essentially make
        paths as if they were from the root of the source code project.
        """
        all_strs = []
        for f in self.all_functions.values():
            if f.function_source_file == "":
                continue
            if "/usr/include/" in f.function_source_file:
                continue
            all_strs.append(os.path.dirname(f.function_source_file))

        if len(all_strs) == 0:
            self.basefolder = ""
            return

        self.basefolder = utils.longest_common_prefix(all_strs) + "/"

    def _compute_function_stats(self) -> None:
        """Consolidates computation of reached/unreached function counts and complexity.
        This speeds up project profiling by avoiding O(3*N) looping over all functions.
        """
        reached_func_count = 0
        unreached_func_count = 0
        reached_complexity = 0
        unreached_complexity = 0

        for fd in self.get_all_functions_with_source().values():
            if fd.hitcount == 0:
                unreached_func_count += 1
                unreached_complexity += fd.cyclomatic_complexity
            else:
                reached_func_count += 1
                reached_complexity += fd.cyclomatic_complexity

        self._reached_count_cache = reached_func_count
        self._unreached_count_cache = unreached_func_count
        self._total_complexity_cache = (reached_complexity,
                                        unreached_complexity)

    def _get_total_unreached_function_count(self) -> int:
        if self._unreached_count_cache is not None:
            return self._unreached_count_cache
        self._compute_function_stats()
        # Mypy requires asserting not None since it was computed
        assert self._unreached_count_cache is not None
        return self._unreached_count_cache

    def _get_total_reached_function_count(self) -> int:
        if self._reached_count_cache is not None:
            return self._reached_count_cache
        self._compute_function_stats()
        assert self._reached_count_cache is not None
        return self._reached_count_cache

    def _get_total_complexity(self) -> Tuple[int, int]:
        if self._total_complexity_cache is not None:
            return self._total_complexity_cache
        self._compute_function_stats()
        assert self._total_complexity_cache is not None
        return self._total_complexity_cache

    def get_all_functions(self) -> Dict[str, function_profile.FunctionProfile]:
        """Returns all function profiles of this project. This includes both
        functions of the module where file paths are available, and, also
        functions of external dependencies that are just destinations of
        callsites, namely where there was no source code to inspect.

        Use only this for accessing/inspecting/operating on the functions, and
        not the internal all_functions dictionary.
        """
        return self.all_functions

    def get_all_functions_with_source(
        self, ) -> Dict[str, function_profile.FunctionProfile]:
        """Returns all functions where there was a source code location
        attached, which roughly corresponds to functions declared in the
        project or third parties where source code was pulled in.

        This returns an internal cached dictionary for performance, so callers
        must treat the returned mapping as read-only.
        """
        if self._all_functions_with_source_cache is not None:
            return self._all_functions_with_source_cache

        local_functions_with_source: Dict[str,
                                          function_profile.FunctionProfile] = (
                                              dict())
        for func_name, func_profile in self.all_functions.items():
            # Go through checks to ensure we have the source code.
            if not func_profile.has_source_file:
                continue
            # Skip any where we do not have a line number.
            if int(func_profile.function_linenumber) == -1:
                continue
            local_functions_with_source[func_name] = func_profile

        self._all_functions_with_source_cache = local_functions_with_source
        return local_functions_with_source

    def get_func_hit_percentage(self, func_name):
        """Returns the percentage of lines covered of a function at runtime.
        Returns 0.0 in case any error happens.
        """
        try:
            func_total_lines, hit_lines = self.runtime_coverage.get_hit_summary(
                func_name)
            if hit_lines is None or func_total_lines is None:
                hit_percentage = 0.0
            else:
                hit_percentage = (hit_lines / func_total_lines) * 100.0
        except Exception:
            hit_percentage = 0.0
        return hit_percentage

    def _set_fd_cache(self):
        for fd_k, fd in self.all_functions.items():
            if self.target_lang == "rust":
                self.dst_to_fd_cache[utils.demangle_rust_func(
                    fd.function_name)] = fd
            else:
                self.dst_to_fd_cache[utils.demangle_cpp_func(
                    fd.function_name)] = fd
