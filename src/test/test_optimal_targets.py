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
"""Regression tests for optimal target selection semantics."""

import copy
import os
import sys

from types import SimpleNamespace

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector.analyses import optimal_targets  # noqa: E402


def _make_function(name, complexity, reached, new_unreached, total_complexity):
    return SimpleNamespace(
        function_name=name,
        cyclomatic_complexity=complexity,
        functions_reached=list(reached),
        hitcount=0,
        reached_by_fuzzers=[],
        arg_count=1,
        bb_count=2,
        total_cyclomatic_complexity=total_complexity,
        new_unreached_complexity=new_unreached,
        incoming_references=[],
    )


def _make_merged_profile():
    functions = {
        "A":
        _make_function("A", complexity=40, reached=["X"], new_unreached=120,
                       total_complexity=80),
        "B":
        _make_function("B", complexity=30, reached=["Y"], new_unreached=90,
                       total_complexity=70),
        "X":
        _make_function("X", complexity=60, reached=[], new_unreached=60,
                       total_complexity=60),
        "Y":
        _make_function("Y", complexity=20, reached=[], new_unreached=20,
                       total_complexity=20),
    }
    return SimpleNamespace(
        profiles=[SimpleNamespace(target_lang="c-cpp")],
        target_lang="c-cpp",
        all_functions=functions,
    )


def _snapshot_functions(merged_profile):
    return {
        name: {
            "hitcount": fd.hitcount,
            "reached_by_fuzzers": list(fd.reached_by_fuzzers),
            "new_unreached_complexity": fd.new_unreached_complexity,
            "total_cyclomatic_complexity": fd.total_cyclomatic_complexity,
        }
        for name, fd in merged_profile.all_functions.items()
    }


def _run_reference_with_deepcopy(analyzer, merged_profile):
    new_merged_profile = copy.deepcopy(merged_profile)
    optimal_functions_targeted = []
    target_fds = analyzer.analysis_get_optimal_targets(merged_profile)
    drivers_to_create = 10
    count_ranges = [(10000, 1), (5000, 3), (2000, 7)]
    for top, count in count_ranges:
        if len(merged_profile.all_functions) > top:
            drivers_to_create = count
            break

    while len(optimal_functions_targeted) < drivers_to_create:
        if len(target_fds) == 0:
            break
        optimal_target_fd = max(
            target_fds,
            key=lambda potential_target: int(
                potential_target.new_unreached_complexity),
        )
        optimal_functions_targeted.append(optimal_target_fd)
        optimal_targets.add_func_to_reached_and_clone(new_merged_profile,
                                                      optimal_target_fd)
        if len(optimal_functions_targeted) < drivers_to_create:
            target_fds = analyzer.analysis_get_optimal_targets(
                new_merged_profile)
    return new_merged_profile, optimal_functions_targeted


def test_iteratively_get_optimal_targets_matches_deepcopy_reference():
    analyzer = optimal_targets.OptimalTargets()
    input_profile = _make_merged_profile()
    original_snapshot = _snapshot_functions(input_profile)

    reference_profile, reference_targets = _run_reference_with_deepcopy(
        analyzer, input_profile)
    result_profile, result_targets = analyzer.iteratively_get_optimal_targets(
        input_profile)

    assert [fd.function_name for fd in result_targets
            ] == [fd.function_name for fd in reference_targets]
    assert _snapshot_functions(result_profile) == _snapshot_functions(
        reference_profile)
    assert _snapshot_functions(input_profile) == original_snapshot
