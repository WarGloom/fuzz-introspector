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
"""Test datatypes/fuzzer_profile.py"""

import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import code_coverage  # noqa: E402
from fuzz_introspector.datatypes import fuzzer_profile  # noqa: E402

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')


@pytest.fixture
def sample_cfg1():
    """Fixture for a sample (shortened paths) calltree"""
    cfg_str = """Call tree
LLVMFuzzerTestOneInput /src/wuffs/fuzz/c/fuzzlib/fuzzlib.c linenumber=-1
  llvmFuzzerTestOneInput /src/wuffs/fuzz/c/../fuzzlib/fuzzlib.c linenumber=93
    jenkins_hash_u32 /src/wuffs/fuzz/c/std/../fuzzlib/fuzzlib.c linenumber=67
    jenkins_hash_u32 /src/wuffs/fuzz/c/std/../fuzzlib/fuzzlib.c linenumber=68
    wuffs_base__ptr_u8__reader /src/wuffs/fuzz/...-snapshot.c linenumber=72
    fuzz /src/wuffs/fuzz/c/std/bmp_fuzzer.c linenumber=74"""
    return cfg_str


def base_cpp_profile(tmpdir, sample_cfg1, fake_yaml_func_elem):
    # Write the CFG
    cfg_path = os.path.join(tmpdir, "test_file.data")
    with open(cfg_path, "w") as f:
        f.write(sample_cfg1)

    fake_frontend_yaml = {
        "Fuzzer filename": "/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c",
        "All functions": {
            "Elements": fake_yaml_func_elem
        }
    }

    fp = fuzzer_profile.FuzzerProfile(os.path.join(tmpdir, "test_file.data"),
                                      fake_frontend_yaml,
                                      "c-cpp",
                                      cfg_content=sample_cfg1)

    return fp


def test_reaches_file(tmpdir, sample_cfg1):
    """Basic test for reaches file"""
    fp = base_cpp_profile(tmpdir, sample_cfg1, [])
    fp._set_file_targets()

    # Ensure set_file_target analysis has been done
    assert len(fp.file_targets) != 0

    assert not fp.reaches_file('fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/...-snapshot.c')


def test_reaches_file_with_refine_path(tmpdir, sample_cfg1):
    """test for reaches file with refine path"""
    fp = base_cpp_profile(tmpdir, sample_cfg1, [])
    fp._set_file_targets()

    # Ensure set_file_target analysis has been done
    assert len(fp.file_targets) != 0

    fp.refine_paths('/src/wuffs/fuzz/c')

    assert not fp.reaches_file('fuzzlib.c')
    assert not fp.reaches_file('/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/...-snapshot.c')
    assert fp.reaches_file('/std/../fuzzlib/fuzzlib.c')


def generate_temp_elem(name,
                       func,
                       source_file='/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c'):
    return {
        "functionName": name,
        "functionsReached": func,
        "functionSourceFile": source_file,
        "linkageType": None,
        "functionLinenumber": None,
        "returnType": None,
        "argCount": None,
        "argTypes": None,
        "argNames": None,
        "BBCount": None,
        "ICount": None,
        "EdgeCount": None,
        "CyclomaticComplexity": None,
        "functionUses": None,
        "functionDepth": None,
        "constantsTouched": None,
        "BranchProfiles": [],
        "Callsites": []
    }


def test_reaches_func(tmpdir, sample_cfg1):
    """test for reaches file with refine path"""
    elem = [
        generate_temp_elem("LLVMFuzzerTestOneInput", ["abc", "def"]),
        generate_temp_elem("TestOneInput", ["jkl", "mno"]),
        generate_temp_elem("Random", ["stu", "vwx"]),
        generate_temp_elem("abc", [], "/src/wuffs/fuzz/...-snapshot.c"),
        generate_temp_elem("def", [], "/src/wuffs/fuzz/...-snapshot.c")
    ]

    # Statically reached functions
    fp = base_cpp_profile(tmpdir, sample_cfg1, elem)
    fp._set_all_reached_functions()

    # Ensure set_all_reached_functions analysis has been done
    assert len(fp.functions_reached_by_fuzzer) != 0

    assert fp.reaches_func('abc')
    assert not fp.reaches_func('stu')
    assert not fp.reaches_func('mno')

    # Runtime reached functions
    fp.coverage = code_coverage.load_llvm_coverage(TEST_DATA_PATH,
                                                   'reached_func')
    fp._set_all_reached_functions_runtime()

    assert fp.reaches_func_runtime('abc')
    assert not fp.reaches_func_runtime('stu')
    assert not fp.reaches_func_runtime('Random')
    assert not fp.reaches_func_runtime('def')
    assert not fp.reaches_func_runtime('jkl')

    # Runtime or tatically reached functions
    assert fp.reaches_func_combined('abc')
    assert not fp.reaches_func_combined('stu')
    assert not fp.reaches_func_combined('Random')
    assert fp.reaches_func_combined('def')
    assert not fp.reaches_func_combined('jkl')


def test_complete_entrypoint_coverage_metadata_uses_static_entrypoint_file(
        tmpdir, sample_cfg1):
    cfg_path = os.path.join(tmpdir, "test_file.data")
    with open(cfg_path, "w") as f:
        f.write(sample_cfg1)

    source_file = "/src/project/fuzzer.cc"
    elem = [
        generate_temp_elem(
            "LLVMFuzzerTestOneInput",
            ["target"],
            source_file,
        )
    ]
    fp = fuzzer_profile.FuzzerProfile(
        cfg_path,
        {
            "Fuzzer filename": source_file,
            "All functions": {
                "Elements": elem
            },
        },
        "c-cpp",
        cfg_content=sample_cfg1,
    )
    fp.coverage = code_coverage.CoverageProfile()
    fp.coverage.set_type("function")
    fp.coverage.covmap = {"LLVMFuzzerTestOneInput": [(13, 1), (14, 0)]}

    fp._complete_entrypoint_coverage_metadata()

    assert fp.coverage.function_file_map == {
        "LLVMFuzzerTestOneInput": source_file
    }


def test_prune_excluded_profile_data_removes_excluded_file_targets_and_funcs(
    tmpdir, ) -> None:
    fp = fuzzer_profile.FuzzerProfile(
        os.path.join(tmpdir, "test.data"),
        {
            "Fuzzer filename": "/src/fuzz/fuzzer_dir/fuzzer.cc",
            "All functions": {
                "Elements": [
                    {
                        "functionName": "LLVMFuzzerTestOneInput",
                        "functionsReached": ["kept", "excluded"],
                        "functionSourceFile": "/src/fuzz/fuzzer_dir/fuzzer.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                    {
                        "functionName": "kept",
                        "functionsReached": [],
                        "functionSourceFile": "/src/fuzz/fuzzer_dir/fuzzer.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                    {
                        "functionName": "excluded",
                        "functionsReached": [],
                        "functionSourceFile": "/src/vendor/ignored/fuzz.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                ]
            },
        },
        "c-cpp",
        cfg_content="""Call tree
LLVMFuzzerTestOneInput /src/fuzz/fuzzer_dir/fuzzer.cc linenumber=-1
  kept /src/fuzz/fuzzer_dir/fuzzer.cc linenumber=10
  excluded /src/vendor/ignored/fuzz.cc linenumber=11""",
        exclude_patterns=["/vendor/.*"],
    )

    fp._set_all_reached_functions()
    fp._set_file_targets()
    fp.functions_reached_by_fuzzer_runtime = ["kept", "excluded"]

    fp._prune_excluded_profile_data()

    assert "excluded" not in fp.functions_reached_by_fuzzer
    assert "excluded" not in fp.functions_reached_by_fuzzer_runtime
    assert "/src/vendor/ignored/fuzz.cc" not in fp.file_targets
    assert "excluded" not in fp.functions_unreached_by_fuzzer


def test_prune_excluded_profile_data_applies_function_patterns_only() -> None:
    fp = fuzzer_profile.FuzzerProfile(
        "test.data",
        {
            "Fuzzer filename": "/src/project/fuzzer.cc",
            "All functions": {
                "Elements": [
                    {
                        "functionName": "LLVMFuzzerTestOneInput",
                        "functionsReached": ["allowed", "skip_me"],
                        "functionSourceFile": "/src/project/fuzzer.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                    {
                        "functionName": "allowed",
                        "functionsReached": [],
                        "functionSourceFile": "/src/project/file.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                    {
                        "functionName": "skip_me",
                        "functionsReached": [],
                        "functionSourceFile": "/src/project/file.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                ]
            },
        },
        "c-cpp",
        cfg_content="""Call tree
LLVMFuzzerTestOneInput /src/project/fuzzer.cc linenumber=-1
  allowed /src/project/file.cc linenumber=10
  skip_me /src/project/file.cc linenumber=11""",
        exclude_function_patterns=[r"skip_me"],
    )

    fp._set_all_reached_functions()
    fp._set_file_targets()
    fp.functions_reached_by_fuzzer_runtime = [
        "allowed", "skip_me", "unknown_symbol"
    ]

    fp._prune_excluded_profile_data()

    assert "skip_me" not in fp.functions_reached_by_fuzzer
    assert "skip_me" not in fp.functions_reached_by_fuzzer_runtime
    assert "unknown_symbol" in fp.functions_reached_by_fuzzer_runtime
    assert fp.file_targets["/src/project/file.cc"] == {"allowed"}


def test_runtime_reached_functions_use_canonical_profile_names() -> None:
    fp = fuzzer_profile.FuzzerProfile(
        "test.data",
        {
            "Fuzzer filename": "/src/project/fuzzer.cc",
            "All functions": {
                "Elements": [
                    {
                        "functionName": "LLVMFuzzerTestOneInput",
                        "functionsReached": ["target()"],
                        "functionSourceFile": "/src/project/fuzzer.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                    {
                        "functionName": "_Z6targetv",
                        "functionsReached": [],
                        "functionSourceFile": "/src/project/target.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                    {
                        "functionName": "LLVMFuzzerInitialize",
                        "functionsReached": [],
                        "functionSourceFile": "/src/project/fuzzer.cc",
                        "linkageType": None,
                        "functionLinenumber": None,
                        "returnType": None,
                        "argCount": None,
                        "argTypes": None,
                        "argNames": None,
                        "BBCount": None,
                        "ICount": None,
                        "EdgeCount": None,
                        "CyclomaticComplexity": None,
                        "functionUses": None,
                        "functionDepth": None,
                        "constantsTouched": None,
                        "BranchProfiles": [],
                        "Callsites": [],
                    },
                ]
            },
        },
        "c-cpp",
        cfg_content="""Call tree
LLVMFuzzerTestOneInput /src/project/fuzzer.cc linenumber=-1
  target() /src/project/target.cc linenumber=10""",
    )
    coverage = code_coverage.CoverageProfile()
    coverage.covmap["_Z6targetv"] = [(10, 1)]
    coverage.covmap["LLVMFuzzerInitialize"] = [(5, 1)]
    fp.coverage = coverage

    fp._set_all_reached_functions()
    fp._set_all_reached_functions_runtime()

    assert fp.functions_reached_by_fuzzer_runtime == {"target()"}


def test_invalid_exclusion_patterns_are_ignored_with_warning(
        caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        fp = fuzzer_profile.FuzzerProfile(
            "test.data",
            {
                "Fuzzer filename": "/src/project/fuzzer.cc",
                "All functions": {
                    "Elements": []
                },
            },
            "c-cpp",
            cfg_content="""Call tree
LLVMFuzzerTestOneInput /src/project/fuzzer.cc linenumber=-1""",
            exclude_patterns=["[invalid"],
            exclude_function_patterns=["(bad"],
        )

    warning_messages = [record.message for record in caplog.records]
    assert any("Ignoring invalid file exclusion pattern" in msg
               for msg in warning_messages)
    assert any("Ignoring invalid function exclusion pattern" in msg
               for msg in warning_messages)
    assert not fp._matches_exclude_pattern("/src/project/fuzzer.cc")
    assert not fp._matches_exclude_function_pattern("keep_me")


def test_is_file_covered_caches_coverage_scans(tmpdir) -> None:
    frontend_yaml = {
        "Fuzzer filename": "/src/project/fuzz_target.cc",
        "All functions": {
            "Elements": [
                {
                    "functionName": "LLVMFuzzerTestOneInput",
                    "functionsReached": ["f1", "f2"],
                    "functionSourceFile": "/src/project/fuzz_target.cc",
                    "linkageType": None,
                    "functionLinenumber": None,
                    "returnType": None,
                    "argCount": None,
                    "argTypes": None,
                    "argNames": None,
                    "BBCount": None,
                    "ICount": None,
                    "EdgeCount": None,
                    "CyclomaticComplexity": None,
                    "functionUses": None,
                    "functionDepth": None,
                    "constantsTouched": None,
                    "BranchProfiles": [],
                    "Callsites": [],
                },
                {
                    "functionName": "f1",
                    "functionsReached": [],
                    "functionSourceFile": "/src/project/file_a.cc",
                    "linkageType": None,
                    "functionLinenumber": None,
                    "returnType": None,
                    "argCount": None,
                    "argTypes": None,
                    "argNames": None,
                    "BBCount": None,
                    "ICount": None,
                    "EdgeCount": None,
                    "CyclomaticComplexity": None,
                    "functionUses": None,
                    "functionDepth": None,
                    "constantsTouched": None,
                    "BranchProfiles": [],
                    "Callsites": [],
                },
                {
                    "functionName": "f2",
                    "functionsReached": [],
                    "functionSourceFile": "/src/project/file_b.cc",
                    "linkageType": None,
                    "functionLinenumber": None,
                    "returnType": None,
                    "argCount": None,
                    "argTypes": None,
                    "argNames": None,
                    "BBCount": None,
                    "ICount": None,
                    "EdgeCount": None,
                    "CyclomaticComplexity": None,
                    "functionUses": None,
                    "functionDepth": None,
                    "constantsTouched": None,
                    "BranchProfiles": [],
                    "Callsites": [],
                },
            ]
        },
    }
    fp = fuzzer_profile.FuzzerProfile(
        os.path.join(tmpdir, "test.data"),
        frontend_yaml,
        "c-cpp",
        cfg_content=(
            "Call tree\n"
            "LLVMFuzzerTestOneInput /src/project/fuzz_target.cc linenumber=-1"),
    )
    fp.file_targets = {
        "/src/project/file_a.cc": {"f1"},
        "/src/project/file_b.cc": {"f2"},
    }

    class FakeCoverage:

        def __init__(self, hit_summary):
            self._hit_summary = hit_summary
            self.call_count = 0

        def get_hit_summary(self, function_name):
            self.call_count += 1
            return self._hit_summary[function_name]

    first_cov = FakeCoverage({
        "LLVMFuzzerTestOneInput": (1, 0),
        "f1": (10, 2),
        "f2": (10, 0),
    })
    fp.coverage = first_cov

    assert fp.is_file_covered("/src/project/file_a.cc", "/src/project")
    assert first_cov.call_count == 2
    assert fp.is_file_covered("/src/project/file_a.cc", "/src/project")
    assert first_cov.call_count == 2

    second_cov = FakeCoverage({
        "LLVMFuzzerTestOneInput": (1, 0),
        "f1": (10, 0),
        "f2": (10, 0),
    })
    fp.coverage = second_cov
    assert not fp.is_file_covered("/src/project/file_a.cc", "/src/project")
    assert second_cov.call_count == 2


def _func_elem(name, source_file, reached=None):
    return {
        "functionName": name,
        "functionsReached": reached or [],
        "functionSourceFile": source_file,
        "linkageType": None,
        "functionLinenumber": None,
        "returnType": None,
        "argCount": None,
        "argTypes": None,
        "argNames": None,
        "BBCount": None,
        "ICount": None,
        "EdgeCount": None,
        "CyclomaticComplexity": None,
        "functionUses": None,
        "functionDepth": None,
        "constantsTouched": None,
        "BranchProfiles": [],
        "Callsites": [],
    }


def test_coverage_blocker_stats_canonicalize_and_deduplicate_aliases() -> None:
    fp = fuzzer_profile.FuzzerProfile(
        "test.data",
        {
            "Fuzzer filename": "/src/project/fuzzer.cc",
            "All functions": {
                "Elements": [
                    _func_elem("LLVMFuzzerTestOneInput",
                               "/src/project/fuzzer.cc", ["_Z6targetv"]),
                    _func_elem("_Z6targetv", "/src/project/target.cc"),
                ]
            },
        },
        "c-cpp",
        cfg_content="""Call tree
LLVMFuzzerTestOneInput /src/project/fuzzer.cc linenumber=-1
  target() /src/project/target.cc linenumber=10""",
    )
    fp.coverage = code_coverage.CoverageProfile()
    fp.coverage.covmap["_Z6targetv"] = [(10, 1)]
    fp.functions_reached_by_fuzzer = {"_Z6targetv", "target()"}
    fp._set_all_reached_functions_runtime()

    assert fp.get_coverage_blocker_stats() == {
        "reachable-funcs": 1,
        "reached-funcs": 1,
        "cov-reach-proportion": 100.0,
    }


def test_runtime_reachability_keeps_broad_runtime_stats() -> None:
    fp = fuzzer_profile.FuzzerProfile(
        "test.data",
        {
            "Fuzzer filename": "/src/project/fuzzer.cc",
            "All functions": {
                "Elements": [
                    _func_elem(
                        "LLVMFuzzerTestOneInput",
                        "/src/project/fuzzer.cc",
                        [
                            "helper",
                            "_Z6targetv",
                            "target_neighbour",
                            "__clang_call_terminate",
                        ],
                    ),
                    _func_elem("helper", "/src/project/fuzzer.cc"),
                    _func_elem("_Z6targetv", "/src/project/target.cc"),
                    _func_elem("target_neighbour",
                               "/src/project/lib/fuzzer.cc"),
                    _func_elem("__clang_call_terminate", ""),
                ]
            },
        },
        "c-cpp",
        cfg_content="""Call tree
LLVMFuzzerTestOneInput /src/project/fuzzer.cc linenumber=-1
  helper /src/project/fuzzer.cc linenumber=10
  target() /src/project/target.cc linenumber=11
  target_neighbour /src/project/lib/fuzzer.cc linenumber=12
  __clang_call_terminate  linenumber=13""",
    )
    fp.coverage = code_coverage.CoverageProfile()
    fp.coverage.covmap["LLVMFuzzerTestOneInput"] = [(1, 1)]
    fp.coverage.covmap["helper"] = [(10, 1)]
    fp.coverage.covmap["_Z6targetv"] = [(11, 1)]
    fp.coverage.covmap["target_neighbour"] = [(12, 1)]
    fp.coverage.covmap["__clang_call_terminate"] = [(13, 1)]
    fp._set_all_reached_functions()
    fp.refine_paths("/src/project")
    fp._set_all_reached_functions_runtime()

    assert fp.functions_reached_by_fuzzer_runtime == {
        "LLVMFuzzerTestOneInput",
        "helper",
        "target()",
        "target_neighbour",
        "__clang_call_terminate",
    }
    assert fp.get_target_reachable_functions() == {
        "target()",
        "target_neighbour",
    }
    assert fp.get_coverage_blocker_stats() == {
        "reachable-funcs": 5,
        "reached-funcs": 5,
        "cov-reach-proportion": 100.0,
    }


def test_coverage_blocker_stats_keep_sourceless_target_blockers() -> None:
    fp = fuzzer_profile.FuzzerProfile(
        "test.data",
        {
            "Fuzzer filename": "/src/project/fuzzer.cc",
            "All functions": {
                "Elements": [
                    _func_elem(
                        "LLVMFuzzerTestOneInput",
                        "/src/project/fuzzer.cc",
                        [
                            "_ZN7BaseXML9parseTextEPKcmbRPK12SharedString",
                            "__clang_call_terminate",
                        ],
                    ),
                    _func_elem(
                        "_ZN7BaseXML9parseTextEPKcmbRPK12SharedString",
                        "",
                    ),
                    _func_elem("__clang_call_terminate", ""),
                ]
            },
        },
        "c-cpp",
        cfg_content="""Call tree
LLVMFuzzerTestOneInput /src/project/fuzzer.cc linenumber=-1
  _ZN7BaseXML9parseTextEPKcmbRPK12SharedString  linenumber=113
  __clang_call_terminate  linenumber=120""",
    )
    fp.coverage = code_coverage.CoverageProfile()
    fp.coverage.covmap["LLVMFuzzerTestOneInput"] = [(1, 1)]
    fp._set_all_reached_functions()
    fp._set_all_reached_functions_runtime()

    assert fp.functions_reached_by_fuzzer_runtime == {"LLVMFuzzerTestOneInput"}
    assert fp.get_coverage_blocker_stats() == {
        "reachable-funcs": 3,
        "reached-funcs": 1,
        "cov-reach-proportion": 33.33333333333333,
    }


def test_coverage_blocker_stats_ignore_callsite_only_target_reach() -> None:
    fp = fuzzer_profile.FuzzerProfile(
        "test.data",
        {
            "Fuzzer filename": "/src/project/fuzzer.cc",
            "All functions": {
                "Elements": [
                    _func_elem(
                        "LLVMFuzzerTestOneInput",
                        "/src/project/fuzzer.cc",
                        ["_ZN7BaseXML9parseTextEPKcmbRPK12SharedString"],
                    ),
                    _func_elem(
                        "_ZN7BaseXML9parseTextEPKcmbRPK12SharedString",
                        "",
                    ),
                ]
            },
        },
        "c-cpp",
        cfg_content="""Call tree
LLVMFuzzerTestOneInput /src/project/fuzzer.cc linenumber=-1
  _ZN7BaseXML9parseTextEPKcmbRPK12SharedString  linenumber=113""",
    )
    fp.coverage = code_coverage.CoverageProfile()
    fp.functions_reached_by_fuzzer = {
        "_ZN7BaseXML9parseTextEPKcmbRPK12SharedString"
    }
    fp._set_all_reached_functions_runtime()
    fp.get_callsites()[1].cov_hitcount = 1720

    assert fp.functions_reached_by_fuzzer_runtime == set()
    assert fp.get_callsite_covered_target_functions() == {
        "BaseXML::parseText(char const*, unsigned long, bool, SharedString const*&)"
    }
    assert fp.get_coverage_blocker_stats() == {
        "reachable-funcs": 1,
        "reached-funcs": 0,
        "cov-reach-proportion": 0.0,
    }
