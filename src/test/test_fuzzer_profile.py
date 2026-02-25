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

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


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

    fp = fuzzer_profile.FuzzerProfile(
        os.path.join(tmpdir, "test_file.data"),
        fake_frontend_yaml,
        "c-cpp",
        cfg_content=sample_cfg1
    )

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


def generate_temp_elem(name, func):
    return {
        "functionName": name,
        "functionsReached": func,
        "functionSourceFile": '/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c',
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
        generate_temp_elem(
            "LLVMFuzzerTestOneInput",
            ["abc", "def"]
        ),
        generate_temp_elem(
            "TestOneInput",
            ["jkl", "mno"]
        ),
        generate_temp_elem(
            "Random",
            ["stu", "vwx"]
        )
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
    fp.coverage = code_coverage.load_llvm_coverage(TEST_DATA_PATH, 'reached_func')
    fp._set_all_reached_functions_runtime()

    assert fp.reaches_func_runtime('abc')
    assert fp.reaches_func_runtime('stu')
    assert fp.reaches_func_runtime('Random')
    assert not fp.reaches_func_runtime('def')
    assert not fp.reaches_func_runtime('jkl')

    # Runtime or tatically reached functions
    assert fp.reaches_func_combined('abc')
    assert fp.reaches_func_combined('stu')
    assert fp.reaches_func_combined('Random')
    assert fp.reaches_func_combined('def')
    assert not fp.reaches_func_combined('jkl')


def test_prune_excluded_profile_data_removes_excluded_file_targets_and_funcs(
    tmpdir,
) -> None:
    fp = fuzzer_profile.FuzzerProfile(
        os.path.join(tmpdir, "test.data"),
        {
            "Fuzzer filename":
            "/src/fuzz/fuzzer_dir/fuzzer.cc",
            "All functions": {
                "Elements":
                [
                    {
                        "functionName": "LLVMFuzzerTestOneInput",
                        "functionsReached": ["kept", "excluded"],
                        "functionSourceFile":
                        "/src/fuzz/fuzzer_dir/fuzzer.cc",
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
                "Elements":
                [
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
    fp.functions_reached_by_fuzzer_runtime = ["allowed", "skip_me", "unknown_symbol"]

    fp._prune_excluded_profile_data()

    assert "skip_me" not in fp.functions_reached_by_fuzzer
    assert "skip_me" not in fp.functions_reached_by_fuzzer_runtime
    assert "unknown_symbol" in fp.functions_reached_by_fuzzer_runtime
    assert fp.file_targets["/src/project/file.cc"] == {"allowed"}


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
