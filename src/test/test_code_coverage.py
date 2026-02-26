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

"""Test code_coverage.py"""

import builtins
import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import code_coverage  # noqa: E402
from fuzz_introspector.datatypes import function_profile  # noqa: E402

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.fixture
def sample_jvm_coverage_xml():
    """Fixture for a sample jvm_coverage_xml"""
    cfg_str = """<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
<report name="JaCoCo Coverage Report">
  <sessioninfo id="9253a4a5cb62-c5efb6cd" start="1669995723552" dump="1669995724729"/>
  <package name="">
    <class name="BASE64EncoderStreamFuzzer" sourcefilename="BASE64EncoderStreamFuzzer.java">
      <method name="&lt;init&gt;" desc="()V" line="23">
        <counter type="INSTRUCTION" missed="3" covered="0"/>
        <counter type="LINE" missed="1" covered="0"/>
        <counter type="COMPLEXITY" missed="1" covered="0"/>
        <counter type="METHOD" missed="1" covered="0"/>
      </method>
      <method name="fuzzerTestOneInput" desc="(LFuzzedDataProvider;)V" line="25">
        <counter type="INSTRUCTION" missed="2" covered="16"/>
        <counter type="LINE" missed="1" covered="1"/>
        <counter type="COMPLEXITY" missed="0" covered="1"/>
        <counter type="METHOD" missed="0" covered="1"/>
      </method>
    </class>
    <sourcefile name="BASE64EncoderStreamFuzzer.java">
      <line nr="23" mi="3" ci="0" mb="0" cb="0"/>
      <line nr="25" mi="0" ci="3" mb="0" cb="0"/>
      <line nr="27" mi="0" ci="6" mb="0" cb="0"/>
      <counter type="INSTRUCTION" missed="3" covered="21"/>
      <counter type="LINE" missed="1" covered="6"/>
      <counter type="COMPLEXITY" missed="1" covered="1"/>
      <counter type="METHOD" missed="1" covered="1"/>
      <counter type="CLASS" missed="0" covered="1"/>
    </sourcefile>
  </package>
</report>"""
    return cfg_str


def test_load_llvm_coverage():
    """Tests loading llvm coverage from a .covreport file."""
    cov_profile = code_coverage.load_llvm_coverage(TEST_DATA_PATH, 'sample_cov')
    assert len(cov_profile.covmap) > 0
    assert len(cov_profile.file_map) == 0
    assert len(cov_profile.branch_cov_map) > 0
    assert cov_profile._cov_type == "function"
    assert len(cov_profile.coverage_files) == 1
    assert len(cov_profile.dual_file_map) == 0

    assert cov_profile.covmap['BZ2_bzCompress'][0] == (408, 4680)
    assert cov_profile.covmap['BZ2_bzCompress'][7] == (416, 9360)
    assert cov_profile.covmap['BZ2_bzCompress'][10] == (420, 0)
    assert cov_profile.covmap['add_pair_to_block'][0] == (217, 36000000)
    assert cov_profile.covmap['add_pair_to_block'][4] == (221, 144000000)
    assert cov_profile.covmap['add_pair_to_block'][11] == (228, 3510000)
    assert cov_profile.covmap['fromtext_md'][1] == (21, 38)
    assert cov_profile.covmap['fromtext_md'][-2] == (40, 13)
    assert cov_profile.covmap['fallbackQSort3'][1] == (136, 1620000000)

    assert cov_profile.branch_cov_map['BZ2_bzCompress:411,8'] == [0, 4680]
    assert cov_profile.branch_cov_map['BZ2_bzCompress:414,8'] == [0, 4680]
    assert cov_profile.branch_cov_map['BZ2_bzCompress:417,4'] == [0, 9360, 0, 4680, 0, 4680]
    assert cov_profile.branch_cov_map['BZ2_bzCompress:425,20'] == [0, 0]
    assert cov_profile.branch_cov_map['BZ2_bzCompress:443,14'] == [0, 0]
    assert cov_profile.branch_cov_map['add_pair_to_block:220,16'] == [144000000, 36000000]
    assert cov_profile.branch_cov_map['add_pair_to_block:224,4'] == (
        [3260, 36000000, 3260, 3510000, 1570000])


def write_coverage_file(tmpdir, coverage_file):
    # Write the coverage_file
    path = os.path.join(tmpdir, "jacoco.xml")
    with open(path, "w") as f:
        f.write(coverage_file)


def generate_temp_function_profile(name, source):
    elem = dict()
    elem["functionName"] = name
    elem["functionSourceFile"] = source
    elem["functionLinenumber"] = 13
    elem['linkageType'] = None
    elem['returnType'] = None
    elem['argCount'] = None
    elem['argTypes'] = None
    elem['argNames'] = None
    elem['BBCount'] = None
    elem['ICount'] = None
    elem['EdgeCount'] = None
    elem['CyclomaticComplexity'] = None
    elem['functionsReached'] = []
    elem['functionUses'] = None
    elem['functionDepth'] = None
    elem['constantsTouched'] = None
    elem['BranchProfiles'] = []
    elem['Callsites'] = []

    return function_profile.FunctionProfile(elem)


def test_jvm_coverage(tmpdir, sample_jvm_coverage_xml):
    """Basic test for jvm coverage"""
    write_coverage_file(tmpdir, sample_jvm_coverage_xml)

    # Generate Coverage Profile
    cp = code_coverage.load_jvm_coverage(tmpdir)

    # Assure coverage profile has been correctly retrieved
    assert cp is not None

    # Ensure getting the correct coverage file
    assert len(cp.coverage_files) == 1
    assert cp.coverage_files == [os.path.join(tmpdir, "jacoco.xml")]

    # Ensure the coverage map result is correct
    assert len(cp.covmap) == 2
    assert "[BASE64EncoderStreamFuzzer].<init>()" in cp.covmap
    assert "[BASE64EncoderStreamFuzzer].fuzzerTestOneInput(FuzzedDataProvider)" in cp.covmap
    assert cp.covmap["[BASE64EncoderStreamFuzzer].<init>()"] == [(23, 0)]
    assert cp.covmap[
        "[BASE64EncoderStreamFuzzer].fuzzerTestOneInput(FuzzedDataProvider)"] == [(25, 3), (27, 6)]


def test_get_hit_details_skips_transform_chain_for_direct_hit(monkeypatch):
    cp = code_coverage.CoverageProfile()
    cp.covmap = {"direct_hit": [(11, 1)]}

    def fail_if_called(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected transform call for direct key lookup")

    monkeypatch.setattr(code_coverage.utils, "demangle_cpp_func", fail_if_called)
    monkeypatch.setattr(code_coverage.utils, "normalise_str", fail_if_called)
    monkeypatch.setattr(code_coverage.utils, "remove_jvm_generics", fail_if_called)
    monkeypatch.setattr(code_coverage.utils, "demangle_rust_func", fail_if_called)
    monkeypatch.setattr(code_coverage.utils, "locate_rust_fuzz_key", fail_if_called)

    assert cp.get_hit_details("direct_hit") == [(11, 1)]


def test_get_hit_details_negative_cache_avoids_repeated_transform_work(monkeypatch):
    cp = code_coverage.CoverageProfile()
    cp.covmap = {"known": [(7, 3)]}
    call_counts = {
        "demangle_cpp_func": 0,
        "normalise_str": 0,
        "remove_jvm_generics": 0,
        "demangle_rust_func": 0,
        "locate_rust_fuzz_key": 0,
    }

    def tracked_demangle_cpp(value):
        call_counts["demangle_cpp_func"] += 1
        return value + "__cpp"

    def tracked_normalise(value):
        call_counts["normalise_str"] += 1
        return value + "__norm"

    def tracked_remove_jvm_generics(value):
        call_counts["remove_jvm_generics"] += 1
        return value + "__jvm"

    def tracked_demangle_rust(value):
        call_counts["demangle_rust_func"] += 1
        return value + "__rust"

    def tracked_locate_rust(value, covmap):
        del value, covmap
        call_counts["locate_rust_fuzz_key"] += 1
        return None

    monkeypatch.setattr(code_coverage.utils, "demangle_cpp_func", tracked_demangle_cpp)
    monkeypatch.setattr(code_coverage.utils, "normalise_str", tracked_normalise)
    monkeypatch.setattr(code_coverage.utils, "remove_jvm_generics",
                        tracked_remove_jvm_generics)
    monkeypatch.setattr(code_coverage.utils, "demangle_rust_func", tracked_demangle_rust)
    monkeypatch.setattr(code_coverage.utils, "locate_rust_fuzz_key", tracked_locate_rust)

    assert cp.get_hit_details("missing") == []
    assert cp.get_hit_details("missing") == []
    assert call_counts == {
        "demangle_cpp_func": 1,
        "normalise_str": 1,
        "remove_jvm_generics": 1,
        "demangle_rust_func": 1,
        "locate_rust_fuzz_key": 1,
    }


def test_get_hit_details_negative_cache_invalidates_on_covmap_growth(monkeypatch):
    cp = code_coverage.CoverageProfile()
    cp.covmap = {"known": [(3, 1)]}
    call_count = {"demangle_cpp_func": 0}

    def tracked_demangle_cpp(value):
        call_count["demangle_cpp_func"] += 1
        return value + "__cpp"

    monkeypatch.setattr(code_coverage.utils, "demangle_cpp_func", tracked_demangle_cpp)
    monkeypatch.setattr(code_coverage.utils, "normalise_str", lambda value: value)
    monkeypatch.setattr(code_coverage.utils, "remove_jvm_generics", lambda value: value)
    monkeypatch.setattr(code_coverage.utils, "demangle_rust_func", lambda value: value)
    monkeypatch.setattr(code_coverage.utils, "locate_rust_fuzz_key",
                        lambda value, covmap: None)

    assert cp.get_hit_details("missing") == []
    cp.covmap["missing"] = [(99, 5)]
    assert cp.get_hit_details("missing") == [(99, 5)]
    assert call_count["demangle_cpp_func"] == 1


def test_load_llvm_coverage_reuses_cached_parse_result(monkeypatch, tmp_path):
    code_coverage._LLVM_COVERAGE_PROFILE_CACHE.clear()
    monkeypatch.delenv(code_coverage.LLVM_COVERAGE_CACHE_ENV, raising=False)

    cov_path = tmp_path / "target.covreport"
    cov_path.write_text(
        "func_a:\n"
        "  10| 2| return 1;\n",
        encoding="utf-8",
    )

    open_counts = {"covreport_reads": 0}
    original_open = builtins.open

    def counting_open(path, mode="r", *args, **kwargs):
        if str(path).endswith(".covreport") and "r" in mode:
            open_counts["covreport_reads"] += 1
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)

    first = code_coverage.load_llvm_coverage(str(tmp_path), "target")
    second = code_coverage.load_llvm_coverage(str(tmp_path), "target")

    assert open_counts["covreport_reads"] == 1
    assert first is not second
    assert first.covmap is second.covmap
    assert first.branch_cov_map is second.branch_cov_map
    assert first.get_hit_summary("func_a") == (1, 1)
    assert "func_a" in first._func_cov_key_cache
    assert "func_a" not in second._func_cov_key_cache


def test_load_llvm_coverage_cache_can_be_disabled(monkeypatch, tmp_path):
    code_coverage._LLVM_COVERAGE_PROFILE_CACHE.clear()
    monkeypatch.setenv(code_coverage.LLVM_COVERAGE_CACHE_ENV, "0")

    cov_path = tmp_path / "target.covreport"
    cov_path.write_text(
        "func_b:\n"
        "  12| 3| return 2;\n",
        encoding="utf-8",
    )

    open_counts = {"covreport_reads": 0}
    original_open = builtins.open

    def counting_open(path, mode="r", *args, **kwargs):
        if str(path).endswith(".covreport") and "r" in mode:
            open_counts["covreport_reads"] += 1
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)

    first = code_coverage.load_llvm_coverage(str(tmp_path), "target")
    second = code_coverage.load_llvm_coverage(str(tmp_path), "target")

    assert open_counts["covreport_reads"] == 2
    assert first.covmap is not second.covmap
