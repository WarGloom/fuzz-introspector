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
"""Tests for precomputed frontend callgraph caches."""

from dataclasses import dataclass
import os
import sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector.frontends import frontend_c_cpp  # noqa: E402
from fuzz_introspector.frontends import frontend_go  # noqa: E402
from fuzz_introspector.frontends import frontend_jvm  # noqa: E402
from fuzz_introspector.frontends import frontend_rust  # noqa: E402


@dataclass
class _FakeFunction:
    name: str
    base_callsites: list[tuple[str, int]]


def test_cpp_precomputed_uses_and_depth(monkeypatch):
    project = object.__new__(frontend_c_cpp.CppProject)
    functions = [
        _FakeFunction("A", [("B", 1)]),
        _FakeFunction("B", [("C", 2)]),
        _FakeFunction("C", []),
    ]
    function_map = {function.name: function for function in functions}

    def fake_find_source_with_func_def(name):
        function = function_map.get(name)
        if function is None:
            return None
        return (None, function)

    monkeypatch.setattr(
        project, "_find_source_with_func_def", fake_find_source_with_func_def
    )

    assert project._build_function_uses_map(functions) == {"A": 0, "B": 1, "C": 1}
    assert project._build_function_depth_map(functions) == {"C": 0, "B": 1, "A": 2}


def test_go_precomputed_uses_and_depth():
    project = object.__new__(frontend_go.GoProject)
    function_map = {
        "A": _FakeFunction("A", [("B", 1)]),
        "B": _FakeFunction("B", [("C", 1)]),
        "C": _FakeFunction("C", []),
    }

    uses = project._build_function_uses_map(list(function_map.values()))
    depth = project._build_function_depth_map(function_map)

    assert uses == {"A": 0, "B": 1, "C": 1}
    assert depth == {"C": 0, "B": 1, "A": 2}


def test_jvm_precomputed_uses_and_depth():
    project = object.__new__(frontend_jvm.JvmProject)
    methods = [
        _FakeFunction("A", [("B", 1)]),
        _FakeFunction("B", [("C", 1)]),
        _FakeFunction("C", []),
    ]

    uses = project._build_method_uses_map(methods)
    depth = project._build_method_depth_map(methods)

    assert uses == {"A": 0, "B": 1, "C": 1}
    assert depth == {"C": 0, "B": 1, "A": 2}


def test_rust_precomputed_uses_and_depth(monkeypatch):
    project = object.__new__(frontend_rust.RustProject)
    function_map = {
        "crate::A": _FakeFunction("crate::A", [("crate::B", 1)]),
        "crate::B": _FakeFunction("crate::B", [("crate::C", 1)]),
        "crate::C": _FakeFunction("crate::C", []),
    }

    def fake_get_function_node(name, all_functions, exact_match):
        del exact_match
        for full_name in all_functions:
            if full_name == name or full_name.endswith(name):
                return all_functions[full_name]
        return None

    monkeypatch.setattr(frontend_rust, "get_function_node", fake_get_function_node)

    uses = project._build_function_uses_map(list(function_map.values()))
    depth = project._build_function_depth_map(function_map)

    assert uses == {"crate::A": 0, "crate::B": 1, "crate::C": 1}
    assert depth == {"crate::C": 0, "crate::B": 1, "crate::A": 2}
