# Copyright 2025 Fuzz Introspector Authors
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
"""Tests for tree-sitter query helpers."""

from tree_sitter import Language, Parser
import tree_sitter_python

from fuzz_introspector.frontends import tree_sitter_utils


def test_get_query_cache():
    lang = Language(tree_sitter_python.language())
    query_a = tree_sitter_utils.get_query(lang, '(identifier) @id')
    query_b = tree_sitter_utils.get_query(lang, '(identifier) @id')
    assert query_a is query_b


def test_query_captures():
    lang = Language(tree_sitter_python.language())
    parser = Parser(lang)
    query = tree_sitter_utils.get_query(lang, '(identifier) @id')
    root = parser.parse(b'alpha = beta').root_node
    captures = tree_sitter_utils.query_captures(query, root)
    assert 'id' in captures
    assert [node.text.decode('utf-8')
            for node in captures['id']] == ['alpha', 'beta']
