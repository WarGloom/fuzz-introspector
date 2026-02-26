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
"""Utilities for tree-sitter query execution."""

from collections import defaultdict
from typing import Any

from tree_sitter import Language, Node, Query, QueryCursor

_QUERY_CACHE: dict[tuple[int, str], Query] = {}


def get_query(language: Language, query_string: str) -> Query:
    """Gets a cached query object for the provided language and query string."""
    query_key = (id(language), query_string)
    if query_key in _QUERY_CACHE:
        return _QUERY_CACHE[query_key]

    try:
        query = Query(language, query_string)
    except TypeError:
        query = language.query(query_string)
    _QUERY_CACHE[query_key] = query
    return query


def query_captures(query: Query, node: Node) -> dict[str, list[Node]]:
    """Runs a query and returns captures indexed by capture name."""
    captures_fn = getattr(query, 'captures', None)
    if callable(captures_fn):
        capture_result = captures_fn(node)
    else:
        capture_result = QueryCursor(query).captures(node)
    return _normalise_capture_result(capture_result)


def _normalise_capture_result(capture_result: Any) -> dict[str, list[Node]]:
    if isinstance(capture_result, dict):
        return {
            str(name): list(nodes)
            for name, nodes in capture_result.items()
        }

    if isinstance(capture_result, list):
        grouped_captures: dict[str, list[Node]] = defaultdict(list)
        for item in capture_result:
            node = None
            name = None
            if isinstance(item, tuple) and len(item) == 2:
                if isinstance(item[0], Node):
                    node = item[0]
                    name = item[1]
                elif isinstance(item[1], Node):
                    node = item[1]
                    name = item[0]
            else:
                node = getattr(item, 'node', None)
                name = getattr(item, 'name', None)

            if isinstance(node, Node) and name is not None:
                grouped_captures[str(name)].append(node)

        return dict(grouped_captures)

    return {}
