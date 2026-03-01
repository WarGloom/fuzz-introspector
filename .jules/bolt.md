## 2025-01-28 - Prefer defaultdict for Accumulating Dict Lists
**Learning:** For performance and readability when accumulating values into dictionary lists (multimaps), replacing manual `.get(key, [])` and reassignment with `collections.defaultdict(list)` is an effective and Pythonic optimization.
**Action:** Always prefer `collections.defaultdict(list)` over `.get(key, [])` paired with dictionary reassignment when creating list multimaps.
