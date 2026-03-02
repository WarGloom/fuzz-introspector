## 2024-03-12 - Optimize dictionary list appends with collections.defaultdict(list)
**Learning:** `dict.setdefault(key, []).append(val)` incurs significant overhead when called repeatedly in tight loops, due to function call overhead and allocating a new empty list on every call even when the key exists.
**Action:** Always prefer `collections.defaultdict(list)` over `setdefault` when accumulating values into multimaps or lists.
