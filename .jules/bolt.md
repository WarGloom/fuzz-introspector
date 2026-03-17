
## 2025-03-05 - Optimize Multimap Accumulation
**Learning:** Using `dict.setdefault(key, []).append(...)` for accumulating values into lists allocates an empty list on every single iteration, creating significant garbage collection pressure and CPU overhead in tight loops parsing debug info and profiling data. `collections.defaultdict(list)` avoids this allocation overhead and operates 30-50% faster.
**Action:** Always prefer `collections.defaultdict(list)` (or `set`) when constructing dictionary multimaps.
## 2025-05-24 - Avoid `dict.setdefault` for allocating collections inside loops
**Learning:** `dict.setdefault(key, []).append(...)` or `dict.setdefault(key, {})` creates a new empty list/dict object on *every* single iteration, even if the key already exists in the dictionary. This can cause significant overhead and memory churn in hot loops or large data collections.
**Action:** Use an explicit `if key not in dict:` check to instantiate the collection only when needed, or use `collections.defaultdict(list)` which handles this more efficiently.
