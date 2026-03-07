
## 2025-03-05 - Optimize Multimap Accumulation
**Learning:** Using `dict.setdefault(key, []).append(...)` for accumulating values into lists allocates an empty list on every single iteration, creating significant garbage collection pressure and CPU overhead in tight loops parsing debug info and profiling data. `collections.defaultdict(list)` avoids this allocation overhead and operates 30-50% faster.
**Action:** Always prefer `collections.defaultdict(list)` (or `set`) when constructing dictionary multimaps.

## 2024-05-20 - Optimal Targets Incremental Complexity Update
**Learning:** In `optimal_targets.py`, `total_cyclomatic_complexity` is a static property of the call graph precomputed during initialization. Additionally, updating `new_unreached_complexity` can be optimized by using `incoming_references` to subtract a newly reached function's cyclomatic complexity from its own and its callers' unreached metrics. This avoids $O(N \times M)$ full-table scans when calculating the incremental impacts.
**Action:** Use incremental graph traversal logic to avoid full graph recalculations for iterative simulations.
