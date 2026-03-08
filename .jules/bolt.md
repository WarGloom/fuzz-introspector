
## 2025-03-05 - Optimize Multimap Accumulation
**Learning:** Using `dict.setdefault(key, []).append(...)` for accumulating values into lists allocates an empty list on every single iteration, creating significant garbage collection pressure and CPU overhead in tight loops parsing debug info and profiling data. `collections.defaultdict(list)` avoids this allocation overhead and operates 30-50% faster.
**Action:** Always prefer `collections.defaultdict(list)` (or `set`) when constructing dictionary multimaps.
## 2025-03-05 - Avoid recomputing unreached complexity with full-table scans
**Learning:** In `optimal_targets.py`, `new_unreached_complexity` and `total_cyclomatic_complexity` were recomputed by iterating over the entire function table ($O(N \times M)$ operation) whenever a new function was marked as reached. Since `total_cyclomatic_complexity` is static, and `new_unreached_complexity` can be updated incrementally using `incoming_references` by subtracting the newly reached function's complexity from its callers, the full-table scan is unnecessary and slows down the analysis significantly.
**Action:** When updating metrics that depend on a graph's state (like reachability or complexity), prefer incremental updates using reverse edges (e.g., `incoming_references`) instead of recomputing metrics for the entire graph from scratch.
