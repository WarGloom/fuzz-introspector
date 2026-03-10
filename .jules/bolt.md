
## 2025-03-05 - Optimize Multimap Accumulation
**Learning:** Using `dict.setdefault(key, []).append(...)` for accumulating values into lists allocates an empty list on every single iteration, creating significant garbage collection pressure and CPU overhead in tight loops parsing debug info and profiling data. `collections.defaultdict(list)` avoids this allocation overhead and operates 30-50% faster.
**Action:** Always prefer `collections.defaultdict(list)` (or `set`) when constructing dictionary multimaps.

## 2025-03-05 - Avoid Redundant Unreached Complexity Computation
**Learning:** During hitcount update loops (e.g., when simulating coverage expansion), recalculating unreached complexity by scanning the full dictionary results in an $O(N \times M)$ overhead. Since cyclomatic complexity is statically precomputed, we can update it incrementally. However, simply propagating through `incoming_references` is insufficient if the property depends on full transitive reachability (`functions_reached`). Instead, an iterative dictionary mapping check over `functions_reached` reduces overhead significantly by skipping redundant deep lookups. Also, invariant properties like `total_cyclomatic_complexity` should not be re-assigned in loops.
**Action:** When updating call graph metrics based on coverage state changes, prefer tracking state transitions (e.g. `hitcount` 0 -> 1) and applying updates incrementally. Ensure the optimization correctly handles transitive dependencies and avoid recomputing static properties.
