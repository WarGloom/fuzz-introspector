## 2024-05-14 - Python any() generator overhead in hot loops
**Learning:** Python's `any()` function combined with a generator expression (e.g. `any(x in s for x in lst)`) incurs significant overhead in hot loops due to generator creation and iteration.
**Action:** Always unroll these into explicit `for` loops with early return or `break` for a 3x speedup.
