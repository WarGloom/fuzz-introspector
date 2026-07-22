## 2025-02-23 - Pythonic Generator Unrolling in Hot Loops
**Learning:** Using `any()` combined with a generator expression inside a hot loop for substring checks (e.g., `any(excluded in function_name.lower() for excluded in excluded_function_name)`) incurs significant generator creation overhead. An explicit `for` loop with an early `break` or `return` is substantially faster in micro-benchmarks.
**Action:** When filtering large lists of items (like function profiles), unroll the generator into an explicit nested loop structure.
