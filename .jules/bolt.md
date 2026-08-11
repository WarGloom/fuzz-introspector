## 2024-05-18 - Generator Overhead in Hot Loops
**Learning:** Generator expressions inside hot loops (like `any()` combined with a generator) incur significant overhead because of generator creation on each iteration.
**Action:** Unroll Pythonic constructs like `any()` into explicit `for` loops in hot paths to speed up execution.
