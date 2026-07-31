## 2024-05-18 - [Optimizing HTML Generation Memory Overhead]
**Learning:** Found O(N^2) string concatenation using `+=` inside large loops in `src/fuzz_introspector/analyses/calltree_analysis.py` causing significant memory reallocation overhead when generating long calltree HTML pages.
**Action:** Replaced string accumulation with `list.append()` followed by `"".join(list)`. Next time, pre-emptively search for large scale string concatenations in HTML generating functions.
