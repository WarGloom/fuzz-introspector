## 2024-05-20 - HTML String Concatenation Bottleneck
**Learning:** Repetitive string concatenation using `+=` inside loops (especially during HTML report generation in `calltree_analysis.py`) creates significant O(N^2) memory reallocation bottlenecks in Python.
**Action:** Always use list accumulation (`list.append()`) followed by `"".join(list)` instead for building large HTML strings.
