## 2024-05-18 - Replacing string concatenations in HTML generation
**Learning:** Repetitive string concatenations using `+=` inside loops (such as generating large HTML blocks) cause significant memory reallocation overhead. Using list accumulation (`list.append()`) followed by `"".join(list)` is significantly faster and more memory efficient in Python, especially for large HTML documents.
**Action:** Always prefer `list.append()` and `"".join(list)` for building large strings in Python, especially when the strings are built iteratively in loops.
