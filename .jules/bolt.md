## 2024-05-30 - String Concatenation Optimization
**Learning:** In Python, repetitively concatenating HTML parts inside a loop using `+=` is significantly slower than adding each string part to an explicit list (e.g., `parts.append(html_string)`) and finishing with `"".join(parts)` due to string immutability in Python resulting in continuous O(N^2) memory reallocation operations.
**Action:** Always use `.append()` followed by `"".join()` to construct large HTML outputs iteratively.
