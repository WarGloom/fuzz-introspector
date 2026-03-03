
## 2024-05-01 - Avoid dict.setdefault for multimap construction
**Learning:** Using `dict.setdefault(key, []).append(...)` for accumulating values into a list (multimap) creates an empty list on every single iteration, even if the key already exists. In hot paths (like processing thousands of debug info entries), this constant allocation and garbage collection causes unnecessary performance overhead.
**Action:** Use `collections.defaultdict(list)` instead, which only allocates a new list when a key is genuinely missing.
