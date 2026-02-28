## 2025-01-28 - Optimize List Accumulation in Dictionaries
**Learning:** Manual pattern of `.get(key, [])` followed by appending and reassigning in Python is a performance bottleneck.
**Action:** Use `collections.defaultdict(list)` whenever accumulating values into a dictionary of lists (multimaps) for improved speed and cleaner code.
