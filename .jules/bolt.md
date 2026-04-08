## 2024-05-24 - [Avoid List Lookups in Sinks Analyser]
**Learning:** Checking for elements in a constantly expanding list in Python via `in` checks scales to $O(N^2)$ inside loops parsing large ASTs or coverage traces, such as `_retrieve_data_list`.
**Action:** Use an auxiliary `set()` to cache seen keys during the iteration, turning the $O(N)$ linear list lookup into an $O(1)$ constant time lookup, thereby dropping the overall scaling back to $O(N)$.
