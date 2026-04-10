## 2024-05-24 - O(N^2) complexity in membership tests on large iteration collections
**Learning:** Checking for duplicate or existing elements via list membership `if x not in large_list` creates O(N^2) CPU bottlenecks during profile analysis iterations. Python's `set` changes this to O(1) and is crucial in `_retrieve_data_list` and `third_party_func_profile` which iterate over massive function collections.
**Action:** Always initialize and use `set()` objects (e.g., `seen_functions = set()`) for membership tracking within these loops to maintain O(N) overall complexity.
## 2024-05-24 - O(N^2) complexity in membership tests on large iteration collections
**Learning:** Checking for duplicate or existing elements via list membership `if x not in large_list` creates O(N^2) CPU bottlenecks during profile analysis iterations. Python's `set` changes this to O(1) and is crucial in `_retrieve_data_list` and `third_party_func_profile` which iterate over massive function collections.
**Action:** Always initialize and use `set()` objects (e.g., `seen_functions = set()`) for membership tracking within these loops to maintain O(N) overall complexity.
