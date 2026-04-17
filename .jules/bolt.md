## 2024-03-24 - O(N^2) Iteration via Loop-based Membership Lookups
**Learning:** During analysis of large fuzzer profiles, building a temporary list and relying on an inner `if key not in list` for duplicates causes severe O(N^2) behavior due to $O(N)$ operations for list checks inside an outer $O(N)$ loop.
**Action:** Always utilize a `set` for duplicate/membership tracking inside aggregation loops to transform membership lookups from O(N) to O(1), restoring linear O(N) traversal.
## 2024-03-24 - O(N^2) Iteration via Loop-based Membership Lookups
**Learning:** During analysis of large fuzzer profiles, building a temporary list and relying on an inner `if key not in list` for duplicates causes severe O(N^2) behavior due to $O(N)$ operations for list checks inside an outer $O(N)$ loop.
**Action:** Always utilize a `set` for duplicate/membership tracking inside aggregation loops to transform membership lookups from O(N) to O(1), restoring linear O(N) traversal.
