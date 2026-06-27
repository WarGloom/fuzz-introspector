
## 2025-05-18 - Python String Concatenation in Calltree Extracts
**Learning:** O(N^2) string concatenation (`+=`) was found to be a severe bottleneck in `calltree_analysis.py` functions like `create_fuzz_blocker_table` and `create_branch_blocker_table`. Appending multiple times directly to the output string makes python constantly allocate memory.
**Action:** Replace `string += string` in deep recursive or looping functions with `list.append()` and `"".join(list)`. This reduces GC overhead and speeds up string generation.
