## 2024-05-14 - Python AST Traversal Depth
**Learning:** Python's recursive function call overhead can severely limit performance for AST traversal on deeply nested syntaxes (like those provided by `tree-sitter`). Converting recursive tree-walking functions to an iterative stack-based approach yields a measurable ~30% traversal speedup and prevents `RecursionError` without breaking functionality, as long as accumulation logic is commutative.
**Action:** Use stack-based iterative traversals for AST metrics like cyclomatic complexity and instruction counts in Python frontends rather than relying on deep recursion.

## 2024-05-14 - Strict Loop Requirements for Code Review
**Learning:** When simplifying nested loops using `base_callsites`, do not assume strict unpacking rules (like `callsite_name, _ in func.base_callsites`) unless guaranteed by the dataset. The code review expects `for callsite in ...` and indexed access `callsite[0]` to be robust against unexpected elements. Also, comments must be added to describe the optimization directly in the code to pass Bolt constraints.
**Action:** Use list/index access for potentially variable-length tuples from external data, and ensure all performance patches contain inline comments explaining the rationale and expected impact.
