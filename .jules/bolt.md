## 2024-10-27 - Replace recursion with iterative stack in AST traversal
**Learning:** Python function call overhead combined with recursion depth limits (`RecursionError`) can cause performance issues and crashes when traversing deeply nested `tree-sitter` AST structures. Replacing recursive AST node traversals with iterative approaches using `while stack:` loops eliminates this overhead and prevents depth-limit crashes.
**Action:** Always favor stack-based iterative loops over deep recursion when processing ASTs or large tree structures in Python.
