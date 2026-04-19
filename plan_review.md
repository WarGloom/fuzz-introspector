I plan to fix multiple O(N) performance bottlenecks in hot directory and file traversal paths across the project.

Specifically, I'll update generator expressions (`any(x in str for x in ...)` and `any(str.endswith(x) for x in ...)`) to use native functions where possible or standard explicit `for` loops with early returns which avoid generator instantiation overhead (a known Python bottleneck in hot loops). This includes converting source code extension lists to tuples to allow `str.endswith()` to naturally accept multiple arguments at C-speed, and expanding `str.startswith()` to multiple arguments at C-speed.

I will:
1. Update `src/fuzz_introspector/analysis.py`:
   - Change `source_extensions` lists to tuples.
   - Refactor `is_interesting_source_file` to use native `tuple` arguments for `endswith` and `startswith`. Replace the `any(...)` avoid checks with explicit loops.
   - Refactor `is_candidate_source` with the same changes.
   - Replace generator `any(...)` evaluations in deep `os.walk` directory structures such as filtering `dirs[:]`, checking inspirations, and handling samples with equivalent `for` loops and early `break`.

2. Update `src/fuzz_introspector/frontends/oss_fuzz.py`:
   - Change `capture_source_files_in_tree`'s directory exclusion `any(...)` generator loop into an explicit `for` loop with a break for speedups traversing large non-project directories.

3. Complete Pre-commit Steps:
   - Call `pre_commit_instructions` and execute linting, tests, and formatting exactly as required.

4. Submit:
   - Record PR information and merge using the `submit` tool.
