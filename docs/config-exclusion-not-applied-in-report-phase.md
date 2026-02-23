# Bug: fuzz_introspector_config.conf Exclusions Not Applied in Report Phase

## Summary

The `fuzz_introspector_config.conf` configuration file (specifically `FILES_TO_AVOID` patterns) is only applied during the LLVM instrumentation phase (Step 1: introspector build), but not during the report generation phase (Step 6). This causes the report phase to waste significant time scanning and processing files that were intentionally excluded from instrumentation, such as third-party dependencies in `_deps`, `build`, `vendor`, etc.

## Problem Description

### Configuration Scope Mismatch

1. **Build Phase (Step 1)**: The LLVM FuzzIntrospector pass reads `FUZZ_INTROSPECTOR_CONFIG` and respects `FILES_TO_AVOID` patterns. Files matching these patterns are **not instrumented**, resulting in smaller, faster builds and fewer fuzzer data files.

2. **Report Phase (Step 6)**: The `main.py report` command invokes `extract_tests_from_directories` in `html_report.py` / `analysis.py`. This code path **does not read or respect** the configuration file. It unconditionally walks the entire source tree, including:
   - `_deps/` (CMake fetchcontent dependencies)
   - `build*/` (build directories)
   - `vendor/` ( vendored dependencies)
   - `/usr/include/` (system headers)
   - Any other directory under the target source path

### Observed Impact

In the cgserver project smoke test:

- Step 1 (introspector build): ~49 fuzzer data files generated (correct, excludes dependencies)
- Step 6 (report): Process scans ~582k files under `/src` and ~74k files under `_deps`, causing:
  - Excessive CPU time in `extract_tests_from_directories` / `is_non_fuzz_harness`
  - Full file reads on every `.cpp`/`.c` file to detect test harnesses
  - Report generation taking 10x longer than necessary
  - Memory exhaustion on large codebases

### Root Cause

The report phase's source scanning logic in `analysis.py:extract_tests_from_directories` does not accept or process exclusion patterns. The configuration loading and pattern matching is only implemented in the LLVM pass (`frontends/llvm/lib/Transforms/FuzzIntrospector/FuzzIntrospector.cpp`), not in the Python analysis code.

## Affected Code Locations

### Report Phase (Python)

- `src/fuzz_introspector/analysis.py`:
  - `extract_tests_from_directories()` - walks directories without filtering
  - `is_non_fuzz_harness()` - reads entire file content for detection

- `src/fuzz_introspector/html_report.py`:
  - `extract_test_information()` - invokes directory extraction

- `src/fuzz_introspector/commands.py`:
  - `create_html_report()` - calls analysis without passing exclusions

### Build Phase (LLVM Pass - Correct Implementation)

- `frontends/llvm/lib/Transforms/FuzzIntrospector/FuzzIntrospector.cpp`:
  - Loads `FUZZ_INTROSPECTOR_CONFIG`
  - Applies `FILES_TO_AVOID` patterns during instrumentation

## Suggested Fixes

### Option 1: Pass Exclusion Patterns to Report Command (Recommended)

Add a new CLI argument `--exclude-dirs` (or `--exclude-patterns`) to `main.py report` that accepts comma-separated patterns. Modify `analysis.py:extract_tests_from_directories` to skip directories matching these patterns.

```python
# In analysis.py
def extract_tests_from_directories(directories, exclude_patterns=None):
    if exclude_patterns:
        for pattern in exclude_patterns:
            if re.search(pattern, dirname):
                continue  # skip excluded
```

Usage:
```bash
python3 main.py report --exclude-dirs '_deps,build,vendor,/usr/include' ...
```

### Option 2: Have Report Phase Read Config File

Modify `commands.py` to load `FUZZ_INTROSPECTOR_CONFIG` and extract `FILES_TO_AVOID` patterns, then pass them to the analysis functions.

```python
def load_exclusion_patterns(config_path):
    # Parse config file, extract FILES_TO_AVOID patterns
    return patterns
```

### Option 3: Cap File Reads in Harness Detection

To mitigate both config-aware and config-agnostic scanning overhead, modify `is_non_fuzz_harness` to read only the first N bytes:

```python
MAX_READ_BYTES = 64 * 1024  # 64 KB

def is_non_fuzz_harness(filepath):
    with open(filepath, 'rb') as f:
        content = f.read(MAX_READ_BYTES)
    # ... detection logic
```

### Option 4: Add Progress Logging to Scan Phase

Add periodic logging during directory traversal so long scans are observable:

```python
def extract_tests_from_directories(directories):
    file_count = 0
    for root, dirs, files in os.walk(directories):
        file_count += len(files)
        if file_count % 1000 == 0:
            logger.info(f"Scanned {file_count} files...")
```

## Verification

After fix, running the same smoke test should show:

- Step 6 completes significantly faster (exclude `_deps` etc.)
- Log should indicate skipped directories
- No difference in fuzzer data files (already correct)

## Impact Analysis: Excluding Directories from Report Phase

### What This Step Actually Does

The `extract_tests_from_directories` function (in `analysis.py:1155-1267`) performs two tasks:

1. **Test file discovery**: Scans source directories for test/example files to use as "inspiration" for fuzzing
2. **Source file copying**: Copies discovered test files to `source-code/` directory in output

### Files Generated

- `test-files.json` - list of discovered test files (only written if `dump_files=True`)
- `source-code/` directory - copies of test source files

### Impact on Report Results

**If we exclude `_deps`, `build`, `vendor` directories from this scan:**

| Report Component | Impact | Severity |
|-----------------|--------|----------|
| `fuzz_report.html` main UI | None | - |
| Function table (`all-fuzz-introspector-functions.json`) | None | - |
| Call tree visualizations | None | - |
| Coverage data | None | - |
| Optimal targets analysis | None | - |
| `test-files.json` | Missing test files from excluded dirs | Low |
| `source-code/` directory | Missing source copies from excluded dirs | Low |

### Why It Has Minimal Impact

1. **Fuzzer data already processed**: The core FI analysis (functions, call trees, coverage) uses the LLVM-generated `.data.yaml` files from Step 1 - these are unaffected.

2. **Third-party code not relevant for fuzzing insights**: `_deps`/vendor directories contain:
   - External libraries (boost, protobuf, etc.)
   - Already-compiled dependencies
   - Not useful as fuzzing "inspiration" targets

3. **Current hardcoded exclusions already skip much**: Look at `analysis.py:1195-1199`:
   ```python
   to_avoid = [
       'fuzztest', 'aflplusplus', 'libfuzzer', 'googletest', 'thirdparty',
       'third_party', '/build/', '/usr/local/', '/fuzz-introspector/',
       '/root/.cache/', '/usr/', '/tmp/', '/src/inspector'
   ]
   ```
   The function already avoids many external paths - but misses `_deps`, `build*`, `vendor`.

4. **`test-files.json` is optional metadata**: It's only written when `dump_files=True` and is not displayed in the main HTML report - it's a supplementary artifact.

### Conclusion

**Excluding `_deps`, `build`, `vendor` from the report phase will have:**

- **Zero impact** on the main fuzz-introspector analysis results (function reachability, call trees, optimal targets, coverage correlation)
- **Zero impact** on the HTML report UI
- **Minimal benefit**: faster report generation (avoid scanning 100k+ unnecessary files)
- **Low impact**: loss of optional `test-files.json` entries from third-party code (not useful for fuzzing anyway)

**Recommendation**: Safe to implement exclusion - the main FI analysis is completely independent of this source-scan phase.

## References

- Config file format: `.clusterfuzzlite/fuzz_introspector_config.conf`
- LLVM pass config handling: `frontends/llvm/lib/Transforms/FuzzIntrospector/FuzzIntrospector.cpp`
- Original bug report context: cgserver fuzz-introspector smoke test (2026-02-23)
