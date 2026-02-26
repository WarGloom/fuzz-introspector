# native_debug_loader_go

Go CLI implementation for `FI_DEBUG_NATIVE_LOADER_CMD` payloads used by
`fuzz_introspector.debug_info.load_debug_report`.

## What it does

- Accepts debug files from LLVM text debug dumps.
- Parses:
  - compile units,
  - functions section,
  - global variables,
  - types.
- Deduplicates repeated files by content hash.
- Prints JSON to stdout with required keys:
  - `all_files_in_project`
  - `all_functions_in_project`
  - `all_global_variables`
  - `all_types`

## Build

```bash
cd tools/native_debug_loader_go
go build
```

## CLI usage

```bash
native_debug_loader_go [--base-dir <path>] <debug_files...>
```

Examples:

```bash
# Option before files
./native_debug_loader_go --base-dir /work/debug-root a.debug b.debug

# Option after files (compatible with current Python invocation order)
./native_debug_loader_go a.debug b.debug --base-dir /work/debug-root
```

## Fuzz Introspector environment wiring

```bash
export FI_DEBUG_NATIVE_LOADER=go
export FI_DEBUG_NATIVE_LOADER_CMD="/tmp/fuzz-introspector-research/tools/native_debug_loader_go/native_debug_loader_go"
```

Then run Fuzz Introspector normally; `load_debug_report` invokes the configured
command and reads its stdout JSON payload.
