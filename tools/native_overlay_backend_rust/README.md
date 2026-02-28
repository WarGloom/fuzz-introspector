# native_overlay_backend_rust

Rust CLI for native calltree overlay and branch blocker computation.

## Build

```bash
cd tools/native_overlay_backend_rust
cargo build --release
```

## Protocol

Input JSON from `stdin`:

```json
{
  "schema_version": 1,
  "profile_id": "fuzzer",
  "output_dir": "/tmp/fi-overlay",
  "target_lang": "c-cpp",
  "target_coverage_url": "https://example/coverage",
  "callsites": [],
  "coverage": {
    "type": "function",
    "covmap": {},
    "file_map": {},
    "branch_cov_map": {}
  },
  "functions": {}
}
```

Output JSON to `stdout` (metadata-only):

```json
{
  "schema_version": 1,
  "status": "success",
  "counters": {
    "callsites": 10,
    "branch_complexities": 8,
    "branch_blockers": 2
  },
  "artifacts": {
    "overlay_nodes": "/tmp/fi-overlay/overlay_nodes.json",
    "branch_complexities": "/tmp/fi-overlay/branch_complexities.json",
    "branch_blockers": "/tmp/fi-overlay/branch_blockers.json"
  },
  "timings": {
    "total_ms": 0
  }
}
```

On failures the tool returns `status: "error"` and exits non-zero.
