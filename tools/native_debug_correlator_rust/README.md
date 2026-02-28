# native_debug_correlator_rust

Rust CLI for debug type/function correlation using stdin/stdout JSON protocol.

## Build

```bash
cd tools/native_debug_correlator_rust
cargo build --release
```

## Protocol

Input JSON (stdin):

```json
{
  "schema_version": 1,
  "debug_types_paths": ["/tmp/a.data.debug_all_types"],
  "debug_functions_paths": ["/tmp/a.data.debug_all_functions"],
  "output_dir": "/tmp/fi-correlated",
  "shard_size": 5000,
  "dump_files": true,
  "out_dir": "/tmp/fi-compatible"
}
```

- `schema_version` (required): echoed in output.
- `debug_types_paths` (required): YAML/JSON files containing debug type records.
- `debug_functions_paths` (required): YAML/JSON files containing debug function records.
- `output_dir` (required unless `out_dir` is provided): destination for correlated NDJSON shards.
- `shard_size` (optional): records per shard, default `5000`.
- `dump_files` (optional): when `true`, emits `all-friendly-debug-types.json`.
- `out_dir` (optional): compatibility output location for `all-friendly-debug-types.json`.

Output JSON (stdout, metadata only):

```json
{
  "schema_version": 1,
  "status": "success",
  "counters": {
    "parsed_types": 22,
    "parsed_functions": 9,
    "deduped_functions": 9,
    "written_records": 9,
    "shards": 1
  },
  "artifacts": {
    "correlated_shards": [
      "/tmp/fi-correlated/correlated-debug-00000.ndjson"
    ],
    "all_friendly_debug_types": "/tmp/fi-compatible/all-friendly-debug-types.json"
  },
  "timings": {
    "parse_ms": 10,
    "dedupe_ms": 0,
    "correlate_ms": 1,
    "write_ms": 2,
    "total_ms": 13
  }
}
```

Error output uses `status: "error"` and includes `reason_code`.

Compatibility input mode:
- The tool prefers `debug_types_paths` / `debug_functions_paths`.
- It also accepts inlined `debug_types` / `debug_functions` arrays for
  compatibility/testing, but path mode is preferred to avoid large IPC payloads.

## Notes

- Correlated records are not returned on stdout; they are streamed to sharded NDJSON files.
- Correlated record schema includes at least `row_idx`, `func_signature_elems`, and `source`.
- Function dedupe follows Python semantics: keep all empty `file_location`; for non-empty values keep latest entry per key.
