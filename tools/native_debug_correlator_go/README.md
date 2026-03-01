# native_debug_correlator_go

Go CLI for debug type/function correlation using the same metadata-only
stdin/stdout contract as `native_debug_correlator_rust`.

## Build

```bash
cd tools/native_debug_correlator_go
go build
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
- `debug_types_paths` (preferred): YAML/JSON/NDJSON files for debug types.
- `debug_functions_paths` (preferred): YAML/JSON/NDJSON files for debug functions.
- `debug_types` (compatibility): inline array alternative.
- `debug_functions` (compatibility): inline array alternative.
- `output_dir` (required unless `out_dir` is provided): destination for correlated NDJSON shards.
- `shard_size` (optional): records per shard, default `5000`.
- `dump_files` (optional): defaults to `true`; emits `all-friendly-debug-types.json`.
- `out_dir` (optional): compatibility output location; also accepted as fallback output dir.

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
    "updated_functions": 9,
    "correlated_functions": 9,
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

## Correlated NDJSON shard records

Records are not returned on stdout; they are written to shard files:

```json
{
  "row_idx": 12,
  "func_signature_elems": {
    "return_type": ["DW_TAG_base_type", "int"],
    "params": [["DW_TAG_pointer_type", "DW_TAG_base_type", "char"]]
  },
  "source": {
    "source_file": "src/foo.c",
    "source_line": "42"
  }
}
```

Function dedupe semantics match the Rust/Python behavior:
- all empty `file_location` entries are preserved;
- for non-empty `file_location`, only the latest record per key is kept.

