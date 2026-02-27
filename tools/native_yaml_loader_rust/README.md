# native_yaml_loader_rust

Rust CLI backend for `FI_DEBUG_YAML_LOADER` and `FI_PROFILE_YAML_LOADER`.

## Build

```bash
cargo build --manifest-path tools/native_yaml_loader_rust/Cargo.toml --release
cp tools/native_yaml_loader_rust/target/release/native_yaml_loader_rust /tmp/native_yaml_loader_rust
```

## Protocol

Reads JSON from stdin and writes JSON to stdout.

- Profile mode input: `{"path": "/abs/path/file.yaml"}`
- Debug mode input: `{"paths": ["/abs/path/a.yaml", "/abs/path/b.yaml"], "category": "debug-info"}`

Outputs:

- Profile mode: parsed YAML value as JSON.
- Debug mode: `{"items": [...]}`.

Implementation note:

- Uses `yaml_serde` for YAML parsing and `serde_json` for JSON I/O.
- Per-file parse errors in debug mode are skipped and processing continues.
