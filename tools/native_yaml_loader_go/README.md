# native_yaml_loader_go

Go CLI backend for `FI_DEBUG_YAML_LOADER` and `FI_PROFILE_YAML_LOADER`.

## Build

```bash
cd tools/native_yaml_loader_go
go build -o /tmp/native_yaml_loader_go .
```

## Protocol

Reads JSON from stdin and writes JSON to stdout.

- Profile mode input: `{"path": "/abs/path/file.yaml"}`
- Debug mode input: `{"paths": ["/abs/path/a.yaml", "/abs/path/b.yaml"], "category": "debug-info"}`

Outputs:

- Profile mode: parsed YAML value as JSON.
- Debug mode: `{"items": [...]}`.

Implementation note:

- Uses `gopkg.in/yaml.v3` for YAML parsing.
- Per-file parse failures in debug mode are skipped and processing continues.
