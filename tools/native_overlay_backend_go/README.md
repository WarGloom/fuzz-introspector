# native_overlay_backend_go

Go implementation of the native overlay backend JSON protocol.

Current rollout safety policy: this backend runs in probe/shadow mode only.
Python overlay output remains authoritative until parity is fully verified.

## Build

```bash
cd tools/native_overlay_backend_go
go build -o native_overlay_backend_go .
```

## Usage

The tool reads request JSON from `stdin` and writes metadata-only response JSON
to `stdout`.

Artifacts are written under `output_dir`:

- `overlay_nodes.json`
- `branch_complexities.json`
- `branch_blockers.json`

Response fields are aligned with the Python overlay contract:

- `schema_version`
- `status`
- `counters`
- `artifacts`
- `timings`
