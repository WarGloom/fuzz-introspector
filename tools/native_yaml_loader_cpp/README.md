# native_yaml_loader_cpp

C++ CLI backend for `FI_DEBUG_YAML_LOADER` and `FI_PROFILE_YAML_LOADER`.

## Build

```bash
g++ -std=c++17 -O2 -Wall -Wextra -pedantic \
  $(llvm-config --cxxflags) \
  tools/native_yaml_loader_cpp/main.cpp \
  $(llvm-config --ldflags --libs support) \
  -o /tmp/native_yaml_loader_cpp
```

## Protocol

Reads JSON from stdin and writes JSON to stdout.

- Profile mode input: `{"path": "/abs/path/file.yaml"}`
- Debug mode input: `{"paths": ["/abs/path/a.yaml", "/abs/path/b.yaml"], "category": "debug-info"}`

Outputs:

- Profile mode: parsed YAML value as JSON.
- Debug mode: `{"items": [...]}`.

Implementation note:

- Uses LLVM's YAML parser (`llvm/Support/YAMLParser.h`).
- Per-file parse errors in debug mode are skipped and processing continues.
