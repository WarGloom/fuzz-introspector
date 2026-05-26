with open("src/fuzz_introspector/frontends/oss_fuzz.py", "r") as f:
    content = f.read()

content = content.replace("""            # Performance Optimization: Use string.endswith(tuple) instead of pathlib.Path(filename).suffix
            # for fast C-level matching, avoiding expensive object instantiation in a hot loop.""", """            # Performance Optimization: Use string.endswith(tuple) instead of
            # pathlib.Path(filename).suffix for fast C-level matching.""")

with open("src/fuzz_introspector/frontends/oss_fuzz.py", "w") as f:
    f.write(content)
