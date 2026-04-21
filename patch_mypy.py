with open('src/fuzz_introspector/analysis.py', 'r') as f:
    content = f.read()

content = content.replace('source_extensions = (".java"', 'source_extensions: tuple[str, ...] = (".java"')

with open('src/fuzz_introspector/analysis.py', 'w') as f:
    f.write(content)
