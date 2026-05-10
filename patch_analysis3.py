import os

filepath = 'src/fuzz_introspector/analysis.py'
with open(filepath, 'r') as f:
    content = f.read()

content = content.replace("source_extensions: tuple[str, ...] = (\".java\", \".scala\", \".sc\", \".groovy\", \".kt\",\n                             \".kts\")", "source_extensions: tuple[str, ...] = (\".java\", \".scala\", \".sc\", \".groovy\", \".kt\", \".kts\")")


with open(filepath, 'w') as f:
    f.write(content)
