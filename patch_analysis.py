import os

filepath = 'src/fuzz_introspector/analysis.py'
with open(filepath, 'r') as f:
    content = f.read()

content = content.replace("source_extensions = (\".java\", \".scala\", \".sc\", \".groovy\", \".kt\",\n                             \".kts\")", "source_extensions: tuple[str, ...] = (\".java\", \".scala\", \".sc\", \".groovy\", \".kt\",\n                             \".kts\")")

# For the other one
content = content.replace("        source_extensions = (\n            \".java\",\n            \".scala\",\n            \".sc\",\n            \".groovy\",\n            \".kt\",\n            \".kts\",\n        )", "        source_extensions: tuple[str, ...] = (\n            \".java\",\n            \".scala\",\n            \".sc\",\n            \".groovy\",\n            \".kt\",\n            \".kts\",\n        )")


with open(filepath, 'w') as f:
    f.write(content)
