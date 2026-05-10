import os

filepath = 'src/fuzz_introspector/frontends/oss_fuzz.py'
with open(filepath, 'r') as f:
    content = f.read()

content = content.replace("import yaml\nimport pathlib\nimport logging", "import yaml\nimport logging")

with open(filepath, 'w') as f:
    f.write(content)
