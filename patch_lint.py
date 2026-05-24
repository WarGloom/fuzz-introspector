import sys
content = open("src/fuzz_introspector/frontends/oss_fuzz.py").read()
content = content.replace("import pathlib\n", "")
# Fix the long line by splitting the comment or moving it
# Line 47: # Performance Optimization: Replaced pathlib.Path with string endswith for faster suffix extraction in hot loop
old_comment = "    # Performance Optimization: Replaced pathlib.Path with string endswith for faster suffix extraction in hot loop"
new_comment = "    # Performance Optimization: Replaced pathlib.Path with string endswith for\n    # faster suffix extraction in hot loop"
content = content.replace(old_comment, new_comment)
open("src/fuzz_introspector/frontends/oss_fuzz.py", "w").write(content)
