import timeit

setup = """
import pathlib
filenames = [f"test_{i}.c" for i in range(1000)] + [f"test_{i}.h" for i in range(1000)] + [f"test_{i}.txt" for i in range(1000)]
language_extensions = [".c", ".cpp", ".cc", ".c++", ".cxx", ".h", ".hpp", ".hh", ".hxx"]
language_ext_tuple = tuple(language_extensions)
"""

test_pathlib = """
res = []
for filename in filenames:
    if pathlib.Path(filename).suffix in language_extensions:
        res.append(filename)
"""

test_endswith = """
res = []
for filename in filenames:
    if filename.endswith(language_ext_tuple):
        res.append(filename)
"""

print("pathlib:", timeit.timeit(test_pathlib, setup=setup, number=1000))
print("endswith:", timeit.timeit(test_endswith, setup=setup, number=1000))
