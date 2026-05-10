import os
import pathlib
import time

EXCLUDE_DIRECTORIES = {
    'node_modules', 'aflplusplus', 'honggfuzz', 'inspector', 'libfuzzer',
    'fuzztest', 'build'
}

def capture_source_files_in_tree_orig(directory_tree: str, language_extensions: list[str]) -> list[str]:
    language_files = []

    for dirpath, _, filenames in os.walk(directory_tree):
        if any(exclude in dirpath for exclude in EXCLUDE_DIRECTORIES):
            continue

        for filename in filenames:
            if pathlib.Path(filename).suffix in language_extensions:
                language_files.append(os.path.join(dirpath, filename))
    return language_files

def capture_source_files_in_tree_opt(directory_tree: str, language_extensions: list[str]) -> list[str]:
    language_files = []
    language_ext_tuple = tuple(language_extensions)

    for dirpath, dirnames, filenames in os.walk(directory_tree):
        excluded = False
        for exclude in EXCLUDE_DIRECTORIES:
            if exclude in dirpath:
                excluded = True
                break
        if excluded:
            # Prevent os.walk from descending into this directory structure at all
            dirnames[:] = []
            continue

        for filename in filenames:
            if filename.endswith(language_ext_tuple):
                language_files.append(os.path.join(dirpath, filename))
    return language_files

# Create a clean directory structure
os.makedirs("test_tree_2/src/main", exist_ok=True)
os.makedirs("test_tree_2/build/bin", exist_ok=True)
os.makedirs("test_tree_2/node_modules/lib", exist_ok=True)
for i in range(100):
    with open(f"test_tree_2/src/main/file{i}.cpp", "w") as f: f.write("")
    with open(f"test_tree_2/src/main/file{i}.h", "w") as f: f.write("")
    with open(f"test_tree_2/build/bin/file{i}.cpp", "w") as f: f.write("")
    with open(f"test_tree_2/node_modules/lib/file{i}.cpp", "w") as f: f.write("")

exts = [".c", ".cpp", ".cc", ".c++", ".cxx", ".h", ".hpp", ".hh", ".hxx"]

start = time.time()
for _ in range(1000):
    res1 = capture_source_files_in_tree_orig("test_tree_2", exts)
end = time.time()
print(f"Original: {end - start:.4f}s (found {len(res1)})")

start = time.time()
for _ in range(1000):
    res2 = capture_source_files_in_tree_opt("test_tree_2", exts)
end = time.time()
print(f"Optimized: {end - start:.4f}s (found {len(res2)})")

assert res1 == res2
