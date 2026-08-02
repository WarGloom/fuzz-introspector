import os
import time

seed_directories = ["/a/b/c", "/d/e/f/", "/g/h", "/i/j/k/", "/l/m/n/o/p", "q/r/s"]
pre_scanned_files = ["/a/b/c/foo.txt", "/d/e/f/bar.txt", "/z/y/x.txt"] * 3000

def original(path):
    if not path:
        return False
    for directory in seed_directories:
        normalized_directory = os.path.normpath(directory)
        directory_prefix = (normalized_directory
                            if normalized_directory.endswith(os.sep) else
                            normalized_directory + os.sep)
        if path == normalized_directory or path.startswith(
                directory_prefix):
            return True
    return False

def optimized(path):
    if not path:
        return False
    for exact, prefix in precomputed:
        if path == exact or path.startswith(prefix):
            return True
    return False

# Precompute for optimized
precomputed = []
for directory in seed_directories:
    normalized_directory = os.path.normpath(directory)
    directory_prefix = (normalized_directory
                        if normalized_directory.endswith(os.sep) else
                        normalized_directory + os.sep)
    precomputed.append((normalized_directory, directory_prefix))

start = time.time()
for f in pre_scanned_files:
    original(f)
end = time.time()
print("original:", end - start)

start = time.time()
for f in pre_scanned_files:
    optimized(f)
end = time.time()
print("optimized:", end - start)
