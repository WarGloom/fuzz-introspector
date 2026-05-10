import time
import os
import pathlib

filenames = [f"file{i}.cpp" for i in range(1000)] + [f"file{i}.h" for i in range(1000)]

def test_pathlib():
    start = time.time()
    count = 0
    for _ in range(1000):
        for filename in filenames:
            if pathlib.Path(filename).suffix in ['.cpp', '.c', '.h']:
                count += 1
    end = time.time()
    print(f"pathlib.Path: {end - start:.4f}s")

def test_splitext():
    start = time.time()
    count = 0
    for _ in range(1000):
        for filename in filenames:
            if os.path.splitext(filename)[1] in ['.cpp', '.c', '.h']:
                count += 1
    end = time.time()
    print(f"os.path.splitext: {end - start:.4f}s")

def test_endswith():
    start = time.time()
    count = 0
    exts = ('.cpp', '.c', '.h')
    for _ in range(1000):
        for filename in filenames:
            if filename.endswith(exts):
                count += 1
    end = time.time()
    print(f"endswith(tuple): {end - start:.4f}s")

test_pathlib()
test_splitext()
test_endswith()
