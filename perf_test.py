import time
import os

EXCLUDE_DIRECTORIES = [
    'node_modules', 'aflplusplus', 'honggfuzz', 'inspector', 'libfuzzer',
    'fuzztest', 'build'
]

# Create some dummy dirpaths to test
paths = [
    '/usr/local/src/project/src/main',
    '/usr/local/src/project/node_modules/library/dist',
    '/usr/local/src/project/build/release/bin',
    '/usr/local/src/project/tests/fuzz',
    '/usr/local/src/project/docs',
    '/usr/local/src/project/libfuzzer/test',
    '/home/user/code/project/src',
    '/home/user/code/project/aflplusplus/out',
] * 100

def test_any():
    start = time.time()
    count = 0
    for _ in range(1000):
        for dirpath in paths:
            if any(exclude in dirpath for exclude in EXCLUDE_DIRECTORIES):
                count += 1
    end = time.time()
    print(f"any() with generator expression: {end - start:.4f}s")

def test_explicit_for():
    start = time.time()
    count = 0
    for _ in range(1000):
        for dirpath in paths:
            # explicit for loop
            excluded = False
            for exclude in EXCLUDE_DIRECTORIES:
                if exclude in dirpath:
                    excluded = True
                    break
            if excluded:
                count += 1
    end = time.time()
    print(f"explicit for loop: {end - start:.4f}s")

test_any()
test_explicit_for()
