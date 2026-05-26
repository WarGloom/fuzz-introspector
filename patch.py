import re

with open("src/fuzz_introspector/frontends/oss_fuzz.py", "r") as f:
    content = f.read()

new_content = content.replace("""def capture_source_files_in_tree(directory_tree: str,
                                 language: str) -> list[str]:
    \"\"\"Captures source code files in a given directory.\"\"\"
    language_files = []
    language_extensions = constants.LANGUAGE_EXTENSIONS.get(
        language.lower(), [])

    for dirpath, _, filenames in os.walk(directory_tree):
        # Skip some non project directories
        if any(exclude in dirpath for exclude in EXCLUDE_DIRECTORIES):
            continue

        for filename in filenames:
            if pathlib.Path(filename).suffix in language_extensions:
                language_files.append(os.path.join(dirpath, filename))
    return language_files""", """def capture_source_files_in_tree(directory_tree: str,
                                 language: str) -> list[str]:
    \"\"\"Captures source code files in a given directory.\"\"\"
    language_files = []
    # Performance Optimization: Convert to tuple for fast endswith checking
    language_extensions = tuple(constants.LANGUAGE_EXTENSIONS.get(
        language.lower(), []))

    for dirpath, dirnames, filenames in os.walk(directory_tree):
        # Performance Optimization: Modify dirnames in-place to prevent os.walk from
        # descending into excluded directories, saving substantial I/O overhead.
        dirnames[:] = [
            d for d in dirnames
            if not any(exclude in d for exclude in EXCLUDE_DIRECTORIES)
        ]

        # Skip some non project directories
        if any(exclude in dirpath for exclude in EXCLUDE_DIRECTORIES):
            continue

        for filename in filenames:
            # Performance Optimization: Use string.endswith(tuple) instead of pathlib.Path(filename).suffix
            # for fast C-level matching, avoiding expensive object instantiation in a hot loop.
            if filename.endswith(language_extensions):
                language_files.append(os.path.join(dirpath, filename))
    return language_files""")

with open("src/fuzz_introspector/frontends/oss_fuzz.py", "w") as f:
    f.write(new_content)
