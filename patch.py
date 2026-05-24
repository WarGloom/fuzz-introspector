import sys
content = open("src/fuzz_introspector/frontends/oss_fuzz.py").read()
old_str = """    language_extensions = constants.LANGUAGE_EXTENSIONS.get(
        language.lower(), [])

    for dirpath, _, filenames in os.walk(directory_tree):
        # Skip some non project directories
        if any(exclude in dirpath for exclude in EXCLUDE_DIRECTORIES):
            continue

        for filename in filenames:
            if pathlib.Path(filename).suffix in language_extensions:
                language_files.append(os.path.join(dirpath, filename))"""
new_str = """    language_extensions = constants.LANGUAGE_EXTENSIONS.get(
        language.lower(), [])
    # Performance Optimization: Replaced pathlib.Path with string endswith for faster suffix extraction in hot loop
    language_extensions_tuple = tuple(language_extensions)

    for dirpath, _, filenames in os.walk(directory_tree):
        # Skip some non project directories
        if any(exclude in dirpath for exclude in EXCLUDE_DIRECTORIES):
            continue

        for filename in filenames:
            if filename.endswith(language_extensions_tuple):
                language_files.append(os.path.join(dirpath, filename))"""
if old_str in content:
    open("src/fuzz_introspector/frontends/oss_fuzz.py", "w").write(content.replace(old_str, new_str))
    print("Patched successfully")
else:
    print("String not found")
