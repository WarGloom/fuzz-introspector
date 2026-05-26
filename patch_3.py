with open("src/fuzz_introspector/frontends/oss_fuzz.py", "r") as f:
    content = f.read()

content = content.replace("""        dirnames[:] = [
            d for d in dirnames if not any(exclude in d for exclude in EXCLUDE_DIRECTORIES)
        ]""", """        dirnames[:] = [
            d for d in dirnames
            if not any(exclude in d for exclude in EXCLUDE_DIRECTORIES)
        ]""")

with open("src/fuzz_introspector/frontends/oss_fuzz.py", "w") as f:
    f.write(content)
