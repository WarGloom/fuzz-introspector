import os

filepath = 'src/test/test_profile_accumulation.py'
with open(filepath, 'r') as f:
    content = f.read()

old_str1 = '''            f"{int(proj_profile.runtime_coverage.covmap.size) + "
            f"int(proj_profile.runtime_coverage.covmap.size)}")'''

new_str1 = '''            f"{int(proj_profile.runtime_coverage.covmap.size) + "
            f"int(proj_profile.runtime_coverage.covmap.size)}")'''

# This seems to be pre-existing. I will only fix my file's lint issues.
