# Copyright 2026 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Shared pytest configuration and fixtures for the fuzz-introspector test suite.

Policy: all test-generated output files must go to pytest tmp_path.
Never write to CWD or hardcoded paths such as /tmp.
"""

import pytest


@pytest.fixture
def work_tmp(tmp_path):
    """Return tmp_path as the canonical working directory for test output.

    Policy: all test output (generated files, reports, artefacts) must be
    written inside this directory.  Never use os.getcwd(), hardcoded '/tmp',
    or any path outside tmp_path for test-generated files.
    """
    return tmp_path
