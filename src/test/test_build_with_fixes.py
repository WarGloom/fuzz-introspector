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
"""Regression tests for ``oss_fuzz_integration/build_with_fixes.sh``."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import textwrap

_RUST_TOOL_DIRS = [
    "native_yaml_loader_rust",
    "native_llvm_cov_loader_rust",
    "native_debug_correlator_rust",
    "native_overlay_backend_rust",
    "native_analysis_plugins_rust",
    "native_reachability_rust",
    "native_filter_functions_rust",
    "native_calltree_bitmap_rust",
]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _prepare_fake_repo(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "src").mkdir()
    (repo_root / "frontends").mkdir()
    (repo_root / "requirements.txt").write_text("pytest\n", encoding="utf-8")

    script_src = (Path(__file__).resolve().parents[2] /
                  "oss_fuzz_integration" / "build_with_fixes.sh")
    script_dst = repo_root / "oss_fuzz_integration" / "build_with_fixes.sh"
    script_dst.parent.mkdir()
    shutil.copy2(script_src, script_dst)
    script_dst.chmod(0o755)

    oss_fuzz_dir = repo_root / "oss_fuzz_integration" / "oss-fuzz"
    base_builder = oss_fuzz_dir / "infra" / "base-images" / "base-builder"
    base_builder.mkdir(parents=True)
    (base_builder / "Dockerfile").write_text(
        'FROM ubuntu:24.04\nCMD ["compile"]\n', encoding="utf-8")
    (base_builder / "compile").write_text(
        textwrap.dedent("""\
        #!/bin/sh
        python3 -m pip install --prefer-binary matplotlib
        python3 -m pip install -e .
        """),
        encoding="utf-8",
    )

    tools_dir = repo_root / "tools"
    tools_dir.mkdir()
    for tool_dir in _RUST_TOOL_DIRS:
        tool_root = tools_dir / tool_dir
        tool_root.mkdir()
        (tool_root / "README.md").write_text(f"# {tool_dir}\n",
                                             encoding="utf-8")
        target_dir = tool_root / "target"
        target_dir.mkdir()
        (target_dir / "artifact").write_text("compiled", encoding="utf-8")

    return repo_root


def _prepare_fake_bin(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    _write_executable(
        bin_dir / "git",
        textwrap.dedent("""\
        #!/bin/sh
        case "$1" in
          diff) exit 0 ;;
          pull) exit 0 ;;
          stash) exit 0 ;;
          *) exit 0 ;;
        esac
        """),
    )
    _write_executable(
        bin_dir / "podman",
        textwrap.dedent("""\
        #!/bin/sh
        case "$1" in
          images)
            printf '%s\n' \
              'gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04' \
              'gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04'
            exit 0
            ;;
          *) exit 0 ;;
        esac
        """),
    )
    _write_executable(
        bin_dir / "rsync",
        textwrap.dedent("""\
        #!/usr/bin/env python3
        import pathlib
        import shutil
        import sys

        src = pathlib.Path(sys.argv[-2])
        dst = pathlib.Path(sys.argv[-1])
        dst.mkdir(parents=True, exist_ok=True)
        for child in src.iterdir():
            target = dst / child.name
            if child.is_dir():
                shutil.copytree(child, target, dirs_exist_ok=True)
            else:
                shutil.copy2(child, target)
        """),
    )
    return bin_dir


def test_build_with_fixes_copies_and_wires_rust_native_backends(
        tmp_path: Path) -> None:
    repo_root = _prepare_fake_repo(tmp_path)
    fake_bin = _prepare_fake_bin(tmp_path)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["IMAGE_TAG"] = "ubuntu-24-04"

    subprocess.run(
        [
            "bash",
            str(repo_root / "oss_fuzz_integration" / "build_with_fixes.sh")
        ],
        cwd=repo_root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    copied_tools = (repo_root / "oss_fuzz_integration" / "oss-fuzz" / "infra" /
                    "base-images" / "base-builder" / "fuzz-introspector" /
                    "tools")
    for tool_dir in _RUST_TOOL_DIRS:
        assert (copied_tools / tool_dir).is_dir()
        assert not (copied_tools / tool_dir / "target").exists()

    dockerfile = (repo_root / "oss_fuzz_integration" / "oss-fuzz" / "infra" /
                  "base-images" / "base-builder" /
                  "Dockerfile").read_text(encoding="utf-8")
    assert "native_analysis_plugins_rust" in dockerfile
    assert "native_reachability_rust" in dockerfile
    assert "native_filter_functions_rust" in dockerfile
    assert "native_calltree_bitmap_rust" in dockerfile
    assert "https://sh.rustup.rs" not in dockerfile
    assert "sha256sum -c -" in dockerfile
    assert (
        "FI_IF_DEBUG_CORRELATOR_RUST_BIN=/opt/fuzz-introspector/bin/native_debug_correlator_rust"
        in dockerfile)
    assert (
        "FI_IF_DEBUG_CORRELATOR_BIN=/opt/fuzz-introspector/bin/native_debug_correlator_rust"
        in dockerfile)
    assert (
        "FI_REACHABILITY_RUST_BIN=/opt/fuzz-introspector/bin/native_reachability_rust"
        in dockerfile)
    assert (
        "FI_FILTER_RUST_BIN=/opt/fuzz-introspector/bin/native_filter_functions_rust"
        in dockerfile)
    assert (
        "FI_CALLTREE_BITMAP_RUST_BIN=/opt/fuzz-introspector/bin/native_calltree_bitmap_rust"
        in dockerfile)
    assert "FI_NATIVE_BACKENDS=rust" in dockerfile
    assert "native_" + "go" not in dockerfile
