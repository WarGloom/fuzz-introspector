#!/usr/bin/env bash
set -euo pipefail

if [[ "${SKIP_CHANGED_HOOK:-0}" == "1" ]]; then
  exit 0
fi

cd "$(git rev-parse --show-toplevel)"

staged_changes=$(git diff --cached --name-only --diff-filter=ACMRTUB || true)
unstaged_changes=$(git diff --name-only --diff-filter=ACMRTUB || true)
changed_files=$(printf "%s\n%s" "$staged_changes" "$unstaged_changes" | sed '/^$/d' | sort -u)

if [[ -z "$changed_files" ]]; then
  echo "No changed files to lint."
  exit 0
fi

mapfile -t changed_file_list < <(printf '%s\n' "$changed_files" | sed '/^$/d')

py_files=()
for changed_file in "${changed_file_list[@]}"; do
  case "$changed_file" in
    *.py|*.PY)
      py_files+=("$changed_file")
      ;;
  esac
done

if [[ ${#py_files[@]} -eq 0 ]]; then
  echo "No Python files changed; skipping flake8/yapf checks."
  exit 0
fi

flake8_args=("--jobs=1" "--ignore" "E125,W503,W504,W605" "--max-line-length" "100")
flake8_args+=("${py_files[@]}")

echo "Running flake8 on ${#py_files[@]} changed Python file(s)."
if ! flake8 "${flake8_args[@]}"; then
  echo "flake8 detected issues on changed files."
  exit 1
fi

echo "Running yapf format checks on ${#py_files[@]} changed Python file(s)."
if ! yapf -d "${py_files[@]}"; then
  echo "yapf detected formatting issues on changed files."
  exit 1
fi

echo "Changed-file hook checks passed."
