#!/usr/bin/env bash
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

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
APP_DIR="${SCRIPT_DIR}/app"
DB_DIR="${APP_DIR}/static/assets/db"
VENV_DIR="${SCRIPT_DIR}/.venv"

BUILD_DB_MODE="skip"
DRY_RUN=false
PORT="${WEBAPP_PORT:-8080}"
PYTHON_BIN="${PYTHON_BIN:-python3.14}"
LOCAL_REPORT_SPECS=()

log() {
	printf '[start_webapp] %s\n' "$*" >&2
}

die() {
	log "ERROR: $*"
	exit 1
}

usage() {
	cat <<EOF
Usage: $(basename "$0") [options]

Start the local web-fuzzing-introspection app.

Options:
  --build-db MODE   Build the local DB before starting. MODE: skip|minor|full
                    Default: skip
  --local-report SPEC
                    Import a local report directory before starting.
                    Repeatable. Use PROJECT=DIR or just DIR.
  --port PORT       Port for the Flask app. Default: ${PORT}
  --python CMD      Python interpreter to use when creating the venv.
                    Default: ${PYTHON_BIN}
  --dry-run         Print the actions without executing them
  -h, --help        Show this help message

Environment:
  WEBAPP_PORT                    Overrides --port
  PYTHON_BIN                     Overrides --python
  FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ Passed through to the app if set
  G_ANALYTICS_TAG                Passed through to the app if set

Examples:
  $(basename "$0")
  $(basename "$0") --build-db minor
  $(basename "$0") --local-report myproj=/tmp/build-introspector-full
  $(basename "$0") --port 9090 --dry-run
EOF
}

run_cmd() {
	if [[ "${DRY_RUN}" == true ]]; then
		printf '[dry-run] ' >&2
		printf '%q ' "$@" >&2
		printf '\n' >&2
		return 0
	fi

	"$@"
}

require_path() {
	local path="$1"
	[[ -e "${path}" ]] || die "Required path not found: ${path}"
}

ensure_venv() {
	if [[ -x "${VENV_DIR}/bin/python" ]]; then
		return 0
	fi

	if command -v uv >/dev/null 2>&1; then
		log "Creating virtual environment with uv"
		run_cmd uv venv "${VENV_DIR}" --python "${PYTHON_BIN}"
		run_cmd uv pip install --python "${VENV_DIR}/bin/python" -r "${SCRIPT_DIR}/requirements.txt"
		return 0
	fi

	if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
		die "Missing both uv and ${PYTHON_BIN}; cannot create ${VENV_DIR}"
	fi

	log "Creating virtual environment with ${PYTHON_BIN}"
	run_cmd "${PYTHON_BIN}" -m venv "${VENV_DIR}"
	run_cmd "${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
}

ensure_dependencies() {
	if run_cmd "${VENV_DIR}/bin/python" -c "import flask, flask_smorest" >/dev/null 2>&1; then
		return 0
	fi

	if command -v uv >/dev/null 2>&1; then
		log "Installing webapp dependencies with uv"
		run_cmd uv pip install --python "${VENV_DIR}/bin/python" -r "${SCRIPT_DIR}/requirements.txt"
		return 0
	fi

	log "Installing webapp dependencies with pip"
	run_cmd "${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
}

build_db() {
	if [[ ${#LOCAL_REPORT_SPECS[@]} -gt 0 ]]; then
		local cmd=("${VENV_DIR}/bin/python" "./web_db_creator_from_summary.py")
		for report_spec in "${LOCAL_REPORT_SPECS[@]}"; do
			cmd+=("--local-report" "${report_spec}")
		done

		log "Importing local report directories into the webapp DB"
		if [[ "${DRY_RUN}" == true ]]; then
			log "Would run from ${DB_DIR}"
			run_cmd "${cmd[@]}"
		else
			(cd "${DB_DIR}" && "${cmd[@]}")
		fi
		return 0
	fi

	case "${BUILD_DB_MODE}" in
	skip)
		return 0
		;;
	minor)
		log "Building a small local DB snapshot"
		if [[ "${DRY_RUN}" == true ]]; then
			run_cmd bash -lc "cd \"${DB_DIR}\" && ./launch_minor_oss_fuzz.sh"
		else
			(cd "${DB_DIR}" && ./launch_minor_oss_fuzz.sh)
		fi
		;;
	full)
		log "Building the full local DB snapshot"
		if [[ "${DRY_RUN}" == true ]]; then
			run_cmd bash -lc "cd \"${DB_DIR}\" && ./launch_full_oss_fuzz.sh"
		else
			(cd "${DB_DIR}" && ./launch_full_oss_fuzz.sh)
		fi
		;;
	*)
		die "Unsupported --build-db mode: ${BUILD_DB_MODE}"
		;;
	esac
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--build-db)
		[[ $# -ge 2 ]] || die "--build-db requires a value"
		BUILD_DB_MODE="$2"
		shift 2
		;;
	--local-report)
		[[ $# -ge 2 ]] || die "--local-report requires a value"
		LOCAL_REPORT_SPECS+=("$2")
		shift 2
		;;
	--port)
		[[ $# -ge 2 ]] || die "--port requires a value"
		PORT="$2"
		shift 2
		;;
	--python)
		[[ $# -ge 2 ]] || die "--python requires a value"
		PYTHON_BIN="$2"
		shift 2
		;;
	--dry-run)
		DRY_RUN=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		die "Unknown argument: $1"
		;;
	esac
done

if [[ ${#LOCAL_REPORT_SPECS[@]} -gt 0 && "${BUILD_DB_MODE}" != "skip" ]]; then
	die "--local-report cannot be combined with --build-db"
fi

require_path "${APP_DIR}/main.py"
require_path "${SCRIPT_DIR}/requirements.txt"
require_path "${DB_DIR}"

ensure_venv
ensure_dependencies
build_db

if [[ -d "${DB_DIR}/db-projects" ]]; then
	log "Using existing local DB at ${DB_DIR}/db-projects"
else
	log "No local DB found at ${DB_DIR}/db-projects; run with --build-db minor or --build-db full if needed"
fi

export WEBAPP_PORT="${PORT}"

log "Starting webapp on port ${WEBAPP_PORT}"
if [[ "${DRY_RUN}" == true ]]; then
	run_cmd bash -lc "cd \"${APP_DIR}\" && exec \"${VENV_DIR}/bin/python\" ./main.py"
else
	cd "${APP_DIR}"
	exec "${VENV_DIR}/bin/python" ./main.py
fi
