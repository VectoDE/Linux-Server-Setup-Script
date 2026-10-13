#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Runs one step of one module in a fresh bash process (started by module_run). A new process is the only way to
# guarantee that set -e applies: bash ignores errexit inside any function that is called from a condition (if, ||,
# &&), and that state is inherited by subshells, including asynchronous ones.
#
# Input (environment): LSS_ROOT, LSS_STEP_MODULE, LSS_STEP_NAME, LSS_STEP_FILE, LSS_STEP_CONTEXT (file with the
# settings of the calling lss process, written by module_run).

set -Eeuo pipefail
shopt -s inherit_errexit

for library in log os config files template secrets state pkg repo fetch service firewall web module; do
	# shellcheck source=/dev/null
	source "${LSS_ROOT}/lib/${library}.sh"
done
# shellcheck source=/dev/null
source "${LSS_STEP_CONTEXT}"

os_detect
LSS_MODULE=${LSS_STEP_MODULE}
LSS_MODULE_MODE=$(module_mode "${LSS_MODULE}")
export LSS_MODULE LSS_MODULE_MODE

trap 'log_error "${LSS_MODULE}: ${LSS_STEP_NAME} failed at ${BASH_SOURCE[0]##*/}:${LINENO}: ${BASH_COMMAND}"' ERR

# shellcheck source=/dev/null
source "${LSS_STEP_FILE}"
declare -F "mod_${LSS_STEP_NAME}" >/dev/null || exit 0
"mod_${LSS_STEP_NAME}"
