# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Modules: discovery, metadata, dependency order and the step runner. A module file is only ever sourced inside a
# subshell, so its variables and functions never leak into the core or into another module.
#
# MOD_REQUIRES entries are module names; "a|b|c" means one of them (the first one is chosen if none is installed or
# requested).

LSS_MODULE_DIRS=${LSS_MODULE_DIRS:-}

_module_dirs() {
	if [[ -n ${LSS_MODULE_DIRS} ]]; then
		printf '%s\n' "${LSS_MODULE_DIRS}"
	else
		printf '%s/modules\n' "${LSS_ROOT}"
	fi
}

module_file() {
	local name=$1 dir file
	[[ ${name} =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
	while IFS= read -r dir; do
		for file in "${dir}"/*/"${name}.sh"; do
			if [[ -f ${file} ]]; then
				printf '%s' "${file}"
				return 0
			fi
		done
	done < <(_module_dirs)
	return 1
}

module_exists() {
	module_file "$1" >/dev/null
}

# module_list: all module names, sorted by group then name ("group name" per line with --groups).
module_list() {
	local dir file group
	while IFS= read -r dir; do
		for file in "${dir}"/*/*.sh; do
			[[ -f ${file} ]] || continue
			group=$(basename "$(dirname "${file}")")
			if [[ ${1:-} == --groups ]]; then
				printf '%s %s\n' "${group}" "$(basename "${file}" .sh)"
			else
				printf '%s\n' "$(basename "${file}" .sh)"
			fi
		done
	done < <(_module_dirs) | sort -u
}

# module_meta NAME VAR: prints a metadata variable of a module.
module_meta() {
	local file
	file=$(module_file "$1") || die "Unknown module '$1'. See 'lss list'."
	(
		# shellcheck source=/dev/null
		source "${file}"
		printf '%s' "${!2-}"
	)
}

# Resolves an alternative "a|b|c" against the requested set and installed modules.
_module_pick() {
	local alternatives=$1 requested=$2 choice
	IFS='|' read -ra choices <<<"${alternatives}"
	for choice in "${choices[@]}"; do
		if [[ " ${requested} " == *" ${choice} "* ]] || state_installed "${choice}"; then
			printf '%s' "${choice}"
			return 0
		fi
	done
	printf '%s' "${choices[0]}"
}

# module_resolve NAME...: prints the modules to run, requirements first. Fails on unknown modules, cycles and
# conflicts (with each other or with installed modules).
module_resolve() {
	local -a order=()
	local -A visiting=() done_=()
	local requested=" $* "
	local name

	_visit() {
		local module=$1 requirement picked
		[[ -n ${done_[${module}]+x} ]] && return 0
		[[ -z ${visiting[${module}]+x} ]] || die "Dependency cycle involving '${module}'."
		module_exists "${module}" || die "Unknown module '${module}'. See 'lss list'."
		visiting[${module}]=1
		for requirement in $(module_meta "${module}" MOD_REQUIRES); do
			picked=$(_module_pick "${requirement}" "${requested}")
			requested+="${picked} "
			_visit "${picked}"
		done
		unset 'visiting[${module}]'
		done_[${module}]=1
		order+=("${module}")
	}

	for name in "$@"; do
		_visit "${name}"
	done

	local module conflict
	for module in "${order[@]}"; do
		for conflict in $(module_meta "${module}" MOD_CONFLICTS); do
			if [[ " ${order[*]} " == *" ${conflict} "* ]]; then
				die "Modules '${module}' and '${conflict}' cannot be installed together."
			fi
			if state_installed "${conflict}"; then
				die "Module '${module}' conflicts with the installed module '${conflict}'. Remove it first (lss remove ${conflict})."
			fi
		done
	done
	printf '%s\n' "${order[@]}"
}

# module_mode NAME: native or docker, from LSS_<MODULE>_MODE, then --mode, limited to MOD_MODES.
module_mode() {
	local name=$1 modes wanted
	modes=$(module_meta "${name}" MOD_MODES)
	modes=${modes:-native}
	wanted=$(config_option "${name}" mode "$(config_get LSS_MODE native)")
	if [[ " ${modes} " == *" ${wanted} "* ]]; then
		printf '%s' "${wanted}"
	else
		printf '%s' "${modes%% *}"
	fi
}

# module_run NAME STEP: runs mod_STEP of the module in a subshell. Returns the step's exit status.
#
# The subshell is started asynchronously and then awaited. Callers use module_run in conditions (if !, ||), and
# bash ignores set -e for everything inside such a condition, even inside a subshell; an asynchronous subshell is
# not part of the condition, so a failing command in a module always stops that step.
module_run() {
	local name=$1 step=$2 file pid
	file=$(module_file "${name}") || die "Unknown module '${name}'."
	(
		set -Eeuo pipefail
		LSS_MODULE=${name}
		LSS_MODULE_MODE=$(module_mode "${name}")
		export LSS_MODULE LSS_MODULE_MODE
		trap 'log_error "${LSS_MODULE}: ${step} failed at ${BASH_SOURCE[0]##*/}:${LINENO}: ${BASH_COMMAND}"' ERR
		# shellcheck source=/dev/null
		source "${file}"
		declare -F "mod_${step}" >/dev/null || exit 0
		"mod_${step}"
	) <&0 &
	pid=$!
	wait "${pid}"
}

# module_apply NAME: install, configure and verify one module; restores its files on failure.
module_apply() {
	local name=$1 changes
	log_step "${name}"
	if ! module_run "${name}" install || ! module_run "${name}" configure; then
		LSS_MODULE=${name} files_restore
		state_set "${name}" status failed
		die "${name}: installation failed; changed files were restored. Details: ${LSS_LOG_FILE:-journalctl -t lss}"
	fi
	if ! module_run "${name}" verify; then
		LSS_MODULE=${name} files_restore
		state_set "${name}" status failed
		die "${name}: verification failed; changed files were restored. Details: ${LSS_LOG_FILE:-journalctl -t lss}"
	fi
	changes=$(files_changes_of "${name}")
	state_set "${name}" status installed
	state_set "${name}" mode "$(module_mode "${name}")"
	state_set "${name}" version "${LSS_VERSION}"
	state_set "${name}" updated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	if [[ -z $(state_get "${name}" installed_at) ]]; then
		state_set "${name}" installed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	fi
	if [[ ${changes} == 0 ]]; then
		log_ok "${name}: unchanged"
	else
		log_ok "${name}: done (${changes} changes)"
	fi
}

module_remove() {
	local name=$1 dependent
	for dependent in $(state_installed_modules); do
		[[ ${dependent} != "${name}" ]] || continue
		module_exists "${dependent}" || continue
		if [[ " $(module_meta "${dependent}" MOD_REQUIRES | tr '|' ' ') " == *" ${name} "* ]]; then
			die "Cannot remove '${name}': the installed module '${dependent}' needs it."
		fi
	done
	log_step "Removing ${name}"
	module_run "${name}" remove || die "${name}: removal failed. Details: ${LSS_LOG_FILE:-journalctl -t lss}"
	LSS_MODULE=${name} fw_remove_module
	files_forget "${name}"
	state_forget "${name}"
	log_ok "${name}: removed"
}
