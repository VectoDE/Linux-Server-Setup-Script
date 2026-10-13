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
	return
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
	local name=$1
	module_file "${name}" >/dev/null
	return
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
	return
}

# module_meta NAME VAR: prints a metadata variable of a module. The final newline lets `while read` loops see the
# last line; command substitutions drop it.
module_meta() {
	local name=$1 file
	file=$(module_file "${name}") || die "Unknown module '${name}'. See 'lss list'."
	(
		# shellcheck source=/dev/null
		source "${file}"
		printf '%s\n' "${!2-}"
	)
	return
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
	return
}

# Variables handed to every module step (module_run). Settings, masks and paths; nothing else of the caller leaks.
LSS_CONTEXT_VARIABLES=(LSS_CFG_SET LSS_CFG_FILE LSS_CFG_PROFILE LSS_MASKED LSS_ROOT LSS_VERSION LSS_RUN_ID
	LSS_STATE_DIR LSS_SECRETS_DIR LSS_LOG_FILE LSS_JOURNAL LSS_COLOR LSS_VERBOSE LSS_DRY_RUN LSS_YES LSS_PURGE
	LSS_MODULE_DIRS LSS_OS_RELEASE LSS_ARCH)

# Writes the context of this process to a private file and prints its path.
_module_context() {
	local dir file variable
	dir="${LSS_STATE_DIR}/runs/${LSS_RUN_ID:?LSS_RUN_ID is not set}"
	mkdir -p "${dir}"
	chmod 700 "${dir}"
	file="${dir}/context"
	(
		umask 077
		local declaration flags
		for variable in "${LSS_CONTEXT_VARIABLES[@]}"; do
			declaration=$(declare -p "${variable}" 2>/dev/null) || continue
			# "declare -A NAME=(...)" becomes "declare -gA NAME=(...)", so it stays global when sourced in a function.
			flags=${declaration#declare -}
			flags=${flags%% *}
			printf 'declare -g%s %s\n' "${flags//-/}" "${declaration#declare -"${flags}" }"
		done >"${file}"
	)
	printf '%s' "${file}"
	return
}

# module_run NAME STEP: runs mod_STEP of the module in a fresh bash process (lib/step.sh) and returns its status.
# The module therefore cannot change the core, and set -e always applies inside the module.
module_run() {
	local name=$1 step=$2 file context
	file=$(module_file "${name}") || die "Unknown module '${name}'."
	context=$(_module_context)
	LSS_STEP_MODULE=${name} LSS_STEP_NAME=${step} LSS_STEP_FILE=${file} LSS_STEP_CONTEXT=${context} \
		bash "${LSS_ROOT}/lib/step.sh"
	return
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
	return
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
	return
}

# config_unknown_keys: prints the given settings that no module reads, usually typos, one per line.
config_unknown_keys() {
	# LSS_WIREGUARD_NETWORK is read by the firewall for the vpn scope before the wireguard module exists.
	local -A known=([LSS_MODULES]=1 [LSS_MODE]=1 [LSS_WIREGUARD_NETWORK]=1)
	local name key _default _description
	while IFS= read -r name; do
		known[$(config_key "${name}" mode)]=1
		while IFS='|' read -r key _default _description; do
			[[ -z ${key} ]] || known[$(config_key "${name}" "${key}")]=1
		done < <(module_meta "${name}" MOD_OPTIONS)
	done < <(module_list)
	for key in "${!LSS_CFG_SET[@]}" "${!LSS_CFG_FILE[@]}" "${!LSS_CFG_PROFILE[@]}"; do
		[[ -n ${known[${key}]+x} ]] || printf '%s\n' "${key}"
	done | sort -u
	return
}

# opt OPTION: value of an option of the module running this step (LSS_<MODULE>_<OPTION>), with the default from the
# module's MOD_OPTIONS. Unknown options are a programming error and stop the step.
opt() {
	local wanted=$1 key default _description
	while IFS='|' read -r key default _description; do
		if [[ ${key} == "${wanted}" ]]; then
			config_option "${LSS_MODULE}" "${key}" "${default}"
			return 0
		fi
	done <<<"${MOD_OPTIONS:-}"
	die "${LSS_MODULE}: unknown option '${wanted}'."
}

# opt_bool OPTION: true for 1/true/yes/on, false for 0/false/no/off/empty; anything else stops the step.
opt_bool() {
	local option=$1 value
	value=$(opt "${option}") || die "${LSS_MODULE}: unknown option '${option}'."
	case ${value,,} in
	1 | true | yes | on) return 0 ;;
	0 | false | no | off | '') return 1 ;;
	*) die "$(config_key "${LSS_MODULE}" "${option}") must be true or false, got '${value}'." ;;
	esac
}

# opt_int OPTION: prints the option after checking it is a non-negative integer.
opt_int() {
	local option=$1 value
	value=$(opt "${option}") || die "${LSS_MODULE}: unknown option '${option}'."
	[[ ${value} =~ ^[0-9]+$ ]] || die "$(config_key "${LSS_MODULE}" "${option}") must be a number, got '${value}'."
	printf '%s' "${value}"
	return
}
