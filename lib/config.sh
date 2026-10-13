# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Settings. Keys look like LSS_<MODULE>_<OPTION>. Values come, in this order of precedence, from --set, the
# environment, the configuration file, the profile and the module default. Files are parsed as KEY=value lines and
# never sourced, so a value is always taken literally.

declare -gA LSS_CFG_SET=()
declare -gA LSS_CFG_FILE=()
declare -gA LSS_CFG_PROFILE=()

config_valid_key() {
	local key=$1
	[[ ${key} =~ ^LSS_[A-Z0-9_]+$ ]]
	return
}

# Strips one pair of matching outer quotes; nothing inside is interpreted.
_config_unquote() {
	local value=$1
	if [[ ${#value} -ge 2 && ${value:0:1} == "${value: -1}" && ${value:0:1} == [\"\'] ]]; then
		value=${value:1:${#value}-2}
	fi
	printf '%s' "${value}"
	return
}

# config_parse FILE ARRAY_NAME: reads KEY=value lines into the associative array.
config_parse() {
	local file=$1 line key value number=0
	local -n target=$2
	[[ -r ${file} ]] || die "Cannot read configuration file ${file}."
	while IFS= read -r line || [[ -n ${line} ]]; do
		number=$((number + 1))
		line=${line%$'\r'}
		[[ ${line} =~ ^[[:space:]]*(#.*)?$ ]] && continue
		if [[ ${line} != *=* ]]; then
			die "${file}:${number}: expected KEY=value."
		fi
		key=${line%%=*}
		key=${key#"${key%%[![:space:]]*}"}
		key=${key%"${key##*[![:space:]]}"}
		key=${key#export }
		value=${line#*=}
		config_valid_key "${key}" || die "${file}:${number}: invalid key '${key}' (expected LSS_ followed by A-Z, 0-9, _)."
		# shellcheck disable=SC2034 # nameref to the caller's array
		target["${key}"]=$(_config_unquote "${value}")
	done <"${file}"
	return
}

config_load_file() {
	local file=$1
	config_parse "${file}" LSS_CFG_FILE
	return
}

config_load_profile() {
	local file=$1
	config_parse "${file}" LSS_CFG_PROFILE
	return
}

# config_set_arg KEY=VALUE (from --set).
config_set_arg() {
	local pair=$1
	[[ ${pair} == *=* ]] || die "--set expects KEY=VALUE, got '${pair}'."
	local key=${pair%%=*}
	config_valid_key "${key}" || die "--set: invalid key '${key}'."
	LSS_CFG_SET["${key}"]=${pair#*=}
	return
}

config_set() {
	local key=$1 value=$2
	config_valid_key "${key}" || die "Invalid setting key '${key}'."
	LSS_CFG_SET["${key}"]=${value}
	return
}

# config_get KEY [DEFAULT]: prints the effective value.
config_get() {
	local key=$1 default=${2-}
	if [[ -v LSS_CFG_SET[${key}] ]]; then
		printf '%s' "${LSS_CFG_SET[${key}]}"
	elif [[ -n ${!key+set} ]] && [[ $(declare -p "${key}" 2>/dev/null) == 'declare -x'* ]]; then
		printf '%s' "${!key}"
	elif [[ -v LSS_CFG_FILE[${key}] ]]; then
		printf '%s' "${LSS_CFG_FILE[${key}]}"
	elif [[ -v LSS_CFG_PROFILE[${key}] ]]; then
		printf '%s' "${LSS_CFG_PROFILE[${key}]}"
	else
		printf '%s' "${default}"
	fi
	return
}

# Option key of a module: config_key ssh-hardening port -> LSS_SSH_HARDENING_PORT
config_key() {
	local module=${1^^} option=${2^^}
	printf 'LSS_%s_%s' "${module//-/_}" "${option//-/_}"
	return
}

# config_option MODULE OPTION DEFAULT
config_option() {
	local module=$1 option=$2 default=${3-}
	config_get "$(config_key "${module}" "${option}")" "${default}"
	return
}

# Boolean option: true for 1/true/yes/on (any case).
config_bool() {
	local key=$1 value
	value=$(config_get "${key}" "${2:-false}")
	case ${value,,} in
	1 | true | yes | on) return 0 ;;
	0 | false | no | off | '') return 1 ;;
	*) die "${key} must be true or false, got '${value}'." ;;
	esac
}
