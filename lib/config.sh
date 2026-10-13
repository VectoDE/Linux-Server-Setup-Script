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
	[[ $1 =~ ^LSS_[A-Z0-9_]+$ ]]
}

# Strips one pair of matching outer quotes; nothing inside is interpreted.
_config_unquote() {
	local value=$1
	if [[ ${#value} -ge 2 && ${value:0:1} == "${value: -1}" && ${value:0:1} == [\"\'] ]]; then
		value=${value:1:${#value}-2}
	fi
	printf '%s' "${value}"
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
}

config_load_file() {
	config_parse "$1" LSS_CFG_FILE
}

config_load_profile() {
	config_parse "$1" LSS_CFG_PROFILE
}

# config_set_arg KEY=VALUE (from --set).
config_set_arg() {
	local pair=$1
	[[ ${pair} == *=* ]] || die "--set expects KEY=VALUE, got '${pair}'."
	local key=${pair%%=*}
	config_valid_key "${key}" || die "--set: invalid key '${key}'."
	LSS_CFG_SET["${key}"]=${pair#*=}
}

config_set() {
	config_valid_key "$1" || die "Invalid setting key '$1'."
	LSS_CFG_SET["$1"]=$2
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
}

# Option key of a module: config_key ssh-hardening port -> LSS_SSH_HARDENING_PORT
config_key() {
	local module=${1^^} option=${2^^}
	printf 'LSS_%s_%s' "${module//-/_}" "${option//-/_}"
}

# config_option MODULE OPTION DEFAULT
config_option() {
	config_get "$(config_key "$1" "$2")" "${3-}"
}

# Boolean option: true for 1/true/yes/on (any case).
config_bool() {
	local value
	value=$(config_get "$1" "${2:-false}")
	case ${value,,} in
	1 | true | yes | on) return 0 ;;
	0 | false | no | off | '') return 1 ;;
	*) die "$1 must be true or false, got '${value}'." ;;
	esac
}
