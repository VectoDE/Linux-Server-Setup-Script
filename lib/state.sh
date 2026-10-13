# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Module state: one file per module in /var/lib/lss/modules with KEY=value lines (status, version, mode,
# installed_at, updated_at). Parsed, never sourced.

state_dir() {
	printf '%s/modules' "${LSS_STATE_DIR:-/var/lib/lss}"
}

state_get() {
	local file key=$2 line
	file="$(state_dir)/$1"
	[[ -f ${file} ]] || return 0
	while IFS= read -r line; do
		if [[ ${line} == "${key}="* ]]; then
			printf '%s' "${line#*=}"
			return 0
		fi
	done <"${file}"
}

state_set() {
	local module=$1 key=$2 value=$3 file dir
	[[ ${key} =~ ^[a-z_]+$ ]] || die "Invalid state key '${key}'."
	[[ ${value} != *$'\n'* ]] || die "State values cannot contain newlines."
	dir=$(state_dir)
	mkdir -p "${dir}"
	file="${dir}/${module}"
	touch "${file}"
	grep -v "^${key}=" "${file}" >"${file}.tmp" || true
	printf '%s=%s\n' "${key}" "${value}" >>"${file}.tmp"
	mv -f -- "${file}.tmp" "${file}"
	chmod 600 "${file}"
}

state_installed() {
	[[ $(state_get "$1" status) == installed ]]
}

state_installed_modules() {
	local dir file
	dir=$(state_dir)
	[[ -d ${dir} ]] || return 0
	for file in "${dir}"/*; do
		[[ -f ${file} ]] || continue
		if [[ $(state_get "${file##*/}" status) == installed ]]; then
			printf '%s\n' "${file##*/}"
		fi
	done
}

state_forget() {
	rm -f -- "$(state_dir)/$1"
}
