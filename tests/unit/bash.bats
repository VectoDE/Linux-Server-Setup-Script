#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The minimum bash version: every entry script refuses bash before 4.4 before it turns on inherit_errexit, and the
# libraries need no nameref.

setup() {
	load helpers
	lss_test_setup
	return
}

# entry_scripts: every script that sets shell options of its own.
entry_scripts() {
	grep -rl '^shopt -s inherit_errexit' "${REPO_ROOT}/lss" "${REPO_ROOT}/bootstrap.sh" "${REPO_ROOT}/lib" \
		"${REPO_ROOT}/libexec"
}

@test "every entry script checks the bash version before it sets inherit_errexit" {
	local script guard shopt count=0
	while IFS= read -r script; do
		count=$((count + 1))
		guard=$(grep -n 'needs bash 4.4 or newer' "${script}" | head -n 1 | cut -d : -f 1)
		shopt=$(grep -n '^shopt -s inherit_errexit' "${script}" | head -n 1 | cut -d : -f 1)
		[ -n "${guard}" ] || {
			echo "no version check in ${script}"
			return 1
		}
		((guard < shopt))
	done < <(entry_scripts)
	((count >= 8))
}

# run_guard MAJOR MINOR: the version check of lss with BASH_VERSINFO replaced.
run_guard() {
	local check
	check=$(sed -n '/^if ((BASH_VERSINFO/,/^fi$/p' "${REPO_ROOT}/lss")
	check=${check//BASH_VERSINFO/FAKE}
	run bash -c "FAKE=($1 $2); BASH_VERSION=$1.$2; ${check}; echo ok"
}

@test "the version check refuses bash 3 and 4.3 and takes 4.4 and 5" {
	run_guard 3 2
	[ "${status}" -eq 1 ]
	[[ ${output} == *"needs bash 4.4 or newer; this is bash 3.2."* ]]
	run_guard 4 3
	[ "${status}" -eq 1 ]
	run_guard 4 4
	[ "${status}" -eq 0 ]
	[ "${output}" = ok ]
	run_guard 5 0
	[ "${output}" = ok ]
}

@test "the libraries use no nameref" {
	run grep -rnE '(local|declare) -n ' "${REPO_ROOT}/lib" "${REPO_ROOT}/lss" "${REPO_ROOT}/libexec"
	[ "${status}" -eq 1 ]
}

@test "config_parse fills the array it is named and refuses other names" {
	printf 'LSS_DEMO="a b"\nLSS_OTHER=1\n' >"${BATS_TEST_TMPDIR}/demo.conf"
	declare -gA LSS_TEST_ARRAY=()
	config_parse "${BATS_TEST_TMPDIR}/demo.conf" LSS_TEST_ARRAY
	[ "${LSS_TEST_ARRAY[LSS_DEMO]}" = 'a b' ]
	[ "${LSS_TEST_ARRAY[LSS_OTHER]}" = 1 ]
	run config_parse "${BATS_TEST_TMPDIR}/demo.conf" 'x[1]'
	[ "${status}" -eq 1 ]
	[[ ${output} == *"config_parse: invalid array name 'x[1]'."* ]]
}
