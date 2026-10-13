#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

setup() {
	load helpers
	lss_test_setup
	export LSS_MODULE_DIRS=${REPO_ROOT}/tests/fixtures/modules
	export TEST_TARGET=${BATS_TEST_TMPDIR}/target
	mkdir -p "${TEST_TARGET}"
}

@test "modules are listed with their group" {
	run module_list --groups
	[[ ${output} == *"test alpha"* ]]
	[[ ${output} == *"test web-b"* ]]
}

@test "requirements come first, each module once" {
	run module_resolve beta alpha gamma
	[ "${status}" -eq 0 ]
	[ "${output}" = $'alpha\nbeta\nweb-a\ngamma' ]
}

@test "an alternative uses the requested one" {
	run module_resolve gamma web-b
	[ "${status}" -eq 0 ]
	[[ ${output} == *web-b* ]]
	[[ ${output} != *web-a* ]]
}

@test "an alternative uses the installed one" {
	state_set web-b status installed
	run module_resolve gamma
	[[ ${output} == *web-b* ]]
}

@test "conflicts are refused before anything runs" {
	run module_resolve web-a web-b
	[ "${status}" -eq 1 ]
	[[ ${output} == *"'web-a' and 'web-b' cannot be installed together"* ]]
	state_set web-a status installed
	run module_resolve web-b
	[ "${status}" -eq 1 ]
	[[ ${output} == *"conflicts with the installed module 'web-a'"* ]]
}

@test "cycles and unknown modules are named" {
	run module_resolve cycle-a
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Dependency cycle involving 'cycle-a'"* ]]
	run module_resolve nope
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Unknown module 'nope'"* ]]
	run module_resolve '../../etc'
	[ "${status}" -eq 1 ]
}

@test "apply installs, records state, and a second run is unchanged" {
	run module_apply alpha
	[ "${status}" -eq 0 ]
	[[ ${output} == *"alpha: done (1 changes)"* ]]
	[ "$(cat "${TEST_TARGET}/alpha.conf")" = hello ]
	[ "$(state_get alpha status)" = installed ]
	LSS_RUN_ID=second-run run module_apply alpha
	[[ ${output} == *"alpha: unchanged"* ]]
}

@test "options reach the module" {
	config_set LSS_ALPHA_VALUE 'from --set'
	module_apply alpha
	[ "$(cat "${TEST_TARGET}/alpha.conf")" = 'from --set' ]
}

@test "a failing configure restores the module's files and marks it failed" {
	module_apply alpha
	LSS_RUN_ID=run-2 run module_apply failing
	[ "${status}" -eq 1 ]
	[[ ${output} == *"failing: installation failed; changed files were restored"* ]]
	[ "$(cat "${TEST_TARGET}/alpha.conf")" = hello ]
	[ ! -e "${TEST_TARGET}/failing.conf" ]
	[ "$(state_get failing status)" = failed ]
}

@test "a module cannot leak variables or functions into the core" {
	module_run alpha configure
	[ -z "${MOD_NAME:-}" ]
	run ! declare -F mod_configure
}

@test "remove refuses while another installed module needs it" {
	module_apply alpha
	module_apply beta
	run module_remove alpha
	[ "${status}" -eq 1 ]
	[[ ${output} == *"'beta' needs it"* ]]
	module_remove beta
	module_remove alpha
	[ ! -e "${TEST_TARGET}/alpha.conf" ]
	[ -z "$(state_get alpha status)" ]
}

@test "a failing verify restores the module's files and marks it failed" {
	run module_apply unverified
	[ "${status}" -eq 1 ]
	[[ ${output} == *"unverified: verification failed; changed files were restored"* ]]
	[ ! -e "${TEST_TARGET}/unverified.conf" ]
	[ "$(state_get unverified status)" = failed ]
}

@test "a failing remove step stops the removal and keeps the state" {
	state_set unverified status installed
	state_set retired status installed
	run module_remove unverified
	[ "${status}" -eq 1 ]
	[[ ${output} == *"unverified: removal failed"* ]]
	[ "$(state_get unverified status)" = installed ]
}

@test "mode falls back to what the module supports" {
	config_set LSS_MODE docker
	[ "$(module_mode alpha)" = native ]
	[ "$(module_mode unverified)" = docker ]
	config_set LSS_UNVERIFIED_MODE native
	[ "$(module_mode unverified)" = native ]
}

@test "metadata, the plain list and the default module directory" {
	[ "$(module_meta alpha MOD_DESCRIPTION)" = 'Writes one file' ]
	run module_meta nope MOD_DESCRIPTION
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Unknown module 'nope'"* ]]
	[ "$(module_list | head -1)" = alpha ]
	LSS_MODULE_DIRS=''
	export LSS_ROOT=${BATS_TEST_TMPDIR}/root
	mkdir -p "${LSS_ROOT}/modules"
	[ -z "$(module_list)" ]
	mkdir -p "${LSS_ROOT}/modules/base"
	printf 'MOD_DESCRIPTION=solo\n' >"${LSS_ROOT}/modules/base/solo.sh"
	[ "$(module_list)" = solo ]
	[ "$(module_file solo)" = "${LSS_ROOT}/modules/base/solo.sh" ]
}

@test "a failing command in the middle of a step stops it, also inside a condition" {
	run module_apply midfail
	[ "${status}" -eq 1 ]
	[ ! -e "${TEST_TARGET}/midfail.conf" ]
	if module_run midfail configure; then
		false
	fi
}

@test "opt reads an option with the default from MOD_OPTIONS" {
	LSS_MODULE=alpha
	MOD_OPTIONS=$'value|hello|Content\nflag|true|A switch\ncount|3|A number'
	run opt value
	[ "${output}" = hello ]
	config_set LSS_ALPHA_VALUE world
	run opt value
	[ "${output}" = world ]
	opt_bool flag
	config_set LSS_ALPHA_FLAG off
	run opt_bool flag
	[ "${status}" -eq 1 ]
	[ "$(opt_int count)" = 3 ]
}

@test "opt refuses unknown options and malformed values" {
	LSS_MODULE=alpha
	MOD_OPTIONS=$'flag|maybe|A switch\ncount|x|A number'
	run opt missing
	[ "${status}" -eq 1 ]
	[[ ${output} == *"unknown option 'missing'"* ]]
	run opt_bool flag
	[ "${status}" -eq 1 ]
	[[ ${output} == *"LSS_ALPHA_FLAG must be true or false"* ]]
	run opt_bool missing
	[[ ${output} == *"unknown option"* ]]
	run opt_int count
	[[ ${output} == *"LSS_ALPHA_COUNT must be a number"* ]]
	run opt_int missing
	[[ ${output} == *"unknown option"* ]]
}

@test "settings that no module reads are reported" {
	LSS_CFG_FILE=([LSS_ALPHA_VALUE]=x [LSS_ALPHA_VALEU]=y [LSS_MODULES]=alpha)
	LSS_CFG_SET=([LSS_BETA_MODE]=docker [LSS_NOPE]=1)
	run config_unknown_keys
	[ "${status}" -eq 0 ]
	[ "${output}" = $'LSS_ALPHA_VALEU\nLSS_NOPE' ]
}
