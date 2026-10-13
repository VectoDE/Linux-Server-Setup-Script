#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The whiptail menu against the whiptail stub; the commands of lss it leads to are recorded in $CALLS.

setup() {
	load helpers
	lss_test_setup
	export LSS_MODULE_DIRS=${REPO_ROOT}/tests/fixtures/modules
	export CALLS=${BATS_TEST_TMPDIR}/calls
	: >"${CALLS}"
	# shellcheck disable=SC2329 # called by the code under test
	cmd_install() { printf 'install %s yes=%s profile=%s\n' "${ARGS[*]}" "${LSS_YES:-0}" "${LSS_PROFILE:-}" >>"${CALLS}"; }
	# shellcheck disable=SC2329
	load_settings() { printf 'load_settings %s\n' "${LSS_PROFILE}" >>"${CALLS}"; }
}

profiles() {
	export LSS_ROOT=${BATS_TEST_TMPDIR}/root
	mkdir -p "${LSS_ROOT}/profiles"
	printf '# Profile: Web server\nLSS_A=1\n' >"${LSS_ROOT}/profiles/web.conf"
	printf '# Profile: Mail server\n' >"${LSS_ROOT}/profiles/mail.conf"
}

@test "the menu needs a terminal" {
	run ui_menu
	[ "${status}" -eq 1 ]
	[[ ${output} == *"The menu needs a terminal"* ]]
}

@test "menu entries lead to their commands" {
	command -v script >/dev/null || skip "script (util-linux) not installed"
	cat >"${BATS_TEST_TMPDIR}/menu.bash" <<'EOF'
for library in log os config files template secrets state pkg repo fetch service firewall module ui; do
	source "${LSS_ROOT}/lib/${library}.sh"
done
_ui_profile() { printf 'profile\n' >>"${CALLS}"; }
_ui_modules() { printf 'modules\n' >>"${CALLS}"; }
cmd_status() { printf 'status\n' >>"${CALLS}"; }
cmd_verify() { printf 'verify\n' >>"${CALLS}"; }
cmd_audit() { printf 'audit\n' >>"${CALLS}"; }
for STUB_OUT_whiptail in profile modules status verify audit other; do
	export STUB_OUT_whiptail
	ui_menu
done
STUB_EXIT_whiptail=1 ui_menu
printf 'done\n' >>"${CALLS}"
EOF
	# script gives the menu a terminal on stdin and stdout.
	script -qec "bash '${BATS_TEST_TMPDIR}/menu.bash'" /dev/null >/dev/null
	[ "$(cat "${CALLS}")" = $'profile\nmodules\nstatus\nverify\naudit\ndone' ]
	grep -q "whiptail --title lss ${LSS_VERSION} --menu What do you want to do?" "${STUB_LOG}"
}

@test "a profile is chosen, confirmed and installed" {
	profiles
	export STUB_OUT_whiptail=web
	_ui_profile
	[ "$(cat "${CALLS}")" = $'load_settings web\ninstall  yes=1 profile=web' ]
	grep -qF 'whiptail --title Profiles --menu Choose a profile 20 78 10 mail Mail server web Web server' "${STUB_LOG}"
	grep -qF "whiptail --yesno Install the profile 'web'?" "${STUB_LOG}"
}

@test "modules are offered with their state and the selection is installed" {
	state_set alpha status installed
	export STUB_OUT_whiptail=$'alpha\nbeta'
	_ui_modules
	[ "$(cat "${CALLS}")" = 'install alpha beta yes=0 profile=' ]
	grep -qF 'alpha [test] Writes one file ON' "${STUB_LOG}"
	grep -qF 'beta [test] Needs alpha OFF' "${STUB_LOG}"
}

@test "cancelling a dialog or choosing nothing installs nothing" {
	profiles
	export STUB_EXIT_whiptail=1
	_ui_profile
	_ui_modules
	export STUB_EXIT_whiptail=0 STUB_EXIT_whiptail_yesno=1 STUB_OUT_whiptail=web
	_ui_profile
	export STUB_EXIT_whiptail_yesno=0 STUB_OUT_whiptail=''
	_ui_modules
	[ "$(cat "${CALLS}")" = 'load_settings web' ]
}
