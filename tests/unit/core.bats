#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

setup() {
	load helpers
	lss_test_setup
}

# --- os ---------------------------------------------------------------------------------------------------------

@test "all six supported systems are detected and accepted" {
	local release family
	for release in debian-12:debian debian-13:debian ubuntu-22.04:debian ubuntu-24.04:debian rocky-9:rhel almalinux-10:rhel rhel-9:rhel; do
		family=${release#*:}
		use_os "${release%%:*}"
		[ "${OS_FAMILY}" = "${family}" ]
		[ -z "$(os_unsupported_reason)" ]
	done
}

@test "codename, major version and architecture names" {
	use_os ubuntu-22.04 aarch64
	[ "${OS_CODENAME}" = jammy ]
	[ "${OS_MAJOR}" = 22 ]
	[ "$(os_deb_arch)" = arm64 ]
	use_os almalinux-10
	[ "${OS_ID}" = almalinux ]
	[ "${OS_MAJOR}" = 10 ]
}

@test "unsupported systems are refused with a reason" {
	use_os centos-7
	run os_require_supported
	[ "${status}" -eq 1 ]
	[[ ${output} == *"CentOS Linux 7 (Core) is not supported"* ]]
	use_os ubuntu-24.10
	[[ $(os_unsupported_reason) == *"not an LTS release"* ]]
	use_os arch
	[[ $(os_unsupported_reason) == *"Arch Linux is not supported"* ]]
	use_os debian-12 armv7l
	[[ $(os_unsupported_reason) == *"Architecture armv7l"* ]]
}

# --- log --------------------------------------------------------------------------------------------------------

@test "masked values never reach the log file or stderr" {
	log_mask 'S3cr3t-Value'
	run log_info "password is S3cr3t-Value here"
	[[ ${output} == *"password is *** here"* ]]
	log_info "again S3cr3t-Value"
	run ! grep -q S3cr3t "${LSS_LOG_FILE}"
	grep -q 'again \*\*\*' "${LSS_LOG_FILE}"
}

@test "die exits with status 1 and an ERROR line" {
	run die "broken"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"ERROR broken"* ]]
}

@test "debug output only with LSS_VERBOSE=1" {
	run log_debug "hidden"
	[ -z "${output}" ]
	LSS_VERBOSE=1 run log_debug "shown"
	[[ ${output} == *"DEBUG shown"* ]]
}

# --- files ------------------------------------------------------------------------------------------------------

@test "file_write writes, then leaves identical content untouched" {
	local dest=${BATS_TEST_TMPDIR}/etc/app.conf
	file_write 0640 "${OWNER}" "${dest}" <<<"one"
	[ "${LSS_FILE_CHANGED}" = 1 ]
	[ "$(cat "${dest}")" = one ]
	[ "$(stat -c %a "${dest}")" = 640 ]
	file_write 0640 "${OWNER}" "${dest}" <<<"one"
	[ "${LSS_FILE_CHANGED}" = 0 ]
	[ "$(files_changes_of core)" = 1 ]
}

@test "a changed mode alone counts as a change" {
	local dest=${BATS_TEST_TMPDIR}/mode.conf
	file_write 0644 "${OWNER}" "${dest}" <<<"x"
	file_write 0600 "${OWNER}" "${dest}" <<<"x"
	[ "${LSS_FILE_CHANGED}" = 1 ]
	[ "$(stat -c %a "${dest}")" = 600 ]
}

@test "files_restore brings back old content and removes new files" {
	local old=${BATS_TEST_TMPDIR}/old.conf new=${BATS_TEST_TMPDIR}/new.conf
	printf 'original\n' >"${old}"
	chmod 600 "${old}"
	LSS_MODULE=demo
	file_write 0644 "${OWNER}" "${old}" <<<"replaced"
	file_write 0644 "${OWNER}" "${old}" <<<"replaced twice"
	file_write 0644 "${OWNER}" "${new}" <<<"created"
	files_restore
	[ "$(cat "${old}")" = original ]
	[ "$(stat -c %a "${old}")" = 600 ]
	[ ! -e "${new}" ]
}

@test "files_drifted reports managed files changed outside lss" {
	local dest=${BATS_TEST_TMPDIR}/managed.conf
	LSS_MODULE=demo
	file_write 0644 "${OWNER}" "${dest}" <<<"managed"
	[ -z "$(files_drifted demo)" ]
	printf 'edited\n' >"${dest}"
	[ "$(files_drifted demo)" = "${dest}" ]
	rm "${dest}"
	[ "$(files_drifted demo)" = "${dest} (missing)" ]
}

# --- template ---------------------------------------------------------------------------------------------------

@test "templates insert values literally" {
	local NAME='a&b\c/d' MULTI=$'line1\nline2' EMPTY=''
	run template_render_string 'x={{NAME}} y={{MULTI}} z={{EMPTY}}! {{NAME}}'
	[ "${output}" = $'x=a&b\\c/d y=line1\nline2 z=! a&b\\c/d' ]
}

@test "a placeholder without a value is an error" {
	run template_render_string 'port {{UNDEFINED_VALUE}}'
	[ "${status}" -eq 1 ]
	[[ ${output} == *"{{UNDEFINED_VALUE}} has no value"* ]]
}

@test "template_render keeps trailing newlines" {
	printf 'a {{V}}\n\n' >"${BATS_TEST_TMPDIR}/t"
	local V=1
	[ "$(template_render "${BATS_TEST_TMPDIR}/t" | od -c | tr -s ' ' | head -1)" = "$(printf 'a 1\n\n' | od -c | tr -s ' ' | head -1)" ]
}

# --- secrets ----------------------------------------------------------------------------------------------------

@test "secrets are generated once, kept and private" {
	local first second
	first=$(secret_get db-root 40)
	second=$(secret_get db-root)
	[ "${first}" = "${second}" ]
	[ "${#first}" -eq 40 ]
	[[ ${first} =~ ^[A-Za-z0-9]+$ ]]
	[ "$(stat -c %a "${LSS_SECRETS_DIR}/db-root")" = 600 ]
	[ "$(stat -c %a "${LSS_SECRETS_DIR}")" = 700 ]
}

@test "secret_load assigns and masks in the current shell" {
	local value
	secret_load api-token value
	run log_info "token ${value}"
	[[ ${output} == *"token ***"* ]]
}

@test "secret names cannot escape the secrets directory" {
	run secret_get ../../etc/passwd
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Invalid secret name"* ]]
}

# --- state ------------------------------------------------------------------------------------------------------

@test "state keeps one value per key" {
	state_set demo status failed
	state_set demo status installed
	state_set demo mode docker
	[ "$(state_get demo status)" = installed ]
	[ "$(grep -c '^status=' "${LSS_STATE_DIR}/modules/demo")" = 1 ]
	state_installed demo
	[ "$(state_installed_modules)" = demo ]
	run state_set demo status $'two\nlines'
	[ "${status}" -eq 1 ]
}
