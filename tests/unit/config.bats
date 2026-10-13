#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

setup() {
	load helpers
	lss_test_setup
	CONF=${BATS_TEST_TMPDIR}/lss.conf
}

@test "values are taken literally, nothing is executed" {
	cat >"${CONF}" <<'EOF'
# comment
LSS_A=plain value with spaces
LSS_B="$(touch /tmp/lss-pwned)"
LSS_C='`id`'
LSS_D=a#b=c
  LSS_E = padded
export LSS_F=exported
LSS_G=
EOF
	config_load_file "${CONF}"
	[ "$(config_get LSS_A)" = "plain value with spaces" ]
	[ "$(config_get LSS_B)" = '$(touch /tmp/lss-pwned)' ]
	[ "$(config_get LSS_C)" = '`id`' ]
	[ "$(config_get LSS_D)" = 'a#b=c' ]
	[ "$(config_get LSS_E)" = ' padded' ]
	[ "$(config_get LSS_F)" = exported ]
	[ "$(config_get LSS_G default)" = '' ]
	[ ! -e /tmp/lss-pwned ]
}

@test "a line without = fails with the line number" {
	printf 'LSS_A=1\nnot a setting\n' >"${CONF}"
	run config_load_file "${CONF}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"lss.conf:2: expected KEY=value"* ]]
}

@test "keys outside the LSS_ namespace are refused" {
	printf 'PATH=/tmp\n' >"${CONF}"
	run config_load_file "${CONF}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"invalid key 'PATH'"* ]]
}

@test "unreadable files and invalid keys from --set or code are refused" {
	run config_load_file "${BATS_TEST_TMPDIR}/missing.conf"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Cannot read configuration file ${BATS_TEST_TMPDIR}/missing.conf"* ]]
	run config_set_arg 'PATH=/tmp'
	[ "${status}" -eq 1 ]
	[[ ${output} == *"--set: invalid key 'PATH'"* ]]
	run config_set lss_lower x
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Invalid setting key 'lss_lower'"* ]]
}

@test "precedence: --set over environment over file over profile over default" {
	printf 'LSS_X=file\nLSS_Y=file\nLSS_Z=file\n' >"${CONF}"
	printf 'LSS_X=profile\nLSS_Y=profile\nLSS_Z=profile\nLSS_P=profile\n' >"${BATS_TEST_TMPDIR}/profile.conf"
	config_load_file "${CONF}"
	config_load_profile "${BATS_TEST_TMPDIR}/profile.conf"
	export LSS_Y=env LSS_X=env
	config_set_arg LSS_X=set
	[ "$(config_get LSS_X)" = set ]
	[ "$(config_get LSS_Y)" = env ]
	[ "$(config_get LSS_Z)" = file ]
	[ "$(config_get LSS_P)" = profile ]
	[ "$(config_get LSS_MISSING fallback)" = fallback ]
}

@test "a non-exported shell variable does not count as environment" {
	LSS_LOCAL_ONLY=shell
	[ "$(config_get LSS_LOCAL_ONLY default)" = default ]
}

@test "--set keeps the value after the first = literally" {
	config_set_arg 'LSS_URL=https://x/?a=b&c=$(id)'
	[ "$(config_get LSS_URL)" = 'https://x/?a=b&c=$(id)' ]
	run config_set_arg 'novalue'
	[ "${status}" -eq 1 ]
}

@test "option keys derive from module and option names" {
	[ "$(config_key ssh-hardening port)" = LSS_SSH_HARDENING_PORT ]
	config_set LSS_SSH_HARDENING_PORT 2222
	[ "$(config_option ssh-hardening port 22)" = 2222 ]
	[ "$(config_option ssh-hardening allow-users root)" = root ]
}

@test "booleans accept the usual spellings and reject others" {
	config_set LSS_T yes
	config_bool LSS_T
	config_set LSS_F off
	run config_bool LSS_F
	[ "${status}" -eq 1 ]
	config_set LSS_BAD maybe
	run config_bool LSS_BAD
	[ "${status}" -eq 1 ]
	[[ ${output} == *"must be true or false"* ]]
	run ! config_bool LSS_UNSET
	config_bool LSS_UNSET true
}

@test "Windows line endings are accepted" {
	printf 'LSS_A=one\r\nLSS_B=two\r\n' >"${CONF}"
	config_load_file "${CONF}"
	[ "$(config_get LSS_A)" = one ]
	[ "$(config_get LSS_B)" = two ]
}
