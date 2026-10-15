#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# lss update: the command hands its version, --rollback and --dry-run to bootstrap.sh of the running version and
# tells it that the lock is held. bootstrap.sh itself is tested in bootstrap.bats.

setup() {
	bats_require_minimum_version 1.5.0
	REPO_ROOT=$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)
	export FAKE_ROOT=${BATS_TEST_TMPDIR}/root
	export CALLS=${BATS_TEST_TMPDIR}/calls
	mkdir -p "${FAKE_ROOT}"
	printf '#!/usr/bin/env bash\nprintf "%%s|%%s\\n" "$*" "${LSS_LOCK_HELD:-}" >>"${CALLS}"\nexit "${BOOTSTRAP_EXIT:-0}"\n' \
		>"${FAKE_ROOT}/bootstrap.sh"
	# Drivers as files, not bash -c: under kcov (coverage.sh) BASH_SOURCE is unset in bash -c, and lss runs with set -u.
	printf '%s\n' 'source "$1"' 'shift' 'parse_args "$@"' 'LSS_ROOT=${FAKE_ROOT}' 'cmd_update' >"${BATS_TEST_TMPDIR}/update.sh"
	printf '%s\n' 'source "$1"' 'echo sourced' >"${BATS_TEST_TMPDIR}/source.sh"
	export LSS_JOURNAL=0 LSS_COLOR=never
	return
}

# update ARGS...: parses the arguments as lss does and runs `lss update` against the stub bootstrap.sh.
update() {
	bash "${BATS_TEST_TMPDIR}/update.sh" "${REPO_ROOT}/lss" "$@"
	return
}

@test "lss update runs bootstrap.sh with the lock held" {
	update update
	[ "$(cat "${CALLS}")" = "|1" ]
}

@test "lss update VERSION passes the version" {
	update update 2.0.1
	[ "$(cat "${CALLS}")" = "2.0.1|1" ]
}

@test "--rollback and --dry-run reach bootstrap.sh" {
	update --dry-run update --rollback
	[ "$(cat "${CALLS}")" = "--rollback --dry-run|1" ]
}

@test "two versions are refused" {
	run update update 2.0.1 2.0.2
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Usage: lss update [VERSION] | lss update --rollback"* ]]
	[ ! -e "${CALLS}" ]
}

@test "a failed update fails the command" {
	BOOTSTRAP_EXIT=1 run update update
	[ "${status}" -eq 1 ]
}

@test "the help lists update, and lss runs only when executed" {
	run bash "${REPO_ROOT}/lss" --help
	[[ ${output} == *"update [VERSION]"* && ${output} == *"update --rollback"* ]]
	run bash "${REPO_ROOT}/lss" version
	[ "${output}" = "lss $(<"${REPO_ROOT}/VERSION")" ]
	run bash "${BATS_TEST_TMPDIR}/source.sh" "${REPO_ROOT}/lss"
	[ "${output}" = sourced ]
}
