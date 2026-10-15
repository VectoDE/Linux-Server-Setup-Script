# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Shared setup for the unit tests: every test gets its own state, secrets and log directories and a PATH with stub
# commands (tests/fixtures/bin) in front, so no test touches the real system.

lss_test_setup() {
	bats_require_minimum_version 1.5.0
	REPO_ROOT=$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)
	export LSS_ROOT=${REPO_ROOT}
	export LSS_STATE_DIR=${BATS_TEST_TMPDIR}/state
	export LSS_SECRETS_DIR=${BATS_TEST_TMPDIR}/secrets
	export LSS_LOG_FILE=${BATS_TEST_TMPDIR}/lss.log
	export LSS_RUN_ID=test-run
	export LSS_JOURNAL=0
	export LSS_COLOR=never
	export LSS_VERSION=0.0.0-test
	export STUB_LOG=${BATS_TEST_TMPDIR}/stub.log
	export PATH="${REPO_ROOT}/tests/fixtures/bin:${PATH}"
	OWNER="$(id -un):$(id -gn)"
	export OWNER
	: >"${STUB_LOG}"
	local library
	for library in log os config files template secrets state pkg repo fetch service firewall container web mail monitoring module ui; do
		# shellcheck source=/dev/null
		source "${REPO_ROOT}/lib/${library}.sh"
	done
	return
}

use_os() {
	export LSS_OS_RELEASE=${REPO_ROOT}/tests/fixtures/os-release/$1
	export LSS_ARCH=${2:-x86_64}
	os_detect
	return
}
