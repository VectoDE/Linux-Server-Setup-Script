# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME=bad-check
MOD_GROUP="test"
MOD_DESCRIPTION="Check refuses"
mod_check() {
	die "precondition not met"
	return
}
mod_configure() {
	file_write 0644 "${OWNER}" "${TEST_TARGET}/never.conf" <<<"x"
	return
}
