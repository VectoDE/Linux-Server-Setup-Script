# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME=failing
MOD_GROUP="test"
MOD_DESCRIPTION="Configure fails after writing"
MOD_REQUIRES="alpha"
mod_configure() {
	file_write 0644 "${OWNER}" "${TEST_TARGET}/alpha.conf" <<<"overwritten by failing"
	file_write 0644 "${OWNER}" "${TEST_TARGET}/failing.conf" <<<"new"
	false
	return
}
