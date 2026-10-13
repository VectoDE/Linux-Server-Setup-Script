# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME=midfail
MOD_GROUP="test"
MOD_DESCRIPTION="A command in the middle fails, the last one succeeds"
mod_configure() {
	false
	file_write 0644 "${OWNER}" "${TEST_TARGET}/midfail.conf" <<<"should not exist"
	true
	return
}
