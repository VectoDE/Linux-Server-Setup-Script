# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME=alpha
MOD_GROUP="test"
MOD_DESCRIPTION="Writes one file"
MOD_REQUIRES=""
MOD_OPTIONS="value|hello|Content of the file"
mod_check() { :; }
mod_install() { :; }
mod_configure() {
	local value
	value=$(config_option alpha value hello)
	file_write 0644 "${OWNER}" "${TEST_TARGET}/alpha.conf" <<<"${value}"
}
mod_verify() { [[ -f ${TEST_TARGET}/alpha.conf ]]; }
mod_remove() { file_remove "${TEST_TARGET}/alpha.conf"; }
