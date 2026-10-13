# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME=beta
MOD_GROUP="test"
MOD_DESCRIPTION="Needs alpha"
MOD_REQUIRES="alpha"
mod_configure() { file_write 0644 "${OWNER}" "${TEST_TARGET}/beta.conf" <<<"beta"; }
mod_verify() { [[ -f ${TEST_TARGET}/beta.conf ]]; }
mod_remove() { file_remove "${TEST_TARGET}/beta.conf"; }
