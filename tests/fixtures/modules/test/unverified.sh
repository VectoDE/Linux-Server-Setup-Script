# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME=unverified
MOD_GROUP="test"
MOD_DESCRIPTION="Writes a file, then fails verify and remove"
MOD_MODES="native docker"
mod_configure() { file_write 0644 "${OWNER}" "${TEST_TARGET}/unverified.conf" <<<"x"; }
mod_verify() { false; }
mod_remove() { false; }
