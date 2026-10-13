#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Lints every shell file of the repository: scripts/dev/lint.sh [shellcheck|shfmt|all]
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

mapfile -t files < <(
	{
		printf '%s\n' lss
		[[ ! -f bootstrap.sh ]] || printf '%s\n' bootstrap.sh
		find libexec -type f 2>/dev/null
		find lib modules scripts tests -type f \( -name '*.sh' -o -name '*.bash' -o -name '*.bats' \) 2>/dev/null
	} | sort -u
)

run_shellcheck() {
	shellcheck -x "${files[@]}"
}

run_shfmt() {
	# Formatting follows .editorconfig (tabs, bash dialect, indented case items).
	shfmt -d "${files[@]}"
}

case ${1:-all} in
shellcheck) run_shellcheck ;;
shfmt) run_shfmt ;;
all)
	run_shellcheck
	run_shfmt
	;;
*)
	echo "usage: lint.sh [shellcheck|shfmt|all]" >&2
	exit 2
	;;
esac
