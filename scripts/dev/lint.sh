#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Lints every shell file of the repository: scripts/dev/lint.sh [shellcheck|shellcheck-sarif|shfmt|all]
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

# ShellCheck findings as SARIF 2.1.0 for GitHub code scanning (ShellCheck itself has no SARIF output).
run_shellcheck_sarif() {
	{ shellcheck -x -f json1 "${files[@]}" || true; } | jq '
		def level: if . == "error" then "error" elif . == "warning" then "warning" else "note" end;
		{
			"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
			version: "2.1.0",
			runs: [{
				tool: { driver: {
					name: "ShellCheck",
					informationUri: "https://www.shellcheck.net",
					rules: ([.comments[] | "SC\(.code)" | { id: ., helpUri: "https://www.shellcheck.net/wiki/\(.)" }] | unique_by(.id))
				} },
				results: [.comments[] | {
					ruleId: "SC\(.code)",
					level: (.level | level),
					message: { text: .message },
					locations: [{ physicalLocation: {
						artifactLocation: { uri: .file },
						region: { startLine: .line, startColumn: .column, endLine: .endLine, endColumn: .endColumn }
					} }]
				}]
			}]
		}'
}

run_shfmt() {
	# Formatting follows .editorconfig (tabs, bash dialect, indented case items).
	shfmt -d "${files[@]}"
}

case ${1:-all} in
shellcheck) run_shellcheck ;;
shellcheck-sarif) run_shellcheck_sarif ;;
shfmt) run_shfmt ;;
all)
	run_shellcheck
	run_shfmt
	;;
*)
	echo "usage: lint.sh [shellcheck|shellcheck-sarif|shfmt|all]" >&2
	exit 2
	;;
esac
