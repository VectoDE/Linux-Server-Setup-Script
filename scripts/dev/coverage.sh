#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Runs the unit tests under kcov and fails below the line coverage threshold for lib/.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

threshold=${LSS_COVERAGE_THRESHOLD:-90}
out=${1:-coverage}
rm -rf -- "${out}"
kcov --include-path="${PWD}/lib" --bash-dont-parse-binary-dir "${out}" bats tests/unit >/dev/null
percent=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["percent_covered"])' "$(find "${out}" -name coverage.json -path '*bats*' | head -1)")
echo "Line coverage of lib/: ${percent} % (threshold ${threshold} %)"
python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)' "${percent}" "${threshold}" ||
	{
		echo "Coverage below ${threshold} %." >&2
		exit 1
	}
