#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Runs the unit tests under kcov (official image, pinned by digest) and fails below the line coverage threshold
# for lib/. Usage: scripts/dev/coverage.sh BATS_DIR [OUT_DIR]
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

bats_dir=$(cd "${1:?usage: coverage.sh BATS_DIR [OUT_DIR]}" && pwd)
out=${2:-coverage}
threshold=${LSS_COVERAGE_THRESHOLD:-90}
image=kcov/kcov@sha256:481289ae32e55e5b733019515acd10948a4f76dfed381765577db909664fc603
rm -rf -- "${out}"
mkdir -p "${out}"
docker run --rm --security-opt seccomp=unconfined \
	-v "${PWD}:/src" -v "${bats_dir}:/bats:ro" -v "$(cd "${out}" && pwd):/out" -w /src \
	"${image}" kcov --include-path=/src/lib --bash-dont-parse-binary-dir /out /bats/bin/bats tests/unit >/dev/null
report=$(find "${out}" -name coverage.json -path '*bats*' | head -1)
python3 - "${report}" <<'PY'
import json, sys
for entry in sorted(json.load(open(sys.argv[1]))["files"], key=lambda e: float(e["percent_covered"])):
    print(f'{float(entry["percent_covered"]):6.1f} %  {entry["covered_lines"]:>4}/{entry["total_lines"]:<4} {entry["file"].replace("/src/", "")}')
PY
percent=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["percent_covered"])' "${report}")
echo "Line coverage of lib/: ${percent} % (threshold ${threshold} %)"
python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)' "${percent}" "${threshold}" || {
	echo "Coverage below ${threshold} %." >&2
	exit 1
}
