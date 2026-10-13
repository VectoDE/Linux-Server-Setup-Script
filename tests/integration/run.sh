#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Integration test: tests/integration/run.sh SYSTEM|host MODULE...
#
# For every module: install (with its requirements), verify, install again (every module in the run must report
# "unchanged"), and remove. SYSTEM is a directory in tests/integration/images (a systemd container); "host" runs on
# the machine itself (for modules that need a real kernel, used on throwaway CI virtual machines only).
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

system=${1:?usage: run.sh SYSTEM|host MODULE...}
shift
[[ $# -gt 0 ]] || {
	echo "usage: run.sh SYSTEM|host MODULE..." >&2
	exit 2
}
settings=tests/integration/settings.conf
container="lss-test-${system}"

in_target() {
	if [[ ${system} == host ]]; then
		sudo --preserve-env=SSH_CONNECTION bash -c "$1"
	else
		docker exec "${container}" bash -c "$1"
	fi
}

start_target() {
	if [[ ${system} == host ]]; then
		sudo rm -rf /opt/lss-src
		sudo cp -a "${PWD}" /opt/lss-src
	else
		[[ -d tests/integration/images/${system} ]] || {
			echo "Unknown system ${system}" >&2
			exit 2
		}
		docker build -q -f "tests/integration/images/${system}/Containerfile" -t "lss-test:${system}" \
			"tests/integration/images/${system}" >/dev/null
		docker rm -f "${container}" >/dev/null 2>&1 || true
		docker run -d --name "${container}" --hostname lss-test --privileged --cgroupns=host \
			-v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp:exec \
			-v "${PWD}:/src:ro" "lss-test:${system}" >/dev/null
		in_target 'for i in $(seq 60); do s=$(systemctl is-system-running 2>/dev/null || true); [[ $s == running || $s == degraded ]] && exit 0; sleep 1; done; exit 1'
		in_target 'cp -a /src /opt/lss-src'
	fi
	in_target 'ln -sf /opt/lss-src/lss /usr/local/sbin/lss && mkdir -p /etc/lss'
	in_target "cat > /etc/lss/lss.conf" <"${settings}"
}

stop_target() {
	local status=$?
	if [[ ${status} -ne 0 ]]; then
		echo "::group::Diagnostics"
		in_target 'tail -n 200 /var/log/lss/*.log 2>/dev/null; systemctl --failed --no-pager; journalctl -p warning -n 80 --no-pager' || true
		echo "::endgroup::"
	fi
	if [[ ${system} != host ]]; then
		docker rm -f "${container}" >/dev/null 2>&1 || true
	fi
	exit "${status}"
}

trap stop_target EXIT
start_target

for module in "$@"; do
	echo "::group::${system}: ${module}"
	in_target "lss --yes --no-color install ${module}"
	in_target "lss --yes --no-color verify"
	second=$(in_target "lss --yes --no-color install ${module} 2>&1") || {
		printf '%s\n' "${second}"
		exit 1
	}
	printf '%s\n' "${second}"
	if grep -E 'OK +[a-z0-9-]+: done' <<<"${second}"; then
		echo "Second install of ${module} changed something; modules must be idempotent." >&2
		exit 1
	fi
	if [[ ${LSS_TEST_KEEP:-0} != 1 ]]; then
		in_target "lss --yes --no-color remove ${module}"
		in_target "! lss status | grep -q '^${module} '"
	fi
	echo "::endgroup::"
done
echo "${system}: ${*} passed"
