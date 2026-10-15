# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# A systemd test container with a release directory, for tests/integration/update.sh and ansible.sh. Sourced; the
# caller sets SYSTEM (a directory in tests/integration/images) and RELEASE_DIR (mounted read-only at /srv/release).

TARGET_CONTAINER="lss-release-${SYSTEM}"

group_start() {
	echo "::group::$1"
	return
}

group_end() {
	echo "::endgroup::"
	return
}

# in_target SCRIPT: runs a script as root in the container, with the release settings of the test.
in_target() {
	local script=$1
	docker exec -i -e LSS_RELEASE_URL=file:///srv/release -e LSS_RELEASE_WORKFLOW -e LSS_RELEASE_REF \
		"${TARGET_CONTAINER}" bash -c "${script}"
	return
}

target_start() {
	[[ -d tests/integration/images/${SYSTEM} ]] || {
		echo "Unknown system ${SYSTEM}" >&2
		exit 2
	}
	docker build -q -f "tests/integration/images/${SYSTEM}/Containerfile" -t "lss-test:${SYSTEM}" \
		"tests/integration/images/${SYSTEM}" >/dev/null
	docker rm -f "${TARGET_CONTAINER}" >/dev/null 2>&1 || true
	docker run -d --name "${TARGET_CONTAINER}" --hostname lss-test --privileged --cgroupns=host \
		-v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp:exec \
		-v "${RELEASE_DIR}:/srv/release:ro" "lss-test:${SYSTEM}" >/dev/null
	in_target 'for i in $(seq 60); do s=$(systemctl is-system-running 2>/dev/null || true); [[ $s == running || $s == degraded ]] && exit 0; sleep 1; done; exit 1'
	return
}

target_stop() {
	local status=$?
	set +e
	if [[ ${status} -ne 0 ]]; then
		echo "Diagnostics (exit status ${status}):"
		in_target 'ls -la /opt/lss /usr/local/sbin 2>&1; tail -n 80 /var/log/lss/*.log 2>/dev/null; journalctl -t lss -n 60 --no-pager' </dev/null
	fi
	docker rm -f "${TARGET_CONTAINER}" >/dev/null 2>&1
	exit "${status}"
}
