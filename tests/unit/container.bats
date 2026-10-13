#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# lib/container.sh: the container rules, the run helpers against stub engines, the Compose check, the container
# firewall and its rule set (libexec/lss-container-firewall).

IMAGE=docker.io/library/nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000

setup() {
	load helpers
	lss_test_setup
	use_os debian-12
	LSS_MODULE=docker
}

# --- ctr_args -----------------------------------------------------------------------------------------------------

@test "every container gets the hardening options and limits" {
	ctr_args docker web "${IMAGE}" --publish 127.0.0.1:8080:80 --volume web-data:/data:ro --cap NET_BIND_SERVICE -- nginx -g 'daemon off;'
	local args="${CTR_ARGS[*]}"
	[[ ${args} == "--name web --label lss.managed=true --security-opt no-new-privileges --cap-drop ALL "* ]]
	[[ ${args} == *"--publish 127.0.0.1:8080:80"* ]]
	[[ ${args} == *"--volume web-data:/data:ro"* ]]
	[[ ${args} == *"--cap-add NET_BIND_SERVICE"* ]]
	[[ ${args} == *"--read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m"* ]]
	[[ ${args} == *"--memory 512m --memory-swap 512m --pids-limit 256 --restart unless-stopped ${IMAGE} nginx -g daemon off;" ]]
}

@test "podman containers get no restart policy; --writable and own limits" {
	ctr_args podman app "${IMAGE}" --writable --memory 1g --pids 64
	local args="${CTR_ARGS[*]}"
	[[ ${args} != *--read-only* ]]
	[[ ${args} != *--restart* ]]
	[[ ${args} == *"--memory 1g --memory-swap 1g --pids-limit 64 ${IMAGE}" ]]
}

@test "images must name their registry and be pinned by digest" {
	run ctr_args docker web nginx:latest
	[ "${status}" -eq 1 ]
	run ctr_args docker web docker.io/library/nginx:1.27
	[ "${status}" -eq 1 ]
	run ctr_args docker web library/nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
	[ "${status}" -eq 1 ]
	[[ ${output} == *"pinned by digest"* ]]
}

@test "dangerous options are refused" {
	run ctr_args docker web "${IMAGE}" --cap SYS_ADMIN
	[[ ${output} == *"SYS_ADMIN is not allowed"* ]]
	run ctr_args docker web "${IMAGE}" --network host
	[[ ${output} == *"never the host network"* ]]
	run ctr_args docker web "${IMAGE}" --publish 8080:80
	[[ ${output} == *"ADDRESS:HOST_PORT:CONTAINER_PORT"* ]]
	run ctr_args docker web "${IMAGE}" --privileged true
	[[ ${output} == *"unknown option '--privileged'"* ]]
	run ctr_args docker web "${IMAGE}" --user root
	[ "${status}" -eq 1 ]
	run ctr_args docker web "${IMAGE}" --volume data
	[ "${status}" -eq 1 ]
	run ctr_args docker web "${IMAGE}" --volume /srv/data:/../etc
	[ "${status}" -eq 1 ]
	run ctr_args docker web "${IMAGE}" --volume /srv/data:/data:shared
	[ "${status}" -eq 1 ]
	run ctr_args docker web "${IMAGE}" --memory
	[[ ${output} == *"--memory needs a value"* ]]
}

@test "the engine socket and system paths are never mounted" {
	local path
	for path in /var/run/docker.sock /run/podman/podman.sock /run /var/lib/docker /srv/x/containerd.sock \
		/etc /etc/passwd /etc/lss/secrets/db /etc/lss/lss.conf /etc/letsencrypt/live/a/privkey.pem /root/.ssh \
		/var/lib/lss /var/lib/lss-pgadmin /var/log/lss /run/systemd/private /run/dbus/system_bus_socket /proc/1 /; do
		run ctr_args docker web "${IMAGE}" --volume "${path}:/mnt"
		[ "${status}" -eq 1 ]
	done
	run ctr_args docker web "${IMAGE}" --volume /var/run/docker.sock:/var/run/docker.sock
	[[ ${output} == *"hands over the container engine"* ]]
	run ctr_args docker web "${IMAGE}" --volume /etc/passwd:/etc/passwd:ro
	[[ ${output} == *"/etc/passwd may not be mounted into a container"* ]]
}

@test "a container may mount its own directory below /etc/lss/containers, no other" {
	ctr_args docker web "${IMAGE}" --volume /etc/lss/containers/web/app.conf:/app.conf:ro --volume /srv/web:/srv
	[[ ${CTR_ARGS[*]} == *"--volume /etc/lss/containers/web/app.conf:/app.conf:ro --volume /srv/web:/srv"* ]]
	run ctr_args docker web "${IMAGE}" --volume /etc/lss/containers/other/app.conf:/app.conf:ro
	[ "${status}" -eq 1 ]
	run ctr_args docker web "${IMAGE}" --volume /etc/lss/containers:/c:ro
	[ "${status}" -eq 1 ]
}

@test "symbolic links are followed: a link to the socket or a system directory is refused" {
	local dir=${BATS_TEST_TMPDIR}/links
	mkdir -p "${dir}"
	ln -s /var/run/docker.sock "${dir}/sock"
	ln -s /etc "${dir}/etc"
	ln -s /root "${dir}/home"
	ln -s "${BATS_TEST_TMPDIR}" "${dir}/fine"
	run ctr_args docker web "${IMAGE}" --volume "${dir}/sock:/data"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"hands over the container engine"* ]]
	run ctr_args docker web "${IMAGE}" --volume "${dir}/etc/ssh:/data:ro"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"may not be mounted into a container (it leads to /etc/ssh)"* ]]
	run ctr_args docker web "${IMAGE}" --volume "${dir}/home:/data"
	[ "${status}" -eq 1 ]
	ctr_args docker web "${IMAGE}" --volume "${dir}/fine:/data"
}

@test "only Portainer gets the socket, in the host user namespace, without SELinux separation on RHEL" {
	run ctr_args docker web "${IMAGE}" --socket
	[ "${status}" -eq 1 ]
	[[ ${output} == *"only lss-portainer may have the socket"* ]]
	ctr_args docker lss-portainer "${IMAGE}" --socket
	[[ ${CTR_ARGS[*]} == *"--volume /var/run/docker.sock:/var/run/docker.sock --userns host"* ]]
	[[ ${CTR_ARGS[*]} != *label=disable* ]]
	use_os rocky-9
	ctr_args podman lss-portainer "${IMAGE}" --socket
	[[ ${CTR_ARGS[*]} == *"--volume /run/podman/podman.sock:/var/run/docker.sock --userns host --security-opt label=disable"* ]]
}

# --- ctr_run and ctr_remove ---------------------------------------------------------------------------------------

# A stub engine: "container inspect" answers from CTR_HASH and CTR_RUNNING; every call is logged.
fake_engine() {
	printf '%s\n' "$*" >>"${BATS_TEST_TMPDIR}/engine.log"
	case "$1 $2" in
	"container inspect")
		[[ -n ${CTR_HASH:-} ]] || return 1
		case $* in
		*lss.hash*) printf '%s\n' "${CTR_HASH}" ;;
		*Running*) printf '%s\n' "${CTR_RUNNING:-true}" ;;
		*) ;;
		esac
		;;
	*) ;;
	esac
	return 0
}

@test "ctr_run creates a container once and keeps an unchanged one" {
	# shellcheck disable=SC2329 # called by ctr_run
	docker() {
		fake_engine "$@"
	}
	ctr_run web "${IMAGE}" --publish 127.0.0.1:8080:80
	grep -q "^pull ${IMAGE}$" "${BATS_TEST_TMPDIR}/engine.log"
	grep -q '^run --detach --label lss.hash=' "${BATS_TEST_TMPDIR}/engine.log"
	CTR_HASH=$(sed -n 's/^run --detach --label lss.hash=\([0-9a-f]*\) .*/\1/p' "${BATS_TEST_TMPDIR}/engine.log")
	: >"${BATS_TEST_TMPDIR}/engine.log"
	ctr_run web "${IMAGE}" --publish 127.0.0.1:8080:80
	run ! grep -q -e '^pull' -e '^run' -e '^start' "${BATS_TEST_TMPDIR}/engine.log"
	CTR_RUNNING=false
	ctr_run web "${IMAGE}" --publish 127.0.0.1:8080:80
	grep -q '^start web$' "${BATS_TEST_TMPDIR}/engine.log"
	CTR_RUNNING=true
	: >"${BATS_TEST_TMPDIR}/engine.log"
	ctr_run web "${IMAGE}" --publish 127.0.0.1:8081:80
	grep -q '^rm --force web$' "${BATS_TEST_TMPDIR}/engine.log"
	grep -q '^run --detach' "${BATS_TEST_TMPDIR}/engine.log"
}

@test "ctr_run with Podman creates the container and a systemd unit; ctr_remove deletes both" {
	LSS_MODULE=podman
	# shellcheck disable=SC2329 # called by ctr_run
	podman() {
		fake_engine "$@"
	}
	local units=${BATS_TEST_TMPDIR}/units
	mkdir -p "${units}"
	# shellcheck disable=SC2329 # called by ctr_run
	svc_unit() {
		cat >"${units}/$1"
	}
	ctr_run app "${IMAGE}"
	grep -q '^create --label lss.hash=' "${BATS_TEST_TMPDIR}/engine.log"
	grep -q 'start --attach app' "${units}/lss-ctr-app.service"
	grep -q 'systemctl enable --now lss-ctr-app.service' "${STUB_LOG}"
	CTR_HASH=x
	ctr_remove app
	grep -q '^rm --force app$' "${BATS_TEST_TMPDIR}/engine.log"
}

@test "ctr_run needs an engine" {
	LSS_MODULE=portainer
	run ctr_run web "${IMAGE}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"neither docker nor podman is installed"* ]]
}

# --- Compose ------------------------------------------------------------------------------------------------------

compose_json() {
	cat <<EOF
{"services": {
	"good": {"image": "${IMAGE}", "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "read_only": true,
		"mem_limit": "256m", "pids_limit": 64, "ports": [{"host_ip": "127.0.0.1", "target": 80, "published": "8080"}],
		"volumes": [{"type": "volume", "source": "data", "target": "/data"},
			{"type": "bind", "source": "/etc/lss/containers/compose-good/app.conf", "target": "/app.conf"}]},
	"bad": {"image": "nginx:latest", "privileged": true, "cap_add": ["SYS_ADMIN", "ALL", "CHOWN"], "network_mode": "host",
		"pid": "container:good", "security_opt": ["seccomp:unconfined"], "devices": ["/dev/sda:/dev/sda"],
		"ports": [{"target": 80, "published": "80"}],
		"volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"},
			{"type": "bind", "source": "${LINK}", "target": "/x"}]}
}}
EOF
	return
}

@test "Compose files are checked against the same rules, symbolic links included" {
	command -v jq >/dev/null || skip "jq is not installed"
	LINK=${BATS_TEST_TMPDIR}/etc-link
	ln -s /etc "${LINK}"
	local file=${BATS_TEST_TMPDIR}/compose.yaml
	: >"${file}"
	# shellcheck disable=SC2329 # called by ctr_compose_check
	docker() {
		compose_json
	}
	run ctr_compose_check "${file}"
	[ "${status}" -eq 1 ]
	[[ ${output} != *"good:"* ]]
	local problem
	for problem in "bad: the image is not pinned by digest" "bad: runs privileged" "bad: keeps capabilities" \
		"bad: adds the capability SYS_ADMIN" "bad: adds the capability ALL" "bad: may gain new privileges" \
		"bad: lifts a security profile" "bad: has host devices" "bad: has a writable root file system" \
		"bad: has no memory limit" "bad: has no process limit" "bad: shares a namespace" \
		"bad: publishes a port without an address" "bad: mounting /var/run/docker.sock hands over the container engine" \
		"bad: ${LINK} may not be mounted into a container (it leads to /etc)"; do
		[[ ${output} == *"${problem}"* ]]
	done
	[[ ${output} != *"capability CHOWN"* ]]
}

@test "a Compose file that cannot be read fails the check" {
	run ctr_compose_check "${BATS_TEST_TMPDIR}/missing.yaml"
	[ "${status}" -eq 1 ]
	: >"${BATS_TEST_TMPDIR}/compose.yaml"
	# shellcheck disable=SC2329 # called by ctr_compose_check
	docker() {
		return 1
	}
	run ctr_compose_check "${BATS_TEST_TMPDIR}/compose.yaml"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"docker compose cannot read"* ]]
}
