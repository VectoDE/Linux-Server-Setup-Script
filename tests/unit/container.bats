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

@test "the named volumes of the socket container belong to root, so the host user namespace can write them" {
	local data=${BATS_TEST_TMPDIR}/volume
	CTR_VOLUME_OWNER="$(id -u):$(id -g)"
	mkdir -p "${data}"
	chmod 0755 "${data}"
	# shellcheck disable=SC2329 # called by _ctr_root_volumes
	docker() {
		printf '%s\n' "$*" >>"${BATS_TEST_TMPDIR}/engine.log"
		[[ $* != "volume inspect --format {{.Mountpoint}} lss-portainer-data" ]] || printf '%s\n' "${data}"
		return 0
	}
	ctr_args docker web "${IMAGE}" --volume web-data:/data
	[ "${#CTR_ROOT_VOLUMES[@]}" -eq 0 ]
	ctr_args docker lss-portainer "${IMAGE}" --socket --volume lss-portainer-data:/data --volume "${BATS_TEST_TMPDIR}/pw:/run/pw:ro"
	[ "${CTR_ROOT_VOLUMES[*]}" = lss-portainer-data ]
	_ctr_root_volumes docker
	[ "$(stat -c '%a' "${data}")" = 700 ]
	grep -qF "gave the volume lss-portainer-data to root" "$(_files_run_dir)/changes"
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

# --- container firewall -------------------------------------------------------------------------------------------

@test "the container firewall lists the public and vpn ports of every module and reloads on a change" {
	LSS_MODULE=web
	fw_allow 443/tcp 3000/tcp:vpn 5432/tcp:local
	LSS_MODULE=mail
	fw_allow 25/tcp
	[ "$(fw_container_ports)" = $'tcp 25 any\ntcp 3000 10.66.0.0/24\ntcp 443 any' ]
	# No container module yet: nothing is written.
	fw_container_sync
	[ ! -e "$(fw_container_list)" ]
	: >"$(fw_container_list)"
	export STUB_ACTIVE_UNITS=lss-container-firewall.service
	fw_container_sync
	[ "$(cat "$(fw_container_list)")" = $'tcp 25 any\ntcp 3000 10.66.0.0/24\ntcp 443 any' ]
	grep -q 'systemctl reload lss-container-firewall.service' "${STUB_LOG}"
	: >"${STUB_LOG}"
	fw_container_sync
	run ! grep -q reload "${STUB_LOG}"
	LSS_MODULE=web fw_remove_module
	[ "$(cat "$(fw_container_list)")" = 'tcp 25 any' ]
}

# Records file_write calls in $BATS_TEST_TMPDIR/writes and reports a change.
record_writes() {
	# shellcheck disable=SC2329 # called by the functions under test
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${BATS_TEST_TMPDIR}/writes"
		cat >>"${BATS_TEST_TMPDIR}/writes"
		LSS_FILE_CHANGED=1
	}
	return
}

@test "ctr_firewall_setup installs the script, the unit and the list; removal waits for the last container module" {
	record_writes
	CTR_FIREWALL_SCRIPT=${BATS_TEST_TMPDIR}/lib/container-firewall
	ctr_firewall_setup
	local writes=${BATS_TEST_TMPDIR}/writes
	grep -qxF "== 0755 root:root ${CTR_FIREWALL_SCRIPT}" "${writes}"
	grep -qxF '== 0644 root:root /etc/systemd/system/lss-container-firewall.service' "${writes}"
	grep -qxF "ExecStart=${CTR_FIREWALL_SCRIPT} start" "${writes}"
	grep -qxF 'Before=network-pre.target docker.service podman.service k3s.service shutdown.target' "${writes}"
	[ -f "$(fw_container_list)" ]
	grep -q 'systemctl enable --now lss-container-firewall.service' "${STUB_LOG}"
	grep -q 'systemctl restart lss-container-firewall.service' "${STUB_LOG}"
	state_set k3s status installed
	: >"${STUB_LOG}"
	ctr_firewall_remove
	[ -f "$(fw_container_list)" ]
	run ! grep -q daemon-reload "${STUB_LOG}"
	state_set k3s status removed
	ctr_firewall_remove
	[ ! -e "$(fw_container_list)" ]
	grep -q 'systemctl daemon-reload' "${STUB_LOG}"
}

@test "ctr_firewall_verify needs the active unit, the table and every listed port" {
	TEST_RULESET=$(LSS_CONTAINER_PORTS=/dev/null bash "${REPO_ROOT}/libexec/lss-container-firewall" print)
	# A variable of the test: ctr_firewall_verify has a local "ruleset" that would hide one of that name.
	# shellcheck disable=SC2329 # called by ctr_firewall_verify
	nft() {
		printf '%s\n' "${TEST_RULESET}"
	}
	run ctr_firewall_verify
	[[ ${output} == *"is not active"* ]]
	export STUB_ACTIVE_UNITS=lss-container-firewall.service
	mkdir -p "${LSS_STATE_DIR}"
	: >"$(fw_container_list)"
	ctr_firewall_verify
	fw_allow 8080/tcp
	run ctr_firewall_verify
	[[ ${output} == *"does not let 8080/tcp through"* ]]
	TEST_RULESET=$(LSS_CONTAINER_PORTS=$(fw_container_list) bash "${REPO_ROOT}/libexec/lss-container-firewall" print)
	ctr_firewall_verify
	printf 'tcp 9 any\n' >>"$(fw_container_list)"
	run ctr_firewall_verify
	[[ ${output} == *"lists other ports than the firewall rules"* ]]
}

@test "the container firewall rule set: redirected connections only to listed ports, nothing straight to containers" {
	local ports=${BATS_TEST_TMPDIR}/ports output
	printf 'tcp 443 any\ntcp 3000 10.66.0.0/24\nudp 51820-51830 fd00::/64\nicmp 1 any\ntcp 80 nonsense\n\n' >"${ports}"
	output=$(LSS_CONTAINER_PORTS=${ports} LSS_CONTAINER_FORWARD_GUARD=/nonexistent bash "${REPO_ROOT}/libexec/lss-container-firewall" print)
	[[ ${output} == $'table inet lss_containers\ndelete table inet lss_containers\ntable inet lss_containers {'* ]]
	[[ ${output} == *$'\t\ttype filter hook forward priority -10; policy accept;\n\t\tct state established,related accept\n'* ]]
	[[ ${output} == *$'\t\tiifname "br-*" accept\n'* ]]
	[[ ${output} == *$'\t\toifname "cni0" ct status dnat jump published\n'* ]]
	[[ ${output} == *$'\t\toifname "podman*" ct state new drop\n'* ]]
	[[ ${output} != *'oifname "cni0" ct state new drop'* ]]
	[[ ${output} == *$'\t\tmeta l4proto tcp ct original proto-dst 443 accept\n'* ]]
	[[ ${output} == *$'\t\tip saddr 10.66.0.0/24 meta l4proto tcp ct original proto-dst 3000 accept\n'* ]]
	[[ ${output} == *$'\t\tip6 saddr fd00::/64 meta l4proto udp ct original proto-dst 51820-51830 accept\n'* ]]
	[[ ${output} != *icmp* && ${output} != *nonsense* && ${output} != *'proto-dst 80 '* ]]
	[[ ${output} == *$'\t\tdrop\n\t}\n}' ]]
	run bash "${REPO_ROOT}/libexec/lss-container-firewall" bogus
	[ "${status}" -eq 2 ]
}

@test "the container firewall drops other forwarding once lss turned it on for Docker" {
	local guard=${BATS_TEST_TMPDIR}/70-lss-docker.conf output
	output=$(LSS_CONTAINER_PORTS=/dev/null LSS_CONTAINER_FORWARD_GUARD=${guard} bash "${REPO_ROOT}/libexec/lss-container-firewall" print)
	[[ ${output} != *'oifname "docker0" accept'* ]]
	: >"${guard}"
	output=$(LSS_CONTAINER_PORTS=/dev/null LSS_CONTAINER_FORWARD_GUARD=${guard} bash "${REPO_ROOT}/libexec/lss-container-firewall" print)
	[[ ${output} == *$'\t\toifname "cni-podman*" ct state new drop\n\t\toifname "docker0" accept\n'* ]]
	[[ ${output} == *$'\t\toifname "flannel*" accept\n\t\tdrop\n\t}\n\tchain published {\n'* ]]
}

# --- engine, Compose, Trivy ---------------------------------------------------------------------------------------

@test "the engine is the module being installed or the installed one" {
	LSS_MODULE=portainer
	run ctr_engine
	[ "${status}" -eq 1 ]
	state_set podman status installed
	[ "$(ctr_engine)" = podman ]
	LSS_MODULE=docker
	[ "$(ctr_engine)" = docker ]
	[ "$(ctr_socket podman)" = /run/podman/podman.sock ]
	run ctr_socket lxc
	[ "${status}" -eq 1 ]
}

@test "Compose projects start only with docker and after the check" {
	command -v jq >/dev/null || skip "jq is not installed"
	local file=${BATS_TEST_TMPDIR}/compose.yaml
	: >"${file}"
	# shellcheck disable=SC2329 # called by ctr_compose_up
	docker() {
		printf 'docker %s\n' "$*" >>"${BATS_TEST_TMPDIR}/engine.log"
		if [[ $* == *config* ]]; then
			printf '{"services": {}}\n'
		fi
		return 0
	}
	run ctr_compose_up 'Bad Name' "${file}"
	[ "${status}" -eq 1 ]
	ctr_compose_up shop "${file}"
	grep -qxF "docker compose --project-name shop -f ${file} up --detach --remove-orphans --quiet-pull" "${BATS_TEST_TMPDIR}/engine.log"
	LSS_MODULE=podman
	run ctr_compose_up shop "${file}"
	[[ ${output} == *"need the docker module"* ]]
}

@test "Trivy is kept when it is current and removed with the last engine" {
	CTR_TRIVY=${BATS_TEST_TMPDIR}/trivy
	CTR_TRIVY_CACHE=${BATS_TEST_TMPDIR}/trivy-cache
	printf '#!/bin/sh\necho "Version: %s"\n' "${CTR_TRIVY_VERSION}" >"${CTR_TRIVY}"
	chmod +x "${CTR_TRIVY}"
	mkdir -p "${CTR_TRIVY_CACHE}"
	ctr_trivy_install
	run ! grep -q curl "${STUB_LOG}"
	state_set podman status installed
	ctr_trivy_remove
	[ -x "${CTR_TRIVY}" ]
	state_set podman status removed
	ctr_trivy_remove
	[ ! -e "${CTR_TRIVY}" ]
	[ ! -e "${CTR_TRIVY_CACHE}" ]
}

# --- modules ------------------------------------------------------------------------------------------------------

@test "the container modules declare their group, requirements and mutual conflicts" {
	[ "$(module_meta docker MOD_GROUP)" = container ]
	[ "$(module_meta portainer MOD_REQUIRES)" = "system docker|podman" ]
	[ "$(module_meta docker MOD_CONFLICTS)" = "podman k3s" ]
	[ "$(module_meta podman MOD_CONFLICTS)" = docker ]
	[ "$(module_meta k3s MOD_CONFLICTS)" = docker ]
	[ "$(module_meta portainer MOD_SECRETS)" = portainer-admin-password ]
	[[ $(module_meta k3s MOD_OPTIONS) == *"api_access|local|"* ]]
	run module_resolve docker podman
	[ "${status}" -eq 1 ]
	run module_resolve k3s docker
	[ "${status}" -eq 1 ]
	run module_resolve podman portainer
	[ "${status}" -eq 0 ]
	[[ ${output} == *$'podman\nportainer'* ]]
}

@test "the downloads of k3s, k3s-selinux and Trivy are pinned for both architectures" {
	local arch name
	for arch in x86_64 aarch64; do
		use_os debian-12 "${arch}"
		for name in k3s-v1.36.5+k3s1 "trivy-${CTR_TRIVY_VERSION}" k3s-selinux-el9 k3s-selinux-el10; do
			[[ $(fetch_entry "${name}") =~ ^[0-9a-f]{64}\ https://github.com/ ]]
		done
	done
}
