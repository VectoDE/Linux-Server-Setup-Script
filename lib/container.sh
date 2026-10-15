# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Containers: the engine of the server (docker or podman), hardened container runs for modules that ship a service as
# a container, a check for Compose files, the container firewall and the Trivy scanner.
#
# Every container lss starts follows the same rules (CIS Docker Benchmark, section 5):
#   - the image names its registry and is pinned by digest (registry/name@sha256:...), so a moved tag cannot change
#     what runs
#   - no new privileges, every capability dropped except the ones named, never --privileged, never the network, PID
#     or IPC namespace of the host
#   - a read-only root file system with a small /tmp, unless the container needs a writable one
#   - memory and process limits
#   - published ports name their address; the container firewall decides who reaches them (lib/firewall.sh)
#   - the socket of a container engine is never mounted, except into the management tool (CTR_SOCKET_CONTAINERS)

# Containers that may mount the socket of the engine. Whoever controls that socket controls the host; Portainer is a
# management tool and needs it, nothing else does.
CTR_SOCKET_CONTAINERS="lss-portainer"
# Capabilities no container of lss gets, whatever a module asks for: each one hands over the kernel or other processes.
CTR_DENIED_CAPS="SYS_ADMIN SYS_MODULE SYS_RAWIO SYS_PTRACE SYS_BOOT SYS_TIME DAC_READ_SEARCH MAC_ADMIN MAC_OVERRIDE BPF PERFMON NET_ADMIN"
CTR_DEFAULT_MEMORY=512m
CTR_DEFAULT_PIDS=256
CTR_TMPFS_OPTIONS=rw,noexec,nosuid,nodev,size=64m
CTR_FIREWALL_SCRIPT=/usr/local/lib/lss/container-firewall
CTR_MODULES="docker podman k3s"
# Trivy scans the images of the server every day (libexec/lss-guard). Pinned release, checksum in data/checksums.txt.
CTR_TRIVY=/usr/local/bin/trivy
CTR_TRIVY_VERSION=0.74.0
CTR_TRIVY_CACHE=/var/cache/lss-trivy

# ctr_engine: docker or podman, whichever is installed (or being installed); fails when there is none.
ctr_engine() {
	local engine
	for engine in docker podman; do
		if [[ ${LSS_MODULE:-} == "${engine}" ]] || state_installed "${engine}"; then
			printf '%s' "${engine}"
			return 0
		fi
	done
	return 1
}

# ctr_socket ENGINE: the API socket of the engine on the host.
ctr_socket() {
	local engine=$1
	case ${engine} in
	docker) printf '/var/run/docker.sock' ;;
	podman) printf '/run/podman/podman.sock' ;;
	*) die "container: unknown engine '${engine}'." ;;
	esac
	return
}

# _ctr_engine_path PATH: PATH is the socket of a container engine or a directory that holds one.
_ctr_engine_path() {
	local path=$1
	path=${path%/}
	case ${path} in
	'' | /run | /var | /var/run | /var/lib) return 0 ;;
	/run/docker* | /var/run/docker* | /run/podman* | /var/run/podman* | /run/containerd* | /var/run/containerd*) return 0 ;;
	/run/crio* | /var/run/crio* | /run/k3s* | /var/run/k3s* | /var/lib/docker* | /var/lib/containers*) return 0 ;;
	/var/lib/containerd* | /var/lib/rancher*) return 0 ;;
	*/docker.sock | */podman.sock | */containerd.sock) return 0 ;;
	*) return 1 ;;
	esac
}

# Host files a container may mount from /etc: only its own directory /etc/lss/containers/NAME (configuration and
# secrets lss hands to that one container).
CTR_CONFIG_DIR=/etc/lss/containers

# _ctr_host_path_denied NAME PATH: system directories, credentials, the state and logs of lss and the sockets of
# systemd and D-Bus, which no container gets. All of /etc is denied except the directory of container NAME.
_ctr_host_path_denied() {
	local name=$1 path=$2
	path=${path%/}
	if [[ ${path} == "${CTR_CONFIG_DIR}/${name}" || ${path} == "${CTR_CONFIG_DIR}/${name}/"* ]]; then
		return 1
	fi
	case ${path} in
	'' | /etc | /etc/* | /usr | /bin | /sbin | /lib | /lib64 | /home | /root | /boot | /proc | /sys | /dev) return 0 ;;
	/root/* | /boot/* | /proc/* | /sys/* | /dev/*) return 0 ;;
	/var/lib/lss | /var/lib/lss/* | /var/lib/lss-* | /var/log/lss | /var/log/lss/* | /var/log/lss-*) return 0 ;;
	/run/systemd | /run/systemd/* | /var/run/systemd | /var/run/systemd/*) return 0 ;;
	/run/dbus | /run/dbus/* | /var/run/dbus | /var/run/dbus/*) return 0 ;;
	*) return 1 ;;
	esac
}

# _ctr_host_source_problem NAME SOURCE: prints why the host path SOURCE may not be mounted into container NAME, or
# nothing. Both the path as written and the path it resolves to (symbolic links followed) are checked, so a link to a
# socket or a system directory does not slip through. Fails when the path cannot be resolved.
_ctr_host_source_problem() {
	local name=$1 source=$2 resolved path
	if [[ ! ${source} =~ ^/[A-Za-z0-9._/-]*$ || /${source}/ == */../* ]]; then
		printf '%s is not a valid host path' "${source}"
		return 0
	fi
	resolved=$(realpath -m -- "${source}") || return 1
	[[ ${resolved} == /* ]] || return 1
	for path in "${source}" "${resolved}"; do
		if _ctr_engine_path "${path}"; then
			printf 'mounting %s hands over the container engine; only %s may have its socket' "${source}" "${CTR_SOCKET_CONTAINERS}"
			return 0
		fi
		if _ctr_host_path_denied "${name}" "${path}"; then
			printf '%s may not be mounted into a container' "${source}"
			[[ ${path} == "${source}" ]] || printf ' (it leads to %s)' "${path}"
			return 0
		fi
	done
	return 0
}

_ctr_check_publish() {
	local name=$1 spec=$2
	[[ ${spec} =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3}|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}:[0-9]{1,5}(/(tcp|udp))?$ ]] ||
		die "container ${name}: publish '${spec}' must be ADDRESS:HOST_PORT:CONTAINER_PORT[/tcp|udp], for example 127.0.0.1:9443:9443."
	return
}

_ctr_check_volume() {
	local name=$1 spec=$2 source target rest options='' problem
	[[ ${spec} == *:* ]] || die "container ${name}: volume '${spec}' must be SOURCE:TARGET[:OPTIONS]."
	source=${spec%%:*}
	rest=${spec#*:}
	target=${rest%%:*}
	if [[ ${rest} == *:* ]]; then
		options=${rest#*:}
	fi
	[[ ${target} =~ ^/[A-Za-z0-9._/-]*$ && /${target}/ != */../* ]] ||
		die "container ${name}: '${target}' is not a valid path inside the container."
	[[ -z ${options} || ${options} =~ ^(ro|rw|z|Z)(,(ro|rw|z|Z))*$ ]] ||
		die "container ${name}: volume options '${options}' (allowed: ro, rw, z, Z)."
	if [[ ${source} != /* ]]; then
		[[ ${source} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "container ${name}: '${source}' is not a volume name."
		return 0
	fi
	problem=$(_ctr_host_source_problem "${name}" "${source}") || die "container ${name}: cannot resolve the host path ${source}."
	[[ -z ${problem} ]] || die "container ${name}: ${problem}."
	return
}

_ctr_check_cap() {
	local name=$1 cap=$2
	cap=${cap#CAP_}
	[[ ${cap} =~ ^[A-Z_]+$ ]] || die "container ${name}: '${cap}' is not a capability."
	[[ " ${CTR_DENIED_CAPS} " != *" ${cap} "* ]] || die "container ${name}: the capability ${cap} is not allowed."
	return
}

# ctr_args ENGINE NAME IMAGE [OPTION...] [-- COMMAND...]: checks a container against the rules above and sets CTR_ARGS
# to the arguments of "ENGINE run" or "ENGINE create" that enforce them (options, image, command). Options:
#   --publish ADDRESS:HOST_PORT:CONTAINER_PORT[/PROTO]   --volume SOURCE:TARGET[:ro]   --tmpfs PATH
#   --cap CAPABILITY   --env KEY=VALUE   --env-file FILE   --user UID[:GID]   --network NAME
#   --memory SIZE (default 512m)   --pids N (default 256)   --writable (no read-only root)
#   --socket (the engine's socket as /var/run/docker.sock; only for CTR_SOCKET_CONTAINERS)
ctr_args() {
	local engine=$1 name=$2 image=$3 option value registry memory=${CTR_DEFAULT_MEMORY} pids=${CTR_DEFAULT_PIDS}
	local writable=0 socket=0 tmp=0
	local -a args=() command=() volumes=()
	shift 3
	[[ ${engine} == docker || ${engine} == podman ]] || die "container: unknown engine '${engine}'."
	[[ ${name} =~ ^[a-z0-9][a-z0-9_.-]*$ ]] || die "container: '${name}' is not a valid container name."
	registry=${image%%/*}
	[[ ${image} =~ ^[a-z0-9.:-]+/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ && (${registry} == *.* || ${registry} == localhost*) ]] ||
		die "container ${name}: the image '${image}' must name its registry and be pinned by digest (registry/name@sha256:...)."
	args=(--name "${name}" --label lss.managed=true --security-opt no-new-privileges --cap-drop ALL)
	while [[ $# -gt 0 ]]; do
		option=$1
		shift
		case ${option} in
		--)
			command=("$@")
			break
			;;
		--writable)
			writable=1
			continue
			;;
		--socket)
			socket=1
			continue
			;;
		*) ;;
		esac
		[[ $# -gt 0 ]] || die "container ${name}: ${option} needs a value."
		value=$1
		shift
		case ${option} in
		--publish)
			_ctr_check_publish "${name}" "${value}"
			args+=(--publish "${value}")
			;;
		--volume)
			_ctr_check_volume "${name}" "${value}"
			args+=(--volume "${value}")
			if [[ ${value} != /* ]]; then
				volumes+=("${value%%:*}")
			fi
			;;
		--tmpfs)
			[[ ${value} =~ ^/[A-Za-z0-9._/-]+$ ]] || die "container ${name}: '${value}' is not a valid tmpfs path."
			[[ ${value} != /tmp ]] || tmp=1
			args+=(--tmpfs "${value}:${CTR_TMPFS_OPTIONS}")
			;;
		--cap)
			_ctr_check_cap "${name}" "${value}"
			args+=(--cap-add "${value#CAP_}")
			;;
		--env)
			[[ ${value} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || die "container ${name}: '${value%%=*}' is not KEY=VALUE."
			args+=(--env "${value}")
			;;
		--env-file)
			[[ ${value} == /* ]] || die "container ${name}: the environment file '${value}' needs an absolute path."
			args+=(--env-file "${value}")
			;;
		--user)
			[[ ${value} =~ ^[0-9]+(:[0-9]+)?$ ]] || die "container ${name}: --user takes UID or UID:GID, got '${value}'."
			args+=(--user "${value}")
			;;
		--network)
			[[ ${value} =~ ^[a-z0-9][a-z0-9_.-]*$ && ${value} != host ]] ||
				die "container ${name}: the network '${value}' is not allowed (never the host network)."
			args+=(--network "${value}")
			;;
		--memory)
			[[ ${value} =~ ^[0-9]+[kmg]$ ]] || die "container ${name}: --memory takes a size such as 256m or 1g, got '${value}'."
			memory=${value}
			;;
		--pids)
			[[ ${value} =~ ^[1-9][0-9]*$ ]] || die "container ${name}: --pids takes a positive number, got '${value}'."
			pids=${value}
			;;
		*) die "container ${name}: unknown option '${option}'." ;;
		esac
	done
	if [[ ${socket} == 1 ]]; then
		[[ " ${CTR_SOCKET_CONTAINERS} " == *" ${name} "* ]] ||
			die "container ${name}: only ${CTR_SOCKET_CONTAINERS} may have the socket of the container engine."
		# The engine's API is root on the host, so the container runs in the host's user namespace to reach it; on the
		# RHEL family SELinux separation is lifted for it, as the socket carries the label of the engine.
		args+=(--volume "$(ctr_socket "${engine}"):/var/run/docker.sock" --userns host)
		if os_is_rhel; then
			args+=(--security-opt label=disable)
		fi
	fi
	if [[ ${writable} == 0 ]]; then
		args+=(--read-only)
		if [[ ${tmp} == 0 ]]; then
			args+=(--tmpfs "/tmp:${CTR_TMPFS_OPTIONS}")
		fi
	fi
	args+=(--memory "${memory}" --memory-swap "${memory}" --pids-limit "${pids}")
	if [[ ${engine} == docker ]]; then
		# Back after a reboot or a crash; Podman containers are started by their systemd unit instead.
		args+=(--restart unless-stopped)
	fi
	CTR_ARGS=("${args[@]}" "${image}" "${command[@]}")
	# Named volumes of a container in the host user namespace (see _ctr_root_volumes).
	CTR_ROOT_VOLUMES=()
	if [[ ${socket} == 1 ]]; then
		CTR_ROOT_VOLUMES=("${volumes[@]}")
	fi
	return
}

# _ctr_root_volumes ENGINE: hands the volumes in CTR_ROOT_VOLUMES to root. With Docker's user namespace remapping a
# new volume belongs to the remapped root, but a container in the host user namespace runs as the real root, which
# without capabilities may not write there.
_ctr_root_volumes() {
	local engine=$1 volume path owner=${CTR_VOLUME_OWNER:-0:0}
	for volume in "${CTR_ROOT_VOLUMES[@]}"; do
		if ! "${engine}" volume inspect "${volume}" >/dev/null 2>&1; then
			log_command "${engine}" volume create "${volume}" || die "container: ${engine} cannot create the volume ${volume}."
			files_note_change "created the volume ${volume}"
		fi
		path=$("${engine}" volume inspect --format '{{.Mountpoint}}' "${volume}") ||
			die "container: ${engine} cannot inspect the volume ${volume}."
		[[ -d ${path} ]] || die "container: the volume ${volume} has no directory (${path:-none})."
		if [[ $(stat -c "%u:%g %a" "${path}") != "${owner} 700" ]]; then
			chown -R "${owner}" -- "${path}"
			chmod 0700 -- "${path}"
			files_note_change "gave the volume ${volume} to root"
		fi
	done
	return
}

_ctr_unit() {
	local name=$1
	printf 'lss-ctr-%s.service' "${name}"
	return
}

# ctr_running NAME: the container exists and runs.
ctr_running() {
	local name=$1 engine
	engine=$(ctr_engine) || return 1
	[[ $("${engine}" container inspect --format '{{.State.Running}}' "${name}" 2>/dev/null) == true ]]
	return
}

_ctr_delete() {
	local engine=$1 name=$2
	"${engine}" container inspect "${name}" >/dev/null 2>&1 || return 0
	if [[ ${engine} == podman ]]; then
		systemctl stop "$(_ctr_unit "${name}")" >/dev/null 2>&1 || true
	fi
	log_command "${engine}" rm --force "${name}" || die "container ${name}: ${engine} cannot remove the old container."
	return
}

# Podman has no daemon that restarts containers; a systemd unit of lss starts and stops each one.
_ctr_podman_unit() {
	local name=$1 podman
	podman=$(command -v podman)
	svc_unit "$(_ctr_unit "${name}")" <<EOF
# Managed by lss (module ${LSS_MODULE:-lss}). Runs the container ${name}; lss creates it (podman create).
[Unit]
Description=Container ${name} (lss)
Wants=network-online.target
After=network-online.target ${FW_CONTAINER_UNIT}.service

[Service]
ExecStart=${podman} start --attach ${name}
ExecStop=${podman} stop --time 10 ${name}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
	return
}

# ctr_run NAME IMAGE [OPTION...] [-- COMMAND...]: runs a container as ctr_args describes it, with the engine of the
# server. A container of that name with the same definition (label lss.hash) is left alone and only started if it
# stopped; otherwise the image is pulled and the container created again. Docker brings it back after a reboot
# (restart policy unless-stopped), Podman through the unit lss-ctr-NAME.service.
ctr_run() {
	local name=$1 image=$2 engine hash current unit
	engine=$(ctr_engine) || die "container ${name}: neither docker nor podman is installed."
	ctr_args "${engine}" "$@"
	_ctr_root_volumes "${engine}"
	hash=$(printf '%s\n' "${engine}" "${CTR_ARGS[@]}" | sha256sum | cut -c 1-16)
	unit=$(_ctr_unit "${name}")
	current=$("${engine}" container inspect --format '{{index .Config.Labels "lss.hash"}}' "${name}" 2>/dev/null || true)
	if [[ ${current} != "${hash}" ]]; then
		log_info "Pulling ${image}"
		log_command "${engine}" pull "${image}" || die "container ${name}: ${engine} cannot pull ${image}."
		_ctr_delete "${engine}" "${name}"
		if [[ ${engine} == docker ]]; then
			log_command docker run --detach --label "lss.hash=${hash}" "${CTR_ARGS[@]}" ||
				die "container ${name}: docker cannot start it; see the log."
		else
			log_command podman create --label "lss.hash=${hash}" "${CTR_ARGS[@]}" ||
				die "container ${name}: podman cannot create it; see the log."
		fi
		files_note_change "container ${name}"
	fi
	if [[ ${engine} == podman ]]; then
		_ctr_podman_unit "${name}"
		if [[ ${current} != "${hash}" ]] && svc_is_active "${unit}"; then
			svc_restart "${unit}" || die "container ${name}: ${unit} does not start."
		fi
		svc_enable "${unit}"
	elif ! ctr_running "${name}"; then
		log_command docker start "${name}" || die "container ${name}: docker cannot start it; see the log."
		files_note_change "started container ${name}"
	fi
	return
}

# ctr_remove NAME: stops and deletes the container (its named volumes stay).
ctr_remove() {
	local name=$1 engine unit
	unit=$(_ctr_unit "${name}")
	if [[ -f /etc/systemd/system/${unit} ]]; then
		svc_disable "${unit}"
		file_remove "/etc/systemd/system/${unit}"
		svc_daemon_reload
	fi
	engine=$(ctr_engine) || return 0
	if "${engine}" container inspect "${name}" >/dev/null 2>&1; then
		_ctr_delete "${engine}" "${name}"
		files_note_change "removed container ${name}"
	fi
	return
}

# The rules of ctr_args for Compose files, as a jq program over the output of "docker compose config --format json":
# one line "SERVICE: problem" per violation. $denied: CTR_DENIED_CAPS. Host paths of bind mounts are checked by the
# shell afterwards (CTR_COMPOSE_BINDS), because only realpath can follow their symbolic links.
# shellcheck disable=SC2016 # jq variables, not shell variables
CTR_COMPOSE_RULES='
($denied | split(" ")) as $deny |
.services // {} | to_entries[] | .key as $name | .value as $s |
(
	(if (($s.image // "") | test("^[a-z0-9.:-]+/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")) then empty
		else "the image is not pinned by digest (registry/name@sha256:...)" end),
	(if $s.privileged == true then "runs privileged" else empty end),
	(if any($s.cap_drop[]?; . == "ALL") then empty else "keeps capabilities (cap_drop: [ALL])" end),
	($s.cap_add[]? | ascii_upcase | ltrimstr("CAP_") | select(. == "ALL" or (. as $c | $deny | index($c)))
		| "adds the capability \(.)"),
	(if any($s.security_opt[]?; test("^no-new-privileges([:=]true)?$")) then empty
		else "may gain new privileges (security_opt: [no-new-privileges:true])" end),
	(if any($s.security_opt[]?; test("unconfined|^label[:=]disable|^no-new-privileges[:=]false"))
		then "lifts a security profile (security_opt)" else empty end),
	(if ($s.devices // []) | length > 0 then "has host devices (devices)" else empty end),
	(if $s.read_only == true or ($s.labels["lss.writable"]? // "") == "true" then empty
		else "has a writable root file system (read_only: true, or the label lss.writable: \"true\")" end),
	(if ($s.mem_limit // $s.deploy.resources.limits.memory // null) == null then "has no memory limit (mem_limit)" else empty end),
	(if ($s.pids_limit // $s.deploy.resources.limits.pids // null) == null then "has no process limit (pids_limit)" else empty end),
	(if ([$s.network_mode, $s.pid, $s.ipc, $s.uts, $s.userns_mode, $s.cgroup] | any(. == "host"))
		or (($s.network_mode // "") | startswith("container:")) or (($s.pid // "") | startswith("container:"))
		then "shares a namespace of the host or another container" else empty end),
	(if any($s.ports[]?; (.host_ip // "") == "") then "publishes a port without an address (host_ip)" else empty end)
) | "\($name): \(.)"'
# "SERVICE<TAB>SOURCE" for every bind mount.
# shellcheck disable=SC2016 # jq variables, not shell variables
CTR_COMPOSE_BINDS='.services // {} | to_entries[] | .key as $name | .value.volumes[]? | select(.type == "bind") | "\($name)\t\(.source // "")"'

# ctr_compose_check FILE: checks every service of a Compose file against the container rules. docker compose resolves
# the file first (extends, anchors, defaults), so the checks see what Compose would run. Prints each violation and fails
# when there is one; a file it cannot read or check fails as well.
ctr_compose_check() {
	local file=$1 json problems binds service source problem line
	[[ -r ${file} ]] || die "container: cannot read the Compose file ${file}."
	json=$(docker compose -f "${file}" config --format json 2>/dev/null) ||
		die "container: docker compose cannot read ${file} (docker compose -f ${file} config shows why)."
	problems=$(jq -r --arg denied "${CTR_DENIED_CAPS}" "${CTR_COMPOSE_RULES}" <<<"${json}") ||
		die "container: jq cannot check ${file}."
	binds=$(jq -r "${CTR_COMPOSE_BINDS}" <<<"${json}") || die "container: jq cannot read the mounts of ${file}."
	while IFS=$'\t' read -r service source; do
		[[ -n ${service} ]] || continue
		problem=$(_ctr_host_source_problem "compose-${service}" "${source}") ||
			die "container: cannot resolve the host path ${source} of ${service} in ${file}."
		[[ -z ${problem} ]] || problems+=$'\n'"${service}: ${problem}"
	done <<<"${binds}"
	problems=$(sed '/^$/d' <<<"${problems}")
	[[ -n ${problems} ]] || return 0
	while IFS= read -r line; do
		log_error "${file}: ${line}"
	done <<<"${problems}"
	return 1
}

# ctr_compose_up PROJECT FILE: starts a Compose project after ctr_compose_check passed (Docker only).
ctr_compose_up() {
	local project=$1 file=$2
	[[ $(ctr_engine) == docker ]] || die "container: Compose projects need the docker module."
	[[ ${project} =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "container: '${project}' is not a valid Compose project name."
	ctr_compose_check "${file}" || die "container: ${file} breaks the container rules; see above."
	log_command docker compose --project-name "${project}" -f "${file}" up --detach --remove-orphans --quiet-pull ||
		die "container: docker compose cannot start ${project}; see the log."
	return
}

# ctr_firewall_setup: installs the container firewall (libexec/lss-container-firewall). docker, podman and k3s share it
# and write the same files, so the managed copies never differ.
ctr_firewall_setup() {
	local list changed=0 unit=${FW_CONTAINER_UNIT}.service
	pkg_install nftables
	install -d -m 0755 "$(dirname "${CTR_FIREWALL_SCRIPT}")"
	file_write 0755 root:root "${CTR_FIREWALL_SCRIPT}" <"${LSS_ROOT}/libexec/lss-container-firewall"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	svc_unit "${unit}" <<EOF
# Managed by lss (container modules). Published container ports stay behind the firewall rules of lss.
[Unit]
Description=lss container firewall: published container ports only where lss opened them
Wants=network-pre.target
Before=network-pre.target docker.service podman.service k3s.service shutdown.target
Conflicts=shutdown.target
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${CTR_FIREWALL_SCRIPT} start
ExecReload=${CTR_FIREWALL_SCRIPT} reload
ExecStop=${CTR_FIREWALL_SCRIPT} stop

[Install]
WantedBy=multi-user.target
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	list=$(fw_container_list)
	if [[ ! -f ${list} ]]; then
		install -d -m 0755 "$(dirname "${list}")"
		: >"${list}"
	fi
	fw_container_sync
	svc_enable "${unit}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${unit}" || die "${LSS_MODULE}: the container firewall does not start; see journalctl -u ${unit}."
	fi
	return
}

# ctr_firewall_verify: the container firewall runs and drops what no module opened.
ctr_firewall_verify() {
	local ruleset proto port _source
	svc_is_active "${FW_CONTAINER_UNIT}.service" ||
		die "${LSS_MODULE}: the container firewall ${FW_CONTAINER_UNIT} is not active."
	ruleset=$(nft list table inet lss_containers 2>/dev/null) ||
		die "${LSS_MODULE}: the nftables table inet lss_containers of the container firewall is missing."
	grep -q 'oifname "docker0" ct status dnat jump published' <<<"${ruleset}" ||
		die "${LSS_MODULE}: the container firewall does not check redirected connections to containers."
	grep -q 'oifname "docker0" ct state new drop' <<<"${ruleset}" ||
		die "${LSS_MODULE}: the container firewall lets direct connections to containers through."
	[[ $(fw_container_ports) == "$(<"$(fw_container_list)")" ]] ||
		die "${LSS_MODULE}: the container firewall lists other ports than the firewall rules; run lss configure ${LSS_MODULE}."
	while read -r proto port _source; do
		[[ -n ${proto} ]] || continue
		grep -q "meta l4proto ${proto} ct original proto-dst ${port} accept" <<<"${ruleset}" ||
			die "${LSS_MODULE}: the container firewall does not let ${port}/${proto} through, which a module opened."
	done <"$(fw_container_list)"
	return
}

# ctr_firewall_remove: removes the container firewall once no other container module needs it.
ctr_firewall_remove() {
	local module unit=${FW_CONTAINER_UNIT}.service
	for module in ${CTR_MODULES}; do
		[[ ${module} != "${LSS_MODULE:-}" ]] || continue
		if state_installed "${module}"; then
			return 0
		fi
	done
	svc_disable "${unit}"
	file_remove "/etc/systemd/system/${unit}"
	svc_daemon_reload
	file_remove "${CTR_FIREWALL_SCRIPT}"
	rm -f -- "$(fw_container_list)"
	return
}

# ctr_trivy_install: Trivy for the daily image scan of the guard, from the pinned, checksum-verified release.
ctr_trivy_install() {
	local tmp current=''
	if [[ -x ${CTR_TRIVY} ]]; then
		current=$("${CTR_TRIVY}" --version 2>/dev/null | awk '$1 == "Version:" && !found { print $2; found = 1 }') || true
	fi
	[[ ${current} != "${CTR_TRIVY_VERSION}" ]] || return 0
	tmp=$(mktemp -d)
	fetch_verified "trivy-${CTR_TRIVY_VERSION}" "${tmp}/trivy.tar.gz"
	tar -xzf "${tmp}/trivy.tar.gz" -C "${tmp}" trivy || die "container: the Trivy archive has no trivy binary."
	install -m 0755 -o root -g root "${tmp}/trivy" "${CTR_TRIVY}"
	rm -rf -- "${tmp}"
	install -d -m 0700 "${CTR_TRIVY_CACHE}"
	files_note_change "installed Trivy ${CTR_TRIVY_VERSION}"
	return
}

# ctr_trivy_remove: removes Trivy once neither docker nor podman stays installed.
ctr_trivy_remove() {
	local engine
	for engine in docker podman; do
		[[ ${engine} != "${LSS_MODULE:-}" ]] || continue
		if state_installed "${engine}"; then
			return 0
		fi
	done
	if [[ -e ${CTR_TRIVY} ]]; then
		rm -f -- "${CTR_TRIVY}"
		files_note_change "removed Trivy"
	fi
	rm -rf -- "${CTR_TRIVY_CACHE}"
	return
}
