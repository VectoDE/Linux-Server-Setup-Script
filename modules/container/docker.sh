# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="docker"
MOD_GROUP="container"
MOD_DESCRIPTION="Docker Engine from Docker's repository with a hardened daemon (CIS Docker), published ports behind the lss firewall, daily image scan"
MOD_REQUIRES="system"
MOD_CONFLICTS="podman k3s"
MOD_OPTIONS="source|auto|Packages: auto (Docker CE from download.docker.com where Docker builds for the release, otherwise the distribution's docker.io), docker-ce or distribution (Debian and Ubuntu)
bind|127.0.0.1|Address a published port binds to when the container names none (docker run -p 8080:80); 0.0.0.0 for all addresses, which the container firewall still guards
userns_remap|true|Run containers in a separate user namespace (root in a container is an unprivileged user on the host); switching it hides the images and containers of the other mode
log_max_size|20m|Largest log file of a container before it rotates (local log driver)
log_max_files|5|Rotated log files kept per container"
MOD_PORTS="none; published container ports only where a module opened them (container firewall)"

DOCKER_CONFIG=/etc/docker/daemon.json
# Releases Docker CE has packages for (checked 2026-10-13, data/repos/docker.conf); the RHEL family uses the RHEL 9
# and 10 repositories.
DOCKER_CE_SUITES="bookworm trixie jammy noble resolute"
DOCKER_CE_PACKAGES="docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"

mod_check() {
	local source
	source=$(opt source)
	[[ ${source} =~ ^(auto|docker-ce|distribution)$ ]] || die "LSS_DOCKER_SOURCE must be auto, docker-ce or distribution."
	if [[ ${source} == distribution ]] && os_is_rhel; then
		die "LSS_DOCKER_SOURCE=distribution: the RHEL family ships no Docker Engine; use auto (Docker CE) or the podman module."
	fi
	[[ $(opt bind) =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "LSS_DOCKER_BIND must be an IPv4 address such as 127.0.0.1."
	opt_bool userns_remap || true
	[[ $(opt log_max_size) =~ ^[1-9][0-9]*[kmg]$ ]] || die "LSS_DOCKER_LOG_MAX_SIZE must be a size such as 20m."
	(($(opt_int log_max_files) >= 1)) || die "LSS_DOCKER_LOG_MAX_FILES must be at least 1."
	return
}

# _docker_source: docker-ce or distribution.
_docker_source() {
	local source
	source=$(opt source)
	if [[ ${source} == auto ]]; then
		if os_is_rhel || [[ " ${DOCKER_CE_SUITES} " == *" ${OS_CODENAME} "* ]]; then
			source=docker-ce
		else
			source=distribution
		fi
	fi
	printf '%s' "${source}"
	return
}

# The daemon settings (CIS Docker Benchmark, section 2): no traffic between containers on the default bridge, published
# ports on BIND unless a container names an address, containers keep running while the daemon restarts, size-limited
# local logs, no new privileges, no userland proxy (iptables forwards instead), open-file limits, a user namespace,
# SELinux labels on the RHEL family. The default seccomp profile stays on.
_docker_config() {
	local userns='' selinux=''
	if opt_bool userns_remap; then
		userns=$'\n  "userns-remap": "default",'
	fi
	if os_is_rhel; then
		selinux=$'\n  "selinux-enabled": true,'
	fi
	cat <<EOF
{
  "icc": false,
  "ip": "$(opt bind)",
  "live-restore": true,
  "log-driver": "local",
  "log-opts": {
    "max-size": "$(opt log_max_size)",
    "max-file": "$(opt_int log_max_files)"
  },
  "no-new-privileges": true,${userns}${selinux}
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 65536
    }
  },
  "userland-proxy": false
}
EOF
	return
}

mod_install() {
	local -a packages=()
	# The settings are in place before the package starts the daemon for the first time.
	install -d -m 0755 "$(dirname "${DOCKER_CONFIG}")"
	file_write 0644 root:root "${DOCKER_CONFIG}" < <(_docker_config)
	if [[ $(_docker_source) == docker-ce ]]; then
		repo_add docker
		read -ra packages <<<"${DOCKER_CE_PACKAGES}"
	else
		packages=(docker.io)
	fi
	pkg_install "${packages[@]}"
	# AppArmor: dockerd loads its profile with apparmor_parser, which Debian installs only as a recommendation. jq: the
	# Compose check of lib/container.sh.
	pkg_install_family "apparmor jq" "jq"
	ctr_trivy_install
	return
}

mod_configure() {
	local changed usage
	file_write 0644 root:root "${DOCKER_CONFIG}" < <(_docker_config)
	changed=${LSS_FILE_CHANGED}
	# dockerd checks a configuration without starting from Docker 23 on.
	usage=$(dockerd --help 2>&1 || true)
	if [[ ${changed} == 1 && ${usage} == *--validate* ]]; then
		log_command dockerd --validate --config-file "${DOCKER_CONFIG}" ||
			die "docker: dockerd rejects ${DOCKER_CONFIG}; see the log."
	fi
	ctr_firewall_setup
	svc_enable docker.socket
	svc_enable docker.service
	if [[ ${changed} == 1 ]]; then
		# live-restore keeps running containers through the restart.
		svc_restart docker.service || die "docker: the daemon does not start with ${DOCKER_CONFIG}; see above."
	fi
	return
}

_docker_wait() {
	local i
	for ((i = 0; i < 30; i++)); do
		if docker info >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	return 1
}

mod_verify() {
	local options listeners
	svc_is_active docker.service || die "docker: the daemon is not running; see journalctl -u docker."
	_docker_wait || die "docker: the daemon does not answer on its socket."
	[[ $(docker info --format '{{.LiveRestoreEnabled}}') == true ]] || die "docker: live-restore is off."
	[[ $(docker info --format '{{.LoggingDriver}}') == local ]] || die "docker: the log driver is not local."
	options=$(docker info --format '{{join .SecurityOptions " "}}')
	[[ ${options} == *name=seccomp* && ${options} != *profile=unconfined* ]] ||
		die "docker: containers run without the default seccomp profile (${options})."
	if opt_bool userns_remap; then
		[[ ${options} == *name=userns* ]] || die "docker: user namespace remapping is off (${options})."
	fi
	if os_is_debian && [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]]; then
		[[ ${options} == *name=apparmor* ]] || die "docker: containers run without AppArmor (${options})."
	fi
	# The API is root on the host: only the Unix socket, never TCP.
	listeners=$(ss -Hltnp 2>/dev/null || true)
	if [[ ${listeners} == *'"dockerd"'* ]]; then
		die "docker: dockerd listens on a TCP port; remove -H tcp://... from its configuration."
	fi
	[[ $(stat -c '%a %U' /var/run/docker.sock) == '660 root' ]] || die "docker: /var/run/docker.sock must be mode 660 and owned by root."
	ctr_firewall_verify
	[[ -x ${CTR_TRIVY} ]] || die "docker: Trivy for the daily image scan is missing (${CTR_TRIVY})."
	return
}

mod_remove() {
	log_warn "docker: stopping Docker; containers stay on disk and start again when the module is installed again."
	svc_disable docker.socket
	svc_disable docker.service
	svc_disable containerd.service
	file_remove "${DOCKER_CONFIG}"
	ctr_firewall_remove
	ctr_trivy_remove
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	local -a packages=()
	read -ra packages <<<"${DOCKER_CE_PACKAGES}"
	pkg_remove "${packages[@]}" docker.io
	repo_remove docker
	local dir
	for dir in /var/lib/docker /var/lib/containerd; do
		[[ ! -L ${dir} ]] || die "docker: refusing to delete ${dir}: it is a symbolic link."
		if [[ -d ${dir} ]]; then
			rm -rf -- "${dir}"
			files_note_change "deleted ${dir}"
		fi
	done
	rmdir /etc/docker 2>/dev/null || true
	return
}
