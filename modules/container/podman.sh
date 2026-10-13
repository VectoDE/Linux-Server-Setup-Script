# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="podman"
MOD_GROUP="container"
MOD_DESCRIPTION="Podman from the distribution: containers without a daemon, process and log limits, published ports behind the lss firewall, daily image scan"
MOD_REQUIRES="system"
MOD_CONFLICTS="docker"
MOD_OPTIONS="pids_limit|2048|Most processes one container may start, unless lss sets a lower limit for it"
MOD_PORTS="none; published container ports only where a module opened them (container firewall)"

# Podman 4 and later read drop-ins from containers.conf.d; Podman 3 (Ubuntu 22.04) only the file itself. Settings in
# either one override the defaults in /usr/share/containers/containers.conf key by key.
PODMAN_DROPIN=/etc/containers/containers.conf.d/60-lss.conf
PODMAN_CONF=/etc/containers/containers.conf

mod_check() {
	(($(opt_int pids_limit) >= 64)) || die "LSS_PODMAN_PIDS_LIMIT must be at least 64."
	return
}

mod_install() {
	pkg_install podman
	# Podman loads its AppArmor profile with apparmor_parser, which Debian installs only as a recommendation. jq: the
	# Compose check of lib/container.sh.
	pkg_install_family "apparmor jq" "jq"
	ctr_trivy_install
	return
}

# The configuration file lss manages: the drop-in where Podman reads one.
_podman_conf() {
	local version
	version=$(podman version --format '{{.Client.Version}}' 2>/dev/null || true)
	[[ ${version} =~ ^[0-9]+ ]] || version=0
	if ((${version%%.*} >= 4)); then
		printf '%s' "${PODMAN_DROPIN}"
	else
		printf '%s' "${PODMAN_CONF}"
	fi
	return
}

mod_configure() {
	local conf
	conf=$(_podman_conf)
	install -d -m 0755 "$(dirname "${conf}")"
	file_write 0644 root:root "${conf}" <<EOF
# Managed by lss (module podman). Change LSS_PODMAN_* in /etc/lss/lss.conf and run lss configure podman.
# Limits for every container; the containers lss starts also get memory limits, a read-only root file system and no
# capabilities beyond the ones they need (lib/container.sh).
[containers]
pids_limit = $(opt_int pids_limit)
log_size_max = 20971520
default_ulimits = [
  "nofile=65536:65536",
]
EOF
	ctr_firewall_setup
	return
}

mod_verify() {
	local seccomp
	podman info >/dev/null 2>&1 || die "podman: podman info fails; run it to see why."
	seccomp=$(podman info --format '{{.Host.Security.SECCOMPEnabled}}' 2>/dev/null || true)
	[[ ${seccomp} == true ]] || die "podman: containers run without seccomp."
	if os_is_rhel && [[ $(getenforce 2>/dev/null) == Enforcing ]]; then
		[[ $(podman info --format '{{.Host.Security.SELinuxEnabled}}' 2>/dev/null) == true ]] ||
			die "podman: SELinux is enforcing, but Podman does not label containers."
	fi
	ctr_firewall_verify
	[[ -x ${CTR_TRIVY} ]] || die "podman: Trivy for the daily image scan is missing (${CTR_TRIVY})."
	return
}

mod_remove() {
	# Only the file lss wrote: on Podman 4 and later containers.conf belongs to the administrator.
	file_remove "$(_podman_conf)"
	ctr_firewall_remove
	ctr_trivy_remove
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	# Every container, image and volume of root.
	if command -v podman >/dev/null 2>&1; then
		log_command podman system reset --force || die "podman: podman system reset failed; see the log."
		files_note_change "deleted the containers, images and volumes of Podman"
	fi
	pkg_remove podman
	return
}
