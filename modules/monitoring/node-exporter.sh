# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="node-exporter"
MOD_GROUP="monitoring"
MOD_DESCRIPTION="Prometheus node exporter: metrics of CPU, memory, disks and network on 127.0.0.1:9100 or the WireGuard network, plus the metric files of the guard and the backup"
MOD_REQUIRES="system"
MOD_OPTIONS="access|local|Who reaches port 9100: local (this server's Prometheus) or vpn (also a Prometheus elsewhere in the WireGuard network)"
MOD_PORTS="9100/tcp from the WireGuard network with access vpn; none with access local"

# Debian and Ubuntu package the node exporter; the RHEL family (EPEL included) does not, so it comes from the
# checksum-verified upstream release (data/checksums.txt) with a unit of the same name.
NODE_VERSION=1.12.1
NODE_UNIT=prometheus-node-exporter
NODE_PORT=9100

_node_binary() {
	if os_is_debian; then printf '/usr/bin/prometheus-node-exporter'; else printf '/usr/local/bin/node_exporter'; fi
	return
}

_node_user() {
	if os_is_debian; then printf 'prometheus'; else printf 'node_exporter'; fi
	return
}

mod_check() {
	[[ $(opt access) =~ ^(local|vpn)$ ]] || die "LSS_NODE_EXPORTER_ACCESS must be local or vpn."
	return
}

mod_install() {
	if os_is_debian; then
		mon_install_stopped prometheus-node-exporter
	else
		mon_user node_exporter /var/lib/node_exporter
		mon_upstream_install node_exporter "${NODE_VERSION}" node_exporter
	fi
	return
}

_node_command() {
	printf '%s --web.listen-address=%s:%s --collector.textfile.directory=%s' "$(_node_binary)" \
		"$(mon_address node-exporter)" "${NODE_PORT}" "${MON_TEXTFILE_DIR}"
	return
}

mod_configure() {
	local before
	before=$(files_changes_of node-exporter)
	mon_vpn_ready
	# The guard and the backup (as root) put their *.prom files here; the exporter only reads them.
	if [[ ! -d ${MON_TEXTFILE_DIR} ]]; then
		install -d -m 0755 "${MON_TEXTFILE_DIR}"
		files_note_change "created ${MON_TEXTFILE_DIR}"
	fi
	if os_is_debian; then
		mon_exec "${NODE_UNIT}" "$(_node_command)"
	else
		mon_unit "${NODE_UNIT}" "$(_node_user)" "$(_node_command)" "Prometheus node exporter"
	fi
	# The file system collector reads the usage of every mount point, /home included.
	svc_sandbox "${NODE_UNIT}.service" ProtectHome=read-only
	mon_vpn_dropin "${NODE_UNIT}.service"
	svc_enable "${NODE_UNIT}"
	if [[ $(files_changes_of node-exporter) != "${before}" ]]; then
		svc_restart "${NODE_UNIT}" || die "node-exporter: ${NODE_UNIT} does not start."
	fi
	mon_firewall "${NODE_PORT}/tcp"
	mon_target node node "$(mon_address node-exporter):${NODE_PORT}"
	return
}

mod_verify() {
	local url metrics
	url=$(mon_url node-exporter "${NODE_PORT}" /metrics)
	svc_is_active "${NODE_UNIT}" || die "node-exporter: ${NODE_UNIT} is not running."
	mon_wait_http "${url}"
	metrics=$(curl -s --max-time 10 "${url}")
	[[ ${metrics} == *$'\nnode_textfile_scrape_error 0'* ]] ||
		die "node-exporter: the textfile collector cannot read ${MON_TEXTFILE_DIR}."
	[[ ${metrics} == *$'\nnode_cpu_seconds_total{'* ]] || die "node-exporter: the metrics have no CPU times."
	mon_listen_check "${NODE_PORT}" "$(mon_address node-exporter)"
	return
}

mod_remove() {
	mon_target_remove node
	svc_disable "${NODE_UNIT}"
	svc_dropin_remove "${NODE_UNIT}.service" lss-sandbox
	svc_dropin_remove "${NODE_UNIT}.service" lss-vpn
	if os_is_debian; then
		svc_dropin_remove "${NODE_UNIT}.service" lss-config
		pkg_remove prometheus-node-exporter
	else
		file_remove "/etc/systemd/system/${NODE_UNIT}.service"
		svc_daemon_reload
		mon_upstream_remove node_exporter
	fi
	# The metric files of the guard and the backup stay; they are small and come back with the module.
	return
}
