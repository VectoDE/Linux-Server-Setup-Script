# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="netdata"
MOD_GROUP="monitoring"
MOD_DESCRIPTION="Netdata real-time dashboard, never claimed to Netdata Cloud, without registry or telemetry; on 127.0.0.1:19999 or the WireGuard network, optionally below /netdata/ on the admin port"
MOD_REQUIRES="system"
MOD_OPTIONS="access|local|Who reaches http://SERVER:19999: local (127.0.0.1 only; SSH tunnel) or vpn (also the WireGuard network)
web_admin|false|Also publish Netdata below /netdata/ on the admin port of the web server (needs nginx, apache or caddy)
ml|false|Machine-learning anomaly detection (costs CPU and memory on small servers)"
MOD_PORTS="19999/tcp from the WireGuard network with access vpn; none with access local"

# Netdata's own repository (data/repos/netdata.conf, pinned keys) for every supported system: Debian 13, Ubuntu 26.04
# and EPEL 10 have no Netdata package. Its packages need EPEL on the RHEL family.
NETDATA_UNIT=netdata
NETDATA_PORT=19999
NETDATA_CONF=/etc/netdata/netdata.conf
NETDATA_OPT_OUT=/etc/netdata/.opt-out-from-anonymous-statistics

mod_check() {
	[[ $(opt access) =~ ^(local|vpn)$ ]] || die "LSS_NETDATA_ACCESS must be local or vpn."
	opt_bool web_admin || true
	opt_bool ml || true
	return
}

_netdata_bind() {
	local bind=127.0.0.1
	mon_vpn netdata && bind+=" $(fw_vpn_address)"
	printf '%s' "${bind}"
	return
}

# _netdata_files: the settings that keep Netdata on this server, written before the package as well, so its first
# start already uses them.
_netdata_files() {
	local ml=no
	opt_bool ml && ml=yes
	install -d -m 0755 /etc/netdata
	file_write 0644 root:root "${NETDATA_CONF}" <<EOF
# Managed by lss (module netdata). Change LSS_NETDATA_* in /etc/lss/lss.conf and run lss configure netdata.
[web]
	bind to = $(_netdata_bind)
	enable gzip compression = yes
[registry]
	enabled = no
[ml]
	enabled = ${ml}
[statsd]
	enabled = no
EOF
	# No anonymous statistics: the file's existence is the opt-out. Netdata 2 has no switch for its Cloud any more
	# (the API reports cloud-enabled as true on every agent); an agent connects only once it is claimed, which lss
	# never does, and mod_verify checks that it is not.
	file_write 0644 root:root "${NETDATA_OPT_OUT}" </dev/null
	return
}

mod_install() {
	pkg_enable_epel
	repo_add netdata
	if ! pkg_is_installed netdata; then
		mon_vpn_ready
		_netdata_files
	fi
	mon_install_stopped netdata
	return
}

mod_configure() {
	local before
	before=$(files_changes_of netdata)
	mon_vpn_ready
	_netdata_files
	# Netdata's collectors (apps.plugin, the eBPF and network plugins) get their rights from file capabilities and a
	# setuid helper, which NoNewPrivileges would take away; they read /proc, /sys and the devices of the whole system.
	svc_sandbox "${NETDATA_UNIT}.service" NoNewPrivileges=no PrivateDevices=no ProtectHome=read-only \
		ReadWritePaths=-/var/lib/netdata ReadWritePaths=-/var/cache/netdata
	mon_vpn_dropin "${NETDATA_UNIT}.service"
	svc_enable "${NETDATA_UNIT}"
	if [[ $(files_changes_of netdata) != "${before}" ]]; then
		svc_restart "${NETDATA_UNIT}" || die "netdata: Netdata does not start."
	fi
	mon_firewall "${NETDATA_PORT}/tcp"
	# Netdata serves from the root of its port, so the web server strips /netdata/.
	mon_web_admin strip "http://127.0.0.1:${NETDATA_PORT}"
	return
}

mod_verify() {
	local info address
	local -a addresses=()
	svc_is_active "${NETDATA_UNIT}" || die "netdata: ${NETDATA_UNIT} is not running."
	mon_wait_http "http://127.0.0.1:${NETDATA_PORT}/api/v1/info" 120
	info=$(curl -s --max-time 10 "http://127.0.0.1:${NETDATA_PORT}/api/v1/info")
	[[ ${info} =~ \"agent-claimed\":[[:space:]]*false ]] || die "netdata: the agent is claimed to Netdata Cloud."
	[[ ${info} =~ \"aclk-available\":[[:space:]]*false ]] || die "netdata: the agent is connected to Netdata Cloud."
	[[ -f ${NETDATA_OPT_OUT} ]] || die "netdata: the opt-out from anonymous statistics is missing."
	for address in $(_netdata_bind); do
		addresses+=("${address}")
	done
	mon_listen_check --process netdata "${NETDATA_PORT}" "${addresses[@]}"
	return
}

mod_remove() {
	mon_web_admin_remove
	svc_disable "${NETDATA_UNIT}"
	svc_dropin_remove "${NETDATA_UNIT}.service" lss-sandbox
	svc_dropin_remove "${NETDATA_UNIT}.service" lss-vpn
	pkg_remove netdata
	repo_remove netdata
	file_remove "${NETDATA_CONF}"
	file_remove "${NETDATA_OPT_OUT}"
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	mon_delete /var/lib/netdata
	return
}
