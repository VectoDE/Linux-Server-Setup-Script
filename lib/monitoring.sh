# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Monitoring layer shared by node-exporter, prometheus, alertmanager, grafana, loki, alloy and netdata, and the
# metric files of the guard and the backup.
#
# Conventions:
#   MON_TEXTFILE_DIR       node-exporter's textfile collector; the guard and the backup write their *.prom files there
#   MON_TARGETS_DIR        one file per module with its scrape target, which Prometheus reads by itself (file_sd), so
#                          the modules can come and go in any order
#   MON_ALERTMANAGERS_DIR  the same for the Alertmanager that Prometheus sends its alerts to
#   MON_DATASOURCES_DIR    one Grafana data source per module, read by Grafana when it starts
#
# Every interface with a UI or an API for people serves below a path of its own name (/prometheus/, /alertmanager/,
# /grafana/), on 127.0.0.1 or, with LSS_<MODULE>_ACCESS=vpn, on the WireGuard address of the server. The web server
# can then publish it below the same path on its admin port (LSS_<MODULE>_WEB_ADMIN), and none of the other modules
# needs to know whether it does.

# shellcheck disable=SC2034 # read by node-exporter; libexec/lss-guard and libexec/lss-backup use the same path
MON_TEXTFILE_DIR=/var/lib/prometheus/node-exporter
MON_PROMETHEUS_DIR=/etc/lss/prometheus
MON_TARGETS_DIR=${MON_PROMETHEUS_DIR}/targets
MON_ALERTMANAGERS_DIR=${MON_PROMETHEUS_DIR}/alertmanagers
MON_GRAFANA_DIR=/etc/lss/grafana
MON_DATASOURCES_DIR=${MON_GRAFANA_DIR}/provisioning/datasources
MON_GRAFANA_UNIT=grafana-server
# shellcheck disable=SC2034 # read by the monitoring modules
MON_PROMETHEUS_PORT=9090
# shellcheck disable=SC2034 # read by the monitoring modules
MON_ALERTMANAGER_PORT=9093
# The unit of the WireGuard interface (modules/network/wireguard.sh).
MON_VPN_UNIT=wg-quick@wg0.service
MON_MANAGED_BY='# Managed by lss (module'
# Where the programs of upstream releases go (the RHEL family), and the policy file of Debian's package scripts.
MON_BIN_DIR=/usr/local/bin
MON_POLICY_RC=/usr/sbin/policy-rc.d
MON_CACHE_DIR=/var/cache/lss
# The interfaces speak plain HTTP; see mon_url.
MON_SCHEME=http

# mon_vpn MODULE: true when MODULE listens on the WireGuard network (LSS_<MODULE>_ACCESS=vpn).
mon_vpn() {
	local module=$1
	[[ $(config_option "${module}" access local) == vpn ]]
	return
}

# mon_address MODULE: the address MODULE listens on, 127.0.0.1 or the WireGuard address of the server.
mon_address() {
	local module=$1
	if mon_vpn "${module}"; then
		fw_vpn_address
	else
		printf '127.0.0.1'
	fi
	return
}

# mon_url MODULE PORT [PATH]: the URL of MODULE's interface. Plain HTTP is safe here: the interface listens on
# 127.0.0.1 or on the WireGuard address, and the WireGuard tunnel encrypts everything that leaves the server.
mon_url() {
	local module=$1 port=$2 path=${3:-}
	printf '%s://%s:%s%s' "${MON_SCHEME}" "$(mon_address "${module}")" "${port}" "${path}"
	return
}

# mon_vpn_ready: the WireGuard address must exist before a service of the current module can listen on it. Checked in
# mod_configure, because wireguard may be installed earlier in the same run.
mon_vpn_ready() {
	local address
	mon_vpn "${LSS_MODULE}" || return 0
	address=$(fw_vpn_address)
	if ! ip -4 -o addr show 2>/dev/null | grep -qF " ${address}/"; then
		die "$(config_key "${LSS_MODULE}" access)=vpn needs the WireGuard address ${address}; install the wireguard module first (lss install wireguard)."
	fi
	return
}

# mon_vpn_dropin UNIT: with access vpn, a drop-in (lss-vpn.conf) starts UNIT after the WireGuard interface, whose
# address it listens on; with access local the drop-in goes away. Sets LSS_FILE_CHANGED.
mon_vpn_dropin() {
	local unit=$1
	if mon_vpn "${LSS_MODULE}"; then
		svc_dropin "${unit}" lss-vpn <<EOF
${MON_MANAGED_BY} ${LSS_MODULE}): ${unit%.service} listens on the WireGuard address.
[Unit]
After=${MON_VPN_UNIT}
Wants=${MON_VPN_UNIT}
EOF
	else
		LSS_FILE_CHANGED=0
		if [[ -e /etc/systemd/system/${unit}.d/lss-vpn.conf ]]; then
			svc_dropin_remove "${unit}" lss-vpn
			LSS_FILE_CHANGED=1
		fi
	fi
	return
}

# mon_firewall SPEC...: opens the ports (PORT/tcp or PORT/udp) to the WireGuard network with access vpn and closes
# every port of the current module with access local.
mon_firewall() {
	local spec
	if mon_vpn "${LSS_MODULE}"; then
		for spec in "$@"; do
			fw_allow "${spec}:vpn"
		done
	else
		fw_remove_module
	fi
	return
}

# mon_web_admin KIND URL: with LSS_<MODULE>_WEB_ADMIN=true and a web server, publishes the current module below
# /MODULE/ on the admin port (web_admin_write proxy or strip); otherwise removes that path. Reloads the web server
# only when something changed.
mon_web_admin() {
	local kind=$1 url=$2 before
	[[ -n $(web_server) ]] || return 0
	before=$(files_changes_of "${LSS_MODULE}")
	if config_bool "$(config_key "${LSS_MODULE}" web_admin)"; then
		web_admin_write "${LSS_MODULE}" "${LSS_MODULE}" "${kind}" "${url}"
	else
		web_admin_remove "${LSS_MODULE}"
	fi
	if [[ $(files_changes_of "${LSS_MODULE}") != "${before}" ]]; then
		web_reload
	fi
	return
}

# mon_web_admin_remove: drops the admin path of the current module (mod_remove).
mon_web_admin_remove() {
	local before
	[[ -n $(web_server) ]] || return 0
	before=$(files_changes_of "${LSS_MODULE}")
	web_admin_remove "${LSS_MODULE}"
	if [[ $(files_changes_of "${LSS_MODULE}") != "${before}" ]]; then
		web_reload
	fi
	return
}

# mon_target NAME JOB HOST:PORT [METRICS_PATH]: the scrape target of the current module for Prometheus.
mon_target() {
	local name=$1 job=$2 target=$3 path=${4:-/metrics}
	install -d -m 0755 "${MON_TARGETS_DIR}"
	file_write 0644 root:root "${MON_TARGETS_DIR}/${name}.yml" <<EOF
${MON_MANAGED_BY} ${LSS_MODULE}). Prometheus reads it by itself.
- targets: ['${target}']
  labels:
    job: ${job}
    __metrics_path__: ${path}
EOF
	return
}

# mon_target_remove NAME
mon_target_remove() {
	local name=$1
	file_remove "${MON_TARGETS_DIR}/${name}.yml"
	rmdir "${MON_TARGETS_DIR}" "${MON_ALERTMANAGERS_DIR}" "${MON_PROMETHEUS_DIR}" 2>/dev/null || true
	return
}

# mon_datasource NAME TYPE URL [DEFAULT]: the Grafana data source of the current module. Grafana reads the files when it
# starts, so a running Grafana is restarted after a change; without Grafana the file waits for it.
mon_datasource() {
	local name=$1 type=$2 url=$3 default=${4:-false} file
	file="${MON_DATASOURCES_DIR}/${LSS_MODULE}.yaml"
	install -d -m 0755 "${MON_DATASOURCES_DIR}"
	file_write 0644 root:root "${file}" < <(
		printf '%s %s). Grafana reads it when it starts.\napiVersion: 1\ndatasources:\n' "${MON_MANAGED_BY}" "${LSS_MODULE}"
		printf '  - name: %s\n    uid: lss-%s\n    type: %s\n    access: proxy\n    url: %s\n' "${name}" "${LSS_MODULE}" "${type}" "${url}"
		printf '    isDefault: %s\n    editable: false\n' "${default}"
		if [[ ${type} == alertmanager ]]; then
			printf '    jsonData:\n      implementation: prometheus\n      handleGrafanaManagedAlerts: false\n'
		fi
	)
	if [[ ${LSS_FILE_CHANGED} == 1 ]] && svc_is_active "${MON_GRAFANA_UNIT}"; then
		svc_restart "${MON_GRAFANA_UNIT}" || die "${LSS_MODULE}: Grafana does not start with the new data source."
	fi
	return
}

# mon_datasource_remove: removes the data source file of the current module. Grafana keeps the data source until it is
# deleted in Grafana.
mon_datasource_remove() {
	file_remove "${MON_DATASOURCES_DIR}/${LSS_MODULE}.yaml"
	return
}

# mon_install_stopped PACKAGE...: installs packages whose Debian scripts would start the service right away, listening on
# every address with the package defaults, before lss has written its configuration. A temporary policy-rc.d forbids
# those starts (exit 101: action not allowed); mod_configure starts the service with the lss settings. The RHEL family
# starts no service on installation.
mon_install_stopped() {
	local policy=${MON_POLICY_RC}
	if ! os_is_debian || [[ -e ${policy} || -L ${policy} ]] || [[ -z $(pkg_missing "$@") ]]; then
		pkg_install "$@"
		return
	fi
	(
		trap 'rm -f -- "${policy}"' EXIT
		printf '#!/bin/sh\n# Written by lss for one package installation.\nexit 101\n' >"${policy}"
		chmod 0755 "${policy}"
		pkg_install "$@"
	)
	return
}

# mon_grafana_repo_remove: grafana, loki and alloy share Grafana's repository; it goes with the last of them.
mon_grafana_repo_remove() {
	local module
	for module in grafana loki alloy; do
		[[ ${module} != "${LSS_MODULE}" ]] || continue
		state_installed "${module}" && return 0
	done
	repo_remove grafana
	return
}

# mon_unit UNIT USER COMMAND DESCRIPTION: the unit of a program lss installs itself (the RHEL family, from the upstream
# release), running COMMAND as USER. Sets LSS_FILE_CHANGED.
mon_unit() {
	local unit=$1 user=$2 command=$3 description=$4
	svc_unit "${unit}.service" <<EOF
${MON_MANAGED_BY} ${LSS_MODULE}).
[Unit]
Description=${description}
Wants=network-online.target
After=network-online.target

[Service]
User=${user}
Group=${user}
ExecStart=${command}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
	return
}

# mon_exec UNIT COMMAND: a drop-in (lss-config.conf) that starts the packaged UNIT with COMMAND instead of the
# package's command line and its environment file. Sets LSS_FILE_CHANGED.
mon_exec() {
	local unit=$1 command=$2
	svc_dropin "${unit}.service" lss-config <<EOF
${MON_MANAGED_BY} ${LSS_MODULE}): the lss settings instead of the package defaults.
[Service]
EnvironmentFile=
ExecStart=
ExecStart=${command}
EOF
	return
}

# mon_upstream_install NAME VERSION PROGRAM...: installs the PROGRAMs of the checksum-verified release archive
# NAME-VERSION (data/checksums.txt) to /usr/local/bin, where SELinux labels them like every other program. Nothing
# happens when the first PROGRAM already reports VERSION.
mon_upstream_install() {
	local name=$1 version=$2 current archive dir program
	shift 2
	current=$("${MON_BIN_DIR}/$1" --version 2>&1 || true)
	[[ ${current} != *"version ${version} "* ]] || return 0
	archive=${MON_CACHE_DIR}/${name}-${version}.tar.gz
	fetch_verified "${name}-${version}" "${archive}"
	dir=$(mktemp -d "${MON_CACHE_DIR}/${name}.XXXXXX")
	log_command tar -xzf "${archive}" -C "${dir}" --strip-components=1 --no-same-owner
	for program in "$@"; do
		[[ -f ${dir}/${program} && ! -L ${dir}/${program} ]] ||
			die "${LSS_MODULE}: the ${name} ${version} archive has no ${program}; its layout changed."
		install -m 0755 -o root -g root "${dir}/${program}" "${MON_BIN_DIR}/${program}"
		if command -v restorecon >/dev/null 2>&1; then
			restorecon -F "${MON_BIN_DIR}/${program}" 2>/dev/null || true
		fi
	done
	rm -rf -- "${dir}" "${archive}"
	files_note_change "installed ${name} ${version} to ${MON_BIN_DIR}"
	return
}

# mon_upstream_remove PROGRAM...
mon_upstream_remove() {
	local program
	for program in "$@"; do
		[[ -e ${MON_BIN_DIR}/${program} ]] || continue
		rm -f -- "${MON_BIN_DIR}/${program}"
		files_note_change "deleted ${MON_BIN_DIR}/${program}"
	done
	return
}

# mon_user NAME HOME: a system user without login for a service (the RHEL family, where no package creates it).
mon_user() {
	local name=$1 home=$2
	getent passwd "${name}" >/dev/null && return 0
	useradd --system --user-group --home-dir "${home}" --no-create-home --shell /usr/sbin/nologin "${name}"
	files_note_change "created user ${name}"
	return
}

# mon_dir PATH OWNER MODE: creates a data directory, or fixes its owner and mode.
mon_dir() {
	local path=$1 owner=$2 mode=$3
	[[ ! -L ${path} ]] || die "${LSS_MODULE}: ${path} is a symbolic link."
	if [[ ! -d ${path} ]]; then
		install -d -m "${mode}" -o "${owner%%:*}" -g "${owner#*:}" "${path}"
		files_note_change "created ${path}"
	elif [[ $(stat -c '%U:%G %a' "${path}") != "${owner} ${mode#0}" ]]; then
		chown "${owner}" "${path}"
		chmod "${mode}" "${path}"
		files_note_change "owner and mode of ${path}"
	fi
	return
}

# mon_delete PATH...: deletes data directories of the current module (mod_remove with --purge). Each PATH must be a
# directory below /var/lib, and never a symbolic link.
mon_delete() {
	local path
	for path in "$@"; do
		[[ ${path} == /var/lib/?* && ${path} != *..* ]] || die "${LSS_MODULE}: refusing to delete ${path}."
		[[ ! -L ${path} ]] || die "${LSS_MODULE}: refusing to delete ${path}: it is a symbolic link."
		[[ -d ${path} ]] || continue
		rm -rf -- "${path}"
		files_note_change "deleted ${path}"
	done
	return
}

# mon_http URL: the HTTP status code of URL, 000 while nothing answers.
mon_http() {
	local url=$1
	curl -s --max-time 10 -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || true
	return
}

# mon_wait_http URL [SECONDS]: waits until URL answers with 200.
mon_wait_http() {
	local url=$1 seconds=${2:-60} i status=''
	for ((i = 0; i < seconds; i += 2)); do
		status=$(mon_http "${url}")
		[[ ${status} != 200 ]] || return 0
		sleep 2
	done
	die "${LSS_MODULE}: ${url} does not answer (${status})."
}

# mon_listen_check [--process NAME] PORT ADDRESS...: every TCP socket listening on PORT (of the process NAME only) is on
# one of the ADDRESSes.
mon_listen_check() {
	local process='' port listeners address first=$1
	if [[ ${first} == --process ]]; then
		process=$2
		shift 2
	fi
	port=$1
	shift
	listeners=$(ss -Hltnp "sport = :${port}" | awk -v process="${process}" '
		process == "" || index($0, "((\"" process "\"") { address = $4; sub(/:[0-9]+$/, "", address)
		sub(/%.*/, "", address); gsub(/[][]/, "", address); print address }')
	[[ -n ${listeners} ]] || die "${LSS_MODULE}: nothing listens on port ${port}."
	while IFS= read -r address; do
		[[ " $* " == *" ${address} "* ]] || die "${LSS_MODULE}: port ${port} is open on ${address}, expected $* only."
	done <<<"${listeners}"
	return
}
