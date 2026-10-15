# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="alertmanager"
MOD_GROUP="monitoring"
MOD_DESCRIPTION="Prometheus Alertmanager: sends the alerts of Prometheus by e-mail or webhook; UI and API below /alertmanager/ on 127.0.0.1:9093 or the WireGuard network"
MOD_REQUIRES="system"
MOD_OPTIONS="access|local|Who reaches http://SERVER:9093/alertmanager/: local (127.0.0.1 only; SSH tunnel) or vpn (WireGuard network only)
web_admin|false|Also publish Alertmanager below /alertmanager/ on the admin port of the web server (needs nginx, apache or caddy)
email||Send alerts to this address (needs the mail-relay module or another mail server on smarthost)
smarthost|localhost:25|Mail server Alertmanager hands e-mails to, HOST:PORT without authentication
webhook||Send alerts as JSON to this HTTPS URL (Alertmanager's webhook format; ntfy, n8n, a chat bridge, ...)"
MOD_PORTS="9093/tcp from the WireGuard network with access vpn; none with access local"

# Debian and Ubuntu package Alertmanager (0.23 to 0.28); the RHEL family gets the checksum-verified upstream release
# with a unit of the same name. The configuration below works with all of these versions.
AM_VERSION=0.34.1
AM_UNIT=prometheus-alertmanager
AM_CONF=/etc/lss/alertmanager/alertmanager.yml
AM_PATH=alertmanager

_am_user() {
	if os_is_debian; then printf 'prometheus'; else printf 'alertmanager'; fi
	return
}

_am_data() {
	if os_is_debian; then printf '/var/lib/prometheus/alertmanager'; else printf '/var/lib/alertmanager'; fi
	return
}

_am_binary() {
	if os_is_debian; then printf '/usr/bin/prometheus-alertmanager'; else printf '/usr/local/bin/alertmanager'; fi
	return
}

_am_url() {
	mon_url alertmanager "${MON_ALERTMANAGER_PORT}" "/${AM_PATH}"
	return
}

mod_check() {
	local email webhook
	[[ $(opt access) =~ ^(local|vpn)$ ]] || die "LSS_ALERTMANAGER_ACCESS must be local or vpn."
	opt_bool web_admin || true
	email=$(opt email)
	webhook=$(opt webhook)
	[[ -z ${email} || ${email} =~ ^[^@[:space:]\'\"]+@[^@[:space:]\'\"]+\.[^@[:space:]\'\"]+$ ]] ||
		die "LSS_ALERTMANAGER_EMAIL '${email}' is not an e-mail address."
	[[ $(opt smarthost) =~ ^[A-Za-z0-9.:-]+:[0-9]{1,5}$ ]] || die "LSS_ALERTMANAGER_SMARTHOST must look like HOST:PORT."
	[[ -z ${webhook} || ${webhook} =~ ^https://[^[:space:]\'\"]+$ ]] || die "LSS_ALERTMANAGER_WEBHOOK must be an https:// URL."
	return
}

mod_install() {
	if os_is_debian; then
		mon_install_stopped prometheus-alertmanager
	else
		mon_user alertmanager "$(_am_data)"
		mon_upstream_install alertmanager "${AM_VERSION}" alertmanager amtool
	fi
	return
}

# _am_config: one receiver for every alert. Without e-mail and webhook the alerts are only shown (Alertmanager UI,
# Grafana).
_am_config() {
	local email webhook host
	email=$(opt email)
	webhook=$(opt webhook)
	host=$(hostname -f 2>/dev/null || hostname)
	printf '%s alertmanager). Change LSS_ALERTMANAGER_* in /etc/lss/lss.conf and run lss configure alertmanager.\n' "${MON_MANAGED_BY}"
	cat <<'EOF'
route:
  receiver: lss
  group_by: [alertname, instance]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
receivers:
  - name: lss
EOF
	if [[ -n ${email} ]]; then
		printf "    email_configs:\n      - to: '%s'\n        from: 'alertmanager@%s'\n        smarthost: '%s'\n        require_tls: false\n        send_resolved: true\n" \
			"${email}" "${host}" "$(opt smarthost)"
	fi
	if [[ -n ${webhook} ]]; then
		printf "    webhook_configs:\n      - url: '%s'\n        send_resolved: true\n" "${webhook}"
	fi
	return
}

_am_command() {
	# An empty cluster address turns the gossip port 9094 off: a single Alertmanager has no peers.
	printf '%s --config.file=%s --storage.path=%s --web.listen-address=%s:%s --web.external-url=%s/ --cluster.listen-address=' \
		"$(_am_binary)" "${AM_CONF}" "$(_am_data)" "$(mon_address alertmanager)" "${MON_ALERTMANAGER_PORT}" "$(_am_url)"
	return
}

_am_amtool() {
	if os_is_debian; then printf '/usr/bin/amtool'; else printf '/usr/local/bin/amtool'; fi
	return
}

mod_configure() {
	local before changed config reload=0
	before=$(files_changes_of alertmanager)
	mon_vpn_ready
	mon_dir "$(_am_data)" "$(_am_user):$(_am_user)" 0750
	install -d -m 0755 "$(dirname "${AM_CONF}")"
	config=$(_am_config)
	# The webhook URL is a credential (whoever has it can post), so only Alertmanager reads the file.
	file_write 0640 "root:$(_am_user)" "${AM_CONF}" <<<"${config}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || reload=1
	"$(_am_amtool)" check-config "${AM_CONF}" >/dev/null || die "alertmanager: amtool rejects ${AM_CONF}."
	install -d -m 0755 "${MON_ALERTMANAGERS_DIR}"
	file_write 0644 root:root "${MON_ALERTMANAGERS_DIR}/alertmanager.yml" <<EOF
${MON_MANAGED_BY} alertmanager). Prometheus reads it by itself.
- targets: ['$(mon_address alertmanager):${MON_ALERTMANAGER_PORT}']
EOF
	mon_target alertmanager alertmanager "$(mon_address alertmanager):${MON_ALERTMANAGER_PORT}" "/${AM_PATH}/metrics"
	changed=$(files_changes_of alertmanager)
	if os_is_debian; then
		mon_exec "${AM_UNIT}" "$(_am_command)"
	else
		mon_unit "${AM_UNIT}" "$(_am_user)" "$(_am_command)" "Prometheus Alertmanager"
	fi
	svc_sandbox "${AM_UNIT}.service" "ReadWritePaths=$(_am_data)"
	mon_vpn_dropin "${AM_UNIT}.service"
	svc_enable "${AM_UNIT}"
	if [[ $(files_changes_of alertmanager) != "${changed}" ]]; then
		svc_restart "${AM_UNIT}" || die "alertmanager: Alertmanager does not start."
	elif [[ ${reload} == 1 && $(files_changes_of alertmanager) != "${before}" ]]; then
		svc_reload "${AM_UNIT}" || die "alertmanager: Alertmanager does not reload its configuration."
	fi
	mon_firewall "${MON_ALERTMANAGER_PORT}/tcp"
	mon_web_admin proxy "$(mon_url alertmanager "${MON_ALERTMANAGER_PORT}")"
	mon_datasource Alertmanager alertmanager "$(_am_url)"
	return
}

mod_verify() {
	local status
	svc_is_active "${AM_UNIT}" || die "alertmanager: ${AM_UNIT} is not running."
	mon_wait_http "$(_am_url)/-/ready" 60
	status=$(curl -s --max-time 10 "$(_am_url)/api/v2/status")
	[[ ${status} == *'"config":'* ]] || die "alertmanager: the API gives no status."
	mon_listen_check "${MON_ALERTMANAGER_PORT}" "$(mon_address alertmanager)"
	if ss -Hltun 'sport = :9094' | grep -q .; then
		die "alertmanager: the cluster port 9094 is open."
	fi
	return
}

mod_remove() {
	mon_web_admin_remove
	mon_datasource_remove
	mon_target_remove alertmanager
	file_remove "${MON_ALERTMANAGERS_DIR}/alertmanager.yml"
	rmdir "${MON_ALERTMANAGERS_DIR}" "${MON_PROMETHEUS_DIR}" 2>/dev/null || true
	svc_disable "${AM_UNIT}"
	svc_dropin_remove "${AM_UNIT}.service" lss-sandbox
	svc_dropin_remove "${AM_UNIT}.service" lss-vpn
	file_remove "${AM_CONF}"
	rmdir "$(dirname "${AM_CONF}")" 2>/dev/null || true
	if os_is_debian; then
		svc_dropin_remove "${AM_UNIT}.service" lss-config
		pkg_remove prometheus-alertmanager
	else
		file_remove "/etc/systemd/system/${AM_UNIT}.service"
		svc_daemon_reload
		mon_upstream_remove alertmanager amtool
	fi
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	mon_delete "$(_am_data)"
	return
}
