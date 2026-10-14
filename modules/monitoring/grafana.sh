# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="grafana"
MOD_GROUP="monitoring"
MOD_DESCRIPTION="Grafana OSS from Grafana's repository with the data sources of the monitoring modules; below /grafana/ on 127.0.0.1:3000 or the WireGuard network"
MOD_REQUIRES="system prometheus"
MOD_OPTIONS="access|local|Who reaches http://SERVER:3000/grafana/: local (127.0.0.1 only; SSH tunnel) or vpn (WireGuard network only)
web_admin|false|Also publish Grafana below /grafana/ on the admin port of the web server (needs nginx, apache or caddy)"
MOD_PORTS="3000/tcp from the WireGuard network with access vpn; none with access local"
MOD_SECRETS="grafana-admin-password"

# Grafana's own repository (data/repos/grafana.conf, pinned key) serves the same release to every supported system.
# The settings go in as GF_* variables of a drop-in, which win over grafana.ini; the package keeps its own file.
GRAFANA_PORT=3000
GRAFANA_PATH=grafana
# The admin password for Grafana's first start, readable by Grafana only (the secrets directory is root's).
GRAFANA_PASSWORD_FILE=${MON_GRAFANA_DIR}/admin-password

_grafana_url() {
	printf 'http://%s:%s/%s' "$(mon_address grafana)" "${GRAFANA_PORT}" "${GRAFANA_PATH}"
	return
}

mod_check() {
	[[ $(opt access) =~ ^(local|vpn)$ ]] || die "LSS_GRAFANA_ACCESS must be local or vpn."
	opt_bool web_admin || true
	return
}

mod_install() {
	repo_add grafana
	pkg_install grafana
	return
}

_grafana_environment() {
	cat <<EOF
${MON_MANAGED_BY} grafana). Change LSS_GRAFANA_* in /etc/lss/lss.conf and run lss configure grafana.
[Service]
Environment=GF_SERVER_HTTP_ADDR=$(mon_address grafana)
Environment=GF_SERVER_HTTP_PORT=${GRAFANA_PORT}
Environment=GF_SERVER_ROOT_URL=$(_grafana_url)/
Environment=GF_SERVER_SERVE_FROM_SUB_PATH=true
Environment=GF_PATHS_PROVISIONING=${MON_GRAFANA_DIR}/provisioning
Environment=GF_SECURITY_ADMIN_USER=admin
Environment=GF_SECURITY_ADMIN_PASSWORD__FILE=${GRAFANA_PASSWORD_FILE}
Environment=GF_SECURITY_DISABLE_GRAVATAR=true
Environment=GF_USERS_ALLOW_SIGN_UP=false
# The admin port of the web server may ask for its own basic auth; Grafana must not take that header for a login.
Environment=GF_AUTH_BASIC_ENABLED=false
# Nothing leaves the server on its own: no usage reports, update checks, news feed or plugin downloads at start.
Environment=GF_ANALYTICS_REPORTING_ENABLED=false
Environment=GF_ANALYTICS_CHECK_FOR_UPDATES=false
Environment=GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false
Environment=GF_NEWS_NEWS_FEED_ENABLED=false
Environment=GF_PLUGINS_PREINSTALL_DISABLED=true
EOF
	return
}

mod_configure() {
	local before password
	before=$(files_changes_of grafana)
	mon_vpn_ready
	secret_load grafana-admin-password password 32
	install -d -m 0755 "${MON_GRAFANA_DIR}" "${MON_DATASOURCES_DIR}"
	install -d -m 0755 "${MON_GRAFANA_DIR}/provisioning/dashboards" "${MON_GRAFANA_DIR}/provisioning/plugins" \
		"${MON_GRAFANA_DIR}/provisioning/alerting"
	file_write 0640 root:grafana "${GRAFANA_PASSWORD_FILE}" <<<"${password}"
	_grafana_environment | svc_dropin "${MON_GRAFANA_UNIT}.service" lss-config
	svc_sandbox "${MON_GRAFANA_UNIT}.service" ReadWritePaths=/var/lib/grafana ReadWritePaths=-/var/log/grafana
	mon_vpn_dropin "${MON_GRAFANA_UNIT}.service"
	svc_enable "${MON_GRAFANA_UNIT}"
	if [[ $(files_changes_of grafana) != "${before}" ]]; then
		svc_restart "${MON_GRAFANA_UNIT}" || die "grafana: Grafana does not start."
		log_info "grafana: user admin, password from lss secrets show grafana-admin-password (set when Grafana creates its database; later changes go through Grafana)."
	fi
	mon_firewall "${GRAFANA_PORT}/tcp"
	mon_web_admin proxy "http://$(mon_address grafana):${GRAFANA_PORT}"
	return
}

mod_verify() {
	local url password jar status uid
	url=$(_grafana_url)
	svc_is_active "${MON_GRAFANA_UNIT}" || die "grafana: ${MON_GRAFANA_UNIT} is not running."
	mon_wait_http "${url}/api/health" 120
	[[ $(curl -s --max-time 10 "${url}/api/health") =~ \"database\":[[:space:]]*\"ok\" ]] ||
		die "grafana: Grafana reports a database problem."
	secret_load grafana-admin-password password 32
	jar=$(mktemp)
	# The password goes to curl on stdin, never on its command line.
	status=$(printf '{"user":"admin","password":"%s"}' "${password}" |
		curl -s --max-time 10 -c "${jar}" -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
			--data-binary @- "${url}/login" || true)
	if [[ ${status} != 200 ]]; then
		rm -f -- "${jar}"
		die "grafana: the admin login with the password from the lss secrets fails (${status})."
	fi
	# Every data source the monitoring modules announced must be loaded.
	for uid in "${MON_DATASOURCES_DIR}"/*.yaml; do
		[[ -f ${uid} ]] || continue
		uid=lss-$(basename "${uid}" .yaml)
		status=$(curl -s --max-time 10 -b "${jar}" -o /dev/null -w '%{http_code}' "${url}/api/datasources/uid/${uid}" || true)
		if [[ ${status} != 200 ]]; then
			rm -f -- "${jar}"
			die "grafana: the data source ${uid} is not loaded (${status})."
		fi
	done
	rm -f -- "${jar}"
	mon_listen_check "${GRAFANA_PORT}" "$(mon_address grafana)"
	return
}

mod_remove() {
	mon_web_admin_remove
	svc_disable "${MON_GRAFANA_UNIT}"
	svc_dropin_remove "${MON_GRAFANA_UNIT}.service" lss-sandbox
	svc_dropin_remove "${MON_GRAFANA_UNIT}.service" lss-vpn
	svc_dropin_remove "${MON_GRAFANA_UNIT}.service" lss-config
	file_remove "${GRAFANA_PASSWORD_FILE}"
	pkg_remove grafana
	mon_grafana_repo_remove
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	mon_delete /var/lib/grafana
	secret_remove grafana-admin-password
	return
}
