# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="prometheus"
MOD_GROUP="monitoring"
MOD_DESCRIPTION="Prometheus with the lss alert rules, scraping what the other monitoring modules announce; UI and API below /prometheus/ on 127.0.0.1:9090 or the WireGuard network"
MOD_REQUIRES="system node-exporter"
MOD_OPTIONS="access|local|Who reaches http://SERVER:9090/prometheus/: local (127.0.0.1 only; SSH tunnel) or vpn (WireGuard network only)
web_admin|false|Also publish Prometheus below /prometheus/ on the admin port of the web server (needs nginx, apache or caddy)
retention|15d|How long Prometheus keeps the metrics (Prometheus duration: 12h, 15d, 8w, 1y)"
MOD_PORTS="9090/tcp from the WireGuard network with access vpn; none with access local"

# Debian and Ubuntu package Prometheus (2.31 to 2.53); the RHEL family has no package, so it gets the checksum-verified
# upstream release, the 3.13 LTS line, with a unit of the same name. The flags and the configuration below work with
# both major versions.
PROM_VERSION=3.13.4
PROM_UNIT=prometheus
PROM_CONF=${MON_PROMETHEUS_DIR}/prometheus.yml
PROM_RULES_DIR=${MON_PROMETHEUS_DIR}/rules
PROM_PATH=prometheus

_prom_data() {
	if os_is_debian; then printf '/var/lib/prometheus/metrics2'; else printf '/var/lib/prometheus/data'; fi
	return
}

_prom_bin() {
	if os_is_debian; then printf '/usr/bin'; else printf '/usr/local/bin'; fi
	return
}

_prom_url() {
	printf 'http://%s:%s/%s' "$(mon_address prometheus)" "${MON_PROMETHEUS_PORT}" "${PROM_PATH}"
	return
}

mod_check() {
	[[ $(opt access) =~ ^(local|vpn)$ ]] || die "LSS_PROMETHEUS_ACCESS must be local or vpn."
	opt_bool web_admin || true
	[[ $(opt retention) =~ ^[1-9][0-9]*(h|d|w|y)$ ]] || die "LSS_PROMETHEUS_RETENTION must look like 15d (h, d, w or y)."
	return
}

mod_install() {
	if os_is_debian; then
		mon_install_stopped prometheus
	else
		mon_user prometheus /var/lib/prometheus
		mon_upstream_install prometheus "${PROM_VERSION}" prometheus promtool
	fi
	return
}

# _prom_config: scrape targets and Alertmanagers come from the files the modules write (file_sd); Prometheus notices
# new and removed files by itself.
_prom_config() {
	cat <<EOF
${MON_MANAGED_BY} prometheus). Change LSS_PROMETHEUS_* in /etc/lss/lss.conf and run lss configure prometheus.
global:
  scrape_interval: 30s
  evaluation_interval: 30s
rule_files:
  - ${PROM_RULES_DIR}/*.yml
alerting:
  alertmanagers:
    - path_prefix: /alertmanager/
      file_sd_configs:
        - files: ['${MON_ALERTMANAGERS_DIR}/*.yml']
scrape_configs:
  - job_name: lss
    file_sd_configs:
      - files: ['${MON_TARGETS_DIR}/*.yml']
EOF
	return
}

_prom_command() {
	printf '%s/prometheus --config.file=%s --storage.tsdb.path=%s --storage.tsdb.retention.time=%s --web.listen-address=%s:%s --web.external-url=%s/' \
		"$(_prom_bin)" "${PROM_CONF}" "$(_prom_data)" "$(opt retention)" "$(mon_address prometheus)" \
		"${MON_PROMETHEUS_PORT}" "$(_prom_url)"
	return
}

mod_configure() {
	local before config reload=0 changed
	before=$(files_changes_of prometheus)
	mon_vpn_ready
	install -d -m 0755 "${MON_PROMETHEUS_DIR}" "${MON_TARGETS_DIR}" "${MON_ALERTMANAGERS_DIR}" "${PROM_RULES_DIR}"
	install -d -m 0755 /var/lib/prometheus
	mon_dir "$(_prom_data)" prometheus:prometheus 0750
	config=$(_prom_config)
	file_write 0644 root:root "${PROM_CONF}" <<<"${config}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || reload=1
	template_install prometheus rules.yml 0644 root:root "${PROM_RULES_DIR}/lss.yml"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || reload=1
	"$(_prom_bin)/promtool" check config "${PROM_CONF}" >/dev/null || die "prometheus: promtool rejects ${PROM_CONF}."
	mon_target prometheus prometheus "$(mon_address prometheus):${MON_PROMETHEUS_PORT}" "/${PROM_PATH}/metrics"
	changed=$(files_changes_of prometheus)
	if os_is_debian; then
		mon_exec "${PROM_UNIT}" "$(_prom_command)"
	else
		mon_unit "${PROM_UNIT}" prometheus "$(_prom_command)" "Prometheus monitoring system"
	fi
	svc_sandbox "${PROM_UNIT}.service" "ReadWritePaths=$(_prom_data)"
	mon_vpn_dropin "${PROM_UNIT}.service"
	svc_enable "${PROM_UNIT}"
	if [[ $(files_changes_of prometheus) != "${changed}" ]]; then
		svc_restart "${PROM_UNIT}" || die "prometheus: Prometheus does not start."
	elif [[ $(files_changes_of prometheus) != "${before}" && ${reload} == 1 ]]; then
		# A new configuration or new rules only need a reload, which keeps the data in memory.
		svc_reload "${PROM_UNIT}" || die "prometheus: Prometheus does not reload its configuration."
	fi
	mon_firewall "${MON_PROMETHEUS_PORT}/tcp"
	mon_web_admin proxy "http://$(mon_address prometheus):${MON_PROMETHEUS_PORT}"
	mon_datasource Prometheus prometheus "$(_prom_url)" true
	return
}

mod_verify() {
	local url rules
	url=$(_prom_url)
	svc_is_active "${PROM_UNIT}" || die "prometheus: ${PROM_UNIT} is not running."
	mon_wait_http "${url}/-/ready" 120
	rules=$(curl -s --max-time 10 "${url}/api/v1/rules")
	[[ ${rules} == *'"name":"LssBackupTooOld"'* ]] || die "prometheus: the lss alert rules are not loaded."
	# Prometheus scrapes itself and the node exporter through the target files.
	_prom_wait_target node
	mon_listen_check --process prometheus "${MON_PROMETHEUS_PORT}" "$(mon_address prometheus)"
	return
}

# _prom_wait_target JOB: waits until Prometheus has scraped the target of JOB successfully.
_prom_wait_target() {
	local job=$1 i result=''
	for ((i = 0; i < 45; i++)); do
		result=$(curl -s --max-time 10 -G "$(_prom_url)/api/v1/query" --data-urlencode "query=up{job=\"${job}\"}")
		[[ ${result} != *'"value":['*',"1"]'* ]] || return 0
		sleep 2
	done
	die "prometheus: the target ${job} is not up (${result:-no answer})."
}

mod_remove() {
	mon_web_admin_remove
	mon_datasource_remove
	mon_target_remove prometheus
	svc_disable "${PROM_UNIT}"
	svc_dropin_remove "${PROM_UNIT}.service" lss-sandbox
	svc_dropin_remove "${PROM_UNIT}.service" lss-vpn
	file_remove "${PROM_RULES_DIR}/lss.yml"
	file_remove "${PROM_CONF}"
	rmdir "${PROM_RULES_DIR}" 2>/dev/null || true
	if os_is_debian; then
		svc_dropin_remove "${PROM_UNIT}.service" lss-config
		pkg_remove prometheus
	else
		file_remove "/etc/systemd/system/${PROM_UNIT}.service"
		svc_daemon_reload
		mon_upstream_remove prometheus promtool
	fi
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	mon_delete "$(_prom_data)"
	return
}
