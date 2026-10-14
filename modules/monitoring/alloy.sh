# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="alloy"
MOD_GROUP="monitoring"
MOD_DESCRIPTION="Grafana Alloy ships the systemd journal of the server to Loki (Promtail's successor); its UI on 127.0.0.1:12345"
MOD_REQUIRES="system loki"
MOD_OPTIONS="max_age|12h|How far back Alloy reads the journal when it starts without a saved position (Go duration: 12h, 30m)"
MOD_PORTS="none (UI on 127.0.0.1:12345)"

# Promtail reached its end of life on 2 March 2026 (https://grafana.com/docs/loki/latest/send-data/promtail/, checked
# 2026-10-14); Grafana Alloy replaces it and comes from the same repository (data/repos/grafana.conf) for every
# supported system. The package starts nothing on installation.
ALLOY_UNIT=alloy
ALLOY_CONF=/etc/lss/alloy/config.alloy
ALLOY_DATA=/var/lib/alloy/data
ALLOY_UI=127.0.0.1:12345

mod_check() {
	[[ $(opt max_age) =~ ^[1-9][0-9]*(h|m)$ ]] || die "LSS_ALLOY_MAX_AGE must look like 12h or 30m."
	return
}

mod_install() {
	repo_add grafana
	pkg_install alloy
	return
}

# _alloy_config: the journal with the unit, the priority and the host as labels, pushed to Loki.
_alloy_config() {
	cat <<EOF
// Managed by lss (module alloy). Change LSS_ALLOY_* in /etc/lss/lss.conf and run lss configure alloy.
loki.relabel "journal" {
  forward_to = []

  rule {
    source_labels = ["__journal__systemd_unit"]
    target_label  = "unit"
  }
  rule {
    source_labels = ["__journal_priority_keyword"]
    target_label  = "level"
  }
  rule {
    source_labels = ["__journal_syslog_identifier"]
    target_label  = "identifier"
  }
}

loki.source.journal "journal" {
  max_age       = "$(opt max_age)"
  relabel_rules = loki.relabel.journal.rules
  labels        = {job = "systemd-journal", host = constants.hostname}
  forward_to    = [loki.write.local.receiver]
}

loki.write "local" {
  endpoint {
    url = "http://$(mon_address loki):3100/loki/api/v1/push"
  }
}
EOF
	return
}

mod_configure() {
	local before config
	before=$(files_changes_of alloy)
	install -d -m 0755 "$(dirname "${ALLOY_CONF}")"
	config=$(_alloy_config)
	file_write 0644 root:root "${ALLOY_CONF}" <<<"${config}"
	mon_dir "${ALLOY_DATA}" alloy:alloy 0770
	mon_exec "${ALLOY_UNIT}" "/usr/bin/alloy run --server.http.listen-addr=${ALLOY_UI} --storage.path=${ALLOY_DATA} --disable-reporting ${ALLOY_CONF}"
	# The journal is readable for the groups systemd-journal and adm, which the package adds the user alloy to.
	svc_sandbox "${ALLOY_UNIT}.service" ReadWritePaths=/var/lib/alloy
	svc_enable "${ALLOY_UNIT}"
	if [[ $(files_changes_of alloy) != "${before}" ]]; then
		svc_restart "${ALLOY_UNIT}" || die "alloy: Alloy does not start."
	fi
	return
}

# _alloy_probe: writes a line to the journal and waits until Loki returns it.
_alloy_probe() {
	local token i result='' url
	url="http://$(mon_address loki):3100/loki/api/v1/query_range"
	token="lss-alloy-probe-$(date +%s)-${RANDOM}"
	logger -t lss-alloy-probe "${token}"
	for ((i = 0; i < 45; i++)); do
		result=$(curl -s --max-time 10 -G "${url}" --data-urlencode "query={job=\"systemd-journal\"} |= \"${token}\"" \
			--data-urlencode "start=$(($(date +%s) - 600))000000000" || true)
		[[ ${result} != *"${token}"* ]] || return 0
		sleep 2
	done
	die "alloy: a journal line does not reach Loki."
}

mod_verify() {
	svc_is_active "${ALLOY_UNIT}" || die "alloy: ${ALLOY_UNIT} is not running."
	mon_wait_http "http://${ALLOY_UI}/-/ready" 60
	_alloy_probe
	mon_listen_check --process alloy "${ALLOY_UI##*:}" "${ALLOY_UI%:*}"
	return
}

mod_remove() {
	svc_disable "${ALLOY_UNIT}"
	svc_dropin_remove "${ALLOY_UNIT}.service" lss-sandbox
	svc_dropin_remove "${ALLOY_UNIT}.service" lss-config
	file_remove "${ALLOY_CONF}"
	rmdir "$(dirname "${ALLOY_CONF}")" 2>/dev/null || true
	pkg_remove alloy
	mon_grafana_repo_remove
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	mon_delete /var/lib/alloy
	return
}
