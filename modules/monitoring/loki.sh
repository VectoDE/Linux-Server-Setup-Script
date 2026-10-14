# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="loki"
MOD_GROUP="monitoring"
MOD_DESCRIPTION="Grafana Loki as a single-binary log store on the local disk, with retention; API on 127.0.0.1:3100 or the WireGuard network, a Grafana data source"
MOD_REQUIRES="system"
MOD_OPTIONS="access|local|Who reaches the API on port 3100: local (this server: Alloy, Grafana) or vpn (also log shippers in the WireGuard network)
retention_days|31|Days Loki keeps the logs"
MOD_PORTS="3100/tcp from the WireGuard network with access vpn; none with access local"

# Grafana's repository (data/repos/grafana.conf) packages Loki for every supported system. The package's own unit
# starts Loki with /etc/loki/config.yml; a drop-in points it to the configuration below instead.
LOKI_UNIT=loki
LOKI_PORT=3100
LOKI_GRPC_PORT=9095
LOKI_CONF=/etc/lss/loki/config.yml
LOKI_DATA=/var/lib/loki

_loki_url() {
	mon_url loki "${LOKI_PORT}"
	return
}

mod_check() {
	local days
	[[ $(opt access) =~ ^(local|vpn)$ ]] || die "LSS_LOKI_ACCESS must be local or vpn."
	days=$(opt_int retention_days)
	((days >= 1)) || die "LSS_LOKI_RETENTION_DAYS must be at least 1."
	return
}

# _loki_config: one process with every component, an in-memory ring (no gossip port), the TSDB index and the chunks on
# the local disk; the compactor deletes what is older than the retention.
_loki_config() {
	local days hours
	days=$(opt_int retention_days)
	hours=$((days * 24))
	cat <<EOF
${MON_MANAGED_BY} loki). Change LSS_LOKI_* in /etc/lss/lss.conf and run lss configure loki.
auth_enabled: false
server:
  http_listen_address: $(mon_address loki)
  http_listen_port: ${LOKI_PORT}
  grpc_listen_address: 127.0.0.1
  grpc_listen_port: ${LOKI_GRPC_PORT}
  log_level: warn
common:
  instance_addr: 127.0.0.1
  path_prefix: ${LOKI_DATA}
  replication_factor: 1
  storage:
    filesystem:
      chunks_directory: ${LOKI_DATA}/chunks
      rules_directory: ${LOKI_DATA}/rules
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
limits_config:
  retention_period: ${hours}h
compactor:
  working_directory: ${LOKI_DATA}/compactor
  retention_enabled: true
  delete_request_store: filesystem
analytics:
  reporting_enabled: false
EOF
	return
}

# _loki_files: the configuration, the drop-in and the sandbox. Written before the package as well: its installation
# script restarts Loki right away, which must not happen with the package's configuration (every address).
_loki_files() {
	local config
	install -d -m 0755 "$(dirname "${LOKI_CONF}")"
	config=$(_loki_config)
	file_write 0644 root:root "${LOKI_CONF}" <<<"${config}"
	mon_exec "${LOKI_UNIT}" "/usr/bin/loki -config.file=${LOKI_CONF}"
	svc_sandbox "${LOKI_UNIT}.service" "ReadWritePaths=-${LOKI_DATA}"
	mon_vpn_dropin "${LOKI_UNIT}.service"
	return
}

mod_install() {
	if ! pkg_is_installed loki; then
		mon_vpn_ready
		_loki_files
	fi
	repo_add grafana
	pkg_install loki
	return
}

mod_configure() {
	local before
	before=$(files_changes_of loki)
	mon_vpn_ready
	# The package creates the user loki; on Debian and Ubuntu without a group of its own (nogroup).
	mon_dir "${LOKI_DATA}" "loki:$(id -gn loki)" 0750
	_loki_files
	/usr/bin/loki -config.file="${LOKI_CONF}" -verify-config >/dev/null 2>&1 ||
		die "loki: Loki rejects ${LOKI_CONF} (loki -config.file=${LOKI_CONF} -verify-config shows why)."
	svc_enable "${LOKI_UNIT}"
	if [[ $(files_changes_of loki) != "${before}" ]] || ! svc_is_active "${LOKI_UNIT}"; then
		svc_restart "${LOKI_UNIT}" || die "loki: Loki does not start."
	fi
	mon_firewall "${LOKI_PORT}/tcp"
	mon_target loki loki "$(mon_address loki):${LOKI_PORT}"
	mon_datasource Loki loki "$(_loki_url)"
	return
}

# _loki_probe: pushes one line and waits until a query returns it.
_loki_probe() {
	local url token now i result=''
	url=$(_loki_url)
	token="lss-verify-$(date +%s)-${RANDOM}"
	now=$(date +%s%N)
	curl -s --max-time 10 -o /dev/null -H 'Content-Type: application/json' --data-binary @- "${url}/loki/api/v1/push" <<EOF || true
{"streams":[{"stream":{"job":"lss-verify"},"values":[["${now}","${token}"]]}]}
EOF
	for ((i = 0; i < 30; i++)); do
		result=$(curl -s --max-time 10 -G "${url}/loki/api/v1/query_range" --data-urlencode 'query={job="lss-verify"}' \
			--data-urlencode "start=$((now - 60000000000))" || true)
		[[ ${result} != *"${token}"* ]] || return 0
		sleep 2
	done
	die "loki: a line pushed to Loki does not come back from a query."
}

mod_verify() {
	svc_is_active "${LOKI_UNIT}" || die "loki: ${LOKI_UNIT} is not running."
	# Loki reports ready about 15 seconds after the start, when its ingester has joined the ring.
	mon_wait_http "$(_loki_url)/ready" 120
	_loki_probe
	mon_listen_check --process loki "${LOKI_PORT}" "$(mon_address loki)"
	mon_listen_check --process loki "${LOKI_GRPC_PORT}" 127.0.0.1
	return
}

mod_remove() {
	mon_datasource_remove
	mon_target_remove loki
	svc_disable "${LOKI_UNIT}"
	svc_dropin_remove "${LOKI_UNIT}.service" lss-sandbox
	svc_dropin_remove "${LOKI_UNIT}.service" lss-vpn
	svc_dropin_remove "${LOKI_UNIT}.service" lss-config
	file_remove "${LOKI_CONF}"
	rmdir "$(dirname "${LOKI_CONF}")" 2>/dev/null || true
	pkg_remove loki
	mon_grafana_repo_remove
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	mon_delete "${LOKI_DATA}"
	return
}
