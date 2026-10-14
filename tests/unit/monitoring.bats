#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The monitoring layer (lib/monitoring.sh) and the WireGuard address of the server (lib/firewall.sh): addresses and
# access, the files Prometheus and Grafana read, drop-ins and units, upstream releases and the checks of the modules.

setup() {
	load helpers
	lss_test_setup
	use_os debian-13
	shopt -s lastpipe
	export TMPDIR=${BATS_TEST_TMPDIR}
	export LSS_MODULE=grafana
	WRITES=${BATS_TEST_TMPDIR}/writes
	: >"${WRITES}"
	MON_TARGETS_DIR=${BATS_TEST_TMPDIR}/prometheus/targets
	MON_ALERTMANAGERS_DIR=${BATS_TEST_TMPDIR}/prometheus/alertmanagers
	MON_PROMETHEUS_DIR=${BATS_TEST_TMPDIR}/prometheus
	MON_DATASOURCES_DIR=${BATS_TEST_TMPDIR}/grafana/datasources
	MON_BIN_DIR=${BATS_TEST_TMPDIR}/bin
	mkdir -p "${MON_BIN_DIR}"
	MON_CACHE_DIR=${BATS_TEST_TMPDIR}/cache
	MON_POLICY_RC=${BATS_TEST_TMPDIR}/policy-rc.d
	# file_write records "== MODE OWNER DEST" and the content, and reports a change unless TEST_FILE_CHANGED=0.
	# shellcheck disable=SC2329 # called by the functions under test
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${WRITES}"
		cat >>"${WRITES}"
		LSS_FILE_CHANGED=${TEST_FILE_CHANGED:-1}
		if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
			files_note_change "wrote $3"
		fi
	}
	# install without -o and -g, so it runs as the test user.
	# shellcheck disable=SC2329 # called by the functions under test
	install() {
		local -a args=()
		while [[ $# -gt 0 ]]; do
			case $1 in
			-o | -g) shift ;;
			*) args+=("$1") ;;
			esac
			shift
		done
		command install "${args[@]}"
	}
}

# --- addresses and access ---------------------------------------------------------------------------------------

@test "the server takes the first address of the WireGuard network" {
	[ "$(fw_vpn_address)" = 10.66.0.1 ]
	config_set LSS_WIREGUARD_NETWORK 172.20.5.7/16
	[ "$(fw_vpn_address)" = 172.20.0.1 ]
	config_set LSS_WIREGUARD_NETWORK 192.168.10.8/30
	[ "$(fw_vpn_address)" = 192.168.10.9 ]
}

@test "the WireGuard network must be IPv4 with a prefix from /8 to /30" {
	config_set LSS_WIREGUARD_NETWORK fd00::/64
	run fw_vpn_address
	[ "${status}" -eq 1 ]
	[[ ${output} == *"must be an IPv4 network such as 10.66.0.0/24."* ]]
	config_set LSS_WIREGUARD_NETWORK 10.66.0.0/31
	run fw_vpn_address
	[ "${status}" -eq 1 ]
	[[ ${output} == *"needs a prefix from /8 to /30, got /31."* ]]
}

@test "a module listens on 127.0.0.1, or on the WireGuard address with access vpn" {
	run ! mon_vpn grafana
	[ "$(mon_address grafana)" = 127.0.0.1 ]
	config_set LSS_GRAFANA_ACCESS vpn
	mon_vpn grafana
	[ "$(mon_address grafana)" = 10.66.0.1 ]
}

@test "access vpn needs the WireGuard address on an interface" {
	# shellcheck disable=SC2329 # called by the functions under test
	ip() {
		printf '%s\n' "${TEST_IP:-}"
	}
	mon_vpn_ready
	config_set LSS_GRAFANA_ACCESS vpn
	run mon_vpn_ready
	[ "${status}" -eq 1 ]
	[[ ${output} == *"LSS_GRAFANA_ACCESS=vpn needs the WireGuard address 10.66.0.1; install the wireguard module first"* ]]
	TEST_IP='4: wg0    inet 10.66.0.1/24 scope global wg0'
	mon_vpn_ready
}

@test "with access vpn the unit starts after wg0; with access local the drop-in goes away" {
	local dropin=${BATS_TEST_TMPDIR}/grafana-server.service.d/lss-vpn.conf
	config_set LSS_GRAFANA_ACCESS vpn
	mon_vpn_dropin grafana-server.service
	[ "${LSS_FILE_CHANGED}" = 1 ]
	grep -qxF '== 0644 root:root /etc/systemd/system/grafana-server.service.d/lss-vpn.conf' "${WRITES}"
	grep -qxF 'After=wg-quick@wg0.service' "${WRITES}"
	grep -qxF 'Wants=wg-quick@wg0.service' "${WRITES}"
	grep -q 'systemctl daemon-reload' "${STUB_LOG}"
	config_set LSS_GRAFANA_ACCESS local
	mon_vpn_dropin grafana-server.service
	[ "${LSS_FILE_CHANGED}" = 0 ]
	# An existing drop-in is removed (the unit name leads into the test directory).
	[ -d /etc/systemd/system ] || skip "no /etc/systemd/system on this machine"
	mkdir -p "$(dirname "${dropin}")"
	: >"${dropin}"
	mon_vpn_dropin "../../..${BATS_TEST_TMPDIR}/grafana-server.service"
	[ "${LSS_FILE_CHANGED}" = 1 ]
	[ ! -e "${dropin}" ]
}

@test "ports open to the WireGuard network with access vpn and close with access local" {
	# shellcheck disable=SC2329 # called by the functions under test
	fw_allow() {
		printf 'allow %s\n' "$*" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by the functions under test
	fw_remove_module() {
		printf 'remove %s\n' "${LSS_MODULE}" >>"${STUB_LOG}"
	}
	config_set LSS_GRAFANA_ACCESS vpn
	mon_firewall 3000/tcp 3001/udp
	grep -qxF 'allow 3000/tcp:vpn' "${STUB_LOG}"
	grep -qxF 'allow 3001/udp:vpn' "${STUB_LOG}"
	config_set LSS_GRAFANA_ACCESS local
	mon_firewall 3000/tcp
	grep -qxF 'remove grafana' "${STUB_LOG}"
}

# --- admin paths ------------------------------------------------------------------------------------------------

admin_stubs() {
	# shellcheck disable=SC2329 # called by the functions under test
	web_server() {
		printf '%s' "${TEST_SERVER:-}"
	}
	# shellcheck disable=SC2329 # called by the functions under test
	web_admin_write() {
		printf 'admin_write %s\n' "$*" >>"${STUB_LOG}"
		[[ ${TEST_FILE_CHANGED:-1} == 0 ]] || files_note_change "admin $1"
	}
	# shellcheck disable=SC2329 # called by the functions under test
	web_admin_remove() {
		printf 'admin_remove %s\n' "$*" >>"${STUB_LOG}"
		[[ ${TEST_FILE_CHANGED:-1} == 0 ]] || files_note_change "removed admin $1"
	}
	# shellcheck disable=SC2329 # called by the functions under test
	web_reload() {
		printf 'reload\n' >>"${STUB_LOG}"
	}
}

@test "the admin path follows LSS_<MODULE>_WEB_ADMIN and reloads the web server only on a change" {
	admin_stubs
	mon_web_admin proxy http://127.0.0.1:3000
	[ ! -s "${STUB_LOG}" ]
	TEST_SERVER=nginx
	config_set LSS_GRAFANA_WEB_ADMIN true
	mon_web_admin proxy http://127.0.0.1:3000
	grep -qxF 'admin_write grafana grafana proxy http://127.0.0.1:3000' "${STUB_LOG}"
	grep -qxF 'reload' "${STUB_LOG}"
	: >"${STUB_LOG}"
	TEST_FILE_CHANGED=0 mon_web_admin proxy http://127.0.0.1:3000
	run ! grep -q reload "${STUB_LOG}"
	config_set LSS_GRAFANA_WEB_ADMIN false
	mon_web_admin proxy http://127.0.0.1:3000
	grep -qxF 'admin_remove grafana' "${STUB_LOG}"
	: >"${STUB_LOG}"
	mon_web_admin_remove
	grep -qxF 'admin_remove grafana' "${STUB_LOG}"
	grep -qxF 'reload' "${STUB_LOG}"
	TEST_SERVER=''
	: >"${STUB_LOG}"
	mon_web_admin_remove
	[ ! -s "${STUB_LOG}" ]
}

@test "an admin path the removed web server took along is no longer expected" {
	local list=${LSS_STATE_DIR}/managed/grafana
	mkdir -p "${LSS_STATE_DIR}/managed"
	printf 'abc\t/etc/nginx/lss/admin/grafana.conf\nabc\t/etc/lss/grafana/admin-password\n' >"${list}"
	admin_stubs
	TEST_SERVER=''
	config_set LSS_GRAFANA_WEB_ADMIN true
	mon_web_admin proxy http://127.0.0.1:3000
	[ "$(cat "${list}")" = $'abc\t/etc/lss/grafana/admin-password' ]
	[ ! -s "${STUB_LOG}" ]
}

# --- Prometheus and Grafana -------------------------------------------------------------------------------------

@test "a scrape target names its job and metrics path for Prometheus" {
	LSS_MODULE=prometheus
	mon_target prometheus prometheus 127.0.0.1:9090 /prometheus/metrics
	grep -qxF "== 0644 root:root ${MON_TARGETS_DIR}/prometheus.yml" "${WRITES}"
	grep -qxF -e "- targets: ['127.0.0.1:9090']" "${WRITES}"
	grep -qxF '    job: prometheus' "${WRITES}"
	grep -qxF '    __metrics_path__: /prometheus/metrics' "${WRITES}"
	mon_target node node 127.0.0.1:9100
	grep -qxF '    __metrics_path__: /metrics' "${WRITES}"
	: >"${MON_TARGETS_DIR}/node.yml"
	# shellcheck disable=SC2329 # called by the functions under test
	file_remove() {
		rm -f -- "$1"
	}
	mon_target_remove node
	[ ! -e "${MON_TARGETS_DIR}" ]
}

@test "a data source is provisioned for Grafana, which restarts only when it runs and the file changed" {
	LSS_MODULE=prometheus
	mon_datasource Prometheus prometheus http://127.0.0.1:9090/prometheus true
	grep -qxF "== 0644 root:root ${MON_DATASOURCES_DIR}/prometheus.yaml" "${WRITES}"
	grep -qxF '  - name: Prometheus' "${WRITES}"
	grep -qxF '    uid: lss-prometheus' "${WRITES}"
	grep -qxF '    url: http://127.0.0.1:9090/prometheus' "${WRITES}"
	grep -qxF '    isDefault: true' "${WRITES}"
	run ! grep -q 'systemctl restart' "${STUB_LOG}"
	export STUB_ACTIVE_UNITS=grafana-server
	LSS_MODULE=alertmanager
	mon_datasource Alertmanager alertmanager http://127.0.0.1:9093/alertmanager
	grep -qxF '    isDefault: false' "${WRITES}"
	grep -qxF '      implementation: prometheus' "${WRITES}"
	grep -q 'systemctl restart grafana-server' "${STUB_LOG}"
	: >"${STUB_LOG}"
	TEST_FILE_CHANGED=0 mon_datasource Alertmanager alertmanager http://127.0.0.1:9093/alertmanager
	run ! grep -q 'systemctl restart' "${STUB_LOG}"
	file_remove() {
		printf 'remove %s\n' "$1" >>"${STUB_LOG}"
	}
	mon_datasource_remove
	grep -qxF "remove ${MON_DATASOURCES_DIR}/alertmanager.yaml" "${STUB_LOG}"
}

@test "a data source that Grafana does not take stops the run" {
	export STUB_ACTIVE_UNITS=grafana-server STUB_EXIT_systemctl=1
	run mon_datasource Loki loki http://127.0.0.1:3100
	[ "${status}" -eq 1 ]
	[[ ${output} == *"grafana: Grafana does not start with the new data source."* ]]
}

@test "units and drop-ins of the monitoring services" {
	LSS_MODULE=prometheus
	mon_unit prometheus prometheus '/usr/local/bin/prometheus --config.file=/x' 'Prometheus monitoring system'
	grep -qxF '== 0644 root:root /etc/systemd/system/prometheus.service' "${WRITES}"
	grep -qxF 'Description=Prometheus monitoring system' "${WRITES}"
	grep -qxF 'User=prometheus' "${WRITES}"
	grep -qxF 'ExecStart=/usr/local/bin/prometheus --config.file=/x' "${WRITES}"
	grep -qxF "ExecReload=/bin/kill -HUP \$MAINPID" "${WRITES}"
	grep -qxF 'WantedBy=multi-user.target' "${WRITES}"
	: >"${WRITES}"
	mon_exec prometheus '/usr/bin/prometheus --config.file=/x'
	grep -qxF '== 0644 root:root /etc/systemd/system/prometheus.service.d/lss-config.conf' "${WRITES}"
	[ "$(grep -c '^ExecStart=' "${WRITES}")" = 2 ]
	grep -qxF 'EnvironmentFile=' "${WRITES}"
	grep -qxF 'ExecStart=/usr/bin/prometheus --config.file=/x' "${WRITES}"
}

@test "Grafana's repository goes with the last of grafana, loki and alloy" {
	# shellcheck disable=SC2329 # called by the functions under test
	repo_remove() {
		printf 'repo_remove %s\n' "$1" >>"${STUB_LOG}"
	}
	state_set grafana status installed
	state_set loki status installed
	mon_grafana_repo_remove
	[ ! -s "${STUB_LOG}" ]
	state_set loki status removed
	mon_grafana_repo_remove
	grep -qxF 'repo_remove grafana' "${STUB_LOG}"
}

# --- packages and upstream releases -----------------------------------------------------------------------------

@test "Debian packages install with service starts forbidden, and the policy goes away afterwards" {
	export STUB_OUT_dpkg_query='deinstall ok config-files'
	# shellcheck disable=SC2329 # called by the functions under test
	pkg_install() {
		printf 'pkg_install %s policy=%s\n' "$*" "$(tail -n 1 "${MON_POLICY_RC}" 2>/dev/null)" >>"${STUB_LOG}"
	}
	mon_install_stopped prometheus
	grep -qxF 'pkg_install prometheus policy=exit 101' "${STUB_LOG}"
	[ ! -e "${MON_POLICY_RC}" ]
	# A policy of the system's own stays untouched.
	printf '#!/bin/sh\nexit 0\n' >"${MON_POLICY_RC}"
	mon_install_stopped prometheus
	grep -qxF 'pkg_install prometheus policy=exit 0' "${STUB_LOG}"
	[ -f "${MON_POLICY_RC}" ]
	rm -f -- "${MON_POLICY_RC}"
	use_os rocky-9
	: >"${STUB_LOG}"
	mon_install_stopped grafana
	grep -qxF 'pkg_install grafana policy=' "${STUB_LOG}"
}

@test "the policy is removed when the installation fails" {
	export STUB_OUT_dpkg_query='deinstall ok config-files'
	# shellcheck disable=SC2329 # called by the functions under test
	pkg_install() {
		die "apt failed"
	}
	run mon_install_stopped prometheus
	[ "${status}" -eq 1 ]
	[ ! -e "${MON_POLICY_RC}" ]
}

# A release archive with the programs NAME and NAME-tool in a top-level directory, as fetch_verified would download it.
fake_release() {
	local name=$1 version=$2 dir
	dir=${BATS_TEST_TMPDIR}/release/${name}-${version}.linux-amd64
	mkdir -p "${dir}"
	printf '#!/bin/sh\necho "%s, version %s (branch: HEAD)"\n' "${name}" "${version}" >"${dir}/${name}"
	printf '#!/bin/sh\n' >"${dir}/${name}tool"
	chmod +x "${dir}/${name}" "${dir}/${name}tool"
	tar -czf "${BATS_TEST_TMPDIR}/release.tar.gz" -C "${BATS_TEST_TMPDIR}/release" "${name}-${version}.linux-amd64"
	# shellcheck disable=SC2329 # called by the functions under test
	fetch_verified() {
		printf 'fetch %s\n' "$1" >>"${STUB_LOG}"
		mkdir -p "$(dirname "$2")"
		cp "${BATS_TEST_TMPDIR}/release.tar.gz" "$2"
	}
}

@test "an upstream release is installed once per version and removed again" {
	fake_release prom 3.13.4
	mon_upstream_install prom 3.13.4 prom promtool
	grep -qxF 'fetch prom-3.13.4' "${STUB_LOG}"
	[ -x "${MON_BIN_DIR}/prom" ]
	[ -x "${MON_BIN_DIR}/promtool" ]
	[ -z "$(ls -A "${MON_CACHE_DIR}")" ]
	[ "$(files_changes_of grafana)" = 1 ]
	: >"${STUB_LOG}"
	mon_upstream_install prom 3.13.4 prom promtool
	[ ! -s "${STUB_LOG}" ]
	mon_upstream_remove prom promtool missing
	[ ! -e "${MON_BIN_DIR}/prom" ]
	[ ! -e "${MON_BIN_DIR}/promtool" ]
	[ "$(files_changes_of grafana)" = 3 ]
}

@test "an archive without the expected program stops the run" {
	fake_release prom 3.13.4
	run mon_upstream_install prom 3.13.4 prom other
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the prom 3.13.4 archive has no other; its layout changed."* ]]
}

@test "service users are created once, without login" {
	# shellcheck disable=SC2329 # called by the functions under test
	useradd() {
		printf 'useradd %s\n' "$*" >>"${STUB_LOG}"
	}
	export STUB_GETENT=""
	mon_user prometheus /var/lib/prometheus
	grep -qxF 'useradd --system --user-group --home-dir /var/lib/prometheus --no-create-home --shell /usr/sbin/nologin prometheus' "${STUB_LOG}"
	export STUB_GETENT=passwd:prometheus
	: >"${STUB_LOG}"
	mon_user prometheus /var/lib/prometheus
	run ! grep -q useradd "${STUB_LOG}"
}

@test "data directories are created and their owner and mode kept, never through a link" {
	local dir=${BATS_TEST_TMPDIR}/data
	mon_dir "${dir}" "${OWNER}" 0750
	[ "$(stat -c '%a' "${dir}")" = 750 ]
	chmod 0755 "${dir}"
	mon_dir "${dir}" "${OWNER}" 0750
	[ "$(stat -c '%a' "${dir}")" = 750 ]
	mon_dir "${dir}" "${OWNER}" 0750
	[ "$(files_changes_of grafana)" = 2 ]
	ln -s "${dir}" "${BATS_TEST_TMPDIR}/link"
	run mon_dir "${BATS_TEST_TMPDIR}/link" "${OWNER}" 0750
	[ "${status}" -eq 1 ]
	[[ ${output} == *"is a symbolic link."* ]]
}

@test "only data directories below /var/lib are deleted" {
	run mon_delete /etc/grafana
	[ "${status}" -eq 1 ]
	[[ ${output} == *"refusing to delete /etc/grafana."* ]]
	run mon_delete /var/lib/../etc
	[ "${status}" -eq 1 ]
	mon_delete /var/lib/lss-test-does-not-exist
	[ "$(files_changes_of grafana)" = 0 ]
}

# --- checks -----------------------------------------------------------------------------------------------------

@test "HTTP checks wait for 200 and report the last status" {
	# shellcheck disable=SC2329 # called by the functions under test
	sleep() {
		:
	}
	# shellcheck disable=SC2329 # called by the functions under test
	curl() {
		printf '%s' "${TEST_HTTP_CODE}"
	}
	TEST_HTTP_CODE=200
	[ "$(mon_http http://127.0.0.1:9090/-/ready)" = 200 ]
	mon_wait_http http://127.0.0.1:9090/-/ready
	TEST_HTTP_CODE=503
	run mon_wait_http http://127.0.0.1:9090/-/ready 4
	[ "${status}" -eq 1 ]
	[[ ${output} == *"grafana: http://127.0.0.1:9090/-/ready does not answer (503)."* ]]
}

@test "listening sockets must be on the expected addresses, of the named process" {
	# shellcheck disable=SC2329 # called by the functions under test
	ss() {
		printf '%s\n' "${TEST_SS:-}"
	}
	TEST_SS=$'LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:(("grafana",pid=10,fd=8))\nLISTEN 0 4096 [::1]:3000 [::]:* users:(("grafana",pid=10,fd=9))'
	mon_listen_check 3000 127.0.0.1 ::1
	run mon_listen_check 3000 127.0.0.1
	[ "${status}" -eq 1 ]
	[[ ${output} == *"grafana: port 3000 is open on ::1, expected 127.0.0.1 only."* ]]
	TEST_SS='LISTEN 0 4096 0.0.0.0:53 0.0.0.0:* users:(("systemd-resolve",pid=5,fd=3))'
	run mon_listen_check --process unbound 53 127.0.0.1
	[ "${status}" -eq 1 ]
	[[ ${output} == *"grafana: nothing listens on port 53."* ]]
	TEST_SS=$'LISTEN 0 4096 10.66.0.1%wg0:53 0.0.0.0:* users:(("unbound",pid=5,fd=3))\nLISTEN 0 4096 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=6,fd=3))'
	mon_listen_check --process unbound 53 10.66.0.1
}

# --- the monitoring modules -------------------------------------------------------------------------------------

# load_module NAME: sources the module as lss does for a step.
load_module() {
	local file
	file=$(module_file "$1")
	export LSS_MODULE=$1
	# shellcheck source=/dev/null
	source "${file}"
	return
}

@test "every monitoring module checks its access setting" {
	local module
	for module in node-exporter prometheus alertmanager grafana loki netdata; do
		load_module "${module}"
		mod_check
		config_set "$(config_key "${module}" access)" public
		run mod_check
		[ "${status}" -eq 1 ]
		[[ ${output} == *"must be local or vpn."* ]]
	done
}

@test "the node exporter listens on its address and reads the textfile directory" {
	load_module node-exporter
	[ "$(_node_command)" = '/usr/bin/prometheus-node-exporter --web.listen-address=127.0.0.1:9100 --collector.textfile.directory=/var/lib/prometheus/node-exporter' ]
	use_os rocky-9
	config_set LSS_NODE_EXPORTER_ACCESS vpn
	[ "$(_node_command)" = '/usr/local/bin/node_exporter --web.listen-address=10.66.0.1:9100 --collector.textfile.directory=/var/lib/prometheus/node-exporter' ]
	[ "$(_node_user)" = node_exporter ]
}

@test "Prometheus finds targets and Alertmanagers in files and serves below /prometheus/" {
	load_module prometheus
	run _prom_config
	[[ ${output} == *"  - ${MON_PROMETHEUS_DIR}/rules/*.yml"* ]]
	[[ ${output} == *"    - path_prefix: /alertmanager/"* ]]
	[[ ${output} == *"        - files: ['${MON_ALERTMANAGERS_DIR}/*.yml']"* ]]
	[[ ${output} == *"      - files: ['${MON_TARGETS_DIR}/*.yml']"* ]]
	config_set LSS_PROMETHEUS_RETENTION 30d
	run _prom_command
	[[ ${output} == '/usr/bin/prometheus --config.file='*' --storage.tsdb.path=/var/lib/prometheus/metrics2 --storage.tsdb.retention.time=30d --web.listen-address=127.0.0.1:9090 --web.external-url=http://127.0.0.1:9090/prometheus/' ]]
	use_os almalinux-10
	run _prom_command
	[[ ${output} == '/usr/local/bin/prometheus '*'--storage.tsdb.path=/var/lib/prometheus/data '* ]]
	config_set LSS_PROMETHEUS_RETENTION 2weeks
	run mod_check
	[[ ${output} == *"LSS_PROMETHEUS_RETENTION must look like 15d"* ]]
}

@test "the alert rules cover targets, disks, the guard and the backup" {
	local rules=${REPO_ROOT}/templates/prometheus/rules.yml alert
	for alert in LssTargetDown LssDiskAlmostFull LssMemoryLow LssGuardFindings LssGuardStale LssBackupFailed LssBackupTooOld LssRestoreTestFailed; do
		grep -qxF "      - alert: ${alert}" "${rules}"
	done
	# The template engine leaves the placeholders of Prometheus itself alone.
	run template_render "${rules}"
	[ "${status}" -eq 0 ]
	[[ ${output} == *'{{ $labels.instance }}'* ]]
}

@test "Alertmanager sends to e-mail and webhook when set and keeps its cluster port closed" {
	load_module alertmanager
	run _am_config
	[[ ${output} == *$'receivers:\n  - name: lss'* ]]
	[[ ${output} != *email_configs* && ${output} != *webhook_configs* ]]
	config_set LSS_ALERTMANAGER_EMAIL ops@example.com
	config_set LSS_ALERTMANAGER_WEBHOOK https://hooks.example.com/abc
	run _am_config
	[[ ${output} == *"      - to: 'ops@example.com'"* ]]
	[[ ${output} == *"        smarthost: 'localhost:25'"* ]]
	[[ ${output} == *"      - url: 'https://hooks.example.com/abc'"* ]]
	run _am_command
	[[ ${output} == *' --web.external-url=http://127.0.0.1:9093/alertmanager/ --cluster.listen-address=' ]]
	config_set LSS_ALERTMANAGER_WEBHOOK 'http://hooks.example.com/x'
	run mod_check
	[[ ${output} == *"LSS_ALERTMANAGER_WEBHOOK must be an https:// URL."* ]]
	config_set LSS_ALERTMANAGER_WEBHOOK ''
	config_set LSS_ALERTMANAGER_EMAIL 'not mail'
	run mod_check
	[[ ${output} == *"is not an e-mail address."* ]]
}

@test "Grafana runs below /grafana/ with its password from a file and nothing sent home" {
	load_module grafana
	run _grafana_environment
	[[ ${output} == *'Environment=GF_SERVER_HTTP_ADDR=127.0.0.1'* ]]
	[[ ${output} == *'Environment=GF_SERVER_ROOT_URL=http://127.0.0.1:3000/grafana/'* ]]
	[[ ${output} == *'Environment=GF_SERVER_SERVE_FROM_SUB_PATH=true'* ]]
	[[ ${output} == *"Environment=GF_SECURITY_ADMIN_PASSWORD=\$__file{${MON_GRAFANA_DIR}/admin-password}"* ]]
	[[ ${output} == *'Environment=GF_ANALYTICS_REPORTING_ENABLED=false'* ]]
	# The password itself never goes into the unit.
	run ! grep -E '^Environment=GF_SECURITY_ADMIN_PASSWORD=[^$]' <<<"${output}"
}

@test "Loki keeps every component on this server with retention" {
	load_module loki
	config_set LSS_LOKI_RETENTION_DAYS 14
	run _loki_config
	[[ ${output} == *$'  http_listen_address: 127.0.0.1\n  http_listen_port: 3100\n  grpc_listen_address: 127.0.0.1'* ]]
	[[ ${output} == *'      store: inmemory'* ]]
	[[ ${output} == *'  retention_period: 336h'* ]]
	[[ ${output} == *'  reporting_enabled: false'* ]]
	config_set LSS_LOKI_RETENTION_DAYS 0
	run mod_check
	[[ ${output} == *"LSS_LOKI_RETENTION_DAYS must be at least 1."* ]]
}

@test "Alloy ships the journal to the local Loki" {
	load_module alloy
	run _alloy_config
	[[ ${output} == *'loki.source.journal "journal" {'* ]]
	[[ ${output} == *'  max_age       = "12h"'* ]]
	[[ ${output} == *'url = "http://127.0.0.1:3100/loki/api/v1/push"'* ]]
	config_set LSS_LOKI_ACCESS vpn
	run _alloy_config
	[[ ${output} == *'url = "http://10.66.0.1:3100/loki/api/v1/push"'* ]]
	config_set LSS_ALLOY_MAX_AGE 2d
	run mod_check
	[[ ${output} == *"LSS_ALLOY_MAX_AGE must look like 12h or 30m."* ]]
}

@test "Netdata binds to 127.0.0.1 and the WireGuard address, without registry or statistics" {
	load_module netdata
	# shellcheck disable=SC2329 # called by the functions under test
	install() {
		:
	}
	_netdata_files
	grep -qxF $'\tbind to = 127.0.0.1' "${WRITES}"
	grep -qxF '[registry]' "${WRITES}"
	grep -qxF "== 0644 root:root ${NETDATA_OPT_OUT}" "${WRITES}"
	config_set LSS_NETDATA_ACCESS vpn
	[ "$(_netdata_bind)" = '127.0.0.1 10.66.0.1' ]
}

@test "smartd finds its unit and configuration on each family and checks the temperatures" {
	load_module smartd
	# shellcheck disable=SC2329 # called by the functions under test
	systemctl() {
		printf 'smartmontools.service\n'
	}
	[ "$(_smartd_unit)" = smartmontools.service ]
	[ "$(_smartd_conf)" = /etc/smartd.conf ]
	use_os rocky-9
	[ "$(_smartd_conf)" = /etc/smartmontools/smartd.conf ]
	mod_check
	config_set LSS_SMARTD_TEMPERATURE 50
	run mod_check
	[[ ${output} == *"LSS_SMARTD_TEMPERATURE must look like 45,55."* ]]
}
