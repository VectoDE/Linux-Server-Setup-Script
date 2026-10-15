# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="haproxy"
MOD_GROUP="web"
MOD_DESCRIPTION="HAProxy load balancer for TCP services (databases, mail, APIs): health checks, failover, statistics on localhost"
MOD_REQUIRES="system"
MOD_OPTIONS="services||Balanced services, separated by spaces: NAME:PORT[/public|vpn|local]:HOST:PORT[,HOST:PORT...], for example pg:5432/vpn:10.0.0.2:5432,10.0.0.3:5432 (default scope public)
balance|leastconn|How connections are spread: leastconn, roundrobin or source (the same client to the same server)
stats_port|8404|Port of the statistics page on 127.0.0.1"

HAPROXY_CONF=/etc/haproxy/haproxy.cfg
HAPROXY_SOCKET=/var/lib/haproxy/admin.sock

# _haproxy_parse SPEC: sets HAPROXY_NAME, HAPROXY_PORT, HAPROXY_SCOPE and HAPROXY_SERVERS (array of HOST:PORT).
_haproxy_parse() {
	local spec=$1 listen servers server
	HAPROXY_NAME=${spec%%:*}
	listen=${spec#*:}
	servers=${listen#*:}
	listen=${listen%%:*}
	HAPROXY_PORT=${listen%%/*}
	HAPROXY_SCOPE=public
	[[ ${listen} != */* ]] || HAPROXY_SCOPE=${listen#*/}
	[[ ${HAPROXY_NAME} =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "LSS_HAPROXY_SERVICES: '${spec}' does not start with a name (a-z, 0-9, -)."
	if [[ ! ${HAPROXY_PORT} =~ ^[0-9]+$ ]] || ((HAPROXY_PORT < 1 || HAPROXY_PORT > 65535)); then
		die "LSS_HAPROXY_SERVICES: '${HAPROXY_PORT}' in '${spec}' is not a port."
	fi
	[[ ${HAPROXY_SCOPE} =~ ^(public|vpn|local)$ ]] || die "LSS_HAPROXY_SERVICES: '${HAPROXY_SCOPE}' is not public, vpn or local."
	IFS=',' read -ra HAPROXY_SERVERS <<<"${servers}"
	if [[ ${servers} == "${spec#*:}" ]] || ((${#HAPROXY_SERVERS[@]} == 0)); then
		die "LSS_HAPROXY_SERVICES: the service ${HAPROXY_NAME} has no servers (HOST:PORT)."
	fi
	for server in "${HAPROXY_SERVERS[@]}"; do
		[[ ${server} =~ ^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]+$ ]] ||
			die "LSS_HAPROXY_SERVICES: '${server}' is not HOST:PORT (IPv6 as [address]:port)."
	done
	return
}

mod_check() {
	local spec stats
	local -A ports=()
	[[ $(opt balance) =~ ^(leastconn|roundrobin|source)$ ]] || die "LSS_HAPROXY_BALANCE must be leastconn, roundrobin or source."
	stats=$(opt_int stats_port)
	((stats >= 1 && stats <= 65535)) || die "LSS_HAPROXY_STATS_PORT must be a port."
	ports[${stats}]=stats
	for spec in $(opt services); do
		_haproxy_parse "${spec}"
		[[ -z ${ports[${HAPROXY_PORT}]+x} ]] || die "LSS_HAPROXY_SERVICES: port ${HAPROXY_PORT} is used twice."
		ports[${HAPROXY_PORT}]=${HAPROXY_NAME}
	done
	return
}

mod_install() {
	pkg_install haproxy curl
	return
}

_haproxy_bind() {
	local port=$1 scope=$2
	if [[ ${scope} == local ]]; then
		printf '\tbind 127.0.0.1:%s\n' "${port}"
	elif web_ipv6; then
		printf '\tbind :::%s v4v6\n' "${port}"
	else
		printf '\tbind 0.0.0.0:%s\n' "${port}"
	fi
	return
}

_haproxy_conf() {
	local spec server i
	cat <<EOF
# Managed by lss (module haproxy). Change LSS_HAPROXY_* in /etc/lss/lss.conf and run lss configure haproxy.
global
	log stdout format short daemon
	chroot /var/lib/haproxy
	user haproxy
	group haproxy
	stats socket ${HAPROXY_SOCKET} mode 600 level admin
	maxconn 20000
	ssl-default-bind-ciphers ${WEB_TLS_CIPHERS}
	ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
	log global
	mode tcp
	option tcplog
	option dontlognull
	timeout connect 5s
	timeout client 1h
	timeout server 1h
	timeout check 5s
	retries 3
	default-server inter 5s fall 3 rise 2

frontend lss-stats
	mode http
	bind 127.0.0.1:$(opt_int stats_port)
	timeout client 30s
	stats enable
	stats uri /
	stats refresh 10s
	stats show-legends
	http-request deny unless { src 127.0.0.1 }
EOF
	for spec in $(opt services); do
		_haproxy_parse "${spec}"
		printf '\nlisten %s\n' "${HAPROXY_NAME}"
		_haproxy_bind "${HAPROXY_PORT}" "${HAPROXY_SCOPE}"
		printf '\tbalance %s\n' "$(opt balance)"
		i=0
		for server in "${HAPROXY_SERVERS[@]}"; do
			i=$((i + 1))
			printf '\tserver %s-%s %s check\n' "${HAPROXY_NAME}" "${i}" "${server}"
		done
	done
	return
}

# Binding and connecting to ports outside HAProxy's SELinux port types needs haproxy_connect_any.
_haproxy_selinux() {
	command -v getsebool >/dev/null 2>&1 || return 0
	[[ $(getenforce 2>/dev/null) == Enforcing ]] || return 0
	if [[ $(getsebool haproxy_connect_any 2>/dev/null) != *' on' ]]; then
		setsebool -P haproxy_connect_any 1
		files_note_change "SELinux boolean haproxy_connect_any"
	fi
	return
}

# The firewall rules follow LSS_HAPROXY_SERVICES: rules of services that were removed or moved are closed first.
_haproxy_firewall() {
	local spec registry wanted=''
	for spec in $(opt services); do
		_haproxy_parse "${spec}"
		wanted+="${HAPROXY_PORT}/tcp:${HAPROXY_SCOPE}"$'\n'
	done
	registry="${LSS_STATE_DIR:-/var/lib/lss}/firewall/haproxy"
	if [[ -f ${registry} && $(sort "${registry}") != "$(printf '%s' "${wanted}" | grep -v ':local$' | sort)" ]]; then
		fw_remove_module
	fi
	for spec in ${wanted}; do
		fw_allow "${spec}"
	done
	return
}

mod_configure() {
	local changed=0
	local -a selinux=()
	_haproxy_conf | file_write 0644 root:root "${HAPROXY_CONF}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_haproxy_selinux
	_haproxy_firewall
	# Under SELinux haproxy runs in its own domain (haproxy_t). NoNewPrivileges blocks the change from init_t, unlike for
	# nginx and Apache, whose domains the policy allows it; in init_t haproxy may not create its admin socket.
	if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
		selinux=(NoNewPrivileges=no)
	fi
	svc_sandbox haproxy.service ReadWritePaths=-/var/lib/haproxy "${selinux[@]}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	haproxy -c -q -f "${HAPROXY_CONF}" || die "haproxy: the configuration does not load; see above."
	svc_enable haproxy
	if [[ ${changed} == 1 ]]; then
		svc_reload haproxy
	fi
	return
}

mod_verify() {
	local spec
	svc_is_active haproxy || die "haproxy: the service is not running."
	haproxy -c -q -f "${HAPROXY_CONF}" || die "haproxy: the configuration does not load."
	svc_wait_port 127.0.0.1 "$(opt_int stats_port)" 15 || die "haproxy: the statistics page does not answer."
	curl -fsS --max-time 10 -o /dev/null "http://127.0.0.1:$(opt_int stats_port)/" ||
		die "haproxy: the statistics page on 127.0.0.1:$(opt_int stats_port) does not load."
	for spec in $(opt services); do
		_haproxy_parse "${spec}"
		svc_wait_port 127.0.0.1 "${HAPROXY_PORT}" 15 || die "haproxy: ${HAPROXY_NAME} does not listen on port ${HAPROXY_PORT}."
	done
	return
}

mod_remove() {
	svc_disable haproxy
	svc_dropin_remove haproxy.service lss-sandbox
	fw_remove_module
	pkg_remove haproxy
	file_remove "${HAPROXY_CONF}"
	return
}
