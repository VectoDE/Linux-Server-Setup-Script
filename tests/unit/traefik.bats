#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Traefik as the edge proxy: the derived files of lib/traefik.sh (certificates, backend, routes, fail2ban and CrowdSec)
# and the configuration the traefik module writes (static configuration, middlewares, WAF, unit, routes).

setup() {
	load helpers
	lss_test_setup
	use_os debian-13
	shopt -s lastpipe
	export TMPDIR=${BATS_TEST_TMPDIR}
	WEB_TLS_DIR=${BATS_TEST_TMPDIR}/tls
	TRAEFIK_DYNAMIC=${BATS_TEST_TMPDIR}/traefik/dynamic
	TRAEFIK_LOG_DIR=${BATS_TEST_TMPDIR}/log/traefik
	TRAEFIK_FAIL2BAN_JAIL=${BATS_TEST_TMPDIR}/fail2ban/jail.d/lss-traefik.local
	TRAEFIK_FAIL2BAN_FILTER_AUTH=${BATS_TEST_TMPDIR}/fail2ban/filter.d/lss-traefik-auth.conf
	TRAEFIK_FAIL2BAN_FILTER_WAF=${BATS_TEST_TMPDIR}/fail2ban/filter.d/lss-traefik-waf.conf
	TRAEFIK_CROWDSEC_ACQUIS=${BATS_TEST_TMPDIR}/crowdsec/acquis.d/lss-traefik.yaml
	mkdir -p "${WEB_TLS_DIR}" "${TRAEFIK_DYNAMIC}" "$(dirname "${TRAEFIK_FAIL2BAN_JAIL}")" \
		"$(dirname "${TRAEFIK_FAIL2BAN_FILTER_AUTH}")" "$(dirname "${TRAEFIK_CROWDSEC_ACQUIS}")"
}

# The module as lss loads it for a step of its own.
load_module() {
	# shellcheck source=modules/web/traefik.sh
	source "${REPO_ROOT}/modules/web/traefik.sh"
	LSS_MODULE=traefik
	TRAEFIK_DYNAMIC=${BATS_TEST_TMPDIR}/traefik/dynamic
	return
}

# Lets the writers run without root: ownership and the SELinux label are left out, the mode stays; the derived files
# of Traefik look as if they belonged to root and Traefik's group.
as_test_user() {
	eval "_lss_file_write() $(declare -f file_write | tail -n +2)"
	# shellcheck disable=SC2329 # called by the functions under test
	file_write() {
		_lss_file_write "$1" "${OWNER}" "$3"
		return
	}
	# shellcheck disable=SC2329 # called by the functions under test
	chown() {
		printf 'chown %s\n' "$*" >>"${STUB_LOG}"
		return
	}
	# shellcheck disable=SC2329 # called by the functions under test
	stat() {
		if [[ ${*: -1} == "${TRAEFIK_DYNAMIC}"/* ]]; then
			printf '%s %s:%s' "$(command stat -c '%a' "${@: -1}")" root "${TRAEFIK_USER}"
		else
			command stat "$@"
		fi
		return
	}
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
		return
	}
	return
}

use_module() {
	state_set "$1" status installed
	return
}

# --- when Traefik is in front -------------------------------------------------------------------------------------

@test "Traefik is in front once installed or while it installs, and not while it hands the ports back" {
	run ! traefik_active
	LSS_MODULE=traefik
	traefik_active
	unset LSS_MODULE
	use_module traefik
	traefik_active
	LSS_WEB_BACKEND=off
	run ! traefik_active
	traefik_present
}

@test "without Traefik the derived files are left alone" {
	traefik_tls_sync
	traefik_backend_sync nginx
	[ -z "$(ls -A "${TRAEFIK_DYNAMIC}")" ]
	run traefik_route_write app http://127.0.0.1:3000 app.example.com
	[ "${status}" -eq 1 ]
	[[ ${output} == *"traefik: the route app needs Traefik's configuration in ${TRAEFIK_DYNAMIC}."* ]]
}

# --- derived files ------------------------------------------------------------------------------------------------

@test "a derived file is written once per change, readable by Traefik's group only" {
	as_test_user
	use_module traefik
	LSS_MODULE=core
	traefik_backend_sync nginx
	[ "${LSS_FILE_CHANGED}" = 1 ]
	[ "$(command stat -c '%a' "${TRAEFIK_DYNAMIC}/backend.yml")" = 640 ]
	grep -q '^chown root:lss-traefik .*/backend.yml.lss.' "${STUB_LOG}"
	traefik_backend_sync nginx
	[ "${LSS_FILE_CHANGED}" = 0 ]
	[ "$(files_changes_of core)" = 1 ]
	traefik_backend_sync ''
	[ ! -e "${TRAEFIK_DYNAMIC}/backend.yml" ]
	[ "$(files_changes_of core)" = 2 ]
}

@test "the backend gets every other host name on HTTPS and the ACME challenges on port 80, on 127.0.0.1 only" {
	run traefik_backend_conf
	[[ ${output} == *$'    lss-backend:\n      entryPoints: [websecure]\n      rule: PathPrefix(`/`)\n      priority: 1'* ]]
	[[ ${output} == *'rule: PathPrefix(`/.well-known/acme-challenge/`)'* ]]
	[[ ${output} == *'- url: https://127.0.0.1:8443'* ]]
	[[ ${output} == *'- url: http://127.0.0.1:8008'* ]]
	[[ ${output} == *$'  serversTransports:\n    lss-backend:\n      insecureSkipVerify: true'* ]]
}

@test "every complete certificate directory is offered by SNI, the default certificate for every other name" {
	mkdir -p "${WEB_TLS_DIR}/default" "${WEB_TLS_DIR}/shop" "${WEB_TLS_DIR}/half"
	touch "${WEB_TLS_DIR}/half/fullchain.pem"
	for dir in default shop; do
		echo pem >"${WEB_TLS_DIR}/${dir}/fullchain.pem"
		echo pem >"${WEB_TLS_DIR}/${dir}/privkey.pem"
	done
	run traefik_tls_conf
	[[ ${output} == *"    - certFile: ${WEB_TLS_DIR}/shop/fullchain.pem"$'\n'"      keyFile: ${WEB_TLS_DIR}/shop/privkey.pem"* ]]
	[[ ${output} == *"- certFile: ${WEB_TLS_DIR}/default/fullchain.pem"* ]]
	[[ ${output} != *"${WEB_TLS_DIR}/half"* ]]
	[[ ${output} == *$'      defaultCertificate:\n        certFile: '"${WEB_TLS_DIR}/default/fullchain.pem"* ]]
	[[ ${output} == *'minVersion: VersionTLS12'* ]]
	[ "$(grep -c '^        - TLS_ECDHE_' <<<"${output}")" = 6 ]
}

@test "a route matches each of its host names and gets Traefik's ACME resolver only when it is switched on" {
	run traefik_route_conf app http://127.0.0.1:3000 app.example.com www.app.example.com
	[[ ${output} == *'rule: "Host(`app.example.com`) || Host(`www.app.example.com`)"'* ]]
	[[ ${output} == *$'    route-app:\n      entryPoints: [websecure]'* ]]
	[[ ${output} == *'- url: http://127.0.0.1:3000'* ]]
	[[ ${output} != *certResolver* ]]
	export LSS_TRAEFIK_ACME=true
	run traefik_route_conf app http://127.0.0.1:3000 app.example.com
	[[ ${output} == *$'      tls:\n        certResolver: lss'* ]]
}

@test "a route file is written for Traefik and removed again" {
	as_test_user
	use_module traefik
	LSS_MODULE=gitea
	traefik_route_write gitea http://127.0.0.1:3000 git.example.com
	grep -qF 'Host(`git.example.com`)' "${TRAEFIK_DYNAMIC}/route-gitea.yml"
	traefik_route_remove gitea
	[ ! -e "${TRAEFIK_DYNAMIC}/route-gitea.yml" ]
	[ "$(files_changes_of gitea)" = 2 ]
	traefik_route_remove gitea
	[ "$(files_changes_of gitea)" = 2 ]
}

# --- fail2ban and CrowdSec ------------------------------------------------------------------------------------------

@test "fail2ban bans failed logins and WAF blocks from Traefik's JSON access log" {
	as_test_user
	use_module traefik
	use_module fail2ban
	export STUB_ACTIVE_UNITS=fail2ban
	traefik_ids_configure
	grep -qxF '[lss-traefik-auth]' "${TRAEFIK_FAIL2BAN_JAIL}"
	grep -qxF '[lss-traefik-waf]' "${TRAEFIK_FAIL2BAN_JAIL}"
	grep -qxF "logpath = ${TRAEFIK_LOG_DIR}/access.log" "${TRAEFIK_FAIL2BAN_JAIL}"
	[ -e "${TRAEFIK_LOG_DIR}/access.log" ]
	grep -qxF 'fail2ban-client --test' "${STUB_LOG}"
	grep -qxF 'systemctl restart fail2ban' "${STUB_LOG}"
	run ! grep -q cscli "${STUB_LOG}"
	# A line as Traefik writes it (keys sorted): the client is ClientHost, not the backend.
	local line regex
	line='{"ClientAddr":"203.0.113.7:51234","ClientHost":"203.0.113.7","DownstreamStatus":403,"RequestHost":"app.example.com"}'
	regex=$(sed -n 's/^failregex = //p' "${TRAEFIK_FAIL2BAN_FILTER_WAF}")
	regex=${regex//<HOST>/([0-9.]+)}
	[[ ${line} =~ ${regex} ]]
	[ "${BASH_REMATCH[1]}" = 203.0.113.7 ]
	regex=$(sed -n 's/^failregex = //p' "${TRAEFIK_FAIL2BAN_FILTER_AUTH}")
	regex=${regex//<HOST>/([0-9.]+)}
	[[ ! ${line} =~ ${regex} ]]
	: >"${STUB_LOG}"
	traefik_ids_configure
	run ! grep -qE 'fail2ban-client|restart' "${STUB_LOG}"
}

@test "CrowdSec gets the Traefik collection and the access log, and both go when Traefik goes" {
	as_test_user
	use_module traefik
	use_module crowdsec
	export STUB_ACTIVE_UNITS=crowdsec
	traefik_ids_configure
	grep -qxF 'cscli collections install crowdsecurity/traefik' "${STUB_LOG}"
	grep -qxF '  type: traefik' "${TRAEFIK_CROWDSEC_ACQUIS}"
	grep -qxF "  - ${TRAEFIK_LOG_DIR}/access.log" "${TRAEFIK_CROWDSEC_ACQUIS}"
	grep -qxF 'systemctl restart crowdsec' "${STUB_LOG}"
	: >"${STUB_LOG}"
	LSS_WEB_BACKEND=off traefik_ids_configure
	[ ! -e "${TRAEFIK_CROWDSEC_ACQUIS}" ]
	grep -qxF 'systemctl restart crowdsec' "${STUB_LOG}"
}

# --- the module -----------------------------------------------------------------------------------------------------

@test "the settings are checked before anything is installed" {
	load_module
	mod_check
	export LSS_TRAEFIK_WAF=modsec
	run mod_check
	[[ ${output} == *'LSS_TRAEFIK_WAF must be coraza, modsecurity, both or off.'* ]]
	export LSS_TRAEFIK_WAF=both LSS_TRAEFIK_PARANOIA=5
	run mod_check
	[[ ${output} == *'LSS_TRAEFIK_PARANOIA must be 1, 2, 3 or 4.'* ]]
	export LSS_TRAEFIK_PARANOIA=2 LSS_TRAEFIK_DASHBOARD_PORT=8443
	run mod_check
	[[ ${output} == *'LSS_TRAEFIK_DASHBOARD_PORT must differ from 8090, 8008 and 8443.'* ]]
	export LSS_TRAEFIK_DASHBOARD_PORT=8099 LSS_TRAEFIK_ROUTES='app:app.example.com:3000'
	run mod_check
	[[ ${output} == *'the route app needs HOST:PORT at the end, like 127.0.0.1:3000.'* ]]
	export LSS_TRAEFIK_ROUTES='app:app.example.com,www.app.example.com:127.0.0.1:3000 api:api.example.com:10.0.0.5:8080'
	mod_check
	export LSS_TRAEFIK_ADMIN_HOST=admin
	run mod_check
	[[ ${output} == *"LSS_TRAEFIK_ADMIN_HOST 'admin' is not a host name like admin.example.com."* ]]
	export LSS_TRAEFIK_ADMIN_HOST=admin.example.com LSS_TRAEFIK_ACME_SERVER=http://acme.example.com/dir
	run mod_check
	[[ ${output} == *'LSS_TRAEFIK_ACME_SERVER must be an https:// URL.'* ]]
}

@test "Traefik and the Coraza plugin have checksums for both architectures" {
	load_module
	use_os debian-13 x86_64
	[[ $(fetch_entry "traefik-${TRAEFIK_VERSION}") == *_linux_amd64.tar.gz ]]
	use_os debian-13 aarch64
	[[ $(fetch_entry "traefik-${TRAEFIK_VERSION}") == *_linux_arm64.tar.gz ]]
	[ "$(_traefik_arch)" = arm64 ]
	[[ $(fetch_entry "coraza-http-wasm-${TRAEFIK_CORAZA_VERSION}") == *"/v${TRAEFIK_CORAZA_VERSION}/"*.zip ]]
}

@test "a route of the setting is split into its name, host names and upstream" {
	load_module
	_traefik_route_parse 'app:app.example.com,www.app.example.com:127.0.0.1:3000'
	[ "${TRAEFIK_ROUTE_NAME}" = app ]
	[ "${TRAEFIK_ROUTE_DOMAINS}" = app.example.com,www.app.example.com ]
	[ "${TRAEFIK_ROUTE_UPSTREAM}" = 127.0.0.1:3000 ]
	run _traefik_route_parse 'App:app.example.com:127.0.0.1:3000'
	[ "${status}" -eq 1 ]
	run _traefik_route_parse 'app:localhost:127.0.0.1:3000'
	[ "${status}" -eq 1 ]
}

@test "the static configuration: HTTP/3 on 443, the middlewares, the dashboard on 127.0.0.1 and a JSON access log" {
	load_module
	OS_ARCH=aarch64
	run _traefik_static
	[[ ${output} == *$'  web:\n    address: ":80"'* ]]
	[[ ${output} == *$'    http3:\n      advertisedPort: 443'* ]]
	[[ ${output} == *$'        - lss-headers@file\n        - lss-waf@file\n'* ]]
	[[ ${output} == *'address: "127.0.0.1:8099"'* ]]
	[[ ${output} == *$'ping:\n  entryPoint: traefik'* ]]
	[[ ${output} == *"directory: ${TRAEFIK_DYNAMIC}"* ]]
	[[ ${output} == *$'  format: json\n  fields:\n    headers:\n      defaultMode: drop'* ]]
	[[ ${output} == *'moduleName: github.com/jcchavezs/coraza-http-wasm-traefik'* ]]
	[[ ${output} == *'checkNewVersion: false'* ]]
	[[ ${output} != *docker* ]]
	[[ ${output} != *certificatesResolvers* ]]
}

@test "without Coraza there is no plugin; Docker and ACME appear only when switched on" {
	load_module
	export LSS_TRAEFIK_WAF=modsecurity LSS_TRAEFIK_DOCKER=true LSS_TRAEFIK_ACME=true LSS_TRAEFIK_ACME_EMAIL=ops@example.com
	run _traefik_static
	[[ ${output} != *lss-waf* ]]
	[[ ${output} != *localPlugins* ]]
	# The socket proxy, never the engine's own socket.
	[[ ${output} == *"endpoint: unix:///run/lss-traefik-docker/docker.sock"* ]]
	[[ ${output} == *'exposedByDefault: false'* ]]
	[[ ${output} != *docker.sock\"* ]]
	[[ ${output} != */var/run/docker.sock* ]]
	[[ ${output} == *$'      tlsChallenge: {}\n      email: ops@example.com'* ]]
	[[ ${output} == *'caServer: https://acme-v02.api.letsencrypt.org/directory'* ]]
}

@test "the middlewares: the security headers, the redirect to HTTPS and Coraza with the Core Rule Set" {
	load_module
	OS_ARCH=aarch64
	export LSS_TRAEFIK_PARANOIA=2
	run _traefik_dynamic
	[[ ${output} == *'          Strict-Transport-Security: "max-age=63072000"'* ]]
	[[ ${output} == *$'          Server: ""\n          X-Powered-By: ""'* ]]
	[[ ${output} == *$'      redirectScheme:\n        scheme: https\n        permanent: true'* ]]
	[[ ${output} == *'- Include @owasp_crs/*.conf'* ]]
	[[ ${output} == *'setvar:tx.blocking_paranoia_level=2"'* ]]
	[[ ${output} == *'- SecRuleEngine On'* ]]
	[[ ${output} == *'rule: Host(`lss-probe.invalid`)'* ]]
	export LSS_TRAEFIK_WAF=off
	run _traefik_dynamic
	[[ ${output} != *coraza* ]]
}

@test "Coraza stays out on amd64 (wazero 1.8.0 in Traefik); ModSecurity takes its place" {
	load_module
	OS_ARCH=x86_64
	run _traefik_static
	[[ ${output} != *lss-waf* ]]
	[[ ${output} != *localPlugins* ]]
	run _traefik_dynamic
	[[ ${output} != *coraza* ]]
	traefik_waf_fallback
	run ! _traefik_modsecurity
	state_set modsecurity status installed
	_traefik_modsecurity
	export LSS_TRAEFIK_WAF=both
	traefik_waf_fallback
	export LSS_TRAEFIK_WAF=modsecurity
	run ! traefik_waf_fallback
	export LSS_TRAEFIK_WAF=off
	run ! traefik_waf_fallback
	run ! _traefik_modsecurity
	export LSS_TRAEFIK_WAF=coraza
	TRAEFIK_CORAZA_AMD64=true
	run ! traefik_waf_fallback
	_traefik_coraza
	TRAEFIK_CORAZA_AMD64=false OS_ARCH=aarch64
	_traefik_coraza
	run ! traefik_waf_fallback
}

@test "routes pass through the web server for ModSecurity only where Coraza cannot run and nginx or Apache serves" {
	load_module
	OS_ARCH=x86_64
	run ! traefik_waf_backend
	state_set nginx status installed
	traefik_waf_backend
	TRAEFIK_BACKEND_GONE=1
	run ! traefik_waf_backend
	unset TRAEFIK_BACKEND_GONE
	LSS_WEB_BACKEND=off
	run ! traefik_waf_backend
	unset LSS_WEB_BACKEND
	state_forget nginx
	state_set caddy status installed
	run ! traefik_waf_backend
	state_forget caddy
	state_set apache status installed
	traefik_waf_backend
	OS_ARCH=aarch64
	run ! traefik_waf_backend
	OS_ARCH=x86_64
	export LSS_TRAEFIK_WAF=modsecurity
	run ! traefik_waf_backend
}

@test "a route through the web server points Traefik at the backend with its transport" {
	load_module
	run traefik_route_conf app "https://127.0.0.1:${WEB_BACKEND_HTTPS_PORT}" app.example.com
	[[ ${output} == *$'      loadBalancer:\n        serversTransport: lss-backend\n        servers:\n          - url: https://127.0.0.1:8443'* ]]
	run traefik_route_conf app http://127.0.0.1:3000 app.example.com
	[[ ${output} != *serversTransport* ]]
	[[ ${output} == *'- url: http://127.0.0.1:3000'* ]]
}

@test "in place of Coraza lss installs modsecurity once, says why, and removes it with Traefik" {
	load_module
	OS_ARCH=x86_64
	# shellcheck disable=SC2329 # called by the functions under test
	_traefik_wait() { return; }
	# shellcheck disable=SC2329 # called by the functions under test
	module_run() {
		printf 'module_run %s\n' "$*" >>"${STUB_LOG}"
		return
	}
	# shellcheck disable=SC2329 # called by the functions under test
	module_apply() {
		printf 'module_apply %s LSS_WEB_BACKEND=%s\n' "$*" "${LSS_WEB_BACKEND:-}" >>"${STUB_LOG}"
		state_set "$1" status installed
		return
	}
	# shellcheck disable=SC2329 # called by the functions under test
	module_remove() {
		printf 'module_remove %s\n' "$*" >>"${STUB_LOG}"
		state_forget "$1"
		return
	}
	run _traefik_waf_fallback
	[[ ${output} == *'traefik: Coraza waits for a Traefik release with wazero 1.9 on amd64; requests reach the applications unfiltered until nginx or Apache is installed'* ]]
	state_set caddy status installed
	run _traefik_waf_fallback
	[[ ${output} == *'Caddy has no ModSecurity connector'* ]]
	state_forget caddy
	state_set nginx status installed
	_traefik_waf_fallback
	grep -qxF 'module_run modsecurity check' "${STUB_LOG}"
	grep -qxF 'module_apply modsecurity LSS_WEB_BACKEND=on' "${STUB_LOG}"
	[ "$(state_get traefik waf_dependency)" = modsecurity ]
	: >"${STUB_LOG}"
	run _traefik_waf_fallback
	[[ ${output} == *'ModSecurity in nginx filters every request, and the routes of applications pass through nginx for it.'* ]]
	[[ ! -s ${STUB_LOG} ]]
	_traefik_waf_fallback_remove
	grep -qxF 'module_remove modsecurity' "${STUB_LOG}"
	# A modsecurity of its own, installed by the user, stays.
	state_set modsecurity status installed
	state_set traefik waf_dependency ''
	: >"${STUB_LOG}"
	_traefik_waf_fallback_remove
	[[ ! -s ${STUB_LOG} ]]
	# With Coraza at work nothing happens.
	OS_ARCH=aarch64
	run _traefik_waf_fallback
	[ -z "${output}" ]
}

@test "the unit runs as its own user with CAP_NET_BIND_SERVICE as its only capability" {
	load_module
	run _traefik_unit
	[[ ${output} == *$'User=lss-traefik\nGroup=lss-traefik'* ]]
	[[ ${output} == *$'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE'* ]]
	[[ ${output} == *'ExecStart=/usr/local/bin/traefik --configFile=/etc/traefik/traefik.yml'* ]]
	[[ ${output} != *LEGO_CA_CERTIFICATES* ]]
	export LSS_TRAEFIK_ACME_CA_BUNDLE=/etc/lss-pebble/ca.pem
	run _traefik_unit
	[[ ${output} == *'Environment=LEGO_CA_CERTIFICATES=/etc/traefik/acme-ca.pem'* ]]
}

@test "the admin host asks for the password and reaches a public admin port over HTTPS" {
	load_module
	use_module nginx
	export LSS_TRAEFIK_ADMIN_HOST=admin.example.com
	run _traefik_admin_conf
	[[ ${output} == *'usersFile: /etc/traefik/admin.htpasswd'* ]]
	[[ ${output} == *'rule: Host(`admin.example.com`)'* ]]
	[[ ${output} == *'- url: http://127.0.0.1:8090'* ]]
	[[ ${output} != *serversTransport* ]]
	export LSS_NGINX_ADMIN_PUBLIC=true
	run _traefik_admin_conf
	[[ ${output} == *$'        serversTransport: lss-backend\n        servers:\n          - url: https://127.0.0.1:8090'* ]]
}

@test "the certificate of the admin host leaves with it, certbot's lineage included" {
	load_module
	WEB_CERT_LIVE=${BATS_TEST_TMPDIR}/letsencrypt/live
	mkdir -p "${WEB_TLS_DIR}/lss-admin" "${WEB_CERT_LIVE}/lss-admin"
	_traefik_admin_cert_remove
	[[ ! -e ${WEB_TLS_DIR}/lss-admin ]]
	grep -qxF 'certbot delete --non-interactive --cert-name lss-admin' "${STUB_LOG}"
	: >"${STUB_LOG}"
	rmdir "${WEB_CERT_LIVE}/lss-admin"
	_traefik_admin_cert_remove
	[[ ! -s ${STUB_LOG} ]]
}

@test "the routes of the setting are recorded, and a route that left the setting is removed" {
	load_module
	# shellcheck disable=SC2329 # called by the functions under test
	web_proxy_route() {
		printf 'route %s\n' "$*" >>"${STUB_LOG}"
		return
	}
	# shellcheck disable=SC2329 # called by the functions under test
	web_route_names() {
		printf 'app\nold\n'
		return
	}
	# shellcheck disable=SC2329 # called by the functions under test
	web_proxy_route_remove() {
		printf 'remove %s\n' "$*" >>"${STUB_LOG}"
		return
	}
	export LSS_TRAEFIK_ROUTES='app:app.example.com:127.0.0.1:3000'
	_traefik_routes
	grep -qxF 'route app app.example.com 127.0.0.1:3000' "${STUB_LOG}"
	grep -qxF 'remove old' "${STUB_LOG}"
	run ! grep -qxF 'remove app' "${STUB_LOG}"
}

@test "the dashboard check accepts the loopback interface only" {
	load_module
	# shellcheck disable=SC2329 # called by the functions under test
	ss() {
		printf '%s\n' "${STUB_SS[@]}"
		return
	}
	STUB_SS=('LISTEN 0 4096 127.0.0.1:8099 0.0.0.0:*')
	_traefik_listen_local 8099
	STUB_SS=('LISTEN 0 4096 127.0.0.1:8099 0.0.0.0:*' 'LISTEN 0 4096 [::]:8099 [::]:*')
	run ! _traefik_listen_local 8099
	STUB_SS=()
	run ! _traefik_listen_local 8099
	[ "$(_traefik_status $'HTTP/2 403\r\n\r\nbody\n403')" = 403 ]
}
