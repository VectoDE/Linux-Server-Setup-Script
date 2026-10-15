# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="traefik"
MOD_GROUP="web"
MOD_DESCRIPTION="Traefik 3.7 edge proxy in front of the web server and the applications: HTTPS with HTTP/3, security headers, OWASP Coraza WAF, JSON access log, dashboard on localhost"
MOD_REQUIRES="system"
MOD_OPTIONS="waf|coraza|Web application firewall: coraza (OWASP Coraza with the Core Rule Set in Traefik, for every route), modsecurity (the modsecurity module in the backend web server, for what goes through it), both, or off
paranoia|1|Paranoia level of the Core Rule Set in Coraza, 1 to 4: higher levels catch more attacks and also block more legitimate requests
routes||Routes Traefik serves, separated by spaces: NAME:DOMAIN[,DOMAIN...]:HOST:PORT, for example app:app.example.com:127.0.0.1:3000 (Traefik forwards to http://HOST:PORT)
admin_host||Host name under which Traefik publishes the admin interfaces of the web server (phpMyAdmin, Adminer, pgAdmin) over HTTPS with a password (user admin, lss secrets show web-admin-password); empty keeps them on the admin port only
acme|false|Traefik requests certificates for its routes itself (TLS-ALPN challenge on port 443; the names must point to this server); otherwise the tls module or the self-signed default certificate
acme_email||Address for Traefik's ACME account (optional)
acme_server|https://acme-v02.api.letsencrypt.org/directory|ACME directory URL of Traefik's ACME client
acme_ca_bundle||CA certificate to trust for a private ACME server (Pebble, step-ca); empty for Let's Encrypt
docker|false|Docker provider: containers with the label traefik.enable=true are routed. Traefik reads the container engine through a socket proxy that allows only listing and inspecting containers, never the socket itself
dashboard_port|8099|Port of the dashboard and the read-only API on 127.0.0.1 (never public)"
MOD_SECRETS="web-admin-password"
MOD_PORTS="80/tcp 443/tcp 443/udp"

# Traefik from its GitHub release (data/checksums.txt, amd64 and arm64), the Coraza plugin from its GitHub release:
# a WebAssembly build of Coraza with the OWASP Core Rule Set 4.0 inside, loaded as a local plugin (Traefik never
# downloads it from the plugin catalog). A new version is a new entry in data/checksums.txt and a new version here.
TRAEFIK_VERSION=3.7.15
TRAEFIK_CORAZA_VERSION=0.3.0
TRAEFIK_CORAZA_MODULE=github.com/jcchavezs/coraza-http-wasm-traefik
TRAEFIK_BIN=/usr/local/bin/traefik
TRAEFIK_CACHE=/var/cache/lss-traefik
# Traefik looks for local plugins below plugins-local/src of its working directory, which stays read-only for it.
TRAEFIK_HOME=/usr/local/lib/lss-traefik
TRAEFIK_PLUGIN_DIR=${TRAEFIK_HOME}/plugins-local/src/${TRAEFIK_CORAZA_MODULE}
TRAEFIK_STATE=/var/lib/lss-traefik
# shellcheck disable=SC2153 # TRAEFIK_DIR is set in lib/traefik.sh
TRAEFIK_CONF=${TRAEFIK_DIR}/traefik.yml
TRAEFIK_HTPASSWD=${TRAEFIK_DIR}/admin.htpasswd
TRAEFIK_ACME_CA=${TRAEFIK_DIR}/acme-ca.pem
TRAEFIK_LOGROTATE=/etc/logrotate.d/lss-traefik
# The probe route: Traefik's own ping behind the HTTPS entry point with its middlewares, for verify.
TRAEFIK_PROBE_HOST=lss-probe.invalid
# Socket proxy for the Docker provider (opt-in): Traefik gets a socket that answers only a few read-only calls.
TRAEFIK_PROXY_NAME=lss-traefik-docker
# wollomatic/socket-proxy 1.13.1, the multi-architecture index (amd64 and arm64) on GHCR, checked 2026-10-15.
TRAEFIK_PROXY_IMAGE=ghcr.io/wollomatic/socket-proxy@sha256:e78e68ba3ea4a6bf8ee47865ac1d1f98d525c3660df948554e766283c40d3f4b
TRAEFIK_PROXY_DIR=/run/lss-traefik-docker
TRAEFIK_PROXY_SOCKET=${TRAEFIK_PROXY_DIR}/docker.sock
TRAEFIK_PROXY_TMPFILES=/etc/tmpfiles.d/lss-traefik-docker.conf
# Listing, inspecting and the event stream of containers, the version, the engine information and the ping (what
# Traefik's Docker provider calls); nothing that changes anything.
TRAEFIK_PROXY_ALLOW='^/(v[0-9.]+/)?(_ping|version|info|events|containers/json|containers/[A-Za-z0-9_.-]+/json)$'

mod_check() {
	local port waf paranoia route bundle
	waf=$(opt waf)
	[[ ${waf} =~ ^(coraza|modsecurity|both|off)$ ]] || die "LSS_TRAEFIK_WAF must be coraza, modsecurity, both or off."
	paranoia=$(opt_int paranoia)
	((paranoia >= 1 && paranoia <= 4)) || die "LSS_TRAEFIK_PARANOIA must be 1, 2, 3 or 4."
	port=$(opt_int dashboard_port)
	((port >= 1024 && port <= 65535)) || die "LSS_TRAEFIK_DASHBOARD_PORT must be a port number from 1024 to 65535."
	case ${port} in
	"${WEB_ADMIN_PORT}" | "${WEB_BACKEND_HTTP_PORT}" | "${WEB_BACKEND_HTTPS_PORT}")
		die "LSS_TRAEFIK_DASHBOARD_PORT must differ from ${WEB_ADMIN_PORT}, ${WEB_BACKEND_HTTP_PORT} and ${WEB_BACKEND_HTTPS_PORT}."
		;;
	*) ;;
	esac
	for route in $(opt routes); do
		_traefik_route_parse "${route}"
	done
	if [[ -n $(opt admin_host) ]]; then
		[[ $(opt admin_host) =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]] ||
			die "LSS_TRAEFIK_ADMIN_HOST '$(opt admin_host)' is not a host name like admin.example.com."
	fi
	opt_bool acme || true
	opt_bool docker || true
	[[ -z $(opt acme_email) || $(opt acme_email) =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] ||
		die "LSS_TRAEFIK_ACME_EMAIL '$(opt acme_email)' is not an e-mail address."
	[[ $(opt acme_server) =~ ^https://[^[:space:]]+$ ]] || die "LSS_TRAEFIK_ACME_SERVER must be an https:// URL."
	bundle=$(opt acme_ca_bundle)
	[[ -z ${bundle} || -s ${bundle} ]] || die "LSS_TRAEFIK_ACME_CA_BUNDLE: ${bundle} does not exist."
	fetch_entry "traefik-${TRAEFIK_VERSION}" >/dev/null ||
		die "traefik: data/checksums.txt has no checksum for Traefik ${TRAEFIK_VERSION} on ${OS_ARCH:-$(uname -m)}."
	fetch_entry "coraza-http-wasm-${TRAEFIK_CORAZA_VERSION}" >/dev/null ||
		die "traefik: data/checksums.txt has no checksum for the Coraza plugin ${TRAEFIK_CORAZA_VERSION}."
	return
}

# _traefik_route_parse SPEC: NAME:DOMAIN[,DOMAIN...]:HOST:PORT; sets TRAEFIK_ROUTE_NAME, TRAEFIK_ROUTE_DOMAINS and
# TRAEFIK_ROUTE_UPSTREAM.
_traefik_route_parse() {
	local spec=$1
	IFS=':' read -r TRAEFIK_ROUTE_NAME TRAEFIK_ROUTE_DOMAINS TRAEFIK_ROUTE_UPSTREAM <<<"${spec}"
	[[ ${TRAEFIK_ROUTE_NAME} =~ ^[a-z0-9][a-z0-9-]*$ ]] ||
		die "LSS_TRAEFIK_ROUTES: '${spec}' does not start with a route name (a-z, 0-9, -)."
	[[ ${TRAEFIK_ROUTE_UPSTREAM} =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] ||
		die "LSS_TRAEFIK_ROUTES: the route ${TRAEFIK_ROUTE_NAME} needs HOST:PORT at the end, like 127.0.0.1:3000."
	# The same checks as for every application route.
	_web_route_parse "${TRAEFIK_ROUTE_NAME}" "${TRAEFIK_ROUTE_DOMAINS}" "${TRAEFIK_ROUTE_UPSTREAM}"
	return
}

_traefik_coraza() {
	[[ $(opt waf) == coraza || $(opt waf) == both ]]
	return
}

_traefik_modsecurity() {
	[[ $(opt waf) == modsecurity || $(opt waf) == both ]]
	return
}

_traefik_arch() {
	case ${OS_ARCH:-$(uname -m)} in
	aarch64 | arm64) printf 'arm64' ;;
	*) printf 'amd64' ;;
	esac
	return
}

# The release archive, checked against data/checksums.txt; the binary is replaced when its version differs.
_traefik_binary() {
	local archive tmp current='' file
	archive="${TRAEFIK_CACHE}/traefik-${TRAEFIK_VERSION}-$(_traefik_arch).tar.gz"
	fetch_verified "traefik-${TRAEFIK_VERSION}" "${archive}"
	for file in "${TRAEFIK_CACHE}"/traefik-*; do
		[[ ! -f ${file} || ${file} == "${archive}" ]] || rm -f -- "${file}"
	done
	if [[ -x ${TRAEFIK_BIN} ]]; then
		current=$("${TRAEFIK_BIN}" version 2>/dev/null | awk '$1 == "Version:" { print $2 }') || current=''
	fi
	[[ ${current} != "${TRAEFIK_VERSION}" ]] || return 0
	tmp=$(mktemp -d)
	tar -xzf "${archive}" -C "${tmp}" traefik || die "traefik: the release archive has no traefik binary."
	install -m 0755 -o root -g root "${tmp}/traefik" "${TRAEFIK_BIN}"
	rm -rf -- "${tmp}"
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -F "${TRAEFIK_BIN}" 2>/dev/null || true
	fi
	files_note_change "installed Traefik ${TRAEFIK_VERSION}"
	return
}

# The Coraza plugin: its manifest and the WebAssembly module from the checked release archive.
_traefik_plugin() {
	local archive file
	archive="${TRAEFIK_CACHE}/coraza-http-wasm-${TRAEFIK_CORAZA_VERSION}.zip"
	fetch_verified "coraza-http-wasm-${TRAEFIK_CORAZA_VERSION}" "${archive}"
	for file in .traefik.yml coraza-http-wasm.wasm LICENSE; do
		unzip -p "${archive}" "${file}" | file_write 0644 root:root "${TRAEFIK_PLUGIN_DIR}/${file}"
	done
	return
}

_traefik_plugin_remove() {
	local file
	for file in .traefik.yml coraza-http-wasm.wasm LICENSE; do
		file_remove "${TRAEFIK_PLUGIN_DIR}/${file}"
	done
	file_remove "${TRAEFIK_HOME}/plugins-local"
	return
}

mod_install() {
	pkg_install curl tar unzip openssl
	if [[ -n $(opt admin_host) ]]; then
		# htpasswd hashes the admin password with bcrypt, which Traefik's basic auth reads.
		pkg_install_family apache2-utils httpd-tools
	fi
	_traefik_binary
	if _traefik_coraza; then
		_traefik_plugin
	fi
	return
}

_traefik_user() {
	if ! getent passwd "${TRAEFIK_USER}" >/dev/null; then
		useradd --system --user-group --home-dir "${TRAEFIK_STATE}" --no-create-home --shell /usr/sbin/nologin \
			--comment "Traefik (lss)" "${TRAEFIK_USER}"
		files_note_change "created user ${TRAEFIK_USER}"
	fi
	# The TLS keys of WEB_TLS_DIR are readable by the web group.
	web_group_ensure "${TRAEFIK_USER}"
	return
}

# Request checks of every entry point: headers whose names alias another one (X_Forwarded_For for X-Forwarded-For,
# which PHP and CGI read as the same variable) are dropped, so a client cannot pass on a header Traefik manages;
# encoded backslashes and null characters in the path are refused (400).
_traefik_entry_http() {
	cat <<'EOF'
    http:
      aliasHeadersStrategy: delete
      encodedCharacters:
        allowEncodedBackslash: false
        allowEncodedNullCharacter: false
EOF
	return
}

# The static configuration: entry points, providers, logs, the ACME client and the local Coraza plugin.
_traefik_static() {
	local email
	cat <<EOF
# Managed by lss (module traefik). Change LSS_TRAEFIK_* in /etc/lss/lss.conf and run lss configure traefik.
global:
  checkNewVersion: false
  sendAnonymousUsage: false
entryPoints:
  web:
    address: ":80"
$(_traefik_entry_http)
  websecure:
    address: ":443"
    http3:
      advertisedPort: 443
$(_traefik_entry_http)
      tls: {}
      middlewares:
        - lss-headers@file
EOF
	if _traefik_coraza; then
		printf '        - lss-waf@file\n'
	fi
	# api.insecure serves the dashboard and the read-only API on the entry point "traefik", which listens on
	# 127.0.0.1 only; nothing of it is reachable from outside.
	cat <<EOF
  traefik:
    address: "127.0.0.1:$(opt_int dashboard_port)"
$(_traefik_entry_http)
api:
  dashboard: true
  insecure: true
ping:
  entryPoint: traefik
providers:
  file:
    directory: ${TRAEFIK_DYNAMIC}
    watch: true
EOF
	if opt_bool docker; then
		cat <<EOF
  docker:
    endpoint: unix://${TRAEFIK_PROXY_SOCKET}
    exposedByDefault: false
    watch: true
EOF
	fi
	cat <<EOF
accessLog:
  filePath: ${TRAEFIK_LOG_DIR}/access.log
  format: json
  fields:
    headers:
      defaultMode: drop
log:
  level: WARN
  noColor: true
EOF
	if opt_bool acme; then
		email=$(opt acme_email)
		cat <<EOF
certificatesResolvers:
  lss:
    acme:
      caServer: $(opt acme_server)
      storage: ${TRAEFIK_STATE}/acme.json
      keyType: EC256
      tlsChallenge: {}
EOF
		[[ -z ${email} ]] || printf '      email: %s\n' "${email}"
	fi
	if _traefik_coraza; then
		printf 'experimental:\n  localPlugins:\n    coraza:\n      moduleName: %s\n' "${TRAEFIK_CORAZA_MODULE}"
	fi
	return
}

# The Coraza directives: the recommended engine settings, the Core Rule Set with the chosen paranoia level and the
# methods of the modsecurity module. Bodies beyond the inspection limit pass partly inspected instead of breaking
# uploads; response bodies are not inspected.
_traefik_waf() {
	cat <<EOF
    lss-waf:
      plugin:
        coraza:
          directives:
            - Include @coraza.conf-recommended
            - SecRuleEngine On
            - SecResponseBodyAccess Off
            - SecRequestBodyLimitAction ProcessPartial
            - Include @crs-setup.conf.example
            - 'SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=$(opt_int paranoia)"'
            - 'SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:''tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE''"'
            - Include @owasp_crs/*.conf
EOF
	return
}

# Middlewares of the HTTPS entry point (headers, WAF), the redirect of port 80 and the probe route.
_traefik_dynamic() {
	cat <<EOF
# Managed by lss (module traefik).
http:
  middlewares:
    lss-headers:
      headers:
        customResponseHeaders:
$(web_headers traefik)
          Server: ""
          X-Powered-By: ""
    lss-redirect:
      redirectScheme:
        scheme: https
        permanent: true
EOF
	if _traefik_coraza; then
		_traefik_waf
	fi
	cat <<EOF
  routers:
    lss-redirect:
      entryPoints: [web]
      rule: PathPrefix(\`/\`)
      priority: 1
      middlewares: [lss-redirect]
      service: noop@internal
    lss-probe:
      entryPoints: [websecure]
      rule: Host(\`${TRAEFIK_PROBE_HOST}\`)
      service: ping@internal
EOF
	return
}

# The admin port of the web server under LSS_TRAEFIK_ADMIN_HOST, behind a password. A public admin port speaks HTTPS
# with the default certificate (and asks for the same password).
_traefik_admin_url() {
	if config_bool "$(config_key "$(web_server)" admin_public)"; then
		printf 'https://127.0.0.1:%s' "${WEB_ADMIN_PORT}"
	else
		printf 'http://127.0.0.1:%s' "${WEB_ADMIN_PORT}"
	fi
	return
}

_traefik_admin_conf() {
	local url
	url=$(_traefik_admin_url)
	cat <<EOF
# Managed by lss (module traefik). The admin interfaces of the web server under $(opt admin_host).
http:
  middlewares:
    lss-admin-auth:
      basicAuth:
        usersFile: ${TRAEFIK_HTPASSWD}
        realm: lss admin
  routers:
    lss-admin:
      entryPoints: [websecure]
      rule: Host(\`$(opt admin_host)\`)
      middlewares: [lss-admin-auth]
      service: lss-admin
EOF
	if opt_bool acme; then
		printf '      tls:\n        certResolver: lss\n'
	fi
	printf '  services:\n    lss-admin:\n      loadBalancer:\n'
	[[ ${url} != https://* ]] || printf '        serversTransport: lss-backend\n'
	printf '        servers:\n          - url: %s\n' "${url}"
	return
}

# The admin password as a bcrypt hash; written again only when it no longer matches the secret.
_traefik_htpasswd() {
	local password
	secret_load web-admin-password password 32
	if [[ -s ${TRAEFIK_HTPASSWD} ]] && htpasswd -vi "${TRAEFIK_HTPASSWD}" admin <<<"${password}" >/dev/null 2>&1; then
		return 0
	fi
	htpasswd -niB -C 12 admin <<<"${password}" | grep -v '^$' | file_write 0640 "root:${TRAEFIK_USER}" "${TRAEFIK_HTPASSWD}"
	return
}

_traefik_admin() {
	local host
	host=$(opt admin_host)
	if [[ -n ${host} && -z $(web_server) ]]; then
		log_warn "traefik: LSS_TRAEFIK_ADMIN_HOST waits for a web server with the admin port (nginx, apache or caddy); run lss configure traefik after its install."
		host=''
	fi
	if [[ -z ${host} ]]; then
		file_remove "${TRAEFIK_DYNAMIC}/admin.yml"
		file_remove "${TRAEFIK_HTPASSWD}"
		return 0
	fi
	_traefik_htpasswd
	web_cert_placeholder lss-admin
	_traefik_admin_conf | file_write 0640 "root:${TRAEFIK_USER}" "${TRAEFIK_DYNAMIC}/admin.yml"
	if state_installed tls; then
		web_cert_issue lss-admin "${host}"
	fi
	return
}

# The socket proxy for the Docker provider: a container that holds the engine's socket and offers Traefik a socket of
# its own with TRAEFIK_PROXY_ALLOW only. It runs as root in the group of Traefik (the socket it creates belongs to
# that group), without capabilities and without a network.
_traefik_docker() {
	local engine gid
	engine=$(ctr_engine) || die "traefik: LSS_TRAEFIK_DOCKER=true needs a container engine (lss install docker or podman)."
	if [[ ${engine} == podman ]]; then
		svc_enable podman.socket
	fi
	gid=$(getent group "${TRAEFIK_USER}" | cut -d ':' -f 3)
	printf '# Managed by lss (module traefik).\nd %s 0750 root %s -\n' "${TRAEFIK_PROXY_DIR}" "${TRAEFIK_USER}" |
		file_write 0644 root:root "${TRAEFIK_PROXY_TMPFILES}"
	systemd-tmpfiles --create "${TRAEFIK_PROXY_TMPFILES}" >/dev/null 2>&1 || install -d -m 0750 -o root -g "${TRAEFIK_USER}" "${TRAEFIK_PROXY_DIR}"
	ctr_run "${TRAEFIK_PROXY_NAME}" "${TRAEFIK_PROXY_IMAGE}" --socket --user "0:${gid}" --network none \
		--volume "${TRAEFIK_PROXY_DIR}:${TRAEFIK_PROXY_DIR}" --memory 64m --pids 64 -- \
		"-proxysocketendpoint=${TRAEFIK_PROXY_SOCKET}" -proxysocketendpointfilemode=0660 \
		"-allowGET=${TRAEFIK_PROXY_ALLOW}" '-allowHEAD=^/(v[0-9.]+/)?_ping$' -watchdoginterval=60 -stoponwatchdog \
		-shutdowngracetime=5
	return
}

_traefik_docker_remove() {
	if [[ -f /etc/systemd/system/lss-ctr-${TRAEFIK_PROXY_NAME}.service ]] || ctr_engine >/dev/null 2>&1; then
		ctr_remove "${TRAEFIK_PROXY_NAME}"
	fi
	file_remove "${TRAEFIK_PROXY_TMPFILES}"
	if [[ -d ${TRAEFIK_PROXY_DIR} ]]; then
		rm -rf -- "${TRAEFIK_PROXY_DIR}"
		files_note_change "removed ${TRAEFIK_PROXY_DIR}"
	fi
	return
}

_traefik_unit() {
	cat <<EOF
# Managed by lss (module traefik).
[Unit]
Description=Traefik edge proxy (lss)
Documentation=https://doc.traefik.io/traefik/
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
User=${TRAEFIK_USER}
Group=${TRAEFIK_USER}
WorkingDirectory=${TRAEFIK_HOME}
ExecStart=${TRAEFIK_BIN} --configFile=${TRAEFIK_CONF}
EOF
	if [[ -n $(opt acme_ca_bundle) ]]; then
		printf 'Environment=LEGO_CA_CERTIFICATES=%s\n' "${TRAEFIK_ACME_CA}"
	fi
	cat <<EOF
# Ports 80 and 443 without root: the one capability it needs, nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65536
UMask=0077
Restart=on-failure
RestartSec=5
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF
	return
}

_traefik_logrotate() {
	cat <<EOF
# Managed by lss (module traefik). Traefik opens its access log again on USR1.
${TRAEFIK_LOG_DIR}/*.log {
	daily
	rotate 14
	missingok
	notifempty
	compress
	delaycompress
	create 0600 ${TRAEFIK_USER} ${TRAEFIK_USER}
	postrotate
		systemctl kill -s USR1 ${TRAEFIK_UNIT}.service >/dev/null 2>&1 || true
	endscript
}
EOF
	return
}

# The routes of LSS_TRAEFIK_ROUTES through web_proxy_route; routes that left the setting since the last run go.
_traefik_routes() {
	local spec name
	local -A wanted=()
	for spec in $(opt routes); do
		_traefik_route_parse "${spec}"
		web_proxy_route "${TRAEFIK_ROUTE_NAME}" "${TRAEFIK_ROUTE_DOMAINS}" "${TRAEFIK_ROUTE_UPSTREAM}"
		wanted[${TRAEFIK_ROUTE_NAME}]=1
	done
	for name in $(web_route_names traefik); do
		[[ -n ${wanted[${name}]+x} ]] || web_proxy_route_remove "${name}"
	done
	return
}

mod_configure() {
	local server changed=0 bundle
	server=$(web_server)
	_traefik_user
	web_default_cert
	install -d -m 0750 -o root -g "${TRAEFIK_USER}" "${TRAEFIK_DIR}" "${TRAEFIK_DYNAMIC}"
	install -d -m 0700 -o "${TRAEFIK_USER}" -g "${TRAEFIK_USER}" "${TRAEFIK_STATE}"
	install -d -m 0750 -o "${TRAEFIK_USER}" -g "${TRAEFIK_USER}" "${TRAEFIK_LOG_DIR}"
	install -d -m 0755 "${TRAEFIK_HOME}"
	if _traefik_coraza; then
		_traefik_plugin
	else
		_traefik_plugin_remove
	fi
	[[ $(files_changes_of traefik) == 0 ]] || changed=1
	bundle=$(opt acme_ca_bundle)
	if [[ -n ${bundle} ]]; then
		file_write 0644 root:root "${TRAEFIK_ACME_CA}" <"${bundle}"
	else
		file_remove "${TRAEFIK_ACME_CA}"
	fi
	_traefik_static | file_write 0640 "root:${TRAEFIK_USER}" "${TRAEFIK_CONF}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_traefik_dynamic | file_write 0640 "root:${TRAEFIK_USER}" "${TRAEFIK_DYNAMIC}/lss.yml"
	_traefik_admin
	# Traefik reads the password file only when it loads the route.
	[[ $(files_changes_of traefik) == 0 ]] || changed=1
	if opt_bool docker; then
		_traefik_docker
	else
		_traefik_docker_remove
	fi
	traefik_tls_sync
	_traefik_logrotate | file_write 0644 root:root "${TRAEFIK_LOGROTATE}"
	fw_allow 80/tcp 443/tcp 443/udp
	_traefik_unit | svc_unit "${TRAEFIK_UNIT}.service"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	svc_sandbox "${TRAEFIK_UNIT}.service" "ReadWritePaths=${TRAEFIK_STATE}" "ReadWritePaths=${TRAEFIK_LOG_DIR}" \
		ProtectProc=invisible ProcSubset=pid SystemCallFilter=@system-service SystemCallErrorNumber=EPERM
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	# The web server leaves ports 80 and 443 to Traefik first and listens on 127.0.0.1 behind it.
	if [[ -n ${server} ]]; then
		LSS_WEB_BACKEND=on module_run "${server}" configure ||
			die "traefik: ${server} could not switch to the backend ports ${WEB_BACKEND_HTTP_PORT} and ${WEB_BACKEND_HTTPS_PORT}."
	fi
	traefik_backend_sync "${server}"
	if [[ ${changed} == 1 ]] && svc_is_active "${TRAEFIK_UNIT}"; then
		svc_restart "${TRAEFIK_UNIT}" || die "traefik: ${TRAEFIK_UNIT} does not start; see journalctl -u ${TRAEFIK_UNIT}."
	fi
	svc_enable "${TRAEFIK_UNIT}"
	# Routes of the applications move from the web server to Traefik; then the routes of this module.
	web_routes_apply
	_traefik_routes
	traefik_ids_configure
	return
}

# _traefik_https HOST PATH [CURL OPTION...]: a request to https://HOST/PATH on this server's port 443; prints the
# response headers, the body and a last line with the status.
_traefik_https() {
	local host=$1 path=$2
	shift 2
	curl -sk --max-time 15 -D - --resolve "${host}:443:127.0.0.1" -w '\n%{http_code}' "$@" "https://${host}/${path}" || true
	return
}

_traefik_status() {
	local answer=$1
	printf '%s' "${answer##*$'\n'}"
	return
}

# _traefik_listen_local PORT: everything that listens on TCP PORT listens on the loopback interface only.
_traefik_listen_local() {
	local port=$1 addresses
	addresses=$(ss -Hltn "sport = :${port}" | awk '{ print $4 }')
	[[ -n ${addresses} ]] || return 1
	! grep -qvE '^(127\.0\.0\.1|\[::1\]):' <<<"${addresses}"
	return
}

_traefik_verify_waf() {
	local answer
	if _traefik_coraza; then
		answer=$(_traefik_https "${TRAEFIK_PROBE_HOST}" "?id=1%27%20OR%20%271%27%3D%271")
		[[ $(_traefik_status "${answer}") == 403 ]] ||
			die "traefik: Coraza let an SQL injection through (status $(_traefik_status "${answer}"), not 403)."
		answer=$(_traefik_https "${TRAEFIK_PROBE_HOST}" "?file=../../../../etc/passwd")
		[[ $(_traefik_status "${answer}") == 403 ]] ||
			die "traefik: Coraza let a path traversal to /etc/passwd through (status $(_traefik_status "${answer}"), not 403)."
	else
		answer=$(_traefik_https "${TRAEFIK_PROBE_HOST}" "?id=1%27%20OR%20%271%27%3D%271")
		[[ $(_traefik_status "${answer}") == 200 ]] ||
			die "traefik: without Coraza the probe route answers $(_traefik_status "${answer}"), not 200."
	fi
	if _traefik_modsecurity; then
		state_installed modsecurity ||
			die "traefik: LSS_TRAEFIK_WAF=$(opt waf) needs the modsecurity module in the web server (lss install modsecurity), or choose coraza."
		# Through Traefik to the backend web server, where ModSecurity decides.
		answer=$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
			"http://127.0.0.1/.well-known/acme-challenge/lss-probe?id=1%27%20OR%20%271%27%3D%271" || true)
		[[ ${answer} == 403 ]] || die "traefik: ModSecurity behind Traefik let an SQL injection through (status ${answer}, not 403)."
	fi
	return
}

# Every site of the vhost module answers through Traefik with the security headers.
_traefik_verify_sites() {
	local spec domains domain answer
	state_installed vhost || return 0
	for spec in $(config_get LSS_VHOST_SITES); do
		IFS=':' read -r _ _ domains _ <<<"${spec}"
		domain=${domains%%,*}
		answer=$(_traefik_https "${domain}" '')
		[[ $(_traefik_status "${answer}") =~ ^[1-5][0-9][0-9]$ ]] ||
			die "traefik: the site https://${domain}/ does not answer through Traefik."
		grep -qi '^strict-transport-security: max-age=63072000' <<<"${answer}" ||
			die "traefik: https://${domain}/ has no Strict-Transport-Security header."
	done
	return
}

# Every recorded route answers (502 counts as an answer: the application may be down); with Traefik's ACME client
# its certificate comes from the ACME server.
_traefik_verify_routes() {
	local name domain answer default i served
	default=$(openssl x509 -noout -fingerprint -sha256 -in "${WEB_TLS_DIR}/default/fullchain.pem" 2>/dev/null || true)
	for name in $(web_route_names); do
		domain=$(awk '{ print $2 }' "$(_web_routes_dir)/${name}")
		[[ -f ${TRAEFIK_DYNAMIC}/route-${name}.yml ]] || die "traefik: the route ${name} has no Traefik configuration."
		answer=''
		for ((i = 0; i < 15; i++)); do
			answer=$(_traefik_https "${domain}" '')
			[[ $(_traefik_status "${answer}") == 404 ]] || break
			sleep 1
		done
		[[ $(_traefik_status "${answer}") =~ ^[1-5][0-9][0-9]$ && $(_traefik_status "${answer}") != 404 ]] ||
			die "traefik: the route ${name} (https://${domain}/) does not answer through Traefik."
		opt_bool acme || continue
		for ((i = 0; i < 90; i++)); do
			served=$(openssl s_client -connect 127.0.0.1:443 -servername "${domain}" </dev/null 2>/dev/null |
				openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)
			[[ -z ${served} || ${served} == "${default}" ]] || break
			sleep 2
		done
		[[ -n ${served} && ${served} != "${default}" ]] ||
			die "traefik: the ACME server issued no certificate for ${domain}; see journalctl -u ${TRAEFIK_UNIT}."
	done
	return
}

# The admin interfaces under LSS_TRAEFIK_ADMIN_HOST: refused without the password, served with it.
_traefik_verify_admin() {
	local host password answer tool path
	host=$(opt admin_host)
	[[ -n ${host} && -n $(web_server) ]] || return 0
	answer=$(_traefik_https "${host}" '')
	[[ $(_traefik_status "${answer}") == 401 ]] ||
		die "traefik: https://${host}/ answers $(_traefik_status "${answer}") without a password, not 401."
	secret_load web-admin-password password 32
	for tool in adminer:adminer/ phpmyadmin:phpmyadmin/ pgadmin:pgadmin4/login; do
		state_installed "${tool%%:*}" || continue
		path=${tool#*:}
		answer=$(_traefik_https "${host}" "${path}" -K - <<<"user = \"admin:${password}\"")
		[[ $(_traefik_status "${answer}") == 200 ]] ||
			die "traefik: https://${host}/${path} answers $(_traefik_status "${answer}") with the password, not 200."
	done
	return
}

# The socket proxy answers Traefik's read-only calls and refuses the rest.
_traefik_verify_docker() {
	local status
	opt_bool docker || return 0
	ctr_running "${TRAEFIK_PROXY_NAME}" || die "traefik: the socket proxy ${TRAEFIK_PROXY_NAME} is not running."
	[[ -S ${TRAEFIK_PROXY_SOCKET} ]] || die "traefik: the socket proxy has no socket at ${TRAEFIK_PROXY_SOCKET}."
	status=$(runuser -u "${TRAEFIK_USER}" -- curl -s --max-time 10 -o /dev/null -w '%{http_code}' \
		--unix-socket "${TRAEFIK_PROXY_SOCKET}" http://localhost/containers/json || true)
	[[ ${status} == 200 ]] || die "traefik: the socket proxy does not list the containers for Traefik (status ${status})."
	status=$(runuser -u "${TRAEFIK_USER}" -- curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X POST \
		--unix-socket "${TRAEFIK_PROXY_SOCKET}" http://localhost/containers/create || true)
	[[ ${status} =~ ^40[0-9]$ ]] || die "traefik: the socket proxy lets a container be created (status ${status})."
	status=$(runuser -u "${TRAEFIK_USER}" -- curl -s --max-time 10 -o /dev/null -w '%{http_code}' \
		--unix-socket "${TRAEFIK_PROXY_SOCKET}" http://localhost/images/json || true)
	[[ ${status} =~ ^40[0-9]$ ]] || die "traefik: the socket proxy answers more than container calls (status ${status})."
	return
}

# _traefik_die MESSAGE: stops verify with MESSAGE and the last lines Traefik wrote to the journal, which hold the reason
# (a configuration it refuses, a port it cannot bind).
_traefik_die() {
	local line
	while IFS= read -r line; do
		log_warn "traefik: journal: ${line}"
	done < <(journalctl -u "${TRAEFIK_UNIT}" -n 25 --no-pager -o cat 2>/dev/null || true)
	die "traefik: $1"
	return 1
}

mod_verify() {
	local port i answer='' server status
	port=$(opt_int dashboard_port)
	svc_is_active "${TRAEFIK_UNIT}" || _traefik_die "${TRAEFIK_UNIT} is not running."
	for ((i = 0; i < 30; i++)); do
		answer=$(curl -s --max-time 5 "http://127.0.0.1:${port}/ping" 2>/dev/null || true)
		[[ ${answer} != OK ]] || break
		sleep 1
	done
	[[ ${answer} == OK ]] || _traefik_die "the ping on 127.0.0.1:${port} does not answer."
	_traefik_listen_local "${port}" || die "traefik: the dashboard port ${port} listens beyond 127.0.0.1."
	curl -fsS --max-time 10 -o /dev/null "http://127.0.0.1:${port}/api/version" ||
		_traefik_die "the API on 127.0.0.1:${port} does not answer."
	# The probe route goes through the middlewares of the HTTPS entry point; a new file takes a moment to load.
	for ((i = 0; i < 30; i++)); do
		answer=$(_traefik_https "${TRAEFIK_PROBE_HOST}" '')
		[[ $(_traefik_status "${answer}") != 200 ]] || break
		sleep 1
	done
	[[ $(_traefik_status "${answer}") == 200 ]] || _traefik_die "port 443 does not answer for the probe route."
	grep -qi '^strict-transport-security: max-age=63072000' <<<"${answer}" ||
		die "traefik: HTTPS answers have no Strict-Transport-Security header."
	grep -qi '^x-content-type-options: nosniff' <<<"${answer}" || die "traefik: HTTPS answers have no X-Content-Type-Options header."
	grep -qi '^alt-svc: .*h3=' <<<"${answer}" || die "traefik: HTTPS answers do not advertise HTTP/3 (Alt-Svc)."
	[[ -n $(ss -Hlun 'sport = :443') ]] || die "traefik: nothing listens on 443/udp for HTTP/3."
	answer=$(curl -s --max-time 10 -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: ${TRAEFIK_PROBE_HOST}" \
		http://127.0.0.1/lss-check || true)
	[[ ${answer} == "301 https://${TRAEFIK_PROBE_HOST}/lss-check" ]] ||
		die "traefik: port 80 does not redirect to HTTPS (${answer})."
	_traefik_verify_waf
	server=$(web_server)
	if [[ -n ${server} ]]; then
		_traefik_listen_local "${WEB_BACKEND_HTTPS_PORT}" ||
			die "traefik: ${server} does not listen on 127.0.0.1:${WEB_BACKEND_HTTPS_PORT} only (backend mode)."
		[[ $(curl -fsS --max-time 10 http://127.0.0.1/.well-known/acme-challenge/lss-probe 2>/dev/null) == lss ]] ||
			die "traefik: ACME challenges on port 80 do not reach ${server}."
		status=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' --resolve "lss-check.invalid:443:127.0.0.1" \
			https://lss-check.invalid/ || true)
		[[ ${status} =~ ^[1-5][0-9][0-9]$ ]] || _traefik_die "requests for other host names do not reach ${server} (status ${status})."
	fi
	_traefik_verify_sites
	_traefik_verify_routes
	_traefik_verify_admin
	_traefik_verify_docker
	return
}

mod_remove() {
	local server name
	# Everything goes back to the web server: routes, ports 80 and 443.
	export LSS_WEB_BACKEND=off
	for name in $(web_route_names traefik); do
		web_proxy_route_remove "${name}"
	done
	svc_disable "${TRAEFIK_UNIT}"
	server=$(web_server)
	if [[ -n ${server} ]]; then
		module_run "${server}" configure || die "traefik: ${server} could not take ports 80 and 443 back."
		web_routes_apply
	elif [[ -n $(web_route_names) ]]; then
		log_warn "traefik: the routes $(web_route_names | tr '\n' ' ')have no web server now; install nginx, apache or caddy to serve them."
	fi
	_traefik_docker_remove
	traefik_ids_remove
	svc_dropin_remove "${TRAEFIK_UNIT}.service" lss-sandbox
	file_remove "/etc/systemd/system/${TRAEFIK_UNIT}.service"
	svc_daemon_reload
	file_remove "${TRAEFIK_LOGROTATE}"
	file_remove "${TRAEFIK_DIR}"
	file_remove "${TRAEFIK_HOME}"
	file_remove "${TRAEFIK_BIN}"
	file_remove "${WEB_TLS_DIR}/lss-admin"
	if [[ -d ${TRAEFIK_CACHE} ]]; then
		rm -rf -- "${TRAEFIK_CACHE}"
		files_note_change "removed ${TRAEFIK_CACHE}"
	fi
	# Traefik's ACME account and certificates and the access logs stay unless the removal purges.
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		rm -rf -- "${TRAEFIK_STATE}" "${TRAEFIK_LOG_DIR}"
		if getent passwd "${TRAEFIK_USER}" >/dev/null; then
			userdel "${TRAEFIK_USER}" >/dev/null 2>&1 || true
		fi
		if getent group "${TRAEFIK_USER}" >/dev/null; then
			groupdel "${TRAEFIK_USER}" >/dev/null 2>&1 || true
		fi
		files_note_change "removed Traefik's data"
	fi
	return
}
