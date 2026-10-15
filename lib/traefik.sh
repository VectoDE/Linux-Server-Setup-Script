# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Traefik as the edge proxy (module traefik). Traefik owns ports 80, 443 and 443/udp; the web server, when there is
# one, runs behind it in backend mode (lib/web.sh, web_backend) and Traefik sends every host name without a route of
# its own there. Routes of applications come from web_proxy_route (lib/web.sh).
#
# /etc/traefik/traefik.yml        static configuration (module traefik)
# /etc/traefik/dynamic/lss.yml    middlewares (headers, WAF, redirect) and the probe route (module traefik)
# /etc/traefik/dynamic/tls.yml    certificates of WEB_TLS_DIR and the TLS settings          (derived, see below)
# /etc/traefik/dynamic/backend.yml  routes to the web server in backend mode                (derived)
# /etc/traefik/dynamic/route-NAME.yml  application routes of web_proxy_route                (derived)
#
# The derived files follow the state of other modules (certificates, the web server, recorded routes) and are written
# by whichever module changes that state, so they carry no checksum of one module: lss verify would report every new
# site as a change made outside lss. Traefik watches the directory and loads a change without a restart.

# shellcheck disable=SC2034 # read by the traefik module
TRAEFIK_DIR=/etc/traefik
TRAEFIK_DYNAMIC=/etc/traefik/dynamic
TRAEFIK_USER=lss-traefik
# shellcheck disable=SC2034 # read by the traefik module
TRAEFIK_UNIT=lss-traefik
TRAEFIK_LOG_DIR=/var/log/traefik
TRAEFIK_FAIL2BAN_JAIL=/etc/fail2ban/jail.d/lss-traefik.local
TRAEFIK_FAIL2BAN_FILTER_AUTH=/etc/fail2ban/filter.d/lss-traefik-auth.conf
TRAEFIK_FAIL2BAN_FILTER_WAF=/etc/fail2ban/filter.d/lss-traefik-waf.conf
TRAEFIK_CROWDSEC_ACQUIS=/etc/crowdsec/acquis.d/lss-traefik.yaml
# TLS 1.2 suites of WEB_TLS_CIPHERS in Go's names; TLS 1.3 has no settings in Go.
TRAEFIK_CIPHERS="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"

# traefik_present: Traefik is installed or being installed (a module's state is recorded only after its install).
traefik_present() {
	[[ ${LSS_MODULE:-} == traefik ]] || state_installed traefik
	return
}

# traefik_active: routes go to Traefik. False while the traefik module hands everything back to the web server
# (LSS_WEB_BACKEND=off during its removal).
traefik_active() {
	[[ ${LSS_WEB_BACKEND:-} != off ]] || return 1
	traefik_present
	return
}

# _traefik_ready: Traefik's dynamic directory exists, so derived files can be written.
_traefik_ready() {
	traefik_active && [[ -d ${TRAEFIK_DYNAMIC} ]]
	return
}

# _traefik_write DEST: a derived file of the dynamic configuration from stdin (mode 0640, group TRAEFIK_USER),
# replaced only when it differs. Sets LSS_FILE_CHANGED.
_traefik_write() {
	local dest=$1 tmp
	LSS_FILE_CHANGED=0
	tmp=$(mktemp "${dest}.lss.XXXXXX")
	cat >"${tmp}"
	if [[ -f ${dest} ]] && cmp -s "${tmp}" "${dest}" &&
		[[ $(stat -c '%a %U:%G' "${dest}") == "640 root:${TRAEFIK_USER}" ]]; then
		rm -f -- "${tmp}"
		return 0
	fi
	chmod 0640 "${tmp}"
	chown "root:${TRAEFIK_USER}" "${tmp}"
	mv -f -- "${tmp}" "${dest}"
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -F "${dest}" 2>/dev/null || true
	fi
	# shellcheck disable=SC2034 # read by callers
	LSS_FILE_CHANGED=1
	files_note_change "wrote ${dest}"
	return
}

# _traefik_drop FILE: removes a derived file.
_traefik_drop() {
	local file=$1
	[[ -e ${file} ]] || return 0
	rm -f -- "${file}"
	files_note_change "removed ${file}"
	return
}

# traefik_tls_conf: the content of tls.yml: every certificate below WEB_TLS_DIR (Traefik picks one by the SNI name), the
# default certificate for every other name, and the TLS settings of the web servers (TLS 1.2 and 1.3, the cipher suites
# of WEB_TLS_CIPHERS).
traefik_tls_conf() {
	local dir cipher
	printf '# Managed by lss (Traefik). The certificates of %s; written again when one is added or removed.\ntls:\n' \
		"${WEB_TLS_DIR}"
	printf '  certificates:\n'
	for dir in "${WEB_TLS_DIR}"/*/; do
		dir=${dir%/}
		[[ -s ${dir}/fullchain.pem && -s ${dir}/privkey.pem ]] || continue
		printf '    - certFile: %s/fullchain.pem\n      keyFile: %s/privkey.pem\n' "${dir}" "${dir}"
	done
	printf '  stores:\n    default:\n      defaultCertificate:\n'
	printf '        certFile: %s/default/fullchain.pem\n        keyFile: %s/default/privkey.pem\n' "${WEB_TLS_DIR}" \
		"${WEB_TLS_DIR}"
	printf '  options:\n    default:\n      minVersion: VersionTLS12\n      cipherSuites:\n'
	for cipher in ${TRAEFIK_CIPHERS}; do
		printf '        - %s\n' "${cipher}"
	done
	return
}

# traefik_tls_sync: writes tls.yml when Traefik is in front.
traefik_tls_sync() {
	_traefik_ready || return 0
	traefik_tls_conf | _traefik_write "${TRAEFIK_DYNAMIC}/tls.yml"
	return
}

# traefik_backend_conf: the content of backend.yml: every host name without a route of its own goes to the web
# server's HTTPS port, ACME challenges on port 80 to its HTTP port (the tls module's webroot challenges). Both stay on
# the loopback interface; the backend presents the certificate of the site, which is not issued for 127.0.0.1, so
# Traefik does not check it on this hop (insecureSkipVerify concerns 127.0.0.1 only).
traefik_backend_conf() {
	cat <<EOF
# Managed by lss (Traefik). The web server behind Traefik (backend mode).
http:
  routers:
    lss-backend:
      entryPoints: [websecure]
      rule: PathPrefix(\`/\`)
      priority: 1
      service: lss-backend
    lss-acme:
      entryPoints: [web]
      rule: PathPrefix(\`/.well-known/acme-challenge/\`)
      priority: 100
      service: lss-backend-http
  services:
    lss-backend:
      loadBalancer:
        serversTransport: lss-backend
        servers:
          - url: https://127.0.0.1:${WEB_BACKEND_HTTPS_PORT}
    lss-backend-http:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:${WEB_BACKEND_HTTP_PORT}
  serversTransports:
    lss-backend:
      insecureSkipVerify: true
EOF
	return
}

# traefik_backend_sync SERVER: backend.yml for the web server SERVER, or no backend when SERVER is empty (the web
# server is being removed).
traefik_backend_sync() {
	local server=$1
	_traefik_ready || return 0
	if [[ -n ${server} ]]; then
		traefik_backend_conf | _traefik_write "${TRAEFIK_DYNAMIC}/backend.yml"
	else
		_traefik_drop "${TRAEFIK_DYNAMIC}/backend.yml"
	fi
	return
}

# _traefik_acme: Traefik requests certificates itself (LSS_TRAEFIK_ACME).
_traefik_acme() {
	config_bool "$(config_key traefik acme)"
	return
}

# traefik_route_conf NAME URL DOMAIN...: a router for the host names and a service for URL.
traefik_route_conf() {
	local name=$1 url=$2 rule='' domain
	shift 2
	for domain in "$@"; do
		rule+="${rule:+ || }Host(\`${domain}\`)"
	done
	printf '# Managed by lss (route %s).\nhttp:\n  routers:\n    route-%s:\n' "${name}" "${name}"
	printf '      entryPoints: [websecure]\n      rule: "%s"\n      service: route-%s\n' "${rule}" "${name}"
	if _traefik_acme; then
		printf '      tls:\n        certResolver: lss\n'
	fi
	printf '  services:\n    route-%s:\n      loadBalancer:\n        servers:\n          - url: %s\n' "${name}" "${url}"
	return
}

# traefik_route_write NAME URL DOMAIN...
traefik_route_write() {
	_traefik_ready || die "traefik: the route $1 needs Traefik's configuration in ${TRAEFIK_DYNAMIC}."
	traefik_route_conf "$@" | _traefik_write "${TRAEFIK_DYNAMIC}/route-$1.yml"
	return
}

# traefik_route_remove NAME
traefik_route_remove() {
	_traefik_drop "${TRAEFIK_DYNAMIC}/route-$1.yml"
	return
}

# traefik_ids_configure: fail2ban jails and CrowdSec log acquisition for Traefik's access log, or none without
# Traefik. Called by the traefik module and through web_ids_configure by fail2ban and crowdsec.
traefik_ids_configure() {
	if ! traefik_active; then
		traefik_ids_remove
		return 0
	fi
	local log="${TRAEFIK_LOG_DIR}/access.log"
	if state_installed fail2ban || [[ ${LSS_MODULE:-} == fail2ban ]]; then
		_traefik_fail2ban "${log}"
	fi
	if state_installed crowdsec || [[ ${LSS_MODULE:-} == crowdsec ]]; then
		_traefik_crowdsec "${log}"
	fi
	return
}

# _traefik_fail2ban LOG: Traefik writes one JSON object per request with sorted keys; ClientHost is the client, and
# DownstreamStatus what it got: 401 from the admin login, 403 from the WAF.
_traefik_fail2ban() {
	local log=$1 changed=0
	[[ -e ${log} ]] || install -d -m 0750 -o "${TRAEFIK_USER}" -g "${TRAEFIK_USER}" "$(dirname "${log}")"
	[[ -e ${log} ]] || install -m 0640 -o "${TRAEFIK_USER}" -g "${TRAEFIK_USER}" /dev/null "${log}"
	file_write 0644 root:root "${TRAEFIK_FAIL2BAN_FILTER_AUTH}" <<'EOF'
# Managed by lss (Traefik). A 401 answer is a failed login on a route with a password.
[Definition]
failregex = ^\{.*"ClientHost":"<HOST>".*"DownstreamStatus":401[,}]
ignoreregex =
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0644 root:root "${TRAEFIK_FAIL2BAN_FILTER_WAF}" <<'EOF'
# Managed by lss (Traefik). A 403 answer is a request the WAF (or the application) refused.
[Definition]
failregex = ^\{.*"ClientHost":"<HOST>".*"DownstreamStatus":403[,}]
ignoreregex =
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0644 root:root "${TRAEFIK_FAIL2BAN_JAIL}" <<EOF
# Managed by lss (Traefik).
[lss-traefik-auth]
enabled = true
backend = auto
filter = lss-traefik-auth
logpath = ${log}

[lss-traefik-waf]
enabled = true
backend = auto
filter = lss-traefik-waf
logpath = ${log}
maxretry = 10
findtime = 10m
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	if [[ ${changed} == 1 ]] && svc_is_active fail2ban; then
		fail2ban-client --test >/dev/null 2>&1 || die "traefik: the fail2ban jails for Traefik do not load."
		svc_restart fail2ban
	fi
	return
}

# _traefik_crowdsec LOG: the CrowdSec collection for Traefik and its access log.
_traefik_crowdsec() {
	local log=$1 changed=0
	if ! cscli collections list -o raw 2>/dev/null | cut -d ',' -f 1 | grep -qxF crowdsecurity/traefik; then
		cscli collections install crowdsecurity/traefik >/dev/null 2>&1 ||
			die "traefik: CrowdSec could not install crowdsecurity/traefik."
		files_note_change "crowdsec collection crowdsecurity/traefik"
		changed=1
	fi
	printf '# Managed by lss (Traefik).\nfilenames:\n  - %s\nlabels:\n  type: traefik\n' "${log}" |
		file_write 0644 root:root "${TRAEFIK_CROWDSEC_ACQUIS}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	if [[ ${changed} == 1 ]] && svc_is_active crowdsec; then
		svc_restart crowdsec
	fi
	return
}

# traefik_ids_remove: drops Traefik's jails and log acquisition.
traefik_ids_remove() {
	if [[ -e ${TRAEFIK_FAIL2BAN_JAIL} ]]; then
		file_remove "${TRAEFIK_FAIL2BAN_JAIL}"
		file_remove "${TRAEFIK_FAIL2BAN_FILTER_AUTH}"
		file_remove "${TRAEFIK_FAIL2BAN_FILTER_WAF}"
		if svc_is_active fail2ban; then
			svc_restart fail2ban
		fi
	fi
	if [[ -e ${TRAEFIK_CROWDSEC_ACQUIS} ]]; then
		file_remove "${TRAEFIK_CROWDSEC_ACQUIS}"
		if svc_is_active crowdsec; then
			svc_restart crowdsec
		fi
	fi
	return
}
