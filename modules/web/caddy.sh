# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="caddy"
MOD_GROUP="web"
MOD_DESCRIPTION="Caddy web server from its official repository: HTTPS only, security headers, JSON access log, admin port on localhost; behind Traefik on 127.0.0.1 only"
MOD_REQUIRES="system"
MOD_CONFLICTS="nginx apache"
MOD_OPTIONS="max_body|64m|Largest request body (uploads), for example 64m or 1g
admin_public|false|Serve the admin interfaces (phpMyAdmin, Adminer, pgAdmin) on port 8090 to everyone, with TLS and a password (user admin, lss secrets show web-admin-password); otherwise only on 127.0.0.1 (use an SSH tunnel)"
MOD_SECRETS="web-admin-password"

CADDY_FILE=/etc/caddy/Caddyfile
CADDY_DIR=/etc/caddy/lss
# The admin API changes the running configuration, so it listens on a socket only the caddy user (and root) can open,
# not on a TCP port every local account can reach.
CADDY_ADMIN_SOCKET=/run/caddy/admin.sock

mod_check() {
	[[ $(opt max_body) =~ ^[0-9]+[kKmMgG]?$ ]] || die "LSS_CADDY_MAX_BODY '$(opt max_body)' is not a size like 64m or 1g."
	opt_bool admin_public || true
	return
}

# Certificates come from the tls module (one ACME client for every web server), so Caddy's own automatic HTTPS is
# off; the configuration is written explicitly instead.
mod_install() {
	repo_add caddy
	pkg_install caddy openssl
	return
}

# _caddy_size SIZE: 64m -> 64MB, the unit Caddy's request_body directive expects.
_caddy_size() {
	local size=$1 number unit
	number=${size%[kKmMgG]}
	unit=${size#"${number}"}
	printf '%s%s' "${number}" "$(tr '[:lower:]' '[:upper:]' <<<"${unit}")"
	[[ -z ${unit} ]] || printf 'B'
	return
}

_caddy_headers() {
	web_headers caddy
	printf '\t\t-Server\n'
	return
}

# Behind Traefik: the backend ports for every http:// and https:// address, the listeners on 127.0.0.1 (lss_bind,
# which every site imports) and the client address from Traefik's X-Forwarded-For (client_ip in the access log).
_caddy_backend_options() {
	if web_backend; then
		printf '\thttp_port %s\n\thttps_port %s\n' "${WEB_BACKEND_HTTP_PORT}" "${WEB_BACKEND_HTTPS_PORT}"
	fi
	return
}

_caddy_backend_proxies() {
	if web_backend; then
		printf '\t\ttrusted_proxies static 127.0.0.1/32 ::1/128\n'
	fi
	return
}

_caddy_bind_snippet() {
	printf '(lss_bind) {\n'
	if web_backend; then
		printf '\tbind 127.0.0.1\n'
	fi
	printf '}\n'
	return
}

_caddy_file() {
	cat <<EOF
# Managed by lss (module caddy). Sites: ${CADDY_DIR}/sites, admin paths: ${CADDY_DIR}/admin.
{
	auto_https off
	admin unix/${CADDY_ADMIN_SOCKET}|0600
$(_caddy_backend_options)
	servers {
		protocols h1 h2
$(_caddy_backend_proxies)
	}
	log default {
		exclude http.log.access
	}
	log access {
		output file /var/log/caddy/access.log {
			roll_size 50MiB
			roll_keep 10
		}
		format json
		include http.log.access
	}
}

$(_caddy_bind_snippet)

(lss_tls_headers) {
	header {
$(_caddy_headers)
	}
	request_body {
		max_size $(_caddy_size "$(opt max_body)")
	}
}

# Dot files and directories (.git, .env, .htpasswd) are never served; ACME challenges below .well-known are.
(lss_hidden) {
	@lss_hidden {
		path */.*
		not path /.well-known/*
	}
	respond @lss_hidden 404
}

(lss_headers) {
	header {
$(_caddy_headers | grep -v Strict-Transport-Security)
	}
	request_body {
		max_size $(_caddy_size "$(opt max_body)")
	}
}

# Host names without a site: ACME challenges on port 80, nothing else.
http:// {
	import lss_bind
	handle /.well-known/acme-challenge/* {
		root * ${WEB_ACME_ROOT}
		file_server
	}
	handle {
		abort
	}
}

https:// {
	import lss_bind
	tls ${WEB_TLS_DIR}/default/fullchain.pem ${WEB_TLS_DIR}/default/privkey.pem
	abort
}

$(_caddy_admin_block)

import ${CADDY_DIR}/sites/*.caddy
EOF
	return
}

_caddy_admin_block() {
	if opt_bool admin_public; then
		printf 'https://:%s {\n\ttls %s/default/fullchain.pem %s/default/privkey.pem\n' "${WEB_ADMIN_PORT}" \
			"${WEB_TLS_DIR}" "${WEB_TLS_DIR}"
		printf '\tbasic_auth {\n\t\timport %s\n\t}\n' "${WEB_ADMIN_CADDY_AUTH}"
	else
		# The site address only matches the Host header; bind keeps the listener itself on the loopback interface.
		printf 'http://127.0.0.1:%s {\n\tbind 127.0.0.1\n' "${WEB_ADMIN_PORT}"
	fi
	printf '\timport lss_headers\n\timport lss_hidden\n\tlog\n\timport %s/admin/*.caddy\n\thandle {\n\t\trespond 404\n\t}\n}\n' "${CADDY_DIR}"
	return
}

mod_configure() {
	local changed=0
	web_prepare caddy
	install -d -m 0750 -o caddy -g caddy /var/log/caddy
	# caddy validate runs as root and opens the access log; a file it creates would be root's, and the service, which
	# runs as caddy, could not write it.
	[[ -e /var/log/caddy/access.log ]] || install -m 0640 -o caddy -g caddy /dev/null /var/log/caddy/access.log
	chown caddy:caddy /var/log/caddy/access.log
	# Empty imports keep Caddy from warning about import patterns that match nothing yet.
	install -d -m 0755 "${CADDY_DIR}/sites" "${CADDY_DIR}/admin"
	printf '# Managed by lss: keeps the import pattern from matching nothing.\n' |
		file_write 0644 root:root "${CADDY_DIR}/sites/00-lss.caddy"
	printf '# Managed by lss: keeps the import pattern from matching nothing.\n' |
		file_write 0644 root:root "${CADDY_DIR}/admin/00-lss.caddy"
	_caddy_file | file_write 0644 root:root "${CADDY_FILE}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0644 root:root "${WEB_ACME_ROOT}/.well-known/acme-challenge/lss-probe" <<<"lss"
	if opt_bool admin_public; then
		web_admin_htpasswd caddy
		fw_allow "${WEB_ADMIN_PORT}/tcp"
	fi
	fw_allow 80/tcp 443/tcp
	svc_sandbox caddy.service ReadWritePaths=-/var/lib/caddy ReadWritePaths=-/var/log/caddy RuntimeDirectory=caddy \
		RuntimeDirectoryMode=0750
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	web_test caddy || die "caddy: the configuration does not load; see above."
	svc_enable caddy
	# A restart, not a reload: the caddy user has to pick up its new group (the TLS keys are readable by it).
	if [[ ${changed} == 1 || $(files_changes_of caddy) != 0 ]]; then
		svc_restart caddy
	fi
	web_ids_configure
	traefik_backend_sync caddy
	return
}

mod_verify() {
	local i http https
	http=$(web_http_port)
	https=$(web_https_port)
	svc_is_active caddy || die "caddy: the service is not running."
	web_test caddy || die "caddy: the configuration does not load."
	for ((i = 0; i < 10; i++)); do
		[[ $(curl -fsS --max-time 5 "http://127.0.0.1:${http}/.well-known/acme-challenge/lss-probe" 2>/dev/null) == lss ]] && break
		sleep 1
	done
	[[ $(curl -fsS --max-time 10 "http://127.0.0.1:${http}/.well-known/acme-challenge/lss-probe" 2>/dev/null) == lss ]] ||
		die "caddy: port ${http} does not serve the ACME challenge path."
	openssl s_client -connect "127.0.0.1:${https}" -servername lss-probe </dev/null 2>/dev/null | grep -q 'BEGIN CERTIFICATE' ||
		die "caddy: port ${https} does not answer with TLS."
	curl -s --max-time 10 -o /dev/null "http://127.0.0.1:${WEB_ADMIN_PORT}/" || opt_bool admin_public ||
		die "caddy: the admin port ${WEB_ADMIN_PORT} does not answer on 127.0.0.1."
	return
}

mod_remove() {
	traefik_backend_sync ''
	svc_disable caddy
	svc_dropin_remove caddy.service lss-sandbox
	web_ids_remove
	file_remove "${CADDY_DIR}"
	file_remove "${WEB_ACME_ROOT}/.well-known/acme-challenge/lss-probe"
	pkg_remove caddy
	file_remove "${CADDY_FILE}"
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		repo_remove caddy
	fi
	return
}
