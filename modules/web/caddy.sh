# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="caddy"
MOD_GROUP="web"
MOD_DESCRIPTION="Caddy web server from its official repository: HTTPS only, security headers, JSON access log, admin port on localhost"
MOD_REQUIRES="system"
MOD_CONFLICTS="nginx apache"
MOD_OPTIONS="max_body|64m|Largest request body (uploads), for example 64m or 1g
admin_public|false|Serve the admin interfaces (phpMyAdmin, Adminer, pgAdmin) on port 8090 to everyone, with TLS and a password (user admin, lss secrets show web-admin-password); otherwise only on 127.0.0.1 (use an SSH tunnel)"
MOD_SECRETS="web-admin-password"

CADDY_FILE=/etc/caddy/Caddyfile
CADDY_DIR=/etc/caddy/lss

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

_caddy_file() {
	cat <<EOF
# Managed by lss (module caddy). Sites: ${CADDY_DIR}/sites, admin paths: ${CADDY_DIR}/admin.
{
	auto_https off
	admin localhost:2019
	servers {
		protocols h1 h2
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

(lss_tls_headers) {
	header {
$(_caddy_headers)
	}
	request_body {
		max_size $(_caddy_size "$(opt max_body)")
	}
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
	handle /.well-known/acme-challenge/* {
		root * ${WEB_ACME_ROOT}
		file_server
	}
	handle {
		abort
	}
}

https:// {
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
		printf 'http://127.0.0.1:%s {\n' "${WEB_ADMIN_PORT}"
	fi
	printf '\timport lss_headers\n\tlog\n\timport %s/admin/*.caddy\n\thandle {\n\t\trespond 404\n\t}\n}\n' "${CADDY_DIR}"
	return
}

mod_configure() {
	local changed=0
	web_prepare caddy
	install -d -m 0750 -o caddy -g caddy /var/log/caddy
	_caddy_file | file_write 0644 root:root "${CADDY_FILE}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0644 root:root "${WEB_ACME_ROOT}/.well-known/acme-challenge/lss-probe" <<<"lss"
	if opt_bool admin_public; then
		web_admin_htpasswd caddy
		fw_allow "${WEB_ADMIN_PORT}/tcp"
	fi
	fw_allow 80/tcp 443/tcp
	svc_sandbox caddy.service ReadWritePaths=-/var/lib/caddy ReadWritePaths=-/var/log/caddy
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	web_test caddy || die "caddy: the configuration does not load; see above."
	svc_enable caddy
	# A restart, not a reload: the caddy user has to pick up its new group (the TLS keys are readable by it).
	if [[ ${changed} == 1 || $(files_changes_of caddy) != 0 ]]; then
		svc_restart caddy
	fi
	web_ids_configure
	return
}

mod_verify() {
	local i
	svc_is_active caddy || die "caddy: the service is not running."
	web_test caddy || die "caddy: the configuration does not load."
	for ((i = 0; i < 10; i++)); do
		[[ $(curl -fsS --max-time 5 http://127.0.0.1/.well-known/acme-challenge/lss-probe 2>/dev/null) == lss ]] && break
		sleep 1
	done
	[[ $(curl -fsS --max-time 10 http://127.0.0.1/.well-known/acme-challenge/lss-probe 2>/dev/null) == lss ]] ||
		die "caddy: port 80 does not serve the ACME challenge path."
	openssl s_client -connect 127.0.0.1:443 -servername lss-probe </dev/null 2>/dev/null | grep -q 'BEGIN CERTIFICATE' ||
		die "caddy: port 443 does not answer with TLS."
	curl -s --max-time 10 -o /dev/null "http://127.0.0.1:${WEB_ADMIN_PORT}/" || opt_bool admin_public ||
		die "caddy: the admin port ${WEB_ADMIN_PORT} does not answer on 127.0.0.1."
	return
}

mod_remove() {
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
