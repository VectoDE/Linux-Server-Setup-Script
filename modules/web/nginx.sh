# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="nginx"
MOD_GROUP="web"
MOD_DESCRIPTION="nginx web server: HTTPS only (TLS 1.2 and 1.3), security headers, closed default server, admin port on localhost"
MOD_REQUIRES="system"
MOD_CONFLICTS="apache caddy"
MOD_OPTIONS="max_body|64m|Largest request body (uploads), for example 64m or 1g
admin_public|false|Serve the admin interfaces (phpMyAdmin, Adminer, pgAdmin) on port 8090 to everyone, with TLS and a password (user admin, lss secrets show web-admin-password); otherwise only on 127.0.0.1 (use an SSH tunnel)"
MOD_SECRETS="web-admin-password"

NGINX_CONF=/etc/nginx/nginx.conf
NGINX_DIR=/etc/nginx/lss

mod_check() {
	[[ $(opt max_body) =~ ^[0-9]+[kKmMgG]?$ ]] || die "LSS_NGINX_MAX_BODY '$(opt max_body)' is not a size like 64m or 1g."
	opt_bool admin_public || true
	return
}

mod_install() {
	pkg_install nginx openssl
	return
}

_nginx_modules_dir() {
	if os_is_debian; then printf '/etc/nginx/modules-enabled'; else printf '/usr/share/nginx/modules'; fi
	return
}

_nginx_main_conf() {
	cat <<EOF
# Managed by lss (module nginx). Sites: ${NGINX_DIR}/sites, admin paths: ${NGINX_DIR}/admin.
user $(web_user nginx);
worker_processes auto;
worker_rlimit_nofile 8192;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;
include $(_nginx_modules_dir)/*.conf;
# Modules and http settings that other lss modules add (modsecurity); empty otherwise.
include ${NGINX_DIR}/modules/*.conf;

events {
	worker_connections 2048;
}

http {
	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	server_names_hash_bucket_size 128;

	server_tokens off;
	client_max_body_size $(opt max_body);
	client_body_timeout 15s;
	client_header_timeout 15s;
	send_timeout 30s;
	keepalive_timeout 30s;
	access_log /var/log/nginx/access.log;

	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers ${WEB_TLS_CIPHERS};
	ssl_prefer_server_ciphers off;
	ssl_session_timeout 1d;
	ssl_session_cache shared:LSS:10m;
	ssl_session_tickets off;

	map \$http_upgrade \$connection_upgrade {
		default upgrade;
		'' close;
	}

	include ${NGINX_DIR}/http/*.conf;
	include ${NGINX_DIR}/default.conf;
	include ${NGINX_DIR}/admin.conf;
	include ${NGINX_DIR}/sites/*.conf;
}
EOF
	return
}

# Unknown host names get no answer (444) on both ports; port 80 still serves ACME challenges for every name.
_nginx_default_conf() {
	printf '# Managed by lss (module nginx). Requests for host names without a site.\nserver {\n'
	_web_listen_nginx 80 default_server
	printf '\tserver_name _;\n\tlocation /.well-known/acme-challenge/ {\n\t\troot %s;\n\t}\n' "${WEB_ACME_ROOT}"
	printf '\tlocation / {\n\t\treturn 444;\n\t}\n}\n\nserver {\n'
	_web_listen_nginx 443 "default_server $(web_nginx_ssl_flags)"
	printf '\tserver_name _;\n'
	_web_tls_nginx "${WEB_TLS_DIR}/default"
	printf '\treturn 444;\n}\n'
	return
}

_nginx_admin_conf() {
	printf '# Managed by lss (module nginx). Admin interfaces on port %s.\nserver {\n' "${WEB_ADMIN_PORT}"
	if opt_bool admin_public; then
		_web_listen_nginx "${WEB_ADMIN_PORT}" "$(web_nginx_ssl_flags)"
		_web_tls_nginx "${WEB_TLS_DIR}/default"
		printf '\tauth_basic "lss admin";\n\tauth_basic_user_file %s;\n' "${WEB_ADMIN_HTPASSWD}"
	else
		printf '\tlisten 127.0.0.1:%s;\n' "${WEB_ADMIN_PORT}"
	fi
	printf '\tserver_name _;\n\tclient_max_body_size %s;\n' "$(opt max_body)"
	web_headers nginx | grep -v Strict-Transport-Security
	printf '\tlocation = / {\n\t\treturn 404;\n\t}\n\tinclude %s/admin/*.conf;\n}\n' "${NGINX_DIR}"
	return
}

_nginx_proxy_conf() {
	cat <<'EOF'
# Managed by lss (module nginx). Included by every proxied location.
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
proxy_read_timeout 300s;
EOF
	return
}

mod_configure() {
	local changed=0
	web_prepare nginx
	_nginx_main_conf | file_write 0644 root:root "${NGINX_CONF}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_nginx_default_conf | file_write 0644 root:root "${NGINX_DIR}/default.conf"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_nginx_admin_conf | file_write 0644 root:root "${NGINX_DIR}/admin.conf"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_nginx_proxy_conf | file_write 0644 root:root "${NGINX_DIR}/proxy.conf"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0644 root:root "${WEB_ACME_ROOT}/.well-known/acme-challenge/lss-probe" <<<"lss"
	if opt_bool admin_public; then
		web_admin_htpasswd nginx
		fw_allow "${WEB_ADMIN_PORT}/tcp"
	fi
	fw_allow 80/tcp 443/tcp
	svc_sandbox nginx.service ReadWritePaths=-/var/lib/nginx ReadWritePaths=-/var/cache/nginx
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	web_test nginx || die "nginx: the configuration does not load; see above."
	svc_enable nginx
	if [[ ${changed} == 1 ]]; then
		svc_restart nginx
	fi
	web_ids_configure
	return
}

mod_verify() {
	svc_is_active nginx || die "nginx: the service is not running."
	web_test nginx || die "nginx: the configuration does not load."
	[[ $(curl -fsS --max-time 10 http://127.0.0.1/.well-known/acme-challenge/lss-probe 2>/dev/null) == lss ]] ||
		die "nginx: port 80 does not serve the ACME challenge path."
	openssl s_client -connect 127.0.0.1:443 -servername lss-probe </dev/null 2>/dev/null | grep -q 'BEGIN CERTIFICATE' ||
		die "nginx: port 443 does not answer with TLS."
	curl -s --max-time 10 -o /dev/null "http://127.0.0.1:${WEB_ADMIN_PORT}/" || opt_bool admin_public ||
		die "nginx: the admin port ${WEB_ADMIN_PORT} does not answer on 127.0.0.1."
	return
}

mod_remove() {
	svc_disable nginx
	svc_dropin_remove nginx.service lss-sandbox
	file_remove "${NGINX_DIR}"
	file_remove "${WEB_ACME_ROOT}/.well-known/acme-challenge/lss-probe"
	web_ids_remove
	pkg_remove_family "nginx nginx-common nginx-core" "nginx"
	file_remove "${NGINX_CONF}"
	return
}
