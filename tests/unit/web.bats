#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The web layer (lib/web.sh): what the sites, admin paths and headers look like for nginx, Apache and Caddy, and the
# certificate helpers.

setup() {
	load helpers
	lss_test_setup
	use_os debian-13
	WEB_TLS_DIR=${BATS_TEST_TMPDIR}/tls
	mkdir -p "${WEB_TLS_DIR}/default"
	NGINX_VERSION=1.26.3
}

# shellcheck disable=SC2329 # called by the functions under test
nginx() {
	printf 'nginx version: nginx/%s\n' "${NGINX_VERSION}" >&2
}

new_cert() {
	local dir=$1 days=$2
	# The kcov image of the coverage run has no openssl.
	command -v openssl >/dev/null || skip 'openssl is not installed'
	shift 2
	local san
	san=$(printf 'DNS:%s,' "$@")
	mkdir -p "${dir}"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days "${days}" -subj "/CN=$1" \
		-addext "subjectAltName=${san%,}" -keyout "${dir}/privkey.pem" -out "${dir}/fullchain.pem" 2>/dev/null
}

@test "nginx 1.25.1 and later get the http2 directive, older versions the listen flag" {
	NGINX_VERSION=1.26.3
	web_nginx_http2_directive
	[ "$(web_nginx_ssl_flags)" = ssl ]
	NGINX_VERSION=1.25.1
	web_nginx_http2_directive
	NGINX_VERSION=1.22.1
	run ! web_nginx_http2_directive
	[ "$(web_nginx_ssl_flags)" = 'ssl http2' ]
}

@test "an nginx PHP site redirects port 80, keeps ACME challenges there and passes PHP to the lss pool" {
	run _web_site_nginx shop php /var/www/shop shop.example.com www.shop.example.com
	[ "${status}" -eq 0 ]
	[[ ${output} == *'server_name shop.example.com www.shop.example.com;'* ]]
	[[ ${output} == *'return 301 https://$host$request_uri;'* ]]
	[[ ${output} == *"root ${WEB_ACME_ROOT};"* ]]
	[[ ${output} == *'http2 on;'* ]]
	[[ ${output} == *"fastcgi_pass unix:${WEB_PHP_SOCKET};"* ]]
	[[ ${output} == *'location ~ /\.(?!well-known)'* ]]
	[[ ${output} == *'Strict-Transport-Security "max-age=63072000" always;'* ]]
}

@test "a site uses its own certificate once it has one and the default certificate before" {
	run _web_site_nginx blog static /var/www/blog blog.example.com
	[[ ${output} == *"ssl_certificate ${WEB_TLS_DIR}/default/fullchain.pem;"* ]]
	new_cert "${WEB_TLS_DIR}/blog" 90 blog.example.com
	run _web_site_nginx blog static /var/www/blog blog.example.com
	[[ ${output} == *"ssl_certificate ${WEB_TLS_DIR}/blog/fullchain.pem;"* ]]
}

@test "OCSP stapling is only switched on for certificates that name a responder" {
	new_cert "${WEB_TLS_DIR}/blog" 90 blog.example.com
	run _web_tls_nginx "${WEB_TLS_DIR}/blog"
	[[ ${output} != *ssl_stapling* ]]
}

@test "an Apache proxy site forwards WebSockets and the client address" {
	run _web_site_apache app proxy http://127.0.0.1:3000 app.example.com
	[ "${status}" -eq 0 ]
	[[ ${output} == *'ServerName app.example.com'* ]]
	[[ ${output} == *'ProxyPass / http://127.0.0.1:3000/ upgrade=websocket'* ]]
	[[ ${output} == *'ProxyPassReverse / http://127.0.0.1:3000/'* ]]
	[[ ${output} == *'Header always set X-Content-Type-Options "nosniff"'* ]]
}

@test "a Caddy site hides dot files and uses the certificate from the TLS directory, not its own ACME client" {
	run _web_site_caddy blog static /var/www/blog blog.example.com
	[ "${status}" -eq 0 ]
	[[ ${output} == *'https://blog.example.com {'* ]]
	[[ ${output} == *"tls ${WEB_TLS_DIR}/default/fullchain.pem ${WEB_TLS_DIR}/default/privkey.pem"* ]]
	[[ ${output} == *'import lss_hidden'* ]]
	[[ ${output} == *'redir https://{host}{uri} permanent'* ]]
}

@test "site names that could leave the configuration directory are refused" {
	run _web_name_check '../etc'
	[ "${status}" -ne 0 ]
	run _web_name_check 'shop-2'
	[ "${status}" -eq 0 ]
}

@test "the names of a certificate come back sorted, one per line" {
	new_cert "${WEB_TLS_DIR}/shop" 90 www.shop.example.com shop.example.com
	[ "$(web_cert_domains "${WEB_TLS_DIR}/shop/fullchain.pem")" = $'shop.example.com\nwww.shop.example.com' ]
}

@test "the admin port is the same for every web server and stays on localhost in the private setup" {
	run _web_admin_nginx pma phpmyadmin php /usr/share/phpmyadmin
	[[ ${output} == *'location ^~ /phpmyadmin/'* ]]
	run _web_admin_caddy pma phpmyadmin php /usr/share/phpmyadmin
	[[ ${output} == *'handle_path /phpmyadmin/*'* ]]
}
