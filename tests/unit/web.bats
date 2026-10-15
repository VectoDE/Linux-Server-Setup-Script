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
	# As in lss: "generator | file_write" sets LSS_FILE_CHANGED in this shell.
	shopt -s lastpipe
	export TMPDIR=${BATS_TEST_TMPDIR}
	WEB_TLS_DIR=${BATS_TEST_TMPDIR}/tls
	mkdir -p "${WEB_TLS_DIR}/default"
	WEB_ACME_ROOT=${BATS_TEST_TMPDIR}/www/acme
	WEB_DEFAULT_ROOT=${BATS_TEST_TMPDIR}/www/default
	WEB_ACME_CA=${BATS_TEST_TMPDIR}/letsencrypt/ca.pem
	WEB_CERT_LIVE=${BATS_TEST_TMPDIR}/letsencrypt/live
	WEB_CERT_HOOK=${BATS_TEST_TMPDIR}/letsencrypt/deploy-hook
	WEB_ADMIN_HTPASSWD=${BATS_TEST_TMPDIR}/web/admin.htpasswd
	WEB_ADMIN_CADDY_AUTH=${BATS_TEST_TMPDIR}/web/admin-auth.caddy
	WEB_FAIL2BAN_JAIL=${BATS_TEST_TMPDIR}/fail2ban/jail.d/lss-web.local
	WEB_FAIL2BAN_FILTER=${BATS_TEST_TMPDIR}/fail2ban/filter.d/lss-caddy-auth.conf
	WEB_CROWDSEC_ACQUIS=${BATS_TEST_TMPDIR}/crowdsec/acquis.d/lss-web.yaml
	WRITES=${BATS_TEST_TMPDIR}/writes
	NGINX_VERSION=1.26.3
}

# nginx stub: "nginx -v" reports NGINX_VERSION, "nginx -t" prints $STUB_OUT_nginx and exits with $STUB_EXIT_nginx.
# shellcheck disable=SC2329 # called by the functions under test
nginx() {
	printf 'nginx %s\n' "$*" >>"${STUB_LOG}"
	if [[ $1 == -t ]]; then
		[[ -z ${STUB_OUT_nginx:-} ]] || printf '%s\n' "${STUB_OUT_nginx}" >&2
		return "${STUB_EXIT_nginx:-0}"
	fi
	printf 'nginx version: nginx/%s\n' "${NGINX_VERSION}" >&2
	return
}

# shellcheck disable=SC2329 # called by the functions under test
hostname() {
	printf 'web.example.com\n'
	return
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

# Replaces openssl for one test (the coverage image has none): "req" writes the -keyout and -out files and exits
# with $STUB_EXIT_openssl_req, "x509 -checkend" exits with $STUB_EXIT_openssl_checkend, "-ocsp_uri" prints
# $STUB_OCSP_URI, "-ext subjectAltName" prints the names in $STUB_SAN and "passwd" a SHA-512 crypt hash.
fake_openssl() {
	# shellcheck disable=SC2329 # called by the functions under test
	openssl() {
		local arg previous=''
		printf 'openssl %s\n' "$*" >>"${STUB_LOG}"
		case $1 in
		req)
			for arg in "$@"; do
				case ${previous} in
				-keyout | -out) printf 'PEM %s\n' "${previous}" >"${arg}" ;;
				*) ;;
				esac
				previous=${arg}
			done
			return "${STUB_EXIT_openssl_req:-0}"
			;;
		passwd) printf '$6$salt$hash\n' ;;
		*)
			case " $* " in
			*' -checkend '*) return "${STUB_EXIT_openssl_checkend:-0}" ;;
			*' -ocsp_uri '*) printf '%s\n' "${STUB_OCSP_URI:-}" ;;
			*' subjectAltName '*) printf 'X509v3 Subject Alternative Name: \n    %s\n' "${STUB_SAN:-}" ;;
			*) ;;
			esac
			;;
		esac
		return 0
	}
	return
}

# Lets the writing functions run without root: file_write writes as the test user and records "== MODE OWNER DEST"
# in $WRITES, install drops -o and -g (and is recorded in the stub log), and the web server configuration lives
# below the test directory.
as_test_user() {
	eval "_lss_file_write() $(declare -f file_write | tail -n +2)"
	# shellcheck disable=SC2329 # called by the functions under test
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${WRITES}"
		_lss_file_write "$1" "${OWNER}" "$3"
		return
	}
	# shellcheck disable=SC2329 # called by the functions under test
	install() {
		local -a args=()
		printf 'install %s\n' "$*" >>"${STUB_LOG}"
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
	# shellcheck disable=SC2329 # called by the functions under test
	web_conf_dir() {
		printf '%s/conf/%s' "${BATS_TEST_TMPDIR}" "$1"
		return
	}
	return
}

# The logs of the web servers below the test directory as well.
test_log_dir() {
	# shellcheck disable=SC2329 # called by the functions under test
	web_log_dir() {
		printf '%s/log/%s' "${BATS_TEST_TMPDIR}" "$1"
		return
	}
	return
}

use_server() {
	state_set "$1" status installed
	return
}

# A deploy hook that only records the lineage it was called for.
cert_hook() {
	mkdir -p "$(dirname "${WEB_CERT_HOOK}")"
	cat >"${WEB_CERT_HOOK}" <<'EOF'
#!/usr/bin/env bash
printf 'hook %s\n' "${RENEWED_LINEAGE}" >>"${STUB_LOG}"
EOF
	chmod +x "${WEB_CERT_HOOK}"
	return
}

# --- servers, users and paths -----------------------------------------------------------------------------------

@test "the installed web server is found, and nothing when none is installed" {
	[ -z "$(web_server)" ]
	use_server caddy
	[ "$(web_server)" = caddy ]
	use_server apache
	[ "$(web_server)" = apache ]
	use_server nginx
	[ "$(web_server)" = nginx ]
}

@test "units, users, configuration and log directories follow the Debian family" {
	use_os debian-12
	[ "$(web_unit nginx)" = nginx ]
	[ "$(web_unit apache)" = apache2 ]
	[ "$(web_unit caddy)" = caddy ]
	[ "$(web_user nginx)" = www-data ]
	[ "$(web_user apache)" = www-data ]
	[ "$(web_user caddy)" = caddy ]
	[ "$(web_conf_dir nginx)" = /etc/nginx/lss ]
	[ "$(web_conf_dir apache)" = /etc/apache2/lss ]
	[ "$(web_conf_dir caddy)" = /etc/caddy/lss ]
	[ "$(web_log_dir nginx)" = /var/log/nginx ]
	[ "$(web_log_dir apache)" = /var/log/apache2 ]
	[ "$(web_log_dir caddy)" = /var/log/caddy ]
	[ "$(web_log_file nginx error)" = /var/log/nginx/error.log ]
	[ "$(web_log_file apache access)" = /var/log/apache2/access.log ]
	[ "$(web_log_file caddy access)" = /var/log/caddy/access.log ]
}

@test "units, users, configuration and log directories follow the RHEL family" {
	use_os rocky-9
	[ "$(web_unit nginx)" = nginx ]
	[ "$(web_unit apache)" = httpd ]
	[ "$(web_unit caddy)" = caddy ]
	[ "$(web_user nginx)" = nginx ]
	[ "$(web_user apache)" = apache ]
	[ "$(web_user caddy)" = caddy ]
	[ "$(web_conf_dir nginx)" = /etc/nginx/lss ]
	[ "$(web_conf_dir apache)" = /etc/httpd/lss ]
	[ "$(web_conf_dir caddy)" = /etc/caddy/lss ]
	[ "$(web_log_dir apache)" = /var/log/httpd ]
	[ "$(web_log_file apache access)" = /var/log/httpd/access_log ]
	[ "$(web_log_file apache error)" = /var/log/httpd/error_log ]
	[ "$(web_log_file nginx access)" = /var/log/nginx/access.log ]
}

@test "the web group is created once and gets every existing web server user" {
	export STUB_GETENT='passwd:www-data'
	# shellcheck disable=SC2329 # called by web_group_ensure
	id() {
		printf '%s\n' "${TEST_GROUPS}"
		return
	}
	TEST_GROUPS=www-data
	web_group_ensure www-data ghost
	grep -qxF "groupadd --system ${WEB_GROUP}" "${STUB_LOG}"
	grep -qxF "usermod --append --groups ${WEB_GROUP} www-data" "${STUB_LOG}"
	run ! grep -q 'usermod.*ghost' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 2 ]
	: >"${STUB_LOG}"
	export STUB_GETENT="group:${WEB_GROUP} passwd:www-data"
	TEST_GROUPS="www-data ${WEB_GROUP}"
	web_group_ensure www-data
	run ! grep -qE '^(groupadd|usermod)' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 2 ]
}

# --- certificates -----------------------------------------------------------------------------------------------

@test "a site points at its placeholder, a copy of the default certificate, until its own one arrives" {
	as_test_user
	printf 'default chain\n' >"${WEB_TLS_DIR}/default/fullchain.pem"
	printf 'default key\n' >"${WEB_TLS_DIR}/default/privkey.pem"
	[ "$(web_cert_dir shop)" = "${WEB_TLS_DIR}/default" ]
	web_cert_placeholder shop
	[ "$(web_cert_dir shop)" = "${WEB_TLS_DIR}/shop" ]
	cmp "${WEB_TLS_DIR}/default/fullchain.pem" "${WEB_TLS_DIR}/shop/fullchain.pem"
	cmp "${WEB_TLS_DIR}/default/privkey.pem" "${WEB_TLS_DIR}/shop/privkey.pem"
	grep -qxF "install -m 0640 -o root -g ${WEB_GROUP} ${WEB_TLS_DIR}/default/privkey.pem ${WEB_TLS_DIR}/shop/privkey.pem" "${STUB_LOG}"
	[ "$(files_changes_of core)" = 1 ]
	# The real certificate is never replaced by the placeholder again.
	printf 'real chain\n' >"${WEB_TLS_DIR}/shop/fullchain.pem"
	web_cert_placeholder shop
	grep -qxF 'real chain' "${WEB_TLS_DIR}/shop/fullchain.pem"
	[ "$(files_changes_of core)" = 1 ]
}

@test "the default certificate is self-signed for the host name with a key for the web group" {
	as_test_user
	fake_openssl
	web_default_cert
	grep -q '^openssl req -x509 .*-subj /CN=web.example.com -addext subjectAltName=DNS:web.example.com ' "${STUB_LOG}"
	[ -s "${WEB_TLS_DIR}/default/fullchain.pem" ]
	[ -s "${WEB_TLS_DIR}/default/privkey.pem" ]
	grep -q "^install -m 0640 -o root -g ${WEB_GROUP} .*/privkey.pem ${WEB_TLS_DIR}/default/privkey.pem$" "${STUB_LOG}"
	grep -q "^install -m 0644 -o root -g root .*/fullchain.pem ${WEB_TLS_DIR}/default/fullchain.pem$" "${STUB_LOG}"
	[ "$(files_changes_of core)" = 1 ]
}

@test "a valid default certificate is kept, one that expires within 30 days is renewed" {
	as_test_user
	fake_openssl
	printf 'chain\n' >"${WEB_TLS_DIR}/default/fullchain.pem"
	printf 'key\n' >"${WEB_TLS_DIR}/default/privkey.pem"
	web_default_cert
	grep -q "^openssl x509 -checkend $((30 * 86400)) " "${STUB_LOG}"
	run ! grep -q '^openssl req' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 0 ]
	export STUB_EXIT_openssl_checkend=1
	web_default_cert
	grep -q '^openssl req' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 1 ]
}

@test "the default certificate of the tls module is left to certbot" {
	fake_openssl
	mkdir -p "${WEB_CERT_LIVE}/default"
	printf 'issued\n' >"${WEB_CERT_LIVE}/default/fullchain.pem"
	printf 'issued\n' >"${WEB_TLS_DIR}/default/fullchain.pem"
	web_default_cert
	[ ! -s "${STUB_LOG}" ]
}

@test "a failed self-signed certificate stops the run" {
	fake_openssl
	export STUB_EXIT_openssl_req=1
	run web_default_cert
	[ "${status}" -eq 1 ]
	[[ ${output} == *'web: could not create the self-signed default certificate.'* ]]
}

@test "the names of a certificate are read from its subjectAltName" {
	fake_openssl
	export STUB_SAN='DNS:www.shop.example.com, DNS:shop.example.com, DNS:shop.example.com'
	[ "$(web_cert_domains "${WEB_TLS_DIR}/shop/fullchain.pem")" = $'shop.example.com\nwww.shop.example.com' ]
}

@test "a certificate is requested once for its names and through the private CA when there is one" {
	fake_openssl
	cert_hook
	printf 'ca\n' >"${WEB_ACME_CA}"
	web_cert_issue shop shop.example.com www.shop.example.com
	grep -qxF "certbot REQUESTS_CA_BUNDLE=${WEB_ACME_CA} certonly --cert-name shop -d shop.example.com -d www.shop.example.com" "${STUB_LOG}"
	grep -qxF "hook ${WEB_CERT_LIVE}/shop" "${STUB_LOG}"
	[ "$(files_changes_of core)" = 2 ]
	# What certbot and the deploy hook leave behind.
	mkdir -p "${WEB_CERT_LIVE}/shop" "${WEB_TLS_DIR}/shop"
	printf 'chain 1\n' >"${WEB_CERT_LIVE}/shop/fullchain.pem"
	cp "${WEB_CERT_LIVE}/shop/fullchain.pem" "${WEB_TLS_DIR}/shop/fullchain.pem"
	export STUB_SAN='DNS:shop.example.com, DNS:www.shop.example.com'
	: >"${STUB_LOG}"
	web_cert_issue shop www.shop.example.com shop.example.com
	run ! grep -qE '^(certbot|hook)' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 2 ]
	# New names: a new request, without the CA bundle once the CA is gone; the copy is current, so no hook.
	rm "${WEB_ACME_CA}"
	web_cert_issue shop shop.example.com api.example.com
	grep -qxF 'certbot certonly --cert-name shop -d shop.example.com -d api.example.com' "${STUB_LOG}"
	run ! grep -q '^hook' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 3 ]
}

@test "a renewed certificate that differs from the installed copy goes through the deploy hook" {
	fake_openssl
	cert_hook
	mkdir -p "${WEB_CERT_LIVE}/shop" "${WEB_TLS_DIR}/shop"
	printf 'chain 2\n' >"${WEB_CERT_LIVE}/shop/fullchain.pem"
	printf 'chain 1\n' >"${WEB_TLS_DIR}/shop/fullchain.pem"
	export STUB_SAN='DNS:shop.example.com'
	web_cert_issue shop shop.example.com
	run ! grep -q '^certbot' "${STUB_LOG}"
	grep -qxF "hook ${WEB_CERT_LIVE}/shop" "${STUB_LOG}"
	[ "$(files_changes_of core)" = 1 ]
}

@test "a certificate the ACME server refuses stops the run" {
	export STUB_EXIT_certbot=1
	run web_cert_issue shop shop.example.com
	[ "${status}" -eq 1 ]
	[[ ${output} == *'tls: the ACME server refused a certificate for shop.example.com;'* ]]
}

# --- preparation, test and reload -------------------------------------------------------------------------------

@test "preparing a web server puts its user in the web group and creates the default certificate and directories" {
	as_test_user
	fake_openssl
	use_os rocky-9
	export STUB_GETENT='passwd:nginx'
	web_prepare nginx
	grep -qxF "groupadd --system ${WEB_GROUP}" "${STUB_LOG}"
	grep -qxF "usermod --append --groups ${WEB_GROUP} nginx" "${STUB_LOG}"
	[ -s "${WEB_TLS_DIR}/default/fullchain.pem" ]
	[ -d "${WEB_ACME_ROOT}/.well-known/acme-challenge" ]
	[ -d "${WEB_DEFAULT_ROOT}" ]
	[ -d "${BATS_TEST_TMPDIR}/conf/nginx/sites" ]
	[ -d "${BATS_TEST_TMPDIR}/conf/nginx/admin" ]
	use_os debian-12
	export STUB_GETENT="group:${WEB_GROUP} passwd:www-data"
	web_prepare apache
	grep -qxF "usermod --append --groups ${WEB_GROUP} www-data" "${STUB_LOG}"
	[ -d "${BATS_TEST_TMPDIR}/conf/apache/sites" ]
	[ "$(grep -c '^openssl req' "${STUB_LOG}")" = 1 ]
}

@test "each web server checks its configuration with its own tool" {
	web_test nginx
	grep -qxF 'nginx -t -q' "${STUB_LOG}"
	web_test apache
	grep -qxF 'apachectl -t' "${STUB_LOG}"
	web_test caddy
	grep -qxF 'caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile' "${STUB_LOG}"
}

@test "a configuration that does not load fails the test and shows the problem" {
	export STUB_EXIT_apachectl=1 STUB_OUT_apachectl='AH00526: Syntax error on line 3'
	run web_test apache
	[ "${status}" -eq 1 ]
	[[ ${output} == *'AH00526: Syntax error on line 3'* ]]
	export STUB_EXIT_nginx=1 STUB_OUT_nginx='unknown directive "lss"'
	run web_test nginx
	[ "${status}" -eq 1 ]
	[[ ${output} == *'unknown directive "lss"'* ]]
}

@test "reload tests the configuration and reloads only a running web server" {
	web_reload
	[ ! -s "${STUB_LOG}" ]
	use_server nginx
	export STUB_ACTIVE_UNITS=nginx
	web_reload
	grep -qxF 'nginx -t -q' "${STUB_LOG}"
	grep -qxF 'systemctl reload-or-restart nginx' "${STUB_LOG}"
	state_forget nginx
	use_os rocky-9
	use_server apache
	: >"${STUB_LOG}"
	web_reload
	grep -qxF 'apachectl -t' "${STUB_LOG}"
	grep -qxF 'systemctl is-active --quiet httpd' "${STUB_LOG}"
	run ! grep -q reload-or-restart "${STUB_LOG}"
}

@test "a configuration that does not load is not reloaded" {
	use_server caddy
	export STUB_ACTIVE_UNITS=caddy STUB_EXIT_caddy=1
	run web_reload
	[ "${status}" -eq 1 ]
	[[ ${output} == *'web: the caddy configuration does not load; see above.'* ]]
	run ! grep -q reload-or-restart "${STUB_LOG}"
}

@test "every web server sends the same six security headers in its own syntax" {
	run web_headers nginx
	[ "${#lines[@]}" -eq 6 ]
	[ "${lines[0]}" = $'\tadd_header Strict-Transport-Security "max-age=63072000" always;' ]
	[ "${lines[5]}" = $'\tadd_header Cross-Origin-Opener-Policy "same-origin" always;' ]
	run web_headers apache
	[ "${#lines[@]}" -eq 6 ]
	[ "${lines[1]}" = $'\tHeader always set X-Content-Type-Options "nosniff"' ]
	run web_headers caddy
	[ "${#lines[@]}" -eq 6 ]
	[ "${lines[2]}" = $'\t\tX-Frame-Options "SAMEORIGIN"' ]
	[[ ${output} == *'Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"'* ]]
}

# --- sites ------------------------------------------------------------------------------------------------------

@test "nginx 1.25.1 and later get the http2 directive, older versions the listen flag" {
	NGINX_VERSION=1.26.3
	web_nginx_http2_directive
	[ "$(web_nginx_ssl_flags)" = ssl ]
	NGINX_VERSION=1.25.1
	web_nginx_http2_directive
	NGINX_VERSION=1.22.1
	run ! web_nginx_http2_directive
	[ "$(web_nginx_ssl_flags)" = 'ssl http2' ]
	NGINX_VERSION=unknown
	run ! web_nginx_http2_directive
}

@test "an nginx PHP site redirects port 80, keeps ACME challenges there and passes PHP to the lss pool" {
	run _web_site_nginx shop php /var/www/shop shop.example.com www.shop.example.com
	[ "${status}" -eq 0 ]
	[[ ${output} == *'server_name shop.example.com www.shop.example.com;'* ]]
	[[ ${output} == *'return 301 https://$host$request_uri;'* ]]
	[[ ${output} == *"root ${WEB_ACME_ROOT};"* ]]
	[[ ${output} == *"include /etc/nginx/lss/listen-http.conf;"* ]]
	[[ ${output} == *"include /etc/nginx/lss/listen-https.conf;"* ]]
	[[ ${output} != *listen\ * ]]
	[[ ${output} == *"fastcgi_pass unix:${WEB_PHP_SOCKET};"* ]]
	# PATH_INFO after the script name (/static.php/skins/...), as Roundcube and Nextcloud use it.
	[[ ${output} == *'location ~ [^/]\.php(/|$) {'* ]]
	[[ ${output} == *'fastcgi_param PATH_INFO $fastcgi_path_info;'* ]]
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

@test "certificates with an OCSP responder get stapling on nginx and Apache" {
	fake_openssl
	export STUB_OCSP_URI=http://ocsp.example.com
	run _web_tls_nginx "${WEB_TLS_DIR}/default"
	[[ ${output} == *$'\tssl_stapling on;\n\tssl_stapling_verify on;'* ]]
	run _web_site_apache blog static /var/www/blog blog.example.com
	[[ ${output} == *$'\tSSLUseStapling on'* ]]
}

@test "nginx listens on every address on 80 and 443, or on 127.0.0.1 on the backend ports behind Traefik" {
	# shellcheck disable=SC2329 # called by the functions under test
	web_ipv6() { return 0; }
	run web_nginx_listen http
	[ "${output}" = $'\tlisten 80;\n\tlisten [::]:80;' ]
	run web_nginx_listen https default_server
	[ "${output}" = $'\tlisten 443 default_server ssl;\n\tlisten [::]:443 default_server ssl;' ]
	NGINX_VERSION=1.22.1
	run web_nginx_listen https
	[ "${output}" = $'\tlisten 443 ssl http2;\n\tlisten [::]:443 ssl http2;' ]
	use_server traefik
	run web_nginx_listen http default_server
	[ "${output}" = $'\tlisten 127.0.0.1:8008 default_server;' ]
	run web_nginx_listen https
	[ "${output}" = $'\tlisten 127.0.0.1:8443 ssl http2;' ]
	# While the traefik module hands the ports back, LSS_WEB_BACKEND wins over its state.
	LSS_WEB_BACKEND=off
	run web_nginx_listen http
	[ "${output}" = $'\tlisten 80;\n\tlisten [::]:80;' ]
}

@test "the backend mode follows Traefik's state unless LSS_WEB_BACKEND says otherwise" {
	run ! web_backend
	[ "$(web_http_port)" = 80 ]
	[ "$(web_https_port)" = 443 ]
	LSS_WEB_BACKEND=on
	web_backend
	[ "$(web_http_port)" = 8008 ]
	[ "$(web_https_port)" = 8443 ]
	unset LSS_WEB_BACKEND
	use_server traefik
	web_backend
	LSS_WEB_BACKEND=off
	run ! web_backend
	[ "$(web_https_port)" = 443 ]
}

@test "Traefik gets the same security headers as entries of its headers middleware" {
	run web_headers traefik
	[ "${#lines[@]}" -eq 6 ]
	[ "${lines[0]}" = '          Strict-Transport-Security: "max-age=63072000"' ]
	[ "${lines[1]}" = '          X-Content-Type-Options: "nosniff"' ]
}

@test "nginx sites are written once per change for static files and proxies, with the shared listeners" {
	as_test_user
	use_server nginx
	local conf=${BATS_TEST_TMPDIR}/conf/nginx/sites
	web_site_write blog static /var/www/blog blog.example.com
	[ "${LSS_FILE_CHANGED}" = 1 ]
	grep -qxF "== 0644 root:root ${conf}/blog.conf" "${WRITES}"
	grep -qxF '# Managed by lss (site blog).' "${conf}/blog.conf"
	grep -qxF $'\tinclude '"${BATS_TEST_TMPDIR}"'/conf/nginx/listen-http.conf;' "${conf}/blog.conf"
	grep -qxF $'\tinclude '"${BATS_TEST_TMPDIR}"'/conf/nginx/listen-https.conf;' "${conf}/blog.conf"
	grep -qxF $'\troot /var/www/blog;' "${conf}/blog.conf"
	grep -qxF $'\tindex index.html;' "${conf}/blog.conf"
	grep -qxF $'\t\ttry_files $uri $uri/ =404;' "${conf}/blog.conf"
	grep -qxF $'\taccess_log /var/log/nginx/access.log;' "${conf}/blog.conf"
	web_site_write blog static /var/www/blog blog.example.com
	[ "${LSS_FILE_CHANGED}" = 0 ]
	web_site_write app proxy http://127.0.0.1:3000 app.example.com
	[ "${LSS_FILE_CHANGED}" = 1 ]
	run ! grep -qE 'listen|http2' "${conf}/app.conf"
	grep -qxF $'\t\tproxy_pass http://127.0.0.1:3000;' "${conf}/app.conf"
	grep -qxF $'\t\tinclude /etc/nginx/lss/proxy.conf;' "${conf}/app.conf"
	[ "$(files_changes_of core)" = 2 ]
}

@test "Apache sites serve static files and PHP and log where the OS family expects it" {
	as_test_user
	use_os rocky-9
	use_server apache
	local conf=${BATS_TEST_TMPDIR}/conf/apache/sites
	web_site_write blog static /var/www/blog blog.example.com
	grep -qxF "== 0644 root:root ${conf}/blog.conf" "${WRITES}"
	grep -qxF $'\tServerName blog.example.com' "${conf}/blog.conf"
	run ! grep -q ServerAlias "${conf}/blog.conf"
	grep -qxF $'\tDocumentRoot /var/www/blog' "${conf}/blog.conf"
	grep -qxF $'\t\tOptions -Indexes +FollowSymLinks' "${conf}/blog.conf"
	grep -qxF $'\tErrorLog /var/log/httpd/error_log' "${conf}/blog.conf"
	# lss_combined logs the client address that mod_remoteip takes from Traefik's X-Forwarded-For.
	grep -qxF $'\tCustomLog /var/log/httpd/access_log lss_combined' "${conf}/blog.conf"
	# The ports come from the Define lines of the global configuration, so the backend mode leaves the sites alone.
	grep -qxF '<VirtualHost *:${LSS_HTTP_PORT}>' "${conf}/blog.conf"
	grep -qxF '<VirtualHost *:${LSS_HTTPS_PORT}>' "${conf}/blog.conf"
	grep -qxF $'\tSSLCertificateFile '"${WEB_TLS_DIR}/default/fullchain.pem" "${conf}/blog.conf"
	run ! grep -q SetHandler "${conf}/blog.conf"
	web_site_write shop php /var/www/shop shop.example.com www.shop.example.com
	[ "${LSS_FILE_CHANGED}" = 1 ]
	grep -qxF $'\tServerAlias www.shop.example.com' "${conf}/shop.conf"
	grep -qxF $'\tDirectoryIndex index.php index.html' "${conf}/shop.conf"
	grep -qxF $'\t\tSetHandler "proxy:unix:'"${WEB_PHP_SOCKET}"'|fcgi://localhost"' "${conf}/shop.conf"
	[ "$(grep -c '^<VirtualHost' "${conf}/shop.conf")" = 2 ]
	web_site_write shop php /var/www/shop shop.example.com www.shop.example.com
	[ "${LSS_FILE_CHANGED}" = 0 ]
	use_os debian-12
	web_site_write app proxy http://127.0.0.1:3000/ app.example.com
	grep -qxF $'\tProxyPass / http://127.0.0.1:3000/ upgrade=websocket' "${conf}/app.conf"
	grep -qxF $'\tErrorLog /var/log/apache2/error.log' "${conf}/app.conf"
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
	# lss_bind keeps both listeners on 127.0.0.1 behind Traefik.
	[ "$(grep -c $'^\timport lss_bind$' <<<"${output}")" = 2 ]
}

@test "Caddy sites serve static files, PHP and proxies for every name" {
	as_test_user
	use_server caddy
	local conf=${BATS_TEST_TMPDIR}/conf/caddy/sites
	web_site_write shop php /var/www/shop shop.example.com www.shop.example.com
	grep -qxF "== 0644 root:root ${conf}/shop.caddy" "${WRITES}"
	grep -qxF 'http://shop.example.com http://www.shop.example.com {' "${conf}/shop.caddy"
	grep -qxF 'https://shop.example.com https://www.shop.example.com {' "${conf}/shop.caddy"
	grep -qxF $'\t\troot * '"${WEB_ACME_ROOT}" "${conf}/shop.caddy"
	grep -qxF $'\tphp_fastcgi unix/'"${WEB_PHP_SOCKET}" "${conf}/shop.caddy"
	web_site_write shop php /var/www/shop shop.example.com www.shop.example.com
	[ "${LSS_FILE_CHANGED}" = 0 ]
	web_site_write blog static /var/www/blog blog.example.com
	grep -qxF $'\troot * /var/www/blog' "${conf}/blog.caddy"
	run ! grep -q php_fastcgi "${conf}/blog.caddy"
	web_site_write app proxy http://127.0.0.1:3000 app.example.com
	grep -qxF $'\treverse_proxy http://127.0.0.1:3000' "${conf}/app.caddy"
	[ "$(files_changes_of core)" = 3 ]
}

@test "proxies switch on httpd_can_network_connect once under an enforcing SELinux" {
	as_test_user
	use_server nginx
	export STUB_OUT_getenforce=Enforcing STUB_OUT_getsebool='httpd_can_network_connect --> off'
	web_site_write app proxy http://127.0.0.1:3000 app.example.com
	grep -qxF 'setsebool -P httpd_can_network_connect 1' "${STUB_LOG}"
	: >"${STUB_LOG}"
	export STUB_OUT_getsebool='httpd_can_network_connect --> on'
	web_admin_write pgadmin pgadmin proxy http://127.0.0.1:5050
	grep -q '^getsebool' "${STUB_LOG}"
	run ! grep -q setsebool "${STUB_LOG}"
	: >"${STUB_LOG}"
	export STUB_OUT_getenforce=Permissive
	web_site_write other proxy http://127.0.0.1:3001 other.example.com
	run ! grep -q getsebool "${STUB_LOG}"
	web_site_write blog static /var/www/blog blog.example.com
	run ! grep -q getsebool "${STUB_LOG}"
}

@test "site names that could leave the configuration directory are refused" {
	run _web_name_check '../etc'
	[ "${status}" -ne 0 ]
	run _web_name_check 'shop-2'
	[ "${status}" -eq 0 ]
}

@test "a site needs a valid name and an installed web server" {
	as_test_user
	run web_site_write ../etc static /var/www/blog blog.example.com
	[ "${status}" -eq 1 ]
	[[ ${output} == *"web: '../etc' is not a valid site name."* ]]
	run web_site_write blog static /var/www/blog blog.example.com
	[ "${status}" -eq 1 ]
	[[ ${output} == *'web: no web server is installed (nginx, apache or caddy).'* ]]
	[ ! -e "${WRITES}" ]
}

@test "removing a site deletes the file of the installed web server and nothing without one" {
	as_test_user
	web_site_remove blog
	[ "$(files_changes_of core)" = 0 ]
	use_server caddy
	web_site_write blog static /var/www/blog blog.example.com
	[ -f "${BATS_TEST_TMPDIR}/conf/caddy/sites/blog.caddy" ]
	web_site_remove blog
	[ ! -e "${BATS_TEST_TMPDIR}/conf/caddy/sites/blog.caddy" ]
	[ "$(files_changes_of core)" = 2 ]
	web_site_remove blog
	[ "$(files_changes_of core)" = 2 ]
}

# --- admin paths ------------------------------------------------------------------------------------------------

@test "the admin port is the same for every web server and stays on localhost in the private setup" {
	run _web_admin_nginx pma phpmyadmin php /usr/share/phpmyadmin
	[[ ${output} == *'location ^~ /phpmyadmin/'* ]]
	run _web_admin_caddy pma phpmyadmin php /usr/share/phpmyadmin
	[[ ${output} == *'handle_path /phpmyadmin/*'* ]]
}

@test "nginx admin paths alias PHP directories and proxy upstreams with their script name" {
	as_test_user
	use_server nginx
	local conf=${BATS_TEST_TMPDIR}/conf/nginx/admin
	web_admin_write phpmyadmin phpmyadmin php /usr/share/phpmyadmin
	grep -qxF "== 0644 root:root ${conf}/phpmyadmin.conf" "${WRITES}"
	grep -qxF '# Managed by lss (admin path of phpmyadmin).' "${conf}/phpmyadmin.conf"
	grep -qxF 'location = /phpmyadmin {' "${conf}/phpmyadmin.conf"
	grep -qxF $'\treturn 301 /phpmyadmin/;' "${conf}/phpmyadmin.conf"
	grep -qxF $'\talias /usr/share/phpmyadmin/;' "${conf}/phpmyadmin.conf"
	grep -qxF $'\t\tfastcgi_pass unix:'"${WEB_PHP_SOCKET};" "${conf}/phpmyadmin.conf"
	web_admin_write phpmyadmin phpmyadmin php /usr/share/phpmyadmin
	[ "${LSS_FILE_CHANGED}" = 0 ]
	web_admin_write pgadmin pgadmin proxy http://127.0.0.1:5050
	[ "${LSS_FILE_CHANGED}" = 1 ]
	grep -qxF 'location ^~ /pgadmin/ {' "${conf}/pgadmin.conf"
	grep -qxF $'\tproxy_pass http://127.0.0.1:5050;' "${conf}/pgadmin.conf"
	grep -qxF $'\tproxy_set_header X-Script-Name /pgadmin;' "${conf}/pgadmin.conf"
}

@test "Apache admin paths alias PHP directories and proxy upstreams with their script name" {
	as_test_user
	use_os rocky-9
	use_server apache
	local conf=${BATS_TEST_TMPDIR}/conf/apache/admin
	web_admin_write adminer adminer php /usr/share/adminer
	grep -qxF "== 0644 root:root ${conf}/adminer.conf" "${WRITES}"
	grep -qxF 'Alias /adminer /usr/share/adminer' "${conf}/adminer.conf"
	grep -qxF '<Directory /usr/share/adminer>' "${conf}/adminer.conf"
	grep -qxF $'\tAllowOverride None' "${conf}/adminer.conf"
	grep -qxF $'\t\tSetHandler "proxy:unix:'"${WEB_PHP_SOCKET}"'|fcgi://localhost"' "${conf}/adminer.conf"
	web_admin_write pgadmin pgadmin proxy http://127.0.0.1:5050/
	grep -qxF '<Location /pgadmin/>' "${conf}/pgadmin.conf"
	grep -qxF $'\tProxyPass http://127.0.0.1:5050/pgadmin/ upgrade=websocket' "${conf}/pgadmin.conf"
	grep -qxF $'\tProxyPassReverse http://127.0.0.1:5050/pgadmin/' "${conf}/pgadmin.conf"
	grep -qxF $'\tRequestHeader set X-Script-Name /pgadmin' "${conf}/pgadmin.conf"
	web_admin_write pgadmin pgadmin proxy http://127.0.0.1:5050/
	[ "${LSS_FILE_CHANGED}" = 0 ]
}

@test "Caddy admin paths strip the prefix for PHP and pass the script name to proxies" {
	as_test_user
	use_server caddy
	local conf=${BATS_TEST_TMPDIR}/conf/caddy/admin
	web_admin_write adminer adminer php /usr/share/adminer
	grep -qxF "== 0644 root:root ${conf}/adminer.caddy" "${WRITES}"
	grep -qxF 'redir /adminer /adminer/' "${conf}/adminer.caddy"
	grep -qxF 'handle_path /adminer/* {' "${conf}/adminer.caddy"
	grep -qxF $'\troot * /usr/share/adminer' "${conf}/adminer.caddy"
	grep -qxF $'\tphp_fastcgi unix/'"${WEB_PHP_SOCKET}" "${conf}/adminer.caddy"
	web_admin_write pgadmin pgadmin proxy http://127.0.0.1:5050
	grep -qxF 'handle /pgadmin/* {' "${conf}/pgadmin.caddy"
	grep -qxF $'\treverse_proxy http://127.0.0.1:5050 {' "${conf}/pgadmin.caddy"
	grep -qxF $'\t\theader_up X-Script-Name /pgadmin' "${conf}/pgadmin.caddy"
	web_admin_write pgadmin pgadmin proxy http://127.0.0.1:5050
	[ "${LSS_FILE_CHANGED}" = 0 ]
	web_admin_remove pgadmin
	[ ! -e "${conf}/pgadmin.caddy" ]
	[ -f "${conf}/adminer.caddy" ]
}

@test "strip admin paths hand the upstream its root, on every web server" {
	as_test_user
	use_server nginx
	web_admin_write netdata netdata strip http://127.0.0.1:19999
	local conf=${BATS_TEST_TMPDIR}/conf
	grep -qxF 'location = /netdata {' "${conf}/nginx/admin/netdata.conf"
	grep -qxF $'\treturn 301 /netdata/;' "${conf}/nginx/admin/netdata.conf"
	grep -qxF $'\tproxy_pass http://127.0.0.1:19999/;' "${conf}/nginx/admin/netdata.conf"
	state_set nginx status removed
	use_server apache
	web_admin_write netdata netdata strip http://127.0.0.1:19999/
	grep -qxF 'RedirectMatch 301 ^/netdata$ /netdata/' "${conf}/apache/admin/netdata.conf"
	grep -qxF $'\tProxyPass http://127.0.0.1:19999/ upgrade=websocket' "${conf}/apache/admin/netdata.conf"
	grep -qxF $'\tProxyPassReverse http://127.0.0.1:19999/' "${conf}/apache/admin/netdata.conf"
	state_set apache status removed
	use_server caddy
	web_admin_write netdata netdata strip http://127.0.0.1:19999
	grep -qxF 'redir /netdata /netdata/' "${conf}/caddy/admin/netdata.caddy"
	grep -qxF 'handle_path /netdata/* {' "${conf}/caddy/admin/netdata.caddy"
	grep -qxF $'\treverse_proxy http://127.0.0.1:19999' "${conf}/caddy/admin/netdata.caddy"
}

@test "admin paths need a valid name, a plain path and an installed web server" {
	as_test_user
	run web_admin_write pgadmin ../pgadmin proxy http://127.0.0.1:5050
	[ "${status}" -eq 1 ]
	[[ ${output} == *"web: '../pgadmin' is not a valid admin path."* ]]
	run web_admin_write 'pg admin' pgadmin proxy http://127.0.0.1:5050
	[ "${status}" -eq 1 ]
	[[ ${output} == *"web: 'pg admin' is not a valid site name."* ]]
	run web_admin_write pgadmin pgadmin proxy http://127.0.0.1:5050
	[ "${status}" -eq 1 ]
	[[ ${output} == *'web: no web server is installed (nginx, apache or caddy).'* ]]
	web_admin_remove pgadmin
	[ ! -e "${WRITES}" ]
}

@test "the admin password is hashed once with SHA-512 crypt for nginx and Apache" {
	as_test_user
	fake_openssl
	web_admin_htpasswd nginx
	grep -qxF "== 0640 root:${WEB_GROUP} ${WEB_ADMIN_HTPASSWD}" "${WRITES}"
	grep -qxF 'admin:$6$salt$hash' "${WEB_ADMIN_HTPASSWD}"
	secret_exists web-admin-password
	web_admin_htpasswd apache
	[ "$(grep -c '^==' "${WRITES}")" = 1 ]
	# A file in another format is replaced.
	printf 'admin:{SHA}old\n' >"${WEB_ADMIN_HTPASSWD}"
	web_admin_htpasswd apache
	[ "$(grep -c '^==' "${WRITES}")" = 2 ]
}

@test "the admin password is hashed once by Caddy in its own format" {
	as_test_user
	export STUB_OUT_caddy='$2a$14$caddyhash'
	web_admin_htpasswd caddy
	grep -qxF "== 0640 root:${WEB_GROUP} ${WEB_ADMIN_CADDY_AUTH}" "${WRITES}"
	grep -qxF 'admin $2a$14$caddyhash' "${WEB_ADMIN_CADDY_AUTH}"
	grep -qxF 'caddy hash-password' "${STUB_LOG}"
	web_admin_htpasswd caddy
	[ "$(grep -c '^caddy' "${STUB_LOG}")" = 1 ]
	rm "${WEB_ADMIN_CADDY_AUTH}"
	export STUB_EXIT_caddy=1
	run web_admin_htpasswd caddy
	[ "${status}" -eq 1 ]
	[[ ${output} == *'web: caddy could not hash the admin password.'* ]]
}

# --- routes of applications -------------------------------------------------------------------------------------

# Records what the Traefik side of a route would do; lib/traefik.sh has its own tests.
stub_traefik_routes() {
	# shellcheck disable=SC2329 # called by the functions under test
	traefik_route_write() {
		printf 'traefik_route_write %s\n' "$*" >>"${STUB_LOG}"
		files_note_change "route-$1.yml"
		return
	}
	# shellcheck disable=SC2329 # called by the functions under test
	traefik_route_remove() {
		printf 'traefik_route_remove %s\n' "$*" >>"${STUB_LOG}"
		return
	}
	return
}

@test "without Traefik a route becomes a proxy site of the web server, written and reloaded once per change" {
	as_test_user
	stub_traefik_routes
	use_server nginx
	LSS_MODULE=gitea
	local site=${BATS_TEST_TMPDIR}/conf/nginx/sites/gitea.conf before
	web_proxy_route gitea 'git.example.com, www.git.example.com' 127.0.0.1:3000
	[ "$(<"${LSS_STATE_DIR}/web-routes/gitea")" = 'gitea git.example.com www.git.example.com http://127.0.0.1:3000' ]
	grep -qxF $'\tserver_name git.example.com www.git.example.com;' "${site}"
	grep -qxF $'\t\tproxy_pass http://127.0.0.1:3000;' "${site}"
	grep -qxF 'traefik_route_remove gitea' "${STUB_LOG}"
	grep -q '^nginx -t' "${STUB_LOG}"
	run ! grep -q traefik_route_write "${STUB_LOG}"
	before=$(files_changes_of gitea)
	: >"${STUB_LOG}"
	web_proxy_route gitea 'git.example.com, www.git.example.com' 127.0.0.1:3000
	[ "$(files_changes_of gitea)" = "${before}" ]
	run ! grep -q '^nginx -t' "${STUB_LOG}"
	[ "$(web_route_names gitea)" = gitea ]
	[ "$(web_route_names)" = gitea ]
	[ -z "$(web_route_names other)" ]
}

@test "with Traefik a route goes to its file provider and comes back to the web server when Traefik leaves" {
	as_test_user
	stub_traefik_routes
	use_server nginx
	use_server traefik
	LSS_MODULE=app
	local site=${BATS_TEST_TMPDIR}/conf/nginx/sites/app.conf
	web_proxy_route app app.example.com http://127.0.0.1:8080/
	grep -qxF 'traefik_route_write app http://127.0.0.1:8080/ app.example.com' "${STUB_LOG}"
	[ ! -e "${site}" ]
	# The traefik module re-applies every route in the name of its owner, with the ports handed back.
	LSS_MODULE=traefik LSS_WEB_BACKEND=off web_routes_apply
	grep -qxF 'traefik_route_remove app' "${STUB_LOG}"
	grep -qxF $'\t\tproxy_pass http://127.0.0.1:8080/;' "${site}"
	[ "$(files_changes_of traefik)" = 0 ]
	web_proxy_route_remove app
	[ ! -e "${site}" ]
	[ ! -e "${LSS_STATE_DIR}/web-routes/app" ]
	[ -z "$(web_route_names)" ]
}

@test "a route needs host names, an upstream with a port and something to serve it" {
	as_test_user
	run web_proxy_route app 'app.example.com localhost' 127.0.0.1:3000
	[ "${status}" -eq 1 ]
	[[ ${output} == *"web: 'localhost' of the route app is not a host name like app.example.com."* ]]
	run web_proxy_route app app.example.com 3000
	[ "${status}" -eq 1 ]
	[[ ${output} == *"web: the upstream '3000' of the route app is not HOST:PORT or an http(s):// URL with a port."* ]]
	run web_proxy_route app app.example.com 'http://127.0.0.1:3000/;return'
	[ "${status}" -eq 1 ]
	run web_proxy_route ../app app.example.com 127.0.0.1:3000
	[ "${status}" -eq 1 ]
	run web_proxy_route app app.example.com 127.0.0.1:3000
	[ "${status}" -eq 1 ]
	[[ ${output} == *'web: the route app needs Traefik or a web server (nginx, apache or caddy).'* ]]
}

# --- fail2ban and CrowdSec --------------------------------------------------------------------------------------

@test "without a web server the jails and the log acquisition are removed" {
	mkdir -p "$(dirname "${WEB_FAIL2BAN_JAIL}")" "$(dirname "${WEB_FAIL2BAN_FILTER}")" "$(dirname "${WEB_CROWDSEC_ACQUIS}")"
	touch "${WEB_FAIL2BAN_JAIL}" "${WEB_FAIL2BAN_FILTER}" "${WEB_CROWDSEC_ACQUIS}"
	web_ids_configure
	[ ! -e "${WEB_FAIL2BAN_JAIL}" ]
	[ ! -e "${WEB_FAIL2BAN_FILTER}" ]
	[ ! -e "${WEB_CROWDSEC_ACQUIS}" ]
	[ "$(files_changes_of core)" = 3 ]
}

@test "nginx gets the fail2ban auth and bot jails, and fail2ban restarts only when they change" {
	as_test_user
	test_log_dir
	use_server nginx
	use_server fail2ban
	export STUB_ACTIVE_UNITS=fail2ban
	local logs=${BATS_TEST_TMPDIR}/log/nginx
	web_ids_configure
	grep -qxF "== 0644 root:root ${WEB_FAIL2BAN_JAIL}" "${WRITES}"
	grep -qxF '[nginx-http-auth]' "${WEB_FAIL2BAN_JAIL}"
	grep -qxF "logpath = ${logs}/error.log" "${WEB_FAIL2BAN_JAIL}"
	grep -qxF '[nginx-botsearch]' "${WEB_FAIL2BAN_JAIL}"
	grep -qxF "logpath = ${logs}/access.log" "${WEB_FAIL2BAN_JAIL}"
	# fail2ban refuses jails whose log files are missing.
	[ -e "${logs}/access.log" ]
	[ -e "${logs}/error.log" ]
	grep -qxF 'fail2ban-client --test' "${STUB_LOG}"
	grep -qxF 'systemctl restart fail2ban' "${STUB_LOG}"
	run ! grep -q cscli "${STUB_LOG}"
	: >"${STUB_LOG}"
	web_ids_configure
	run ! grep -qE 'fail2ban-client|restart' "${STUB_LOG}"
}

@test "Apache on the RHEL family gets its jails while fail2ban itself is being installed" {
	as_test_user
	test_log_dir
	use_os rocky-9
	use_server apache
	LSS_MODULE=fail2ban
	web_ids_configure
	grep -qxF '# Managed by lss (web server apache).' "${WEB_FAIL2BAN_JAIL}"
	grep -qxF '[apache-auth]' "${WEB_FAIL2BAN_JAIL}"
	grep -qxF "logpath = ${BATS_TEST_TMPDIR}/log/apache/error_log" "${WEB_FAIL2BAN_JAIL}"
	grep -qxF '[apache-botsearch]' "${WEB_FAIL2BAN_JAIL}"
	run ! grep -qE 'fail2ban-client|restart' "${STUB_LOG}"
}

@test "nginx writes the jails during its own first install, before its state is recorded" {
	as_test_user
	test_log_dir
	use_server fail2ban
	LSS_MODULE=nginx
	web_ids_configure
	grep -qxF '[nginx-http-auth]' "${WEB_FAIL2BAN_JAIL}"
	grep -qxF '[nginx-botsearch]' "${WEB_FAIL2BAN_JAIL}"
}

@test "Caddy gets its own basic-auth filter and jail" {
	as_test_user
	test_log_dir
	use_server caddy
	use_server fail2ban
	export STUB_ACTIVE_UNITS=fail2ban
	web_ids_configure
	grep -qxF "== 0644 root:root ${WEB_FAIL2BAN_FILTER}" "${WRITES}"
	grep -qF '"status":401' "${WEB_FAIL2BAN_FILTER}"
	# client_ip is the client behind Traefik as well (remote_ip would be Traefik itself).
	grep -qF '"client_ip":"<HOST>"' "${WEB_FAIL2BAN_FILTER}"
	grep -qxF '[lss-caddy-auth]' "${WEB_FAIL2BAN_JAIL}"
	grep -qxF 'filter = lss-caddy-auth' "${WEB_FAIL2BAN_JAIL}"
	grep -qxF "logpath = ${BATS_TEST_TMPDIR}/log/caddy/access.log" "${WEB_FAIL2BAN_JAIL}"
	grep -qxF 'systemctl restart fail2ban' "${STUB_LOG}"
	# Only the filter changed: fail2ban still restarts.
	printf '# changed\n' >>"${WEB_FAIL2BAN_FILTER}"
	: >"${STUB_LOG}"
	web_ids_configure
	grep -qxF 'systemctl restart fail2ban' "${STUB_LOG}"
}

@test "jails that do not load stop the run before fail2ban restarts" {
	as_test_user
	test_log_dir
	use_server nginx
	use_server fail2ban
	export STUB_ACTIVE_UNITS=fail2ban STUB_EXIT_fail2ban_client=1
	run web_ids_configure
	[ "${status}" -eq 1 ]
	[[ ${output} == *'web: the fail2ban jails for nginx do not load.'* ]]
	run ! grep -q 'systemctl restart' "${STUB_LOG}"
}

@test "CrowdSec gets the collection and the logs of nginx and restarts only on a change" {
	as_test_user
	test_log_dir
	use_server nginx
	use_server crowdsec
	export STUB_ACTIVE_UNITS=crowdsec
	local logs=${BATS_TEST_TMPDIR}/log/nginx
	web_ids_configure
	grep -qxF 'cscli collections install crowdsecurity/nginx' "${STUB_LOG}"
	grep -qxF "== 0644 root:root ${WEB_CROWDSEC_ACQUIS}" "${WRITES}"
	grep -qxF "  - ${logs}/access.log" "${WEB_CROWDSEC_ACQUIS}"
	grep -qxF "  - ${logs}/error.log" "${WEB_CROWDSEC_ACQUIS}"
	grep -qxF '  type: nginx' "${WEB_CROWDSEC_ACQUIS}"
	grep -qxF 'systemctl restart crowdsec' "${STUB_LOG}"
	run ! grep -q fail2ban "${STUB_LOG}"
	: >"${STUB_LOG}"
	export STUB_OUT_cscli='crowdsecurity/nginx,enabled,1.0'
	web_ids_configure
	run ! grep -qE 'collections install|restart' "${STUB_LOG}"
}

@test "CrowdSec reads the Apache logs of the OS family and only the access log of Caddy" {
	as_test_user
	test_log_dir
	use_os rocky-9
	use_server apache
	LSS_MODULE=crowdsec
	web_ids_configure
	grep -qxF 'cscli collections install crowdsecurity/apache2' "${STUB_LOG}"
	grep -qxF "  - ${BATS_TEST_TMPDIR}/log/apache/error_log" "${WEB_CROWDSEC_ACQUIS}"
	grep -qxF '  type: apache2' "${WEB_CROWDSEC_ACQUIS}"
	run ! grep -q restart "${STUB_LOG}"
	state_forget apache
	use_server caddy
	web_ids_configure
	grep -qxF 'cscli collections install crowdsecurity/caddy' "${STUB_LOG}"
	grep -qxF "  - ${BATS_TEST_TMPDIR}/log/caddy/access.log" "${WEB_CROWDSEC_ACQUIS}"
	[ "$(grep -c '^  - ' "${WEB_CROWDSEC_ACQUIS}")" = 1 ]
	grep -qxF '  type: caddy' "${WEB_CROWDSEC_ACQUIS}"
}

@test "a CrowdSec collection that cannot be installed stops the run" {
	as_test_user
	test_log_dir
	use_server caddy
	use_server crowdsec
	export STUB_EXIT_cscli=1
	run web_ids_configure
	[ "${status}" -eq 1 ]
	[[ ${output} == *'web: CrowdSec could not install crowdsecurity/caddy.'* ]]
}

@test "removing the web server drops its jails and acquisition and restarts what runs" {
	web_ids_remove
	[ ! -s "${STUB_LOG}" ]
	mkdir -p "$(dirname "${WEB_FAIL2BAN_JAIL}")" "$(dirname "${WEB_FAIL2BAN_FILTER}")" "$(dirname "${WEB_CROWDSEC_ACQUIS}")"
	touch "${WEB_FAIL2BAN_JAIL}" "${WEB_FAIL2BAN_FILTER}" "${WEB_CROWDSEC_ACQUIS}"
	export STUB_ACTIVE_UNITS='fail2ban crowdsec'
	web_ids_remove
	[ ! -e "${WEB_FAIL2BAN_JAIL}" ]
	[ ! -e "${WEB_FAIL2BAN_FILTER}" ]
	[ ! -e "${WEB_CROWDSEC_ACQUIS}" ]
	grep -qxF 'systemctl restart fail2ban' "${STUB_LOG}"
	grep -qxF 'systemctl restart crowdsec' "${STUB_LOG}"
	touch "${WEB_FAIL2BAN_JAIL}" "${WEB_CROWDSEC_ACQUIS}"
	export STUB_ACTIVE_UNITS=''
	: >"${STUB_LOG}"
	web_ids_remove
	[ ! -e "${WEB_FAIL2BAN_JAIL}" ]
	run ! grep -q restart "${STUB_LOG}"
}

@test "the names of a certificate come back sorted, one per line" {
	new_cert "${WEB_TLS_DIR}/shop" 90 www.shop.example.com shop.example.com
	[ "$(web_cert_domains "${WEB_TLS_DIR}/shop/fullchain.pem")" = $'shop.example.com\nwww.shop.example.com' ]
}

@test "the nginx module builds against the patched sources of the installed Debian package" {
	# shellcheck source=modules/web/modsecurity.sh
	source "${REPO_ROOT}/modules/web/modsecurity.sh"
	local tree=${BATS_TEST_TMPDIR}/nginx-1.28.3 available=1.28.3-2ubuntu1.11 installed=''
	MODSEC_NGINX_DEV_SRC=${BATS_TEST_TMPDIR}/nginx-dev
	mkdir -p "${tree}/src/http" "${MODSEC_NGINX_DEV_SRC}/src/http"
	echo upstream >"${tree}/src/http/ngx_http_request.h"
	echo patched >"${MODSEC_NGINX_DEV_SRC}/src/http/ngx_http_request.h"
	# shellcheck disable=SC2329 # called by the functions under test
	_modsecurity_nginx_package() {
		printf 'nginx 1.28.3-2ubuntu1.11'
	}
	# shellcheck disable=SC2329
	pkg_update_once() {
		return 0
	}
	# shellcheck disable=SC2329
	apt-cache() {
		[[ $2 == "nginx-dev=${available}" ]]
	}
	# shellcheck disable=SC2329
	pkg_is_installed() {
		[[ -n ${installed} ]]
	}
	# shellcheck disable=SC2329
	pkg_install() {
		printf 'pkg_install %s
' "$*" >>"${STUB_LOG}"
	}
	_modsecurity_nginx_headers "${tree}"
	[ "$(<"${tree}/src/http/ngx_http_request.h")" = patched ]
	grep -qxF 'pkg_install nginx-dev=1.28.3-2ubuntu1.11' "${STUB_LOG}"
	[ "${MODSEC_BUILD_DEPS[*]}" = nginx-dev ]
	# An nginx-dev installed before stays; a release without nginx-dev of that version keeps the nginx.org sources.
	MODSEC_BUILD_DEPS=()
	installed=1
	_modsecurity_nginx_headers "${tree}"
	[ "${#MODSEC_BUILD_DEPS[@]}" -eq 0 ]
	echo upstream >"${tree}/src/http/ngx_http_request.h"
	available=1.28.3-2ubuntu1.12
	: >"${STUB_LOG}"
	_modsecurity_nginx_headers "${tree}"
	[ "$(<"${tree}/src/http/ngx_http_request.h")" = upstream ]
	run ! grep -q pkg_install "${STUB_LOG}"
	rm -r "${MODSEC_NGINX_DEV_SRC}/src"
	available=1.28.3-2ubuntu1.11
	run _modsecurity_nginx_headers "${tree}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"nginx-dev 1.28.3-2ubuntu1.11 has no nginx sources in ${MODSEC_NGINX_DEV_SRC}."* ]]
}
