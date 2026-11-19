# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="apache"
MOD_GROUP="web"
MOD_DESCRIPTION="Apache httpd web server: HTTPS only (TLS 1.2 and 1.3), HTTP/2, security headers, admin port on localhost; behind Traefik on 127.0.0.1 only"
MOD_REQUIRES="system"
MOD_CONFLICTS="nginx caddy"
MOD_OPTIONS="max_body|64m|Largest request body (uploads), for example 64m or 1g
admin_public|false|Serve the admin interfaces (phpMyAdmin, Adminer, pgAdmin) on port 8090 to everyone, with TLS and a password (user admin, lss secrets show web-admin-password); otherwise only on 127.0.0.1 (use an SSH tunnel)"
MOD_SECRETS="web-admin-password"

APACHE_MODULES_DEB="ssl headers rewrite proxy proxy_http proxy_fcgi proxy_wstunnel setenvif http2 socache_shmcb auth_basic authn_file remoteip"

_apache_root() {
	if os_is_debian; then printf '/etc/apache2'; else printf '/etc/httpd'; fi
	return
}

# The global configuration: conf-available/zz-lss.conf on Debian (loaded after security.conf, so its settings win),
# conf.d/lss.conf on the RHEL family.
_apache_global_file() {
	if os_is_debian; then printf '/etc/apache2/conf-available/zz-lss.conf'; else printf '/etc/httpd/conf.d/lss.conf'; fi
	return
}

# _apache_bytes SIZE: 64m -> bytes for LimitRequestBody.
_apache_bytes() {
	local size=$1 number unit
	number=${size%[kKmMgG]}
	unit=${size#"${number}"}
	case ${unit,,} in
	k) printf '%s' $((number * 1024)) ;;
	m) printf '%s' $((number * 1024 * 1024)) ;;
	g) printf '%s' $((number * 1024 * 1024 * 1024)) ;;
	*) printf '%s' "${number}" ;;
	esac
	return
}

mod_check() {
	[[ $(opt max_body) =~ ^[0-9]+[kKmMgG]?$ ]] || die "LSS_APACHE_MAX_BODY '$(opt max_body)' is not a size like 64m or 1g."
	opt_bool admin_public || true
	return
}

mod_install() {
	pkg_install_family "apache2 openssl" "httpd mod_ssl mod_http2 openssl"
	return
}

_apache_stapling_cache() {
	if os_is_debian; then
		# shellcheck disable=SC2016 # ${APACHE_RUN_DIR} is expanded by Apache from /etc/apache2/envvars
		printf 'shmcb:${APACHE_RUN_DIR}/ssl_stapling(32768)'
	else
		printf 'shmcb:/run/httpd/ssl_stapling(32768)'
	fi
	return
}

# The listeners: ports 80 and 443 on every address, or the backend ports on 127.0.0.1 behind Traefik. The sites name
# their port through ${LSS_HTTP_PORT} and ${LSS_HTTPS_PORT}, so a switch of the mode leaves them alone. The stock
# Listen lines (ports.conf, httpd.conf, ssl.conf) are switched off.
_apache_listen_conf() {
	local address=''
	web_backend && address=127.0.0.1:
	printf 'Define LSS_HTTP_PORT %s\nDefine LSS_HTTPS_PORT %s\n' "$(web_http_port)" "$(web_https_port)"
	printf 'Listen %s%s\nListen %s%s https\n' "${address}" "$(web_http_port)" "${address}" "$(web_https_port)"
	# %a is the client: behind Traefik mod_remoteip takes it from X-Forwarded-For, which only Traefik on the loopback
	# interface may set; logs, fail2ban and ModSecurity then see the client instead of Traefik.
	# shellcheck disable=SC2016 # Apache format strings
	printf 'LogFormat "%%a %%l %%u %%t \\"%%r\\" %%>s %%b \\"%%{Referer}i\\" \\"%%{User-Agent}i\\"" lss_combined\n'
	if web_backend; then
		printf 'RemoteIPHeader X-Forwarded-For\nRemoteIPInternalProxy 127.0.0.1 ::1\n'
		# Traefik connects to 127.0.0.1 without SNI, so the handshake runs in the default site and Host picks the site
		# afterwards. Apache 2.4.65 and later refuse that switch (421) when the TLS settings of the two sites differ in
		# anything (certificate, stapling); "authonly" compares only client authentication, which lss never uses.
		printf '<IfDirective SSLVHostSNIPolicy>\n\tSSLVHostSNIPolicy authonly\n</IfDirective>\n'
	fi
	return
}

_apache_global_conf() {
	cat <<EOF
# Managed by lss (module apache). Sites: $(web_conf_dir apache)/sites, admin paths: $(web_conf_dir apache)/admin.
$(_apache_listen_conf)
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None
Timeout 60
KeepAliveTimeout 5
LimitRequestBody $(_apache_bytes "$(opt max_body)")
Protocols h2 http/1.1

SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ${WEB_TLS_CIPHERS}
SSLHonorCipherOrder off
SSLSessionTickets off
SSLStaplingCache "$(_apache_stapling_cache)"

<Directory />
	Options None
	AllowOverride None
	Require all denied
</Directory>
<Directory ${WEB_ACME_ROOT}>
	Options None
	AllowOverride None
	Require all granted
</Directory>
<DirectoryMatch "/\\.(?!well-known)">
	Require all denied
</DirectoryMatch>

Include lss/default.conf
Include lss/admin.conf
IncludeOptional lss/sites/*.conf
EOF
	return
}

# The first virtual hosts answer requests for host names without a site: ACME challenges on port 80, nothing else.
_apache_default_conf() {
	cat <<EOF
# Managed by lss (module apache). Requests for host names without a site.
<VirtualHost *:\${LSS_HTTP_PORT}>
	ServerName lss-default.invalid
	DocumentRoot ${WEB_DEFAULT_ROOT}
	Alias /.well-known/acme-challenge/ ${WEB_ACME_ROOT}/.well-known/acme-challenge/
	<Directory ${WEB_DEFAULT_ROOT}>
		Require all denied
	</Directory>
</VirtualHost>

<VirtualHost *:\${LSS_HTTPS_PORT}>
	ServerName lss-default.invalid
	SSLEngine on
	SSLCertificateFile ${WEB_TLS_DIR}/default/fullchain.pem
	SSLCertificateKeyFile ${WEB_TLS_DIR}/default/privkey.pem
	DocumentRoot ${WEB_DEFAULT_ROOT}
	<Directory ${WEB_DEFAULT_ROOT}>
		Require all denied
	</Directory>
</VirtualHost>
EOF
	return
}

_apache_admin_conf() {
	local address="127.0.0.1:${WEB_ADMIN_PORT}"
	opt_bool admin_public && address="*:${WEB_ADMIN_PORT}"
	printf '# Managed by lss (module apache). Admin interfaces on port %s.\n' "${WEB_ADMIN_PORT}"
	if opt_bool admin_public; then
		printf 'Listen %s https\n' "${WEB_ADMIN_PORT}"
	else
		printf 'Listen %s\n' "${address}"
	fi
	printf '<VirtualHost %s>\n\tServerName lss-admin.invalid\n\tDocumentRoot %s\n' "${address}" "${WEB_DEFAULT_ROOT}"
	if opt_bool admin_public; then
		cat <<EOF
	SSLEngine on
	SSLCertificateFile ${WEB_TLS_DIR}/default/fullchain.pem
	SSLCertificateKeyFile ${WEB_TLS_DIR}/default/privkey.pem
	<Location />
		AuthType Basic
		AuthName "lss admin"
		AuthUserFile ${WEB_ADMIN_HTPASSWD}
		Require valid-user
	</Location>
EOF
	fi
	web_headers apache | grep -v Strict-Transport-Security
	printf '\tErrorLog %s\n\tCustomLog %s lss_combined\n' "$(web_log_file apache error)" "$(web_log_file apache access)"
	printf '\tIncludeOptional lss/admin/*.conf\n</VirtualHost>\n'
	return
}

# Debian: modules and the configuration are switched on with a2enmod and a2enconf; the stock site goes away.
_apache_debian_enable() {
	local module
	for module in ${APACHE_MODULES_DEB}; do
		if ! a2query -q -m "${module}" 2>/dev/null; then
			a2enmod -q "${module}" >/dev/null
			files_note_change "apache module ${module}"
		fi
	done
	if ! a2query -q -c zz-lss 2>/dev/null; then
		a2enconf -q zz-lss >/dev/null
		files_note_change "apache configuration zz-lss"
	fi
	if a2query -q -s 000-default 2>/dev/null; then
		a2dissite -q 000-default >/dev/null
		files_note_change "apache site 000-default off"
	fi
	return
}

# RHEL family: mod_ssl's ssl.conf carries a test virtual host and welcome.conf the test page; lss replaces both.
_apache_rhel_files() {
	file_write 0644 root:root /etc/httpd/conf.d/ssl.conf <<'EOF'
# Managed by lss (module apache). The TLS settings, the Listen lines and the virtual hosts are in conf.d/lss.conf
# and lss/.
SSLPassPhraseDialog exec:/usr/libexec/httpd-ssl-pass-dialog
SSLSessionCache shmcb:/run/httpd/sslcache(512000)
SSLSessionCacheTimeout 300
SSLCryptoDevice builtin
EOF
	file_write 0644 root:root /etc/httpd/conf.d/welcome.conf <<<'# Managed by lss (module apache). No test page.'
	# httpd.conf listens on port 80 itself; conf.d/lss.conf has the Listen lines of both modes instead.
	if grep -qx 'Listen 80' /etc/httpd/conf/httpd.conf; then
		sed 's|^Listen 80$|# Listen 80: lss sets the Listen lines in conf.d/lss.conf.|' /etc/httpd/conf/httpd.conf |
			file_write 0644 root:root /etc/httpd/conf/httpd.conf
	fi
	return
}

# Debian: ports.conf carries the stock Listen lines; conf-available/zz-lss.conf has those of both modes instead.
_apache_debian_ports() {
	file_write 0644 root:root /etc/apache2/ports.conf <<<'# Managed by lss (module apache). The Listen lines are in conf-available/zz-lss.conf.'
	return
}

mod_configure() {
	local dir unit before changed=0
	dir=$(web_conf_dir apache)
	unit=$(web_unit apache)
	web_prepare apache
	_apache_global_conf | file_write 0644 root:root "$(_apache_global_file)"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_apache_default_conf | file_write 0644 root:root "${dir}/default.conf"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_apache_admin_conf | file_write 0644 root:root "${dir}/admin.conf"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0644 root:root "${WEB_ACME_ROOT}/.well-known/acme-challenge/lss-probe" <<<"lss"
	before=$(files_changes_of apache)
	if os_is_debian; then
		_apache_debian_ports
		_apache_debian_enable
	else
		_apache_rhel_files
	fi
	[[ $(files_changes_of apache) == "${before}" ]] || changed=1
	if opt_bool admin_public; then
		web_admin_htpasswd apache
		fw_allow "${WEB_ADMIN_PORT}/tcp"
	fi
	fw_allow 80/tcp 443/tcp
	if os_is_debian; then
		svc_sandbox "${unit}.service" ReadWritePaths=-/var/lib/apache2 ReadWritePaths=-/var/cache/apache2
	else
		svc_sandbox "${unit}.service" ReadWritePaths=-/var/lib/httpd ReadWritePaths=-/var/cache/httpd
	fi
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	web_selinux_admin_port
	web_test apache || die "apache: the configuration does not load; see above."
	svc_enable "${unit}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${unit}"
	fi
	web_ids_configure
	traefik_backend_sync apache
	return
}

mod_verify() {
	local http https
	http=$(web_http_port)
	https=$(web_https_port)
	svc_is_active "$(web_unit apache)" || die "apache: the service is not running."
	web_test apache || die "apache: the configuration does not load."
	[[ $(curl -fsS --max-time 10 "http://127.0.0.1:${http}/.well-known/acme-challenge/lss-probe" 2>/dev/null) == lss ]] ||
		die "apache: port ${http} does not serve the ACME challenge path."
	openssl s_client -connect "127.0.0.1:${https}" -servername lss-probe </dev/null 2>/dev/null | grep -q 'BEGIN CERTIFICATE' ||
		die "apache: port ${https} does not answer with TLS."
	curl -s --max-time 10 -o /dev/null "http://127.0.0.1:${WEB_ADMIN_PORT}/" || opt_bool admin_public ||
		die "apache: the admin port ${WEB_ADMIN_PORT} does not answer on 127.0.0.1."
	return
}

mod_remove() {
	local unit
	unit=$(web_unit apache)
	traefik_backend_sync ''
	svc_disable "${unit}"
	svc_dropin_remove "${unit}.service" lss-sandbox
	web_ids_remove
	file_remove "$(web_conf_dir apache)"
	file_remove "$(_apache_global_file)"
	file_remove "${WEB_ACME_ROOT}/.well-known/acme-challenge/lss-probe"
	pkg_remove_family "apache2 apache2-bin apache2-data apache2-utils" "httpd mod_ssl mod_http2"
	return
}
