# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="webmail"
MOD_GROUP="mail"
MOD_DESCRIPTION="Roundcube 1.7.4 for the mailboxes of the mailserver module, as an HTTPS site of the web server (login with the mailbox address and password)"
MOD_REQUIRES="mailserver nginx|apache|caddy php"
MOD_OPTIONS="domains||Host names of the webmail site, separated by spaces; empty: the host name of the mail server (LSS_MAILSERVER_HOSTNAME)
product_name|Webmail|Name on the login page
session_lifetime|30|Minutes without activity before Roundcube asks for the password again"
MOD_SECRETS="webmail-des-key"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# A new version is a new entry roundcube-<version> in data/checksums.txt and a new RC_VERSION; the next install
# replaces the whole tree and updates the database schema.
RC_VERSION=1.7.4
RC_DIR=/usr/share/lss/roundcube
RC_CONFIG=${RC_DIR}/config/config.inc.php
# Below /var/lib/php, which the sandbox of PHP-FPM may write and which carries the SELinux label PHP may write to.
RC_DATA=/var/lib/php/lss-roundcube
RC_DB=${RC_DATA}/roundcube.db
RC_SITE=webmail

mod_check() {
	local domain minutes
	for domain in $(opt domains); do
		[[ ${domain} =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]] ||
			die "LSS_WEBMAIL_DOMAINS: '${domain}' is not a host name like mail.example.com."
	done
	[[ $(opt product_name) =~ ^[A-Za-z0-9\ ._-]{1,40}$ ]] ||
		die "LSS_WEBMAIL_PRODUCT_NAME may contain letters, digits, spaces, '.', '_' and '-' (up to 40)."
	minutes=$(opt_int session_lifetime)
	((minutes >= 5 && minutes <= 1440)) || die "LSS_WEBMAIL_SESSION_LIFETIME must be between 5 and 1440 minutes."
	fetch_entry "roundcube-${RC_VERSION}" >/dev/null ||
		die "webmail: data/checksums.txt has no checksum for Roundcube ${RC_VERSION}."
	return
}

# _rc_php: the PHP command line of the php module.
_rc_php() {
	local version
	version=$(state_get php php_version)
	if os_is_debian; then printf '/usr/bin/php%s' "${version}"; else printf '/usr/bin/php'; fi
	return
}

# The release archive from GitHub, checked against data/checksums.txt, unpacked next to the old tree and swapped in.
# The installer is left out; lss writes the configuration itself.
mod_install() {
	local tmp version
	version=$(state_get php php_version)
	# SQLite for the settings and contacts of the users (PDO SQLite comes with php-pdo on the RHEL family).
	pkg_install_family "curl tar php${version}-sqlite3" "curl tar php-pdo"
	[[ ! -f ${RC_DIR}/.lss-version-${RC_VERSION} ]] || return 0
	install -d -m 0755 "$(dirname "${RC_DIR}")"
	tmp=$(mktemp -d "$(dirname "${RC_DIR}")/.roundcube.XXXXXX")
	fetch_verified "roundcube-${RC_VERSION}" "${tmp}/roundcube.tar.gz"
	install -d -m 0755 "${tmp}/tree"
	tar -xzf "${tmp}/roundcube.tar.gz" -C "${tmp}/tree" --strip-components=1 --no-same-owner --no-same-permissions ||
		die "webmail: the archive of Roundcube ${RC_VERSION} does not unpack."
	grep -qF "define('RCMAIL_VERSION', '${RC_VERSION}')" "${tmp}/tree/program/include/iniset.php" ||
		die "webmail: the archive does not contain Roundcube ${RC_VERSION}."
	rm -rf -- "${tmp}/tree/installer" "${tmp}/tree/public_html/installer.php" "${tmp}/tree/temp" "${tmp}/tree/logs"
	touch "${tmp}/tree/.lss-version-${RC_VERSION}"
	chown -R root:root "${tmp}/tree"
	chmod -R u=rwX,go=rX "${tmp}/tree"
	# The configuration of the old tree is written again by mod_configure.
	rm -rf -- "${RC_DIR}.old"
	if [[ -d ${RC_DIR} ]]; then
		mv -- "${RC_DIR}" "${RC_DIR}.old"
	fi
	mv -- "${tmp}/tree" "${RC_DIR}"
	rm -rf -- "${RC_DIR}.old" "${tmp}"
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -R "${RC_DIR}" 2>/dev/null || true
	fi
	files_note_change "installed Roundcube ${RC_VERSION}"
	return
}

# _rc_domains: the host names of the site.
_rc_domains() {
	local domains
	domains=$(opt domains)
	[[ -n ${domains} ]] || domains=$(state_get mailserver hostname)
	[[ -n ${domains} ]] || die "webmail: the mailserver module has no host name yet; run lss install mailserver."
	printf '%s' "${domains}"
	return
}

# _rc_config GROUP: config.inc.php. Roundcube talks to Dovecot and Postfix on 127.0.0.1, where they accept a
# password without TLS because the connection does not leave the server.
_rc_config() {
	local key domain
	secret_load webmail-des-key key 32
	domain=$(state_get mailserver domain)
	cat <<EOF
<?php
// Managed by lss (module webmail). Change LSS_WEBMAIL_* in /etc/lss/lss.conf and run lss configure webmail.
\$config = [];
\$config['db_dsnw'] = 'sqlite:///${RC_DB}?mode=0600';
\$config['imap_host'] = '127.0.0.1:143';
\$config['smtp_host'] = '127.0.0.1:10587';
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['username_domain'] = '${domain}';
\$config['des_key'] = '${key}';
\$config['cipher_method'] = 'AES-256-CBC';
\$config['product_name'] = '$(opt product_name)';
\$config['useragent'] = 'Webmail';
\$config['support_url'] = '';
\$config['skin'] = 'elastic';
\$config['plugins'] = ['archive'];
\$config['temp_dir'] = '${RC_DATA}/temp/';
\$config['log_driver'] = 'syslog';
\$config['syslog_id'] = 'roundcube';
\$config['enable_installer'] = false;
// Sessions: HTTPS only, tied to the address of the client, cookies not sent to other sites.
\$config['use_https'] = true;
\$config['ip_check'] = true;
\$config['session_lifetime'] = $(opt_int session_lifetime);
\$config['session_samesite'] = 'Strict';
\$config['login_rate_limit'] = 3;
\$config['x_frame_options'] = 'sameorigin';
// Users send only as their own address (Postfix refuses others anyway) and cannot see the server's PHP settings.
\$config['identities_level'] = 3;
\$config['enable_spellcheck'] = false;
EOF
	return
}

# _rc_run COMMAND...: a Roundcube command line tool as the user of the PHP-FPM pool, which owns the database.
_rc_run() {
	local user
	user=$(web_php_pool_user)
	runuser -u "${user:-lss-php}" -- "$(_rc_php)" "$@"
	return
}

# _rc_database USER GROUP: creates the SQLite database or brings its schema to the installed version.
_rc_database() {
	local user=$1 group=$2
	install -d -m 0700 -o "${user}" -g "${group}" "${RC_DATA}" "${RC_DATA}/temp"
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -R "${RC_DATA}" 2>/dev/null || true
	fi
	if [[ ! -s ${RC_DB} ]]; then
		log_command _rc_run "${RC_DIR}/bin/initdb.sh" --dir="${RC_DIR}/SQL" || die "webmail: Roundcube could not create its database."
		files_note_change "created the Roundcube database"
	elif [[ $(state_get webmail schema) != "${RC_VERSION}" ]]; then
		log_command _rc_run "${RC_DIR}/bin/updatedb.sh" --package=roundcube --dir="${RC_DIR}/SQL" ||
			die "webmail: Roundcube could not update its database to ${RC_VERSION}."
		files_note_change "updated the Roundcube database"
	fi
	state_set webmail schema "${RC_VERSION}"
	return
}

mod_configure() {
	local user group config unit
	local -a domains=()
	user=$(web_php_pool_user)
	user=${user:-lss-php}
	group=$(web_php_pool_group)
	config=$(_rc_config)
	# Read by PHP-FPM only: the key encrypts the IMAP password in the session.
	file_write 0640 "root:${group}" "${RC_CONFIG}" <<<"${config}"
	_rc_database "${user}" "${group}"
	read -ra domains <<<"$(_rc_domains)"
	web_cert_placeholder "${RC_SITE}"
	web_site_write "${RC_SITE}" php "${RC_DIR}/public_html" "${domains[@]}"
	# PHP connects to IMAP and SMTP on 127.0.0.1; under SELinux that needs the network boolean of the web servers.
	web_selinux_proxy
	if [[ $(files_changes_of webmail) != 0 ]]; then
		web_reload
		# OPcache may not look at file times; a reload makes PHP-FPM read the new tree and load PDO SQLite.
		while IFS= read -r unit; do
			if [[ -n ${unit} ]] && svc_is_active "${unit}"; then
				svc_reload "${unit}" || die "webmail: ${unit} does not reload."
			fi
		done < <(web_php_fpm_units)
	fi
	if state_installed tls; then
		web_cert_issue "${RC_SITE}" "${domains[@]}"
	fi
	return
}

# _rc_get DOMAIN PATH: a page of the site as this server serves it, followed by a line with the HTTP status.
_rc_get() {
	local domain=$1 path=$2
	curl -ks --max-time 30 -w '\n%{http_code}' --resolve "${domain}:443:127.0.0.1" "https://${domain}/${path}"
	return
}

mod_verify() {
	local domain page status asset try schema
	local -a domains=()
	[[ -f ${RC_DIR}/.lss-version-${RC_VERSION} ]] || die "webmail: Roundcube ${RC_VERSION} is missing in ${RC_DIR}."
	[[ ! -e ${RC_DIR}/installer && ! -e ${RC_DIR}/public_html/installer.php ]] ||
		die "webmail: the Roundcube installer must not exist."
	[[ $(stat -c '%a %U' "${RC_CONFIG}") == '640 root' ]] || die "webmail: ${RC_CONFIG} must be mode 640, owned by root."
	schema=$(_rc_run -r "echo (new PDO('sqlite:${RC_DB}'))->query(\"SELECT value FROM system WHERE name = 'roundcube-version'\")->fetchColumn();" 2>/dev/null) ||
		true
	[[ -n ${schema} ]] || die "webmail: the Roundcube database ${RC_DB} has no schema."
	read -ra domains <<<"$(_rc_domains)"
	domain=${domains[0]}
	# Right after a reload the old workers of the web server answer for a moment without the site.
	for ((try = 0; try < 15; try++)); do
		page=$(_rc_get "${domain}" '') || true
		status=${page##*$'\n'}
		[[ ${status} != 200 ]] || break
		sleep 1
	done
	[[ ${status} == 200 ]] || die "webmail: https://${domain}/ answers ${status:-nothing} instead of the login page."
	grep -qF 'name="_user"' <<<"${page}" || die "webmail: https://${domain}/ shows no login form."
	if grep -qE '<b>(Deprecated|Warning|Notice|Fatal error)</b>:|^(Deprecated|Warning|Fatal error): ' <<<"${page}"; then
		die "webmail: the login page shows PHP errors; display_errors must be off."
	fi
	# Styles and scripts come through static.php/... (PATH_INFO), which the web server must pass to PHP.
	asset=$(grep -oE 'static\.php/[^"?]+\.css' <<<"${page}" | head -n 1) || true
	[[ -n ${asset} ]] || die "webmail: the login page links no style sheet."
	page=$(_rc_get "${domain}" "${asset}") || true
	[[ ${page##*$'\n'} == 200 ]] || die "webmail: https://${domain}/${asset} answers ${page##*$'\n'} instead of the style sheet."
	return
}

mod_remove() {
	web_site_remove "${RC_SITE}"
	web_reload
	file_remove "${WEB_TLS_DIR}/${RC_SITE}"
	if [[ -d /etc/letsencrypt/live/${RC_SITE} ]] && command -v certbot >/dev/null 2>&1; then
		log_command certbot delete --non-interactive --cert-name "${RC_SITE}" || log_warn "webmail: certbot could not delete the certificate ${RC_SITE}."
	fi
	file_remove "${RC_CONFIG}"
	if [[ -d ${RC_DIR} ]]; then
		rm -rf -- "${RC_DIR}"
		files_note_change "removed ${RC_DIR}"
	fi
	rmdir "$(dirname "${RC_DIR}")" 2>/dev/null || true
	# The database holds the settings, contacts and identities of the users; it stays unless --purge.
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		rm -rf -- "${RC_DATA}"
		secret_remove webmail-des-key
		files_note_change "deleted the Roundcube database"
	fi
	return
}
