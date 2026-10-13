# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="phpmyadmin"
MOD_GROUP="database"
MOD_DESCRIPTION="phpMyAdmin 5.2.3 for the local MariaDB or MySQL server, on the admin port (127.0.0.1:8090/phpmyadmin/), login with the database users"
MOD_REQUIRES="system nginx|apache|caddy php mariadb|mysql"
MOD_OPTIONS="port|3306|Port of the MariaDB or MySQL server on 127.0.0.1 (the only server phpMyAdmin connects to)
allow_root|false|Allow logins as the database user root (root should use the socket on the server instead)
login_timeout|1440|Seconds without activity before phpMyAdmin asks for the password again"
MOD_SECRETS="phpmyadmin-blowfish"

# A new version is a new entry phpmyadmin-<version> in data/checksums.txt and a new PMA_VERSION; the next install
# replaces the whole tree, so no file of the old version stays behind.
PMA_VERSION=5.2.3
PMA_DIR=/usr/share/lss/phpmyadmin
PMA_CONFIG=${PMA_DIR}/config.inc.php
PMA_PATH=phpmyadmin
# Template cache and uploads. PHP-FPM creates the directory itself (mode 0770, owned by the pool user) inside its
# private /tmp, which no other account can see; see _phpmyadmin_private_tmp.
PMA_TEMP=/tmp/lss-phpmyadmin

mod_check() {
	local port timeout
	port=$(opt_int port)
	((port >= 1 && port <= 65535)) || die "LSS_PHPMYADMIN_PORT must be a port number (1-65535)."
	opt_bool allow_root || true
	timeout=$(opt_int login_timeout)
	((timeout >= 60)) || die "LSS_PHPMYADMIN_LOGIN_TIMEOUT must be at least 60 seconds."
	fetch_entry "phpmyadmin-${PMA_VERSION}" >/dev/null ||
		die "phpmyadmin: data/checksums.txt has no checksum for phpMyAdmin ${PMA_VERSION}."
	return
}

# The release archive from files.phpmyadmin.net, checked against the published SHA-256, unpacked next to the old tree
# and swapped in with a rename. The setup wizard (it writes configurations through the browser) and the examples are
# left out; lss writes config.inc.php itself.
mod_install() {
	local tmp
	pkg_install_family "curl tar xz-utils" "curl tar xz"
	[[ ! -f ${PMA_DIR}/RELEASE-DATE-${PMA_VERSION} ]] || return 0
	install -d -m 0755 "$(dirname "${PMA_DIR}")"
	tmp=$(mktemp -d "$(dirname "${PMA_DIR}")/.phpmyadmin.XXXXXX")
	fetch_verified "phpmyadmin-${PMA_VERSION}" "${tmp}/phpmyadmin.tar.xz"
	install -d -m 0755 "${tmp}/tree"
	tar -xJf "${tmp}/phpmyadmin.tar.xz" -C "${tmp}/tree" --strip-components=1 --no-same-owner --no-same-permissions ||
		die "phpmyadmin: the archive of phpMyAdmin ${PMA_VERSION} does not unpack."
	[[ -f ${tmp}/tree/RELEASE-DATE-${PMA_VERSION} ]] || die "phpmyadmin: the archive does not contain phpMyAdmin ${PMA_VERSION}."
	rm -rf -- "${tmp}/tree/setup" "${tmp}/tree/examples" "${tmp}/tree/config.sample.inc.php"
	chown -R root:root "${tmp}/tree"
	chmod -R u=rwX,go=rX "${tmp}/tree"
	rm -rf -- "${PMA_DIR}.old"
	if [[ -d ${PMA_DIR} ]]; then
		mv -- "${PMA_DIR}" "${PMA_DIR}.old"
	fi
	mv -- "${tmp}/tree" "${PMA_DIR}"
	rm -rf -- "${PMA_DIR}.old" "${tmp}"
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -R "${PMA_DIR}" 2>/dev/null || true
	fi
	files_note_change "installed phpMyAdmin ${PMA_VERSION}"
	return
}

mod_configure() {
	local secret group port timeout allow_root=false unit
	_phpmyadmin_private_tmp
	secret_load phpmyadmin-blowfish secret 32
	group=$(_phpmyadmin_fpm_group)
	port=$(opt_int port)
	timeout=$(opt_int login_timeout)
	opt_bool allow_root && allow_root=true
	# Read by PHP-FPM only: the blowfish secret encrypts the database password in the login cookie.
	file_write 0640 "root:${group}" "${PMA_CONFIG}" <<EOF
<?php
// Managed by lss (module phpmyadmin). Change LSS_PHPMYADMIN_* in /etc/lss/lss.conf and run lss configure phpmyadmin.
declare(strict_types=1);

\$cfg['blowfish_secret'] = '${secret}';

// One server: the local MariaDB or MySQL over TCP. Users log in with their database account (cookie login).
\$i = 1;
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['host'] = '127.0.0.1';
\$cfg['Servers'][\$i]['port'] = '${port}';
\$cfg['Servers'][\$i]['connect_type'] = 'tcp';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['AllowRoot'] = ${allow_root};
\$cfg['AllowArbitraryServer'] = false;

\$cfg['LoginCookieValidity'] = ${timeout};
\$cfg['LoginCookieStore'] = 0;
\$cfg['LoginCookieDeleteAll'] = true;

\$cfg['TempDir'] = '${PMA_TEMP}';
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';

// No calls home, no error reports to phpmyadmin.net, no automatic configuration storage in the user's databases.
\$cfg['VersionCheck'] = false;
\$cfg['SendErrorReports'] = 'never';
\$cfg['ZeroConf'] = false;
\$cfg['ShowPhpInfo'] = false;
EOF
	web_admin_write phpmyadmin "${PMA_PATH}" php "${PMA_DIR}"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		web_reload
	fi
	_phpmyadmin_selinux_db
	# PHP's opcode cache may not look at file times (a common production setting); a reload makes PHP-FPM read the
	# new tree and configuration.
	if [[ $(files_changes_of phpmyadmin) != 0 ]]; then
		while IFS= read -r unit; do
			if [[ -n ${unit} ]] && svc_is_active "${unit}"; then
				svc_reload "${unit}" || die "phpmyadmin: ${unit} does not reload."
			fi
		done < <(_phpmyadmin_fpm_units)
	fi
	return
}

# The PHP-FPM units of the php module (php8.x-fpm on Debian and Ubuntu, php-fpm on the RHEL family).
_phpmyadmin_fpm_units() {
	systemctl list-units --type=service --all --no-legend --plain '*php*fpm*' 2>/dev/null | awk '{ print $1 }'
	return
}

# phpMyAdmin compiles its templates into PHP files below TempDir and includes them. Inside the private /tmp of the
# PHP-FPM service (svc_sandbox sets PrivateTmp) nobody else can plant such a file; a shared /tmp is refused.
_phpmyadmin_private_tmp() {
	local unit found=0
	while IFS= read -r unit; do
		[[ -n ${unit} ]] || continue
		found=1
		case $(systemctl show -p PrivateTmp --value "${unit}" 2>/dev/null) in
		yes | disconnected) ;;
		*) die "phpmyadmin: ${unit} shares /tmp with other services; phpMyAdmin needs the private /tmp of the php module's sandbox (lss install php)." ;;
		esac
	done < <(_phpmyadmin_fpm_units)
	if [[ ${found} == 0 ]]; then
		log_warn "phpmyadmin: no PHP-FPM service found; phpMyAdmin needs the php module."
	fi
	return
}

# _phpmyadmin_fpm_group: the group of the PHP-FPM pool on WEB_PHP_SOCKET, which has to read config.inc.php; WEB_GROUP
# when the pool configuration does not name one.
_phpmyadmin_fpm_group() {
	local file pool_user='' pool_group=''
	for file in /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf; do
		[[ -f ${file} ]] || continue
		grep -qE "^[[:space:]]*listen[[:space:]]*=[[:space:]]*${WEB_PHP_SOCKET}[[:space:]]*\$" "${file}" || continue
		pool_user=$(sed -nE 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*([A-Za-z0-9_.-]+).*/\1/p' "${file}" | head -n 1)
		pool_group=$(sed -nE 's/^[[:space:]]*group[[:space:]]*=[[:space:]]*([A-Za-z0-9_.-]+).*/\1/p' "${file}" | head -n 1)
		break
	done
	if [[ -z ${pool_group} && -n ${pool_user} ]]; then
		pool_group=$(id -gn "${pool_user}" 2>/dev/null || true)
	fi
	if [[ -z ${pool_group} ]] || ! getent group "${pool_group}" >/dev/null; then
		pool_group=${WEB_GROUP}
	fi
	printf '%s' "${pool_group}"
	return
}

# With SELinux enforcing, PHP-FPM (httpd_t) may only connect to database ports once httpd_can_network_connect_db is
# on. The boolean stays on after a removal; Adminer and other PHP applications need it as well.
_phpmyadmin_selinux_db() {
	command -v getsebool >/dev/null 2>&1 || return 0
	[[ $(getenforce 2>/dev/null) == Enforcing ]] || return 0
	if [[ $(getsebool httpd_can_network_connect_db 2>/dev/null) != *' on' ]]; then
		setsebool -P httpd_can_network_connect_db 1
		files_note_change "SELinux boolean httpd_can_network_connect_db"
	fi
	return
}

# _phpmyadmin_get PATH: the page PATH on the admin port as the web server serves it, followed by a line with the HTTP
# status. A public admin port speaks HTTPS with the default certificate and asks for the admin password, which curl
# reads from standard input, so it never shows in the process list.
_phpmyadmin_get() {
	local path=$1 password
	if config_bool "$(config_key "$(web_server)" admin_public)"; then
		secret_load web-admin-password password 32
		curl -sk --max-time 30 -K - -w '\n%{http_code}' "https://127.0.0.1:${WEB_ADMIN_PORT}/${path}" \
			<<<"user = \"admin:${password}\""
	else
		curl -s --max-time 30 -w '\n%{http_code}' "http://127.0.0.1:${WEB_ADMIN_PORT}/${path}"
	fi
	return
}

mod_verify() {
	local page status try
	[[ -f ${PMA_DIR}/RELEASE-DATE-${PMA_VERSION} ]] || die "phpmyadmin: phpMyAdmin ${PMA_VERSION} is missing in ${PMA_DIR}."
	[[ ! -e ${PMA_DIR}/setup ]] || die "phpmyadmin: the setup wizard ${PMA_DIR}/setup must not exist."
	[[ $(stat -c '%a %U' "${PMA_CONFIG}") == '640 root' ]] || die "phpmyadmin: ${PMA_CONFIG} must be mode 640, owned by root."
	# Right after a reload the old workers of the web server answer for a moment without the new admin path.
	for ((try = 0; try < 15; try++)); do
		page=$(_phpmyadmin_get "${PMA_PATH}/") || true
		status=${page##*$'\n'}
		[[ ${status} != 200 ]] || break
		sleep 1
	done
	[[ ${status} == 200 ]] ||
		die "phpmyadmin: the admin port answers ${status:-nothing} for /${PMA_PATH}/ instead of the login page."
	grep -qF 'name="pma_username"' <<<"${page}" ||
		die "phpmyadmin: /${PMA_PATH}/ shows no login form; PHP may lack the mysqli extension."
	# PHP 8.4 is newer than the PHP versions phpMyAdmin 5.2 names; a deprecation notice in the page means PHP shows
	# errors to visitors (display_errors, set by the php module).
	if grep -qE '<b>(Deprecated|Warning|Notice|Fatal error)</b>:|^(Deprecated|Warning|Fatal error): ' <<<"${page}"; then
		die "phpmyadmin: the login page shows PHP errors; display_errors must be off."
	fi
	return
}

mod_remove() {
	web_admin_remove phpmyadmin
	web_reload
	file_remove "${PMA_CONFIG}"
	if [[ -d ${PMA_DIR} ]]; then
		rm -rf -- "${PMA_DIR}"
		files_note_change "removed ${PMA_DIR}"
	fi
	rmdir "$(dirname "${PMA_DIR}")" 2>/dev/null || true
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		secret_remove phpmyadmin-blowfish
	fi
	return
}
