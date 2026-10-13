# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="adminer"
MOD_GROUP="database"
MOD_DESCRIPTION="Adminer 6.1.2, one-file database manager for MariaDB, MySQL and PostgreSQL, on the admin port (127.0.0.1:8090/adminer/), local servers only"
MOD_REQUIRES="system nginx|apache|caddy php"
MOD_OPTIONS="servers|mysql:127.0.0.1:3306 pgsql:127.0.0.1:5432|Database servers offered at login as driver:host:port (driver mysql for MariaDB and MySQL, or pgsql), separated by spaces; Adminer refuses every other server"

# A new version is a new entry adminer-<version> in data/checksums.txt and a new ADMINER_VERSION.
ADMINER_VERSION=6.1.2
ADMINER_DIR=/usr/share/lss/adminer
ADMINER_CACHE=/var/cache/lss/adminer
ADMINER_PATH=adminer

mod_check() {
	local entry port count=0
	for entry in $(opt servers); do
		[[ ${entry} =~ ^(mysql|pgsql):[A-Za-z0-9.-]+:([0-9]{1,5})$ ]] ||
			die "LSS_ADMINER_SERVERS: '${entry}' is not driver:host:port (driver mysql or pgsql)."
		port=${BASH_REMATCH[2]}
		((port >= 1 && port <= 65535)) || die "LSS_ADMINER_SERVERS: '${entry}' has no valid port."
		count=$((count + 1))
	done
	((count > 0)) || die "LSS_ADMINER_SERVERS must name at least one database server."
	fetch_entry "adminer-${ADMINER_VERSION}" >/dev/null ||
		die "adminer: data/checksums.txt has no checksum for Adminer ${ADMINER_VERSION}."
	return
}

# The single-file release from GitHub, checked against the SHA-256 GitHub publishes for the asset. The copy in the
# cache saves a download on the next run (fetch_verified keeps a file whose checksum matches).
mod_install() {
	local file
	pkg_install curl
	fetch_verified "adminer-${ADMINER_VERSION}" "${ADMINER_CACHE}/adminer-${ADMINER_VERSION}.php"
	for file in "${ADMINER_CACHE}"/*; do
		if [[ -f ${file} && ${file} != "${ADMINER_CACHE}/adminer-${ADMINER_VERSION}.php" ]]; then
			rm -f -- "${file}"
		fi
	done
	return
}

# _adminer_servers: the PHP array entries of the login plugin, one per server; the key is what the login form shows.
_adminer_servers() {
	local entry driver address
	for entry in $(opt servers); do
		driver=${entry%%:*}
		address=${entry#*:}
		# Adminer calls its MySQL driver "server".
		[[ ${driver} != mysql ]] || driver=server
		printf "\t\t'%s' => array('server' => '%s', 'driver' => '%s'),\n" "${address}" "${address}" "${driver}"
	done
	return
}

mod_configure() {
	# Downloads again only when the cached copy is gone or damaged.
	fetch_verified "adminer-${ADMINER_VERSION}" "${ADMINER_CACHE}/adminer-${ADMINER_VERSION}.php"
	file_write 0644 root:root "${ADMINER_DIR}/index.php" <"${ADMINER_CACHE}/adminer-${ADMINER_VERSION}.php"
	ADMINER_SERVERS=$(_adminer_servers)
	template_install adminer adminer-plugins.php 0644 root:root "${ADMINER_DIR}/adminer-plugins.php"
	web_admin_write adminer "${ADMINER_PATH}" php "${ADMINER_DIR}"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		web_reload
	fi
	_adminer_selinux_db
	return
}

# With SELinux enforcing, PHP-FPM (httpd_t) may only connect to database ports once httpd_can_network_connect_db is
# on. The boolean stays on after a removal; phpMyAdmin and other PHP applications need it as well.
_adminer_selinux_db() {
	command -v getsebool >/dev/null 2>&1 || return 0
	[[ $(getenforce 2>/dev/null) == Enforcing ]] || return 0
	if [[ $(getsebool httpd_can_network_connect_db 2>/dev/null) != *' on' ]]; then
		setsebool -P httpd_can_network_connect_db 1
		files_note_change "SELinux boolean httpd_can_network_connect_db"
	fi
	return
}

# _adminer_get PATH: the page PATH on the admin port as the web server serves it, followed by a line with the HTTP
# status. A public admin port speaks HTTPS with the default certificate and asks for the admin password, which curl
# reads from standard input, so it never shows in the process list.
_adminer_get() {
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
	local page status first try
	[[ $(sha256sum "${ADMINER_DIR}/index.php" | cut -d ' ' -f 1) == "$(fetch_entry "adminer-${ADMINER_VERSION}" | cut -d ' ' -f 1)" ]] ||
		die "adminer: ${ADMINER_DIR}/index.php is not Adminer ${ADMINER_VERSION} as published."
	# Right after a reload the old workers of the web server answer for a moment without the new admin path.
	for ((try = 0; try < 15; try++)); do
		page=$(_adminer_get "${ADMINER_PATH}/") || true
		status=${page##*$'\n'}
		[[ ${status} != 200 ]] || break
		sleep 1
	done
	[[ ${status} == 200 ]] ||
		die "adminer: the admin port answers ${status:-nothing} for /${ADMINER_PATH}/ instead of the login page."
	grep -qF 'auth[username]' <<<"${page}" || die "adminer: /${ADMINER_PATH}/ shows no login form."
	# The server list of the login plugin proves that Adminer loaded adminer-plugins.php.
	first=$(opt servers)
	first=${first%% *}
	grep -qF "${first#*:}" <<<"${page}" || die "adminer: the login form does not offer the configured servers."
	if grep -qE '<b>(Deprecated|Warning|Notice|Fatal error)</b>:|^(Deprecated|Warning|Fatal error): ' <<<"${page}"; then
		die "adminer: the login page shows PHP errors; display_errors must be off."
	fi
	return
}

mod_remove() {
	web_admin_remove adminer
	web_reload
	file_remove "${ADMINER_DIR}/adminer-plugins.php"
	file_remove "${ADMINER_DIR}/index.php"
	rmdir "${ADMINER_DIR}" 2>/dev/null || true
	rmdir "$(dirname "${ADMINER_DIR}")" 2>/dev/null || true
	rm -rf -- "${ADMINER_CACHE}"
	rmdir "$(dirname "${ADMINER_CACHE}")" 2>/dev/null || true
	return
}
