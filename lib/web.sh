# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Web layer shared by the web server modules (nginx, apache, caddy) and everything that publishes something through
# them (tls, vhost, php, phpmyadmin, adminer, pgadmin, apps). One web server owns ports 80 and 443; the others
# conflict with it.
#
# Conventions:
#   WEB_GROUP        group of every web server user; PHP-FPM's socket and the TLS keys are readable by it
#   WEB_PHP_SOCKET   the PHP-FPM pool of the php module listens here (owner root, group WEB_GROUP, mode 0660)
#   WEB_TLS_DIR      one directory per certificate (NAME/fullchain.pem, NAME/privkey.pem); "default" is a
#                    self-signed certificate for the host name that every web server creates
#   WEB_ACME_ROOT    webroot for ACME http-01 challenges, served on port 80 for every host name
#   WEB_ADMIN_PORT   admin interfaces (phpMyAdmin, Adminer, pgAdmin) live on this port, on 127.0.0.1 by default

WEB_GROUP=lss-web
WEB_PHP_SOCKET=/run/lss-php-fpm.sock
WEB_TLS_DIR=/etc/lss/tls
WEB_ACME_ROOT=/var/lib/lss/acme
WEB_DEFAULT_ROOT=/var/www/lss-default
WEB_ADMIN_PORT=8090

# The installed web server (nginx, apache or caddy), or nothing.
web_server() {
	local server
	for server in nginx apache caddy; do
		if state_installed "${server}"; then
			printf '%s' "${server}"
			return 0
		fi
	done
	return 0
}

# web_group_ensure [USER...]: creates WEB_GROUP and adds the users to it.
web_group_ensure() {
	local user
	if ! getent group "${WEB_GROUP}" >/dev/null; then
		groupadd --system "${WEB_GROUP}"
		files_note_change "created group ${WEB_GROUP}"
	fi
	for user in "$@"; do
		getent passwd "${user}" >/dev/null || continue
		if ! id -nG "${user}" | tr ' ' '\n' | grep -qxF "${WEB_GROUP}"; then
			usermod --append --groups "${WEB_GROUP}" "${user}"
			files_note_change "added ${user} to ${WEB_GROUP}"
		fi
	done
	return
}
