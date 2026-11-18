# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="wordpress"
MOD_GROUP="apps"
MOD_DESCRIPTION="WordPress 7.1 with MariaDB as a Docker Compose stack behind the reverse proxy, installed with a first administrator; the theme and plugin editor is off"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the WordPress site, separated by spaces; empty: wordpress.<host name of the server>
port|8088|Port of the WordPress container on 127.0.0.1, which the web server forwards to
title|WordPress|Title of the site
admin_user|lssadmin|Name of the first administrator (the password is the secret wordpress-admin-password)
admin_email||E-mail address of the first administrator; empty: ADMIN_USER@<first host name>
memory|768m|Memory limit of the WordPress container"
MOD_SECRETS="wordpress-admin-password wordpress-db-password wordpress-db-root-password"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# WordPress 7.1.3 with PHP 8.4 (apache), the multi-architecture index (amd64 and arm64), checked 2026-10-15.
WP_IMAGE=docker.io/library/wordpress@sha256:309307430abf80009378a63a79df73554a6449b700fac59a991b4959e6dda8ca
# www-data in the image; the container runs as this user from the start, so it needs no capabilities.
WP_USER=33:33

mod_check() {
	app_check_domains
	app_check_port port
	[[ $(opt admin_user) =~ ^[a-z][a-z0-9._-]{2,59}$ && $(opt admin_user) != admin ]] ||
		die "LSS_WORDPRESS_ADMIN_USER must be a lowercase login name other than admin (the first name attackers try)."
	[[ -z $(opt admin_email) || $(opt admin_email) =~ ^[^@[:space:]]+@[^@[:space:]]+\.[a-z]+$ ]] ||
		die "LSS_WORDPRESS_ADMIN_EMAIL must be an e-mail address."
	[[ -n $(opt title) && $(opt title) != *[\'\"\\]* ]] || die "LSS_WORDPRESS_TITLE must not be empty or contain quotes or backslashes."
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_WORDPRESS_MEMORY must be a size such as 768m or 1g."
	return
}

mod_install() {
	app_compose_ready
	return
}

# _wp_compose: the stack. wp-config.php reads the database password from WORDPRESS_DB_PASSWORD_FILE on every request;
# the extra settings fix the address, force HTTPS for the login and turn off the file editor of the dashboard.
_wp_compose() {
	local domain
	domain=$(app_domain)
	cat <<EOF
# Managed by lss (module wordpress). Change LSS_WORDPRESS_* in /etc/lss/lss.conf and run lss configure wordpress.
name: $(app_project)
services:
  app:
    image: ${WP_IMAGE}
    user: "${WP_USER}"
    depends_on:
      db:
        condition: service_healthy
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD_FILE: /run/secrets/db-password
      WORDPRESS_CONFIG_EXTRA: |
        define('WP_HOME', 'https://${domain}');
        define('WP_SITEURL', 'https://${domain}');
        define('FORCE_SSL_ADMIN', true);
        define('DISALLOW_FILE_EDIT', true);
    ports:
      - 127.0.0.1:$(opt_int port):80
    # WordPress calls itself (WP-Cron, site health) through the web server of this server.
    extra_hosts:
      - "${domain}:host-gateway"
    volumes:
      - html:/var/www/html
$(app_mount secrets/db-password.app /run/secrets/db-password)
    tmpfs:
      - /tmp:mode=1777,size=256m
      - /var/run/apache2:mode=1777,size=16m
      - /var/lock/apache2:mode=1777,size=16m
    networks: [default, backend]
$(app_hardening "$(opt memory)" 512)
$(app_mariadb wordpress)
volumes:
  html:
  db:
$(app_networks)
EOF
	return
}

# _wp_installed: WordPress shows its login page (before the installation it sends every page to the installer).
_wp_installed() {
	[[ $(app_status "$(app_get wp-login.php)") == 200 ]]
	return
}

# _wp_login: logs the administrator of lss in with the password of the secret and sets WP_LOGIN_STATUS (the HTTP
# status) and WP_LOGIN_COOKIES (the session cookies as a Cookie header value). A redirect alone proves nothing (WordPress
# also redirects to HTTPS or to the installer); only a successful login sets wordpress_logged_in_* for this user. The
# cookies come from the Set-Cookie headers and go back in a Cookie header of their own, not through the cookie engine of
# curl: curl 7.76 (Rocky 9) does not send a Secure cookie to http://127.0.0.1, where the installation check runs.
_wp_login() {
	local headers page user cookie
	local -a cookies
	WP_LOGIN_STATUS='' WP_LOGIN_COOKIES=''
	user=$(opt admin_user)
	headers=$(mktemp)
	page=$(app_get wp-login.php -D "${headers}" -X POST --data-urlencode "log=${user}" \
		--data-urlencode "pwd@$(secret_path wordpress-admin-password)" \
		--data-urlencode "redirect_to=https://$(app_domain)/wp-admin/") || true
	WP_LOGIN_STATUS=$(app_status "${page}")
	WP_LOGIN_COOKIES=$(tr -d '\r' <"${headers}" |
		sed -nE 's/^[Ss][Ee][Tt]-[Cc][Oo][Oo][Kk][Ii][Ee]:[[:space:]]*(wordpress_(sec|logged_in)_[^=;[:space:]]*=[^;[:space:]]+).*/\1/p' |
		paste -sd ';' - | sed 's/;/; /g')
	rm -f -- "${headers}"
	[[ ${WP_LOGIN_STATUS} == 302 ]] || return 1
	# The value of wordpress_logged_in_* starts with the login name and a | (URL-encoded %7C).
	IFS=';' read -ra cookies <<<"${WP_LOGIN_COOKIES}"
	for cookie in "${cookies[@]}"; do
		cookie=${cookie# }
		[[ ${cookie} == wordpress_logged_in_*=* ]] || continue
		case ${cookie#*=} in
		"${user}%7C"* | "${user}%7c"* | "${user}|"*) return 0 ;;
		*) ;;
		esac
	done
	return 1
}

# _wp_admin_page: the dashboard with the session cookies of _wp_login; they go to curl as a header file, so they never
# appear in a process list.
_wp_admin_page() {
	local header page
	header=$(mktemp)
	printf 'Cookie: %s\n' "${WP_LOGIN_COOKIES}" >"${header}"
	page=$(app_get wp-admin/ -H "@${header}") || true
	rm -f -- "${header}"
	printf '%s' "${page}"
	return
}

# _wp_owner_check: an installation that exists already must be the one lss made, so its administrator logs in with
# the password of the secret (_wp_login). Otherwise somebody else ran the installer first, and lss stops before it
# publishes the site.
_wp_owner_check() {
	secret_exists wordpress-admin-password ||
		die "wordpress: WordPress is installed already, but lss has no password for $(opt admin_user), so lss did not install it. Check the instance; lss remove wordpress --purge starts over."
	_wp_login ||
		die "wordpress: WordPress is installed already, but $(opt admin_user) cannot log in with the password of lss (HTTP ${WP_LOGIN_STATUS:-none}, no session cookie of $(opt admin_user)), so lss did not install it. Check the instance; lss remove wordpress --purge starts over."
	return
}

# _wp_install: step 2 of the installer; the password goes to curl as a file. Runs against the container on
# 127.0.0.1 (APP_GET_LOCAL), before app_site publishes the site, so nobody else can reach the open installer.
_wp_install() {
	local email page
	if _wp_installed; then
		_wp_owner_check
		return 0
	fi
	email=$(opt admin_email)
	[[ -n ${email} ]] || email=$(opt admin_user)@$(app_domain)
	secret_get wordpress-admin-password 32 >/dev/null || die "wordpress: the password of the administrator cannot be created."
	log_info "wordpress: installing WordPress (administrator $(opt admin_user), password in $(secret_path wordpress-admin-password))"
	page=$(app_get 'wp-admin/install.php?step=2' -X POST --data-urlencode "weblog_title=$(opt title)" \
		--data-urlencode "user_name=$(opt admin_user)" --data-urlencode "admin_password@$(secret_path wordpress-admin-password)" \
		--data-urlencode "admin_password2@$(secret_path wordpress-admin-password)" --data-urlencode "admin_email=${email}" \
		-d blog_public=1) || true
	[[ $(app_status "${page}") == 200 ]] || die "wordpress: the installer answers $(app_status "${page}")."
	_wp_installed || die "wordpress: WordPress is not installed after the installer."
	files_note_change "installed WordPress"
	return
}

mod_configure() {
	local APP_GET_LOCAL
	app_db_secrets mariadb "${WP_USER}"
	_wp_compose | app_compose
	app_backup DB=mariadb LIVE=html
	app_up
	# The installer takes the first visitor as the administrator: it runs against the container before the site is
	# published.
	APP_GET_LOCAL=$(opt_int port)
	app_wait wp-includes/css/buttons.min.css 200 >/dev/null ||
		die "wordpress: the container on 127.0.0.1:${APP_GET_LOCAL} does not answer."
	_wp_install
	APP_GET_LOCAL=''
	app_site "$(opt_int port)"
	app_wait wp-includes/css/buttons.min.css 200 >/dev/null || die "wordpress: https://$(app_domain)/ does not answer."
	return
}

mod_verify() {
	local page home
	app_verify_stack
	app_verify_backup
	page=$(app_wait wp-login.php 200) || die "wordpress: the login page does not answer."
	grep -q 'name="pwd"' <<<"${page}" || die "wordpress: https://$(app_domain)/wp-login.php shows no login."
	# rest_route works with plain permalinks too; /wp-json/ needs pretty permalinks, which a fresh site lacks.
	page=$(app_get 'index.php?rest_route=/') || true
	home=$(jq -r '.home // empty' <<<"${page%$'\n'*}" 2>/dev/null) || home=''
	[[ $(app_status "${page}") == 200 && ${home} == "https://$(app_domain)" ]] ||
		die "wordpress: the REST API answers $(app_status "${page}") with the address '${home}' instead of https://$(app_domain)."
	# Used, not only running: the administrator logs in and opens the dashboard with the session cookies of the login.
	_wp_login || die "wordpress: $(opt admin_user) cannot log in (HTTP ${WP_LOGIN_STATUS:-none}, no session cookie of $(opt admin_user))."
	page=$(_wp_admin_page)
	if [[ $(app_status "${page}") != 200 ]] || ! grep -q 'id="wpadminbar"' <<<"${page}"; then
		die "wordpress: the dashboard does not open after the login."
	fi
	return
}

mod_remove() {
	app_remove
	return
}
