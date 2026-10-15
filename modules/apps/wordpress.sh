# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="wordpress"
MOD_GROUP="apps"
MOD_DESCRIPTION="WordPress 7.1 with MariaDB as a Docker Compose stack behind the web server, installed with a first administrator; the theme and plugin editor is off"
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

# _wp_install: step 2 of the installer; the password goes to curl as a file.
_wp_install() {
	local email page
	_wp_installed && return 0
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
	app_db_secrets mariadb "${WP_USER}"
	_wp_compose | app_compose
	app_up
	app_site "$(opt_int port)"
	app_wait wp-includes/images/w-logo-blue.png 200 >/dev/null || die "wordpress: https://$(app_domain)/ does not answer."
	_wp_install
	return
}

mod_verify() {
	local page jar status
	app_verify_stack
	page=$(app_wait wp-login.php 200) || die "wordpress: the login page does not answer."
	grep -q 'name="pwd"' <<<"${page}" || die "wordpress: https://$(app_domain)/wp-login.php shows no login."
	page=$(app_get wp-json/) || true
	[[ $(app_status "${page}") == 200 && $(jq -r '.home' <<<"${page%$'\n'*}" 2>/dev/null) == "https://$(app_domain)" ]] ||
		die "wordpress: the REST API does not report https://$(app_domain) as the address of the site."
	# Used, not only running: the administrator logs in and opens the dashboard.
	jar=$(mktemp)
	page=$(app_get wp-login.php -b "${jar}" -c "${jar}" -b 'wordpress_test_cookie=WP%20Cookie%20check' -X POST \
		--data-urlencode "log=$(opt admin_user)" --data-urlencode "pwd@$(secret_path wordpress-admin-password)" \
		-d testcookie=1 --data-urlencode "redirect_to=https://$(app_domain)/wp-admin/") || true
	status=$(app_status "${page}")
	if [[ ${status} != 302 ]]; then
		rm -f -- "${jar}"
		die "wordpress: $(opt admin_user) cannot log in (HTTP ${status})."
	fi
	page=$(app_get wp-admin/ -b "${jar}") || true
	rm -f -- "${jar}"
	if [[ $(app_status "${page}") != 200 ]] || ! grep -q 'id="wpadminbar"' <<<"${page}"; then
		die "wordpress: the dashboard does not open after the login."
	fi
	return
}

mod_remove() {
	app_remove
	return
}
