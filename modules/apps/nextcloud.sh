# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="nextcloud"
MOD_GROUP="apps"
MOD_DESCRIPTION="Nextcloud Hub 34 with PostgreSQL as a Docker Compose stack behind the web server, background jobs by a systemd timer, linked to Collabora Online when the collabora module is installed"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the Nextcloud site, separated by spaces; empty: nextcloud.<host name of the server>
port|8081|Port of the Nextcloud container on 127.0.0.1, which the web server forwards to
admin_user|admin|Name of the first administrator (the password is the secret nextcloud-admin-password)
memory|1g|Memory limit of the Nextcloud container"
MOD_SECRETS="nextcloud-admin-password nextcloud-db-password"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# Nextcloud 34.0.4 (apache), the multi-architecture index (amd64 and arm64), checked 2026-10-15. A new release means a
# new digest here; the container upgrades the installation when it starts.
NC_IMAGE=docker.io/library/nextcloud@sha256:0e5688ba0988b9112cf03f9c6bab53eccb466d278435f6596f16c1f25acacf74
# www-data in the image; the container runs as this user from the start, so it needs no capabilities.
NC_USER=33:33

mod_check() {
	app_check_domains
	app_check_port port
	[[ $(opt admin_user) =~ ^[a-z][a-z0-9._-]{1,31}$ ]] || die "LSS_NEXTCLOUD_ADMIN_USER must be a lowercase login name."
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_NEXTCLOUD_MEMORY must be a size such as 1g or 768m."
	return
}

mod_install() {
	app_compose_ready
	return
}

# _nc_compose: the stack. Nextcloud runs as www-data on a read-only root file system; its code, configuration and
# files are in the volume "html". The secrets reach it only as files; occ reads the passwords for the installation
# from stdin (_nc_install).
_nc_compose() {
	local domain
	domain=$(app_domain)
	cat <<EOF
# Managed by lss (module nextcloud). Change LSS_NEXTCLOUD_* in /etc/lss/lss.conf and run lss configure nextcloud.
name: $(app_project)
services:
  app:
    image: ${NC_IMAGE}
    user: "${NC_USER}"
    depends_on:
      db:
        condition: service_healthy
    environment:
      OVERWRITEPROTOCOL: https
      OVERWRITECLIURL: https://${domain}
      TRUSTED_PROXIES: 127.0.0.1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
      PHP_UPLOAD_LIMIT: 1G
    ports:
      - 127.0.0.1:$(opt_int port):80
    extra_hosts:
$(_nc_extra_hosts)
    volumes:
      - html:/var/www/html
$(app_mount secrets/db-password.app /run/secrets/db-password)
$(app_mount secrets/admin-password /run/secrets/admin-password)
    tmpfs:
      - /tmp:mode=1777,size=512m
      - /var/run/apache2:mode=1777,size=16m
      - /var/lock/apache2:mode=1777,size=16m
    networks: [default, backend]
$(app_hardening "$(opt memory)" 512)
$(app_postgres nextcloud)
volumes:
  html:
  db:
$(app_networks)
EOF
	return
}

# _nc_extra_hosts: the host names of Nextcloud and Collabora (also before the collabora module is installed, so adding
# it later does not recreate the container) resolve to the host inside the container, so Nextcloud reaches both sites
# through the web server even where the public address does not loop back.
_nc_extra_hosts() {
	local domain
	for domain in $(app_domains) $(app_domains_of collabora); do
		printf '      - "%s:host-gateway"\n' "${domain}"
	done
	return
}

# _nc_occ ARG...: occ as www-data in the running container.
_nc_occ() {
	app_exec app php occ "$@"
	return
}

# _nc_installed: Nextcloud reports itself installed.
_nc_installed() {
	[[ $(_nc_occ status --output=json 2>/dev/null | jq -r '.installed // false' 2>/dev/null) == true ]]
	return
}

# _nc_started: the entrypoint of the image has finished. On the first start it copies Nextcloud into the volume
# (custom_apps, config and version.php come last) and only then starts Apache; occ in between finds a half-copied tree
# ("App directory custom_apps not found"). Through docker-proxy the port takes connections from the start, so the
# test is an HTTP answer from Apache itself (any status; curl reports 000 for none).
_nc_started() {
	[[ $(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$(opt_int port)/status.php" 2>/dev/null) != 000 ]]
	return
}

# _nc_install: the first installation. occ asks for the database and the admin password when they are not on its
# command line; both come from the mounted secret files through a pipe, so they never appear in a process list.
_nc_install() {
	local i
	for ((i = 0; i < 100; i++)); do
		_nc_started && _nc_occ status >/dev/null 2>&1 && break
		sleep 3
	done
	_nc_installed && return 0
	log_info "nextcloud: installing Nextcloud (admin user $(opt admin_user), password in $(secret_path nextcloud-admin-password))"
	# shellcheck disable=SC2016 # expanded by the shell in the container
	log_command app_exec -e SHELL_INTERACTIVE=1 app sh -c 'printf "%s\n%s\n" "$(cat /run/secrets/db-password)" "$(cat /run/secrets/admin-password)" |
		php occ maintenance:install --database pgsql --database-host db --database-name nextcloud --database-user nextcloud \
			--admin-user "$1" --data-dir /var/www/html/data' sh "$(opt admin_user)" ||
		die "nextcloud: the installation failed; see the log."
	_nc_installed || die "nextcloud: Nextcloud is not installed after occ maintenance:install."
	files_note_change "installed Nextcloud"
	return
}

# _nc_set KEY VALUE: a system setting, changed only when it differs.
_nc_set() {
	local key=$1 value=$2 index=${3:-}
	local -a keys=("${key}")
	[[ -z ${index} ]] || keys+=("${index}")
	if [[ $(_nc_occ config:system:get "${keys[@]}" 2>/dev/null) != "${value}" ]]; then
		log_command _nc_occ config:system:set "${keys[@]}" --value="${value}" || die "nextcloud: occ cannot set ${key}."
		files_note_change "nextcloud setting ${key}"
	fi
	return
}

# _nc_settings: host names, URLs and defaults after the installation.
_nc_settings() {
	local domain index=1
	_nc_set trusted_domains localhost 0
	for domain in $(app_domains); do
		_nc_set trusted_domains "${domain}" "${index}"
		index=$((index + 1))
	done
	_nc_set overwrite.cli.url "https://$(app_domain)"
	_nc_set overwriteprotocol https
	_nc_set maintenance_window_start 1
	if [[ $(_nc_occ config:app:get core backgroundjobs_mode 2>/dev/null) != cron ]]; then
		log_command _nc_occ background:cron || die "nextcloud: occ cannot switch background jobs to cron."
		files_note_change "nextcloud background jobs by cron"
	fi
	return
}

mod_configure() {
	app_db_secrets postgres "${NC_USER}"
	app_secret nextcloud-admin-password "${NC_USER}" 32 admin-password
	_nc_compose | app_compose
	app_backup DB=postgres DB_USER=nextcloud LIVE=html
	app_up
	_nc_install
	_nc_settings
	app_site "$(opt_int port)"
	app_nextcloud_office
	app_timer nextcloud-cron 5min "Nextcloud background jobs" app php -f /var/www/html/cron.php
	return
}

# _nc_dav METHOD PATH [CURL OPTION...]: a WebDAV request as the administrator; prints the body and the status.
_nc_dav() {
	local method=$1 path=$2 netrc page
	shift 2
	netrc=$(app_netrc "$(opt admin_user)" nextcloud-admin-password)
	page=$(app_get "remote.php/dav/files/$(opt admin_user)/${path}" --netrc-file "${netrc}" -X "${method}" "$@") || true
	rm -f -- "${netrc}"
	printf '%s' "${page}"
	return
}

mod_verify() {
	local page status probe
	app_verify_stack
	app_verify_backup
	page=$(app_wait status.php 200) || die "nextcloud: https://$(app_domain)/status.php does not answer."
	[[ $(jq -r '.installed' <<<"${page%$'\n'*}" 2>/dev/null) == true ]] || die "nextcloud: Nextcloud is not installed."
	[[ $(jq -r '.maintenance' <<<"${page%$'\n'*}" 2>/dev/null) == false ]] || die "nextcloud: Nextcloud is in maintenance mode."
	page=$(app_wait login 200 60) || die "nextcloud: the login page does not answer."
	grep -q 'name="password"\|id="password"\|login' <<<"${page}" || die "nextcloud: https://$(app_domain)/login shows no login."
	# Used, not only running: the administrator stores a file over WebDAV, reads it back and deletes it.
	probe="lss-verify-$(date +%s)"
	printf '%s' "${probe}" >"${TMPDIR:-/tmp}/${probe}.txt"
	status=$(app_status "$(_nc_dav PUT "${probe}.txt" --data-binary "@${TMPDIR:-/tmp}/${probe}.txt")")
	rm -f -- "${TMPDIR:-/tmp}/${probe}.txt"
	[[ ${status} == 201 || ${status} == 204 ]] || die "nextcloud: WebDAV upload as $(opt admin_user) answers ${status}."
	page=$(_nc_dav GET "${probe}.txt")
	[[ ${page%$'\n'*} == "${probe}" ]] || die "nextcloud: the uploaded file does not come back over WebDAV."
	status=$(app_status "$(_nc_dav DELETE "${probe}.txt")")
	[[ ${status} == 204 ]] || die "nextcloud: deleting the test file answers ${status}."
	svc_is_enabled lss-nextcloud-cron.timer || die "nextcloud: the timer lss-nextcloud-cron for the background jobs is off."
	timeout 600 systemctl start lss-nextcloud-cron.service || die "nextcloud: the background jobs fail (journalctl -u lss-nextcloud-cron)."
	if state_installed collabora; then
		log_command _nc_occ richdocuments:activate-config || die "nextcloud: Nextcloud Office cannot reach Collabora Online."
		app_collabora_check
	fi
	return
}

mod_remove() {
	app_timer_remove nextcloud-cron
	app_remove
	return
}
