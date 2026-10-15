# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Apps: the modules of the group apps run as Docker Compose stacks behind the installed web server. Each stack is the
# project lss-NAME with its files in CTR_CONFIG_DIR/lss-NAME (the one directory of /etc its containers may mount):
#   compose.yaml   the stack, checked against the container rules (lib/container.sh) before every start
#   secrets/       copies of the secrets in /etc/lss/secrets that a container reads, mounted read-only as
#                  /run/secrets/NAME and owned by the user the container runs as (seen from the host)
#   config/        other files a container reads
# Nothing secret is written into compose.yaml, an environment variable or a command line: the images read
# /run/secrets/NAME themselves (*_FILE variables) or a small wrapper reads it before the program starts.
#
# Every published port binds to 127.0.0.1; the web server publishes the app as an HTTPS site with the security headers
# of lib/web.sh. Data lives in named volumes (lss-NAME_*), which stay when the module is removed, unless --purge.

APP_START_TIMEOUT=${APP_START_TIMEOUT:-600}

# app_project: the Compose project of the module running this step.
app_project() {
	printf 'lss-%s' "${LSS_MODULE}"
	return
}

# app_dir: the directory of the stack.
app_dir() {
	printf '%s/%s' "${CTR_CONFIG_DIR}" "$(app_project)"
	return
}

app_compose_file() {
	printf '%s/compose.yaml' "$(app_dir)"
	return
}

# app_valid_domain NAME: a host name like cloud.example.com (lowercase, at least two labels).
app_valid_domain() {
	local name=$1
	[[ ${name} =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]]
	return
}

# app_check_domains: checks the option domains of the module (host names separated by spaces).
app_check_domains() {
	local domain
	for domain in $(opt domains); do
		app_valid_domain "${domain}" ||
			die "$(config_key "${LSS_MODULE}" domains): '${domain}' is not a host name like ${LSS_MODULE}.example.com."
	done
	return
}

# app_check_port OPTION: the option is a port from 1024 to 65535 other than the admin port of the web server.
app_check_port() {
	local option=$1 port
	port=$(opt_int "${option}")
	((port >= 1024 && port <= 65535)) || die "$(config_key "${LSS_MODULE}" "${option}") must be a port from 1024 to 65535."
	[[ ${port} != "${WEB_ADMIN_PORT}" ]] ||
		die "$(config_key "${LSS_MODULE}" "${option}") must differ from the admin port of the web server (${WEB_ADMIN_PORT})."
	return
}

# app_domains: the host names of the app: the option domains, or NAME.<host name of the server>.
app_domains() {
	local domains host
	domains=$(opt domains)
	if [[ -z ${domains} ]]; then
		host=$(hostname -f 2>/dev/null || true)
		[[ -n ${host} ]] || host=$(hostname)
		domains=${LSS_MODULE}.${host,,}
	fi
	printf '%s' "${domains}"
	return
}

# app_domain: the first host name of the app, the one its links use.
app_domain() {
	local -a domains=()
	read -ra domains <<<"$(app_domains)"
	printf '%s' "${domains[0]}"
	return
}

# app_compose_ready: docker compose is there (the Compose plugin of Docker CE).
app_compose_ready() {
	docker compose version >/dev/null 2>&1 ||
		die "${LSS_MODULE}: docker compose is missing; the apps need the Compose plugin (LSS_DOCKER_SOURCE=auto installs it)."
	return
}

# _app_userns_base FILE: the first ID of the range Docker maps containers into (/etc/subuid or /etc/subgid), or 0
# when the daemon runs without user namespace remapping.
_app_userns_base() {
	local file=$1 user base
	# The daemon.json of the docker module has the setting on a line of its own; read without jq.
	user=$(sed -n 's/.*"userns-remap"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${APP_DOCKER_CONFIG:-/etc/docker/daemon.json}" 2>/dev/null |
		head -n 1) || user=''
	if [[ -z ${user} ]]; then
		printf '0'
		return 0
	fi
	[[ ${user} != default ]] || user=dockremap
	user=${user%%:*}
	base=$(awk -F ':' -v user="${user}" '$1 == user { print $2; exit }' "${file}" 2>/dev/null) || base=''
	[[ ${base} =~ ^[0-9]+$ ]] || die "${LSS_MODULE}: ${file} has no ID range for ${user}, which Docker maps containers into."
	printf '%s' "${base}"
	return
}

# app_host_owner UID[:GID]: the owner, as the host sees it, of a file the container user UID:GID must read.
app_host_owner() {
	local ids=$1 uid gid
	uid=${ids%%:*}
	gid=${ids#*:}
	[[ ${ids} == *:* ]] || gid=${uid}
	[[ ${uid} =~ ^[0-9]+$ && ${gid} =~ ^[0-9]+$ ]] || die "${LSS_MODULE}: '${ids}' is not UID or UID:GID."
	printf '%s:%s' "$((uid + $(_app_userns_base "${APP_SUBUID:-/etc/subuid}")))" \
		"$((gid + $(_app_userns_base "${APP_SUBGID:-/etc/subgid}")))"
	return
}

# APP_CHANGED: a file the containers mount changed in this step, so they must be created again (a bind-mounted file
# keeps showing the old copy once file_write replaced it). APP_COMPOSE_CHANGED: compose.yaml changed.
APP_CHANGED=0
APP_COMPOSE_CHANGED=0

# app_file PATH UID[:GID] MODE: writes stdin to $(app_dir)/PATH for the container user UID:GID.
app_file() {
	local path=$1 ids=$2 mode=$3
	[[ ${path} =~ ^[a-z0-9][a-z0-9._/-]*$ && /${path}/ != */../* ]] || die "${LSS_MODULE}: '${path}' is not a valid file name."
	install -d -m 0700 "$(app_dir)"
	install -d -m 0700 "$(dirname "$(app_dir)/${path}")"
	file_write "${mode}" "$(app_host_owner "${ids}")" "$(app_dir)/${path}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || APP_CHANGED=1
	return
}

# app_secret SECRET UID[:GID] [LENGTH] [FILE]: the secret from /etc/lss/secrets (created on first use), copied to
# secrets/FILE (default: SECRET) for the container user UID:GID, mode 0400, without a final newline. The container
# mounts it with app_mount secrets/FILE /run/secrets/NAME.
app_secret() {
	local secret=$1 ids=$2 length=${3:-32} file=${4:-$1} value
	secret_load "${secret}" value "${length}"
	printf '%s' "${value}" | app_file "secrets/${file}" "${ids}" 0400
	return
}

# app_mount PATH TARGET: the volume line of a Compose service that mounts $(app_dir)/PATH read-only at TARGET (with
# the shared SELinux label on the RHEL family, so every container of the stack may read it).
app_mount() {
	local path=$1 target=$2
	printf '      - %s/%s:%s:ro,z\n' "$(app_dir)" "${path}" "${target}"
	return
}

# app_hardening MEMORY PIDS [writable]: the lines every Compose service of lss gets (indented for a service): no
# capabilities, no new privileges, memory and process limits, a read-only root file system unless "writable", restart
# after a crash or reboot. Services add the capabilities they need with cap_add.
app_hardening() {
	local memory=$1 pids=$2 writable=${3:-}
	printf '    restart: unless-stopped\n    cap_drop: [ALL]\n    security_opt: ["no-new-privileges:true"]\n'
	printf '    mem_limit: %s\n    memswap_limit: %s\n    pids_limit: %s\n' "${memory}" "${memory}" "${pids}"
	if [[ ${writable} == writable ]]; then
		printf '    labels:\n      lss.managed: "true"\n      lss.writable: "true"\n'
	else
		printf '    read_only: true\n    labels:\n      lss.managed: "true"\n'
	fi
	return
}

# app_compose: writes the stack from stdin to compose.yaml (root only: it names the files with the secrets).
app_compose() {
	install -d -m 0700 "$(app_dir)"
	file_write 0600 root:root "$(app_compose_file)"
	APP_COMPOSE_CHANGED=${LSS_FILE_CHANGED}
	return
}

# _app_compose COMMAND...: docker compose for the stack of the module.
_app_compose() {
	docker compose --project-name "$(app_project)" -f "$(app_compose_file)" "$@"
	return
}

# app_running: every service of the stack has a running container (except "init", which runs once per start).
app_running() {
	local services running
	services=$(_app_compose config --services 2>/dev/null | grep -vx init | sort) || return 1
	running=$(_app_compose ps --status running --services 2>/dev/null | sort) || return 1
	[[ -n ${services} && ${services} == "${running}" ]]
	return
}

# app_up: starts the stack after compose.yaml or a mounted file changed, or when a service is not running. A changed
# mounted file creates every container again, because a bind mount keeps the replaced file.
app_up() {
	local -a options=()
	app_compose_ready
	if [[ ${APP_CHANGED} == 1 ]]; then
		options=(--force-recreate)
	elif [[ ${APP_COMPOSE_CHANGED} == 0 ]] && app_running; then
		return 0
	fi
	log_info "Starting $(app_project) (images are pulled on the first start)"
	ctr_compose_up "$(app_project)" "$(app_compose_file)" "${options[@]}"
	files_note_change "started $(app_project)"
	APP_CHANGED=0
	APP_COMPOSE_CHANGED=0
	return
}

# app_exec [OPTION...] SERVICE COMMAND...: runs COMMAND in the running container of SERVICE (no terminal, stdin passed
# on); OPTIONs of "docker compose exec" such as --user or --env come first.
app_exec() {
	_app_compose exec -T "$@"
	return
}

# Nextcloud Office: the collabora module and the nextcloud module link each other, whichever comes second.
APP_NEXTCLOUD_PROJECT=lss-nextcloud

# app_domains_of MODULE: the host names of another app module (its option domains, or MODULE.<host name>).
app_domains_of() {
	local module=$1 domains host
	domains=$(config_option "${module}" domains '')
	if [[ -z ${domains} ]]; then
		host=$(hostname -f 2>/dev/null || true)
		[[ -n ${host} ]] || host=$(hostname)
		domains=${module}.${host,,}
	fi
	printf '%s' "${domains}"
	return
}

# _app_nc_exec COMMAND...: a command in the Nextcloud container (stdin passed on).
_app_nc_exec() {
	docker compose --project-name "${APP_NEXTCLOUD_PROJECT}" -f "${CTR_CONFIG_DIR}/${APP_NEXTCLOUD_PROJECT}/compose.yaml" exec -T app "$@"
	return
}

# _app_nc_occ ARG...: occ in the Nextcloud container.
_app_nc_occ() {
	_app_nc_exec php occ "$@"
	return
}

# _app_nc_trust: the certificate Nextcloud must trust to reach the Collabora site: the CA of a private ACME server
# (LSS_TLS_CA_BUNDLE) or, without the tls module, the self-signed default certificate of the web server; nothing for
# Let's Encrypt. Prints the file, or nothing.
_app_nc_trust() {
	local bundle
	if state_installed tls; then
		bundle=$(config_option tls ca_bundle '')
		[[ -z ${bundle} || ! -s ${bundle} ]] || printf '%s' "${bundle}"
	elif [[ -s ${WEB_TLS_DIR}/default/fullchain.pem ]]; then
		printf '%s/default/fullchain.pem' "${WEB_TLS_DIR}"
	fi
	return
}

# app_nextcloud_office: with both modules installed (or the other one being installed), Nextcloud Office
# (richdocuments) points at the Collabora site and checks that it reaches it.
app_nextcloud_office() {
	local url trust sum module first
	for module in nextcloud collabora; do
		state_installed "${module}" || [[ ${LSS_MODULE} == "${module}" ]] || return 0
	done
	read -r first _ <<<"$(app_domains_of collabora)"
	url=https://${first}
	if ! _app_nc_occ app:list --output=json 2>/dev/null | jq -e '.enabled.richdocuments' >/dev/null 2>&1; then
		log_command _app_nc_occ app:install richdocuments || log_command _app_nc_occ app:enable richdocuments ||
			die "${LSS_MODULE}: the Nextcloud app Nextcloud Office (richdocuments) cannot be installed."
		files_note_change "installed Nextcloud Office"
	fi
	if [[ $(_app_nc_occ config:app:get richdocuments wopi_url 2>/dev/null) != "${url}" ]]; then
		log_command _app_nc_occ config:app:set richdocuments wopi_url --value="${url}" ||
			die "${LSS_MODULE}: occ cannot set the address of Collabora Online."
		files_note_change "linked Nextcloud Office to ${url}"
	fi
	trust=$(_app_nc_trust)
	if [[ -n ${trust} ]]; then
		sum=$(sha256sum "${trust}" | cut -d ' ' -f 1)
		if [[ $(state_get nextcloud trusted_cert) != "${sum}" ]]; then
			_app_nc_exec sh -c 'cat >/tmp/lss-web.pem' <"${trust}" ||
				die "${LSS_MODULE}: cannot copy the certificate of the web server into the Nextcloud container."
			log_command _app_nc_occ security:certificates:import /tmp/lss-web.pem ||
				die "${LSS_MODULE}: occ cannot add the certificate of the web server to the trusted ones of Nextcloud."
			state_set nextcloud trusted_cert "${sum}"
			files_note_change "Nextcloud trusts the certificate of the web server"
		fi
	fi
	log_command _app_nc_occ richdocuments:activate-config ||
		die "${LSS_MODULE}: Nextcloud Office cannot reach Collabora Online at ${url}; see the log."
	return
}

# app_timer NAME INTERVAL DESCRIPTION SERVICE COMMAND...: the systemd timer lss-NAME.timer, which runs COMMAND in the
# container of SERVICE every INTERVAL (a systemd time span such as 5min), first INTERVAL after boot.
app_timer() {
	local name=$1 interval=$2 description=$3 service=$4 docker
	shift 4
	docker=$(command -v docker) || die "${LSS_MODULE}: docker is missing."
	svc_unit "lss-${name}.service" <<EOF
# Managed by lss (module ${LSS_MODULE}).
[Unit]
Description=${description} (lss)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${docker} compose --project-name $(app_project) -f $(app_compose_file) exec -T ${service} $*
EOF
	svc_unit "lss-${name}.timer" <<EOF
# Managed by lss (module ${LSS_MODULE}).
[Unit]
Description=${description} every ${interval} (lss)

[Timer]
OnBootSec=${interval}
OnUnitActiveSec=${interval}

[Install]
WantedBy=timers.target
EOF
	svc_enable "lss-${name}.timer"
	return
}

# app_timer_remove NAME: stops and removes the timer of app_timer.
app_timer_remove() {
	local name=$1
	svc_disable "lss-${name}.timer"
	file_remove "/etc/systemd/system/lss-${name}.timer"
	file_remove "/etc/systemd/system/lss-${name}.service"
	svc_daemon_reload
	return
}

# app_site PORT [NAME DOMAIN...]: the HTTPS route NAME (default: the module) for the host names DOMAIN (default: those
# of the app) to 127.0.0.1:PORT, through web_proxy_route (lib/web.sh).
app_site() {
	local port=$1 name=${2:-${LSS_MODULE}}
	local -a domains=("${@:3}")
	[[ ${#domains[@]} -gt 0 ]] || read -ra domains <<<"$(app_domains)"
	web_proxy_route "${name}" "http://127.0.0.1:${port}" "${domains[@]}"
	return
}

# app_get PATH [CURL OPTION...]: the page at https://DOMAIN/PATH as the web server of this server serves it (the
# first host name of the app, or APP_GET_DOMAIN, resolved to 127.0.0.1), followed by a line with the HTTP status.
app_get() {
	local path=$1 domain
	shift
	domain=${APP_GET_DOMAIN:-$(app_domain)}
	curl -ks --max-time 30 -w '\n%{http_code}' --resolve "${domain}:443:127.0.0.1" "$@" "https://${domain}/${path#/}"
	return
}

# app_status PAGE: the HTTP status at the end of the output of app_get.
app_status() {
	local page=$1
	printf '%s' "${page##*$'\n'}"
	return
}

# app_wait PATH STATUS [SECONDS]: waits until https://DOMAIN/PATH answers STATUS (the app starts, migrates its
# database, ...) and prints the page; fails with the last answer after SECONDS (default APP_START_TIMEOUT).
app_wait() {
	local path=$1 wanted=$2 seconds=${3:-${APP_START_TIMEOUT}} page='' status='' started=${SECONDS}
	while ((SECONDS - started < seconds)); do
		page=$(app_get "${path}") || true
		status=$(app_status "${page}")
		if [[ ${status} == "${wanted}" ]]; then
			printf '%s' "${page}"
			return 0
		fi
		sleep 3
	done
	log_error "${LSS_MODULE}: https://$(app_domain)/${path#/} answers ${status:-nothing} instead of ${wanted} after ${seconds} s."
	_app_compose ps --all >&2 2>/dev/null || true
	_app_compose logs --tail 30 >&2 2>/dev/null || true
	return 1
}

# app_verify_stack: the stack runs, its compose.yaml still passes the container rules and the site serves security
# headers.
app_verify_stack() {
	local page
	[[ -s $(app_compose_file) ]] || die "${LSS_MODULE}: $(app_compose_file) is missing."
	[[ $(stat -c '%a %U' "$(app_compose_file)") == '600 root' ]] || die "${LSS_MODULE}: $(app_compose_file) must be mode 600, owned by root."
	ctr_compose_check "$(app_compose_file)" "$(app_project)" || die "${LSS_MODULE}: the stack breaks the container rules; see above."
	app_running || die "${LSS_MODULE}: a container of $(app_project) is not running (docker compose -p $(app_project) ps)."
	page=$(app_get '' --head) || true
	grep -qi '^strict-transport-security:' <<<"${page}" ||
		die "${LSS_MODULE}: https://$(app_domain)/ sends no Strict-Transport-Security header; the web server site is missing."
	return
}

# Database containers for the stacks: official images, pinned by digest (multi-architecture index, amd64 and arm64),
# running as their own unprivileged user without capabilities, only on the internal network "backend" of the stack.
# PostgreSQL 18.6 (alpine; postgres is 70:70) and MariaDB 11.8.9 LTS (mysql is 999:999), checked 2026-10-15.
APP_POSTGRES_IMAGE=docker.io/library/postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873
APP_POSTGRES_USER=70:70
APP_MARIADB_IMAGE=docker.io/library/mariadb@sha256:6422478cb8e159f080fb1d8ccf65101e26fe51385787fde7d16c3b165a331f15
APP_MARIADB_USER=999:999

# app_postgres NAME: the service "db" (PostgreSQL with database and user NAME); the password is the secret
# <module>-db-password, mounted as /run/secrets/db-password. Call app_secret for it with APP_POSTGRES_USER and the file
# name db-password.db first.
app_postgres() {
	local name=$1
	cat <<EOF
  db:
    image: ${APP_POSTGRES_IMAGE}
    user: "${APP_POSTGRES_USER}"
    environment:
      POSTGRES_DB: ${name}
      POSTGRES_USER: ${name}
      POSTGRES_PASSWORD_FILE: /run/secrets/db-password
    volumes:
      - db:/var/lib/postgresql
$(app_mount secrets/db-password.db /run/secrets/db-password)
    tmpfs:
      - /var/run/postgresql:mode=1777,size=16m
      - /tmp:mode=1777,size=64m
    networks: [backend]
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "${name}", "-d", "${name}"]
      interval: 10s
      timeout: 5s
      retries: 30
$(app_hardening 512m 256)
EOF
	return
}

# app_mariadb NAME: the service "db" (MariaDB with database and user NAME), like app_postgres; the root password is
# the secret <module>-db-root-password (db-root-password.db).
app_mariadb() {
	local name=$1
	cat <<EOF
  db:
    image: ${APP_MARIADB_IMAGE}
    user: "${APP_MARIADB_USER}"
    environment:
      MARIADB_DATABASE: ${name}
      MARIADB_USER: ${name}
      MARIADB_PASSWORD_FILE: /run/secrets/db-password
      MARIADB_ROOT_PASSWORD_FILE: /run/secrets/db-root-password
      MARIADB_AUTO_UPGRADE: "1"
    volumes:
      - db:/var/lib/mysql
$(app_mount secrets/db-password.db /run/secrets/db-password)
$(app_mount secrets/db-root-password.db /run/secrets/db-root-password)
    tmpfs:
      - /run/mysqld:mode=1777,size=16m
      - /tmp:mode=1777,size=256m
    networks: [backend]
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 10s
      timeout: 5s
      retries: 30
$(app_hardening 512m 256)
EOF
	return
}

# app_db_secrets postgres|mariadb CONSUMER_IDS [FILE]: the database password for the database container and for the
# app (secrets/FILE, default db-password.app, for the container user CONSUMER_IDS); MariaDB also gets a root password.
app_db_secrets() {
	local engine=$1 ids=$2 file=${3:-db-password.app}
	if [[ ${engine} == postgres ]]; then
		app_secret "${LSS_MODULE}-db-password" "${APP_POSTGRES_USER}" 32 db-password.db
	else
		app_secret "${LSS_MODULE}-db-password" "${APP_MARIADB_USER}" 32 db-password.db
		app_secret "${LSS_MODULE}-db-root-password" "${APP_MARIADB_USER}" 32 db-root-password.db
	fi
	app_secret "${LSS_MODULE}-db-password" "${ids}" 32 "${file}"
	return
}

# app_init VOLUME PATH UID:GID: the service "init", which gives the mount point PATH of the named volume VOLUME (not
# what is inside) to the container user UID:GID before the app starts; for images whose data directory belongs to root
# while the app runs as another user. It runs as root with only CAP_CHOWN, without a network, and exits. The app waits
# for it with "depends_on: init: condition: service_completed_successfully".
app_init() {
	local volume=$1 path=$2 ids=$3
	cat <<EOF
  init:
    image: ${APP_POSTGRES_IMAGE}
    user: "0:0"
    entrypoint: ["chown", "${ids}", "${path}"]
    network_mode: none
    volumes:
      - ${volume}:${path}
    restart: "no"
    cap_drop: [ALL]
    cap_add: [CHOWN]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 32m
    memswap_limit: 32m
    pids_limit: 16
    read_only: true
    labels:
      lss.managed: "true"
EOF
	return
}

# app_networks: the networks of a stack: "default" (the app, with access to the internet) and "backend" (internal,
# no route out; the database).
app_networks() {
	printf 'networks:\n  default:\n  backend:\n    internal: true\n'
	return
}

# app_netrc USER SECRET: a temporary netrc file (mode 0600) with the login of USER at the app's host name, so curl
# sends the password without it showing up in the process list; prints its path. The caller deletes it.
app_netrc() {
	local user=$1 secret=$2 file password
	secret_load "${secret}" password
	file=$(mktemp)
	chmod 600 "${file}"
	printf 'machine %s login %s password %s\n' "$(app_domain)" "${user}" "${password}" >"${file}"
	printf '%s' "${file}"
	return
}

# app_site_remove NAME: removes the route NAME of app_site.
app_site_remove() {
	local name=$1
	web_proxy_route_remove "${name}"
	return
}

# app_remove: stops the stack and removes its site and files; the named volumes (the data) and the secrets stay unless
# --purge.
app_remove() {
	local name=${LSS_MODULE} secret
	app_site_remove "${name}"
	if [[ -s $(app_compose_file) ]] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
		local -a options=(--remove-orphans)
		[[ ${LSS_PURGE:-0} != 1 ]] || options+=(--volumes)
		log_command _app_compose down "${options[@]}" || die "${name}: docker compose cannot stop $(app_project)."
		files_note_change "stopped $(app_project)"
	fi
	file_remove "$(app_dir)"
	rmdir "${CTR_CONFIG_DIR}" 2>/dev/null || true
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		for secret in ${MOD_SECRETS:-}; do
			secret_remove "${secret}"
		done
	fi
	return
}
