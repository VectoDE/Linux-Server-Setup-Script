#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# lib/apps.sh: the Compose stacks of the app modules (files, secrets for a container user, start, site, checks,
# removal) against a stub docker.

setup() {
	load helpers
	lss_test_setup
	use_os debian-12
	shopt -s lastpipe
	LSS_MODULE=demo
	MOD_OPTIONS="domains||Host names
port|8081|Port on 127.0.0.1"
	CTR_CONFIG_DIR=${BATS_TEST_TMPDIR}/containers
	APP_DOCKER_CONFIG=${BATS_TEST_TMPDIR}/daemon.json
	APP_SUBUID=${BATS_TEST_TMPDIR}/subuid
	APP_SUBGID=${BATS_TEST_TMPDIR}/subgid
	printf '{"icc": false}\n' >"${APP_DOCKER_CONFIG}"
	ENGINE_LOG=${BATS_TEST_TMPDIR}/engine.log
	: >"${ENGINE_LOG}"
	APP_BACKUP_SCRIPT=${BATS_TEST_TMPDIR}/app-backup
	APP_BACKUP_REGISTRY=${BATS_TEST_TMPDIR}/app-backup.d
	APP_BACKUP_DIR=${BATS_TEST_TMPDIR}/lss-apps
	WRITES=${BATS_TEST_TMPDIR}/writes
	: >"${WRITES}"
	# file_write as the test user; the owner it was asked for goes to $WRITES ("== MODE OWNER DEST").
	eval "_lss_file_write() $(declare -f file_write | tail -n +2)"
	# shellcheck disable=SC2329 # called by the functions under test
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${WRITES}"
		_lss_file_write "$1" "${OWNER}" "$3"
		return
	}
}

# docker stub: records every call; "compose ... config --services" prints $SERVICES, "compose ... ps" prints
# $RUNNING, "compose ... config --format json" an empty stack, "compose version" and "info" succeed.
docker() {
	printf 'docker %s\n' "$*" >>"${ENGINE_LOG}"
	case $* in
	*"config --services"*) [[ -z ${SERVICES:-} ]] || tr ' ' '\n' <<<"${SERVICES}" ;;
	*"ps --status running --services"*) [[ -z ${RUNNING:-} ]] || tr ' ' '\n' <<<"${RUNNING}" ;;
	*"config --format json"*) printf '{"services": {}}\n' ;;
	*) ;;
	esac
	return "${DOCKER_EXIT:-0}"
}

@test "the stack of a module has its project name and directory" {
	[ "$(app_project)" = lss-demo ]
	[ "$(app_dir)" = "${CTR_CONFIG_DIR}/lss-demo" ]
	[ "$(app_compose_file)" = "${CTR_CONFIG_DIR}/lss-demo/compose.yaml" ]
}

@test "host names and ports are checked" {
	app_valid_domain cloud.example.com
	run app_valid_domain localhost
	[ "${status}" -eq 1 ]
	run app_valid_domain Cloud.Example.com
	[ "${status}" -eq 1 ]
	config_set LSS_DEMO_DOMAINS 'a.example.com b.example.org'
	app_check_domains
	config_set LSS_DEMO_DOMAINS 'a.example.com bad_name'
	run app_check_domains
	[ "${status}" -eq 1 ]
	[[ ${output} == *"LSS_DEMO_DOMAINS: 'bad_name' is not a host name like demo.example.com"* ]]
	app_check_port port
	config_set LSS_DEMO_PORT 80
	run app_check_port port
	[[ ${output} == *"must be a port from 1024 to 65535"* ]]
	config_set LSS_DEMO_PORT "${WEB_ADMIN_PORT}"
	run app_check_port port
	[[ ${output} == *"must differ from the admin port"* ]]
}

@test "without host names the app is named after the module below the server's name" {
	# shellcheck disable=SC2329 # called by app_domains
	hostname() {
		printf 'Server1.Example.com\n'
	}
	[ "$(app_domains)" = demo.server1.example.com ]
	config_set LSS_DEMO_DOMAINS 'cloud.example.com www.example.com'
	[ "$(app_domains)" = 'cloud.example.com www.example.com' ]
	[ "$(app_domain)" = cloud.example.com ]
}

@test "container users are mapped into Docker's user namespace" {
	[ "$(app_host_owner 1000)" = 1000:1000 ]
	[ "$(app_host_owner 33:44)" = 33:44 ]
	printf '{"userns-remap": "default"}\n' >"${APP_DOCKER_CONFIG}"
	printf 'admin:100000:65536\ndockremap:231072:65536\n' >"${APP_SUBUID}"
	printf 'dockremap:231072:65536\n' >"${APP_SUBGID}"
	[ "$(app_host_owner 0)" = 231072:231072 ]
	[ "$(app_host_owner 70:71)" = 231142:231143 ]
	printf '{"userns-remap": "remap:remap"}\n' >"${APP_DOCKER_CONFIG}"
	run app_host_owner 0
	[ "${status}" -eq 1 ]
	[[ ${output} == *"has no ID range for remap"* ]]
	run app_host_owner www-data
	[[ ${output} == *"'www-data' is not UID or UID:GID"* ]]
}

@test "secrets are copied for the container user without a final newline" {
	printf '{"userns-remap": "default"}\n' >"${APP_DOCKER_CONFIG}"
	printf 'dockremap:100000:65536\n' | tee "${APP_SUBUID}" >"${APP_SUBGID}"
	app_secret demo-db-password 999:70 40
	local copy=${CTR_CONFIG_DIR}/lss-demo/secrets/demo-db-password
	grep -qxF "== 0400 100999:100070 ${copy}" "${WRITES}"
	[ "$(stat -c '%a' "${copy}")" = 400 ]
	cmp -s "${copy}" "${LSS_SECRETS_DIR}/demo-db-password"
	[ "$(wc -c <"${copy}")" -eq 40 ]
	[ "${APP_CHANGED}" = 1 ]
	APP_CHANGED=0
	app_secret demo-db-password 999:70 40
	[ "${APP_CHANGED}" = 0 ]
	app_secret demo-db-password 999:70 40 db-password.app
	[ -f "${CTR_CONFIG_DIR}/lss-demo/secrets/db-password.app" ]
	run app_file ../escape 0 0400 </dev/null
	[[ ${output} == *"is not a valid file name"* ]]
}

@test "service lines: hardening, limits and read-only mounts" {
	run app_hardening 512m 128
	[[ ${output} == *"cap_drop: [ALL]"* ]]
	[[ ${output} == *'security_opt: ["no-new-privileges:true"]'* ]]
	[[ ${output} == *"mem_limit: 512m"*"memswap_limit: 512m"*"pids_limit: 128"* ]]
	[[ ${output} == *"read_only: true"* ]]
	[[ ${output} != *lss.writable* ]]
	run app_hardening 1g 256 writable
	[[ ${output} != *read_only* ]]
	[[ ${output} == *'lss.writable: "true"'* ]]
	[ "$(app_mount secrets/x /run/secrets/x)" = "      - ${CTR_CONFIG_DIR}/lss-demo/secrets/x:/run/secrets/x:ro,z" ]
}

@test "the stack starts after a change and when a service stopped, otherwise not" {
	command -v jq >/dev/null || skip "jq is not installed"
	LSS_MODULE=docker
	state_set docker status installed
	LSS_MODULE=demo
	printf 'services: {}\n' | app_compose
	[ "${APP_COMPOSE_CHANGED}" = 1 ]
	grep -qxF "== 0600 root:root $(app_compose_file)" "${WRITES}"
	SERVICES='app db' RUNNING='app db'
	app_up
	grep -q -- "up --detach --remove-orphans --quiet-pull$" "${ENGINE_LOG}"
	[ "${APP_COMPOSE_CHANGED}" = 0 ]
	: >"${ENGINE_LOG}"
	app_up
	run ! grep -q -- " up " "${ENGINE_LOG}"
	RUNNING='db'
	app_up
	grep -q -- " up --detach" "${ENGINE_LOG}"
	: >"${ENGINE_LOG}"
	RUNNING='app db'
	APP_CHANGED=1
	app_up
	grep -q -- "up --detach --remove-orphans --quiet-pull --force-recreate$" "${ENGINE_LOG}"
	[ "${APP_CHANGED}" = 0 ]
	DOCKER_EXIT=1 run app_up
	[[ ${output} == *"docker compose is missing"* ]]
}

@test "app_running needs every service of the stack" {
	SERVICES='' RUNNING=''
	run app_running
	[ "${status}" -eq 1 ]
	SERVICES='db app' RUNNING='app db'
	app_running
	SERVICES='db app' RUNNING='app'
	run app_running
	[ "${status}" -eq 1 ]
	app_exec app occ status
	grep -qxF "docker compose --project-name lss-demo -f ${CTR_CONFIG_DIR}/lss-demo/compose.yaml exec -T app occ status" "${ENGINE_LOG}"
}

@test "pages come from the web server of this server, with their status" {
	config_set LSS_DEMO_DOMAINS cloud.example.com
	# shellcheck disable=SC2329 # called by app_get
	curl() {
		printf 'curl %s\n' "$*" >>"${STUB_LOG}"
		printf '<html>login</html>\n%s' "${CURL_STATUS:-200}"
		return 0
	}
	local page
	page=$(app_get /status.php)
	[ "$(app_status "${page}")" = 200 ]
	grep -qF -- "--resolve cloud.example.com:443:127.0.0.1 https://cloud.example.com/status.php" "${STUB_LOG}"
	page=$(app_wait login 200 5)
	[[ ${page} == *login* ]]
	# shellcheck disable=SC2329 # called by app_wait
	sleep() {
		return 0
	}
	CURL_STATUS=502 run app_wait login 200 1
	[ "${status}" -eq 1 ]
	[[ ${output} == *"https://cloud.example.com/login answers 502 instead of 200"* ]]
}

@test "the site proxies to 127.0.0.1 for every host name and gets a certificate with tls" {
	config_set LSS_DEMO_DOMAINS 'cloud.example.com www.example.com'
	# shellcheck disable=SC2329 # called by app_site
	web_cert_placeholder() {
		printf 'placeholder %s\n' "$*" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by app_site
	web_site_write() {
		printf 'site %s\n' "$*" >>"${STUB_LOG}"
		LSS_FILE_CHANGED=1
	}
	# shellcheck disable=SC2329 # called by app_site
	web_reload() {
		printf 'reload\n' >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by app_site
	web_cert_issue() {
		printf 'issue %s\n' "$*" >>"${STUB_LOG}"
	}
	app_site 8081
	grep -qxF 'placeholder demo cloud.example.com www.example.com' "${STUB_LOG}"
	grep -qxF 'site demo proxy http://127.0.0.1:8081 cloud.example.com www.example.com' "${STUB_LOG}"
	grep -qxF reload "${STUB_LOG}"
	run ! grep -q '^issue' "${STUB_LOG}"
	state_set tls status installed
	app_site 8081
	grep -qxF 'issue demo cloud.example.com www.example.com' "${STUB_LOG}"
}

@test "verify checks the files, the rules, the containers and the headers of the site" {
	command -v jq >/dev/null || skip "jq is not installed"
	# shellcheck disable=SC2329 # called by app_verify_stack
	stat() {
		printf '600 root\n'
	}
	run app_verify_stack
	[[ ${output} == *"compose.yaml is missing"* ]]
	printf 'services: {}\n' | app_compose
	SERVICES='app' RUNNING=''
	run app_verify_stack
	[[ ${output} == *"a container of lss-demo is not running"* ]]
	RUNNING='app'
	# shellcheck disable=SC2329 # called by app_verify_stack
	curl() {
		printf 'HTTP/2 200\r\n%s\r\n\n200' "${HEADER:-}"
		return 0
	}
	run app_verify_stack
	[[ ${output} == *"sends no Strict-Transport-Security header"* ]]
	HEADER='strict-transport-security: max-age=63072000'
	app_verify_stack
}

@test "removal stops the stack and keeps the data unless --purge" {
	MOD_SECRETS="demo-db-password"
	app_secret demo-db-password 0
	printf 'services: {}\n' | app_compose
	# shellcheck disable=SC2329 # called by app_remove
	web_server() {
		printf 'nginx'
	}
	# shellcheck disable=SC2329 # called by app_remove
	web_site_remove() {
		printf 'site-remove %s\n' "$*" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by app_remove
	web_reload() {
		return 0
	}
	app_remove
	grep -q -- "down --remove-orphans$" "${ENGINE_LOG}"
	grep -qxF 'site-remove demo' "${STUB_LOG}"
	[ ! -e "$(app_dir)" ]
	secret_exists demo-db-password
	printf 'services: {}\n' | app_compose
	LSS_PURGE=1 app_remove
	grep -q -- "down --remove-orphans --volumes$" "${ENGINE_LOG}"
	run secret_exists demo-db-password
	[ "${status}" -eq 1 ]
}

@test "database services run unprivileged on the internal network, with their password from a file" {
	run app_postgres cloud
	[[ ${output} == *"image: ${APP_POSTGRES_IMAGE}"* ]]
	[[ ${output} == *'user: "70:70"'* ]]
	[[ ${output} == *"POSTGRES_USER: cloud"*"POSTGRES_PASSWORD_FILE: /run/secrets/db-password"* ]]
	[[ ${output} == *"secrets/db-password.db:/run/secrets/db-password:ro,z"* ]]
	[[ ${output} == *"networks: [backend]"*"pg_isready"* ]]
	[[ ${output} == *"cap_drop: [ALL]"*"read_only: true"* ]]
	run app_mariadb shop
	[[ ${output} == *'user: "999:999"'* ]]
	[[ ${output} == *"MARIADB_PASSWORD_FILE: /run/secrets/db-password"*"MARIADB_ROOT_PASSWORD_FILE: /run/secrets/db-root-password"* ]]
	[[ ${output} == *"healthcheck.sh"* ]]
	run app_networks
	[[ ${output} == *"backend:"*"internal: true"* ]]
	run app_init data /data 1000:1000
	[[ ${output} == *'entrypoint: ["chown", "1000:1000", "/data"]'* ]]
	# Shared SELinux label: the app mounts the volume with another MCS category than init.
	[[ ${output} == *"- data:/data:z"* ]]
	[[ ${output} == *"network_mode: none"*"cap_drop: [ALL]"*"cap_add: [CHOWN]"*"read_only: true"* ]]
	[[ ${output} == *'restart: "no"'* ]]
}

@test "database secrets go to the database container and the app, each for its own user" {
	app_db_secrets postgres 33:33
	local dir=${CTR_CONFIG_DIR}/lss-demo/secrets
	grep -qxF "== 0400 70:70 ${dir}/db-password.db" "${WRITES}"
	grep -qxF "== 0400 33:33 ${dir}/db-password.app" "${WRITES}"
	cmp -s "${dir}/db-password.db" "${LSS_SECRETS_DIR}/demo-db-password"
	run ! grep -q db-root-password "${WRITES}"
	app_db_secrets mariadb 1000 app-db
	grep -qxF "== 0400 999:999 ${dir}/db-root-password.db" "${WRITES}"
	grep -qxF "== 0400 1000:1000 ${dir}/app-db" "${WRITES}"
	secret_exists demo-db-root-password
}

@test "the one-shot init service does not count as a stopped service" {
	SERVICES='app init' RUNNING='app'
	app_running
	SERVICES='app db init' RUNNING='db'
	run app_running
	[ "${status}" -eq 1 ]
}

@test "logins for curl go through a private netrc file" {
	config_set LSS_DEMO_DOMAINS cloud.example.com
	secret_set demo-admin-password 'S3cret'
	local file
	file=$(app_netrc admin demo-admin-password)
	[ "$(stat -c '%a' "${file}")" = 600 ]
	[ "$(cat "${file}")" = 'machine cloud.example.com login admin password S3cret' ]
	rm -f -- "${file}"
}

@test "the host names of another app come from its settings or the server's name" {
	# shellcheck disable=SC2329 # called by app_domains_of
	hostname() {
		printf 'srv.example.com\n'
	}
	[ "$(app_domains_of collabora)" = collabora.srv.example.com ]
	config_set LSS_COLLABORA_DOMAINS 'office.example.com docs.example.com'
	[ "$(app_domains_of collabora)" = 'office.example.com docs.example.com' ]
}

@test "Nextcloud Office is linked once both apps are there, trusting the certificate of the collabora site" {
	config_set LSS_COLLABORA_DOMAINS office.example.com
	# shellcheck disable=SC2329 # called by app_collabora_check
	curl() {
		printf 'curl %s\n' "$*" >>"${STUB_LOG}"
		printf '{"status": "Ok"}\n200'
	}
	LSS_MODULE=collabora
	app_nextcloud_office
	[ ! -s "${ENGINE_LOG}" ]
	state_set nextcloud status installed
	WEB_TLS_DIR=${BATS_TEST_TMPDIR}/tls
	mkdir -p "${WEB_TLS_DIR}/collabora"
	printf 'CERT\n' >"${WEB_TLS_DIR}/collabora/fullchain.pem"
	app_nextcloud_office
	local occ="docker compose --project-name lss-nextcloud -f ${CTR_CONFIG_DIR}/lss-nextcloud/compose.yaml exec -T app php occ"
	grep -qxF "${occ} app:install richdocuments" "${ENGINE_LOG}"
	grep -qxF "${occ} config:app:set richdocuments wopi_url --value=https://office.example.com" "${ENGINE_LOG}"
	grep -qF "exec -T app sh -c cat >/tmp/lss-web.pem" "${ENGINE_LOG}"
	grep -qxF "${occ} security:certificates:import /tmp/lss-web.pem" "${ENGINE_LOG}"
	grep -qxF "${occ} richdocuments:activate-config" "${ENGINE_LOG}"
	grep -q '^curl .*--resolve office.example.com:443:127.0.0.1 -X POST .*https://office.example.com/hosting/wopiAccessCheck$' "${STUB_LOG}"
	[ -n "$(state_get nextcloud trusted_cert)" ]
	: >"${ENGINE_LOG}"
	app_nextcloud_office
	run ! grep -q 'certificates:import' "${ENGINE_LOG}"
	# With the tls module, only a private CA needs trusting.
	state_set tls status installed
	[ -z "$(_app_route_trust collabora)" ]
	printf 'CA\n' >"${BATS_TEST_TMPDIR}/ca.pem"
	config_set LSS_TLS_CA_BUNDLE "${BATS_TEST_TMPDIR}/ca.pem"
	[ "$(_app_route_trust collabora)" = "${BATS_TEST_TMPDIR}/ca.pem" ]
	DOCKER_EXIT=1 run app_nextcloud_office
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Nextcloud Office (richdocuments) cannot be installed"* ]]
}

@test "timers run a command in a container of the stack and go away on removal" {
	# shellcheck disable=SC2329 # called by app_timer
	svc_unit() {
		printf -- '--- %s\n' "$1" >>"${STUB_LOG}"
		cat >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by app_timer
	svc_enable() {
		printf 'enable %s\n' "$1" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by app_timer_remove
	svc_disable() {
		printf 'disable %s\n' "$1" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by app_timer_remove
	file_remove() {
		printf 'remove %s\n' "$1" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by app_timer_remove
	svc_daemon_reload() {
		return 0
	}
	app_timer demo-cron 5min "Demo jobs" app php -f cron.php
	grep -qxF -- '--- lss-demo-cron.service' "${STUB_LOG}"
	grep -qxF "ExecStart=docker compose --project-name lss-demo -f ${CTR_CONFIG_DIR}/lss-demo/compose.yaml exec -T app php -f cron.php" "${STUB_LOG}"
	grep -qxF 'OnUnitActiveSec=5min' "${STUB_LOG}"
	grep -qxF 'enable lss-demo-cron.timer' "${STUB_LOG}"
	app_timer_remove demo-cron
	grep -qxF 'disable lss-demo-cron.timer' "${STUB_LOG}"
	grep -qxF 'remove /etc/systemd/system/lss-demo-cron.service' "${STUB_LOG}"
}

@test "a second site of an app has its own name and host names, and goes away with its certificate" {
	# shellcheck disable=SC2329 # called by app_site
	web_cert_placeholder() {
		return 0
	}
	# shellcheck disable=SC2329 # called by app_site
	web_site_write() {
		printf 'site %s\n' "$*" >>"${STUB_LOG}"
		LSS_FILE_CHANGED=0
	}
	app_site 8092 demo-console console.example.com
	grep -qxF 'site demo-console proxy http://127.0.0.1:8092 console.example.com' "${STUB_LOG}"
	# shellcheck disable=SC2329 # called by app_site_remove
	web_server() {
		printf 'caddy'
	}
	# shellcheck disable=SC2329 # called by app_site_remove
	web_site_remove() {
		printf 'site-remove %s\n' "$*" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by app_site_remove
	web_reload() {
		return 0
	}
	# shellcheck disable=SC2329 # called by app_site_remove
	certbot() {
		printf 'certbot %s\n' "$*" >>"${STUB_LOG}"
	}
	WEB_TLS_DIR=${BATS_TEST_TMPDIR}/tls
	WEB_CERT_LIVE=${BATS_TEST_TMPDIR}/live
	mkdir -p "${WEB_CERT_LIVE}/demo-console"
	app_site_remove demo-console
	grep -qxF 'site-remove demo-console' "${STUB_LOG}"
	grep -qxF 'certbot delete --non-interactive --cert-name demo-console' "${STUB_LOG}"
}

@test "pages of a second host name of the app" {
	config_set LSS_DEMO_DOMAINS cloud.example.com
	# shellcheck disable=SC2329 # called by app_get
	curl() {
		printf 'curl %s\n' "$*" >>"${STUB_LOG}"
		printf 'ok\n200'
	}
	APP_GET_DOMAIN=console.example.com app_get login >/dev/null
	grep -qF -- "--resolve console.example.com:443:127.0.0.1 https://console.example.com/login" "${STUB_LOG}"
}

@test "Collabora trusts the host CAs and the Nextcloud route, and starts again when Nextcloud comes second" {
	config_set LSS_NEXTCLOUD_DOMAINS cloud.example.com
	config_set LSS_COLLABORA_DOMAINS office.example.com
	WEB_TLS_DIR=${BATS_TEST_TMPDIR}/tls
	mkdir -p "${WEB_TLS_DIR}/nextcloud" "${WEB_TLS_DIR}/default"
	printf 'DEFAULT\n' >"${WEB_TLS_DIR}/default/fullchain.pem"
	local trust="${CTR_CONFIG_DIR}/lss-collabora/trust/ca.pem"
	# Collabora alone: the CAs of the host (or the default certificate on a host without a bundle).
	app_collabora_trust
	[ -s "${trust}" ]
	grep -qxF "== 0444 root:root ${trust}" "${WRITES}"
	run ! grep -qxF NEXTCLOUD "${trust}"
	# With the Nextcloud route: its self-signed certificate too.
	printf 'NEXTCLOUD\n' >"${WEB_TLS_DIR}/nextcloud/fullchain.pem"
	app_collabora_trust
	[ "${LSS_FILE_CHANGED}" = 1 ]
	grep -qxF NEXTCLOUD "${trust}"
	app_collabora_trust
	[ "${LSS_FILE_CHANGED}" = 0 ]
	# Nextcloud second: Collabora gets the new certificate and starts again before the access check.
	# shellcheck disable=SC2329 # called by app_nextcloud_office
	curl() {
		printf 'curl %s\n' "$*" >>"${STUB_LOG}"
		printf '{"status": "Ok"}\n200'
	}
	command -v jq >/dev/null || skip "jq is not installed"
	state_set docker status installed
	state_set collabora status installed
	printf 'services: {}\n' >"${CTR_CONFIG_DIR}/lss-collabora/compose.yaml"
	printf 'NEXTCLOUD 2\n' >"${WEB_TLS_DIR}/nextcloud/fullchain.pem"
	LSS_MODULE=nextcloud
	app_nextcloud_office
	grep -q "compose --project-name lss-collabora .* up .*--force-recreate" "${ENGINE_LOG}"
	grep -q '^curl .* https://office.example.com/hosting/wopiAccessCheck$' "${STUB_LOG}"
	grep -qxF 'NEXTCLOUD 2' "${trust}"
}

@test "the WOPI access check of Collabora must reach Nextcloud with a valid certificate" {
	config_set LSS_NEXTCLOUD_DOMAINS cloud.example.com
	config_set LSS_COLLABORA_DOMAINS office.example.com
	# shellcheck disable=SC2329 # called by app_collabora_check
	curl() {
		printf 'curl %s\n' "$*" >>"${STUB_LOG}"
		printf '%s\n%s' "${ANSWER}" "${CODE:-200}"
	}
	ANSWER='{"status": "Ok"}' app_collabora_check
	grep -qF -- '--data {"callbackUrl":"https://cloud.example.com/status.php"}' "${STUB_LOG}"
	ANSWER='{"status": "SelfSignedCertificate"}' run app_collabora_check
	[ "${status}" -eq 1 ]
	[[ ${output} == *'cannot reach Nextcloud at https://cloud.example.com with a valid certificate ({"status": "SelfSignedCertificate"}'* ]]
	ANSWER='{"status": "Ok"}' CODE=502 run app_collabora_check
	[ "${status}" -eq 1 ]
}

@test "an app registers its data for the backup, which verify saves and removal forgets" {
	app_backup DB=postgres DB_USER=demo LIVE=html 'COPY=data cache'
	local conf="${APP_BACKUP_REGISTRY}/demo.conf"
	grep -qxF "== 0755 root:root ${APP_BACKUP_SCRIPT}" "${WRITES}"
	cmp "${REPO_ROOT}/libexec/lss-app-backup" "${APP_BACKUP_SCRIPT}"
	grep -qxF "== 0600 root:root ${conf}" "${WRITES}"
	grep -qxF PROJECT=lss-demo "${conf}"
	grep -qxF "COMPOSE=${CTR_CONFIG_DIR}/lss-demo/compose.yaml" "${conf}"
	grep -qxF DB=postgres "${conf}"
	grep -qxF DB_USER=demo "${conf}"
	grep -qxF 'COPY=data cache' "${conf}"
	grep -qxF LIVE=html "${conf}"
	grep -qxF PATHS= "${conf}"
	run app_backup DATABASE=postgres
	[[ ${output} == *"app_backup does not know 'DATABASE=postgres'"* ]]
	run app_backup 'PATHS=/srv;rm'
	[ "${status}" -eq 1 ]
	# verify runs the script for this app; a database app needs a dump.
	printf '#!/bin/sh\necho "save $*" >>"%s"\n' "${STUB_LOG}" >"${APP_BACKUP_SCRIPT}"
	chmod +x "${APP_BACKUP_SCRIPT}"
	run app_verify_backup
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the database dump for the backup is empty"* ]]
	grep -qxF 'save demo' "${STUB_LOG}"
	mkdir -p "${APP_BACKUP_DIR}/demo"
	printf 'SQL\n' >"${APP_BACKUP_DIR}/demo/db.sql"
	app_verify_backup
	printf '#!/bin/sh\nexit 1\n' >"${APP_BACKUP_SCRIPT}"
	run app_verify_backup
	[[ ${output} == *"saving the data of the app for the backup fails"* ]]
	# Removal keeps the saved data unless --purge; the script goes with the last app.
	app_backup_remove
	[ ! -e "${conf}" ]
	[ ! -e "${APP_BACKUP_REGISTRY}" ]
	[ ! -e "${APP_BACKUP_SCRIPT}" ]
	[ -s "${APP_BACKUP_DIR}/demo/db.sql" ]
	run app_verify_backup
	[[ ${output} == *"the backup would leave the app out"* ]]
	app_backup COPY=data
	LSS_PURGE=1 app_backup_remove
	[ ! -e "${APP_BACKUP_DIR}/demo" ]
}
