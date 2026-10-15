# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="keycloak"
MOD_GROUP="apps"
MOD_DESCRIPTION="Keycloak 26 (single sign-on with OpenID Connect and SAML) with PostgreSQL as a Docker Compose stack behind the web server"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the Keycloak site, separated by spaces; empty: keycloak.<host name of the server>
port|8086|Port of the Keycloak container on 127.0.0.1, which the web server forwards to
admin_user|admin|Name of the first administrator of the master realm (the password is the secret keycloak-admin-password)
memory|1536m|Memory limit of the Keycloak container"
MOD_SECRETS="keycloak-admin-password keycloak-db-password"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# Keycloak 26.8.1 (runs as keycloak, 1000:0), the multi-architecture index (amd64 and arm64), checked 2026-10-15.
KC_IMAGE=quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244
KC_USER=1000:0

mod_check() {
	app_check_domains
	app_check_port port
	[[ $(opt admin_user) =~ ^[a-z][a-z0-9._-]{1,31}$ ]] || die "LSS_KEYCLOAK_ADMIN_USER must be a lowercase login name."
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_KEYCLOAK_MEMORY must be a size such as 1536m or 2g."
	return
}

mod_install() {
	app_compose_ready
	return
}

# _kc_compose: the stack. The passwords reach Keycloak in a configuration file (KC_CONFIG_FILE), not in the
# environment. "start" builds the server for PostgreSQL and the health checks on the first start and writes below
# /opt/keycloak, so the root file system stays writable.
_kc_compose() {
	cat <<EOF
# Managed by lss (module keycloak). Change LSS_KEYCLOAK_* in /etc/lss/lss.conf and run lss configure keycloak.
name: $(app_project)
services:
  app:
    image: ${KC_IMAGE}
    user: "${KC_USER}"
    command: ["start"]
    depends_on:
      db:
        condition: service_healthy
    environment:
      KC_CONFIG_FILE: /run/secrets/keycloak.conf
      KC_DB: postgres
      KC_DB_URL_HOST: db
      KC_DB_URL_DATABASE: keycloak
      KC_DB_USERNAME: keycloak
      KC_HOSTNAME: https://$(app_domain)
      KC_HTTP_ENABLED: "true"
      KC_PROXY_HEADERS: xforwarded
      KC_PROXY_TRUSTED_ADDRESSES: 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
      KC_HEALTH_ENABLED: "true"
      KC_BOOTSTRAP_ADMIN_USERNAME: "$(opt admin_user)"
      KC_LOG_LEVEL: warn
    ports:
      - 127.0.0.1:$(opt_int port):8080
    volumes:
$(app_mount secrets/keycloak.conf /run/secrets/keycloak.conf)
    tmpfs:
      - /tmp:mode=1777,size=256m
    networks: [default, backend]
$(app_hardening "$(opt memory)" 1024 writable)
$(app_postgres keycloak)
volumes:
  db:
$(app_networks)
EOF
	return
}

# _kc_config: keycloak.conf with the database password and the password of the first administrator (it applies when
# Keycloak creates the master realm, on the first start).
_kc_config() {
	local db admin
	secret_load keycloak-db-password db 32
	secret_load keycloak-admin-password admin 32
	printf '# Managed by lss (module keycloak).\ndb-password=%s\nbootstrap-admin-password=%s\n' "${db}" "${admin}" |
		app_file secrets/keycloak.conf "${KC_USER}" 0400
	return
}

mod_configure() {
	app_secret keycloak-db-password "${APP_POSTGRES_USER}" 32 db-password.db
	_kc_config
	_kc_compose | app_compose
	app_up
	app_site "$(opt_int port)"
	app_wait realms/master/.well-known/openid-configuration 200 >/dev/null ||
		die "keycloak: the master realm at https://$(app_domain)/realms/master does not answer."
	log_info "keycloak: the admin console is https://$(app_domain)/admin/; user $(opt admin_user), password in $(secret_path keycloak-admin-password)"
	return
}

# _kc_token: an access token of the administrator (admin-cli, password grant); the password goes to curl as a file.
_kc_token() {
	local page
	page=$(app_get realms/master/protocol/openid-connect/token -X POST -d grant_type=password -d client_id=admin-cli \
		--data-urlencode "username=$(opt admin_user)" --data-urlencode "password@$(secret_path keycloak-admin-password)") || true
	[[ $(app_status "${page}") == 200 ]] || return 1
	jq -r '.access_token // empty' <<<"${page%$'\n'*}"
	return
}

mod_verify() {
	local page token headers user id status
	app_verify_stack
	page=$(app_wait realms/master/.well-known/openid-configuration 200) || die "keycloak: the master realm does not answer."
	[[ $(jq -r '.issuer' <<<"${page%$'\n'*}" 2>/dev/null) == "https://$(app_domain)/realms/master" ]] ||
		die "keycloak: the issuer is not https://$(app_domain)/realms/master (KC_HOSTNAME or the proxy headers are wrong)."
	# Used, not only running: the administrator logs in, creates a user through the admin API and deletes it.
	token=$(_kc_token) || die "keycloak: $(opt admin_user) cannot log in to the master realm."
	[[ -n ${token} ]] || die "keycloak: the login of $(opt admin_user) returned no token."
	headers=$(mktemp)
	printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "${token}" >"${headers}"
	user="lss-verify-$(date +%s)"
	status=$(app_status "$(app_get admin/realms/master/users -X POST -H "@${headers}" -d "{\"username\":\"${user}\",\"enabled\":false}")")
	if [[ ${status} != 201 ]]; then
		rm -f -- "${headers}"
		die "keycloak: creating a user answers ${status}."
	fi
	page=$(app_get "admin/realms/master/users?exact=true&username=${user}" -H "@${headers}")
	id=$(jq -r '.[0].id // empty' <<<"${page%$'\n'*}" 2>/dev/null) || id=''
	if [[ -z ${id} ]]; then
		rm -f -- "${headers}"
		die "keycloak: the new user is missing."
	fi
	status=$(app_status "$(app_get "admin/realms/master/users/${id}" -X DELETE -H "@${headers}")")
	rm -f -- "${headers}"
	[[ ${status} == 204 ]] || die "keycloak: deleting the test user answers ${status}."
	return
}

mod_remove() {
	app_remove
	return
}
