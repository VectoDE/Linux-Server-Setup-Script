# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="n8n"
MOD_GROUP="apps"
MOD_DESCRIPTION="n8n 2 (workflow automation) with PostgreSQL as a Docker Compose stack behind the web server, with the owner account already created and telemetry off"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the n8n site, separated by spaces; empty: n8n.<host name of the server>
port|8089|Port of the n8n container on 127.0.0.1, which the web server forwards to
owner_email||E-mail address of the owner account (its login); empty: admin@<first host name>
memory|1g|Memory limit of the n8n container"
MOD_SECRETS="n8n-owner-password n8n-encryption-key n8n-db-password"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# n8n 2.44.2 (runs as node, 1000:1000), the multi-architecture index (amd64 and arm64), checked 2026-10-15.
N8N_IMAGE=docker.io/n8nio/n8n@sha256:b57e7a9c8e5ab1a8fe9b03fff3158052aec65f571ed1f759897a20f306ad329d
N8N_USER=1000:1000
# n8n binds a browser session to this header; the requests of mod_verify send the same one throughout.
N8N_BROWSER_ID=lss-verify

mod_check() {
	app_check_domains
	app_check_port port
	[[ -z $(opt owner_email) || $(opt owner_email) =~ ^[^@[:space:]]+@[^@[:space:]]+\.[a-z]+$ ]] ||
		die "LSS_N8N_OWNER_EMAIL must be an e-mail address."
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_N8N_MEMORY must be a size such as 1g or 768m."
	return
}

mod_install() {
	app_compose_ready
	return
}

_n8n_email() {
	local email
	email=$(opt owner_email)
	[[ -n ${email} ]] || email=admin@$(app_domain)
	printf '%s' "${email}"
	return
}

# _n8n_compose: the stack. Every secret reaches n8n as a file (*_FILE); the frontend cache and /tmp are the only
# writable paths besides the volume.
_n8n_compose() {
	local domain
	domain=$(app_domain)
	cat <<EOF
# Managed by lss (module n8n). Change LSS_N8N_* in /etc/lss/lss.conf and run lss configure n8n.
name: $(app_project)
services:
  app:
    image: ${N8N_IMAGE}
    user: "${N8N_USER}"
    depends_on:
      db:
        condition: service_healthy
    environment:
      DB_TYPE: postgresdb
      DB_POSTGRESDB_HOST: db
      DB_POSTGRESDB_DATABASE: n8n
      DB_POSTGRESDB_USER: n8n
      DB_POSTGRESDB_PASSWORD_FILE: /run/secrets/db-password
      N8N_ENCRYPTION_KEY_FILE: /run/secrets/encryption-key
      N8N_HOST: ${domain}
      N8N_PROTOCOL: https
      N8N_PORT: "5678"
      N8N_EDITOR_BASE_URL: https://${domain}/
      WEBHOOK_URL: https://${domain}/
      N8N_PROXY_HOPS: "1"
      N8N_DIAGNOSTICS_ENABLED: "false"
      N8N_VERSION_NOTIFICATIONS_ENABLED: "false"
      N8N_TEMPLATES_ENABLED: "false"
      N8N_PERSONALIZATION_ENABLED: "false"
      N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS: "true"
      N8N_LOG_LEVEL: warn
      GENERIC_TIMEZONE: UTC
    ports:
      - 127.0.0.1:$(opt_int port):5678
    volumes:
      - data:/home/node/.n8n
$(app_mount secrets/db-password.app /run/secrets/db-password)
$(app_mount secrets/encryption-key /run/secrets/encryption-key)
    tmpfs:
      - /tmp:mode=1777,size=256m
      - /home/node/.cache:mode=1777,size=256m
    networks: [default, backend]
$(app_hardening "$(opt memory)" 1024)
$(app_postgres n8n)
volumes:
  data:
  db:
$(app_networks)
EOF
	return
}

# _n8n_password: the password of the owner, which n8n wants with an upper case letter and a digit.
_n8n_password() {
	local value
	secret_exists n8n-owner-password && return 0
	value=$(secret_random 30)
	secret_set n8n-owner-password "${value}Q7"
	return
}

# _n8n_body FILE JQ-ARGS...: writes a JSON body with the owner password (read from the secret by jq) to FILE.
_n8n_body() {
	local file=$1 filter=$2
	shift 2
	jq -n --rawfile password "$(secret_path n8n-owner-password)" --arg email "$(_n8n_email)" "$@" "${filter}" >"${file}"
	return
}

# _n8n_owner: the owner account (POST /rest/owner/setup, possible once, before anybody logs in).
_n8n_owner() {
	local body page status
	_n8n_password
	body=$(mktemp)
	chmod 600 "${body}"
	# shellcheck disable=SC2016 # jq variables
	_n8n_body "${body}" '{email: $email, firstName: "Server", lastName: "Admin", password: $password}'
	page=$(app_get rest/owner/setup -X POST -H 'Content-Type: application/json' --data-binary "@${body}") || true
	rm -f -- "${body}"
	status=$(app_status "${page}")
	if [[ ${status} == 200 ]]; then
		log_info "n8n: created the owner $(_n8n_email); password in $(secret_path n8n-owner-password)"
		files_note_change "created the n8n owner"
	elif [[ ${status} != 400 ]] || ! grep -qi 'already setup' <<<"${page}"; then
		die "n8n: the owner cannot be created (HTTP ${status})."
	fi
	return
}

mod_configure() {
	app_db_secrets postgres "${N8N_USER}"
	app_secret n8n-encryption-key "${N8N_USER}" 48 encryption-key
	_n8n_compose | app_compose
	app_backup DB=postgres DB_USER=n8n LIVE=data
	app_up
	app_site "$(opt_int port)"
	app_wait healthz/readiness 200 >/dev/null || die "n8n: https://$(app_domain)/healthz/readiness does not answer."
	_n8n_owner
	return
}

# _n8n_rest JAR PATH [CURL OPTION...]: a request to the REST API of the editor in the session of JAR.
_n8n_rest() {
	local jar=$1 path=$2
	shift 2
	app_get "rest/${path}" -b "${jar}" -c "${jar}" -H "browser-id: ${N8N_BROWSER_ID}" -H 'Content-Type: application/json' "$@"
	return
}

mod_verify() {
	local page jar body id name
	app_verify_stack
	app_verify_backup
	page=$(app_wait healthz/readiness 200) || die "n8n: https://$(app_domain)/healthz/readiness does not answer."
	page=$(app_wait signin 200 60) || die "n8n: the sign-in page does not answer."
	grep -qi 'n8n' <<<"${page}" || die "n8n: https://$(app_domain)/signin is not n8n."
	# Used, not only running: the owner logs in, creates a workflow, reads it back and deletes it.
	jar=$(mktemp)
	body=$(mktemp)
	chmod 600 "${body}"
	# shellcheck disable=SC2016 # jq variables
	_n8n_body "${body}" '{emailOrLdapLoginId: $email, email: $email, password: $password}'
	page=$(_n8n_rest "${jar}" login -X POST --data-binary "@${body}") || true
	rm -f -- "${body}"
	if [[ $(app_status "${page}") != 200 ]]; then
		rm -f -- "${jar}"
		die "n8n: the owner $(_n8n_email) cannot log in (HTTP $(app_status "${page}"))."
	fi
	name="lss-verify-$(date +%s)"
	page=$(_n8n_rest "${jar}" workflows -X POST -d "{\"name\":\"${name}\",\"nodes\":[],\"connections\":{},\"settings\":{}}")
	id=$(jq -r '.data.id // empty' <<<"${page%$'\n'*}" 2>/dev/null) || id=''
	if [[ -z ${id} ]]; then
		rm -f -- "${jar}"
		die "n8n: creating a workflow answers $(app_status "${page}")."
	fi
	page=$(_n8n_rest "${jar}" "workflows/${id}")
	if [[ $(jq -r '.data.name // empty' <<<"${page%$'\n'*}" 2>/dev/null) != "${name}" ]]; then
		rm -f -- "${jar}"
		die "n8n: the new workflow does not come back."
	fi
	# n8n 2 deletes only archived workflows.
	_n8n_rest "${jar}" "workflows/${id}/archive" -X POST -d '{}' >/dev/null || true
	page=$(_n8n_rest "${jar}" "workflows/${id}" -X DELETE)
	rm -f -- "${jar}"
	[[ $(app_status "${page}") == 200 ]] || die "n8n: deleting the test workflow answers $(app_status "${page}")."
	return
}

mod_remove() {
	app_remove
	return
}
