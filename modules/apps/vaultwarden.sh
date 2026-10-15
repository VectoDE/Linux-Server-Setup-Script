# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="vaultwarden"
MOD_GROUP="apps"
MOD_DESCRIPTION="Vaultwarden 1.37 (password manager, compatible with the Bitwarden apps) as a Docker Compose stack behind the web server; no open registration, users are invited from the admin page"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the Vaultwarden site, separated by spaces; empty: vaultwarden.<host name of the server>
port|8085|Port of the Vaultwarden container on 127.0.0.1, which the web server forwards to
memory|512m|Memory limit of the Vaultwarden container"
MOD_SECRETS="vaultwarden-admin-token"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# Vaultwarden 1.37.4, the multi-architecture index (amd64 and arm64), checked 2026-10-15.
VW_IMAGE=docker.io/vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055
# Not the root user of the image: an unprivileged user that owns only the data volume.
VW_USER=1000:1000

mod_check() {
	app_check_domains
	app_check_port port
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_VAULTWARDEN_MEMORY must be a size such as 512m or 1g."
	return
}

mod_install() {
	app_compose_ready
	# argon2 hashes the admin token (EPEL on the RHEL family).
	pkg_enable_epel
	pkg_install argon2
	return
}

_vw_compose() {
	cat <<EOF
# Managed by lss (module vaultwarden). Change LSS_VAULTWARDEN_* in /etc/lss/lss.conf and run lss configure vaultwarden.
name: $(app_project)
services:
  app:
    image: ${VW_IMAGE}
    user: "${VW_USER}"
    depends_on:
      init:
        condition: service_completed_successfully
    environment:
      DOMAIN: https://$(app_domain)
      ROCKET_PORT: "8080"
      ADMIN_TOKEN_FILE: /run/secrets/admin-token
      SIGNUPS_ALLOWED: "false"
      INVITATIONS_ALLOWED: "true"
      PASSWORD_HINTS_ALLOWED: "false"
      SHOW_PASSWORD_HINT: "false"
      IP_HEADER: X-Forwarded-For
      LOG_LEVEL: warn
    ports:
      - 127.0.0.1:$(opt_int port):8080
    volumes:
      - data:/data
$(app_mount secrets/admin-token /run/secrets/admin-token)
    tmpfs:
      - /tmp:mode=1777,size=64m
$(app_hardening "$(opt memory)" 256)
$(app_init data /data "${VW_USER}")
volumes:
  data:
EOF
	return
}

# _vw_admin_token: the admin token is the secret vaultwarden-admin-token; the container only gets its Argon2id hash
# (PHC string), made again when the secret changes.
_vw_admin_token() {
	local token sum salt hash
	secret_load vaultwarden-admin-token token 48
	sum=$(printf '%s' "${token}" | sha256sum | cut -d ' ' -f 1)
	if [[ $(state_get vaultwarden token_sum) == "${sum}" && -s $(app_dir)/secrets/admin-token ]]; then
		return 0
	fi
	salt=$(secret_random 32)
	# The settings Vaultwarden recommends (Bitwarden defaults: 64 MiB, 3 iterations, 4 lanes).
	hash=$(printf '%s' "${token}" | argon2 "${salt}" -e -id -k 65540 -t 3 -p 4) || die "vaultwarden: argon2 cannot hash the admin token."
	[[ ${hash} == "\$argon2id\$"* ]] || die "vaultwarden: argon2 printed no Argon2id hash."
	printf '%s' "${hash}" | app_file secrets/admin-token "${VW_USER}" 0400
	state_set vaultwarden token_sum "${sum}"
	return
}

mod_configure() {
	_vw_admin_token
	_vw_compose | app_compose
	app_up
	app_site "$(opt_int port)"
	app_wait alive 200 >/dev/null || die "vaultwarden: https://$(app_domain)/alive does not answer."
	log_info "vaultwarden: the admin page is https://$(app_domain)/admin; token in $(secret_path vaultwarden-admin-token)"
	return
}

# _vw_admin JAR PATH [CURL OPTION...]: a request to the admin page with the session in the cookie file JAR.
_vw_admin() {
	local jar=$1 path=$2
	shift 2
	app_get "admin/${path}" -b "${jar}" -c "${jar}" "$@"
	return
}

mod_verify() {
	local page jar email id status
	app_verify_stack
	page=$(app_wait alive 200) || die "vaultwarden: https://$(app_domain)/alive does not answer."
	page=$(app_wait '' 200 60) || die "vaultwarden: the web vault does not answer."
	grep -qi 'bitwarden\|vaultwarden' <<<"${page}" || die "vaultwarden: https://$(app_domain)/ is not the web vault."
	# Used, not only running: log in to the admin page with the token, invite a user, find and delete it.
	jar=$(mktemp)
	email="lss-verify-$(date +%s)@example.com"
	status=$(app_status "$(_vw_admin "${jar}" '' -X POST --data-urlencode "token@$(secret_path vaultwarden-admin-token)")")
	if [[ ${status} != 200 && ${status} != 303 ]] || ! grep -q 'VW_ADMIN' "${jar}"; then
		rm -f -- "${jar}"
		die "vaultwarden: the admin token is not accepted (HTTP ${status})."
	fi
	page=$(_vw_admin "${jar}" invite -X POST -H 'Content-Type: application/json' -d "{\"email\":\"${email}\"}")
	if [[ $(app_status "${page}") != 200 ]]; then
		rm -f -- "${jar}"
		die "vaultwarden: inviting a user answers $(app_status "${page}")."
	fi
	page=$(_vw_admin "${jar}" users -H 'Accept: application/json')
	id=$(jq -r --arg email "${email}" '.[] | select(.email == $email) | .id' <<<"${page%$'\n'*}" 2>/dev/null) || id=''
	if [[ -z ${id} ]]; then
		rm -f -- "${jar}"
		die "vaultwarden: the invited user is missing from the user list."
	fi
	status=$(app_status "$(_vw_admin "${jar}" "users/${id}/delete" -X POST)")
	rm -f -- "${jar}"
	[[ ${status} == 200 ]] || die "vaultwarden: deleting the invited user answers ${status}."
	return
}

mod_remove() {
	app_remove
	[[ ${LSS_PURGE:-0} != 1 ]] || state_set vaultwarden token_sum ''
	return
}
