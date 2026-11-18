# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="forgejo"
MOD_GROUP="apps"
MOD_DESCRIPTION="Forgejo 16 (Git hosting) as a rootless Docker Compose stack behind the web server, with SQLite, Git over HTTPS only and no open registration"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the Forgejo site, separated by spaces; empty: forgejo.<host name of the server>
port|8083|Port of the Forgejo container on 127.0.0.1, which the web server forwards to
admin_user|lssadmin|Name of the first administrator (the password is the secret forgejo-admin-password)
admin_email||E-mail address of the first administrator; empty: ADMIN_USER@<first host name>
memory|1g|Memory limit of the Forgejo container"
MOD_SECRETS="forgejo-admin-password forgejo-secret-key forgejo-internal-token"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# Forgejo 16.0.6 rootless (runs as git, 1000:1000), the multi-architecture index (amd64 and arm64), checked
# 2026-10-15. A new release means a new digest here; Forgejo migrates its database when it starts.
FJ_IMAGE=codeberg.org/forgejo/forgejo@sha256:51b47921660e1ec7127f094208fe06901ba57df4fe6d59fcccc3a2419514a77f
FJ_USER=1000:1000

mod_check() {
	app_check_domains
	app_check_port port
	[[ $(opt admin_user) =~ ^[a-z][a-z0-9._-]{1,38}$ && $(opt admin_user) != admin ]] ||
		die "LSS_FORGEJO_ADMIN_USER must be a lowercase login name other than admin (reserved by Forgejo)."
	[[ -z $(opt admin_email) || $(opt admin_email) =~ ^[^@[:space:]]+@[^@[:space:]]+\.[a-z]+$ ]] ||
		die "LSS_FORGEJO_ADMIN_EMAIL must be an e-mail address."
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_FORGEJO_MEMORY must be a size such as 1g or 768m."
	return
}

mod_install() {
	app_compose_ready
	return
}

# _fj_email: the e-mail address of the first administrator.
_fj_email() {
	local email
	email=$(opt admin_email)
	[[ -n ${email} ]] || email=$(opt admin_user)@$(app_domain)
	printf '%s' "${email}"
	return
}

# _fj_compose: the stack. Forgejo reads its keys from files (the *_URI settings), so they are neither in app.ini nor
# in the environment. SSH stays off: Git works over HTTPS through the web server.
_fj_compose() {
	local domain
	domain=$(app_domain)
	cat <<EOF
# Managed by lss (module forgejo). Change LSS_FORGEJO_* in /etc/lss/lss.conf and run lss configure forgejo.
name: $(app_project)
services:
  app:
    image: ${FJ_IMAGE}
    user: "${FJ_USER}"
    environment:
      FORGEJO__database__DB_TYPE: sqlite3
      FORGEJO__security__INSTALL_LOCK: "true"
      FORGEJO__security__SECRET_KEY_URI: file:/run/secrets/secret-key
      FORGEJO__security__INTERNAL_TOKEN_URI: file:/run/secrets/internal-token
      FORGEJO__security__REVERSE_PROXY_TRUSTED_PROXIES: 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
      FORGEJO__server__DOMAIN: ${domain}
      FORGEJO__server__ROOT_URL: https://${domain}/
      FORGEJO__server__HTTP_PORT: "3000"
      FORGEJO__server__DISABLE_SSH: "true"
      FORGEJO__server__START_SSH_SERVER: "false"
      FORGEJO__service__DISABLE_REGISTRATION: "true"
      FORGEJO__service__REQUIRE_SIGNIN_VIEW: "false"
      FORGEJO__session__COOKIE_SECURE: "true"
      FORGEJO__openid__ENABLE_OPENID_SIGNIN: "false"
      FORGEJO__log__LEVEL: Warn
    ports:
      - 127.0.0.1:$(opt_int port):3000
    volumes:
      - data:/var/lib/gitea
$(app_mount secrets/secret-key /run/secrets/secret-key)
$(app_mount secrets/internal-token /run/secrets/internal-token)
    tmpfs:
      - /tmp:mode=1777,size=512m
$(app_hardening "$(opt memory)" 512)
volumes:
  data:
EOF
	return
}

# _fj ARG...: the forgejo command as git in the running container.
_fj() {
	app_exec app forgejo "$@"
	return
}

# _fj_admin: the first administrator, with a random password that Forgejo generates; it goes straight into the
# secret forgejo-admin-password (Forgejo takes a password only on its command line, where other users could see it).
_fj_admin() {
	local user output password
	user=$(opt admin_user)
	if _fj admin user list --admin 2>/dev/null | awk 'NR > 1 { print $2 }' | grep -qx -- "${user}"; then
		secret_exists forgejo-admin-password ||
			log_warn "forgejo: the administrator ${user} exists, but the secret forgejo-admin-password is missing."
		return 0
	fi
	output=$(_fj admin user create --username "${user}" --email "$(_fj_email)" --admin --random-password \
		--random-password-length 32 --must-change-password=false 2>&1) || {
		log_error "forgejo: $(grep -v 'generated random password' <<<"${output}")"
		die "forgejo: the administrator ${user} cannot be created."
	}
	password=$(sed -n "s/^generated random password is '\(.*\)'$/\1/p" <<<"${output}")
	[[ -n ${password} ]] || die "forgejo: Forgejo did not report the password of ${user}."
	secret_set forgejo-admin-password "${password}"
	log_info "forgejo: created the administrator ${user}; password in $(secret_path forgejo-admin-password)"
	files_note_change "created the Forgejo administrator ${user}"
	return
}

mod_configure() {
	app_secret forgejo-secret-key "${FJ_USER}" 64 secret-key
	app_secret forgejo-internal-token "${FJ_USER}" 64 internal-token
	_fj_compose | app_compose
	app_backup COPY=data
	app_up
	app_site "$(opt_int port)"
	app_wait api/healthz 200 >/dev/null || die "forgejo: https://$(app_domain)/api/healthz does not answer."
	_fj_admin
	return
}

# _fj_api METHOD PATH [CURL OPTION...]: an API request as the administrator; prints the body and the status.
_fj_api() {
	local method=$1 path=$2 netrc page
	shift 2
	netrc=$(app_netrc "$(opt admin_user)" forgejo-admin-password)
	page=$(app_get "api/v1/${path}" --netrc-file "${netrc}" -X "${method}" -H 'Content-Type: application/json' "$@") || true
	rm -f -- "${netrc}"
	printf '%s' "${page}"
	return
}

mod_verify() {
	local page repo user
	user=$(opt admin_user)
	app_verify_stack
	app_verify_backup
	page=$(app_wait api/healthz 200) || die "forgejo: https://$(app_domain)/api/healthz does not answer."
	[[ $(jq -r '.status' <<<"${page%$'\n'*}" 2>/dev/null) =~ ^(pass|warn)$ ]] || die "forgejo: the health check fails."
	page=$(app_wait user/login 200 60) || die "forgejo: the login page does not answer."
	grep -q 'name="password"' <<<"${page}" || die "forgejo: https://$(app_domain)/user/login shows no login."
	# Registration is off: the sign-up page has no form to repeat a password.
	page=$(app_get user/sign_up) || true
	! grep -q 'name="retype"' <<<"${page}" || die "forgejo: anybody can register at https://$(app_domain)/user/sign_up."
	# Used, not only running: the administrator creates a repository through the API, reads it and deletes it.
	repo="lss-verify-$(date +%s)"
	page=$(_fj_api POST user/repos -d "{\"name\":\"${repo}\",\"private\":true,\"auto_init\":true}")
	[[ $(app_status "${page}") == 201 ]] || die "forgejo: creating a repository as ${user} answers $(app_status "${page}")."
	page=$(_fj_api GET "repos/${user}/${repo}/contents/README.md")
	[[ $(app_status "${page}") == 200 ]] || die "forgejo: the new repository has no README.md ($(app_status "${page}"))."
	page=$(_fj_api DELETE "repos/${user}/${repo}")
	[[ $(app_status "${page}") == 204 ]] || die "forgejo: deleting the test repository answers $(app_status "${page}")."
	return
}

mod_remove() {
	app_remove
	return
}
