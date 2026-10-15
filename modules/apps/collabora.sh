# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="collabora"
MOD_GROUP="apps"
MOD_DESCRIPTION="Collabora Online (CODE 26.04) as a Docker Compose stack behind the web server, the office suite of Nextcloud Office; only the Nextcloud host names may open documents"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the Collabora site, separated by spaces; empty: collabora.<host name of the server>
port|8082|Port of the Collabora container on 127.0.0.1, which the web server forwards to
memory|2g|Memory limit of the Collabora container
dictionaries|de_DE en_GB en_US|Spell checking languages, separated by spaces"
MOD_SECRETS=""
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# Collabora Online Development Edition 26.04.5.1.1, the multi-architecture index (amd64 and arm64), checked 2026-10-15.
# The image is distroless (no shell) and runs as cool (1001).
COOL_IMAGE=docker.io/collabora/code@sha256:bb8f3c9c5c9016045f25fccb5f0649be94469ebc7c7cc379f3576e470cccf33d

mod_check() {
	local languages='^[a-zA-Z_ -]*$'
	app_check_domains
	app_check_port port
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_COLLABORA_MEMORY must be a size such as 2g or 1536m."
	[[ $(opt dictionaries) =~ ${languages} ]] || die "LSS_COLLABORA_DICTIONARIES must be language codes such as de_DE en_US."
	return
}

mod_install() {
	app_compose_ready
	return
}

# _cool_wopi_hosts: the sites allowed to open documents (WOPI hosts): the host names of Nextcloud, as an alias group
# (the first one is the host, the others its aliases). Nothing else may use this server.
_cool_wopi_hosts() {
	local domain list=''
	for domain in $(app_domains_of nextcloud); do
		list+=${list:+,}https://${domain}:443
	done
	printf '%s' "${list}"
	return
}

# _cool_verify_tls: Collabora checks the certificate of Nextcloud only when it comes from a public CA (the tls module
# without a private ACME server); the image has no way to add another CA, and the connection stays on this server.
_cool_verify_tls() {
	if state_installed tls && [[ -z $(config_option tls ca_bundle '') ]]; then
		printf 'true'
	else
		printf 'false'
	fi
	return
}

# _cool_compose: the stack. Collabora runs without capabilities and without new privileges, so it cannot build its
# chroot jails; COOL_FORCE_LANDLOCK makes it isolate the document processes with Landlock instead. The root file
# system stays writable because the jails are created below /opt/cool. The admin console is off: it would need a
# password in the environment.
_cool_compose() {
	local domain params
	domain=$(app_domain)
	params="--o:ssl.enable=false --o:ssl.termination=true --o:admin_console.enable=false"
	params+=" --o:ssl.ssl_verification=$(_cool_verify_tls) --o:logging.level=warning"
	cat <<EOF
# Managed by lss (module collabora). Change LSS_COLLABORA_* in /etc/lss/lss.conf and run lss configure collabora.
name: $(app_project)
services:
  app:
    image: ${COOL_IMAGE}
    environment:
      aliasgroup1: "$(_cool_wopi_hosts)"
      server_name: "${domain}"
      dictionaries: "$(opt dictionaries)"
      DONT_GEN_SSL_CERT: "1"
      COOL_FORCE_LANDLOCK: "1"
      extra_params: "${params}"
    ports:
      - 127.0.0.1:$(opt_int port):9980
    extra_hosts:
$(_cool_extra_hosts)
    tmpfs:
      - /tmp:mode=1777,size=512m
$(app_hardening "$(opt memory)" 1024 writable)
EOF
	return
}

# _cool_extra_hosts: the Nextcloud host names resolve to the host, so Collabora reaches Nextcloud (WOPI) through the
# web server of this server.
_cool_extra_hosts() {
	local domain
	for domain in $(app_domains_of nextcloud); do
		printf '      - "%s:host-gateway"\n' "${domain}"
	done
	return
}

mod_configure() {
	_cool_compose | app_compose
	app_up
	app_site "$(opt_int port)"
	app_wait '' 200 >/dev/null || die "collabora: https://$(app_domain)/ does not answer."
	if state_installed nextcloud; then
		app_nextcloud_office
	fi
	return
}

mod_verify() {
	local page probe pdf status
	app_verify_stack
	page=$(app_wait '' 200) || die "collabora: https://$(app_domain)/ does not answer."
	[[ ${page%$'\n'*} == OK ]] || die "collabora: https://$(app_domain)/ answers '${page%$'\n'*}' instead of OK."
	page=$(app_wait hosting/discovery 200 60) || die "collabora: the WOPI discovery does not answer."
	grep -q 'urlsrc=' <<<"${page}" || die "collabora: the WOPI discovery lists no editors."
	# Used, not only running: Collabora converts a text document to PDF.
	probe=$(mktemp)
	pdf=$(mktemp)
	printf 'lss verify %s\n' "$(date +%s)" >"${probe}"
	status=$(app_status "$(app_get cool/convert-to/pdf -F "data=@${probe};filename=lss-verify.txt" -o "${pdf}" --max-time 120)")
	if [[ ${status} != 200 || $(head -c 4 "${pdf}") != %PDF ]]; then
		rm -f -- "${probe}" "${pdf}"
		die "collabora: converting a document to PDF failed (HTTP ${status})."
	fi
	rm -f -- "${probe}" "${pdf}"
	if state_installed nextcloud; then
		log_command _app_nc_occ richdocuments:activate-config ||
			die "collabora: Nextcloud Office cannot reach Collabora Online; see the log."
	fi
	return
}

mod_remove() {
	# Nextcloud stops offering Nextcloud Office; installing the module again turns it back on.
	if state_installed nextcloud && command -v docker >/dev/null 2>&1; then
		log_command _app_nc_occ app:disable richdocuments ||
			log_warn "collabora: Nextcloud Office could not be turned off in Nextcloud."
	fi
	app_remove
	return
}
