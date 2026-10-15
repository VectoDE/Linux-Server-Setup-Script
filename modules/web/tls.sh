# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="tls"
MOD_GROUP="web"
MOD_DESCRIPTION="Certificates from Let's Encrypt (or another ACME server) for every site, renewed by a timer and installed for the web server"
MOD_REQUIRES="nginx|apache|caddy"
MOD_OPTIONS="domains||Host names of this server, separated by spaces: they get a certificate that replaces the self-signed default (admin port, unknown names); the names must point to this server
email||Address for the ACME account (optional)
server|https://acme-v02.api.letsencrypt.org/directory|ACME directory URL (Let's Encrypt staging: https://acme-staging-v02.api.letsencrypt.org/directory)
ca_bundle||CA certificate to trust for a private ACME server (Pebble, step-ca); empty for Let's Encrypt"

TLS_CLI_INI=/etc/letsencrypt/cli.ini

_tls_unit() {
	if os_is_debian; then printf 'certbot'; else printf 'certbot-renew'; fi
	return
}

mod_check() {
	local domain email server bundle
	for domain in $(opt domains); do
		[[ ${domain} =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]] ||
			die "LSS_TLS_DOMAINS: '${domain}' is not a host name like www.example.com."
	done
	email=$(opt email)
	[[ -z ${email} || ${email} =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] ||
		die "LSS_TLS_EMAIL '${email}' is not an e-mail address."
	server=$(opt server)
	[[ ${server} =~ ^https://[^[:space:]]+$ ]] || die "LSS_TLS_SERVER must be an https:// URL."
	bundle=$(opt ca_bundle)
	[[ -z ${bundle} || -s ${bundle} ]] || die "LSS_TLS_CA_BUNDLE: ${bundle} does not exist."
	return
}

mod_install() {
	pkg_enable_epel
	pkg_install certbot openssl
	return
}

# Settings for every certbot run, including the renewals of the timer: webroot challenges below WEB_ACME_ROOT (every
# web server serves it on port 80 for every host name), ECDSA keys, no questions.
_tls_cli_ini() {
	cat <<EOF
# Managed by lss (module tls). Change LSS_TLS_* in /etc/lss/lss.conf and run lss configure tls.
server = $(opt server)
authenticator = webroot
webroot-path = ${WEB_ACME_ROOT}
key-type = ecdsa
elliptic-curve = secp256r1
agree-tos = true
non-interactive = true
quiet = true
max-log-backups = 20
EOF
	if [[ -n $(opt email) ]]; then
		printf 'email = %s\n' "$(opt email)"
	else
		printf 'register-unsafely-without-email = true\n'
	fi
	return
}

# certbot runs the hooks in renewal-hooks/deploy after every renewal; lss runs it after the first issue.
_tls_hook() {
	cat <<EOF
#!/bin/sh
# Managed by lss (module tls). Installs a certificate certbot issued or renewed for the web server: the directory of
# the same name below ${WEB_TLS_DIR} (fullchain.pem, privkey.pem, combined.pem for HAProxy), then a reload.
set -eu
lineage=\${RENEWED_LINEAGE:?}
dir=${WEB_TLS_DIR}/\${lineage##*/}
umask 077
install -d -m 0755 "\${dir}"
install -m 0644 -o root -g root "\${lineage}/fullchain.pem" "\${dir}/fullchain.pem.new"
install -m 0640 -o root -g ${WEB_GROUP} "\${lineage}/privkey.pem" "\${dir}/privkey.pem.new"
cat "\${lineage}/privkey.pem" "\${lineage}/fullchain.pem" >"\${dir}/combined.pem.new"
chgrp ${WEB_GROUP} "\${dir}/combined.pem.new"
chmod 0640 "\${dir}/combined.pem.new"
for file in privkey.pem fullchain.pem combined.pem; do
	mv -f "\${dir}/\${file}.new" "\${dir}/\${file}"
done
for unit in nginx apache2 httpd haproxy; do
	if systemctl is-active --quiet "\${unit}"; then
		systemctl reload "\${unit}"
	fi
done
# Caddy keeps certificates it loaded from files until it restarts.
if systemctl is-active --quiet caddy; then
	systemctl restart caddy
fi
EOF
	return
}

mod_configure() {
	local bundle
	local -a domains
	web_group_ensure
	install -d -m 0755 /etc/letsencrypt /etc/letsencrypt/renewal-hooks /etc/letsencrypt/renewal-hooks/deploy
	_tls_cli_ini | file_write 0644 root:root "${TLS_CLI_INI}"
	_tls_hook | file_write 0755 root:root "${WEB_CERT_HOOK}"
	bundle=$(opt ca_bundle)
	if [[ -n ${bundle} ]]; then
		file_write 0644 root:root "${WEB_ACME_CA}" <"${bundle}"
		printf '# Managed by lss (module tls).\n[Service]\nEnvironment=REQUESTS_CA_BUNDLE=%s\n' "${WEB_ACME_CA}" |
			svc_dropin "$(_tls_unit).service" lss-acme-ca
	else
		file_remove "${WEB_ACME_CA}"
		svc_dropin_remove "$(_tls_unit).service" lss-acme-ca
	fi
	svc_enable "$(_tls_unit).timer"
	read -ra domains <<<"$(opt domains)"
	if ((${#domains[@]} > 0)); then
		web_cert_issue default "${domains[@]}"
	fi
	return
}

mod_verify() {
	local live name wanted
	local -a domains
	svc_is_enabled "$(_tls_unit).timer" || die "tls: $(_tls_unit).timer is not enabled."
	[[ -x ${WEB_CERT_HOOK} ]] || die "tls: the deploy hook ${WEB_CERT_HOOK} is missing."
	for live in /etc/letsencrypt/live/*/fullchain.pem; do
		[[ -f ${live} ]] || continue
		name=${live%/fullchain.pem}
		name=${name##*/}
		cmp -s "${live}" "${WEB_TLS_DIR}/${name}/fullchain.pem" ||
			die "tls: the certificate ${name} is not installed for the web server (run lss configure tls)."
		openssl x509 -checkend $((14 * 86400)) -noout -in "${live}" >/dev/null ||
			die "tls: the certificate ${name} expires within 14 days; renewal does not work (journalctl -u $(_tls_unit))."
	done
	read -ra domains <<<"$(opt domains)"
	if ((${#domains[@]} > 0)); then
		wanted=$(printf '%s\n' "${domains[@]}" | sort -u)
		[[ $(web_cert_domains "${WEB_TLS_DIR}/default/fullchain.pem") == "${wanted}" ]] ||
			die "tls: the default certificate does not cover ${wanted//$'\n'/ }."
	fi
	return
}

# Certificates and the ACME account stay unless the removal purges (lss remove --purge tls).
mod_remove() {
	svc_disable "$(_tls_unit).timer"
	svc_dropin_remove "$(_tls_unit).service" lss-acme-ca
	file_remove "${WEB_CERT_HOOK}"
	file_remove "${TLS_CLI_INI}"
	file_remove "${WEB_ACME_CA}"
	pkg_remove certbot
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		file_remove /etc/letsencrypt
	fi
	return
}
