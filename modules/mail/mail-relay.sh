# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="mail-relay"
MOD_GROUP="mail"
MOD_DESCRIPTION="Postfix as a send-only relay on 127.0.0.1: mail of the server (guard, cron, applications) goes out through a smarthost with TLS and login, or directly"
MOD_REQUIRES="system"
MOD_CONFLICTS="mailserver"
MOD_OPTIONS="relayhost||Smarthost as HOST or HOST:PORT (587: STARTTLS, 465: TLS from the start); empty delivers straight to the recipients' mail servers, which needs outgoing port 25
user||Login name at the smarthost
password||Password at the smarthost, stored in the lss secrets (mail-relay-password)
tls_verify|true|Check the certificate of the smarthost against the CA certificates of the system; false only encrypts
from||Sender address of mail from this server (root, cron, the guard); empty keeps USER@HOSTNAME, which smarthosts often refuse
forward||Address that receives mail for root and the other system accounts; empty keeps it on the server in /var/mail/root
hostname||Host name in the greeting and in local addresses; empty: the full host name of the server (with .localdomain when it has no domain)"
MOD_SECRETS="mail-relay-password"
MOD_PORTS="25/tcp on 127.0.0.1 and ::1 only (outgoing SMTP to the smarthost or the recipients)"

RELAY_ALIASES=/etc/postfix/lss-aliases
RELAY_SASL=/etc/postfix/lss-sasl-passwd
RELAY_GENERIC=/etc/postfix/lss-generic

_relay_address_ok() {
	local address=$1
	[[ ${address} =~ ^[A-Za-z0-9._%+-]+@([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]]
	return
}

mod_check() {
	local relayhost host port address hostname
	relayhost=$(opt relayhost)
	if [[ -n ${relayhost} ]]; then
		host=${relayhost%:*}
		port=25
		[[ ${relayhost} != *:* ]] || port=${relayhost##*:}
		mail_valid_domain "${host}" || die "LSS_MAIL_RELAY_RELAYHOST: '${host}' is not a host name like smtp.example.com."
		if [[ ! ${port} =~ ^[0-9]{1,5}$ ]] || ((port < 1 || port > 65535)); then
			die "LSS_MAIL_RELAY_RELAYHOST: '${port}' is not a port number."
		fi
	fi
	if [[ -n $(opt user) || -n $(opt password) ]]; then
		[[ -n ${relayhost} ]] || die "LSS_MAIL_RELAY_USER and LSS_MAIL_RELAY_PASSWORD need LSS_MAIL_RELAY_RELAYHOST."
		[[ -n $(opt user) ]] || die "LSS_MAIL_RELAY_PASSWORD needs LSS_MAIL_RELAY_USER."
		[[ $(opt user) =~ ^[^[:space:]]+$ ]] || die "LSS_MAIL_RELAY_USER must not contain spaces."
	fi
	[[ $(opt password) != *[[:space:]]* ]] || die "LSS_MAIL_RELAY_PASSWORD must not contain spaces."
	opt_bool tls_verify || true
	for address in "$(opt from)" "$(opt forward)"; do
		[[ -z ${address} ]] || _relay_address_ok "${address}" || die "mail-relay: '${address}' is not an e-mail address."
	done
	hostname=$(opt hostname)
	[[ -z ${hostname} ]] || mail_valid_domain "${hostname}" ||
		die "LSS_MAIL_RELAY_HOSTNAME: '${hostname}' is not a full host name like server.example.com."
	return
}

mod_install() {
	mail_postfix_install
	return
}

# _relay_nexthop: the relayhost in Postfix's form, [HOST]:PORT (brackets: no MX lookup for the smarthost).
_relay_nexthop() {
	local relayhost
	relayhost=$(opt relayhost)
	[[ -n ${relayhost} ]] || return 0
	if [[ ${relayhost} == *:* ]]; then
		printf '[%s]:%s' "${relayhost%:*}" "${relayhost##*:}"
	else
		printf '[%s]:25' "${relayhost}"
	fi
	return
}

# _relay_tls_level: secure (encrypted, certificate checked) or encrypt for a smarthost; for direct delivery DANE with a
# validating resolver (dns-resolver), opportunistic TLS otherwise, as the receiving servers decide.
_relay_tls_level() {
	if [[ -n $(opt relayhost) ]]; then
		if opt_bool tls_verify; then printf 'secure'; else printf 'encrypt'; fi
	elif state_installed dns-resolver; then
		printf 'dane'
	else
		printf 'may'
	fi
	return
}

# _relay_main HOSTNAME: main.cf of the relay.
_relay_main() {
	local hostname=$1 nexthop level
	nexthop=$(_relay_nexthop)
	level=$(_relay_tls_level)
	cat <<EOF
# Managed by lss (module mail-relay). Change LSS_MAIL_RELAY_* in /etc/lss/lss.conf and run lss configure mail-relay.
compatibility_level = 3.6
myhostname = ${hostname}
myorigin = \$myhostname
mydestination = \$myhostname, localhost.localdomain, localhost
inet_interfaces = loopback-only
inet_protocols = $(mail_inet_protocols)
mynetworks = 127.0.0.0/8 [::1]/128
smtpd_banner = \$myhostname ESMTP
smtpd_relay_restrictions = permit_mynetworks, reject
smtpd_recipient_restrictions = permit_mynetworks, reject
disable_vrfy_command = yes
biff = no
append_dot_mydomain = no
message_size_limit = 26214400
# Local mail goes to the mailboxes in /var/mail or to the forward address, never to programs, files or ~/.forward.
alias_maps = texthash:${RELAY_ALIASES}
alias_database =
forward_path =
allow_mail_to_commands =
allow_mail_to_files =
# lss verify sends a test message to this address; it is discarded.
transport_maps = inline:{ ${MAIL_VERIFY_LOCALPART}@${hostname}=discard: }
relayhost = ${nexthop}
smtp_tls_security_level = ${level}
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_CAfile = $(mail_ca_bundle)
smtp_tls_loglevel = 1
EOF
	if [[ ${level} == dane ]]; then
		printf 'smtp_dns_support_level = dnssec\n'
	fi
	if [[ ${nexthop} == *:465 ]]; then
		printf 'smtp_tls_wrappermode = yes\n'
	fi
	if [[ -n $(opt user) ]]; then
		printf 'smtp_sasl_auth_enable = yes\nsmtp_sasl_password_maps = texthash:%s\n' "${RELAY_SASL}"
		printf 'smtp_sasl_security_options = noanonymous\nsmtp_sasl_tls_security_options = noanonymous\n'
	fi
	if [[ -n $(opt from) ]]; then
		printf 'smtp_generic_maps = texthash:%s\n' "${RELAY_GENERIC}"
	fi
	return
}

_relay_master() {
	printf '# Managed by lss (module mail-relay).\n'
	printf 'smtp      inet  n       -       n       -       -       smtpd\n'
	mail_master_cf
	return
}

# _relay_tables HOSTNAME: the aliases, the login at the smarthost and the sender rewriting.
_relay_tables() {
	local hostname=$1 forward from password
	forward=$(opt forward)
	{
		# texthash reads "key value" lines, not the "key: value" lines of aliases(5).
		printf '# Managed by lss (module mail-relay).\npostmaster root\nabuse root\n'
		[[ -z ${forward} ]] || printf 'root %s\n' "${forward}"
	} | file_write 0644 root:root "${RELAY_ALIASES}"
	if [[ -n $(opt user) ]]; then
		password=$(opt password)
		if [[ -n ${password} ]]; then
			log_mask "${password}"
			if ! secret_exists mail-relay-password || [[ $(secret_get mail-relay-password) != "${password}" ]]; then
				secret_set mail-relay-password "${password}"
			fi
		fi
		secret_exists mail-relay-password || die "mail-relay: set LSS_MAIL_RELAY_PASSWORD for the login at the smarthost."
		secret_load mail-relay-password password
		# Read by Postfix as root before its daemons drop their privileges.
		printf '%s %s:%s\n' "$(_relay_nexthop)" "$(opt user)" "${password}" | file_write 0600 root:root "${RELAY_SASL}"
	else
		file_remove "${RELAY_SASL}"
	fi
	from=$(opt from)
	if [[ -n ${from} ]]; then
		printf '@%s %s\n@localhost %s\n' "${hostname}" "${from}" "${from}" | file_write 0644 root:root "${RELAY_GENERIC}"
	else
		file_remove "${RELAY_GENERIC}"
	fi
	return
}

mod_configure() {
	local before hostname main master
	before=$(files_changes_of mail-relay)
	hostname=$(mail_fqdn "$(opt hostname)")
	_relay_tables "${hostname}"
	main=$(_relay_main "${hostname}")
	master=$(_relay_master)
	mail_postfix_sandbox ReadWritePaths=-/var/mail ReadWritePaths=-/var/spool/mail
	mail_postfix_apply "${main}" "${master}" "${before}"
	state_set mail-relay hostname "${hostname}"
	return
}

mod_verify() {
	local hostname
	hostname=$(mail_fqdn "$(opt hostname)")
	svc_is_active "$(mail_postfix_unit)" || die "mail-relay: Postfix is not running."
	postfix check >/dev/null 2>&1 || die "mail-relay: postfix check reports a problem."
	[[ $(postconf -h inet_interfaces) == loopback-only ]] || die "mail-relay: Postfix must listen on the loopback addresses only."
	[[ $(postconf -h relayhost) == "$(_relay_nexthop)" ]] || die "mail-relay: Postfix does not use the relayhost of the settings."
	if [[ -e ${RELAY_SASL} ]]; then
		[[ $(stat -c '%a %U' "${RELAY_SASL}") == '600 root' ]] || die "mail-relay: ${RELAY_SASL} must be mode 600, owned by root."
	fi
	mon_listen_check 25 127.0.0.1 ::1
	command -v sendmail >/dev/null 2>&1 || die "mail-relay: the sendmail command is missing."
	mail_send_check "root@${hostname}" "${MAIL_VERIFY_LOCALPART}@${hostname}" >/dev/null
	return
}

mod_remove() {
	local unit
	unit=$(mail_postfix_template)
	svc_disable "$(mail_postfix_unit)"
	svc_disable postfix
	svc_dropin_remove "${unit}" lss-sandbox
	file_remove "${RELAY_ALIASES}"
	file_remove "${RELAY_SASL}"
	file_remove "${RELAY_GENERIC}"
	files_forget_path "${MAIL_POSTFIX_MAIN}"
	files_forget_path "${MAIL_POSTFIX_MASTER}"
	pkg_remove postfix
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		secret_remove mail-relay-password
	fi
	return
}
