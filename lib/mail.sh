# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Mail layer shared by mail-relay and mailserver: Postfix (its configuration, unit and systemd sandbox), the host name
# mail leaves with, a TLS certificate for it, and the local delivery test both modules verify with. The two modules
# conflict: each one owns the whole Postfix configuration.
#
# Lookup tables are texthash: files Postfix reads directly, so no postmap run and no database format (Berkeley DB is
# gone on the RHEL 10 family). Postfix reads them when a daemon starts; mail_postfix_apply reloads after a change.

MAIL_POSTFIX_DIR=/etc/postfix
MAIL_POSTFIX_MAIN=${MAIL_POSTFIX_DIR}/main.cf
MAIL_POSTFIX_MASTER=${MAIL_POSTFIX_DIR}/master.cf
# The self-signed certificate of the mail host name, next to the certificates of the web layer.
MAIL_TLS_DIR=/etc/lss/tls/mail
# Mail to this local part is discarded (transport discard:); verify sends one message to it through the whole queue.
# shellcheck disable=SC2034 # read by the mail modules
MAIL_VERIFY_LOCALPART=lss-verify

# mail_fqdn [NAME]: NAME, or the server's full host name; a name without a domain gets .localdomain, because Postfix
# refuses a host name without a dot.
mail_fqdn() {
	local name=${1:-}
	if [[ -z ${name} ]]; then
		name=$(hostname -f 2>/dev/null || true)
		[[ -n ${name} ]] || name=$(hostname)
	fi
	name=${name,,}
	[[ ${name} == *.* ]] || name+=.localdomain
	printf '%s' "${name}"
	return
}

# mail_valid_domain NAME: a DNS name with at least two labels (example.com, mail.example.org).
mail_valid_domain() {
	[[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]]
	return
}

# mail_postfix_unit: the unit that runs the Postfix master. Debian and Ubuntu up to Postfix 3.9 start it as the
# instance postfix@-, and postfix.service there only groups the instances (ExecStart=/bin/true); from Debian 13 and
# Ubuntu 26.04 on (Postfix 3.10), and on the RHEL family, postfix.service runs the master itself.
mail_postfix_unit() {
	local fragment
	if os_is_debian; then
		fragment=$(systemctl show -P FragmentPath postfix.service 2>/dev/null) || fragment=''
		if [[ -z ${fragment} || ! -r ${fragment} ]] || grep -q '^ExecStart=/bin/true' "${fragment}"; then
			printf 'postfix@-'
			return
		fi
	fi
	printf 'postfix'
	return
}

# mail_postfix_template: the unit file the sandbox drop-in of the Postfix master belongs to.
mail_postfix_template() {
	if [[ $(mail_postfix_unit) == postfix@- ]]; then printf 'postfix@.service'; else printf 'postfix.service'; fi
	return
}

# mail_postfix_install: Postfix without the configuration questions of the Debian package (lss writes main.cf).
mail_postfix_install() {
	if os_is_debian && ! pkg_is_installed postfix; then
		printf 'postfix postfix/main_mailer_type select No configuration\n' | debconf-set-selections
	fi
	pkg_install postfix
	return
}

# mail_ca_bundle: the CA certificates of the system, for checking the certificates of other mail servers.
mail_ca_bundle() {
	if os_is_debian; then printf '/etc/ssl/certs/ca-certificates.crt'; else printf '/etc/pki/tls/certs/ca-bundle.crt'; fi
	return
}

# mail_inet_protocols: all where the kernel has IPv6, ipv4 otherwise (kernel-hardening can switch IPv6 off).
mail_inet_protocols() {
	if [[ -f /proc/net/if_inet6 ]]; then printf 'all'; else printf 'ipv4'; fi
	return
}

# mail_master_cf: the internal services of master.cf. The caller puts its listeners in front of it. Nothing runs
# chrooted: the systemd sandbox (mail_postfix_sandbox) confines the whole Postfix instead.
mail_master_cf() {
	cat <<'EOF'
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
  -o syslog_name=postfix/$service_name
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
EOF
	return
}

# mail_postfix_sandbox [DIRECTIVE...]: the systemd sandbox of the Postfix master and its daemons. They write the queue,
# their state and the local mailboxes only. Postfix needs /dev/log of the host for syslog, so /dev stays.
mail_postfix_sandbox() {
	svc_sandbox "$(mail_postfix_template)" PrivateDevices=no ReadWritePaths=/var/spool/postfix ReadWritePaths=/var/lib/postfix \
		"$@"
	return
}

# mail_postfix_apply MAIN MASTER: writes main.cf and master.cf from the two strings, checks them with postfix check,
# starts Postfix and restarts it when the module changed anything since BEFORE (a change count, files_changes_of).
mail_postfix_apply() {
	local main=$1 master=$2 before=$3 unit output
	unit=$(mail_postfix_unit)
	file_write 0644 root:root "${MAIL_POSTFIX_MAIN}" <<<"${main}"
	file_write 0644 root:root "${MAIL_POSTFIX_MASTER}" <<<"${master}"
	output=$(postfix check 2>&1) || {
		printf '%s\n' "${output}" >&2
		die "${LSS_MODULE}: postfix check rejects the configuration."
	}
	# On Debian and Ubuntu postfix.service starts the instance; the instance itself has nothing to enable.
	svc_enable postfix
	if ! svc_is_active "${unit}"; then
		timeout "${SVC_START_TIMEOUT}" systemctl start "${unit}" || die "${LSS_MODULE}: Postfix does not start."
		files_note_change "started ${unit}"
	fi
	if [[ $(files_changes_of "${LSS_MODULE}") != "${before}" ]]; then
		svc_restart "${unit}" || die "${LSS_MODULE}: Postfix does not start with the new configuration."
	fi
	return
}

# mail_tls_cert NAME: a self-signed certificate for the host name NAME in MAIL_TLS_DIR, renewed when it expires within
# 30 days or names another host. The key is readable by root only; Postfix and Dovecot load it before they drop their
# privileges.
mail_tls_cert() {
	local name=$1 tmp
	if [[ -s ${MAIL_TLS_DIR}/fullchain.pem && -s ${MAIL_TLS_DIR}/privkey.pem ]] &&
		openssl x509 -checkend $((30 * 86400)) -noout -in "${MAIL_TLS_DIR}/fullchain.pem" >/dev/null 2>&1 &&
		[[ $(web_cert_domains "${MAIL_TLS_DIR}/fullchain.pem") == "${name}" ]]; then
		return 0
	fi
	tmp=$(mktemp -d)
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=${name}" \
		-addext "subjectAltName=DNS:${name}" -keyout "${tmp}/privkey.pem" -out "${tmp}/fullchain.pem" >/dev/null 2>&1 ||
		die "${LSS_MODULE}: could not create a self-signed certificate for ${name}."
	install -d -m 0755 "${MAIL_TLS_DIR}"
	install -m 0600 -o root -g root "${tmp}/privkey.pem" "${MAIL_TLS_DIR}/privkey.pem"
	install -m 0644 -o root -g root "${tmp}/fullchain.pem" "${MAIL_TLS_DIR}/fullchain.pem"
	rm -rf -- "${tmp}"
	files_note_change "self-signed certificate for ${name}"
	return
}

# mail_queue_has TEXT: a message in the Postfix queue (any queue) names TEXT as a recipient.
mail_queue_has() {
	local text=$1
	postqueue -j 2>/dev/null | grep -F "\"${text}\"" >/dev/null
	return
}

# mail_send_check SENDER RECIPIENT [SECONDS]: hands a message to the sendmail command of Postfix and waits until it
# has left the queue. That proves pickup, cleanup, the queue manager and a delivery agent work. Prints the Message-ID.
mail_send_check() {
	local sender=$1 recipient=$2 seconds=${3:-60} id i
	id="<lss-verify.$(date +%s).${RANDOM}@${sender#*@}>"
	printf 'From: %s\nTo: %s\nSubject: lss verify\nMessage-ID: %s\nDate: %s\n\nTest message of lss verify; it is deleted right away.\n' \
		"${sender}" "${recipient}" "${id}" "$(LC_ALL=C date -R)" |
		sendmail -i -f "${sender}" -- "${recipient}" ||
		die "${LSS_MODULE}: sendmail does not accept a message."
	for ((i = 0; i < seconds; i++)); do
		mail_queue_has "${recipient}" || {
			printf '%s' "${id}"
			return 0
		}
		sleep 1
	done
	postqueue -j >&2 || true
	die "${LSS_MODULE}: a test message to ${recipient} is still in the Postfix queue after ${seconds} s."
}
