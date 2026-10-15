#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The mail flow on a test server without public DNS, run inside the target by run.sh after lss verify:
#   mail-flow.sh server    mail between two mailboxes (submission with STARTTLS and with TLS, IMAPS), the DKIM
#                          signature checked by Rspamd against the DNS records lss printed (served from Rspamd's fake
#                          DNS), SPF and DMARC, GTUBE rejected, relaying and logins without TLS or password refused
#   mail-flow.sh webmail   a Roundcube login with a mailbox of the mail server
#   mail-flow.sh relay     the guard sends its daily summary through mail-relay to root's mailbox
# Certificates are checked against the self-signed certificate of the mail host name; nothing reaches the Internet.
set -Eeuo pipefail

STATE=/var/lib/lss/modules
SECRETS=/etc/lss/secrets
CERT=/etc/lss/tls/mail/fullchain.pem
DNS_FILE=/etc/lss/mailserver-dns.txt
RSPAMD_OPTIONS=/etc/rspamd/local.d/options.inc
# A documentation address (RFC 5737) the fake DNS gives the mail host, so SPF has an address to match.
TEST_IP=192.0.2.25
WORK=$(mktemp -d)
trap 'rm -rf -- "${WORK}"' EXIT

say() {
	printf 'mail flow: %s\n' "$*"
	return
}

fail() {
	printf 'mail flow FAILED: %s\n' "$*" >&2
	exit 1
}

state() {
	local module=$1 key=$2
	sed -n "s/^${key}=//p" "${STATE}/${module}"
	return
}

# login ADDRESS: a curl configuration line with the login of a mailbox, for curl -K - (no password in the process
# list).
login() {
	printf 'user = "%s:%s"\n' "$1" "$(<"${SECRETS}/mailbox-${1/@/_}")"
	return
}

# message FROM TO SUBJECT: a test message in WORK/message.
message() {
	printf 'From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s@lss-test>\r\nDate: %s\r\n\r\nlss mail flow test.\r\n' \
		"$1" "$2" "$3" "${RANDOM}${RANDOM}" "$(LC_ALL=C date -R)" >"${WORK}/message"
	return
}

# smtp URL FROM TO [LOGIN] [CURL OPTION...]: sends WORK/message; prints curl's error output on failure.
smtp() {
	local url=$1 from=$2 to=$3 user=$4
	shift 4
	local host=${url#*://}
	host=${host%%:*}
	local -a args=(-sS --max-time 60 --url "${url}" --mail-from "${from}" --mail-rcpt "${to}" --upload-file "${WORK}/message")
	[[ ${host} =~ ^[0-9.]+$ ]] || args+=(--resolve "${host}:${url##*:}:127.0.0.1" --cacert "${CERT}")
	if [[ -n ${user} ]]; then
		login "${user}" | curl "${args[@]}" "$@" -K - 2>&1
	else
		curl "${args[@]}" "$@" 2>&1
	fi
	return
}

# imap MAILBOX URL-PATH [CURL OPTION...]: an IMAPS request as MAILBOX.
imap() {
	local user=$1 path=$2
	shift 2
	login "${user}" | curl -sS --max-time 60 --resolve "${HOSTNAME_MAIL}:993:127.0.0.1" --cacert "${CERT}" \
		"imaps://${HOSTNAME_MAIL}:993/${path}" "$@" -K -
	return
}

# fetch_subject MAILBOX SUBJECT: waits for the message with SUBJECT in the inbox and prints it.
fetch_subject() {
	local user=$1 subject=$2 uid='' i
	for ((i = 0; i < 30; i++)); do
		uid=$(imap "${user}" INBOX -X "UID SEARCH SUBJECT \"${subject}\"" | tr -d '\r' | awk '$1 == "*" && $2 == "SEARCH" { print $3 }')
		[[ -z ${uid} ]] || break
		sleep 2
	done
	[[ -n ${uid} ]] || fail "the message '${subject}' did not arrive in the inbox of ${user}."
	imap "${user}" "INBOX;UID=${uid}" | tr -d '\r'
	return
}

# txt NAME: the value of a TXT record in the DNS records lss printed, its strings joined.
txt() {
	local name=$1
	awk -v name="${name}." '$1 == name && $2 == "TXT" { $1 = ""; $2 = ""; print }' "${DNS_FILE}" |
		sed -E 's/^ +//; s/" "//g; s/^"//; s/"$//'
	return
}

# The DNS records of the main domain, as lss printed them, in Rspamd's fake DNS; the mail host gets TEST_IP.
fake_dns() {
	local domain=$1 selector=$2 i
	record() {
		printf '  { name = "%s"; type = "%s"; replies = ["%s"]; },\n' "$1" "$2" "$3"
		return
	}
	{
		printf '# Written by tests/integration/mail-flow.sh: the DNS records of %s without public DNS.\ndns {\n fake_records = [\n' "${domain}"
		record "${domain}" mx "10 ${HOSTNAME_MAIL}"
		record "${HOSTNAME_MAIL}" a "${TEST_IP}"
		record "${domain}" txt "$(txt "${domain}")"
		record "_dmarc.${domain}" txt "$(txt "_dmarc.${domain}")"
		record "${selector}._domainkey.${domain}" txt "$(txt "${selector}._domainkey.${domain}")"
		printf ' ];\n}\n'
	} >"${RSPAMD_OPTIONS}"
	systemctl restart rspamd
	for ((i = 0; i < 60; i++)); do
		rspamc -h 127.0.0.1:11333 stat >/dev/null 2>&1 && return 0
		printf 'From: a@b.c\n\nping\n' | rspamc -h 127.0.0.1:11333 symbols >/dev/null 2>&1 && return 0
		sleep 1
	done
	fail "Rspamd does not answer after the restart."
}

# full_curl: the RHEL family installs curl-minimal, which speaks no SMTP and IMAP; the test swaps in the full curl.
full_curl() {
	[[ $(curl -V) != *' smtp '* ]] || return 0
	dnf -y -q install --allowerasing curl libcurl >/dev/null || fail "the full curl does not install."
	[[ $(curl -V) == *' smtp '* ]] || fail "curl still speaks no SMTP."
	return
}

server() {
	local alice bob domain selector token mail result output ip i symbol
	local -a mailboxes=()
	full_curl
	HOSTNAME_MAIL=$(state mailserver hostname)
	domain=$(state mailserver domain)
	selector=$(sed -nE 's/^([a-z0-9-]+)\._domainkey\..*/\1/p' "${DNS_FILE}" | head -n 1)
	mapfile -t mailboxes < <(awk '$2 == "OK" && $1 !~ /^lss-verify@/ { print $1 }' /etc/postfix/lss-mailboxes)
	((${#mailboxes[@]} >= 2)) || fail "the test settings need two mailboxes (LSS_MAILSERVER_USERS)."
	alice=${mailboxes[0]}
	bob=${mailboxes[1]}
	token=$(date +%s)
	say "the DNS records lss printed:"
	sed 's/^/  /' "${DNS_FILE}"

	message "${alice}" "${bob}" "lss flow 587 ${token}"
	output=$(smtp "smtp://${HOSTNAME_MAIL}:587" "${alice}" "${bob}" "${alice}" --ssl-reqd) || fail "submission on 587: ${output}"
	say "${alice} sent to ${bob} on 587 (STARTTLS, login)"
	message "${bob}" "${alice}" "lss flow 465 ${token}"
	output=$(smtp "smtps://${HOSTNAME_MAIL}:465" "${bob}" "${alice}" "${bob}") || fail "submission on 465: ${output}"
	say "${bob} sent to ${alice} on 465 (TLS, login)"

	mail=$(fetch_subject "${bob}" "lss flow 587 ${token}")
	say "the message arrived in the inbox of ${bob} (IMAPS 993)"
	grep -qiE "^DKIM-Signature:.*d=${domain//./\\.};" <<<"$(sed -e ':a' -e 'N;$!ba' -e 's/\n[ \t]\+/ /g' <<<"${mail}")" ||
		fail "the message carries no DKIM signature of ${domain}: $(grep -i '^dkim' <<<"${mail}" || true)"
	grep -qi '^Authentication-Results:' <<<"${mail}" || fail "the message has no Authentication-Results header."
	say "Rspamd signed it with the DKIM key of ${domain}"
	fetch_subject "${alice}" "lss flow 465 ${token}" >/dev/null
	say "the reply arrived in the inbox of ${alice}"

	# DKIM, SPF and DMARC of the delivered message, checked with the printed records as DNS.
	fake_dns "${domain}" "${selector}"
	result=$(rspamc -h 127.0.0.1:11333 --ip "${TEST_IP}" --helo "${HOSTNAME_MAIL}" --from "${alice}" symbols <<<"${mail}")
	rm -f -- "${RSPAMD_OPTIONS}"
	systemctl restart rspamd
	for symbol in R_DKIM_ALLOW R_SPF_ALLOW DMARC_POLICY_ALLOW; do
		grep -qF "${symbol}" <<<"${result}" || fail "Rspamd does not report ${symbol} for the signed message: ${result}"
	done
	say "DKIM, SPF and DMARC pass against the printed records (R_DKIM_ALLOW, R_SPF_ALLOW, DMARC_POLICY_ALLOW)"

	# The spam filter rejects GTUBE during the SMTP dialogue.
	printf 'From: %s\r\nTo: %s\r\nSubject: spam\r\n\r\nXJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n' \
		"${alice}" "${bob}" >"${WORK}/message"
	for ((i = 0; i < 20; i++)); do
		output=$(smtp smtp://127.0.0.1:25 "${alice}" "${bob}" '') && fail "GTUBE was accepted on port 25."
		[[ ${output} != *' 554'* && ${output} != *'(55)'* ]] || break
		sleep 2
	done
	[[ ${output} == *'(55)'* || ${output} == *554* ]] || fail "GTUBE was not rejected as spam: ${output}"
	say "GTUBE is rejected on port 25"

	# What must be refused: submission without login, a wrong password, relaying for strangers.
	message "${alice}" "${bob}" "lss flow refused ${token}"
	output=$(smtp "smtp://${HOSTNAME_MAIL}:587" "${alice}" "${bob}" '' --ssl-reqd) && fail "submission without a login was accepted."
	printf 'user = "%s:wrong-password"\n' "${alice}" |
		curl -sS --max-time 60 --url "smtp://${HOSTNAME_MAIL}:587" --resolve "${HOSTNAME_MAIL}:587:127.0.0.1" --cacert "${CERT}" \
			--ssl-reqd --mail-from "${alice}" --mail-rcpt "${bob}" --upload-file "${WORK}/message" -K - >/dev/null 2>&1 &&
		fail "submission with a wrong password was accepted."
	ip=$(ip -4 -o route get 192.0.2.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
	output=$(smtp "smtp://${ip}:25" "${alice}" stranger@example.net '') && fail "port 25 relays for a stranger from ${ip}."
	say "submission without login or with a wrong password and relaying from ${ip} are refused"
	return
}

webmail() {
	local site user page token status
	site=$(sed -nE 's/.*server_name ([^ ;]+).*/\1/p' /etc/nginx/lss/sites/webmail.conf 2>/dev/null | head -n 1)
	[[ -n ${site} ]] || site=$(state mailserver hostname)
	user=$(awk '$2 == "OK" && $1 !~ /^lss-verify@/ { print $1; exit }' /etc/postfix/lss-mailboxes)
	local -a curl_args=(-ks --max-time 60 --resolve "${site}:443:127.0.0.1" -b "${WORK}/cookies" -c "${WORK}/cookies")
	page=$(curl "${curl_args[@]}" "https://${site}/")
	token=$(grep -oE 'name="_token" value="[^"]+"' <<<"${page}" | head -n 1 | sed -E 's/.*value="([^"]+)"/\1/')
	[[ -n ${token} ]] || fail "the Roundcube login page has no form token."
	cp "${SECRETS}/mailbox-${user/@/_}" "${WORK}/password"
	status=$(curl "${curl_args[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -d _task=login -d _action=login \
		-d _timezone=UTC --data-urlencode "_token=${token}" --data-urlencode "_user=${user}" \
		--data-urlencode "_pass@${WORK}/password" "https://${site}/?_task=login")
	[[ ${status} == 302*'_task=mail'* ]] || fail "the Roundcube login of ${user} answers ${status} instead of a redirect to the mail view."
	page=$(curl "${curl_args[@]}" "https://${site}/?_task=mail&_mbox=INBOX")
	grep -qF 'task-mail' <<<"${page}" || fail "Roundcube does not show the mailbox of ${user} after the login."
	say "${user} logged in to Roundcube on https://${site}/ and sees the inbox"
	return
}

relay() {
	local box hostname i
	hostname=$(state mail-relay hostname)
	box=/var/mail/root
	[[ -d /var/mail ]] || box=/var/spool/mail/root
	timeout 900 systemctl start lss-guard.service || true
	for ((i = 0; i < 60; i++)); do
		if grep -qF 'Subject: [lss guard]' "${box}" 2>/dev/null; then
			say "the guard's summary arrived in ${box} through mail-relay (${hostname})"
			grep -F -A 3 'Subject: [lss guard]' "${box}" | head -n 4
			return 0
		fi
		sleep 2
	done
	postqueue -p || true
	journalctl -u lss-guard.service -n 30 --no-pager || true
	fail "the guard's summary did not arrive in ${box}."
}

case ${1:-} in
server) server ;;
webmail) webmail ;;
relay) relay ;;
*)
	echo "usage: mail-flow.sh server|webmail|relay" >&2
	exit 2
	;;
esac
