#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The mail modules: the checks of their settings, the Postfix, Dovecot and Rspamd configuration they write, the DNS
# records lss prints for the mail server, and the guard's warning when it cannot send its mail.

setup() {
	load helpers
	lss_test_setup
	use_os debian-13
	export TMPDIR=${BATS_TEST_TMPDIR}
	WRITES=${BATS_TEST_TMPDIR}/writes
	: >"${WRITES}"
	# shellcheck disable=SC2329 # called by the functions under test
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${WRITES}"
		cat >>"${WRITES}"
		LSS_FILE_CHANGED=${TEST_FILE_CHANGED:-1}
	}
	# shellcheck disable=SC2329 # called by the functions under test
	id() {
		case $1 in
		-u | -g) printf '990\n' ;;
		*) command id "$@" ;;
		esac
	}
}

load_module() {
	local file
	file=$(module_file "$1")
	export LSS_MODULE=$1
	# shellcheck source=/dev/null
	source "${file}"
	return
}

# --- lib/mail.sh -------------------------------------------------------------------------------------------------

@test "the mail host name keeps a full name and adds .localdomain to a short one" {
	[ "$(mail_fqdn mail.example.com)" = mail.example.com ]
	[ "$(mail_fqdn Server)" = server.localdomain ]
	mail_valid_domain example.com
	run ! mail_valid_domain localhost
	run ! mail_valid_domain 'example.com;reboot'
}

@test "Postfix installs without the questions of the Debian package" {
	# shellcheck disable=SC2329 # called by mail_postfix_install
	pkg_is_installed() { return 1; }
	# shellcheck disable=SC2329 # called by mail_postfix_install
	pkg_install() { printf 'install %s\n' "$*" >>"${STUB_LOG}"; }
	# shellcheck disable=SC2329 # called by mail_postfix_install
	debconf-set-selections() { cat >>"${STUB_LOG}"; }
	mail_postfix_install
	grep -qxF 'postfix postfix/main_mailer_type select No configuration' "${STUB_LOG}"
	grep -qxF 'install postfix' "${STUB_LOG}"
	: >"${STUB_LOG}"
	use_os rocky-9
	mail_postfix_install
	[ "$(cat "${STUB_LOG}")" = 'install postfix' ]
	[[ $(mail_inet_protocols) == @(all|ipv4) ]]
}

@test "the Postfix sandbox keeps /dev and opens only the queue, the state and what the module adds" {
	# shellcheck disable=SC2329 # called by mail_postfix_sandbox
	svc_sandbox() { printf '%s\n' "$@"; }
	run mail_postfix_sandbox ReadWritePaths=/var/mail
	[ "${lines[0]}" = 'postfix@.service' ]
	[[ ${output} == *$'PrivateDevices=no\nReadWritePaths=/var/spool/postfix\nReadWritePaths=/var/lib/postfix\nReadWritePaths=/var/mail'* ]]
}

@test "Postfix starts once, restarts only after a change and stops the run on a configuration it rejects" {
	export LSS_MODULE=mail-relay SVC_START_TIMEOUT=5
	local changes=0
	# shellcheck disable=SC2329 # called by mail_postfix_apply
	postfix() { printf 'postfix %s\n' "$*" >>"${STUB_LOG}"; }
	# shellcheck disable=SC2329 # called by mail_postfix_apply
	files_changes_of() { printf '%s' "${changes}"; }
	# shellcheck disable=SC2329 # called by mail_postfix_apply
	svc_restart() { printf 'restart %s\n' "$1" >>"${STUB_LOG}"; }
	mail_postfix_apply 'myhostname = a.example' 'smtp inet n - n - - smtpd' 0
	grep -qxF '== 0644 root:root /etc/postfix/main.cf' "${WRITES}"
	grep -qxF 'postfix check' "${STUB_LOG}"
	grep -qxF 'systemctl start postfix@-' "${STUB_LOG}"
	run ! grep -q '^restart' "${STUB_LOG}"
	: >"${STUB_LOG}"
	export STUB_ACTIVE_UNITS=postfix@-
	changes=2
	mail_postfix_apply 'myhostname = b.example' 'smtp inet n - n - - smtpd' 1
	run ! grep -qxF 'systemctl start postfix@-' "${STUB_LOG}"
	grep -qxF 'restart postfix@-' "${STUB_LOG}"
	# shellcheck disable=SC2329 # called by mail_postfix_apply
	postfix() {
		printf 'postfix: fatal: bad main.cf\n' >&2
		return 1
	}
	run mail_postfix_apply 'bad' 'bad' 0
	[ "${status}" -eq 1 ]
	[[ ${output} == *'bad main.cf'* && ${output} == *'postfix check rejects the configuration'* ]]
}

@test "the self-signed mail certificate is made once and again when it names another host" {
	export LSS_MODULE=mailserver
	MAIL_TLS_DIR=${BATS_TEST_TMPDIR}/tls
	# A stand-in for openssl (the test image has none): req writes both files, x509 -checkend passes.
	# shellcheck disable=SC2329 # called by mail_tls_cert
	openssl() {
		printf 'openssl %s\n' "$1" >>"${STUB_LOG}"
		[[ $1 == req ]] || return 0
		local arg previous=''
		for arg in "$@"; do
			[[ ${previous} != -keyout && ${previous} != -out ]] || printf 'PEM\n' >"${arg}"
			previous=${arg}
		done
	}
	# shellcheck disable=SC2329 # called by mail_tls_cert
	install() {
		local -a args=()
		while (($#)); do
			case $1 in -o | -g | -m) shift 2 ;; *) args+=("$1") && shift ;; esac
		done
		command install "${args[@]}"
	}
	# shellcheck disable=SC2329 # called by mail_tls_cert
	web_cert_domains() { printf '%s' "${CERT_NAME}"; }
	mail_tls_cert mail.example.com
	[ -s "${MAIL_TLS_DIR}/privkey.pem" ] && [ -s "${MAIL_TLS_DIR}/fullchain.pem" ]
	[ "$(grep -c 'openssl req' "${STUB_LOG}")" -eq 1 ]
	CERT_NAME=mail.example.com mail_tls_cert mail.example.com
	[ "$(grep -c 'openssl req' "${STUB_LOG}")" -eq 1 ]
	CERT_NAME=old.example.com mail_tls_cert mail.example.com
	[ "$(grep -c 'openssl req' "${STUB_LOG}")" -eq 2 ]
}

@test "the delivery test waits until the message left the queue and fails when it stays" {
	export LSS_MODULE=mail-relay
	# shellcheck disable=SC2329 # called by mail_send_check
	sendmail() { cat >"${BATS_TEST_TMPDIR}/sent"; }
	# shellcheck disable=SC2329 # called by mail_send_check
	sleep() { :; }
	printf '0\n' >"${BATS_TEST_TMPDIR}/polls"
	# shellcheck disable=SC2329 # called by mail_queue_has
	postqueue() {
		local polls
		polls=$(($(<"${BATS_TEST_TMPDIR}/polls") + 1))
		printf '%s\n' "${polls}" >"${BATS_TEST_TMPDIR}/polls"
		((polls > ${QUEUE_POLLS:-2})) || printf '{"recipients":[{"address":"lss-verify@a.example"}]}\n'
	}
	run mail_send_check root@a.example lss-verify@a.example 10
	[ "${status}" -eq 0 ]
	[[ ${output} =~ ^\<lss-verify\.[0-9]+\.[0-9]+@a\.example\>$ ]]
	grep -qxF 'To: lss-verify@a.example' "${BATS_TEST_TMPDIR}/sent"
	[ "$(<"${BATS_TEST_TMPDIR}/polls")" -eq 3 ]
	printf '0\n' >"${BATS_TEST_TMPDIR}/polls"
	QUEUE_POLLS=100 run mail_send_check root@a.example lss-verify@a.example 3
	[ "${status}" -eq 1 ]
	[[ ${output} == *'still in the Postfix queue after 3 s'* ]]
	# shellcheck disable=SC2329 # called by mail_send_check
	sendmail() { return 75; }
	run mail_send_check root@a.example lss-verify@a.example 3
	[[ ${output} == *'sendmail does not accept a message'* ]]
}

@test "master.cf runs nothing chrooted and carries every service Postfix needs" {
	run mail_master_cf
	[[ ${output} == *pickup*cleanup*qmgr*smtp*local*virtual*lmtp*postlogd* ]]
	run awk 'NF >= 8 && $5 != "n" && $1 != "-o" { print }' <<<"${output}"
	[ -z "${output}" ]
}

@test "the Postfix unit is the instance postfix@- on Debian and postfix on the RHEL family" {
	[ "$(mail_postfix_unit)" = 'postfix@-' ]
	[ "$(mail_postfix_template)" = 'postfix@.service' ]
	# Postfix 3.10 on Debian 13 and Ubuntu 26.04: postfix.service runs the master itself.
	printf '[Service]\nExecStart=/usr/sbin/postfix start\n' >"${BATS_TEST_TMPDIR}/postfix.service"
	# shellcheck disable=SC2329 # called by mail_postfix_unit
	systemctl() { printf '%s\n' "${BATS_TEST_TMPDIR}/postfix.service"; }
	[ "$(mail_postfix_unit)" = postfix ]
	[ "$(mail_postfix_template)" = postfix.service ]
	printf '[Service]\nExecStart=/bin/true\n' >"${BATS_TEST_TMPDIR}/postfix.service"
	[ "$(mail_postfix_unit)" = 'postfix@-' ]
	unset -f systemctl
	use_os rocky-9
	[ "$(mail_postfix_unit)" = postfix ]
	[ "$(mail_ca_bundle)" = /etc/pki/tls/certs/ca-bundle.crt ]
}

# --- mail-relay --------------------------------------------------------------------------------------------------

@test "mail-relay accepts a smarthost with login and refuses bad hosts, ports and addresses" {
	load_module mail-relay
	config_set LSS_MAIL_RELAY_RELAYHOST smtp.example.com:587
	config_set LSS_MAIL_RELAY_USER relay@example.com
	config_set LSS_MAIL_RELAY_PASSWORD secret
	config_set LSS_MAIL_RELAY_FROM server@example.com
	mod_check
	config_set LSS_MAIL_RELAY_RELAYHOST 'smtp.example.com:99999'
	run mod_check
	[[ ${output} == *"'99999' is not a port number."* ]]
	config_set LSS_MAIL_RELAY_RELAYHOST ''
	run mod_check
	[[ ${output} == *"LSS_MAIL_RELAY_USER and LSS_MAIL_RELAY_PASSWORD need LSS_MAIL_RELAY_RELAYHOST."* ]]
	config_set LSS_MAIL_RELAY_USER ''
	config_set LSS_MAIL_RELAY_PASSWORD ''
	config_set LSS_MAIL_RELAY_FORWARD 'admin at example.com'
	run mod_check
	[[ ${output} == *"'admin at example.com' is not an e-mail address."* ]]
}

@test "mail-relay with a smarthost on 465 checks its certificate, logs in and rewrites the sender" {
	load_module mail-relay
	config_set LSS_MAIL_RELAY_RELAYHOST smtp.example.com:465
	config_set LSS_MAIL_RELAY_USER relay@example.com
	config_set LSS_MAIL_RELAY_FROM server@example.com
	run _relay_main host.example.com
	[[ ${output} == *$'\nrelayhost = [smtp.example.com]:465\n'* ]]
	[[ ${output} == *$'\nsmtp_tls_security_level = secure\n'* ]]
	[[ ${output} == *$'\nsmtp_tls_wrappermode = yes\n'* ]]
	[[ ${output} == *$'\nsmtp_sasl_password_maps = texthash:/etc/postfix/lss-sasl-passwd\n'* ]]
	[[ ${output} == *$'\nsmtp_generic_maps = texthash:/etc/postfix/lss-generic'* ]]
	[[ ${output} == *$'\ninet_interfaces = loopback-only\n'* ]]
	[[ ${output} == *'transport_maps = inline:{ lss-verify@host.example.com=discard: }'* ]]
	config_set LSS_MAIL_RELAY_TLS_VERIFY false
	run _relay_main host.example.com
	[[ ${output} == *$'\nsmtp_tls_security_level = encrypt\n'* ]]
}

@test "mail-relay without a smarthost delivers directly with opportunistic TLS, DANE with dns-resolver" {
	load_module mail-relay
	run _relay_main host.example.com
	[[ ${output} == *$'\nrelayhost = \n'* ]]
	[[ ${output} == *$'\nsmtp_tls_security_level = may\n'* ]]
	[[ ${output} != *smtp_sasl* ]]
	state_set dns-resolver status installed
	run _relay_main host.example.com
	[[ ${output} == *$'\nsmtp_tls_security_level = dane\nsmtp_tls_mandatory_protocols'* ]]
	[[ ${output} == *$'\nsmtp_dns_support_level = dnssec'* ]]
}

@test "mail-relay keeps the smarthost password in the secrets and writes it for root only" {
	load_module mail-relay
	config_set LSS_MAIL_RELAY_RELAYHOST smtp.example.com
	config_set LSS_MAIL_RELAY_USER relay@example.com
	config_set LSS_MAIL_RELAY_PASSWORD s3cret
	config_set LSS_MAIL_RELAY_FORWARD admin@example.com
	_relay_tables host.example.com
	[ "$(secret_get mail-relay-password)" = s3cret ]
	grep -qxF "== 0600 root:root /etc/postfix/lss-sasl-passwd" "${WRITES}"
	grep -qxF '[smtp.example.com]:25 relay@example.com:s3cret' "${WRITES}"
	grep -qxF 'root admin@example.com' "${WRITES}"
}

# --- mailserver --------------------------------------------------------------------------------------------------

@test "mailserver needs a domain and refuses bad mailboxes, aliases and settings" {
	load_module mailserver
	run mod_check
	[[ ${output} == *"LSS_MAILSERVER_DOMAINS is empty"* ]]
	config_set LSS_MAILSERVER_DOMAINS 'example.com example.org'
	config_set LSS_MAILSERVER_USERS 'alice bob@example.org'
	config_set LSS_MAILSERVER_ALIASES 'info:alice,bob@example.org'
	mod_check
	config_set LSS_MAILSERVER_USERS 'alice carol@example.net'
	run mod_check
	[[ ${output} == *"carol@example.net is not at one of the mail domains"* ]]
	config_set LSS_MAILSERVER_USERS 'alice alice@example.com'
	run mod_check
	[[ ${output} == *"names alice@example.com twice."* ]]
	config_set LSS_MAILSERVER_USERS 'lss-verify'
	run mod_check
	[[ ${output} == *"lss-verify is reserved"* ]]
	config_set LSS_MAILSERVER_USERS alice
	config_set LSS_MAILSERVER_ALIASES 'alice:bob@example.org'
	run mod_check
	[[ ${output} == *"alice@example.com is a mailbox or another alias already."* ]]
	config_set LSS_MAILSERVER_ALIASES ''
	config_set LSS_MAILSERVER_HOSTNAME example.com
	run mod_check
	[[ ${output} == *"must differ from the mail domains"* ]]
	config_set LSS_MAILSERVER_HOSTNAME ''
	config_set LSS_MAILSERVER_DMARC_POLICY strict
	run mod_check
	[[ ${output} == *"must be none, quarantine or reject."* ]]
	config_set LSS_MAILSERVER_DMARC_POLICY reject
	config_set LSS_MAILSERVER_SPAM_HEADER 20
	run mod_check
	[[ ${output} == *"LSS_MAILSERVER_SPAM_HEADER must be lower than LSS_MAILSERVER_SPAM_REJECT."* ]]
}

@test "postmaster and abuse of every domain go to the first mailbox unless an alias names them" {
	load_module mailserver
	config_set LSS_MAILSERVER_DOMAINS 'example.com example.org'
	config_set LSS_MAILSERVER_USERS 'alice bob@example.org'
	config_set LSS_MAILSERVER_ALIASES 'abuse@example.org:bob@example.org team:alice,bob@example.org'
	_ms_parse
	[ "${MS_ADDRESSES[*]}" = 'alice@example.com bob@example.org' ]
	local key
	key=postmaster@example.com
	[ "${MS_ALIAS[${key}]}" = alice@example.com ]
	key=postmaster@example.org
	[ "${MS_ALIAS[${key}]}" = alice@example.com ]
	key=abuse@example.org
	[ "${MS_ALIAS[${key}]}" = bob@example.org ]
	key=team@example.com
	[ "${MS_ALIAS[${key}]}" = alice@example.com,bob@example.org ]
	[ "$(_ms_hostname)" = mail.example.com ]
	[ "$(_ms_secret bob@example.org)" = mailbox-bob_example.org ]
}

@test "the Postfix tables let each login send as its own address and its aliases only" {
	load_module mailserver
	config_set LSS_MAILSERVER_DOMAINS example.com
	config_set LSS_MAILSERVER_USERS 'alice bob'
	config_set LSS_MAILSERVER_ALIASES 'team:alice,bob,someone@example.net'
	_ms_parse
	_ms_tables
	grep -qxF 'lss-verify@example.com OK' "${WRITES}"
	grep -qxF 'team@example.com alice@example.com,bob@example.com,someone@example.net' "${WRITES}"
	grep -qxF 'alice@example.com alice@example.com' "${WRITES}"
	grep -qxF 'lss-verify@example.com REJECT' "${WRITES}"
	grep -qxF 'root postmaster@example.com' "${WRITES}"
	run grep -c '^team@example.com ' "${WRITES}"
	[ "${output}" = 2 ]
}

@test "Rspamd checks the From header of logged-in senders against the same sender map as Postfix" {
	load_module mailserver
	config_set LSS_MAILSERVER_DOMAINS 'example.com example.org'
	config_set LSS_MAILSERVER_USERS 'alice bob@example.org'
	config_set LSS_MAILSERVER_ALIASES 'info:alice,bob@example.org'
	_ms_parse
	MS_RSPAMD_LUA=${BATS_TEST_TMPDIR}/lua.local.d/lss-sender.lua
	_ms_sender_filter
	[ -d "${BATS_TEST_TMPDIR}/lua.local.d" ]
	# The Rspamd copy of the map is the Postfix map, readable by Rspamd only.
	run sed -n '/^== 0640 root:_rspamd \/etc\/rspamd\/lss-senders.map$/,/^== /p' "${WRITES}"
	[[ ${output} == *$'\nalice@example.com alice@example.com\n'* ]]
	[[ ${output} == *$'\ninfo@example.com alice@example.com,bob@example.org\n'* ]]
	[[ ${output} == *$'\npostmaster@example.org alice@example.com'* ]]
	[ "$(sed -n '2,$p' <<<"${output}" | grep -v '^== ')" = "$(_ms_senders)" ]
	# The Lua prefilter reads that map, needs exactly one From address the login owns and rejects everything else.
	run sed -n "/^== 0644 root:root ${MS_RSPAMD_LUA//\//\\/}$/,\$p" "${WRITES}"
	[[ ${output} == *'local map_path = "/etc/rspamd/lss-senders.map"'* ]]
	[[ ${output} == *'type = "prefilter"'* ]]
	[[ ${output} == *'task:get_user()'* && ${output} == *'#headers == 1 and #from == 1'* ]]
	[[ ${output} == *'task:set_pre_result("reject", reply, "lss")'* ]]
	[[ ${output} == *'local reply = "From header address belongs to another login"'* ]]
	[[ ${output} != *'"Not'* && ${output} != *'"No'* ]]
}

@test "DKIM signs only the domain of the login, and mail of this server only with a key of a hosted domain" {
	load_module mailserver
	config_set LSS_MAILSERVER_DOMAINS example.com
	_ms_parse
	# shellcheck disable=SC2329 # called by _ms_rspamd
	rspamadm() { :; }
	# shellcheck disable=SC2329 # called by _ms_rspamd
	svc_sandbox() { :; }
	MS_RSPAMD=${BATS_TEST_TMPDIR}/local.d
	MS_RSPAMD_LUA=${BATS_TEST_TMPDIR}/lua.local.d/lss-sender.lua
	_ms_rspamd
	run sed -n "/dkim_signing.conf$/,/^== /p" "${WRITES}"
	[[ ${output} == *$'\nallow_username_mismatch = false;\n'* ]]
	[[ ${output} == *$'\nuse_domain = "header";\nuse_esld = true;\n'* ]]
	[[ ${output} == *$'\nsign_local = true;\n'* ]]
	[[ ${output} == *'path = "/var/lib/rspamd/dkim/$domain.$selector.key";'* ]]
	grep -qxF '== 0640 root:_rspamd /etc/rspamd/lss-senders.map' "${WRITES}"
}

@test "main.cf filters every message through Rspamd and allows login only with TLS" {
	load_module mailserver
	config_set LSS_MAILSERVER_DOMAINS 'example.com example.org'
	_ms_parse
	run _ms_main mail.example.com /etc/lss/tls/mail
	[[ ${output} == *$'\nvirtual_mailbox_domains = example.com example.org\n'* ]]
	[[ ${output} == *$'\nsmtpd_milters = inet:127.0.0.1:11332\n'* ]]
	[[ ${output} == *$'\nmilter_default_action = tempfail\n'* ]]
	[[ ${output} == *$'\nsmtpd_tls_auth_only = yes\n'* ]]
	[[ ${output} == *$'\nsmtpd_tls_chain_files = /etc/lss/tls/mail/privkey.pem, /etc/lss/tls/mail/fullchain.pem\n'* ]]
	[[ ${output} == *$'\nmessage_size_limit = 26214400\n'* ]]
	run _ms_master
	[[ ${output} == *$'submission inet'*'-o smtpd_tls_security_level=encrypt'* ]]
	[[ ${output} == *$'465       inet'*'-o smtpd_tls_wrappermode=yes'* ]]
	[[ ${output} == *$'127.0.0.1:10587 inet'*'-o smtpd_tls_security_level=none'* ]]
	[[ ${output} == *'-o smtpd_sender_restrictions=reject_sender_login_mismatch'* ]]
}

@test "dovecot.conf follows the syntax of Dovecot 2.3 or 2.4" {
	load_module mailserver
	config_set LSS_MAILSERVER_DOMAINS example.com
	_ms_parse
	# shellcheck disable=SC2329 # called by _ms_dovecot_24
	dovecot() { printf '2.4.1 (abc)\n'; }
	run _ms_dovecot_conf /etc/lss/tls/mail
	[[ ${output} == *'dovecot_config_version = 2.4.0'* ]]
	[[ ${output} == *'ssl_server_key_file = /etc/lss/tls/mail/privkey.pem'* ]]
	[[ ${output} == *'passwd_file_path = /etc/dovecot/lss-users'* ]]
	[[ ${output} != *mail_location* ]]
	[[ ${output} == *$'inet_listener imap {\n    listen = 127.0.0.1\n    port = 143'* ]]
	# shellcheck disable=SC2329 # called by _ms_dovecot_24
	dovecot() { printf '2.3.21 (47349e2482)\n'; }
	run _ms_dovecot_conf /etc/lss/tls/mail
	[[ ${output} == *'ssl_key = </etc/lss/tls/mail/privkey.pem'* ]]
	[[ ${output} == *'disable_plaintext_auth = yes'* ]]
	[[ ${output} == *$'inet_listener imap {\n    address = 127.0.0.1\n    port = 143'* ]]
	[[ ${output} != *dovecot_config_version* ]]
}

@test "the Dovecot user file keeps a password hash that still matches and blocks logins to the verify mailbox" {
	load_module mailserver
	config_set LSS_MAILSERVER_DOMAINS example.com
	config_set LSS_MAILSERVER_USERS alice
	_ms_parse
	# A stand-in for "openssl passwd -6 [-salt SALT] -stdin" (the test image has no openssl): salt and digest.
	# shellcheck disable=SC2329 # called by _ms_hash
	openssl() {
		local salt="${RANDOM}${RANDOM}" password
		[[ $3 != -salt ]] || salt=$4
		read -r password
		printf '$6$%s$%s\n' "${salt}" "$(printf '%s:%s' "${salt}" "${password}" | sha256sum | cut -c 1-43)"
	}
	MS_USERS=${BATS_TEST_TMPDIR}/lss-users
	_ms_users_file >"${MS_USERS}"
	grep -qE '^alice@example.com:\{SHA512-CRYPT\}\$6\$[^:]+:990:990::/var/vmail/example.com/alice::$' "${MS_USERS}"
	grep -qE '^lss-verify@example.com:.*::nologin=y reason=lss-verify$' "${MS_USERS}"
	run _ms_users_file
	[ "${output}" = "$(<"${MS_USERS}")" ]
	secret_set mailbox-alice_example.com changed
	run _ms_users_file
	[ "$(grep '^alice' <<<"${output}")" != "$(grep '^alice' "${MS_USERS}")" ]
	run grep -c 'changed' "${MS_USERS}"
	[ "${output}" = 0 ]
}

@test "the DNS records name the mail host, SPF, the DKIM key, DMARC and the reverse DNS" {
	load_module mailserver
	config_set LSS_MAILSERVER_DOMAINS example.com
	config_set LSS_MAILSERVER_DMARC_POLICY reject
	local key
	key=$(printf 'A%.0s' {1..400})
	run _ms_dns_records mail.example.com 203.0.113.5 2001:db8::25 "example.com=${key}"
	[[ ${output} == *$'mail.example.com. A 203.0.113.5\n'* ]]
	[[ ${output} == *$'mail.example.com. AAAA 2001:db8::25\n'* ]]
	[[ ${output} == *$'example.com. MX 10 mail.example.com.\n'* ]]
	[[ ${output} == *$'example.com. TXT "v=spf1 mx -all"\n'* ]]
	[[ ${output} == *'lss._domainkey.example.com. TXT "v=DKIM1; k=rsa; p=AAAA'*'" "AAAA'* ]]
	[[ ${output} == *'_dmarc.example.com. TXT "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:postmaster@example.com"'* ]]
	[[ ${output} == *'5.113.0.203.in-addr.arpa. PTR mail.example.com.'* ]]
	[[ ${output} == *'5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. PTR mail.example.com.'* ]]
	run _ms_dns_records mail.example.com '' '' "example.com=${key}"
	[[ ${output} != *PTR* && ${output} != *' A '* ]]
}

@test "the reverse DNS name of IPv6 addresses expands every form" {
	load_module mailserver
	[ "$(_ms_ptr6 ::1)" = "1.$(printf '0.%.0s' {1..31})ip6.arpa." ]
	[ "$(_ms_ptr6 2001:db8:0:0:0:0:0:1)" = "$(_ms_ptr6 2001:db8::1)" ]
	[ "$(_ms_ptr6 fe80::)" = "$(printf '0.%.0s' {1..28})0.8.e.f.ip6.arpa." ]
}

@test "a TXT value longer than 255 characters is split into strings" {
	load_module mailserver
	run _ms_txt "$(printf 'x%.0s' {1..600})"
	[[ ${output} =~ ^\"x{255}\"\ \"x{255}\"\ \"x{90}\"$ ]]
}

# --- webmail -----------------------------------------------------------------------------------------------------

@test "webmail checks its host names and settings, and names the checksum of its release" {
	load_module webmail
	mod_check
	config_set LSS_WEBMAIL_DOMAINS 'mail.example.com bad_name'
	run mod_check
	[[ ${output} == *"'bad_name' is not a host name"* ]]
	config_set LSS_WEBMAIL_DOMAINS ''
	config_set LSS_WEBMAIL_PRODUCT_NAME "Mail'); system('id"
	run mod_check
	[[ ${output} == *"LSS_WEBMAIL_PRODUCT_NAME may contain"* ]]
	config_set LSS_WEBMAIL_PRODUCT_NAME Webmail
	config_set LSS_WEBMAIL_SESSION_LIFETIME 2
	run mod_check
	[[ ${output} == *"between 5 and 1440 minutes."* ]]
}

@test "the Roundcube configuration talks to the local mail server and keeps sessions strict" {
	load_module webmail
	state_set mailserver domain example.com
	run _rc_config
	[[ ${output} == *"\$config['imap_host'] = '127.0.0.1:143';"* ]]
	[[ ${output} == *"\$config['smtp_host'] = '127.0.0.1:10587';"* ]]
	[[ ${output} == *"\$config['username_domain'] = 'example.com';"* ]]
	[[ ${output} == *"\$config['des_key'] = '$(secret_get webmail-des-key)';"* ]]
	[[ ${output} == *"\$config['enable_installer'] = false;"* ]]
	[[ ${output} == *"\$config['identities_level'] = 3;"* ]]
	[[ ${output} == *"\$config['session_lifetime'] = 30;"* ]]
	state_set mailserver hostname mail.example.com
	[ "$(_rc_domains)" = mail.example.com ]
}

# --- guard -------------------------------------------------------------------------------------------------------

@test "the guard warns when it has an address but no sendmail to reach it" {
	load_module guard
	config_set LSS_GUARD_EMAIL admin@example.com
	# A PATH with date (for the log line) and without sendmail.
	mkdir -p "${BATS_TEST_TMPDIR}/bin"
	ln -s "$(command -v date)" "${BATS_TEST_TMPDIR}/bin/date"
	PATH=${BATS_TEST_TMPDIR}/bin run _guard_mail_check
	[[ ${output} == *"LSS_GUARD_EMAIL is set, but this server cannot send mail yet; install mail-relay"* ]]
	config_set LSS_GUARD_EMAIL ''
	run _guard_mail_check
	[ -z "${output}" ]
}
