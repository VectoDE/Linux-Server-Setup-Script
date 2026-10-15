# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="mailserver"
MOD_GROUP="mail"
MOD_DESCRIPTION="Mail server for your domains: Postfix (SMTP, submission with TLS and login only), Dovecot (IMAPS), Rspamd (spam filter, DKIM signing, SPF, DKIM and DMARC checks); prints the DNS records to set"
MOD_REQUIRES="system"
MOD_CONFLICTS="mail-relay"
MOD_OPTIONS="domains||Mail domains, separated by spaces; the first one is the main domain (required)
hostname||Host name of the mail server (MX record, greeting, certificate); empty: mail.<main domain>
users||Mailboxes, separated by spaces: addresses (alice@example.com) or local parts of the main domain (alice); the password of each with lss secrets show mailbox-alice_example.com
aliases||Aliases as SOURCE:TARGET, separated by spaces (info:alice, sales@example.org:bob@example.com, team:alice,bob); postmaster and abuse of every domain go to the first mailbox unless set here
certificate||Certificate directory below /etc/lss/tls, for example default from the tls module when LSS_TLS_DOMAINS contains the host name; empty: a self-signed certificate
dkim_selector|lss|DKIM selector (the DNS name SELECTOR._domainkey.DOMAIN)
dmarc_policy|quarantine|Policy in the printed DMARC record: none, quarantine or reject
message_size|25|Largest message in MB
spam_reject|15|Rspamd score from which a message is rejected
spam_header|6|Rspamd score from which a message gets a spam header (X-Spam: Yes)"
MOD_SECRETS="mailbox-<local part>_<domain>"
MOD_PORTS="25/tcp (SMTP), 465/tcp and 587/tcp (submission, TLS and login required), 993/tcp (IMAPS); IMAP 143 and submission 10587 for webmail on 127.0.0.1 only"

MS_DOVECOT_CONF=/etc/dovecot/dovecot.conf
MS_USERS=/etc/dovecot/lss-users
MS_VMAIL=/var/vmail
MS_VMAIL_USER=vmail
MS_MAILBOXES=/etc/postfix/lss-mailboxes
MS_VIRTUAL=/etc/postfix/lss-virtual
MS_SENDERS=/etc/postfix/lss-senders
MS_ALIASES=/etc/postfix/lss-aliases
# The first line of the files lss writes for this module.
MS_HEADER='# Managed by lss (module mailserver).'
MS_RECIPIENT_ACCESS=/etc/postfix/lss-recipient-access
MS_RSPAMD=/etc/rspamd/local.d
# The header-From check of Rspamd: its Lua rule and its copy of the sender map, below /etc/rspamd so that Rspamd may
# read them under SELinux and AppArmor.
MS_RSPAMD_LUA=/etc/rspamd/lua.local.d/lss-sender.lua
MS_RSPAMD_SENDERS=/etc/rspamd/lss-senders.map
MS_DKIM_DIR=/var/lib/rspamd/dkim
MS_RSPAMD_USER=_rspamd
MS_DNS_FILE=/etc/lss/mailserver-dns.txt
MS_MILTER=127.0.0.1:11332
MS_SCANNER=127.0.0.1:11333
# Webmail on the same server logs in on these listeners, which only 127.0.0.1 reaches.
MS_LOCAL_IMAP=143
MS_LOCAL_SUBMISSION=10587
# Mailboxes, aliases and domains as parsed by _ms_parse.
declare -ga MS_DOMAINS=() MS_ADDRESSES=()
declare -gA MS_ALIAS=()

# _ms_parse: reads the domains, mailboxes and aliases of the settings into MS_DOMAINS, MS_ADDRESSES and MS_ALIAS (source
# address -> comma-separated targets), with the postmaster and abuse defaults. Stops on anything invalid.
_ms_parse() {
	local domain entry address source targets target out local_part key
	local -A seen=()
	read -ra MS_DOMAINS <<<"$(opt domains)"
	((${#MS_DOMAINS[@]} > 0)) || die "LSS_MAILSERVER_DOMAINS is empty: name at least one mail domain (example.com)."
	for domain in "${MS_DOMAINS[@]}"; do
		mail_valid_domain "${domain}" || die "LSS_MAILSERVER_DOMAINS: '${domain}' is not a domain like example.com."
		[[ -z ${seen[${domain}]+x} ]] || die "LSS_MAILSERVER_DOMAINS names ${domain} twice."
		seen[${domain}]=1
	done
	MS_ADDRESSES=()
	for entry in $(opt users); do
		address=$(_ms_address "${entry}")
		_ms_check_address "${address}" LSS_MAILSERVER_USERS
		[[ ${address%@*} != "${MAIL_VERIFY_LOCALPART}" ]] || die "LSS_MAILSERVER_USERS: ${MAIL_VERIFY_LOCALPART} is reserved for lss verify."
		[[ -z ${seen[${address}]+x} ]] || die "LSS_MAILSERVER_USERS names ${address} twice."
		seen[${address}]=1
		MS_ADDRESSES+=("${address}")
	done
	MS_ALIAS=()
	for entry in $(opt aliases); do
		[[ ${entry} == *:* ]] || die "LSS_MAILSERVER_ALIASES: '${entry}' is not SOURCE:TARGET."
		source=$(_ms_address "${entry%%:*}")
		_ms_check_address "${source}" LSS_MAILSERVER_ALIASES
		[[ -z ${seen[${source}]+x} ]] || die "LSS_MAILSERVER_ALIASES: ${source} is a mailbox or another alias already."
		seen[${source}]=1
		out=''
		IFS=, read -ra targets <<<"${entry#*:}"
		((${#targets[@]} > 0)) || die "LSS_MAILSERVER_ALIASES: '${entry}' has no target."
		for target in "${targets[@]}"; do
			target=$(_ms_address "${target}")
			[[ ${target} =~ ^[a-z0-9._+-]+@([a-z0-9-]+\.)+[a-z0-9-]+$ ]] ||
				die "LSS_MAILSERVER_ALIASES: '${target}' is not an e-mail address."
			out+="${out:+,}${target}"
		done
		MS_ALIAS[${source}]=${out}
	done
	# Every domain needs postmaster (RFC 5321) and abuse; they go to the first mailbox unless the settings say otherwise.
	if ((${#MS_ADDRESSES[@]} > 0)); then
		for domain in "${MS_DOMAINS[@]}"; do
			for local_part in postmaster abuse; do
				key="${local_part}@${domain}"
				[[ -n ${seen[${key}]+x} ]] || MS_ALIAS[${key}]=${MS_ADDRESSES[0]}
			done
		done
	fi
	return
}

# _ms_address ENTRY: ENTRY as an address; a local part alone belongs to the main domain.
_ms_address() {
	local entry=${1,,}
	if [[ ${entry} == *@* ]]; then
		printf '%s' "${entry}"
	else
		printf '%s@%s' "${entry}" "${MS_DOMAINS[0]}"
	fi
	return
}

# _ms_check_address ADDRESS SETTING: a mailbox or alias address must be a local part at one of the mail domains.
_ms_check_address() {
	local address=$1 setting=$2 domain
	[[ ${address%@*} =~ ^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$ ]] ||
		die "${setting}: '${address}' needs a local part of a-z, 0-9, '.', '_' and '-'."
	for domain in "${MS_DOMAINS[@]}"; do
		[[ ${address#*@} != "${domain}" ]] || return 0
	done
	die "${setting}: ${address} is not at one of the mail domains (${MS_DOMAINS[*]})."
}

# _ms_secret ADDRESS: the name of the secret with the password of a mailbox.
_ms_secret() {
	printf 'mailbox-%s' "${1/@/_}"
	return
}

_ms_hostname() {
	local hostname
	hostname=$(opt hostname)
	printf '%s' "${hostname:-mail.${MS_DOMAINS[0]}}"
	return
}

# _ms_cert_dir: where the certificate of the mail host name is.
_ms_cert_dir() {
	local name
	name=$(opt certificate)
	if [[ -n ${name} ]]; then
		printf '%s/%s' "${WEB_TLS_DIR}" "${name}"
	else
		printf '%s' "${MAIL_TLS_DIR}"
	fi
	return
}

mod_check() {
	local hostname number name domain
	_ms_parse
	hostname=$(_ms_hostname)
	mail_valid_domain "${hostname}" || die "LSS_MAILSERVER_HOSTNAME: '${hostname}' is not a full host name like mail.example.com."
	for domain in "${MS_DOMAINS[@]}"; do
		[[ ${domain} != "${hostname}" ]] ||
			die "LSS_MAILSERVER_HOSTNAME must differ from the mail domains (use mail.${domain} as the host name)."
	done
	[[ $(opt dkim_selector) =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] ||
		die "LSS_MAILSERVER_DKIM_SELECTOR must be a DNS label such as lss or 2026."
	[[ $(opt dmarc_policy) =~ ^(none|quarantine|reject)$ ]] || die "LSS_MAILSERVER_DMARC_POLICY must be none, quarantine or reject."
	number=$(opt_int message_size)
	((number >= 1 && number <= 200)) || die "LSS_MAILSERVER_MESSAGE_SIZE must be between 1 and 200 (MB)."
	(($(opt_int spam_header) < $(opt_int spam_reject))) ||
		die "LSS_MAILSERVER_SPAM_HEADER must be lower than LSS_MAILSERVER_SPAM_REJECT."
	name=$(opt certificate)
	if [[ -n ${name} ]]; then
		[[ ${name} =~ ^[a-z0-9][a-z0-9.-]*$ ]] || die "LSS_MAILSERVER_CERTIFICATE: '${name}' is not a certificate name."
	fi
	return
}

mod_install() {
	mail_postfix_install
	if os_is_rhel; then
		pkg_enable_epel
	fi
	repo_add rspamd
	pkg_install_family "dovecot-core dovecot-imapd dovecot-lmtpd rspamd openssl" "dovecot rspamd openssl"
	return
}

# --- Dovecot ---------------------------------------------------------------------------------------------------------

# _ms_dovecot_24: Dovecot 2.4 (Debian 13, Ubuntu 26.04) has a new configuration syntax; the others run 2.3.
_ms_dovecot_24() {
	[[ $(dovecot --version 2>/dev/null) == 2.4* ]]
	return
}

_ms_vmail_user() {
	if ! getent passwd "${MS_VMAIL_USER}" >/dev/null; then
		useradd --system --user-group --home-dir "${MS_VMAIL}" --no-create-home --shell "$(command -v nologin)" \
			"${MS_VMAIL_USER}"
		files_note_change "created user ${MS_VMAIL_USER}"
	fi
	if [[ ! -d ${MS_VMAIL} ]]; then
		install -d -m 0700 -o "${MS_VMAIL_USER}" -g "${MS_VMAIL_USER}" "${MS_VMAIL}"
		files_note_change "created ${MS_VMAIL}"
	fi
	# Under SELinux Dovecot may write mailboxes only with the label of the mail spool.
	if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v semanage >/dev/null 2>&1; then
		if ! semanage fcontext -l -C 2>/dev/null | grep -qF "${MS_VMAIL}(/.*)?"; then
			semanage fcontext -a -t mail_spool_t "${MS_VMAIL}(/.*)?"
			files_note_change "SELinux label for ${MS_VMAIL}"
		fi
		restorecon -R "${MS_VMAIL}" 2>/dev/null || true
	fi
	return
}

# _ms_hash SECRET [OLD]: the SHA512-CRYPT hash of a password, the one in OLD when it still matches (a new salt on every
# run would rewrite the user file each time). The password goes to openssl on standard input.
_ms_hash() {
	local name=$1 old=${2:-} password salt hash
	secret_load "${name}" password 24
	if [[ ${old} =~ ^\$6\$([A-Za-z0-9./]{1,16})\$ ]]; then
		salt=${BASH_REMATCH[1]}
		hash=$(openssl passwd -6 -salt "${salt}" -stdin <<<"${password}")
		if [[ ${hash} == "${old}" ]]; then
			printf '%s' "${old}"
			return 0
		fi
	fi
	openssl passwd -6 -stdin <<<"${password}"
	return
}

# _ms_users_file: the passwd-file of Dovecot: every mailbox with its hash, uid, gid and home, and the verify mailbox,
# which cannot log in (a random password nobody knows, and nologin).
_ms_users_file() {
	local address old hash uid gid home
	local -A current=()
	uid=$(id -u "${MS_VMAIL_USER}")
	gid=$(id -g "${MS_VMAIL_USER}")
	if [[ -f ${MS_USERS} ]]; then
		while IFS=: read -r address hash _; do
			[[ ${address} == '#'* || -z ${address} ]] || current[${address}]=${hash#\{SHA512-CRYPT\}}
		done <"${MS_USERS}"
	fi
	printf '# Managed by lss (module mailserver). Mailboxes come from LSS_MAILSERVER_USERS.\n'
	for address in "${MS_ADDRESSES[@]}" "${MAIL_VERIFY_LOCALPART}@${MS_DOMAINS[0]}"; do
		old=${current[${address}]:-}
		if [[ ${address%@*} == "${MAIL_VERIFY_LOCALPART}" ]]; then
			hash=$(_ms_hash mailserver-verify "${old}")
		else
			hash=$(_ms_hash "$(_ms_secret "${address}")" "${old}")
		fi
		home="${MS_VMAIL}/${address#*@}/${address%@*}"
		printf '%s:{SHA512-CRYPT}%s:%s:%s::%s::' "${address}" "${hash}" "${uid}" "${gid}" "${home}"
		[[ ${address%@*} != "${MAIL_VERIFY_LOCALPART}" ]] || printf 'nologin=y reason=lss-verify'
		printf '\n'
	done
	return
}

# _ms_dovecot_conf CERTDIR: the whole dovecot.conf (the distribution's conf.d is not included).
_ms_dovecot_conf() {
	local cert=$1 listen='*' address=address
	[[ $(mail_inet_protocols) == ipv4 ]] || listen='*, ::'
	# Dovecot 2.4 names the address of a listener "listen".
	! _ms_dovecot_24 || address=listen
	printf '# Managed by lss (module mailserver). Change LSS_MAILSERVER_* in /etc/lss/lss.conf and run lss configure mailserver.\n'
	if _ms_dovecot_24; then
		cat <<EOF
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0
protocols {
  imap = yes
  lmtp = yes
}
mail_driver = maildir
mail_path = ~/Maildir
ssl_server_cert_file = ${cert}/fullchain.pem
ssl_server_key_file = ${cert}/privkey.pem
ssl_server_prefer_ciphers = client
auth_allow_cleartext = no
passdb passwd-file {
  passwd_file_path = ${MS_USERS}
}
userdb passwd-file {
  passwd_file_path = ${MS_USERS}
}
EOF
	else
		cat <<EOF
protocols = imap lmtp
mail_location = maildir:~/Maildir
ssl_cert = <${cert}/fullchain.pem
ssl_key = <${cert}/privkey.pem
ssl_prefer_server_ciphers = no
disable_plaintext_auth = yes
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u ${MS_USERS}
}
userdb {
  driver = passwd-file
  args = username_format=%u ${MS_USERS}
}
EOF
	fi
	cat <<EOF
listen = ${listen}
login_greeting = IMAP ready.
mail_uid = ${MS_VMAIL_USER}
mail_gid = ${MS_VMAIL_USER}
first_valid_uid = $(id -u "${MS_VMAIL_USER}")
last_valid_uid = $(id -u "${MS_VMAIL_USER}")
ssl = yes
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ${WEB_TLS_CIPHERS}
auth_mechanisms = plain login
log_path = syslog
syslog_facility = mail
namespace inbox {
  inbox = yes
  separator = /
  mailbox Drafts {
    special_use = \\Drafts
    auto = subscribe
  }
  mailbox Sent {
    special_use = \\Sent
    auto = subscribe
  }
  mailbox Junk {
    special_use = \\Junk
    auto = subscribe
  }
  mailbox Trash {
    special_use = \\Trash
    auto = subscribe
  }
  mailbox Archive {
    special_use = \\Archive
    auto = subscribe
  }
}
# IMAP only with TLS from the start (993); plain IMAP on 127.0.0.1 for webmail, where Dovecot allows a password
# without TLS because the connection does not leave the server.
service imap-login {
  inet_listener imap {
    ${address} = 127.0.0.1
    port = ${MS_LOCAL_IMAP}
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
	return
}

_ms_dovecot() {
	local cert=$1 before config users output
	before=$(files_changes_of mailserver)
	users=$(_ms_users_file)
	file_write 0640 root:dovecot "${MS_USERS}" <<<"${users}"
	config=$(_ms_dovecot_conf "${cert}")
	file_write 0644 root:root "${MS_DOVECOT_CONF}" <<<"${config}"
	output=$(doveconf -n 2>&1 >/dev/null) || {
		printf '%s\n' "${output}" >&2
		die "mailserver: Dovecot rejects ${MS_DOVECOT_CONF}."
	}
	# Dovecot puts its sockets for Postfix there; Postfix 3.10 creates the directory only on its first start, which
	# comes later, and the sandbox needs it to exist. Postfix's own owner and mode.
	[[ -d /var/spool/postfix/private ]] || install -d -m 0700 -o postfix -g root /var/spool/postfix/private
	svc_sandbox dovecot.service "ReadWritePaths=${MS_VMAIL}" ReadWritePaths=-/var/lib/dovecot \
		ReadWritePaths=/var/spool/postfix/private
	svc_enable dovecot
	if [[ $(files_changes_of mailserver) != "${before}" ]]; then
		svc_restart dovecot || die "mailserver: Dovecot does not start with the new configuration."
	fi
	return
}

# --- Rspamd ----------------------------------------------------------------------------------------------------------

# _ms_dkim_key DOMAIN: the DKIM key of DOMAIN (RSA 2048, made once); prints the public key for the DNS record.
_ms_dkim_key() {
	local domain=$1 key
	key="${MS_DKIM_DIR}/${domain}.$(opt dkim_selector).key"
	install -d -m 0750 -o root -g "${MS_RSPAMD_USER}" "${MS_DKIM_DIR}"
	if [[ ! -s ${key} ]]; then
		(
			umask 077
			openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${key}.new" 2>/dev/null
		) || die "mailserver: could not create the DKIM key for ${domain}."
		mv -f -- "${key}.new" "${key}"
		files_note_change "DKIM key for ${domain}"
	fi
	if [[ $(stat -c '%a %U:%G' "${key}") != "640 root:${MS_RSPAMD_USER}" ]]; then
		chown "root:${MS_RSPAMD_USER}" "${key}"
		chmod 0640 "${key}"
	fi
	openssl pkey -in "${key}" -pubout -outform DER 2>/dev/null | base64 -w 0
	return
}

_ms_rspamd() {
	local before
	before=$(files_changes_of mailserver)
	install -d -m 0755 "${MS_RSPAMD}"
	# The scanner and the milter on 127.0.0.1 only; they never read files a client names. The controller (web interface,
	# training) stays off.
	file_write 0644 root:root "${MS_RSPAMD}/worker-normal.inc" <<EOF
# Managed by lss (module mailserver).
bind_socket = "${MS_SCANNER}";
allow_file_and_shm_inputs = false;
EOF
	file_write 0644 root:root "${MS_RSPAMD}/worker-proxy.inc" <<EOF
# Managed by lss (module mailserver).
bind_socket = "${MS_MILTER}";
milter = yes;
timeout = 120s;
allow_file_and_shm_inputs = false;
upstream "local" {
  default = yes;
  hosts = "${MS_SCANNER}";
}
EOF
	file_write 0644 root:root "${MS_RSPAMD}/worker-controller.inc" <<'EOF'
# Managed by lss (module mailserver): no web interface.
enabled = false;
EOF
	file_write 0644 root:root "${MS_RSPAMD}/actions.conf" <<EOF
# Managed by lss (module mailserver). Change LSS_MAILSERVER_SPAM_* and run lss configure mailserver.
reject = $(opt_int spam_reject);
add_header = $(opt_int spam_header);
greylist = null;
EOF
	# Mail from logged-in users and from this server is signed with the key of the domain in its From header (or of the
	# domain above a host name: root@mail.example.com signs as example.com), and only when Rspamd has a key for that
	# domain. A logged-in user gets a signature only for the domain of the login (allow_username_mismatch = false), and
	# the header-From check (_ms_sender_filter) has already refused every From address the login does not own; an
	# alias of another domain is delivered, but unsigned. sign_local covers mail that leaves this server itself
	# (sendmail, cron, the guard, local SMTP without a login): whoever runs programs here can read and send as the
	# server anyway, so it is trusted like the server; a From of a domain this server does not host gets no key and
	# no signature.
	file_write 0644 root:root "${MS_RSPAMD}/dkim_signing.conf" <<EOF
# Managed by lss (module mailserver).
enabled = true;
sign_authenticated = true;
sign_local = true;
use_domain = "header";
use_esld = true;
allow_username_mismatch = false;
selector = "$(opt dkim_selector)";
path = "${MS_DKIM_DIR}/\$domain.\$selector.key";
EOF
	file_write 0644 root:root "${MS_RSPAMD}/milter_headers.conf" <<'EOF'
# Managed by lss (module mailserver).
use = ["authentication-results", "x-spam-status"];
authenticated_headers = ["authentication-results"];
# Mail from this server gets the headers too (lss verify checks them); mail of logged-in users does not.
skip_local = false;
skip_authenticated = true;
EOF
	file_write 0644 root:root "${MS_RSPAMD}/logging.inc" <<'EOF'
# Managed by lss (module mailserver): to the journal.
type = "syslog";
level = "notice";
EOF
	_ms_sender_filter
	rspamadm configtest >/dev/null 2>&1 || {
		rspamadm configtest >&2 || true
		die "mailserver: Rspamd rejects its configuration."
	}
	svc_sandbox rspamd.service ReadWritePaths=/var/lib/rspamd ReadWritePaths=-/var/log/rspamd
	svc_enable rspamd
	if [[ $(files_changes_of mailserver) != "${before}" ]]; then
		svc_restart rspamd || die "mailserver: Rspamd does not start with the new configuration."
	fi
	return
}

# _ms_sender_filter: Postfix ties only the envelope sender to the login (reject_sender_login_mismatch); this Rspamd
# prefilter does the same for the From header, which recipients see and DKIM signs. A logged-in sender passes only with
# exactly one From address that the login owns (its own address or an alias leading to it, from the sender map).
_ms_sender_filter() {
	install -d -m 0755 "${MS_RSPAMD_LUA%/*}"
	_ms_senders | file_write 0640 "root:${MS_RSPAMD_USER}" "${MS_RSPAMD_SENDERS}"
	file_write 0644 root:root "${MS_RSPAMD_LUA}" <<EOF
-- ${MS_HEADER#\# } The From header of logged-in senders must name an address of their login.
local rspamd_logger = require "rspamd_logger"

local map_path = "${MS_RSPAMD_SENDERS}"
local reply = "5.7.1 From header address belongs to another login"
local senders = {}
local loaded = false

local file = io.open(map_path, "r")
if file then
  for line in file:lines() do
    local address, logins = line:match("^([^#%s]%S*)%s+(%S+)%s*$")
    if address then
      local owners = {}
      for login in logins:gmatch("[^,]+") do
        owners[login:lower()] = true
      end
      senders[address:lower()] = owners
    end
  end
  file:close()
  loaded = true
else
  rspamd_logger.errx(rspamd_config, "lss: %s is missing; mail of logged-in senders is rejected", map_path)
end

rspamd_config:register_symbol({
  name = "LSS_FROM_LOGIN_MISMATCH",
  type = "prefilter",
  callback = function(task)
    local user = task:get_user()
    if not user then
      return false
    end
    local login = user:lower()
    local headers = task:get_header_full("From") or {}
    local from = task:get_from("mime") or {}
    local address = (#headers == 1 and #from == 1 and from[1].addr or ""):lower()
    local owners = loaded and senders[address]
    if owners and owners[login] then
      return false
    end
    rspamd_logger.infox(task, "lss: login %s may not send as From <%s>", login, address)
    task:set_pre_result("reject", reply, "lss")
    return true
  end,
})
EOF
	return
}

# --- Postfix ---------------------------------------------------------------------------------------------------------

# _ms_tables: the mailboxes, the aliases, which login may send as which address, and the local aliases of root.
# _ms_senders: the sender map, ADDRESS LOGIN[,LOGIN...] per line. A login sends as its own address and as the aliases
# that lead to it. Postfix checks the envelope sender with it, Rspamd the address in the From header.
_ms_senders() {
	local address source target
	local -a owners=()
	printf '%s\n' "${MS_HEADER}"
	for address in "${MS_ADDRESSES[@]}"; do
		printf '%s %s\n' "${address}" "${address}"
	done
	for source in $(printf '%s\n' "${!MS_ALIAS[@]}" | sort); do
		owners=()
		for target in ${MS_ALIAS[${source}]//,/ }; do
			[[ " ${MS_ADDRESSES[*]} " != *" ${target} "* ]] || owners+=("${target}")
		done
		((${#owners[@]} == 0)) || printf '%s %s\n' "${source}" "$(
			IFS=,
			printf '%s' "${owners[*]}"
		)"
	done
	return
}

_ms_tables() {
	local address source verify
	verify="${MAIL_VERIFY_LOCALPART}@${MS_DOMAINS[0]}"
	{
		printf '%s\n' "${MS_HEADER}"
		for address in "${MS_ADDRESSES[@]}" "${verify}"; do
			printf '%s OK\n' "${address}"
		done
	} | file_write 0644 root:root "${MS_MAILBOXES}"
	{
		printf '%s\n' "${MS_HEADER}"
		for source in $(printf '%s\n' "${!MS_ALIAS[@]}" | sort); do
			printf '%s %s\n' "${source}" "${MS_ALIAS[${source}]}"
		done
	} | file_write 0644 root:root "${MS_VIRTUAL}"
	_ms_senders | file_write 0644 root:root "${MS_SENDERS}"
	# Nobody outside reaches the verify mailbox; lss verify delivers to it with sendmail.
	printf '# Managed by lss (module mailserver).\n%s REJECT\n' "${verify}" |
		file_write 0644 root:root "${MS_RECIPIENT_ACCESS}"
	{
		printf '# Managed by lss (module mailserver). Mail for root and the system accounts.\n'
		# texthash reads "key value" lines, not the "key: value" lines of aliases(5).
		printf 'postmaster root\nabuse root\nroot postmaster@%s\n' "${MS_DOMAINS[0]}"
	} | file_write 0644 root:root "${MS_ALIASES}"
	return
}

_ms_main() {
	local hostname=$1 cert=$2 level=may
	state_installed dns-resolver && level=dane
	cat <<EOF
# Managed by lss (module mailserver). Change LSS_MAILSERVER_* in /etc/lss/lss.conf and run lss configure mailserver.
compatibility_level = 3.6
myhostname = ${hostname}
mydomain = ${MS_DOMAINS[0]}
myorigin = \$myhostname
mydestination = \$myhostname, localhost.localdomain, localhost
inet_interfaces = all
inet_protocols = $(mail_inet_protocols)
mynetworks = 127.0.0.0/8 [::1]/128
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
message_size_limit = $(($(opt_int message_size) << 20))
mailbox_size_limit = 0
recipient_delimiter = +
virtual_mailbox_domains = ${MS_DOMAINS[*]}
virtual_mailbox_maps = texthash:${MS_MAILBOXES}
virtual_alias_maps = texthash:${MS_VIRTUAL}
virtual_transport = lmtp:unix:private/dovecot-lmtp
alias_maps = texthash:${MS_ALIASES}
alias_database =
forward_path =
allow_mail_to_commands =
allow_mail_to_files =
disable_vrfy_command = yes
smtpd_helo_required = yes
strict_rfc821_envelopes = yes
smtpd_client_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_pipelining
smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname
smtpd_sender_restrictions = permit_mynetworks, reject_non_fqdn_sender, reject_unknown_sender_domain
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_recipient_restrictions = check_recipient_access texthash:${MS_RECIPIENT_ACCESS}, reject_non_fqdn_recipient, reject_unknown_recipient_domain
smtpd_data_restrictions = reject_unauth_pipelining
smtpd_sender_login_maps = texthash:${MS_SENDERS}
smtpd_client_auth_rate_limit = 10
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = no
smtpd_sasl_security_options = noanonymous, noplaintext
smtpd_sasl_tls_security_options = noanonymous
smtpd_tls_chain_files = ${cert}/privkey.pem, ${cert}/fullchain.pem
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high
smtpd_tls_received_header = yes
smtpd_tls_loglevel = 1
smtp_tls_security_level = ${level}
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_CAfile = $(mail_ca_bundle)
smtp_tls_loglevel = 1
# Every message passes Rspamd: spam filter, DKIM signing, SPF, DKIM and DMARC checks. While Rspamd is down, mail waits.
smtpd_milters = inet:${MS_MILTER}
non_smtpd_milters = \$smtpd_milters
milter_default_action = tempfail
milter_protocol = 6
milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}
EOF
	[[ ${level} != dane ]] || printf 'smtp_dns_support_level = dnssec\n'
	return
}

# _ms_submission NAME LISTEN [OPTION...]: a master.cf listener for logged-in users (submission).
_ms_submission() {
	local name=$1 listen=$2 option
	shift 2
	printf '%-9s inet  n       -       n       -       -       smtpd\n' "${listen}"
	for option in "syslog_name=postfix/${name}" smtpd_sasl_auth_enable=yes \
		smtpd_client_restrictions=permit_sasl_authenticated,reject smtpd_helo_restrictions= \
		smtpd_sender_restrictions=reject_sender_login_mismatch smtpd_recipient_restrictions= \
		smtpd_relay_restrictions=permit_sasl_authenticated,reject milter_macro_daemon_name=ORIGINATING "$@"; do
		printf '  -o %s\n' "${option}"
	done
	return
}

_ms_master() {
	printf '%s\n' "${MS_HEADER}"
	printf 'smtp      inet  n       -       n       -       -       smtpd\n'
	_ms_submission submission submission smtpd_tls_security_level=encrypt smtpd_tls_auth_only=yes
	_ms_submission submissions 465 smtpd_tls_wrappermode=yes smtpd_tls_security_level=encrypt smtpd_tls_auth_only=yes
	_ms_submission webmail "127.0.0.1:${MS_LOCAL_SUBMISSION}" smtpd_tls_security_level=none smtpd_tls_auth_only=no \
		smtpd_sasl_security_options=noanonymous
	mail_master_cf
	return
}

# --- DNS records -----------------------------------------------------------------------------------------------------

# _ms_ptr4 ADDRESS / _ms_ptr6 ADDRESS: the reverse DNS name of an IPv4 or IPv6 address.
_ms_ptr4() {
	local address=$1 a b c d
	IFS=. read -r a b c d <<<"${address}"
	printf '%s.%s.%s.%s.in-addr.arpa.' "${d}" "${c}" "${b}" "${a}"
	return
}

_ms_ptr6() {
	local address=$1 group full='' out='' i missing
	local -a head=() tail=() groups=()
	if [[ ${address} == *::* ]]; then
		IFS=: read -ra head <<<"${address%%::*}"
		IFS=: read -ra tail <<<"${address#*::}"
		missing=$((8 - ${#head[@]} - ${#tail[@]}))
		groups=("${head[@]}")
		for ((i = 0; i < missing; i++)); do
			groups+=(0)
		done
		groups+=("${tail[@]}")
	else
		IFS=: read -ra groups <<<"${address}"
	fi
	for group in "${groups[@]}"; do
		full+=$(printf '%04x' "$((16#${group:-0}))")
	done
	for ((i = ${#full} - 1; i >= 0; i--)); do
		out+="${full:i:1}."
	done
	printf '%sip6.arpa.' "${out}"
	return
}

# _ms_txt TEXT: TEXT as the quoted strings of a TXT record (at most 255 characters each).
_ms_txt() {
	local text=$1 out=''
	while ((${#text} > 255)); do
		out+="\"${text:0:255}\" "
		text=${text:255}
	done
	printf '%s"%s"' "${out}" "${text}"
	return
}

# _ms_dns_records HOSTNAME IPV4 IPV6 DOMAIN=PUBLICKEY...: the records lss cannot set, as zone file lines.
_ms_dns_records() {
	local hostname=$1 ipv4=$2 ipv6=$3 entry domain key
	shift 3
	[[ -z ${ipv4} ]] || printf '%s. A %s\n' "${hostname}" "${ipv4}"
	[[ -z ${ipv6} ]] || printf '%s. AAAA %s\n' "${hostname}" "${ipv6}"
	for entry in "$@"; do
		domain=${entry%%=*}
		key=${entry#*=}
		printf '%s. MX 10 %s.\n' "${domain}" "${hostname}"
		printf '%s. TXT %s\n' "${domain}" "$(_ms_txt 'v=spf1 mx -all')"
		printf '%s._domainkey.%s. TXT %s\n' "$(opt dkim_selector)" "${domain}" "$(_ms_txt "v=DKIM1; k=rsa; p=${key}")"
		printf '_dmarc.%s. TXT %s\n' "${domain}" \
			"$(_ms_txt "v=DMARC1; p=$(opt dmarc_policy); adkim=r; aspf=r; rua=mailto:postmaster@${domain}")"
	done
	# Reverse DNS belongs to whoever owns the address (the hosting provider); it must name the mail host.
	[[ -z ${ipv4} ]] || printf '%s PTR %s.\n' "$(_ms_ptr4 "${ipv4}")" "${hostname}"
	[[ -z ${ipv6} ]] || printf '%s PTR %s.\n' "$(_ms_ptr6 "${ipv6}")" "${hostname}"
	return
}

# _ms_ipv6: the IPv6 address this server sends from on its default route, if it has one.
_ms_ipv6() {
	local route
	route=$(ip -6 -o route get 2001:db8::1 2>/dev/null) || return 0
	sed -n 's/.* src \([0-9a-fA-F:]*\).*/\1/p' <<<"${route}"
	return
}

_ms_dns() {
	local hostname=$1 domain key records line
	local -a keys=()
	for domain in "${MS_DOMAINS[@]}"; do
		key=$(_ms_dkim_key "${domain}")
		keys+=("${domain}=${key}")
	done
	records=$(_ms_dns_records "${hostname}" "$(_fw_host_addresses)" "$(_ms_ipv6)" "${keys[@]}")
	{
		printf '; Managed by lss (module mailserver). DNS records the mail server needs; lss cannot set them.\n'
		printf '%s\n' "${records}"
	} | file_write 0644 root:root "${MS_DNS_FILE}"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		log_info "mailserver: set these DNS records at your DNS provider (also in ${MS_DNS_FILE}); the PTR records at the provider of the addresses:"
		while IFS= read -r line; do
			log_info "mailserver:   ${line}"
		done <<<"${records}"
	fi
	return
}

mod_configure() {
	local before hostname cert main master
	before=$(files_changes_of mailserver)
	_ms_parse
	hostname=$(_ms_hostname)
	cert=$(_ms_cert_dir)
	if [[ -z $(opt certificate) ]]; then
		mail_tls_cert "${hostname}"
	else
		[[ -s ${cert}/fullchain.pem && -s ${cert}/privkey.pem ]] ||
			die "mailserver: ${cert} has no certificate (fullchain.pem, privkey.pem)."
	fi
	_ms_vmail_user
	_ms_rspamd
	_ms_dns "${hostname}"
	_ms_dovecot "${cert}"
	_ms_tables
	main=$(_ms_main "${hostname}" "${cert}")
	master=$(_ms_master)
	mail_postfix_sandbox
	mail_postfix_apply "${main}" "${master}" "${before}"
	fw_allow 25/tcp 465/tcp 587/tcp 993/tcp
	state_set mailserver hostname "${hostname}"
	state_set mailserver domain "${MS_DOMAINS[0]}"
	return
}

# --- Verify ----------------------------------------------------------------------------------------------------------

# _ms_from_test LOGIN FROM: Rspamd's verdict on a message of LOGIN with FROM in its From header.
_ms_from_test() {
	printf 'From: %s\nTo: %s\nSubject: lss sender test\nMessage-ID: <lss-from@%s>\n\nlss verify\n' \
		"$2" "$1" "${MS_DOMAINS[0]}" | rspamc -h "${MS_SCANNER}" --user "$1" symbols 2>/dev/null || true
	return
}

# _ms_gtube: the GTUBE test message, which every spam filter rejects.
_ms_gtube() {
	printf 'From: lss@%s\nTo: %s@%s\nSubject: lss spam filter test\nMessage-ID: <lss-gtube@%s>\n\n' \
		"${MS_DOMAINS[0]}" "${MAIL_VERIFY_LOCALPART}" "${MS_DOMAINS[0]}" "${MS_DOMAINS[0]}"
	printf 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\n'
	return
}

# _ms_served_cert PORT [STARTTLS]: the SHA-256 fingerprint of the certificate a TLS port on 127.0.0.1 presents.
_ms_served_cert() {
	local port=$1 starttls=${2:-}
	local -a args=(-connect "127.0.0.1:${port}")
	[[ -z ${starttls} ]] || args+=(-starttls "${starttls}")
	openssl s_client "${args[@]}" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true
	return
}

mod_verify() {
	local hostname cert expected served port verify id message try result key unit domain
	_ms_parse
	hostname=$(_ms_hostname)
	cert=$(_ms_cert_dir)
	verify="${MAIL_VERIFY_LOCALPART}@${MS_DOMAINS[0]}"
	for unit in "$(mail_postfix_unit)" dovecot rspamd; do
		svc_is_active "${unit}" || die "mailserver: ${unit} is not running."
	done
	postfix check >/dev/null 2>&1 || die "mailserver: postfix check reports a problem."
	doveconf -n >/dev/null 2>&1 || die "mailserver: Dovecot reports a problem with its configuration."
	[[ $(stat -c '%a %U:%G' "${MS_USERS}") == '640 root:dovecot' ]] || die "mailserver: ${MS_USERS} must be mode 640, root:dovecot."
	for port in 25 465 587 993; do
		[[ -n $(ss -Hltn "sport = :${port}") ]] || die "mailserver: nothing listens on port ${port}."
	done
	mon_listen_check "${MS_LOCAL_IMAP}" 127.0.0.1
	mon_listen_check "${MS_LOCAL_SUBMISSION}" 127.0.0.1
	mon_listen_check "${MS_MILTER##*:}" 127.0.0.1
	mon_listen_check "${MS_SCANNER##*:}" 127.0.0.1
	# IMAPS and submission present the certificate of the mail host name.
	expected=$(openssl x509 -noout -fingerprint -sha256 -in "${cert}/fullchain.pem")
	for port in 993:'' 465:'' 587:smtp; do
		served=''
		for ((try = 0; try < 10; try++)); do
			served=$(_ms_served_cert "${port%%:*}" "${port#*:}")
			[[ ${served} != "${expected}" ]] || break
			sleep 1
		done
		[[ ${served} == "${expected}" ]] || die "mailserver: port ${port%%:*} does not present the certificate in ${cert}."
	done
	# The spam filter rejects the GTUBE test message.
	result=''
	for ((try = 0; try < 30; try++)); do
		result=$(_ms_gtube | rspamc -h "${MS_SCANNER}" symbols 2>/dev/null) || true
		[[ ${result} != *'Action: reject'* ]] || break
		sleep 2
	done
	[[ ${result} == *'Action: reject'* && ${result} == *GTUBE* ]] || die "mailserver: Rspamd does not reject the GTUBE test message."
	# A logged-in sender may not put an address of somebody else into From (here the verify mailbox, which no login
	# owns), but passes with its own.
	if ((${#MS_ADDRESSES[@]} > 0)); then
		result=$(_ms_from_test "${MS_ADDRESSES[0]}" "${MAIL_VERIFY_LOCALPART}@${MS_DOMAINS[0]}")
		[[ ${result} == *'Action: reject'* ]] ||
			die "mailserver: Rspamd lets ${MS_ADDRESSES[0]} send with the From address of another login."
		result=$(_ms_from_test "${MS_ADDRESSES[0]}" "${MS_ADDRESSES[0]}")
		[[ ${result} == *'Action:'* && ${result} != *'Action: reject'* ]] ||
			die "mailserver: Rspamd rejects ${MS_ADDRESSES[0]} with its own From address."
	fi
	# The DNS records name the DKIM key Rspamd signs with (its TXT strings joined, as resolvers do).
	for domain in "${MS_DOMAINS[@]}"; do
		key="${MS_DKIM_DIR}/${domain}.$(opt dkim_selector).key"
		[[ -s ${key} ]] || die "mailserver: the DKIM key ${key} is missing."
		sed 's/" "//g' "${MS_DNS_FILE}" |
			grep -qF "p=$(openssl pkey -in "${key}" -pubout -outform DER 2>/dev/null | base64 -w 0)" ||
			die "mailserver: ${MS_DNS_FILE} does not carry the DKIM key of ${domain}."
	done
	# A message through the whole server: sendmail, Postfix, Rspamd (signs it), LMTP into the verify mailbox.
	id=$(mail_send_check "postmaster@${MS_DOMAINS[0]}" "${verify}")
	message=''
	for ((try = 0; try < 20; try++)); do
		message=$(doveadm fetch -u "${verify}" hdr mailbox INBOX header Message-ID "${id}" 2>/dev/null) || true
		[[ -z ${message} ]] || break
		sleep 1
	done
	doveadm expunge -u "${verify}" mailbox INBOX all >/dev/null 2>&1 || true
	[[ -n ${message} ]] || die "mailserver: a test message did not arrive in the mailbox ${verify}."
	# Unfolded, so a header that continues on the next line is one line.
	message=${message//$'\n\t'/ }
	message=${message//$'\n '/ }
	grep -qiE "^DKIM-Signature:.*[; ]d=${MS_DOMAINS[0]//./\\.};" <<<"${message}" ||
		die "mailserver: Rspamd did not sign the test message with the DKIM key of ${MS_DOMAINS[0]}."
	grep -qi '^X-Spam-Status:' <<<"${message}" || die "mailserver: the test message did not pass the spam filter."
	return
}

mod_remove() {
	local unit
	unit=$(mail_postfix_template)
	svc_disable rspamd
	svc_disable dovecot
	svc_disable "$(mail_postfix_unit)"
	svc_disable postfix
	svc_dropin_remove "${unit}" lss-sandbox
	svc_dropin_remove dovecot.service lss-sandbox
	svc_dropin_remove rspamd.service lss-sandbox
	local file
	for file in "${MS_MAILBOXES}" "${MS_VIRTUAL}" "${MS_SENDERS}" "${MS_ALIASES}" "${MS_RECIPIENT_ACCESS}" "${MS_USERS}" \
		"${MS_DOVECOT_CONF}" "${MS_DNS_FILE}" "${MS_RSPAMD}/worker-normal.inc" "${MS_RSPAMD}/worker-proxy.inc" \
		"${MS_RSPAMD}/worker-controller.inc" "${MS_RSPAMD}/actions.conf" "${MS_RSPAMD}/dkim_signing.conf" \
		"${MS_RSPAMD}/milter_headers.conf" "${MS_RSPAMD}/logging.inc" "${MS_RSPAMD_LUA}" "${MS_RSPAMD_SENDERS}"; do
		file_remove "${file}"
	done
	files_forget_path "${MAIL_POSTFIX_MAIN}"
	files_forget_path "${MAIL_POSTFIX_MASTER}"
	pkg_remove_family "rspamd dovecot-imapd dovecot-lmtpd dovecot-core postfix" "rspamd dovecot postfix"
	repo_remove rspamd
	# Mailboxes, DKIM keys and passwords stay unless --purge.
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	rm -rf -- "${MS_VMAIL}" "${MS_DKIM_DIR}" "${MAIL_TLS_DIR}"
	for file in "${LSS_SECRETS_DIR}"/mailbox-* "${LSS_SECRETS_DIR}/mailserver-verify"; do
		if [[ -e ${file} ]]; then
			secret_remove "${file##*/}"
		fi
	done
	files_note_change "deleted the mailboxes and DKIM keys"
	return
}
