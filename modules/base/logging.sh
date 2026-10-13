# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="logging"
MOD_GROUP="base"
MOD_DESCRIPTION="Persistent, size-limited journal; optional log forwarding over TLS (rsyslog)"
MOD_REQUIRES="system"
MOD_OPTIONS="max_use|1G|Disk space the journal may use
retention|3month|How long journal entries are kept (systemd time span, for example 90day or 1year)
remote||Forward all logs to this syslog server (HOST or HOST:PORT, TLS, port 6514 by default)
remote_ca|/etc/ssl/certs/ca-certificates.crt|CA bundle that signed the certificate of the syslog server"

LOGGING_JOURNALD=/etc/systemd/journald.conf.d/60-lss.conf
LOGGING_RSYSLOG=/etc/rsyslog.d/60-lss-remote.conf

_logging_remote_host() {
	local remote
	remote=$(opt remote)
	printf '%s' "${remote%%:*}"
	return
}

_logging_remote_port() {
	local remote
	remote=$(opt remote)
	if [[ ${remote} == *:* ]]; then printf '%s' "${remote##*:}"; else printf '6514'; fi
	return
}

mod_check() {
	local max_use retention remote
	max_use=$(opt max_use)
	retention=$(opt retention)
	remote=$(opt remote)
	[[ ${max_use} =~ ^[0-9]+[KMGT]?$ ]] || die "LSS_LOGGING_MAX_USE '${max_use}' must look like 500M or 2G."
	[[ ${retention} =~ ^[0-9]+(s|min|h|day|week|month|year)$ ]] ||
		die "LSS_LOGGING_RETENTION '${retention}' must look like 90day or 1year."
	if [[ -n ${remote} ]]; then
		[[ ${remote} =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || die "LSS_LOGGING_REMOTE '${remote}' must be HOST or HOST:PORT."
		[[ -r $(opt remote_ca) ]] || die "LSS_LOGGING_REMOTE_CA $(opt remote_ca) does not exist."
	fi
	return
}

mod_install() {
	if [[ -n $(opt remote) ]]; then
		pkg_install_family "rsyslog rsyslog-gnutls" "rsyslog rsyslog-gnutls"
	fi
	return
}

mod_configure() {
	file_write 0644 root:root "${LOGGING_JOURNALD}" <<EOF
# Managed by lss (module logging).
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=$(opt max_use)
MaxRetentionSec=$(opt retention)
ForwardToSyslog=$(if [[ -n $(opt remote) ]]; then printf yes; else printf no; fi)
EOF
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		install -d -m 2755 -g systemd-journal /var/log/journal
		systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
		svc_restart systemd-journald
	fi

	if [[ -n $(opt remote) ]]; then
		local host port
		host=$(_logging_remote_host)
		port=$(_logging_remote_port)
		file_write 0644 root:root "${LOGGING_RSYSLOG}" <<EOF
# Managed by lss (module logging). Forwards every message over TLS; the server certificate must match ${host}.
global(DefaultNetstreamDriverCAFile="$(opt remote_ca)")
*.* action(type="omfwd" target="${host}" port="${port}" protocol="tcp"
	StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
	StreamDriverPermittedPeers="${host}"
	queue.type="LinkedList" queue.size="50000" queue.filename="lss-remote"
	queue.saveOnShutdown="on" action.resumeRetryCount="-1")
EOF
		local changed=${LSS_FILE_CHANGED}
		rsyslogd -N1 >/dev/null 2>&1 || die "logging: rsyslog rejects the forwarding configuration."
		svc_enable rsyslog
		if [[ ${changed} == 1 ]]; then
			svc_restart rsyslog
		fi
	else
		_logging_remove_remote
	fi
	return
}

_logging_remove_remote() {
	[[ -f ${LOGGING_RSYSLOG} ]] || return 0
	file_remove "${LOGGING_RSYSLOG}"
	if svc_is_active rsyslog; then
		svc_restart rsyslog
	fi
}

mod_verify() {
	svc_is_active systemd-journald || die "logging: systemd-journald is not running."
	[[ -d /var/log/journal ]] || die "logging: the journal is not persistent (/var/log/journal is missing)."
	logger -t lss-logging-check "verify $$"
	journalctl --flush >/dev/null 2>&1 || true
	local i
	for ((i = 0; i < 10; i++)); do
		journalctl -t lss-logging-check --since '-2min' --no-pager -q | grep -qF "verify $$" && break
		sleep 1
	done
	journalctl -t lss-logging-check --since '-2min' --no-pager -q | grep -qF "verify $$" ||
		die "logging: a test message did not reach the journal."
	if [[ -n $(opt remote) ]]; then
		svc_is_active rsyslog || die "logging: rsyslog is not running."
	fi
	return
}

mod_remove() {
	_logging_remove_remote
	file_remove "${LOGGING_JOURNALD}"
	svc_restart systemd-journald
	return
}
