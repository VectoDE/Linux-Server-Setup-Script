# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="fail2ban"
MOD_GROUP="security"
MOD_DESCRIPTION="Bans addresses after failed logins (SSH and the jails other modules add), growing ban times"
MOD_REQUIRES="system"
MOD_CONFLICTS="crowdsec"
MOD_OPTIONS="bantime|1h|First ban duration
maxtime|1w|Longest ban for repeat offenders
maxretry|5|Failures within findtime before a ban
findtime|10m|Window for counting failures
ignoreip||Addresses or networks never banned, separated by spaces"

FAIL2BAN_JAIL=/etc/fail2ban/jail.d/00-lss.local
FAIL2BAN_SERVER=/etc/fail2ban/fail2ban.d/00-lss.local
FAIL2BAN_LOG=/var/log/fail2ban.log

mod_check() {
	local value address
	for value in "$(opt bantime)" "$(opt maxtime)" "$(opt findtime)"; do
		[[ ${value} =~ ^[0-9]+[smhdw]?$ ]] || die "fail2ban: '${value}' is not a duration like 10m, 1h or 1w."
	done
	opt_int maxretry >/dev/null
	for address in $(opt ignoreip); do
		[[ ${address} =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] || die "LSS_FAIL2BAN_IGNOREIP: '${address}' is not an address."
	done
	return
}

mod_install() {
	pkg_enable_epel
	pkg_install_family "fail2ban python3-systemd nftables" "fail2ban-server python3-systemd nftables"
	return
}

_fail2ban_ssh_port() {
	local port
	port=$({ sshd -T 2>/dev/null || true; } | awk '$1 == "port" { print $2 }' | paste -sd ',' -)
	printf '%s' "${port:-ssh}"
	return
}

mod_configure() {
	local ignore changed
	ignore="127.0.0.1/8 ::1 $(opt ignoreip)"
	# The recidive jail reads fail2ban's own log; RHEL sends it to the journal by default, so pin it to a file.
	file_write 0644 root:root "${FAIL2BAN_SERVER}" <<EOF
# Managed by lss (module fail2ban).
[Definition]
logtarget = ${FAIL2BAN_LOG}
EOF
	changed=${LSS_FILE_CHANGED}
	[[ ! -L ${FAIL2BAN_LOG} ]] || die "fail2ban: ${FAIL2BAN_LOG} is a symbolic link."
	[[ -e ${FAIL2BAN_LOG} ]] || install -m 0640 -o root -g root /dev/null "${FAIL2BAN_LOG}"
	file_write 0644 root:root "${FAIL2BAN_JAIL}" <<EOF
# Managed by lss (module fail2ban). Other modules add their jails as /etc/fail2ban/jail.d/lss-*.local.
[DEFAULT]
backend = systemd
banaction = nftables-multiport
banaction_allports = nftables-allports
bantime = $(opt bantime)
bantime.increment = true
bantime.maxtime = $(opt maxtime)
findtime = $(opt findtime)
maxretry = $(opt_int maxretry)
ignoreip = ${ignore% }

[sshd]
enabled = true
backend = systemd
port = $(_fail2ban_ssh_port)
mode = aggressive

[recidive]
enabled = true
backend = auto
logpath = ${FAIL2BAN_LOG}
bantime = 1w
findtime = 1d
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	# The Debian default jail reads /var/log/auth.log, which does not exist on journal-only systems.
	fail2ban-client --test >/dev/null 2>&1 || {
		fail2ban-client --test >&2 || true
		die "fail2ban: the configuration does not load."
	}
	svc_enable fail2ban
	if [[ ${changed} == 1 ]]; then
		svc_restart fail2ban
	fi
	return
}

mod_verify() {
	local i
	svc_is_active fail2ban || die "fail2ban: the service is not running."
	for ((i = 0; i < 15; i++)); do
		fail2ban-client ping >/dev/null 2>&1 && break
		sleep 1
	done
	fail2ban-client ping >/dev/null 2>&1 || die "fail2ban: the server does not answer."
	fail2ban-client status sshd >/dev/null 2>&1 || die "fail2ban: the sshd jail is not running."
	return
}

mod_remove() {
	svc_disable fail2ban
	file_remove "${FAIL2BAN_JAIL}"
	file_remove "${FAIL2BAN_SERVER}"
	pkg_remove_family "fail2ban" "fail2ban-server"
	return
}
