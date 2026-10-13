# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="guard"
MOD_GROUP="security"
MOD_DESCRIPTION="Keeps the server at the level lss set up: daily verify and repair, failed services, disk, updates, alerts"
MOD_REQUIRES="system"
MOD_OPTIONS="autofix|true|Configure modules again that fail verify or were changed outside lss
time|07:00|Time of the daily check (HH:MM)
email||Send findings to this address (needs the mail-relay module or another sendmail)
webhook||Send findings to this HTTPS webhook (Slack, Teams, Mattermost, Discord or ntfy)
disk_threshold|90|Report file systems that are fuller than this (percent)
lynis_min|0|Report a Lynis hardening index below this (needs the lynis module)
daily_summary|false|Also send a message when everything is fine"

GUARD_SCRIPT=/usr/local/lib/lss/guard
GUARD_CONF=/etc/lss/guard.conf
GUARD_UNIT=lss-guard
GUARD_LSS=/usr/local/sbin/lss

mod_check() {
	local email webhook
	opt_bool autofix || true
	opt_bool daily_summary || true
	[[ $(opt time) =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "LSS_GUARD_TIME must look like 07:00."
	(($(opt_int disk_threshold) <= 100)) || die "LSS_GUARD_DISK_THRESHOLD must be at most 100."
	opt_int lynis_min >/dev/null
	email=$(opt email)
	webhook=$(opt webhook)
	[[ -z ${email} || ${email} =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "LSS_GUARD_EMAIL '${email}' is not an e-mail address."
	[[ -z ${webhook} || ${webhook} =~ ^https://[^[:space:]]+$ ]] || die "LSS_GUARD_WEBHOOK must be an https:// URL."
	[[ -x ${GUARD_LSS} ]] || die "guard needs lss installed as ${GUARD_LSS} (bootstrap.sh does that)."
	return
}

mod_configure() {
	local bool
	file_write 0755 root:root "${GUARD_SCRIPT}" <"${LSS_ROOT}/libexec/lss-guard"
	# The webhook URL is a credential (whoever has it can post), so the file is readable by root only.
	file_write 0600 root:root "${GUARD_CONF}" < <(
		printf '# Managed by lss (module guard). Change LSS_GUARD_* in /etc/lss/lss.conf and run lss configure guard.\n'
		bool=false
		opt_bool autofix && bool=true
		printf 'GUARD_AUTOFIX=%s\n' "${bool}"
		bool=false
		opt_bool daily_summary && bool=true
		printf 'GUARD_DAILY_SUMMARY=%s\n' "${bool}"
		printf 'GUARD_EMAIL=%s\nGUARD_WEBHOOK=%s\n' "$(opt email)" "$(opt webhook)"
		printf 'GUARD_DISK_THRESHOLD=%s\nGUARD_LYNIS_MIN=%s\n' "$(opt_int disk_threshold)" "$(opt_int lynis_min)"
	)
	svc_unit "${GUARD_UNIT}.service" <<EOF
# Managed by lss (module guard).
[Unit]
Description=lss guard: verify and repair the server set-up
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${GUARD_SCRIPT}
Nice=10
EOF
	svc_unit "${GUARD_UNIT}.timer" <<EOF
# Managed by lss (module guard).
[Unit]
Description=Daily lss guard run

[Timer]
OnCalendar=*-*-* $(opt time):00
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF
	svc_enable "${GUARD_UNIT}.timer"
	return
}

mod_verify() {
	[[ -x ${GUARD_SCRIPT} ]] || die "guard: ${GUARD_SCRIPT} is missing."
	bash -n "${GUARD_SCRIPT}" || die "guard: ${GUARD_SCRIPT} is not a valid script."
	[[ $(stat -c '%a' "${GUARD_CONF}") == 600 ]] || die "guard: ${GUARD_CONF} must be mode 600."
	svc_is_enabled "${GUARD_UNIT}.timer" || die "guard: the daily run is not scheduled."
	systemctl list-timers --all --no-legend "${GUARD_UNIT}.timer" | grep -q "${GUARD_UNIT}" ||
		die "guard: systemd does not know the timer."
	return
}

mod_remove() {
	svc_disable "${GUARD_UNIT}.timer"
	file_remove "/etc/systemd/system/${GUARD_UNIT}.timer"
	file_remove "/etc/systemd/system/${GUARD_UNIT}.service"
	file_remove "${GUARD_SCRIPT}"
	file_remove "${GUARD_CONF}"
	svc_daemon_reload
	return
}
