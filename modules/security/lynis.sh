# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="lynis"
MOD_GROUP="security"
MOD_DESCRIPTION="Lynis security audit: weekly run, hardening index kept over time, 'lss audit' on demand"
MOD_REQUIRES="system"
MOD_OPTIONS="min_index|0|lss audit fails below this hardening index (0 = only report)
audit_day|Sun|Day of the weekly audit (Mon..Sun)"

LYNIS_RUNNER=/usr/local/lib/lss/lynis-run
LYNIS_UNIT=lss-lynis
LYNIS_HISTORY=${LSS_STATE_DIR:-/var/lib/lss}/lynis-history
LYNIS_REPORT=/var/log/lynis-report.dat

mod_check() {
	local index
	index=$(opt_int min_index)
	((index <= 100)) || die "LSS_LYNIS_MIN_INDEX must be between 0 and 100."
	[[ $(opt audit_day) =~ ^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$ ]] || die "LSS_LYNIS_AUDIT_DAY must be Mon..Sun."
	return
}

mod_install() {
	pkg_enable_epel
	pkg_install lynis
	return
}

mod_configure() {
	file_write 0755 root:root "${LYNIS_RUNNER}" <<EOF
#!/bin/sh
# Managed by lss (module lynis). Runs the audit and appends "time index" to ${LYNIS_HISTORY}.
set -eu
lynis audit system --cronjob --quiet --no-colors >/dev/null 2>&1 || true
index=\$(sed -n 's/^hardening_index=//p' ${LYNIS_REPORT})
[ -n "\${index}" ] || exit 1
printf '%s %s\n' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\${index}" >>${LYNIS_HISTORY}
logger -t lss "Lynis hardening index \${index}"
EOF
	svc_unit "${LYNIS_UNIT}.service" <<EOF
# Managed by lss (module lynis).
[Unit]
Description=Lynis security audit (lss)

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=${LYNIS_RUNNER}
$(svc_scanner_sandbox full)
EOF
	svc_unit "${LYNIS_UNIT}.timer" <<EOF
# Managed by lss (module lynis).
[Unit]
Description=Weekly Lynis audit (lss)

[Timer]
OnCalendar=$(opt audit_day) *-*-* 06:00:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
	svc_enable "${LYNIS_UNIT}.timer"
	return
}

mod_verify() {
	lynis show version >/dev/null || die "lynis: lynis does not run."
	[[ -x ${LYNIS_RUNNER} ]] || die "lynis: ${LYNIS_RUNNER} is missing."
	svc_is_enabled "${LYNIS_UNIT}.timer" || die "lynis: the weekly audit is not scheduled."
	return
}

# lss audit: full audit now, prints findings and the hardening index, fails below LSS_LYNIS_MIN_INDEX.
mod_audit() {
	local index minimum
	minimum=$(opt_int min_index)
	"${LYNIS_RUNNER}" || die "lynis: the audit did not produce a hardening index."
	index=$(sed -n 's/^hardening_index=//p' "${LYNIS_REPORT}")
	printf '\nWarnings:\n'
	sed -n 's/^warning\[\]=/  /p' "${LYNIS_REPORT}" | cut -d '|' -f 1,2 | tr '|' ' '
	printf '\nSuggestions:\n'
	sed -n 's/^suggestion\[\]=/  /p' "${LYNIS_REPORT}" | cut -d '|' -f 1,2 | tr '|' ' '
	printf '\nHardening index: %s (history: %s, full report: %s)\n' "${index}" "${LYNIS_HISTORY}" "${LYNIS_REPORT}"
	if ((index < minimum)); then
		die "Hardening index ${index} is below the required ${minimum}."
	fi
	log_ok "Hardening index ${index}"
	return
}

mod_remove() {
	svc_disable "${LYNIS_UNIT}.timer"
	file_remove "/etc/systemd/system/${LYNIS_UNIT}.timer"
	file_remove "/etc/systemd/system/${LYNIS_UNIT}.service"
	file_remove "${LYNIS_RUNNER}"
	svc_daemon_reload
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		pkg_remove lynis
	fi
	return
}
