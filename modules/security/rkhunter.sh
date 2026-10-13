# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="rkhunter"
MOD_GROUP="security"
MOD_DESCRIPTION="Rootkit Hunter: daily scan for rootkits, backdoors and suspicious changes to system binaries"
MOD_REQUIRES="system"
MOD_OPTIONS="check_time|05:45|Time of the daily scan (HH:MM)"

RKH_LOCAL=/etc/rkhunter.conf.local
RKH_UNIT=lss-rkhunter
# Scripts that replace binaries on current distributions; only existing paths are listed (rkhunter rejects others).
RKH_SCRIPTS="/usr/bin/egrep /usr/bin/fgrep /usr/bin/which /usr/bin/ldd /usr/sbin/adduser /usr/bin/lwp-request"

mod_check() {
	[[ $(opt check_time) =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "LSS_RKHUNTER_CHECK_TIME must look like 05:45."
	return
}

mod_install() {
	pkg_enable_epel
	pkg_install_family "rkhunter unhide" "rkhunter"
	return
}

_rkh_config() {
	local script package_manager=DPKG
	os_is_rhel && package_manager=RPM
	cat <<EOF
# Managed by lss (module rkhunter). Overrides /etc/rkhunter.conf.
# File properties are checked against the package database, so updates do not raise false alarms.
PKGMGR=${package_manager}
# No downloads from the rkhunter mirrors (unsigned); the data files come with the package.
UPDATE_MIRRORS=0
MIRRORS_MODE=1
WEB_CMD=/bin/false
# Root login is denied in /etc/ssh/sshd_config.d (ssh-hardening), which rkhunter does not read.
ALLOW_SSH_ROOT_USER=unset
ALLOWDEVFILE=/dev/shm/PostgreSQL.*
ALLOWDEVFILE=/dev/shm/sem.*
DISABLE_TESTS=suspscan hidden_procs deleted_files packet_cap_apps apps
EOF
	for script in ${RKH_SCRIPTS}; do
		if [[ -f ${script} ]]; then
			printf 'SCRIPTWHITELIST=%s\n' "${script}"
		fi
	done
	return
}

mod_configure() {
	file_write 0644 root:root "${RKH_LOCAL}" < <(_rkh_config)
	local changed=${LSS_FILE_CHANGED}
	rkhunter --config-check --nocolors >/dev/null || die "rkhunter: the configuration is invalid."
	if [[ ! -s /var/lib/rkhunter/db/rkhunter.dat || ${changed} == 1 ]]; then
		rkhunter --propupd --nocolors >/dev/null
		files_note_change "rkhunter file properties"
	fi
	# Debian's cron job would scan a second time.
	if [[ -f /etc/default/rkhunter ]]; then
		file_write 0644 root:root /etc/default/rkhunter < <(
			sed -E -e 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="false"/' -e 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="false"/' \
				-e 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter
		)
	fi
	svc_unit "${RKH_UNIT}.service" <<EOF
# Managed by lss (module rkhunter). Findings go to /var/log/rkhunter.log and the journal.
[Unit]
Description=Rootkit Hunter scan (lss)

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=$(command -v rkhunter) --check --skip-keypress --report-warnings-only --nocolors
SuccessExitStatus=1
EOF
	svc_unit "${RKH_UNIT}.timer" <<EOF
# Managed by lss (module rkhunter).
[Unit]
Description=Daily Rootkit Hunter scan (lss)

[Timer]
OnCalendar=*-*-* $(opt check_time):00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF
	svc_enable "${RKH_UNIT}.timer"
	return
}

mod_verify() {
	rkhunter --config-check --nocolors >/dev/null || die "rkhunter: the configuration is invalid."
	[[ -s /var/lib/rkhunter/db/rkhunter.dat ]] || die "rkhunter: the file properties database is missing."
	svc_is_enabled "${RKH_UNIT}.timer" || die "rkhunter: the daily scan is not scheduled."
	return
}

mod_remove() {
	svc_disable "${RKH_UNIT}.timer"
	file_remove "/etc/systemd/system/${RKH_UNIT}.timer"
	file_remove "/etc/systemd/system/${RKH_UNIT}.service"
	file_remove "${RKH_LOCAL}"
	svc_daemon_reload
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		pkg_remove rkhunter
	fi
	return
}
