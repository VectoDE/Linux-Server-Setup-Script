# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="aide"
MOD_GROUP="security"
MOD_DESCRIPTION="File integrity monitoring: daily AIDE check of system files against a trusted database"
MOD_REQUIRES="system"
MOD_OPTIONS="check_time|05:15|Time of the daily check (HH:MM)
exclude||More directories AIDE leaves out, separated by spaces (large data or tool directories)"

AIDE_UNIT=lss-aide-check

_aide_conf() {
	if os_is_debian; then printf '/etc/aide/aide.conf'; else printf '/etc/aide.conf'; fi
}

_aide_db() {
	if os_is_debian; then printf '/var/lib/aide/aide.db'; else printf '/var/lib/aide/aide.db.gz'; fi
}

mod_check() {
	local path
	[[ $(opt check_time) =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "LSS_AIDE_CHECK_TIME must look like 05:15."
	for path in $(opt exclude); do
		[[ ${path} =~ ^/[A-Za-z0-9._+/-]+$ && ${path} != */../* && ${path} != */.. ]] ||
			die "LSS_AIDE_EXCLUDE: '${path}' is not an absolute directory path."
	done
}

mod_install() {
	pkg_install_family "aide aide-common" "aide"
}

# Paths that change all the time and would drown real findings.
_aide_excludes() {
	cat <<'EOF'
# Managed by lss (module aide).
!/var/lib/lss
!/var/log
!/var/cache
!/var/tmp
!/var/spool
!/var/lib/docker
!/var/lib/containerd
!/var/lib/rancher
!/var/lib/clamav
!/var/lib/rkhunter
!/var/lib/fail2ban
!/var/lib/aide
EOF
	local path
	for path in $(opt exclude); do
		# AIDE reads the path as a regular expression; a literal dot must not match any character.
		printf '!%s\n' "${path//./[.]}"
	done
}

mod_configure() {
	LSS_FILE_CHANGED=0
	if os_is_debian; then
		file_write 0644 root:root /etc/aide/aide.conf.d/99_lss_excludes <<<"$(_aide_excludes)"
	else
		# RHEL has no conf.d: the block after the marker belongs to lss and is rewritten on every run, so changed
		# excludes take effect; everything before it stays as the package or the administrator left it.
		local base
		base=$(sed '/^# lss excludes$/,$d' /etc/aide.conf)
		file_write 0600 root:root /etc/aide.conf < <(
			printf '%s\n\n# lss excludes\n' "${base}"
			_aide_excludes
		)
	fi
	local changed=${LSS_FILE_CHANGED}
	if [[ ! -s $(_aide_db) || ${changed} == 1 ]]; then
		log_info "Building the AIDE database; this reads every system file and takes minutes on large systems."
		log_info "Directories with large data can be left out with LSS_AIDE_EXCLUDE."
		local start=${SECONDS}
		if os_is_debian; then
			nice -n 19 ionice -c 2 -n 7 aideinit --yes --force >/dev/null
		else
			nice -n 19 ionice -c 2 -n 7 aide --init --config /etc/aide.conf >/dev/null
			mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
		fi
		log_info "AIDE database built in $((SECONDS - start)) seconds."
		files_note_change "AIDE database"
	fi
	svc_unit "${AIDE_UNIT}.service" <<EOF
# Managed by lss (module aide). Exit codes 1-7 mean changes were found; they are reported, not failures.
[Unit]
Description=AIDE file integrity check (lss)

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=$(command -v aide) --check --config $(_aide_conf)
SuccessExitStatus=1 2 3 4 5 6 7
EOF
	svc_unit "${AIDE_UNIT}.timer" <<EOF
# Managed by lss (module aide).
[Unit]
Description=Daily AIDE check (lss)

[Timer]
OnCalendar=*-*-* $(opt check_time):00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF
	svc_enable "${AIDE_UNIT}.timer"
	# Debian's own daily check would run a second time.
	svc_disable dailyaidecheck.timer
}

mod_verify() {
	[[ -s $(_aide_db) ]] || die "aide: no database at $(_aide_db)."
	aide --config "$(_aide_conf)" --config-check >/dev/null || die "aide: the configuration is invalid."
	svc_is_enabled "${AIDE_UNIT}.timer" || die "aide: the daily check is not scheduled."
}

mod_remove() {
	svc_disable "${AIDE_UNIT}.timer"
	file_remove "/etc/systemd/system/${AIDE_UNIT}.timer"
	file_remove "/etc/systemd/system/${AIDE_UNIT}.service"
	file_remove /etc/aide/aide.conf.d/99_lss_excludes
	svc_daemon_reload
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		pkg_remove_family "aide aide-common" "aide"
	fi
}
