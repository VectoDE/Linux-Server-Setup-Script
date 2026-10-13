# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="clamav"
MOD_GROUP="security"
MOD_DESCRIPTION="ClamAV: signatures updated several times a day, daily low-priority scan of writable directories"
MOD_REQUIRES="system"
MOD_OPTIONS="scan_paths|/home /root /srv /opt /var/www /tmp /var/tmp|Directories scanned daily, separated by spaces
scan_time|02:30|Time of the daily scan (HH:MM)"

CLAM_UNIT=lss-clamscan
CLAM_FRESHCLAM=clamav-freshclam

mod_check() {
	local path
	[[ $(opt scan_time) =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "LSS_CLAMAV_SCAN_TIME must look like 02:30."
	for path in $(opt scan_paths); do
		[[ ${path} =~ ^/[A-Za-z0-9._/-]*$ ]] || die "LSS_CLAMAV_SCAN_PATHS: '${path}' is not an absolute path."
	done
}

mod_install() {
	pkg_enable_epel
	pkg_install_family "clamav clamav-freshclam" "clamav clamav-update"
}

_clam_db_ready() {
	compgen -G '/var/lib/clamav/main.c[vl]d' >/dev/null && compgen -G '/var/lib/clamav/daily.c[vl]d' >/dev/null
}

mod_configure() {
	local i
	if os_is_rhel; then
		# The RHEL package ships freshclam.conf with an "Example" line that disables it; lss writes its own. The
		# daemon runs as clamupdate, which cannot create files in /var/log, so it logs to the journal only.
		file_write 0644 root:root /etc/freshclam.conf <<'EOF'
# Managed by lss (module clamav).
DatabaseDirectory /var/lib/clamav
LogSyslog yes
DatabaseOwner clamupdate
DatabaseMirror database.clamav.net
Checks 12
EOF
	fi
	svc_enable "${CLAM_FRESHCLAM}"
	# The first download takes a while; scans need the signatures.
	for ((i = 0; i < 90; i++)); do
		_clam_db_ready && break
		sleep 5
	done
	if ! _clam_db_ready; then
		journalctl -u "${CLAM_FRESHCLAM}" -n 30 --no-pager >&2 || true
		die "clamav: no signatures after 7 minutes; check that database.clamav.net is reachable."
	fi

	svc_unit "${CLAM_UNIT}.service" <<EOF
# Managed by lss (module clamav). Infected files are listed in the journal (exit code 1 = found something).
[Unit]
Description=ClamAV scan of writable directories (lss)

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/bin/sh -c 'for d in $(opt scan_paths); do [ -d "\$\$d" ] && set -- "\$\$@" "\$\$d"; done; [ \$\$# -eq 0 ] || exec $(command -v clamscan) --recursive --infected --cross-fs=no --max-filesize=100M --max-scansize=400M "\$\$@"'
SuccessExitStatus=1
EOF
	svc_unit "${CLAM_UNIT}.timer" <<EOF
# Managed by lss (module clamav).
[Unit]
Description=Daily ClamAV scan (lss)

[Timer]
OnCalendar=*-*-* $(opt scan_time):00
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
EOF
	svc_enable "${CLAM_UNIT}.timer"
}

mod_verify() {
	local sample
	svc_is_active "${CLAM_FRESHCLAM}" || die "clamav: freshclam is not running."
	_clam_db_ready || die "clamav: no signature database."
	# EICAR test string: every scanner must report it.
	sample=$(mktemp)
	# shellcheck disable=SC2016 # the EICAR test string is literal
	printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"${sample}"
	local status=0
	clamscan --no-summary "${sample}" >/dev/null 2>&1 || status=$?
	rm -f -- "${sample}"
	# 1 = virus found (expected), 0 = missed, 2 = scanner error.
	[[ ${status} == 1 ]] || die "clamav: the EICAR test file was not detected (clamscan exit ${status})."
	svc_is_enabled "${CLAM_UNIT}.timer" || die "clamav: the daily scan is not scheduled."
}

mod_remove() {
	svc_disable "${CLAM_UNIT}.timer"
	file_remove "/etc/systemd/system/${CLAM_UNIT}.timer"
	file_remove "/etc/systemd/system/${CLAM_UNIT}.service"
	svc_daemon_reload
	svc_disable "${CLAM_FRESHCLAM}"
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		pkg_remove_family "clamav clamav-freshclam" "clamav clamav-update"
	fi
}
