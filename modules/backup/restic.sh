# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="restic"
MOD_GROUP="backup"
MOD_DESCRIPTION="Encrypted, deduplicated daily backups with restic to a local path, SFTP or S3, with retention, repository checks and a weekly restore test (guard)"
MOD_REQUIRES="system"
MOD_OPTIONS="repository|/var/backups/lss-restic|Where the backups go: a local path (better another disk), sftp:USER@HOST:/PATH or s3:https://HOST/BUCKET/PATH
paths|/etc /root /home /srv /opt /usr/local /var/www /var/spool/cron /var/lib/lss /var/backups/lss-db /var/vmail /var/lib/rspamd/dkim /var/lib/php/lss-roundcube|What to back up, separated by spaces; paths that do not exist are skipped
exclude|/var/lib/lss/runs|Paths or patterns restic leaves out, separated by spaces (restic --exclude)
time|03:00|Time of the daily backup (HH:MM)
keep_daily|7|Daily snapshots to keep
keep_weekly|4|Weekly snapshots to keep
keep_monthly|6|Monthly snapshots to keep
check_subset|5%|Share of the data the weekly restore test reads back (restic check --read-data-subset)
s3_key_id||S3 access key ID, stored in the lss secrets (restic-s3-key-id); s3 repositories only
s3_secret||S3 secret access key, stored in the lss secrets (restic-s3-secret); s3 repositories only
s3_region||S3 region, when the provider needs one"
MOD_SECRETS="restic-password restic-ssh-key restic-s3-key-id restic-s3-secret"
MOD_PORTS="none (outgoing SSH or HTTPS to the repository)"

# Every supported release packages restic (0.12 on Ubuntu 22.04 up to 0.19 in EPEL); the commands lss uses work with
# all of them. libexec/lss-backup does the work; the unit runs it daily.
BACKUP_SCRIPT=/usr/local/lib/lss/backup
BACKUP_CONF=/etc/lss/backup.conf
BACKUP_UNIT=lss-backup
BACKUP_STATE=/var/lib/lss/restic
BACKUP_CACHE=/var/cache/restic
BACKUP_PUBLIC_KEY=/etc/lss/restic-ssh-key.pub

_restic_kind() {
	case $(opt repository) in
	sftp:*) printf 'sftp' ;;
	s3:*) printf 's3' ;;
	*) printf 'local' ;;
	esac
	return
}

mod_check() {
	local repository number
	repository=$(opt repository)
	case ${repository} in
	sftp:*) [[ ${repository} =~ ^sftp:(//)?[A-Za-z0-9._-]+@[A-Za-z0-9.-]+(:[0-9]+)?[:/].+$ ]] ||
		die "LSS_RESTIC_REPOSITORY: an sftp repository looks like sftp:USER@HOST:/PATH." ;;
	s3:*) [[ ${repository} =~ ^s3:https://[A-Za-z0-9.:-]+/[A-Za-z0-9._/-]+$ ]] ||
		die "LSS_RESTIC_REPOSITORY: an s3 repository looks like s3:https://HOST/BUCKET/PATH." ;;
	/*) [[ ${repository} =~ ^/[A-Za-z0-9._/-]+$ && ${repository} != *..* ]] ||
		die "LSS_RESTIC_REPOSITORY: '${repository}' is not a plain absolute path." ;;
	*) die "LSS_RESTIC_REPOSITORY must be an absolute path, sftp:USER@HOST:/PATH or s3:https://HOST/BUCKET/PATH." ;;
	esac
	[[ $(opt paths) =~ ^/[A-Za-z0-9._/[:space:]-]*$ ]] || die "LSS_RESTIC_PATHS must be absolute paths separated by spaces."
	[[ $(opt exclude) =~ ^[A-Za-z0-9._/*?[:space:]-]*$ ]] || die "LSS_RESTIC_EXCLUDE holds characters restic patterns do not need."
	[[ $(opt time) =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "LSS_RESTIC_TIME must look like 03:00."
	for number in keep_daily keep_weekly keep_monthly; do
		opt_int "${number}" >/dev/null
	done
	[[ $(opt check_subset) =~ ^([1-9][0-9]?|100)%$ ]] || die "LSS_RESTIC_CHECK_SUBSET must be a percentage such as 5%."
	if [[ $(_restic_kind) == s3 ]] && ! secret_exists restic-s3-key-id && [[ -z $(opt s3_key_id) || -z $(opt s3_secret) ]]; then
		die "LSS_RESTIC_REPOSITORY is an s3 repository: set LSS_RESTIC_S3_KEY_ID and LSS_RESTIC_S3_SECRET."
	fi
	[[ $(opt s3_region) =~ ^[a-z0-9-]*$ ]] || die "LSS_RESTIC_S3_REGION must look like eu-central-1."
	return
}

mod_install() {
	if os_is_rhel; then
		pkg_enable_epel
	fi
	pkg_install restic
	return
}

# _restic_secrets: the repository password (generated once), the S3 keys from the settings, the SSH key for sftp.
_restic_secrets() {
	local value key
	if ! secret_exists restic-password; then
		secret_get restic-password 48 >/dev/null
		log_warn "restic: generated the repository password. Keep a copy outside this server (lss secrets show restic-password); without it no backup can be restored."
		files_note_change "generated the restic repository password"
	fi
	for key in s3_key_id:restic-s3-key-id s3_secret:restic-s3-secret; do
		value=$(opt "${key%%:*}")
		[[ -n ${value} ]] || continue
		log_mask "${value}"
		if ! secret_exists "${key#*:}" || [[ $(secret_get "${key#*:}") != "${value}" ]]; then
			secret_set "${key#*:}" "${value}"
			files_note_change "stored ${key#*:}"
		fi
	done
	if [[ $(_restic_kind) == sftp && ! -s $(secret_path restic-ssh-key) ]]; then
		ssh-keygen -q -t ed25519 -N '' -C "lss-restic@$(hostname)" -f "$(secret_path restic-ssh-key)"
		mv -f -- "$(secret_path restic-ssh-key).pub" "${BACKUP_PUBLIC_KEY}"
		chmod 0644 "${BACKUP_PUBLIC_KEY}"
		files_note_change "generated the SSH key for the sftp repository"
	fi
	if [[ -s ${BACKUP_PUBLIC_KEY} ]]; then
		log_info "restic: the sftp server must accept this key for the repository user: $(<"${BACKUP_PUBLIC_KEY}")"
	fi
	return
}

_restic_conf() {
	printf '# Managed by lss (module restic). Change LSS_RESTIC_* in /etc/lss/lss.conf and run lss configure restic.\n'
	printf 'BACKUP_REPOSITORY=%s\nBACKUP_PATHS=%s\nBACKUP_EXCLUDE=%s\n' "$(opt repository)" "$(opt paths)" "$(opt exclude)"
	printf 'BACKUP_KEEP_DAILY=%s\nBACKUP_KEEP_WEEKLY=%s\nBACKUP_KEEP_MONTHLY=%s\n' "$(opt_int keep_daily)" \
		"$(opt_int keep_weekly)" "$(opt_int keep_monthly)"
	printf 'BACKUP_CHECK_SUBSET=%s\nBACKUP_S3_REGION=%s\n' "$(opt check_subset)" "$(opt s3_region)"
	return
}

mod_configure() {
	local repository writable=''
	repository=$(opt repository)
	_restic_secrets
	install -d -m 0700 "${BACKUP_STATE}" "${BACKUP_CACHE}"
	if [[ $(_restic_kind) == local ]]; then
		install -d -m 0700 "${repository}"
		writable=${repository}
	fi
	file_write 0755 root:root "${BACKUP_SCRIPT}" <"${LSS_ROOT}/libexec/lss-backup"
	_restic_conf | file_write 0600 root:root "${BACKUP_CONF}"
	# Reads everything, writes only its state, its cache, the dumps (of the databases and of the app stacks, which it
	# reaches through the Docker socket), the metrics and a local repository.
	svc_unit "${BACKUP_UNIT}.service" < <(
		printf '# Managed by lss (module restic).\n[Unit]\nDescription=lss backup with restic\n'
		printf 'After=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\n'
		printf 'ExecStart=%s run\nNice=10\nIOSchedulingClass=idle\n' "${BACKUP_SCRIPT}"
		svc_scanner_sandbox strict "${BACKUP_STATE}" "${BACKUP_CACHE}" /var/backups/lss-db /var/backups/lss-apps \
			/var/lib/lss/app-backup "${MON_TEXTFILE_DIR}" \
			${writable:+"${writable}"}
	)
	svc_unit "${BACKUP_UNIT}.timer" <<EOF
# Managed by lss (module restic).
[Unit]
Description=Daily lss backup

[Timer]
OnCalendar=*-*-* $(opt time):00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF
	svc_enable "${BACKUP_UNIT}.timer"
	"${BACKUP_SCRIPT}" init || die "restic: the repository ${repository} cannot be opened or created."
	return
}

mod_verify() {
	[[ -x ${BACKUP_SCRIPT} ]] || die "restic: ${BACKUP_SCRIPT} is missing."
	[[ $(stat -c '%a' "${BACKUP_CONF}") == 600 ]] || die "restic: ${BACKUP_CONF} must be mode 600."
	svc_is_enabled "${BACKUP_UNIT}.timer" || die "restic: the daily backup is not scheduled."
	"${BACKUP_SCRIPT}" restic cat config >/dev/null 2>&1 ||
		die "restic: the repository $(opt repository) does not open with the password from the lss secrets."
	# Before the first scheduled backup a small probe proves that a backup goes in and comes back out.
	if [[ ! -s ${BACKUP_STATE}/last-success && ! -s ${BACKUP_STATE}/probe ]]; then
		"${BACKUP_SCRIPT}" probe || die "restic: the probe backup and its restore test fail."
		date +%s >"${BACKUP_STATE}/probe"
	fi
	return
}

mod_remove() {
	svc_disable "${BACKUP_UNIT}.timer"
	file_remove "/etc/systemd/system/${BACKUP_UNIT}.timer"
	file_remove "/etc/systemd/system/${BACKUP_UNIT}.service"
	svc_daemon_reload
	file_remove "${BACKUP_SCRIPT}"
	file_remove "${BACKUP_CONF}"
	file_remove "${BACKUP_PUBLIC_KEY}"
	rm -f -- "${MON_TEXTFILE_DIR}/lss_backup.prom"
	pkg_remove restic
	# The repository holds the backups and is never deleted by lss, not even with --purge.
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	rm -rf -- "${BACKUP_CACHE}"
	mon_delete "${BACKUP_STATE}"
	log_info "restic: the repository $(opt repository) and the password (lss secrets show restic-password) stay; delete them yourself when the backups are no longer needed."
	return
}
