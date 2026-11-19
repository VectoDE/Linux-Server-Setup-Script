# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Service helpers for the init system of the server (svc_init): systemd, OpenRC (Alpine, Gentoo), SysV init scripts
# (Devuan, older systems) and Upstart (Ubuntu 14.04 and older). Units are named as systemd names them; for the others
# lss drops the .service suffix (nginx.service is the init script nginx). Drop-ins, sandboxes and units of lss's own
# exist only under systemd; without it svc_schedule writes a cron job where systemd would get a timer.

# Seconds lss waits for a unit to start. Some units (MySQL) wait for their service without a limit; a service that
# never reports ready would stop the run for good.
SVC_START_TIMEOUT=${SVC_START_TIMEOUT:-300}
# Sources of the SELinux policy modules that let services start their programs in their domains (svc_selinux_spawner).
SVC_SELINUX_DIR=${SVC_SELINUX_DIR:-/etc/lss/selinux}
# Where the init systems keep their state and jobs; the tests point them into their own directory.
SVC_SYSTEMD_RUN=${SVC_SYSTEMD_RUN:-/run/systemd/system}
SVC_OPENRC_RUN=${SVC_OPENRC_RUN:-/run/openrc}
SVC_INITD=${SVC_INITD:-/etc/init.d}
SVC_UPSTART_DIR=${SVC_UPSTART_DIR:-/etc/init}
SVC_RC_DIR=${SVC_RC_DIR:-/etc}
SVC_CRON_DIR=${SVC_CRON_DIR:-/etc/cron.d}

# svc_init: the init system that runs this server: systemd, openrc, upstart, sysv or unknown. LSS_INIT overrides the
# detection. systemd is running when /run/systemd/system exists (what sd_booted checks), OpenRC when /run/openrc
# does; Upstart answers "initctl version" with its name.
svc_init() {
	if [[ -n ${LSS_INIT:-} ]]; then
		printf '%s' "${LSS_INIT}"
	elif [[ -d ${SVC_SYSTEMD_RUN} ]]; then
		printf 'systemd'
	elif [[ -d ${SVC_OPENRC_RUN} ]] && command -v rc-service >/dev/null 2>&1; then
		printf 'openrc'
	elif command -v initctl >/dev/null 2>&1 && initctl version 2>/dev/null | grep -q upstart; then
		printf 'upstart'
	elif [[ -d ${SVC_INITD} ]]; then
		printf 'sysv'
	else
		printf 'unknown'
	fi
	return
}

# svc_is_systemd: systemd runs the server.
svc_is_systemd() {
	[[ $(svc_init) == systemd ]]
	return
}

# _svc_name UNIT: the name of the job outside systemd (nginx for nginx.service).
_svc_name() {
	printf '%s' "${1%.service}"
	return
}

# _svc_sysv_enabled NAME: a start link in one of the multi-user runlevels (2 to 5).
_svc_sysv_enabled() {
	local link
	for link in "${SVC_RC_DIR}"/rc[2345].d/S[0-9][0-9]"$1"; do
		[[ -e ${link} || -L ${link} ]] && return 0
	done
	return 1
}

# _svc_upstart_enabled NAME: the job exists and no override file sets it to manual.
_svc_upstart_enabled() {
	[[ -f ${SVC_UPSTART_DIR}/$1.conf ]] || return 1
	! grep -qx manual "${SVC_UPSTART_DIR}/$1.override" 2>/dev/null
	return
}

svc_exists() {
	local name
	name=$(_svc_name "$1")
	case $(svc_init) in
	systemd) systemctl list-unit-files --no-legend "$1" "$1.service" 2>/dev/null | grep -q . ;;
	upstart) [[ -f ${SVC_UPSTART_DIR}/${name}.conf || -x ${SVC_INITD}/${name} ]] ;;
	openrc | sysv) [[ -x ${SVC_INITD}/${name} ]] ;;
	*) return 1 ;;
	esac
	return
}

svc_is_active() {
	local name
	name=$(_svc_name "$1")
	case $(svc_init) in
	systemd) systemctl is-active --quiet "$1" ;;
	openrc) rc-service --quiet "${name}" status >/dev/null 2>&1 ;;
	upstart)
		if [[ -f ${SVC_UPSTART_DIR}/${name}.conf ]]; then
			initctl status "${name}" 2>/dev/null | grep -q 'start/running'
		else
			service "${name}" status >/dev/null 2>&1
		fi
		;;
	sysv) service "${name}" status >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
	return
}

svc_is_enabled() {
	local name
	name=$(_svc_name "$1")
	case $(svc_init) in
	systemd) systemctl is-enabled --quiet "$1" 2>/dev/null ;;
	openrc) rc-update show default 2>/dev/null | awk '{ print $1 }' | grep -qxF "${name}" ;;
	upstart) _svc_upstart_enabled "${name}" || _svc_sysv_enabled "${name}" ;;
	sysv) _svc_sysv_enabled "${name}" ;;
	*) return 1 ;;
	esac
	return
}

# _svc_start_other NAME: enables NAME at boot and starts it, outside systemd.
_svc_start_other() {
	local name=$1
	case $(svc_init) in
	openrc)
		rc-update add "${name}" default >/dev/null 2>&1 && timeout "${SVC_START_TIMEOUT}" rc-service "${name}" start
		;;
	upstart)
		if [[ -f ${SVC_UPSTART_DIR}/${name}.conf ]]; then
			rm -f -- "${SVC_UPSTART_DIR}/${name}.override"
			initctl status "${name}" 2>/dev/null | grep -q 'start/running' ||
				timeout "${SVC_START_TIMEOUT}" initctl start "${name}"
		else
			_svc_sysv_on "${name}" && timeout "${SVC_START_TIMEOUT}" service "${name}" start
		fi
		;;
	sysv) _svc_sysv_on "${name}" && timeout "${SVC_START_TIMEOUT}" service "${name}" start ;;
	*) return 1 ;;
	esac
	return
}

# _svc_sysv_on NAME / _svc_sysv_off NAME: start links with update-rc.d (Debian family) or chkconfig (RHEL family).
_svc_sysv_on() {
	if command -v update-rc.d >/dev/null 2>&1; then
		update-rc.d "$1" defaults >/dev/null 2>&1
	else
		chkconfig "$1" on >/dev/null 2>&1
	fi
	return
}
_svc_sysv_off() {
	if command -v update-rc.d >/dev/null 2>&1; then
		update-rc.d "$1" disable >/dev/null 2>&1
	else
		chkconfig "$1" off >/dev/null 2>&1
	fi
	return
}

# _svc_failed UNIT: what the init system says about a unit that failed, for the log.
_svc_failed() {
	if svc_is_systemd; then
		systemctl status --no-pager "$1" >&2 || true
		journalctl -u "$1" -n 30 --no-pager >&2 || true
	else
		svc_is_active "$1" || printf '%s is not running.\n' "$(_svc_name "$1")" >&2
	fi
	return 0
}

# Enables and starts a unit; records a change only if it was not enabled or not running.
svc_enable() {
	local unit=$1
	if svc_is_enabled "${unit}" && svc_is_active "${unit}"; then
		return 0
	fi
	if svc_is_systemd; then
		timeout "${SVC_START_TIMEOUT}" systemctl enable --now "${unit}" >/dev/null 2>&1 || {
			_svc_failed "${unit}"
			die "Could not start ${unit}."
		}
	else
		_svc_start_other "$(_svc_name "${unit}")" >/dev/null 2>&1 || {
			_svc_failed "${unit}"
			die "Could not start ${unit}."
		}
	fi
	files_note_change "enabled ${unit}"
}

# svc_timer_skip_missed TIMER: before a stopped timer with Persistent=true is started, records "ran now" in its
# stamp file, so systemd does not catch up on runs it missed while the timer was off. Otherwise enabling
# apt-daily-upgrade.timer on a fresh server starts a full unattended upgrade at once, which holds the dpkg lock
# for the rest of the setup. Without systemd there are no timers.
svc_timer_skip_missed() {
	local stamp="${LSS_SYSTEMD_TIMER_DIR:-/var/lib/systemd/timers}/stamp-$1"
	svc_is_systemd || return 0
	svc_is_active "$1" && return 0
	[[ ! -L ${stamp} ]] || die "${stamp} is a symbolic link."
	mkdir -p "$(dirname "${stamp}")"
	touch "${stamp}"
}

svc_disable() {
	local unit=$1 name
	svc_exists "${unit}" || return 0
	svc_is_enabled "${unit}" || svc_is_active "${unit}" || return 0
	name=$(_svc_name "${unit}")
	case $(svc_init) in
	systemd) systemctl disable --now "${unit}" >/dev/null 2>&1 || true ;;
	openrc)
		rc-service "${name}" stop >/dev/null 2>&1 || true
		rc-update del "${name}" default >/dev/null 2>&1 || true
		;;
	upstart)
		if [[ -f ${SVC_UPSTART_DIR}/${name}.conf ]]; then
			printf 'manual\n' >"${SVC_UPSTART_DIR}/${name}.override"
			initctl stop "${name}" >/dev/null 2>&1 || true
		else
			service "${name}" stop >/dev/null 2>&1 || true
			_svc_sysv_off "${name}" || true
		fi
		;;
	*)
		service "${name}" stop >/dev/null 2>&1 || true
		_svc_sysv_off "${name}" || true
		;;
	esac
	files_note_change "disabled ${unit}"
}

svc_restart() {
	local name
	name=$(_svc_name "$1")
	case $(svc_init) in
	systemd) timeout "${SVC_START_TIMEOUT}" systemctl restart "$1" ;;
	openrc) timeout "${SVC_START_TIMEOUT}" rc-service "${name}" restart ;;
	upstart)
		if [[ -f ${SVC_UPSTART_DIR}/${name}.conf ]]; then
			timeout "${SVC_START_TIMEOUT}" initctl restart "${name}" ||
				timeout "${SVC_START_TIMEOUT}" initctl start "${name}"
		else
			timeout "${SVC_START_TIMEOUT}" service "${name}" restart
		fi
		;;
	*) timeout "${SVC_START_TIMEOUT}" service "${name}" restart ;;
	esac || {
		_svc_failed "$1"
		return 1
	}
}

# svc_reload UNIT: reloads the configuration, or restarts a service that cannot reload.
svc_reload() {
	local name
	name=$(_svc_name "$1")
	case $(svc_init) in
	systemd)
		timeout "${SVC_START_TIMEOUT}" systemctl reload-or-restart "$1" || {
			systemctl status --no-pager "$1" >&2 || true
			return 1
		}
		return 0
		;;
	openrc) timeout "${SVC_START_TIMEOUT}" rc-service "${name}" reload >/dev/null 2>&1 ;;
	upstart)
		if [[ -f ${SVC_UPSTART_DIR}/${name}.conf ]]; then
			timeout "${SVC_START_TIMEOUT}" initctl reload "${name}" >/dev/null 2>&1
		else
			timeout "${SVC_START_TIMEOUT}" service "${name}" reload >/dev/null 2>&1
		fi
		;;
	*) timeout "${SVC_START_TIMEOUT}" service "${name}" reload >/dev/null 2>&1 ;;
	esac || svc_restart "$1"
}

# Only systemd has unit files to reload.
svc_daemon_reload() {
	svc_is_systemd || return 0
	systemctl daemon-reload
	return
}

# _svc_cron_field VALUE MAX: one field of an OnCalendar time (a number, *, or a list such as 1,15) as a cron field.
_svc_cron_field() {
	local value=$1 max=$2 part
	[[ ${value} == '*' ]] && {
		printf '*'
		return 0
	}
	[[ ${value} =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
	local -a parts=() out=()
	IFS=, read -ra parts <<<"${value}"
	for part in "${parts[@]}"; do
		((10#${part} <= max)) || return 1
		out+=("$((10#${part}))")
	done
	local IFS=,
	printf '%s' "${out[*]}"
	return
}

# svc_calendar_cron CALENDAR: the cron time ("MIN HOUR DOM MON DOW") of a systemd OnCalendar expression of the forms lss
# uses: [WEEKDAYS] *-*-* HH:MM[:SS] (weekdays as Mon, Mon,Thu or Mon..Fri), daily, weekly, monthly and hourly. Seconds
# other than 00 and other forms fail, so a schedule cron cannot express is never changed silently.
svc_calendar_cron() {
	local calendar=$1 days="" date time extra hour minute second dow="*" day out
	case ${calendar} in
	hourly) printf '0 * * * *' && return 0 ;;
	daily) printf '0 0 * * *' && return 0 ;;
	weekly) printf '0 0 * * 1' && return 0 ;;
	monthly) printf '0 0 1 * *' && return 0 ;;
	*) ;;
	esac
	read -r date time extra <<<"${calendar}"
	if [[ -n ${extra:-} ]]; then
		days=${date}
		date=${time}
		time=${extra}
	elif [[ -z ${time} ]]; then
		return 1
	fi
	[[ ${date} == '*-*-*' ]] || return 1
	IFS=: read -r hour minute second <<<"${time}"
	[[ -z ${second} || ${second} =~ ^0+$ ]] || return 1
	hour=$(_svc_cron_field "${hour}" 23) || return 1
	minute=$(_svc_cron_field "${minute:-}" 59) || return 1
	if [[ -n ${days} ]]; then
		local -a names=(Sun Mon Tue Wed Thu Fri Sat) list=()
		local item first last i
		IFS=, read -ra list <<<"${days}"
		out=''
		for item in "${list[@]}"; do
			first=${item%%..*}
			last=${item##*..}
			for ((i = 0; i < 7; i++)); do
				[[ ${names[i]} == "${first}" ]] && first=${i}
				[[ ${names[i]} == "${last}" ]] && last=${i}
			done
			[[ ${first} =~ ^[0-6]$ && ${last} =~ ^[0-6]$ ]] || return 1
			if [[ ${first} == "${last}" ]]; then
				day=${first}
			else
				day="${first}-${last}"
			fi
			out+="${out:+,}${day}"
		done
		dow=${out}
	fi
	printf '%s %s * * %s' "${minute}" "${hour}" "${dow}"
	return
}

# svc_schedule NAME CALENDAR DESCRIPTION COMMAND...: runs COMMAND as root on the schedule CALENDAR (a systemd OnCalendar
# expression, see svc_calendar_cron). Under systemd it writes NAME.service and NAME.timer (Persistent, so a run missed
# while the server was off is made up) and enables the timer; otherwise a cron job /etc/cron.d/NAME, which cronie,
# cron, dcron and busybox crond with /etc/cron.d all read. The COMMAND words must not contain a percent sign (cron
# turns it into a newline).
svc_schedule() {
	local name=$1 calendar=$2 description=$3 cron word job
	shift 3
	[[ ${name} =~ ^[A-Za-z0-9_-]+$ ]] || die "Invalid schedule name '${name}'."
	(($# > 0)) || die "The schedule ${name} has no command."
	for word in "$@"; do
		[[ ${word} != *%* && ${word} != *$'\n'* ]] || die "The command of the schedule ${name} contains % or a line break."
	done
	job=$(printf '%q ' "$@")
	job=${job% }
	if svc_is_systemd; then
		svc_unit "${name}.service" <<EOF
# Managed by lss (module ${LSS_MODULE:-lss}).
[Unit]
Description=${description}

[Service]
Type=oneshot
ExecStart=${job}
EOF
		svc_unit "${name}.timer" <<EOF
# Managed by lss (module ${LSS_MODULE:-lss}).
[Unit]
Description=${description} (schedule)

[Timer]
OnCalendar=${calendar}
Persistent=true

[Install]
WantedBy=timers.target
EOF
		svc_timer_skip_missed "${name}.timer"
		svc_enable "${name}.timer"
		return
	fi
	cron=$(svc_calendar_cron "${calendar}") || die "The schedule '${calendar}' of ${name} has no cron form."
	file_write 0644 root:root "${SVC_CRON_DIR}/${name}" <<EOF
# Managed by lss (module ${LSS_MODULE:-lss}). ${description}.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${cron} root ${job}
EOF
	return
}

# svc_schedule_remove NAME: removes the timer or the cron job of svc_schedule.
svc_schedule_remove() {
	local name=$1
	if svc_is_systemd; then
		svc_disable "${name}.timer"
		file_remove "/etc/systemd/system/${name}.timer"
		file_remove "/etc/systemd/system/${name}.service"
		svc_daemon_reload
	fi
	file_remove "${SVC_CRON_DIR}/${name}"
	return
}

# svc_dropin UNIT NAME: writes /etc/systemd/system/UNIT.d/NAME.conf from stdin and reloads systemd when it changed.
# UNIT includes the suffix (nginx.service, fail2ban.service, ...).
svc_dropin() {
	local unit=$1 name=$2
	if ! svc_is_systemd; then
		cat >/dev/null
		log_debug "No systemd: drop-in ${name} of ${unit} skipped."
		return 0
	fi
	file_write 0644 root:root "/etc/systemd/system/${unit}.d/${name}.conf"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		svc_daemon_reload
	fi
	return
}

svc_dropin_remove() {
	local path="/etc/systemd/system/$1.d/$2.conf"
	[[ -e ${path} ]] || return 0
	file_remove "${path}"
	rmdir "/etc/systemd/system/$1.d" 2>/dev/null || true
	svc_daemon_reload
}

# Waits up to SECONDS for a TCP port on HOST to accept connections.
svc_wait_port() {
	local host=$1 port=$2 seconds=${3:-30} i
	for ((i = 0; i < seconds; i++)); do
		if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	return 1
}

_svc_selinux_on() {
	command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled
}

# _svc_selinux_nnp UNIT: under SELinux a confined service enters its own domain on exec (httpd_t, postgresql_t).
# NoNewPrivileges blocks that change wherever the policy does not allow it (avc: nnp_transition); systemd also implies
# NoNewPrivileges for a service with User= and the sandbox's system call settings. The service then stays in init_t,
# which may not read its own files and is less confined than its domain. For a UNIT whose program carries an
# entrypoint label (TYPE_exec_t), a policy module of lss (lss_nnp_TYPE) lets systemd start TYPE_t with
# NoNewPrivileges, so the sandbox stays whole.
_svc_selinux_nnp() {
	local unit=$1 program type domain module dir
	_svc_selinux_on || return 0
	program=$(systemctl show -P ExecStart "${unit}" 2>/dev/null | sed -n 's/^{ path=\([^ ;]*\) .*/\1/p' | head -n 1) || true
	# A module may sandbox its unit before the package brings the program; it calls svc_sandbox again after the
	# installation, and the module follows then.
	[[ -n ${program} && -e ${program} ]] || return 0
	type=$(stat -c %C "${program}" 2>/dev/null | cut -d : -f 3) || true
	[[ ${type} == ?*_exec_t ]] || return 0
	domain=${type%_exec_t}_t
	module=lss_nnp_${type%_exec_t}
	! _svc_selinux_loaded "${module}" || return 0
	dir=$(mktemp -d)
	printf '(allow init_t %s (process2 (nnp_transition nosuid_transition)))\n' "${domain}" >"${dir}/${module}.cil"
	if ! log_command semodule -i "${dir}/${module}.cil"; then
		rm -rf -- "${dir}"
		die "${unit}: SELinux does not take the policy module ${module} that lets systemd start ${domain}; see the log."
	fi
	rm -rf -- "${dir}"
	files_note_change "SELinux module ${module}: systemd starts ${domain} with NoNewPrivileges"
	return
}

# _svc_selinux_loaded MODULE: the SELinux policy module MODULE is installed.
_svc_selinux_loaded() {
	semodule -l 2>/dev/null | awk '{ print $1 }' | grep -qxF "$1"
	return
}

# svc_exec_programs UNIT: the programs systemd runs for UNIT (ExecStartPre, ExecStart, ExecStartPost), one per line.
svc_exec_programs() {
	local property
	for property in ExecStartPre ExecStart ExecStartPost; do
		systemctl show -P "${property}" "$1" 2>/dev/null | grep -o 'path=[^ ;]*' | cut -d = -f 2
	done
	return 0
}

# svc_selinux_spawner NAME SOURCE PATH...: lets a process start programs in their own SELinux domains while its
# sandbox keeps NoNewPrivileges: the Postfix master its daemons (postfix_qmgr_t, postfix_smtpd_t), Dovecot its auth
# process (dovecot_auth_t), systemd the helpers of postfix.service (restorecon, newaliases). NoNewPrivileges forbids
# each such change unless the policy allows it (avc: nnp_transition), and the program does not start. SOURCE is the
# domain of the process (init_t for systemd) or the program systemd starts it from; the PATHs are programs or
# directories of programs. The policy itself names the domain of every program (selinuxexeccon), and the policy module
# lss_spawn_NAME allows exactly these changes and nothing else. Its source stays in SVC_SELINUX_DIR, so a second run
# loads it only when an update brought other programs. Without SELinux it does nothing.
svc_selinux_spawner() {
	local name=$1 source=$2 module=lss_spawn_$1 path file domain
	shift 2
	_svc_selinux_on || return 0
	if [[ ${source} == /* ]]; then
		domain=$(selinuxexeccon "${source}" system_u:system_r:init_t:s0 2>/dev/null | cut -d : -f 3) || true
		[[ -n ${domain} ]] || die "${LSS_MODULE:-lss}: SELinux names no domain for ${source}."
		source=${domain}
	fi
	local -a rules=() files=()
	for path in "$@"; do
		if [[ -d ${path} ]]; then
			files=("${path}"/*)
		else
			files=("${path}")
		fi
		for file in "${files[@]}"; do
			[[ -f ${file} && -x ${file} ]] || continue
			domain=$(selinuxexeccon "${file}" "system_u:system_r:${source}:s0" 2>/dev/null | cut -d : -f 3) || true
			[[ -z ${domain} || ${domain} == "${source}" ]] ||
				rules+=("(allow ${source} ${domain} (process2 (nnp_transition nosuid_transition)))")
		done
	done
	if [[ ${#rules[@]} -eq 0 ]]; then
		svc_selinux_spawner_remove "${name}"
		return 0
	fi
	install -d -m 0755 "${SVC_SELINUX_DIR}"
	file_write 0644 root:root "${SVC_SELINUX_DIR}/${module}.cil" < <(printf '%s\n' "${rules[@]}" | LC_ALL=C sort -u)
	if [[ ${LSS_FILE_CHANGED} == 0 ]] && _svc_selinux_loaded "${module}"; then
		return 0
	fi
	log_command semodule -i "${SVC_SELINUX_DIR}/${module}.cil" ||
		die "${LSS_MODULE:-lss}: SELinux does not take the policy module ${module} for ${source}; see the log."
	files_note_change "SELinux module ${module}: ${source} starts its programs in their domains with NoNewPrivileges"
	return
}

# svc_selinux_spawner_remove NAME: unloads the policy module of svc_selinux_spawner and deletes its source.
svc_selinux_spawner_remove() {
	local module=lss_spawn_$1
	if command -v semodule >/dev/null 2>&1 && _svc_selinux_loaded "${module}"; then
		log_command semodule -r "${module}" ||
			die "${LSS_MODULE:-lss}: SELinux keeps the policy module ${module}; see the log."
		files_note_change "removed SELinux module ${module}"
	fi
	file_remove "${SVC_SELINUX_DIR}/${module}.cil"
	return
}

# svc_scanner_sandbox full|strict [PATH...]: [Service] lines that confine lss's own scanner units. They read the whole
# system but write only to the PATHs (with strict) or below /var (with full). The real /tmp, /proc/kallsyms, the
# kernel modules and the kernel log stay visible: a private /tmp would hide it from ClamAV and rkhunter, and rkhunter,
# AIDE and Lynis check the others.
svc_scanner_sandbox() {
	local level=$1 path nnp=yes
	shift
	# Under SELinux a scanner enters its own domain (aide_t, antivirus_t) when lss's wrapper runs it. NoNewPrivileges
	# blocks that change; the scanner then stays in init_t, which may not write its reports.
	if _svc_selinux_on; then
		nnp=no
	fi
	printf '%s\n' "ProtectSystem=${level}" ProtectHome=read-only "NoNewPrivileges=${nnp}" ProtectControlGroups=yes \
		ProtectClock=yes ProtectHostname=yes RestrictSUIDSGID=yes RestrictRealtime=yes RestrictNamespaces=yes \
		LockPersonality=yes SystemCallArchitectures=native
	for path in "$@"; do
		printf 'ReadWritePaths=-%s\n' "${path}"
	done
	return
}

# svc_sandbox UNIT [DIRECTIVE...]: confines a service with a drop-in (lss-sandbox.conf): read-only system, no home
# directories, a private /tmp and /dev, no kernel tunables, modules or logs, no new privileges (see _svc_selinux_nnp for
# SELinux). DIRECTIVEs follow the baseline, so a service adds the paths it writes (ReadWritePaths=/var/lib/NAME) or
# relaxes a setting it cannot live with (PrivateDevices=no); for single-value settings the last assignment wins.
svc_sandbox() {
	local unit=$1 directive
	shift
	_svc_selinux_nnp "${unit}"
	{
		printf '# Managed by lss (module %s). Sandbox of %s.\n[Service]\n' "${LSS_MODULE:-lss}" "${unit}"
		printf '%s\n' NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateTmp=yes PrivateDevices=yes \
			ProtectKernelTunables=yes ProtectKernelModules=yes ProtectKernelLogs=yes ProtectControlGroups=yes \
			ProtectClock=yes ProtectHostname=yes RestrictSUIDSGID=yes RestrictRealtime=yes RestrictNamespaces=yes \
			LockPersonality=yes SystemCallArchitectures=native \
			'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' ReadWritePaths=-/var/log ReadWritePaths=-/run
		for directive in "$@"; do
			printf '%s\n' "${directive}"
		done
	} | svc_dropin "${unit}" lss-sandbox
	return
}

# Settings that turn off every part of the svc_sandbox baseline that needs a mount namespace (the empty ReadWritePaths=
# clears the list). An AppArmor profile without attach_disconnected cannot name paths seen from such a namespace and
# refuses the service its systemd notification socket; that profile confines the files of the service instead.
# shellcheck disable=SC2034 # read by modules
SVC_SANDBOX_NO_MOUNTS=(ProtectSystem=no ProtectHome=no PrivateTmp=no PrivateDevices=no ProtectKernelTunables=no
	ProtectKernelModules=no ProtectKernelLogs=no ProtectControlGroups=no ProtectHostname=no ReadWritePaths=)

# svc_apparmor_confined PROGRAM: whether an enforcing AppArmor profile confines PROGRAM. Without a readable profile
# list (in a container, whose processes the host's profiles still confine) the label of a running PROGRAM tells;
# anything else counts as unconfined, so the full sandbox stays.
svc_apparmor_confined() {
	local enabled=${SVC_APPARMOR_ENABLED:-/sys/module/apparmor/parameters/enabled}
	local profiles=${SVC_APPARMOR_PROFILES:-/sys/kernel/security/apparmor/profiles}
	local proc=${SVC_PROC:-/proc} pid label
	[[ $(cat "${enabled}" 2>/dev/null) == Y ]] || return 1
	if [[ -r ${profiles} ]]; then
		grep -qxF "$1 (enforce)" "${profiles}"
		return
	fi
	for pid in $(pidof "$1" 2>/dev/null); do
		label=$(cat "${proc}/${pid}/attr/apparmor/current" 2>/dev/null || cat "${proc}/${pid}/attr/current" 2>/dev/null) || continue
		[[ ${label} == "$1 (enforce)" ]] && return 0
	done
	return 1
}

# svc_unit UNIT: writes /etc/systemd/system/UNIT (a unit of lss's own) from stdin and reloads systemd when it
# changed.
svc_unit() {
	if ! svc_is_systemd; then
		cat >/dev/null
		log_debug "No systemd: unit $1 skipped."
		return 0
	fi
	file_write 0644 root:root "/etc/systemd/system/$1"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		svc_daemon_reload
	fi
	return
}
