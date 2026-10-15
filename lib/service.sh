# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# systemd helpers.

# Seconds lss waits for a unit to start. Some units (MySQL) wait for their service without a limit; a service that
# never reports ready would stop the run for good.
SVC_START_TIMEOUT=${SVC_START_TIMEOUT:-300}

svc_exists() {
	systemctl list-unit-files --no-legend "$1" "$1.service" 2>/dev/null | grep -q .
	return
}

svc_is_active() {
	systemctl is-active --quiet "$1"
	return
}

svc_is_enabled() {
	systemctl is-enabled --quiet "$1" 2>/dev/null
	return
}

# Enables and starts a unit; records a change only if it was not enabled or not running.
svc_enable() {
	local unit=$1
	if svc_is_enabled "${unit}" && svc_is_active "${unit}"; then
		return 0
	fi
	timeout "${SVC_START_TIMEOUT}" systemctl enable --now "${unit}" >/dev/null 2>&1 || {
		systemctl status --no-pager "${unit}" >&2 || true
		journalctl -u "${unit}" -n 30 --no-pager >&2 || true
		die "Could not start ${unit}."
	}
	files_note_change "enabled ${unit}"
}

# svc_timer_skip_missed TIMER: before a stopped timer with Persistent=true is started, records "ran now" in its
# stamp file, so systemd does not catch up on runs it missed while the timer was off. Otherwise enabling
# apt-daily-upgrade.timer on a fresh server starts a full unattended upgrade at once, which holds the dpkg lock
# for the rest of the setup.
svc_timer_skip_missed() {
	local stamp="${LSS_SYSTEMD_TIMER_DIR:-/var/lib/systemd/timers}/stamp-$1"
	svc_is_active "$1" && return 0
	[[ ! -L ${stamp} ]] || die "${stamp} is a symbolic link."
	mkdir -p "$(dirname "${stamp}")"
	touch "${stamp}"
}

svc_disable() {
	local unit=$1
	svc_exists "${unit}" || return 0
	if svc_is_enabled "${unit}" || svc_is_active "${unit}"; then
		systemctl disable --now "${unit}" >/dev/null 2>&1 || true
		files_note_change "disabled ${unit}"
	fi
}

svc_restart() {
	timeout "${SVC_START_TIMEOUT}" systemctl restart "$1" || {
		systemctl status --no-pager "$1" >&2 || true
		journalctl -u "$1" -n 30 --no-pager >&2 || true
		return 1
	}
}

svc_reload() {
	timeout "${SVC_START_TIMEOUT}" systemctl reload-or-restart "$1" || {
		systemctl status --no-pager "$1" >&2 || true
		return 1
	}
}

svc_daemon_reload() {
	systemctl daemon-reload
	return
}

# svc_dropin UNIT NAME: writes /etc/systemd/system/UNIT.d/NAME.conf from stdin and reloads systemd when it changed.
# UNIT includes the suffix (nginx.service, fail2ban.service, ...).
svc_dropin() {
	local unit=$1 name=$2
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
	if semodule -l 2>/dev/null | awk '{ print $1 }' | grep -qxF "${module}"; then
		return 0
	fi
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
	file_write 0644 root:root "/etc/systemd/system/$1"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		svc_daemon_reload
	fi
	return
}
