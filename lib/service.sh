# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# systemd helpers.

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
	systemctl enable --now "${unit}" >/dev/null 2>&1 || {
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
	systemctl restart "$1" || {
		systemctl status --no-pager "$1" >&2 || true
		journalctl -u "$1" -n 30 --no-pager >&2 || true
		return 1
	}
}

svc_reload() {
	systemctl reload-or-restart "$1" || {
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

# svc_unit UNIT: writes /etc/systemd/system/UNIT (a unit of lss's own) from stdin and reloads systemd when it
# changed.
svc_unit() {
	file_write 0644 root:root "/etc/systemd/system/$1"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		svc_daemon_reload
	fi
	return
}
