# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="time"
MOD_GROUP="base"
MOD_DESCRIPTION="Time zone and time synchronisation with chrony over NTS (authenticated time)"
MOD_REQUIRES="system"
MOD_OPTIONS="timezone|UTC|Time zone, for example UTC or Europe/Berlin
servers|time.cloudflare.com nts.netnod.se ptbtime1.ptb.de|Time servers, separated by spaces
nts|true|Authenticate the time servers with NTS (they must support it)"

_time_unit() {
	if os_is_debian; then printf 'chrony'; else printf 'chronyd'; fi
	return
}

_time_config() {
	if os_is_debian; then printf '/etc/chrony/chrony.conf'; else printf '/etc/chrony.conf'; fi
	return
}

mod_check() {
	local timezone server
	timezone=$(opt timezone)
	[[ ${timezone} =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]] || die "LSS_TIME_TIMEZONE '${timezone}' is not a time zone name."
	for server in $(opt servers); do
		[[ ${server} =~ ^[A-Za-z0-9.-]+$ ]] || die "LSS_TIME_SERVERS: '${server}' is not a host name."
	done
	[[ -n $(opt servers) ]] || die "LSS_TIME_SERVERS must name at least one server."
	opt_bool nts || true
	return
}

# A container shares the clock of its host, which keeps it in sync; there the module sets only the time zone.
mod_install() {
	pkg_install tzdata
	if ! os_in_container; then
		pkg_install chrony
	fi
	return
}

mod_configure() {
	local timezone zone_file server suffix=''
	timezone=$(opt timezone)
	zone_file="/usr/share/zoneinfo/${timezone}"
	[[ -f ${zone_file} ]] || die "Unknown time zone '${timezone}' (no ${zone_file})."
	if [[ $(readlink /etc/localtime 2>/dev/null) != "${zone_file}" ]]; then
		files_backup /etc/localtime
		ln -sfn "${zone_file}" /etc/localtime
		files_note_change "time zone ${timezone}"
	fi
	if os_is_debian; then
		file_write 0644 root:root /etc/timezone <<<"${timezone}"
	fi

	if os_in_container; then
		log_info "time: container detected; the host keeps the clock in sync, so chrony is not set up."
		return 0
	fi

	opt_bool nts && suffix=' nts'
	TIME_SOURCES=''
	for server in $(opt servers); do
		TIME_SOURCES+="server ${server} iburst${suffix}"$'\n'
	done
	TIME_SOURCES=${TIME_SOURCES%$'\n'}
	if os_is_debian; then TIME_DRIFTFILE=/var/lib/chrony/chrony.drift; else TIME_DRIFTFILE=/var/lib/chrony/drift; fi
	template_install time chrony.conf 0644 root:root "$(_time_config)"
	local changed=${LSS_FILE_CHANGED}
	# systemd-timesyncd must not fight chrony for the clock.
	svc_disable systemd-timesyncd
	svc_enable "$(_time_unit)"
	if [[ ${changed} == 1 ]]; then
		svc_restart "$(_time_unit)"
	fi
}

mod_verify() {
	local i server
	[[ $(readlink /etc/localtime) == "/usr/share/zoneinfo/$(opt timezone)" ]] ||
		die "time: the time zone is not $(opt timezone)."
	os_in_container && return 0
	svc_is_active "$(_time_unit)" || die "time: $(_time_unit) is not running."
	# chronyc answers once the daemon is up; reaching a server is not required (the network may block NTP).
	for ((i = 0; i < 10; i++)); do
		chronyc -n tracking >/dev/null 2>&1 && break
		sleep 1
	done
	chronyc -n tracking >/dev/null || die "time: chronyc gets no answer from chronyd."
	# chronyd resolves the server names in the background, so a source appears a few seconds after the start.
	server=$(opt servers | cut -d ' ' -f 1)
	for ((i = 0; i < 30; i++)); do
		chronyc -N sources 2>/dev/null | grep -qF "${server}" && return 0
		sleep 1
	done
	die "time: chronyd does not use the configured servers."
}

mod_remove() {
	svc_disable "$(_time_unit)"
	pkg_remove chrony
	if svc_exists systemd-timesyncd; then
		svc_enable systemd-timesyncd
	fi
	return
}
