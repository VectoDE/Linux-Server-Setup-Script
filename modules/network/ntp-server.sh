# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="ntp-server"
MOD_GROUP="network"
MOD_DESCRIPTION="chrony of the time module also serves NTP on port 123, to the WireGuard network or to everyone, rate-limited"
MOD_REQUIRES="time"
MOD_OPTIONS="access|vpn|Who may ask for the time: vpn (the WireGuard network) or public (everyone)
ratelimit|true|Answer each client at most about once a second, with short bursts, so the server cannot amplify floods"
MOD_PORTS="123/udp from the WireGuard network (access vpn) or from everyone (access public)"

# chrony keeps the time module's configuration, which reads the files of this directory last; the file here turns the
# NTP port on and names who may ask. Inside a container the time module leaves chrony out (the host owns the clock), so
# this module sets chrony up there to serve the time without ever setting the clock (chronyd -x).
NTP_FILE_NAME=lss-ntp-server.conf
NTP_PORT=123

_ntp_unit() {
	if os_is_debian; then printf 'chrony'; else printf 'chronyd'; fi
	return
}

_ntp_conf() {
	if os_is_debian; then printf '/etc/chrony/conf.d/%s' "${NTP_FILE_NAME}"; else printf '/etc/chrony.d/%s' "${NTP_FILE_NAME}"; fi
	return
}

mod_check() {
	[[ $(opt access) =~ ^(vpn|public)$ ]] || die "LSS_NTP_SERVER_ACCESS must be vpn or public."
	opt_bool ratelimit || true
	return
}

mod_install() {
	pkg_install chrony
	return
}

# _ntp_time_config: chrony's configuration as the time module writes it, from the time module's options. Inside a
# container only; elsewhere the time module has written it already.
_ntp_time_config() {
	(
		# shellcheck source=/dev/null
		source "$(module_file time)"
		LSS_MODULE="time"
		_time_chrony_config
	)
	return
}

_ntp_config() {
	printf '# Managed by lss (module ntp-server). Change LSS_NTP_SERVER_* in /etc/lss/lss.conf and run lss configure ntp-server.\n'
	printf 'port %s\n' "${NTP_PORT}"
	if [[ $(opt access) == public ]]; then
		printf 'allow all\n'
	else
		printf 'allow %s\n' "$(fw_vpn_network)"
	fi
	# lss verify asks over the loopback interface.
	printf 'allow 127.0.0.1\nallow ::1\n'
	if opt_bool ratelimit; then
		printf 'ratelimit interval 1 burst 16 leak 2\n'
	fi
	return
}

# _ntp_exec UNIT: the command line of the distribution's chronyd unit with -x added. It is taken over rather than
# written anew: Debian starts chronyd with "!" (as root although the unit says User=_chrony) and -n (Type=notify),
# the RHEL family lets it fork.
_ntp_exec() {
	local unit=$1 fragment line
	fragment=$(systemctl show -p FragmentPath --value "${unit}")
	line=$(sed -n 's/^ExecStart=\(..*\)$/\1/p' "${fragment}" 2>/dev/null | tail -n 1)
	[[ -n ${line} ]] || die "ntp-server: ${unit} has no command line in ${fragment:-its unit file}."
	printf '%s -x' "${line}"
	return
}

# _ntp_container_dropin: inside a container chronyd serves the time but must not set the clock it shares with the host
# (-x), and the unit's conditions on CAP_SYS_TIME and on running outside a container no longer apply.
_ntp_container_dropin() {
	local unit exec
	unit="$(_ntp_unit).service"
	if os_in_container; then
		exec=$(_ntp_exec "${unit}") || return 1
		svc_dropin "${unit}" lss-ntp-server <<EOF
# Managed by lss (module ntp-server): inside a container chronyd serves the time without setting the clock.
[Unit]
ConditionCapability=
ConditionVirtualization=
[Service]
ExecStart=
ExecStart=${exec}
EOF
	else
		LSS_FILE_CHANGED=0
		if [[ -e /etc/systemd/system/${unit}.d/lss-ntp-server.conf ]]; then
			svc_dropin_remove "${unit}" lss-ntp-server
			LSS_FILE_CHANGED=1
		fi
	fi
	return
}

mod_configure() {
	local before before_time config unit
	unit=$(_ntp_unit)
	before=$(files_changes_of ntp-server)
	before_time=$(files_changes_of time)
	if os_in_container; then
		_ntp_time_config
	fi
	_ntp_container_dropin
	config=$(_ntp_config)
	file_write 0644 root:root "$(_ntp_conf)" <<<"${config}"
	# chronyd adjusts the clock (adjtimex), so ProtectClock stays off; it writes its drift file and NTS keys.
	svc_sandbox "${unit}.service" ReadWritePaths=/var/lib/chrony ProtectClock=no
	fw_allow "${NTP_PORT}/udp:$(opt access)"
	svc_enable "${unit}"
	if [[ $(files_changes_of ntp-server) != "${before}" || $(files_changes_of time) != "${before_time}" ]]; then
		svc_restart "${unit}" || die "ntp-server: chronyd does not start with the NTP port open."
	fi
	return
}

# _ntp_probe ADDRESS: sends an NTP client request (version 4, mode 3) and prints the first byte of the reply as a number;
# nothing when no reply came within 5 seconds.
_ntp_probe() {
	local address=$1 fd reply
	exec {fd}<>"/dev/udp/${address}/${NTP_PORT}" || return 0
	# 48 bytes: LI 0, VN 4, mode 3, then zeros.
	printf '\x23%047d' 0 | tr 0 '\000' >&"${fd}"
	reply=$(timeout 5 dd bs=512 count=1 status=none <&"${fd}" | od -An -N1 -tu1 | tr -d ' \n' || true)
	exec {fd}>&-
	printf '%s' "${reply}"
	return
}

mod_verify() {
	local unit i first=''
	unit=$(_ntp_unit)
	svc_is_active "${unit}" || die "ntp-server: ${unit} is not running."
	# chronyd answers clients also before it is synchronised itself (with the leap indicator "unsynchronised").
	for ((i = 0; i < 10; i++)); do
		first=$(_ntp_probe 127.0.0.1)
		[[ -z ${first} ]] || break
		sleep 1
	done
	[[ -n ${first} ]] || die "ntp-server: chronyd does not answer NTP requests on port ${NTP_PORT}."
	(((first & 7) == 4)) || die "ntp-server: the answer on port ${NTP_PORT} is no NTP server reply (mode $((first & 7)))."
	ss -Hlun "sport = :${NTP_PORT}" | grep -q . || die "ntp-server: nothing listens on ${NTP_PORT}/udp."
	return
}

mod_remove() {
	local unit
	unit=$(_ntp_unit)
	file_remove "$(_ntp_conf)"
	svc_dropin_remove "${unit}.service" lss-sandbox
	if os_in_container; then
		svc_dropin_remove "${unit}.service" lss-ntp-server
		svc_disable "${unit}"
		pkg_remove chrony
	elif svc_is_active "${unit}"; then
		# The time module's chrony keeps the clock, with the NTP port closed again.
		svc_restart "${unit}" || die "ntp-server: chronyd does not start without the NTP port."
	fi
	return
}
