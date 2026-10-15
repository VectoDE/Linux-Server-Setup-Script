# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="smartd"
MOD_GROUP="monitoring"
MOD_DESCRIPTION="smartd watches the SMART health of every drive, runs short self-tests daily and long ones weekly, and logs failures and temperatures to the journal"
MOD_REQUIRES="system"
MOD_OPTIONS="temperature|45,55|Log a drive temperature above the first value (Celsius) and warn above the second"
MOD_PORTS="none"

# Virtual machines and containers usually show no SMART drives. smartd then has nothing to watch; it keeps running
# (-q never) instead of failing, so the module behaves the same on every server and picks up drives that appear later
# on the next restart.
SMARTD_BINARY=/usr/sbin/smartd
# Self-tests: short ones daily at 02:00, long ones on Saturdays at 03:00 (smartd -s, a regular expression).
SMARTD_TESTS='(S/../.././02|L/../../6/03)'

_smartd_conf() {
	if os_is_debian; then printf '/etc/smartd.conf'; else printf '/etc/smartmontools/smartd.conf'; fi
	return
}

# The unit is smartmontools.service on Debian and Ubuntu (smartd.service is an alias there) and smartd.service on the
# RHEL family; drop-ins must go to the real name.
_smartd_unit() {
	local unit
	unit=$(systemctl show -p Id --value smartd.service 2>/dev/null || true)
	printf '%s' "${unit:-smartd.service}"
	return
}

mod_check() {
	[[ $(opt temperature) =~ ^[0-9]{2},[0-9]{2,3}$ ]] || die "LSS_SMARTD_TEMPERATURE must look like 45,55."
	return
}

mod_install() {
	pkg_install smartmontools
	return
}

mod_configure() {
	local before unit
	before=$(files_changes_of smartd)
	unit=$(_smartd_unit)
	# Every drive that speaks SMART: health, attributes and error logs (-a), automatic offline tests and attribute
	# autosave on, drives in standby are not woken up (and not counted as missed), self-tests by schedule, temperature.
	file_write 0644 root:root "$(_smartd_conf)" <<EOF
# Managed by lss (module smartd). Change LSS_SMARTD_* in /etc/lss/lss.conf and run lss configure smartd.
DEVICESCAN -a -o on -S on -n standby,q -s ${SMARTD_TESTS} -W 4,$(opt temperature)
EOF
	svc_dropin "${unit}" lss-config <<EOF
${MON_MANAGED_BY} smartd): runs in virtual machines and containers too, and keeps running without drives.
[Unit]
ConditionVirtualization=
[Service]
EnvironmentFile=
ExecStart=
ExecStart=${SMARTD_BINARY} -n -q never
EOF
	# smartd talks to the drives (/dev) with raw I/O; ProtectClock would add a device filter that hides them.
	svc_sandbox "${unit}" PrivateDevices=no ProtectClock=no ReadWritePaths=-/var/lib/smartmontools
	svc_enable "${unit%.service}"
	if [[ $(files_changes_of smartd) != "${before}" ]]; then
		svc_restart "${unit%.service}" || die "smartd: smartd does not start."
	fi
	return
}

mod_verify() {
	local unit devices
	unit=$(_smartd_unit)
	svc_is_active "${unit%.service}" || die "smartd: ${unit} is not running."
	grep -q '^DEVICESCAN ' "$(_smartd_conf)" || die "smartd: $(_smartd_conf) does not scan the drives."
	devices=$(smartctl --scan 2>/dev/null | grep -c '^/dev/' || true)
	if ((devices == 0)); then
		log_info "smartd: smartctl finds 0 drives here (virtual machine or container); smartd keeps running for drives added later."
	fi
	return
}

mod_remove() {
	local unit
	unit=$(_smartd_unit)
	svc_disable "${unit%.service}"
	svc_dropin_remove "${unit}" lss-sandbox
	svc_dropin_remove "${unit}" lss-config
	file_remove "$(_smartd_conf)"
	pkg_remove smartmontools
	return
}
