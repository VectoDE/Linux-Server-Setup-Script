# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="auto-updates"
MOD_GROUP="security"
MOD_DESCRIPTION="Daily security updates, restart of affected services, reboot in a fixed window when needed"
MOD_REQUIRES="system"
MOD_OPTIONS="scope|security|security (only security fixes) or all (every update)
reboot|true|Reboot automatically when an update needs it (kernel, libc, systemd)
reboot_time|04:00|Time of day for the automatic reboot (HH:MM, local time)"

AU_REBOOT_UNIT=lss-reboot-if-needed

mod_check() {
	[[ $(opt scope) =~ ^(security|all)$ ]] || die "LSS_AUTO_UPDATES_SCOPE must be security or all."
	opt_bool reboot || true
	[[ $(opt reboot_time) =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "LSS_AUTO_UPDATES_REBOOT_TIME must look like 04:00."
}

mod_install() {
	if os_is_debian; then
		pkg_install unattended-upgrades apt-listchanges needrestart
	else
		pkg_install dnf-automatic dnf-utils
	fi
}

_au_debian() {
	local origins
	if [[ $(opt scope) == all ]]; then
		origins='"origin=*";'
	else
		# The distribution's security archive, plus ESM where Ubuntu Pro is attached. Origins-Pattern entries are
		# key=value lists; patterns for the other distribution simply match nothing.
		# shellcheck disable=SC2016 # unattended-upgrades expands ${distro_codename} itself
		origins='"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
	"origin=Debian,codename=${distro_codename},label=Debian-Security";
	"origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu";
	"origin=UbuntuESMApps,archive=${distro_codename}-apps-security";
	"origin=UbuntuESM,archive=${distro_codename}-infra-security";'
	fi
	file_write 0644 root:root /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
// Managed by lss (module auto-updates).
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
	file_write 0644 root:root /etc/apt/apt.conf.d/52lss-unattended-upgrades <<EOF
// Managed by lss (module auto-updates). Reboots are done by ${AU_REBOOT_UNIT}.timer.
Unattended-Upgrade::Origins-Pattern {
	${origins}
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
Dpkg::Options {
	"--force-confdef";
	"--force-confold";
};
EOF
	# Services that use updated libraries are restarted right away (a = automatic).
	file_write 0644 root:root /etc/needrestart/conf.d/60-lss.conf <<'EOF'
# Managed by lss (module auto-updates).
$nrconf{restart} = 'a';
$nrconf{kernelhints} = 0;
EOF
	svc_timer_skip_missed apt-daily.timer
	svc_timer_skip_missed apt-daily-upgrade.timer
	svc_enable apt-daily.timer
	svc_enable apt-daily-upgrade.timer
}

_au_rhel() {
	local type=default
	[[ $(opt scope) == security ]] && type=security
	file_write 0644 root:root /etc/dnf/automatic.conf <<EOF
# Managed by lss (module auto-updates). Reboots are done by ${AU_REBOOT_UNIT}.timer.
[commands]
upgrade_type = ${type}
random_sleep = 900
network_online_timeout = 120
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio

[base]
debuglevel = 1
EOF
	svc_timer_skip_missed dnf-automatic.timer
	svc_enable dnf-automatic.timer
}

# Reboots in the configured window if an update needs it; logs the reason to the journal.
_au_reboot_timer() {
	local check
	if os_is_debian; then
		check='test -f /run/reboot-required'
	else
		check='! needs-restarting --reboothint >/dev/null 2>&1'
	fi
	svc_unit "${AU_REBOOT_UNIT}.service" <<EOF
# Managed by lss (module auto-updates).
[Unit]
Description=Reboot if installed updates need it (lss)
After=apt-daily-upgrade.service dnf-automatic.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'if ${check}; then logger -t lss "Rebooting for updates"; systemctl reboot; fi'
EOF
	svc_unit "${AU_REBOOT_UNIT}.timer" <<EOF
# Managed by lss (module auto-updates).
[Unit]
Description=Daily reboot window for updates (lss)

[Timer]
OnCalendar=*-*-* $(opt reboot_time):00
RandomizedDelaySec=10min
Persistent=false

[Install]
WantedBy=timers.target
EOF
	svc_enable "${AU_REBOOT_UNIT}.timer"
}

mod_configure() {
	if os_is_debian; then
		_au_debian
	else
		_au_rhel
	fi
	if opt_bool reboot; then
		_au_reboot_timer
	else
		_au_remove_reboot_timer
	fi
}

_au_remove_reboot_timer() {
	[[ -f /etc/systemd/system/${AU_REBOOT_UNIT}.timer ]] || return 0
	svc_disable "${AU_REBOOT_UNIT}.timer"
	file_remove "/etc/systemd/system/${AU_REBOOT_UNIT}.timer"
	file_remove "/etc/systemd/system/${AU_REBOOT_UNIT}.service"
	svc_daemon_reload
}

mod_verify() {
	if os_is_debian; then
		svc_is_enabled apt-daily-upgrade.timer || die "auto-updates: apt-daily-upgrade.timer is not enabled."
		local output='' ok=0 i
		# A running unattended-upgrade holds its lock; the dry run then fails for a reason that has nothing to do
		# with the configuration, so wait for it.
		for ((i = 0; i < 40; i++)); do
			if output=$(unattended-upgrade --dry-run --debug 2>&1); then
				ok=1
				break
			fi
			grep -q 'Lock could not be acquired' <<<"${output}" || break
			sleep 15
		done
		if [[ ${ok} != 1 ]]; then
			printf '%s\n' "${output}" | tail -n 40 >&2
			die "auto-updates: unattended-upgrade --dry-run fails (output above)."
		fi
	else
		svc_is_enabled dnf-automatic.timer || die "auto-updates: dnf-automatic.timer is not enabled."
	fi
	if opt_bool reboot; then
		svc_is_enabled "${AU_REBOOT_UNIT}.timer" || die "auto-updates: the reboot timer is not enabled."
	fi
}

mod_remove() {
	_au_remove_reboot_timer
	if os_is_debian; then
		file_remove /etc/apt/apt.conf.d/52lss-unattended-upgrades
		file_remove /etc/apt/apt.conf.d/20auto-upgrades
		file_remove /etc/needrestart/conf.d/60-lss.conf
	else
		svc_disable dnf-automatic.timer
		file_remove /etc/dnf/automatic.conf
	fi
}
