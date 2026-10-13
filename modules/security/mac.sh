# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="mac"
MOD_GROUP="security"
MOD_DESCRIPTION="Mandatory access control: AppArmor on Debian/Ubuntu, SELinux enforcing on the RHEL family"
MOD_REQUIRES="system"
MOD_OPTIONS="apparmor_extra_profiles|true|Debian/Ubuntu: also load the profiles of apparmor-profiles (complain mode)"

SELINUX_CONFIG=/etc/selinux/config

mod_check() {
	opt_bool apparmor_extra_profiles || true
	if os_in_container; then
		die "mac needs the kernel's security module; run it on a virtual machine or bare metal, not in a container."
	fi
	return
}

mod_install() {
	if os_is_debian; then
		pkg_install apparmor apparmor-utils
		if opt_bool apparmor_extra_profiles; then
			pkg_install apparmor-profiles
		fi
	else
		pkg_install selinux-policy-targeted policycoreutils policycoreutils-python-utils
	fi
	return
}

_mac_selinux() {
	local current config
	config=$(sed -E -e 's/^SELINUX=.*/SELINUX=enforcing/' -e 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' "${SELINUX_CONFIG}")
	grep -q '^SELINUX=' <<<"${config}" || config+=$'\nSELINUX=enforcing'
	file_write 0644 root:root "${SELINUX_CONFIG}" <<<"${config}"
	current=$(getenforce 2>/dev/null || printf 'Disabled')
	case ${current} in
	Enforcing) ;;
	Permissive)
		setenforce 1
		files_note_change "SELinux enforcing"
		;;
	*)
		# Switching on from Disabled needs a relabel of every file, which happens during the next boot.
		if [[ ! -e /.autorelabel ]]; then
			touch /.autorelabel
			files_note_change "SELinux relabel scheduled"
		fi
		log_warn "SELinux was disabled; it becomes enforcing after the next reboot (the first boot relabels all files)."
		;;
	esac
	return
}

_mac_apparmor() {
	svc_enable apparmor
	[[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]] ||
		die "mac: the kernel runs without AppArmor (add apparmor=1 security=apparmor to the kernel command line)."
	return
}

mod_configure() {
	if os_is_debian; then
		_mac_apparmor
	else
		_mac_selinux
	fi
	return
}

mod_verify() {
	if os_is_debian; then
		aa-status --enabled 2>/dev/null || die "mac: AppArmor is not enabled."
		[[ $(aa-status --profiled 2>/dev/null || printf 0) -gt 0 ]] || die "mac: AppArmor has no profiles loaded."
	else
		grep -q '^SELINUX=enforcing' "${SELINUX_CONFIG}" || die "mac: SELinux is not configured as enforcing."
		if [[ $(getenforce) != Enforcing && ! -e /.autorelabel ]]; then
			die "mac: SELinux is $(getenforce), not enforcing."
		fi
	fi
	return
}

# MAC stays on: AppArmor is the Debian/Ubuntu default and SELinux enforcing the RHEL default, so lowering it on
# removal would leave the server weaker than its distribution ships it.
mod_remove() {
	log_info "mac: AppArmor/SELinux stay enabled (distribution default)."
	return
}
