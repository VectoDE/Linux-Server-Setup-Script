# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="auditd"
MOD_GROUP="security"
MOD_DESCRIPTION="Linux audit: who changed users, sudo, SSH, time, permissions and kernel modules (CIS rules)"
MOD_REQUIRES="system"
MOD_OPTIONS="immutable|false|Lock the rules until the next reboot (-e 2); rule changes then need a reboot
max_log_file|32|Size of one audit log in MiB
num_logs|10|Number of audit logs kept"

AUDIT_RULES=/etc/audit/rules.d/60-lss.rules
AUDIT_FINAL=/etc/audit/rules.d/99-lss-immutable.rules
AUDIT_CONF=/etc/audit/auditd.conf

mod_check() {
	opt_bool immutable || true
	opt_int max_log_file >/dev/null
	opt_int num_logs >/dev/null
	if os_in_container; then
		die "auditd needs the kernel audit system; run it on a virtual machine or bare metal, not in a container."
	fi
}

mod_install() {
	pkg_install_family "auditd audispd-plugins" "audit audit-libs"
}

# ausyscall name of the 64- or 32-bit ABI of this machine; fails if there is no 32-bit ABI.
_auditd_machine() {
	case $1:$(uname -m) in
	b64:*) uname -m ;;
	b32:x86_64) printf 'i386' ;;
	b32:aarch64) printf 'arm' ;;
	*) return 1 ;;
	esac
}

# Drops system calls (and whole rules) the architecture does not have; auditctl rejects unknown names.
_auditd_filter() {
	local line arch names name kept machine
	while IFS= read -r line; do
		if [[ ${line} =~ -F\ arch=(b32|b64).*-S\ ([a-z0-9_,]+) ]]; then
			arch=${BASH_REMATCH[1]}
			names=${BASH_REMATCH[2]}
			machine=$(_auditd_machine "${arch}") || continue
			kept=''
			for name in ${names//,/ }; do
				if ausyscall "${machine}" "${name}" --exact >/dev/null 2>&1; then
					kept+="${name},"
				fi
			done
			[[ -n ${kept} ]] || continue
			line=${line/"-S ${names}"/"-S ${kept%,}"}
		fi
		printf '%s\n' "${line}"
	done
}

# Sets KEY = VALUE pairs in auditd.conf, keeping everything else of the distribution's file.
_auditd_conf() {
	local content key value
	content=$(<"${AUDIT_CONF}")
	while [[ $# -gt 1 ]]; do
		key=$1 value=$2
		shift 2
		if grep -qE "^[[:space:]]*${key}[[:space:]]*=" <<<"${content}"; then
			content=$(sed -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" <<<"${content}")
		else
			content+=$'\n'"${key} = ${value}"
		fi
	done
	file_write 0640 root:root "${AUDIT_CONF}" <<<"${content}"
}

_auditd_immutable_now() {
	auditctl -s 2>/dev/null | grep -q '^enabled 2'
}

# Audit from the first process on, not only after auditd starts (takes effect at the next boot).
_auditd_boot_args() {
	local args='audit=1 audit_backlog_limit=8192'
	if os_is_debian && [[ -d /etc/default/grub.d ]] && command -v update-grub >/dev/null 2>&1; then
		file_write 0644 root:root /etc/default/grub.d/60-lss-audit.cfg <<<"GRUB_CMDLINE_LINUX=\"\${GRUB_CMDLINE_LINUX} ${args}\""
		if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
			update-grub >/dev/null 2>&1 || log_warn "auditd: update-grub failed; audit=1 applies once the boot loader is updated."
		fi
	elif os_is_rhel && command -v grubby >/dev/null 2>&1; then
		if ! grubby --info=DEFAULT 2>/dev/null | grep -q 'audit=1'; then
			grubby --update-kernel=ALL --args="${args}"
			files_note_change "kernel arguments ${args}"
		fi
	fi
}

mod_configure() {
	local changed=0
	file_write 0640 root:root "${AUDIT_RULES}" < <(template_render "$(template_path auditd 60-lss.rules)" | _auditd_filter)
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	if opt_bool immutable; then
		file_write 0640 root:root "${AUDIT_FINAL}" <<<$'## Managed by lss (module auditd): rules cannot change until reboot.\n-e 2'
		[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	elif [[ -f ${AUDIT_FINAL} ]]; then
		file_remove "${AUDIT_FINAL}"
		changed=1
	fi
	_auditd_conf max_log_file "$(opt_int max_log_file)" num_logs "$(opt_int num_logs)" max_log_file_action ROTATE \
		space_left_action SYSLOG admin_space_left_action SUSPEND disk_full_action SUSPEND disk_error_action SUSPEND
	local conf_changed=${LSS_FILE_CHANGED}
	_auditd_boot_args

	svc_enable auditd
	if [[ ${conf_changed} == 1 ]]; then
		# auditd refuses "systemctl restart" on the RHEL family; SIGHUP rereads auditd.conf.
		pkill -HUP -x auditd || true
	fi
	if [[ ${changed} == 1 ]]; then
		if _auditd_immutable_now; then
			log_warn "auditd: the loaded rules are locked (-e 2); the new rules apply after the next reboot."
		else
			augenrules --check >/dev/null 2>&1 || true
			augenrules --load >/dev/null || die "auditd: the kernel rejected the audit rules."
		fi
	fi
}

mod_verify() {
	svc_is_active auditd || die "auditd: the service is not running."
	auditctl -s | grep -qE '^enabled [12]' || die "auditd: kernel auditing is off."
	auditctl -l | grep -q 'key=identity' || die "auditd: the lss rules are not loaded."
}

mod_remove() {
	file_remove "${AUDIT_RULES}"
	file_remove "${AUDIT_FINAL}"
	if [[ -f /etc/default/grub.d/60-lss-audit.cfg ]]; then
		file_remove /etc/default/grub.d/60-lss-audit.cfg
		update-grub >/dev/null 2>&1 || true
	fi
	if _auditd_immutable_now; then
		log_warn "auditd: the loaded rules are locked; they disappear with the next reboot."
	else
		augenrules --load >/dev/null 2>&1 || true
	fi
}
