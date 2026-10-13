# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="kernel-hardening"
MOD_GROUP="security"
MOD_DESCRIPTION="Kernel and network hardening (sysctl), unused kernel modules blocked, no core dumps"
MOD_REQUIRES="system"
MOD_OPTIONS="block_usb_storage|true|Block USB mass storage
ipv6_router_advertisements|true|Accept IPv6 router advertisements (many hosters configure IPv6 that way)
extra_blocked_modules||More kernel modules to block, separated by spaces"

KH_SYSCTL=/etc/sysctl.d/60-lss-hardening.conf
KH_MODPROBE=/etc/modprobe.d/60-lss-hardening.conf
KH_COREDUMP=/etc/systemd/coredump.conf.d/60-lss.conf
KH_LIMITS=/etc/security/limits.d/60-lss-coredump.conf

# File systems and network protocols a server does not need; each one is attack surface (CIS 1.1.1, 3.2).
KH_MODULES="cramfs freevxfs hfs hfsplus jffs2 udf dccp sctp rds tipc firewire-core firewire-ohci thunderbolt bluetooth btusb"

_kh_settings() {
	local accept_ra=0
	opt_bool ipv6_router_advertisements && accept_ra=1
	cat <<EOF
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.sysrq = 0
kernel.perf_event_paranoid = 3
kernel.core_uses_pid = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
dev.tty.ldisc_autoload = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = ${accept_ra}
net.ipv6.conf.default.accept_ra = ${accept_ra}
EOF
}

mod_check() {
	local module
	opt_bool block_usb_storage || true
	opt_bool ipv6_router_advertisements || true
	for module in $(opt extra_blocked_modules); do
		[[ ${module} =~ ^[a-z0-9_-]+$ ]] || die "LSS_KERNEL_HARDENING_EXTRA_BLOCKED_MODULES: '${module}' is not a module name."
	done
	if os_in_container; then
		die "kernel-hardening changes the kernel; run it on a virtual machine or bare metal, not in a container."
	fi
}

mod_configure() {
	local module modules
	{
		printf '# Managed by lss (module kernel-hardening). Later files (70-lss-*.conf) may relax single values,\n'
		printf '# for example net.ipv4.ip_forward for containers and VPNs.\n'
		_kh_settings
	} | file_write 0644 root:root "${KH_SYSCTL}"
	# -e: a key this kernel does not have is skipped instead of failing the run.
	sysctl -q -e -p "${KH_SYSCTL}" >/dev/null

	modules="${KH_MODULES} $(opt extra_blocked_modules)"
	opt_bool block_usb_storage && modules+=" usb-storage uas"
	{
		printf '# Managed by lss (module kernel-hardening).\n'
		for module in ${modules}; do
			printf 'install %s /bin/false\nblacklist %s\n' "${module}" "${module}"
		done
	} | file_write 0644 root:root "${KH_MODPROBE}"

	file_write 0644 root:root "${KH_COREDUMP}" <<'EOF'
# Managed by lss (module kernel-hardening). Core dumps can contain passwords and keys.
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
	file_write 0644 root:root "${KH_LIMITS}" <<'EOF'
# Managed by lss (module kernel-hardening).
*    hard    core    0
EOF
}

mod_verify() {
	local key value actual
	while IFS='=' read -r key value; do
		key=${key// /}
		value=${value# }
		[[ -n ${key} ]] || continue
		# Keys the running kernel does not offer are skipped (sysctl -e did the same).
		actual=$(sysctl -n "${key}" 2>/dev/null) || continue
		actual=$(tr -s '[:space:]' ' ' <<<"${actual}")
		[[ ${actual% } == "${value}" ]] || die "kernel-hardening: ${key} is ${actual% }, expected ${value}."
	done < <(_kh_settings)
	modprobe -n -v cramfs 2>/dev/null | grep -q '/bin/false' || die "kernel-hardening: blocked modules can still be loaded."
}

mod_remove() {
	file_remove "${KH_SYSCTL}"
	file_remove "${KH_MODPROBE}"
	file_remove "${KH_COREDUMP}"
	file_remove "${KH_LIMITS}"
	# The distribution defaults come back with "sysctl --system"; values without a default stay until reboot.
	sysctl -q --system >/dev/null 2>&1 || true
}
