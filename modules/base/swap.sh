# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="swap"
MOD_GROUP="base"
MOD_DESCRIPTION="Swap file managed as a systemd unit, with low swappiness"
MOD_REQUIRES="system"
MOD_OPTIONS="size|auto|Size in MiB; auto = RAM up to 2 GiB, half of RAM up to 8 GiB, 4 GiB above
swappiness|10|How eagerly the kernel swaps (0-100)
path|/swapfile|Location of the swap file"

_swap_size() {
	local size memory
	size=$(opt size)
	if [[ ${size} == auto ]]; then
		memory=$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)
		if ((memory <= 2048)); then
			size=${memory}
		elif ((memory <= 8192)); then
			size=$((memory / 2))
		else
			size=4096
		fi
	fi
	printf '%s' "${size}"
	return
}

# systemd names a swap unit after its path: /swapfile -> swapfile.swap, /var/swap/file -> var-swap-file.swap.
_swap_unit() {
	systemd-escape --path --suffix=swap "$(opt path)"
	return
}

mod_check() {
	local size path
	size=$(opt size)
	path=$(opt path)
	[[ ${size} == auto || ${size} =~ ^[1-9][0-9]*$ ]] || die "LSS_SWAP_SIZE must be 'auto' or a size in MiB."
	[[ ${path} =~ ^/[A-Za-z0-9._/-]+$ && ${path} != */ ]] || die "LSS_SWAP_PATH '${path}' is not an absolute file path."
	opt_int swappiness >/dev/null
	(($(opt_int swappiness) <= 100)) || die "LSS_SWAP_SWAPPINESS must be between 0 and 100."
	if os_in_container; then
		die "swap needs a virtual machine or bare metal; containers use the swap of their host."
	fi
	return
}

mod_configure() {
	local path size unit current
	path=$(opt path)
	size=$(_swap_size)
	unit=$(_swap_unit)
	current=0
	if [[ -f ${path} ]]; then
		current=$(($(stat -c '%s' "${path}") / 1024 / 1024))
	fi
	if [[ ${current} != "${size}" ]]; then
		if swapon --show=NAME --noheadings | grep -qxF "${path}"; then
			swapoff "${path}"
		fi
		rm -f -- "${path}"
		log_info "Creating ${size} MiB swap file ${path}"
		(
			umask 077
			# fallocate makes holes on some file systems, which swapon rejects; dd always works.
			dd if=/dev/zero of="${path}" bs=1M count="${size}" status=none
		)
		chmod 600 "${path}"
		mkswap --quiet "${path}" >/dev/null
		files_note_change "swap file ${path} (${size} MiB)"
	fi
	chmod 600 "${path}"
	svc_unit "${unit}" <<UNIT
# Managed by lss (module swap).
[Unit]
Description=Swap file ${path} (lss)

[Swap]
What=${path}

[Install]
WantedBy=swap.target
UNIT
	svc_enable "${unit}"
	file_write 0644 root:root /etc/sysctl.d/60-lss-swap.conf <<<"vm.swappiness = $(opt_int swappiness)"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		sysctl -q -p /etc/sysctl.d/60-lss-swap.conf
	fi
	return
}

mod_verify() {
	swapon --show=NAME --noheadings | grep -qxF "$(opt path)" || die "swap: $(opt path) is not active."
	[[ $(sysctl -n vm.swappiness) == "$(opt_int swappiness)" ]] || die "swap: vm.swappiness is not $(opt_int swappiness)."
	return
}

mod_remove() {
	local path unit
	path=$(opt path)
	unit=$(_swap_unit)
	svc_disable "${unit}"
	if swapon --show=NAME --noheadings | grep -qxF "${path}"; then
		swapoff "${path}"
	fi
	file_remove "/etc/systemd/system/${unit}"
	svc_daemon_reload
	rm -f -- "${path}"
	file_remove /etc/sysctl.d/60-lss-swap.conf
	sysctl -q --system >/dev/null 2>&1 || true
	return
}
