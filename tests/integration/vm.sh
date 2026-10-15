# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# shellcheck shell=bash
# KVM virtual machines for tests/integration/run.sh (systems named vm-NAME, see vm-images.conf). Needs qemu-system-x86,
# qemu-utils, cloud-image-utils and access to /dev/kvm. The VM gets a test user with a fresh key in the administrator
# group, so the SSH hardening keeps letting it in. A USB controller with a keyboard gives usbguard a device to allow.

VM_DIR=''
VM_PORT=${LSS_VM_SSH_PORT:-2222}
# Size of the VM: the app stacks and the profile all need more than the default (LSS_VM_MEMORY in MiB, LSS_VM_CPUS,
# LSS_VM_DISK as for qemu-img).
VM_MEMORY=${LSS_VM_MEMORY:-4096}
VM_CPUS=${LSS_VM_CPUS:-2}
VM_DISK=${LSS_VM_DISK:-20G}

vm_ssh() {
	ssh -i "${VM_DIR}/key" -p "${VM_PORT}" -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 tester@127.0.0.1 "$@"
	return
}

# vm_image NAME: downloads the image unless a copy with the published checksum is there; prints its path.
vm_image() {
	local name=$1 line url sums algo group cache file expected
	line=$(grep "^${name}|" tests/integration/vm-images.conf) || {
		echo "Unknown VM image ${name}" >&2
		return 2
	}
	IFS='|' read -r _ url sums algo group <<<"${line}"
	cache=${LSS_VM_CACHE:-${HOME}/.cache/lss-vm}
	mkdir -p "${cache}"
	file=${cache}/${url##*/}
	expected=$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "${sums}" | grep -F "${url##*/}" |
		grep -oE '[0-9a-f]{64,128}' | head -n 1)
	[[ -n ${expected} ]] || {
		echo "No checksum for ${url##*/} in ${sums}" >&2
		return 1
	}
	if [[ ! -f ${file} ]] || ! "${algo}sum" --check --quiet <<<"${expected}  ${file}" >/dev/null 2>&1; then
		curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "${file}.part" "${url}" >&2
		"${algo}sum" --check --quiet <<<"${expected}  ${file}.part" >&2 || {
			rm -f -- "${file}.part"
			echo "Checksum mismatch for ${url}" >&2
			return 1
		}
		mv -f -- "${file}.part" "${file}"
	fi
	printf '%s %s\n' "${file}" "${group}"
	return
}

vm_start() {
	local name=$1 image group i
	read -r image group <<<"$(vm_image "${name}")"
	[[ -n ${image} ]] || exit 1
	VM_DIR=$(mktemp -d)
	qemu-img create -q -f qcow2 -b "${image}" -F qcow2 "${VM_DIR}/disk.qcow2" "${VM_DISK}"
	ssh-keygen -q -t ed25519 -N '' -C lss-vm-test -f "${VM_DIR}/key"
	cat >"${VM_DIR}/user-data" <<EOF
#cloud-config
hostname: lss-test
users:
  - name: tester
    groups: [${group}]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys:
      - $(<"${VM_DIR}/key.pub")
EOF
	printf 'instance-id: lss-test\nlocal-hostname: lss-test\n' >"${VM_DIR}/meta-data"
	cloud-localds "${VM_DIR}/seed.iso" "${VM_DIR}/user-data" "${VM_DIR}/meta-data"
	qemu-system-x86_64 -enable-kvm -cpu host -machine q35 -m "${VM_MEMORY}" -smp "${VM_CPUS}" \
		-drive "file=${VM_DIR}/disk.qcow2,if=virtio" -drive "file=${VM_DIR}/seed.iso,if=virtio,format=raw" \
		-nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${VM_PORT}-:22" \
		-device qemu-xhci -device usb-kbd \
		-display none -serial "file:${VM_DIR}/console.log" -daemonize -pidfile "${VM_DIR}/qemu.pid"
	for ((i = 0; i < 60; i++)); do
		vm_ssh true 2>/dev/null && break
		sleep 5
	done
	vm_ssh true || {
		tail -n 60 "${VM_DIR}/console.log" >&2
		exit 1
	}
	vm_ssh 'sudo cloud-init status --wait >/dev/null 2>&1 || true'
	tar --exclude=.git -cf - . | vm_ssh 'sudo rm -rf /opt/lss-src && sudo mkdir -p /opt/lss-src && sudo tar -xf - -C /opt/lss-src'
	return
}

# vm_run SCRIPT: runs SCRIPT as root in the VM; standard input is passed on.
vm_run() {
	local script=$1
	# The RHEL family's sudo path has no /usr/local/sbin, where the harness links lss.
	vm_ssh "sudo --preserve-env=SSH_CONNECTION bash -c $(printf '%q' "PATH=/usr/local/sbin:\${PATH}; ${script}")"
	return
}

vm_stop() {
	[[ -n ${VM_DIR} && -f ${VM_DIR}/qemu.pid ]] || return 0
	kill "$(<"${VM_DIR}/qemu.pid")" 2>/dev/null || true
	return
}
