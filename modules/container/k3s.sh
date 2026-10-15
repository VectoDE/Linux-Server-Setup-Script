# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="k3s"
MOD_GROUP="container"
MOD_DESCRIPTION="k3s single-server Kubernetes (pinned, checksum-verified) hardened along the k3s CIS guide: encrypted secrets, Pod Security, audit log, protected kernel defaults"
MOD_REQUIRES="system"
MOD_CONFLICTS="docker"
MOD_OPTIONS="api_access|local|Kubernetes API on 6443/tcp: local (no rule; kubectl through an SSH tunnel), vpn (WireGuard network only) or public
traefik|true|Run the bundled Traefik ingress controller; opens 80/tcp and 443/tcp
pod_security|restricted|Pod Security Standard enforced in every namespace except kube-system: restricted, baseline or privileged"
MOD_PORTS="6443/tcp with api_access vpn or public; 80/tcp and 443/tcp with traefik"

K3S_VERSION=v1.36.5+k3s1
K3S_BIN=/usr/local/bin/k3s
K3S_LINKS="kubectl crictl ctr"
K3S_UNIT=k3s.service
K3S_DIR=/etc/rancher/k3s
K3S_CONFIG=${K3S_DIR}/config.yaml
K3S_PSA=${K3S_DIR}/lss-pod-security.yaml
K3S_AUDIT_POLICY=${K3S_DIR}/lss-audit-policy.yaml
K3S_KUBECONFIG=${K3S_DIR}/k3s.yaml
K3S_DATA=/var/lib/rancher/k3s
K3S_AUDIT_DIR=${K3S_DATA}/server/logs
K3S_SYSCTL=/etc/sysctl.d/70-lss-k3s.conf
K3S_MODULES=/etc/modules-load.d/lss-k3s.conf
# The pod network (the k3s default) and the bridge its pods use on this node. The host accepts what pods send it (DNS,
# the API through the kubernetes service), as the k3s documentation asks, but only when it arrives on that bridge.
K3S_POD_NETWORK=10.42.0.0/16
K3S_POD_BRIDGE=cni0

mod_check() {
	[[ $(opt api_access) =~ ^(local|vpn|public)$ ]] || die "LSS_K3S_API_ACCESS must be local, vpn or public."
	opt_bool traefik || true
	[[ $(opt pod_security) =~ ^(restricted|baseline|privileged)$ ]] ||
		die "LSS_K3S_POD_SECURITY must be restricted, baseline or privileged."
	fetch_entry "k3s-${K3S_VERSION}" >/dev/null || die "k3s: data/checksums.txt has no checksum for k3s ${K3S_VERSION} on ${OS_ARCH}."
	return
}

# The kubelet refuses to start with protect-kernel-defaults unless the kernel has exactly these values (CIS Kubernetes
# 4.2.6); the rest lets pods reach each other and the outside.
_k3s_sysctl() {
	cat <<'EOF'
vm.panic_on_oom = 0
vm.overcommit_memory = 1
kernel.panic = 10
kernel.panic_on_oops = 1
kernel.keys.root_maxkeys = 1000000
kernel.keys.root_maxbytes = 25000000
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
	return
}

# SELinux on the RHEL family: k3s-selinux labels the k3s binary and its data, and containerd labels every pod. Rancher's
# repository has no EL 10 build yet, so both releases come as pinned, checksum-verified packages (data/checksums.txt).
_k3s_selinux_install() {
	local tmp
	os_is_rhel || return 0
	[[ $(getenforce 2>/dev/null || printf 'Disabled') != Disabled ]] || return 0
	pkg_install container-selinux
	pkg_is_installed k3s-selinux && return 0
	tmp=$(mktemp -d)
	fetch_verified "k3s-selinux-el${OS_MAJOR}" "${tmp}/k3s-selinux.noarch.rpm"
	log_command dnf -y -q install "${tmp}/k3s-selinux.noarch.rpm" || die "k3s: dnf cannot install k3s-selinux; see the log."
	rm -rf -- "${tmp}"
	files_note_change "installed k3s-selinux"
	return
}

_k3s_selinux_on() {
	os_is_rhel && pkg_is_installed k3s-selinux && [[ $(getenforce 2>/dev/null || true) =~ ^(Enforcing|Permissive)$ ]]
	return
}

_k3s_binary() {
	local entry tmp link
	entry=$(fetch_entry "k3s-${K3S_VERSION}") || die "k3s: no checksum for k3s ${K3S_VERSION}."
	if [[ ! -f ${K3S_BIN} || $(sha256sum "${K3S_BIN}" | cut -d ' ' -f 1) != "${entry%% *}" ]]; then
		tmp=$(mktemp -d)
		fetch_verified "k3s-${K3S_VERSION}" "${tmp}/k3s"
		install -m 0755 -o root -g root "${tmp}/k3s" "${K3S_BIN}"
		rm -rf -- "${tmp}"
		if command -v restorecon >/dev/null 2>&1; then
			restorecon -F "${K3S_BIN}" 2>/dev/null || true
		fi
		files_note_change "installed k3s ${K3S_VERSION}"
		if svc_is_active "${K3S_UNIT}"; then
			svc_restart "${K3S_UNIT}" || die "k3s: k3s ${K3S_VERSION} does not start; see journalctl -u k3s."
		fi
	fi
	# kubectl, crictl and ctr are k3s itself under another name; a binary of the same name from elsewhere stays.
	for link in ${K3S_LINKS}; do
		if [[ ! -e /usr/local/bin/${link} ]]; then
			ln -s k3s "/usr/local/bin/${link}"
			files_note_change "linked /usr/local/bin/${link}"
		fi
	done
	return
}

mod_install() {
	# containerd loads its AppArmor profile with apparmor_parser on Debian and Ubuntu.
	pkg_install_family "apparmor" ""
	_k3s_selinux_install
	_k3s_binary
	return
}

_k3s_config() {
	local protect=true
	# A container shares the kernel of its host; its values cannot be set from inside.
	if os_in_container; then
		protect=false
	fi
	printf '# Managed by lss (module k3s). Change LSS_K3S_* in /etc/lss/lss.conf and run lss configure k3s.\n'
	printf '# Hardened along the k3s CIS Hardening Guide.\n'
	printf 'write-kubeconfig-mode: "0600"\nsecrets-encryption: true\nprotect-kernel-defaults: %s\n' "${protect}"
	if _k3s_selinux_on; then
		printf 'selinux: true\n'
	fi
	if ! opt_bool traefik; then
		printf 'disable:\n  - traefik\n'
	fi
	cat <<EOF
kube-apiserver-arg:
  - "admission-control-config-file=${K3S_PSA}"
  - "audit-policy-file=${K3S_AUDIT_POLICY}"
  - "audit-log-path=${K3S_AUDIT_DIR}/audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=10"
  - "audit-log-maxsize=100"
kube-controller-manager-arg:
  - "terminated-pod-gc-threshold=10"
kubelet-arg:
  - "streaming-connection-idle-timeout=5m"
EOF
	return
}

_k3s_pod_security() {
	local level
	level=$(opt pod_security)
	cat <<EOF
# Managed by lss (module k3s). Pod Security Standard for every namespace; kube-system runs the k3s components.
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: "${level}"
        enforce-version: "latest"
        audit: "${level}"
        audit-version: "latest"
        warn: "${level}"
        warn-version: "latest"
      exemptions:
        usernames: []
        runtimeClasses: []
        namespaces: [kube-system]
EOF
	return
}

mod_configure() {
	local changed=0
	install -d -m 0755 "${K3S_DIR}"
	install -d -m 0700 "${K3S_AUDIT_DIR}"
	file_write 0600 root:root "${K3S_CONFIG}" < <(_k3s_config)
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0600 root:root "${K3S_PSA}" < <(_k3s_pod_security)
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0600 root:root "${K3S_AUDIT_POLICY}" <<'EOF'
# Managed by lss (module k3s). Who did what in the cluster, without request bodies (secrets stay out of the log).
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:
  - level: Metadata
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	if ! os_in_container; then
		file_write 0644 root:root "${K3S_MODULES}" <<<$'# Managed by lss (module k3s).\nbr_netfilter\noverlay'
		modprobe br_netfilter 2>/dev/null || true
		modprobe overlay 2>/dev/null || true
		file_write 0644 root:root "${K3S_SYSCTL}" < <(
			printf '# Managed by lss (module k3s). Kernel values the kubelet expects (protect-kernel-defaults).\n'
			_k3s_sysctl
		)
		sysctl -q -e -p "${K3S_SYSCTL}" >/dev/null
	fi
	svc_unit "${K3S_UNIT}" <<EOF
# Managed by lss (module k3s). Settings: ${K3S_CONFIG}.
[Unit]
Description=Lightweight Kubernetes (k3s ${K3S_VERSION}, lss)
Documentation=https://docs.k3s.io
Wants=network-online.target
After=network-online.target ${FW_CONTAINER_UNIT}.service

[Service]
Type=notify
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=0
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStartPre=-/sbin/modprobe br_netfilter
ExecStartPre=-/sbin/modprobe overlay
ExecStart=${K3S_BIN} server

[Install]
WantedBy=multi-user.target
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	ctr_firewall_setup
	fw_trust "${K3S_POD_NETWORK}" "${K3S_POD_BRIDGE}"
	fw_allow "6443/tcp:$(opt api_access)"
	if opt_bool traefik; then
		fw_allow 80/tcp 443/tcp
	fi
	svc_enable "${K3S_UNIT}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${K3S_UNIT}" || die "k3s: the server does not start; see journalctl -u k3s."
	fi
	return
}

# _k3s_wait SECONDS COMMAND...: retries COMMAND every 2 seconds until it prints "ok" or True.
_k3s_wait() {
	local seconds=$1 i output
	shift
	for ((i = 0; i < seconds; i += 2)); do
		output=$("$@" 2>/dev/null || true)
		if [[ ${output} == ok || ${output} == True ]]; then
			return 0
		fi
		sleep 2
	done
	return 1
}

mod_verify() {
	local key value actual status i
	svc_is_active "${K3S_UNIT}" || die "k3s: the server is not running; see journalctl -u k3s."
	_k3s_wait 180 "${K3S_BIN}" kubectl get --raw=/readyz || die "k3s: the Kubernetes API is not ready."
	_k3s_wait 180 "${K3S_BIN}" kubectl get nodes -o 'jsonpath={.items[0].status.conditions[?(@.type=="Ready")].status}' ||
		die "k3s: the node does not become Ready; see k3s kubectl describe nodes."
	[[ $(stat -c '%a %U' "${K3S_KUBECONFIG}") == '600 root' ]] || die "k3s: ${K3S_KUBECONFIG} must be mode 600 and owned by root."
	# The status comes from the server's encryption controller, which can report later than the API on a busy host.
	for ((i = 0; i < 60; i += 2)); do
		status=$("${K3S_BIN}" secrets-encrypt status 2>&1 || true)
		[[ ${status} != *'Encryption Status: Enabled'* ]] || break
		sleep 2
	done
	if [[ ${status} != *'Encryption Status: Enabled'* ]]; then
		# The status names the keys and whether their hashes match, never the key material.
		printf 'k3s: secrets-encrypt status: %s\n' "${status//$'\n'/$'\n'k3s: secrets-encrypt status: }" >&2
		die "k3s: secrets are not encrypted at rest."
	fi
	if ! os_in_container; then
		while IFS='=' read -r key value; do
			key=${key// /}
			value=${value# }
			[[ -n ${key} ]] || continue
			actual=$(sysctl -n "${key}" 2>/dev/null) || continue
			[[ ${actual} == "${value}" ]] || die "k3s: ${key} is ${actual}, the kubelet expects ${value}."
		done < <(_k3s_sysctl)
	fi
	ctr_firewall_verify
	return
}

# What the uninstall script of k3s does (k3s-killall.sh): k3s leaves its pods running when it stops (KillMode=process),
# so the container shims, the mounts and network interfaces of the pods and the iptables rules of kube-proxy, flannel
# and the network policy controller go separately.
_k3s_stop() {
	local tool rules target link
	svc_disable "${K3S_UNIT}"
	pkill -9 -f "${K3S_DATA}/data/[^/]+/bin/containerd-shim" 2>/dev/null || true
	awk '$2 ~ "^(/run/k3s|/var/lib/kubelet/pods|/var/lib/kubelet/plugins|/run/netns/cni-)" { print $2 }' /proc/self/mounts |
		sort -r | while IFS= read -r target; do
		umount -l "${target}" 2>/dev/null || true
	done
	for link in cni0 flannel.1 flannel-v6.1 flannel-wg flannel-wg-v6 kube-ipvs0; do
		ip link delete "${link}" 2>/dev/null || true
	done
	for tool in iptables ip6tables; do
		command -v "${tool}-save" >/dev/null 2>&1 || continue
		rules=$("${tool}-save" 2>/dev/null) || continue
		grep -Eiv 'KUBE-|CNI-|flannel' <<<"${rules}" | "${tool}-restore" 2>/dev/null || true
	done
	return
}

mod_remove() {
	local link
	_k3s_stop
	file_remove "/etc/systemd/system/${K3S_UNIT}"
	svc_daemon_reload
	file_remove "${K3S_CONFIG}"
	file_remove "${K3S_PSA}"
	file_remove "${K3S_AUDIT_POLICY}"
	file_remove "${K3S_MODULES}"
	file_remove "${K3S_SYSCTL}"
	sysctl -q --system >/dev/null 2>&1 || true
	for link in ${K3S_LINKS}; do
		if [[ -L /usr/local/bin/${link} && $(readlink "/usr/local/bin/${link}") == k3s ]]; then
			rm -f -- "/usr/local/bin/${link}"
		fi
	done
	if [[ -f ${K3S_BIN} ]]; then
		rm -f -- "${K3S_BIN}"
		files_note_change "removed ${K3S_BIN}"
	fi
	ctr_firewall_remove
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	local dir
	for dir in "${K3S_DATA}" /var/lib/kubelet /etc/rancher /var/lib/cni/networks/cbr0 /run/k3s; do
		[[ ! -L ${dir} ]] || die "k3s: refusing to delete ${dir}: it is a symbolic link."
		if [[ -e ${dir} ]]; then
			rm -rf -- "${dir}"
			files_note_change "deleted ${dir}"
		fi
	done
	if os_is_rhel; then
		pkg_remove k3s-selinux
	fi
	return
}
