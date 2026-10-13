# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Firewall abstraction: ufw on Debian and Ubuntu, firewalld on the RHEL family. Rules are recorded per module in
# /var/lib/lss/firewall/<module>, so removing a module closes exactly its ports.
#
# Rule spec: PORT/PROTO[:SCOPE], for example 443/tcp, 51820/udp:public, 3000/tcp:vpn, 5432/tcp:local.
#   public  open to everyone
#   vpn     open to the WireGuard network only (LSS_WIREGUARD_NETWORK, default 10.66.0.0/24)
#   local   no rule; the service listens on localhost only

fw_backend() {
	if os_is_debian; then printf 'ufw'; else printf 'firewalld'; fi
}

fw_vpn_network() {
	config_get LSS_WIREGUARD_NETWORK 10.66.0.0/24
}

fw_is_enabled() {
	if [[ $(fw_backend) == ufw ]]; then
		command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'
	else
		svc_is_active firewalld
	fi
}

_fw_registry() {
	printf '%s/firewall/%s' "${LSS_STATE_DIR:-/var/lib/lss}" "${LSS_MODULE:-core}"
}

_fw_registered() {
	local registry
	registry=$(_fw_registry)
	[[ -f ${registry} ]] && grep -qxF -- "$1" "${registry}"
}

_fw_parse() {
	local spec=$1
	FW_SCOPE=${spec#*:}
	[[ ${spec} == *:* ]] || FW_SCOPE=public
	spec=${spec%%:*}
	FW_PORT=${spec%/*}
	FW_PROTO=${spec#*/}
	[[ ${FW_PORT} =~ ^[0-9]+(-[0-9]+)?$ && ${FW_PROTO} =~ ^(tcp|udp)$ && ${FW_SCOPE} =~ ^(public|vpn|local)$ ]] ||
		die "Invalid firewall rule '$1' (expected PORT/tcp|udp[:public|vpn|local])."
}

_fw_apply() {
	local action=$1 port=${FW_PORT} range
	range=${port/-/:}
	if [[ $(fw_backend) == ufw ]]; then
		local -a rule=()
		if [[ ${FW_SCOPE} == vpn ]]; then
			rule=(from "$(fw_vpn_network)" to any port "${range}" proto "${FW_PROTO}")
		else
			rule=(proto "${FW_PROTO}" from any to any port "${range}")
		fi
		if [[ ${action} == add ]]; then
			ufw allow "${rule[@]}" comment "lss:${LSS_MODULE:-core}" >/dev/null
		else
			ufw delete allow "${rule[@]}" >/dev/null 2>&1 || true
		fi
	else
		local flag=--add
		[[ ${action} == add ]] || flag=--remove
		if [[ ${FW_SCOPE} == vpn ]]; then
			firewall-cmd --permanent "${flag}-rich-rule=rule family=ipv4 source address=$(fw_vpn_network) port port=${port} protocol=${FW_PROTO} accept" >/dev/null 2>&1 || [[ ${flag} == --remove ]]
		else
			firewall-cmd --permanent "${flag}-port=${port}/${FW_PROTO}" >/dev/null 2>&1 || [[ ${flag} == --remove ]]
		fi
		firewall-cmd --reload >/dev/null
	fi
}

# The backend tool is installed (the firewall module installs it).
fw_available() {
	if [[ $(fw_backend) == ufw ]]; then
		command -v ufw >/dev/null 2>&1
	else
		command -v firewall-cmd >/dev/null 2>&1 && svc_is_active firewalld
	fi
}

# Applies the rules every module recorded (used by the firewall module after installing the backend).
fw_apply_all() {
	local registry spec module
	for registry in "${LSS_STATE_DIR:-/var/lib/lss}"/firewall/*; do
		[[ -f ${registry} ]] || continue
		module=${registry##*/}
		while IFS= read -r spec; do
			[[ -n ${spec} ]] || continue
			_fw_parse "${spec}"
			LSS_MODULE=${module} _fw_apply add
		done <"${registry}"
	done
}

# fw_allow SPEC...: opens ports for the current module (no-op for scope local).
fw_allow() {
	local spec registry
	registry=$(_fw_registry)
	for spec in "$@"; do
		_fw_parse "${spec}"
		[[ ${FW_SCOPE} != local ]] || continue
		_fw_registered "${spec}" && continue
		# Without the firewall module the rule is only recorded; the firewall module applies all recorded rules.
		if fw_available; then
			_fw_apply add
		fi
		mkdir -p "$(dirname "${registry}")"
		printf '%s\n' "${spec}" >>"${registry}"
		files_note_change "firewall allow ${spec}"
	done
}

# fw_remove_module: closes every port the current module opened.
fw_remove_module() {
	local registry spec
	registry=$(_fw_registry)
	[[ -f ${registry} ]] || return 0
	if fw_available; then
		while IFS= read -r spec; do
			[[ -n ${spec} ]] || continue
			_fw_parse "${spec}"
			_fw_apply remove
			files_note_change "firewall remove ${spec}"
		done <"${registry}"
	fi
	rm -f -- "${registry}"
}

# Port sshd listens on (first one), from the effective configuration.
fw_ssh_port() {
	local port
	port=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')
	printf '%s' "${port:-22}"
}

# fw_rollback_arm SECONDS: if lss runs over SSH, schedules a firewall shutdown in case this session dies. The
# caller cancels it with fw_rollback_cancel once the SSH rule is confirmed.
fw_rollback_arm() {
	[[ -n ${SSH_CONNECTION:-} ]] || return 0
	local command
	if [[ $(fw_backend) == ufw ]]; then command='ufw --force disable'; else command='systemctl stop firewalld'; fi
	systemctl stop lss-firewall-rollback.timer >/dev/null 2>&1 || true
	systemd-run --quiet --unit=lss-firewall-rollback --on-active="${1:-120}" /bin/sh -c "${command}" >/dev/null
	log_warn "Firewall rollback armed: it switches the firewall off in ${1:-120} s unless lss confirms SSH access."
}

fw_rollback_cancel() {
	systemctl stop lss-firewall-rollback.timer >/dev/null 2>&1 || true
	systemctl reset-failed lss-firewall-rollback.service >/dev/null 2>&1 || true
}
