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

# firewalld command: the live one while the service runs, the offline one otherwise. Both change the permanent
# configuration, so a rule added or removed while firewalld is stopped is still right when it starts again.
_fw_firewalld() {
	if svc_is_active firewalld; then
		firewall-cmd --permanent "$@"
	else
		firewall-offline-cmd "$@"
	fi
}

# _fw_apply add|remove: changes the rule parsed by _fw_parse. Fails loudly; a rule that could not be removed stays
# in the registry, so lss never forgets an open port.
_fw_apply() {
	local action=$1 port=${FW_PORT} range output
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
		elif ! output=$(ufw delete allow "${rule[@]}" 2>&1) && [[ ${output} != *non-existent* ]]; then
			die "Could not remove firewall rule ${FW_PORT}/${FW_PROTO}: ${output}"
		fi
	else
		local flag=--add rich
		[[ ${action} == add ]] || flag=--remove
		rich="rule family=ipv4 source address=$(fw_vpn_network) port port=${port} protocol=${FW_PROTO} accept"
		if [[ ${FW_SCOPE} == vpn ]]; then
			output=$(_fw_firewalld "${flag}-rich-rule=${rich}" 2>&1) || die "firewalld: ${output}"
		else
			output=$(_fw_firewalld "${flag}-port=${port}/${FW_PROTO}" 2>&1) || die "firewalld: ${output}"
		fi
		if svc_is_active firewalld; then
			firewall-cmd --reload >/dev/null
		fi
	fi
}

# The backend tool is installed (the firewall module installs it).
fw_available() {
	if [[ $(fw_backend) == ufw ]]; then
		command -v ufw >/dev/null 2>&1
	else
		command -v firewall-offline-cmd >/dev/null 2>&1
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
	# Only reached when every rule is gone (or no firewall tool is installed, so no rule can exist).
	rm -f -- "${registry}"
}

# Port sshd listens on (first one), from the effective configuration.
fw_ssh_port() {
	local port
	# Without sshd (or with an invalid configuration) the default port is assumed; awk reads all input, so no
	# broken pipe reaches pipefail.
	port=$({ sshd -T 2>/dev/null || true; } | awk '$1 == "port" && !found { print $2; found = 1 }')
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
