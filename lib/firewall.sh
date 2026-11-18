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
#
# Published container ports (Docker, Podman, Kubernetes NodePorts and hostPorts) are redirected to the container
# before the INPUT rules of ufw or firewalld see them. The container modules therefore install the container firewall
# (libexec/lss-container-firewall), which lets such a port through only when a module recorded it here; see
# fw_container_ports.

fw_backend() {
	if os_is_debian; then printf 'ufw'; else printf 'firewalld'; fi
	return
}

# Attempts and the pause in seconds for a ufw command that loses a race in iptables.
FW_UFW_TRIES=3
FW_UFW_DELAY=2

# ufw ARG...: ufw, again after a short pause when it fails with "initcaps". Before every change ufw tests the
# capabilities of iptables with a chain of its own; when k3s (or Docker) rewrites its chains at the same moment, that
# test fails ("CHAIN_DEL failed") although nothing is wrong. Other failures and the output pass through unchanged.
# The function hides the command from command -v; "type -P ufw" tells whether ufw is installed.
ufw() {
	local try=1 code err
	err=$(mktemp)
	while :; do
		code=0
		command ufw "$@" 2>"${err}" || code=$?
		if ((code == 0 || try >= FW_UFW_TRIES)) || ! grep -q initcaps "${err}"; then
			break
		fi
		try=$((try + 1))
		sleep "${FW_UFW_DELAY}"
	done
	cat "${err}" >&2
	rm -f -- "${err}"
	return "${code}"
}

fw_vpn_network() {
	config_get LSS_WIREGUARD_NETWORK 10.66.0.0/24
	return
}

# fw_vpn_address: the address of this server in the WireGuard network, the first host of it (10.66.0.1 for
# 10.66.0.0/24). The wireguard module gives it to wg0; admin interfaces with access vpn listen on it.
fw_vpn_address() {
	local network prefix base
	network=$(fw_vpn_network)
	[[ ${network} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]] ||
		die "LSS_WIREGUARD_NETWORK '${network}' must be an IPv4 network such as 10.66.0.0/24."
	prefix=$((10#${BASH_REMATCH[2]}))
	((prefix >= 8 && prefix <= 30)) || die "LSS_WIREGUARD_NETWORK needs a prefix from /8 to /30, got /${prefix}."
	base=$(_fw_ipv4_int "${network%/*}")
	base=$(((base >> (32 - prefix) << (32 - prefix)) + 1))
	printf '%s.%s.%s.%s' $((base >> 24 & 255)) $((base >> 16 & 255)) $((base >> 8 & 255)) $((base & 255))
	return
}

fw_is_enabled() {
	if [[ $(fw_backend) == ufw ]]; then
		type -P ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'
	else
		svc_is_active firewalld
	fi
	return
}

_fw_registry() {
	printf '%s/firewall/%s' "${LSS_STATE_DIR:-/var/lib/lss}" "${LSS_MODULE:-core}"
	return
}

_fw_registered() {
	local rule=$1 registry
	registry=$(_fw_registry)
	[[ -f ${registry} ]] && grep -qxF -- "${rule}" "${registry}"
	return
}

_fw_parse() {
	local rule=$1 spec=$1
	FW_SCOPE=${spec#*:}
	[[ ${spec} == *:* ]] || FW_SCOPE=public
	spec=${spec%%:*}
	FW_PORT=${spec%/*}
	FW_PROTO=${spec#*/}
	[[ ${FW_PORT} =~ ^[0-9]+(-[0-9]+)?$ && ${FW_PROTO} =~ ^(tcp|udp)$ && ${FW_SCOPE} =~ ^(public|vpn|local)$ ]] ||
		die "Invalid firewall rule '${rule}' (expected PORT/tcp|udp[:public|vpn|local])."
	return
}

# firewalld command: the live one while the service runs, the offline one otherwise. Both change the permanent
# configuration, so a rule added or removed while firewalld is stopped is still right when it starts again.
_fw_firewalld() {
	if svc_is_active firewalld; then
		firewall-cmd --permanent "$@"
	else
		firewall-offline-cmd "$@"
	fi
	return
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
	return
}

# The backend tool is installed (the firewall module installs it).
fw_available() {
	if [[ $(fw_backend) == ufw ]]; then
		type -P ufw >/dev/null
	else
		command -v firewall-offline-cmd >/dev/null 2>&1
	fi
	return
}

# Applies the rules every module recorded (used by the firewall module after installing the backend).
fw_apply_all() {
	local registry spec module network interface
	for registry in "${LSS_STATE_DIR:-/var/lib/lss}"/firewall/*; do
		[[ -f ${registry} ]] || continue
		module=${registry##*/}
		while IFS= read -r spec; do
			[[ -n ${spec} ]] || continue
			_fw_parse "${spec}"
			LSS_MODULE=${module} _fw_apply add
		done <"${registry}"
	done
	for registry in "${LSS_STATE_DIR:-/var/lib/lss}"/firewall-trusted/*; do
		[[ -f ${registry} ]] || continue
		module=${registry##*/}
		while read -r network interface; do
			[[ -n ${network} && -n ${interface} ]] || continue
			LSS_MODULE=${module} _fw_trust_apply add "${network}" "${interface}"
		done <"${registry}"
	done
	return
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
	fw_container_sync
	return
}

# fw_remove_module: closes every port the current module opened and drops the networks it trusted.
fw_remove_module() {
	local registry spec
	_fw_trust_remove_module
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
	fw_container_sync
	return
}

_fw_trust_registry() {
	printf '%s/firewall-trusted/%s' "${LSS_STATE_DIR:-/var/lib/lss}" "${LSS_MODULE:-core}"
	return
}

# _fw_ipv4_int ADDRESS: the IPv4 address as a number.
_fw_ipv4_int() {
	local address=$1 a b c d
	IFS=. read -r a b c d <<<"${address}"
	printf '%s' "$(((10#${a} << 24) | (10#${b} << 16) | (10#${c} << 8) | 10#${d}))"
	return
}

# _fw_host_addresses: the IPv4 address this server sends from on its default route (its public or LAN address).
_fw_host_addresses() {
	local route
	route=$(ip -4 -o route get 192.0.2.1 2>/dev/null) || return 0
	sed -n 's/.* src \([0-9.]*\).*/\1/p' <<<"${route}"
	return
}

# _fw_check_network CIDR: an IPv4 network with a prefix of 8 to 32 or an IPv6 network with a prefix of 32 to 128.
# Broader networks (0.0.0.0/0, ::/0) and networks that contain the address of this server's default route are
# refused: trusting them would open the server to the internet or the local network.
_fw_check_network() {
	local network=$1 address prefix octet host base value
	local -a octets=()
	[[ ${network} =~ ^[0-9A-Fa-f.:]+/[0-9]{1,3}$ ]] ||
		die "Invalid network '${network}' (expected an address with a prefix length, such as 10.42.0.0/16)."
	address=${network%/*}
	prefix=$((10#${network##*/}))
	if [[ ${address} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
		IFS=. read -ra octets <<<"${address}"
		for octet in "${octets[@]}"; do
			((10#${octet} <= 255)) || die "Invalid network '${network}': ${octet} is not an address byte."
		done
		((prefix <= 32)) || die "Invalid network '${network}': an IPv4 prefix is at most 32."
		((prefix >= 8)) || die "The network '${network}' is too broad to trust (a prefix of at least /8 is needed)."
		base=$(_fw_ipv4_int "${address}")
		for host in $(_fw_host_addresses); do
			[[ ${host} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || continue
			value=$(_fw_ipv4_int "${host}")
			((value >> (32 - prefix) != base >> (32 - prefix))) ||
				die "The network '${network}' contains ${host}, the address of this server; it cannot be trusted."
		done
	elif [[ ${address} =~ ^[0-9A-Fa-f:]+$ && ${address} == *:*:* ]]; then
		((prefix <= 128)) || die "Invalid network '${network}': an IPv6 prefix is at most 128."
		((prefix >= 32)) || die "The network '${network}' is too broad to trust (a prefix of at least /32 is needed)."
	else
		die "Invalid network '${network}' (expected an address with a prefix length, such as 10.42.0.0/16)."
	fi
	return
}

# _fw_check_interface NAME: a network interface name (at most 15 characters, no wildcards).
_fw_check_interface() {
	local interface=$1
	[[ ${interface} =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die "Invalid network interface '${interface}'."
	return
}

# _fw_trust_apply add|remove NETWORK INTERFACE: accepts traffic that arrives on INTERFACE from NETWORK. ufw matches
# both; firewalld binds INTERFACE to its trusted zone (a zone cannot match both, and the interface is the part a
# neighbour cannot forge). Adding fails loudly; removing a rule that is already gone is fine.
_fw_trust_apply() {
	local action=$1 network=$2 interface=$3 output
	local -a rule=(in on "${interface}" from "${network}")
	if [[ $(fw_backend) == ufw ]]; then
		if [[ ${action} == add ]]; then
			output=$(ufw allow "${rule[@]}" comment "lss:${LSS_MODULE:-core}" 2>&1) ||
				die "Could not trust ${network} on ${interface}: ${output}"
		elif ! output=$(ufw delete allow "${rule[@]}" 2>&1) && [[ ${output} != *non-existent* ]]; then
			die "Could not remove the firewall rule for ${network} on ${interface}: ${output}"
		fi
	else
		if [[ ${action} == add ]]; then
			output=$(_fw_firewalld --zone=trusted "--change-interface=${interface}" 2>&1) || die "firewalld: ${output}"
		elif ! output=$(_fw_firewalld --zone=trusted "--remove-interface=${interface}" 2>&1) &&
			[[ ${output} != *NOT_ENABLED* && ${output} != *UNKNOWN_INTERFACE* ]]; then
			die "firewalld: ${output}"
		fi
		if svc_is_active firewalld; then
			firewall-cmd --reload >/dev/null
		fi
	fi
	return
}

# fw_trust NETWORK INTERFACE: accepts all traffic from NETWORK that arrives on INTERFACE, for networks that belong to
# the server itself, such as the pod network of Kubernetes on its bridge. Recorded per module like ports ("NETWORK
# INTERFACE"): the firewall module applies the record when it comes later, and removing the module drops the rule.
fw_trust() {
	local network=${1:-} interface=${2:-} registry entry
	_fw_check_network "${network}"
	_fw_check_interface "${interface}"
	entry="${network} ${interface}"
	registry=$(_fw_trust_registry)
	if [[ -f ${registry} ]] && grep -qxF -- "${entry}" "${registry}"; then
		return 0
	fi
	if fw_available; then
		_fw_trust_apply add "${network}" "${interface}"
	fi
	mkdir -p "$(dirname "${registry}")"
	printf '%s\n' "${entry}" >>"${registry}"
	files_note_change "firewall trust ${network} on ${interface}"
	return
}

_fw_trust_remove_module() {
	local registry network interface
	registry=$(_fw_trust_registry)
	[[ -f ${registry} ]] || return 0
	if fw_available; then
		while read -r network interface; do
			[[ -n ${network} && -n ${interface} ]] || continue
			_fw_trust_apply remove "${network}" "${interface}"
			files_note_change "firewall distrust ${network} on ${interface}"
		done <"${registry}"
	fi
	rm -f -- "${registry}"
	return
}

# The container firewall: lss-container-firewall.service loads its rules from the list fw_container_list names.
FW_CONTAINER_UNIT=lss-container-firewall

fw_container_list() {
	printf '%s/container-ports' "${LSS_STATE_DIR:-/var/lib/lss}"
	return
}

# fw_container_ports: "PROTO PORT SOURCE" for every public (SOURCE any) and vpn (SOURCE the WireGuard network) rule
# any module recorded, sorted. A published container port is reachable from outside exactly when it is listed here.
fw_container_ports() {
	local registry spec vpn
	vpn=$(fw_vpn_network)
	for registry in "${LSS_STATE_DIR:-/var/lib/lss}"/firewall/*; do
		[[ -f ${registry} ]] || continue
		while IFS= read -r spec; do
			[[ -n ${spec} ]] || continue
			_fw_parse "${spec}"
			case ${FW_SCOPE} in
			public) printf '%s %s any\n' "${FW_PROTO}" "${FW_PORT}" ;;
			vpn) printf '%s %s %s\n' "${FW_PROTO}" "${FW_PORT}" "${vpn}" ;;
			*) ;;
			esac
		done <"${registry}"
	done | sort -u
	return
}

# fw_container_sync: brings the list of the container firewall up to date and reloads the firewall. Does nothing until
# a container module has created the list (ctr_firewall_setup in lib/container.sh).
fw_container_sync() {
	local list ports current
	list=$(fw_container_list)
	[[ -f ${list} ]] || return 0
	ports=$(fw_container_ports)
	current=$(<"${list}")
	[[ ${current} != "${ports}" ]] || return 0
	printf '%s\n' "${ports}" >"${list}"
	files_note_change "container firewall ports"
	if svc_is_active "${FW_CONTAINER_UNIT}.service"; then
		systemctl reload "${FW_CONTAINER_UNIT}.service" || die "Could not reload ${FW_CONTAINER_UNIT}.service."
	fi
	return
}

# Port sshd listens on (first one), from the effective configuration.
fw_ssh_port() {
	local port
	# Without sshd (or with an invalid configuration) the default port is assumed; awk reads all input, so no
	# broken pipe reaches pipefail.
	port=$({ sshd -T 2>/dev/null || true; } | awk '$1 == "port" && !found { print $2; found = 1 }')
	printf '%s' "${port:-22}"
	return
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
	return
}
