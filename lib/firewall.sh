# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Firewall abstraction (fw_backend): ufw on Debian and Ubuntu, firewalld on the RHEL and SUSE families, nftables
# elsewhere, iptables where nft is missing; LSS_FIREWALL chooses one of them. Rules are recorded per module in
# /var/lib/lss/firewall/<module>, so removing a module closes exactly its ports. ufw and firewalld get each rule as it
# comes. nftables and iptables get lss's whole rule set from the records every time (fw_sync): a table "inet lss" of
# its own, or a chain LSS-INPUT that INPUT jumps to; both drop what no rule accepts.
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
	local backend
	backend=$(config_get LSS_FIREWALL '')
	case ${backend} in
	ufw | firewalld | nftables | iptables)
		printf '%s' "${backend}"
		return 0
		;;
	'') ;;
	*) die "LSS_FIREWALL '${backend}' is none of ufw, firewalld, nftables and iptables." ;;
	esac
	case ${OS_FAMILY} in
	debian) printf 'ufw' ;;
	rhel | suse) printf 'firewalld' ;;
	*)
		if ! type -P nft >/dev/null && type -P iptables-restore >/dev/null; then
			printf 'iptables'
		else
			printf 'nftables'
		fi
		;;
	esac
	return
}

# fw_declarative: the backend takes lss's whole rule set at once (nftables, iptables).
fw_declarative() {
	[[ $(fw_backend) == nftables || $(fw_backend) == iptables ]]
	return
}

# Where the rule sets of nftables and iptables live. The nftables service loads its configuration at boot
# (/etc/nftables.conf, on Alpine /etc/nftables.nft, or FW_NFT_CONF); fw_enable adds an include of FW_NFT_FILE to it
# unless it already includes the directory. The iptables files are loaded at boot by lss-firewall.service or, without systemd,
# by the OpenRC local service (FW_LOCAL_D).
FW_NFT_FILE=${FW_NFT_FILE:-/etc/nftables.d/lss.nft}
FW_NFT_CONF=${FW_NFT_CONF:-}
FW_IPT_DIR=${FW_IPT_DIR:-/etc/lss/firewall}
FW_LOCAL_D=${FW_LOCAL_D:-/etc/local.d}

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
	case $(fw_backend) in
	ufw) type -P ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active' ;;
	firewalld) svc_is_active firewalld ;;
	nftables) type -P nft >/dev/null && nft list table inet lss >/dev/null 2>&1 ;;
	*) type -P iptables >/dev/null && iptables -C INPUT -j LSS-INPUT >/dev/null 2>&1 ;;
	esac
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
	# nftables and iptables take the whole rule set from the records (fw_sync).
	! fw_declarative || return 0
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
	case $(fw_backend) in
	ufw) type -P ufw >/dev/null ;;
	firewalld) command -v firewall-offline-cmd >/dev/null 2>&1 ;;
	nftables) type -P nft >/dev/null ;;
	*) type -P iptables-restore >/dev/null && type -P ip6tables-restore >/dev/null ;;
	esac
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
	fw_sync
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
	fw_sync
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
	fw_sync
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
	! fw_declarative || return 0
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
	fw_sync
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
	fw_sync
	return
}

# _fw_records: every recorded rule as "port PROTO PORT SCOPE" and every trusted network as "trust NETWORK INTERFACE",
# sorted, so the same records always give the same rule set.
_fw_records() {
	local registry spec network interface
	for registry in "${LSS_STATE_DIR:-/var/lib/lss}"/firewall/*; do
		[[ -f ${registry} ]] || continue
		while IFS= read -r spec; do
			[[ -n ${spec} ]] || continue
			_fw_parse "${spec}"
			[[ ${FW_SCOPE} == local ]] || printf 'port %s %s %s\n' "${FW_PROTO}" "${FW_PORT}" "${FW_SCOPE}"
		done <"${registry}"
	done
	for registry in "${LSS_STATE_DIR:-/var/lib/lss}"/firewall-trusted/*; do
		[[ -f ${registry} ]] || continue
		while read -r network interface; do
			[[ -n ${network} && -n ${interface} ]] || continue
			printf 'trust %s %s\n' "${network}" "${interface}"
		done <"${registry}"
	done
	return
}

# fw_nft_ruleset: lss's table for nftables. Loading it replaces the table in one transaction (the empty "table" line
# lets "delete" succeed when the table does not exist yet), so there is never a moment without rules.
fw_nft_ruleset() {
	local kind a b c vpn family
	vpn=$(fw_vpn_network)
	printf '%s\n' '# Managed by lss: the rules of the modules (lss firewall records), replaced as a whole.' \
		'table inet lss' 'delete table inet lss' 'table inet lss {' '	chain input {' \
		'		type filter hook input priority filter; policy drop;' '		ct state established,related accept' \
		'		ct state invalid drop' '		iifname "lo" accept' '		meta l4proto { icmp, ipv6-icmp } accept'
	while read -r kind a b c; do
		case ${kind} in
		port)
			if [[ ${c} == vpn ]]; then
				printf '\t\tip saddr %s %s dport %s accept\n' "${vpn}" "${a}" "${b}"
			else
				printf '\t\t%s dport %s accept\n' "${a}" "${b}"
			fi
			;;
		*)
			family=ip
			[[ ${a} != *:* ]] || family=ip6
			printf '\t\tiifname "%s" %s saddr %s accept\n' "${b}" "${family}" "${a}"
			;;
		esac
	done < <(_fw_records | sort -u)
	printf '%s\n' '	}' '}'
	return
}

# fw_ipt_ruleset 4|6: lss's chain for iptables-restore --noflush (IPv4) or ip6tables-restore --noflush (IPv6). The
# WireGuard network is IPv4, so its rules exist only in the IPv4 set; trusted networks go to the set of their family.
fw_ipt_ruleset() {
	local version=$1 kind a b c vpn icmp=icmp
	vpn=$(fw_vpn_network)
	[[ ${version} == 4 ]] || icmp=ipv6-icmp
	printf '%s\n' '# Managed by lss: the rules of the modules (lss firewall records), replaced as a whole.' '*filter' \
		':LSS-INPUT - [0:0]' '-F LSS-INPUT' '-A LSS-INPUT -i lo -j ACCEPT' \
		'-A LSS-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' \
		'-A LSS-INPUT -m conntrack --ctstate INVALID -j DROP' "-A LSS-INPUT -p ${icmp} -j ACCEPT"
	while read -r kind a b c; do
		case ${kind} in
		port)
			if [[ ${c} == vpn ]]; then
				[[ ${version} == 4 ]] || continue
				printf -- '-A LSS-INPUT -s %s -p %s -m %s --dport %s -j ACCEPT\n' "${vpn}" "${a}" "${a}" "${b/-/:}"
			else
				printf -- '-A LSS-INPUT -p %s -m %s --dport %s -j ACCEPT\n' "${a}" "${a}" "${b/-/:}"
			fi
			;;
		*)
			if [[ ${a} == *:* ]]; then
				[[ ${version} == 6 ]] || continue
			else
				[[ ${version} == 4 ]] || continue
			fi
			printf -- '-A LSS-INPUT -i %s -s %s -j ACCEPT\n' "${b}" "${a}"
			;;
		esac
	done < <(_fw_records | sort -u)
	printf '%s\n' '-A LSS-INPUT -j DROP' 'COMMIT'
	return
}

# _fw_ipt_hook iptables|ip6tables: INPUT jumps to LSS-INPUT first.
_fw_ipt_hook() {
	"$1" -C INPUT -j LSS-INPUT >/dev/null 2>&1 || "$1" -I INPUT 1 -j LSS-INPUT
	return
}

# fw_sync: writes the rule set of nftables or iptables from the records and loads it while the firewall is on. ufw and
# firewalld take their rules one by one, so for them it does nothing.
fw_sync() {
	local backend
	backend=$(fw_backend)
	if ! fw_declarative || ! fw_available; then
		return 0
	fi
	if [[ ${backend} == nftables ]]; then
		file_write 0600 root:root "${FW_NFT_FILE}" < <(fw_nft_ruleset)
		if [[ ${LSS_FILE_CHANGED} == 1 ]] && fw_is_enabled; then
			nft -f "${FW_NFT_FILE}" || die "nftables does not take the rules in ${FW_NFT_FILE}."
		fi
		return 0
	fi
	file_write 0600 root:root "${FW_IPT_DIR}/rules.v4" < <(fw_ipt_ruleset 4)
	local changed=${LSS_FILE_CHANGED}
	file_write 0600 root:root "${FW_IPT_DIR}/rules.v6" < <(fw_ipt_ruleset 6)
	[[ ${changed} == 1 || ${LSS_FILE_CHANGED} == 1 ]] || return 0
	if fw_is_enabled; then
		iptables-restore --noflush "${FW_IPT_DIR}/rules.v4" || die "iptables does not take the rules in ${FW_IPT_DIR}/rules.v4."
		ip6tables-restore --noflush "${FW_IPT_DIR}/rules.v6" ||
			die "ip6tables does not take the rules in ${FW_IPT_DIR}/rules.v6."
	fi
	return
}

# fw_enable: switches nftables or iptables on with the recorded rules and keeps them across reboots: nftables through
# an include in FW_NFT_CONF and its service, iptables through lss-firewall.service (systemd) or the OpenRC local
# service. SysV and Upstart have no such hook; lss warns that the rules are gone after a reboot there.
fw_enable() {
	local backend
	backend=$(fw_backend)
	fw_declarative || die "fw_enable is for nftables and iptables; ${backend} is switched on by the firewall module."
	_fw_no_other_firewall
	fw_sync
	if [[ ${backend} == nftables ]]; then
		nft -f "${FW_NFT_FILE}" || die "nftables does not take the rules in ${FW_NFT_FILE}."
		local conf=${FW_NFT_CONF:-/etc/nftables.conf} mode owner
		[[ -n ${FW_NFT_CONF} || ${OS_FAMILY} != alpine ]] || conf=/etc/nftables.nft
		if [[ ! -f ${conf} ]] || ! grep -qF -e "include \"${FW_NFT_FILE}\"" -e "include \"${FW_NFT_FILE%/*}/*.nft\"" "${conf}"; then
			# The file keeps its mode (Debian's is an executable nft script) and its owner.
			mode=$(stat -c '%a' "${conf}" 2>/dev/null) || mode=644
			owner=$(stat -c '%U:%G' "${conf}" 2>/dev/null) || owner=root:root
			file_ensure_lines "0${mode}" "${owner}" "${conf}" <<<"include \"${FW_NFT_FILE}\""
		fi
		svc_enable nftables
		return
	fi
	iptables-restore --noflush "${FW_IPT_DIR}/rules.v4" || die "iptables does not take the rules in ${FW_IPT_DIR}/rules.v4."
	ip6tables-restore --noflush "${FW_IPT_DIR}/rules.v6" || die "ip6tables does not take the rules in ${FW_IPT_DIR}/rules.v6."
	_fw_ipt_hook iptables
	_fw_ipt_hook ip6tables
	local load
	load="iptables-restore --noflush ${FW_IPT_DIR}/rules.v4 && ip6tables-restore --noflush ${FW_IPT_DIR}/rules.v6"
	load+=" && { iptables -C INPUT -j LSS-INPUT || iptables -I INPUT 1 -j LSS-INPUT; }"
	load+=" && { ip6tables -C INPUT -j LSS-INPUT || ip6tables -I INPUT 1 -j LSS-INPUT; }"
	case $(svc_init) in
	systemd)
		svc_unit lss-firewall.service <<EOF
# Managed by lss (module ${LSS_MODULE:-firewall}). Loads lss's iptables rules at boot.
[Unit]
Description=lss firewall rules (iptables)
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '${load}'

[Install]
WantedBy=multi-user.target
EOF
		svc_enable lss-firewall.service
		;;
	openrc)
		file_write 0755 root:root "${FW_LOCAL_D}/lss-firewall.start" <<EOF
#!/bin/sh
# Managed by lss (module ${LSS_MODULE:-firewall}). Loads lss's iptables rules at boot.
${load}
EOF
		svc_enable local
		;;
	*) log_warn "firewall: $(svc_init) has no boot hook lss knows; the iptables rules are gone after a reboot." ;;
	esac
	return
}

# _fw_no_other_firewall: refuses to add lss's own rules next to an active ufw, firewalld or Proxmox VE firewall; two
# firewalls that each drop what they do not know would block each other's ports.
_fw_no_other_firewall() {
	local unit
	if type -P ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
		die "firewall: ufw is active; switch it off or set LSS_FIREWALL=ufw instead of $(fw_backend)."
	fi
	for unit in firewalld pve-firewall; do
		if svc_exists "${unit}" && svc_is_active "${unit}"; then
			die "firewall: ${unit} is active; switch it off or use it instead of $(fw_backend)."
		fi
	done
	return
}

# fw_disable: takes lss's rules out of nftables or iptables and off the boot path; the records stay.
fw_disable() {
	case $(fw_backend) in
	nftables)
		if type -P nft >/dev/null && nft list table inet lss >/dev/null 2>&1; then
			nft delete table inet lss
		fi
		;;
	iptables)
		local tool
		for tool in iptables ip6tables; do
			type -P "${tool}" >/dev/null || continue
			while "${tool}" -C INPUT -j LSS-INPUT >/dev/null 2>&1; do
				"${tool}" -D INPUT -j LSS-INPUT
			done
		done
		svc_disable lss-firewall.service
		file_remove /etc/systemd/system/lss-firewall.service
		file_remove "${FW_LOCAL_D}/lss-firewall.start"
		;;
	*) die "fw_disable is for nftables and iptables." ;;
	esac
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
	case $(fw_backend) in
	ufw) command='ufw --force disable' ;;
	firewalld) command='systemctl stop firewalld' ;;
	nftables) command='nft delete table inet lss' ;;
	*) command='while iptables -D INPUT -j LSS-INPUT; do :; done; while ip6tables -D INPUT -j LSS-INPUT; do :; done' ;;
	esac
	systemctl stop lss-firewall-rollback.timer >/dev/null 2>&1 || true
	systemd-run --quiet --unit=lss-firewall-rollback --on-active="${1:-120}" /bin/sh -c "${command}" >/dev/null
	log_warn "Firewall rollback armed: it switches the firewall off in ${1:-120} s unless lss confirms SSH access."
}

fw_rollback_cancel() {
	systemctl stop lss-firewall-rollback.timer >/dev/null 2>&1 || true
	systemctl reset-failed lss-firewall-rollback.service >/dev/null 2>&1 || true
	return
}
