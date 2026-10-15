# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="wireguard"
MOD_GROUP="network"
MOD_DESCRIPTION="WireGuard VPN server on wg0 with the peers from the settings and its keys in the lss secrets; admin interfaces with access vpn listen on it"
MOD_REQUIRES="system"
MOD_OPTIONS="network|10.66.0.0/24|VPN network (IPv4, /8 to /30); the server takes its first address, the peers others; the vpn scope of the firewall is this network
port|51820|UDP port WireGuard listens on, open to everyone
peers||Peers as NAME:PUBLIC_KEY:ADDRESS, separated by spaces (laptop:<the peer's public key>:10.66.0.2); each also gets a preshared key (lss secrets show wireguard-psk-NAME)
endpoint||Host name or address the peers connect to, for the peer settings lss prints; empty: the address of the default route"
MOD_PORTS="51820/udp from everyone"
MOD_SECRETS="wireguard-private-key wireguard-psk-<peer>"

# Peers reach the server itself (its admin interfaces, SSH, the DNS resolver), not the networks behind it: lss does not
# turn on IP forwarding, which kernel-hardening keeps off.
WG_INTERFACE=wg0
WG_CONF=/etc/wireguard/${WG_INTERFACE}.conf
WG_UNIT=wg-quick@${WG_INTERFACE}
WG_KEY_SECRET=wireguard-private-key
# The public key is no secret; peers need it.
WG_PUBLIC_KEY=/etc/lss/wireguard-public-key

_wg_server_address() {
	fw_vpn_address
	return
}

_wg_prefix() {
	local network
	network=$(opt network)
	printf '%s' "${network##*/}"
	return
}

# _wg_in_network ADDRESS: ADDRESS lies in the VPN network.
_wg_in_network() {
	local address=$1 network prefix
	network=$(opt network)
	prefix=$((10#${network##*/}))
	(($(_fw_ipv4_int "${address}") >> (32 - prefix) == $(_fw_ipv4_int "${network%/*}") >> (32 - prefix)))
	return
}

mod_check() {
	local port peer name key address server endpoint
	local -A names=() keys=() addresses=()
	server=$(_wg_server_address)
	port=$(opt_int port)
	((port >= 1 && port <= 65535)) || die "LSS_WIREGUARD_PORT must be between 1 and 65535."
	for peer in $(opt peers); do
		IFS=: read -r name key address <<<"${peer}"
		address=${address%/32}
		[[ ${name} =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] ||
			die "LSS_WIREGUARD_PEERS: '${name}' is not a peer name (a-z, 0-9 and -, up to 32 characters)."
		# A Curve25519 key in base64: 43 characters and "=", the last one from the set a 256-bit value allows.
		[[ ${key} =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] ||
			die "LSS_WIREGUARD_PEERS: the key of '${name}' is not a WireGuard public key."
		if [[ ! ${address} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || ! _wg_in_network "${address}"; then
			die "LSS_WIREGUARD_PEERS: the address of '${name}' must be an IPv4 address in $(opt network)."
		fi
		[[ ${address} != "${server}" ]] || die "LSS_WIREGUARD_PEERS: ${address} is the address of the server."
		[[ -z ${names[${name}]+x} && -z ${keys[${key}]+x} && -z ${addresses[${address}]+x} ]] ||
			die "LSS_WIREGUARD_PEERS: every peer needs its own name, key and address ('${name}')."
		names[${name}]=1
		keys[${key}]=1
		addresses[${address}]=1
	done
	endpoint=$(opt endpoint)
	[[ -z ${endpoint} || ${endpoint} =~ ^[A-Za-z0-9.:-]+$ ]] || die "LSS_WIREGUARD_ENDPOINT '${endpoint}' is not a host name."
	return
}

mod_install() {
	pkg_install wireguard-tools
	return
}

# _wg_keys: the private key of the server and a preshared key per peer, made once by wg itself and kept in the lss
# secrets.
_wg_keys() {
	local peer name _key _address value
	if ! secret_exists "${WG_KEY_SECRET}"; then
		value=$(wg genkey)
		secret_set "${WG_KEY_SECRET}" "${value}"
		log_info "Generated secret ${WG_KEY_SECRET}"
		files_note_change "generated the WireGuard key"
	fi
	for peer in $(opt peers); do
		IFS=: read -r name _key _address <<<"${peer}"
		secret_exists "wireguard-psk-${name}" && continue
		value=$(wg genpsk)
		secret_set "wireguard-psk-${name}" "${value}"
		log_info "Generated secret wireguard-psk-${name} (lss secrets show wireguard-psk-${name})"
		files_note_change "generated the preshared key of ${name}"
	done
	return
}

# _wg_config: wg-quick configuration without keys; PostUp hands the private and preshared keys to the interface from
# the secrets, so they exist in one place only.
_wg_config() {
	local peer name key address
	printf '# Managed by lss (module wireguard). Change LSS_WIREGUARD_* in /etc/lss/lss.conf and run lss configure wireguard.\n'
	printf '[Interface]\nAddress = %s/%s\nListenPort = %s\n' "$(_wg_server_address)" "$(_wg_prefix)" "$(opt_int port)"
	printf 'PostUp = wg set %%i private-key %s\n' "$(secret_path "${WG_KEY_SECRET}")"
	for peer in $(opt peers); do
		IFS=: read -r name key address <<<"${peer}"
		printf 'PostUp = wg set %%i peer %s preshared-key %s\n' "${key}" "$(secret_path "wireguard-psk-${name}")"
	done
	for peer in $(opt peers); do
		IFS=: read -r name key address <<<"${peer}"
		printf '\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n' "${name}" "${key}" "${address%/32}"
	done
	return
}

# The settings a peer needs, printed after a change (no secret: the preshared key is named, not shown).
_wg_hints() {
	local peer name _key address endpoint public
	endpoint=$(opt endpoint)
	if [[ -z ${endpoint} ]]; then
		endpoint=$(_fw_host_addresses)
		endpoint=${endpoint%%$'\n'*}
	fi
	public=$(<"${WG_PUBLIC_KEY}")
	for peer in $(opt peers); do
		IFS=: read -r name _key address <<<"${peer}"
		log_info "wireguard: peer ${name}: Address = ${address%/32}/32; [Peer] PublicKey = ${public}, Endpoint = ${endpoint:-SERVER}:$(opt_int port), AllowedIPs = $(_wg_server_address)/32, PresharedKey from lss secrets show wireguard-psk-${name}"
	done
	return
}

mod_configure() {
	local before public config
	before=$(files_changes_of wireguard)
	_wg_keys
	public=$(wg pubkey <"$(secret_path "${WG_KEY_SECRET}")")
	file_write 0644 root:root "${WG_PUBLIC_KEY}" <<<"${public}"
	install -d -m 0700 /etc/wireguard
	config=$(_wg_config)
	file_write 0600 root:root "${WG_CONF}" <<<"${config}"
	# wg-quick is a root script that runs ip and wg; under SELinux these switch to their own domains (ifconfig_t),
	# which NoNewPrivileges forbids, so the interface would never come up on the RHEL family. wg reads its settings
	# from a pipe through /dev/fd, which SELinux denies wg in the private /dev of PrivateDevices.
	svc_sandbox "${WG_UNIT}.service" NoNewPrivileges=no PrivateDevices=no
	fw_allow "$(opt_int port)/udp"
	svc_enable "${WG_UNIT}"
	if [[ $(files_changes_of wireguard) != "${before}" ]]; then
		svc_restart "${WG_UNIT}" || die "wireguard: ${WG_INTERFACE} does not come up with the new configuration."
		_wg_hints
	fi
	return
}

mod_verify() {
	local peer _name key _address expected actual without
	svc_is_active "${WG_UNIT}" || die "wireguard: ${WG_UNIT} is not running."
	[[ $(wg show "${WG_INTERFACE}" listen-port) == "$(opt_int port)" ]] ||
		die "wireguard: ${WG_INTERFACE} does not listen on port $(opt_int port)."
	[[ $(wg show "${WG_INTERFACE}" public-key) == "$(<"${WG_PUBLIC_KEY}")" ]] ||
		die "wireguard: ${WG_INTERFACE} does not use the key in the lss secrets."
	ip -4 -o addr show dev "${WG_INTERFACE}" | grep -qF " $(_wg_server_address)/$(_wg_prefix) " ||
		die "wireguard: ${WG_INTERFACE} does not have the address $(_wg_server_address)/$(_wg_prefix)."
	expected=''
	for peer in $(opt peers); do
		IFS=: read -r _name key _address <<<"${peer}"
		expected+="${key}"$'\n'
	done
	expected=$(sort <<<"${expected%$'\n'}")
	actual=$(wg show "${WG_INTERFACE}" peers | sort)
	[[ ${actual} == "${expected}" ]] || die "wireguard: the peers of ${WG_INTERFACE} differ from LSS_WIREGUARD_PEERS."
	# Only the peers without one are printed; the preshared keys themselves never leave wg.
	without=$(wg show "${WG_INTERFACE}" preshared-keys | awk '$2 == "(none)" { print $1 }')
	[[ -z ${without} ]] || die "wireguard: peers without a preshared key: ${without//$'\n'/ }."
	return
}

mod_remove() {
	local secret
	if svc_is_enabled "${WG_UNIT}" || svc_is_active "${WG_UNIT}"; then
		systemctl disable --now "${WG_UNIT}" >/dev/null 2>&1 || die "wireguard: ${WG_UNIT} does not stop."
		files_note_change "disabled ${WG_UNIT}"
	fi
	svc_dropin_remove "${WG_UNIT}.service" lss-sandbox
	file_remove "${WG_CONF}"
	file_remove "${WG_PUBLIC_KEY}"
	pkg_remove wireguard-tools
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	for secret in "${LSS_SECRETS_DIR}"/wireguard-*; do
		[[ -f ${secret} ]] || continue
		secret_remove "${secret##*/}"
	done
	return
}
