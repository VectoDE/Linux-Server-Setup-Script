# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="dns-resolver"
MOD_GROUP="network"
MOD_DESCRIPTION="Unbound as a validating (DNSSEC) caching resolver on 127.0.0.1, optionally for the WireGuard network; the server itself resolves through it"
MOD_REQUIRES="system"
MOD_OPTIONS="access|local|Who may ask: local (this server only) or vpn (also the WireGuard network, on the server's WireGuard address)
forward||Resolvers to forward every query to instead of asking the root servers, separated by spaces (1.1.1.1, or 1.1.1.1@853#cloudflare-dns.com with forward_tls); empty: Unbound resolves from the root servers itself
forward_tls|false|Forward over DNS over TLS; every forward entry then needs @853#NAME, the name its certificate must carry
system|true|Make this server resolve through Unbound (systemd-resolved, NetworkManager or /etc/resolv.conf); inside a container the engine owns /etc/resolv.conf, so it stays as it is"
MOD_PORTS="53/udp and 53/tcp from the WireGuard network with access vpn; none with access local"

DNS_CONF=/etc/unbound/unbound.conf
DNS_ANCHOR=/var/lib/unbound/root.key
DNS_RESOLV=/etc/resolv.conf
# The resolv.conf found before lss changed it, put back when the module is removed.
DNS_SAVED_DIR=${LSS_STATE_DIR:-/var/lib/lss}/dns-resolver
DNS_SAVED=${DNS_SAVED_DIR}/resolv.conf
DNS_RESOLVED_DROPIN=/etc/systemd/resolved.conf.d/lss-dns-resolver.conf
DNS_NM_CONF=/etc/NetworkManager/conf.d/lss-dns-resolver.conf
# dhclient rewrites /etc/resolv.conf on every lease renewal unless a hook replaces its make_resolv_conf.
DNS_DHCLIENT_HOOK=/etc/dhcp/dhclient-enter-hooks.d/lss-dns-resolver
DNS_UNIT=unbound
DNS_LOOPBACK=127.0.0.1

mod_check() {
	local entry
	[[ $(opt access) =~ ^(local|vpn)$ ]] || die "LSS_DNS_RESOLVER_ACCESS must be local or vpn."
	opt_bool system || true
	for entry in $(opt forward); do
		[[ ${entry} =~ ^[0-9A-Fa-f.:]+(@[0-9]{1,5})?(#[A-Za-z0-9.-]+)?$ ]] ||
			die "LSS_DNS_RESOLVER_FORWARD: '${entry}' is not ADDRESS, ADDRESS@PORT or ADDRESS@PORT#NAME."
		if opt_bool forward_tls && [[ ${entry} != *'#'* ]]; then
			die "LSS_DNS_RESOLVER_FORWARD: '${entry}' needs #NAME (the name in its certificate) with forward_tls."
		fi
	done
	if opt_bool forward_tls && [[ -z $(opt forward) ]]; then
		die "LSS_DNS_RESOLVER_FORWARD_TLS=true needs resolvers in LSS_DNS_RESOLVER_FORWARD."
	fi
	return
}

mod_install() {
	# unbound-anchor creates and refreshes the DNSSEC trust anchor of the root zone; Debian ships it separately.
	pkg_install_family "unbound unbound-anchor dns-root-data" unbound
	return
}

# IPv6 is used where the server has a default route for it; otherwise Unbound would try IPv6 root servers in vain.
_dns_ipv6() {
	[[ -n $(ip -6 route show default 2>/dev/null) ]] && grep -q '^0\{31\}1 ' /proc/net/if_inet6 2>/dev/null
	return
}

# The control socket: in /run on Debian and Ubuntu, in Unbound's own directory under SELinux on the RHEL family.
_dns_control() {
	if os_is_debian; then printf '/run/unbound.ctl'; else printf '/run/unbound/unbound.ctl'; fi
	return
}

_dns_ca_bundle() {
	if os_is_debian; then printf '/etc/ssl/certs/ca-certificates.crt'; else printf '/etc/pki/tls/certs/ca-bundle.crt'; fi
	return
}

_dns_config() {
	local ip6=no entry network
	_dns_ipv6 && ip6=yes
	network=$(fw_vpn_network)
	printf '# Managed by lss (module dns-resolver). Change LSS_DNS_RESOLVER_* in /etc/lss/lss.conf and run lss configure dns-resolver.\n'
	printf 'server:\n\tverbosity: 0\n\tuse-syslog: yes\n\tport: 53\n\tinterface: %s\n' "${DNS_LOOPBACK}"
	[[ ${ip6} == no ]] || printf '\tinterface: ::1\n'
	if [[ $(opt access) == vpn ]]; then
		# The WireGuard address may come up after Unbound; freebind lets Unbound listen on it anyway.
		printf '\tinterface: %s\n\tip-freebind: yes\n' "$(fw_vpn_address)"
	fi
	printf '\tdo-ip4: yes\n\tdo-ip6: %s\n\tdo-udp: yes\n\tdo-tcp: yes\n' "${ip6}"
	printf '\taccess-control: 0.0.0.0/0 refuse\n\taccess-control: ::/0 refuse\n'
	printf '\taccess-control: 127.0.0.0/8 allow\n\taccess-control: ::1/128 allow\n'
	[[ $(opt access) != vpn ]] || printf '\taccess-control: %s allow\n' "${network}"
	cat <<EOF
	chroot: ""
	username: "unbound"
	directory: "/etc/unbound"
	auto-trust-anchor-file: "${DNS_ANCHOR}"
	tls-cert-bundle: "$(_dns_ca_bundle)"
	hide-identity: yes
	hide-version: yes
	harden-glue: yes
	harden-dnssec-stripped: yes
	harden-below-nxdomain: yes
	qname-minimisation: yes
	aggressive-nsec: yes
	use-caps-for-id: no
	prefetch: yes
	prefetch-key: yes
	minimal-responses: yes
	val-clean-additional: yes
	unwanted-reply-threshold: 10000000
	num-threads: 1
	msg-cache-size: 16m
	rrset-cache-size: 32m
	# Public names must not resolve to private addresses (DNS rebinding).
	private-address: 10.0.0.0/8
	private-address: 172.16.0.0/12
	private-address: 192.168.0.0/16
	private-address: 169.254.0.0/16
	private-address: fd00::/8
	private-address: fe80::/10
remote-control:
	control-enable: yes
	control-interface: $(_dns_control)
EOF
	[[ -n $(opt forward) ]] || return 0
	printf 'forward-zone:\n\tname: "."\n'
	if opt_bool forward_tls; then
		printf '\tforward-tls-upstream: yes\n'
	fi
	for entry in $(opt forward); do
		printf '\tforward-addr: %s\n' "${entry}"
	done
	return
}

# The DNSSEC trust anchor of the root zone, created once from unbound-anchor's built-in copy (it fetches a newer one when
# it can) and then kept current by Unbound itself (RFC 5011); Unbound must own it.
_dns_anchor() {
	install -d -m 0755 -o unbound -g unbound /var/lib/unbound
	if [[ ! -s ${DNS_ANCHOR} ]]; then
		# unbound-anchor exits with 1 after creating or updating the file; the file is what counts.
		unbound-anchor -a "${DNS_ANCHOR}" >/dev/null 2>&1 || true
		if [[ ! -s ${DNS_ANCHOR} && -s /usr/share/dns/root.key ]]; then
			cp /usr/share/dns/root.key "${DNS_ANCHOR}"
		fi
		[[ -s ${DNS_ANCHOR} ]] || die "dns-resolver: unbound-anchor could not create ${DNS_ANCHOR}."
		files_note_change "created the DNSSEC trust anchor"
	fi
	if [[ $(stat -c '%U' "${DNS_ANCHOR}") != unbound ]]; then
		chown unbound:unbound "${DNS_ANCHOR}"
	fi
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -F "${DNS_ANCHOR}" 2>/dev/null || true
	fi
	return
}

# How the server picks its resolver: systemd-resolved, NetworkManager, a plain /etc/resolv.conf, or nothing to change
# (inside a container, or with system=false).
_dns_system_mode() {
	if ! opt_bool system || os_in_container; then
		printf 'none'
	elif svc_is_active systemd-resolved; then
		printf 'resolved'
	elif svc_is_active NetworkManager; then
		printf 'networkmanager'
	else
		printf 'file'
	fi
	return
}

# _dns_resolv_conf: /etc/resolv.conf pointing at Unbound, with the search domains of the original file.
_dns_resolv_conf() {
	printf '# Managed by lss (module dns-resolver): this server resolves through Unbound.\nnameserver %s\n' "${DNS_LOOPBACK}"
	if [[ -f ${DNS_SAVED} && ! -L ${DNS_SAVED} ]]; then
		grep -E '^(search|domain)[[:space:]]' "${DNS_SAVED}" || true
	fi
	printf 'options edns0 trust-ad\n'
	return
}

_dns_save_original() {
	[[ ! -e ${DNS_SAVED} && ! -L ${DNS_SAVED} ]] || return 0
	install -d -m 0700 "${DNS_SAVED_DIR}"
	cp -a "${DNS_RESOLV}" "${DNS_SAVED}"
	return
}

_dns_system_apply() {
	local mode=$1 changed=0 content
	case ${mode} in
	resolved)
		# resolved keeps its stub on 127.0.0.53 and forwards everything to Unbound, which does the DNSSEC validation.
		file_write 0644 root:root "${DNS_RESOLVED_DROPIN}" <<EOF
# Managed by lss (module dns-resolver): resolve every name through Unbound.
[Resolve]
DNS=${DNS_LOOPBACK}
Domains=~.
DNSSEC=no
EOF
		if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
			svc_restart systemd-resolved || die "dns-resolver: systemd-resolved does not start with Unbound as its server."
		fi
		;;
	networkmanager | file)
		_dns_save_original
		if [[ ${mode} == networkmanager ]]; then
			file_write 0644 root:root "${DNS_NM_CONF}" <<'EOF'
# Managed by lss (module dns-resolver): /etc/resolv.conf points at Unbound and NetworkManager leaves it alone.
[main]
dns=none
rc-manager=unmanaged
EOF
			[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
		elif [[ -d $(dirname "${DNS_DHCLIENT_HOOK}") ]]; then
			file_write 0644 root:root "${DNS_DHCLIENT_HOOK}" <<'EOF'
# Managed by lss (module dns-resolver): /etc/resolv.conf points at Unbound, so dhclient does not rewrite it.
make_resolv_conf() {
	:
}
EOF
		fi
		content=$(_dns_resolv_conf)
		file_write 0644 root:root "${DNS_RESOLV}" <<<"${content}"
		if [[ ${changed} == 1 ]]; then
			systemctl reload NetworkManager || die "dns-resolver: NetworkManager does not reload."
		fi
		;;
	*) ;;
	esac
	return
}

# Puts the resolver of the server back as it was (module removed, or system=false).
_dns_system_undo() {
	local before
	before=$(files_changes_of dns-resolver)
	if [[ -e ${DNS_RESOLVED_DROPIN} ]]; then
		file_remove "${DNS_RESOLVED_DROPIN}"
		svc_restart systemd-resolved || true
	fi
	file_remove "${DNS_DHCLIENT_HOOK}"
	if [[ -e ${DNS_SAVED} || -L ${DNS_SAVED} ]]; then
		files_backup "${DNS_RESOLV}"
		rm -f -- "${DNS_RESOLV}"
		cp -a "${DNS_SAVED}" "${DNS_RESOLV}"
		rm -f -- "${DNS_SAVED}"
		rmdir "${DNS_SAVED_DIR}" 2>/dev/null || true
		files_note_change "restored ${DNS_RESOLV}"
	fi
	if [[ -e ${DNS_NM_CONF} ]]; then
		file_remove "${DNS_NM_CONF}"
		systemctl reload NetworkManager || true
	fi
	[[ $(files_changes_of dns-resolver) == "${before}" ]] || log_info "dns-resolver: the server uses its previous resolvers again."
	return
}

mod_configure() {
	local before config mode
	before=$(files_changes_of dns-resolver)
	mon_vpn_ready
	_dns_anchor
	config=$(_dns_config)
	file_write 0644 root:root "${DNS_CONF}" <<<"${config}"
	unbound-checkconf "${DNS_CONF}" >/dev/null || die "dns-resolver: unbound-checkconf rejects ${DNS_CONF}."
	svc_sandbox "${DNS_UNIT}.service" ReadWritePaths=/var/lib/unbound
	if os_is_rhel; then
		# The unit of the RHEL family runs unbound-anchor before every start and fails when it cannot reach the root
		# servers. Unbound keeps the anchor current itself (RFC 5011, _dns_anchor), so the unit's own update stays off.
		svc_dropin "${DNS_UNIT}.service" lss-config <<'EOF'
# Managed by lss (module dns-resolver): Unbound updates its trust anchor itself.
[Service]
Environment=DISABLE_UNBOUND_ANCHOR=yes
EOF
	fi
	mon_vpn_dropin "${DNS_UNIT}.service"
	svc_enable "${DNS_UNIT}"
	if [[ $(files_changes_of dns-resolver) != "${before}" ]]; then
		svc_restart "${DNS_UNIT}" || die "dns-resolver: Unbound does not start with the new configuration."
	fi
	mon_firewall 53/udp 53/tcp
	# The server switches to Unbound only once it answers, and only when it reaches the DNS of the Internet: where
	# outgoing DNS is blocked, the switch would leave the server without any name resolution.
	_dns_wait
	mode=$(_dns_system_mode)
	if [[ ${mode} != none ]] && ! _dns_online; then
		log_warn "dns-resolver: Unbound reaches no DNS server on the Internet, so this server keeps its previous resolvers; LSS_DNS_RESOLVER_FORWARD names resolvers that are reachable."
		mode=none
	fi
	if [[ ${mode} == none ]]; then
		_dns_system_undo
	else
		_dns_system_apply "${mode}"
	fi
	return
}

# _dns_packet NAME TYPE: a DNS query (recursion desired, AD bit set to ask for the validation result) as printf %b
# escapes. NAME is a host name or "." for the root.
_dns_packet() {
	local name=$1 type=$2 label packet='\x4c\x53\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00'
	local -a labels=()
	IFS=. read -ra labels <<<"${name%.}"
	for label in "${labels[@]}"; do
		[[ -n ${label} ]] || continue
		packet+=$(printf '\\x%02x%s' "${#label}" "${label}")
	done
	packet+=$(printf '\\x00\\x%02x\\x%02x\\x00\\x01' $((type >> 8)) $((type & 255)))
	printf '%s' "${packet}"
	return
}

# _dns_query SERVER NAME TYPE: sends one query over UDP and prints the reply as hexadecimal bytes separated by
# spaces; nothing when no reply came within 5 seconds.
_dns_query() {
	local server=$1 name=$2 type=$3 fd reply
	exec {fd}<>"/dev/udp/${server}/53" || return 0
	printf '%b' "$(_dns_packet "${name}" "${type}")" >&"${fd}"
	reply=$(timeout 5 dd bs=4096 count=1 status=none <&"${fd}" | od -An -v -tx1 | tr -s ' \n' '  ' || true)
	exec {fd}>&-
	printf '%s' "${reply# }"
	return
}

# _dns_reply_rcode REPLY / _dns_reply_ad REPLY / _dns_reply_answers REPLY: fields of a reply from _dns_query.
_dns_reply_rcode() {
	local -a bytes=()
	read -ra bytes <<<"$1"
	[[ ${#bytes[@]} -ge 12 && ${bytes[0]}${bytes[1]} == 4c53 ]] || return 1
	printf '%s' $((0x${bytes[3]} & 15))
	return
}

_dns_reply_ad() {
	local -a bytes=()
	read -ra bytes <<<"$1"
	[[ ${#bytes[@]} -ge 12 ]] && (((0x${bytes[3]} & 0x20) != 0))
	return
}

_dns_reply_answers() {
	local -a bytes=()
	read -ra bytes <<<"$1"
	[[ ${#bytes[@]} -ge 12 ]] || return 1
	printf '%s' $((0x${bytes[6]} * 256 + 0x${bytes[7]}))
	return
}

# Waits until Unbound answers a local name (no network needed): the built-in zone localhost.
_dns_wait() {
	local i reply=''
	for ((i = 0; i < 15; i++)); do
		reply=$(_dns_query "${DNS_LOOPBACK}" localhost 1)
		if [[ $(_dns_reply_rcode "${reply}") == 0 && $(_dns_reply_answers "${reply}") -ge 1 ]]; then
			return 0
		fi
		sleep 1
	done
	die "dns-resolver: Unbound does not answer on ${DNS_LOOPBACK}:53."
}

# _dns_root_reply: Unbound's answer for the SOA of the signed root zone. A cold Unbound first fetches the root servers
# and keys, so it gets three tries.
_dns_root_reply() {
	local reply=''
	for _ in 1 2 3; do
		reply=$(_dns_query "${DNS_LOOPBACK}" . 6)
		[[ -z $(_dns_reply_rcode "${reply}" || true) ]] || break
	done
	printf '%s' "${reply}"
	return
}

# _dns_online: whether Unbound resolves the root zone, which needs the root servers or the forward resolvers.
_dns_online() {
	[[ $(_dns_reply_rcode "$(_dns_root_reply)" || true) == 0 ]]
	return
}

mod_verify() {
	local reply rcode address mode
	local -a addresses=("${DNS_LOOPBACK}")
	svc_is_active "${DNS_UNIT}" || die "dns-resolver: ${DNS_UNIT} is not running."
	_dns_wait
	unbound-control -c "${DNS_CONF}" status >/dev/null 2>&1 || die "dns-resolver: unbound-control gets no answer."
	[[ $(unbound-control -c "${DNS_CONF}" get_option module-config 2>/dev/null) == *validator* ]] ||
		die "dns-resolver: Unbound does not validate DNSSEC."
	[[ -s ${DNS_ANCHOR} ]] || die "dns-resolver: the DNSSEC trust anchor ${DNS_ANCHOR} is missing."
	# The signed root zone must come back validated (AD). Without a reachable resolver upstream only the offline checks
	# above apply, and the server keeps its previous resolvers (mod_configure).
	reply=$(_dns_root_reply)
	rcode=$(_dns_reply_rcode "${reply}" || true)
	mode=$(_dns_system_mode)
	if [[ ${rcode} == 0 ]]; then
		_dns_reply_ad "${reply}" || die "dns-resolver: the answer for the root zone is not DNSSEC-validated."
	else
		log_warn "dns-resolver: the root zone did not resolve (rcode ${rcode:-none}); DNSSEC was checked offline only."
		mode=none
	fi
	_dns_ipv6 && addresses+=(::1)
	[[ $(opt access) != vpn ]] || addresses+=("$(fw_vpn_address)")
	mon_listen_check --process unbound 53 "${addresses[@]}"
	case ${mode} in
	resolved)
		resolvectl dns 2>/dev/null | grep -qE "^Global: .*${DNS_LOOPBACK}" ||
			die "dns-resolver: systemd-resolved does not forward to Unbound."
		;;
	networkmanager | file)
		address=$(awk '$1 == "nameserver" { print $2; exit }' "${DNS_RESOLV}")
		[[ ${address} == "${DNS_LOOPBACK}" ]] || die "dns-resolver: ${DNS_RESOLV} does not point at Unbound."
		;;
	*) ;;
	esac
	return
}

mod_remove() {
	_dns_system_undo
	svc_disable "${DNS_UNIT}"
	svc_dropin_remove "${DNS_UNIT}.service" lss-sandbox
	svc_dropin_remove "${DNS_UNIT}.service" lss-vpn
	svc_dropin_remove "${DNS_UNIT}.service" lss-config
	file_remove "${DNS_CONF}"
	pkg_remove_family "unbound unbound-anchor" unbound
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	mon_delete /var/lib/unbound
	return
}
