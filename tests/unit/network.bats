#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The network modules: the checks and the configuration they write for WireGuard, Unbound and chrony, and the DNS
# messages dns-resolver verifies with.

setup() {
	load helpers
	lss_test_setup
	use_os debian-13
	export TMPDIR=${BATS_TEST_TMPDIR}
	WRITES=${BATS_TEST_TMPDIR}/writes
	: >"${WRITES}"
	# shellcheck disable=SC2329 # called by the functions under test
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${WRITES}"
		cat >>"${WRITES}"
		LSS_FILE_CHANGED=${TEST_FILE_CHANGED:-1}
	}
}

# load_module NAME: sources the module as lss does for a step.
load_module() {
	local file
	file=$(module_file "$1")
	export LSS_MODULE=$1
	# shellcheck source=/dev/null
	source "${file}"
	return
}

KEY_A=xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
KEY_B=TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=

# --- wireguard --------------------------------------------------------------------------------------------------

@test "wireguard accepts peers with a key and an address of their own in the network" {
	load_module wireguard
	config_set LSS_WIREGUARD_PEERS "laptop:${KEY_A}:10.66.0.2 phone:${KEY_B}:10.66.0.3/32"
	mod_check
}

@test "wireguard refuses bad names, keys, addresses and duplicates" {
	load_module wireguard
	config_set LSS_WIREGUARD_PEERS "Laptop:${KEY_A}:10.66.0.2"
	run mod_check
	[[ ${output} == *"'Laptop' is not a peer name"* ]]
	config_set LSS_WIREGUARD_PEERS "laptop:abc=:10.66.0.2"
	run mod_check
	[[ ${output} == *"the key of 'laptop' is not a WireGuard public key."* ]]
	config_set LSS_WIREGUARD_PEERS "laptop:${KEY_A}:10.67.0.2"
	run mod_check
	[[ ${output} == *"the address of 'laptop' must be an IPv4 address in 10.66.0.0/24."* ]]
	config_set LSS_WIREGUARD_PEERS "laptop:${KEY_A}:10.66.0.1"
	run mod_check
	[[ ${output} == *"10.66.0.1 is the address of the server."* ]]
	config_set LSS_WIREGUARD_PEERS "laptop:${KEY_A}:10.66.0.2 phone:${KEY_A}:10.66.0.3"
	run mod_check
	[[ ${output} == *"every peer needs its own name, key and address ('phone')."* ]]
	config_set LSS_WIREGUARD_PEERS ''
	config_set LSS_WIREGUARD_PORT 70000
	run mod_check
	[[ ${output} == *"LSS_WIREGUARD_PORT must be between 1 and 65535."* ]]
	config_set LSS_WIREGUARD_PORT 51820
	config_set LSS_WIREGUARD_ENDPOINT 'vpn.example.com;reboot'
	run mod_check
	[[ ${output} == *"is not a host name."* ]]
}

@test "the WireGuard configuration holds no key: PostUp loads them from the secrets" {
	load_module wireguard
	config_set LSS_WIREGUARD_NETWORK 10.70.0.0/16
	config_set LSS_WIREGUARD_PEERS "laptop:${KEY_A}:10.70.3.4"
	run _wg_config
	[[ ${output} == *$'\nAddress = 10.70.0.1/16\nListenPort = 51820\n'* ]]
	[[ ${output} == *"PostUp = wg set %i private-key ${LSS_SECRETS_DIR}/wireguard-private-key"* ]]
	[[ ${output} == *"PostUp = wg set %i peer ${KEY_A} preshared-key ${LSS_SECRETS_DIR}/wireguard-psk-laptop"* ]]
	[[ ${output} == *$'[Peer]\n# laptop\nPublicKey = '"${KEY_A}"$'\nAllowedIPs = 10.70.3.4/32'* ]]
	[[ ${output} != *PrivateKey* && ${output} != *PresharedKey* ]]
}

@test "the server key and one preshared key per peer are generated once" {
	load_module wireguard
	# shellcheck disable=SC2329 # called by the functions under test
	wg() {
		printf 'wg %s\n' "$*" >>"${STUB_LOG}"
		printf 'GENERATED%s=\n' "${RANDOM}"
	}
	config_set LSS_WIREGUARD_PEERS "laptop:${KEY_A}:10.66.0.2"
	_wg_keys
	[ -s "${LSS_SECRETS_DIR}/wireguard-private-key" ]
	[ -s "${LSS_SECRETS_DIR}/wireguard-psk-laptop" ]
	[ "$(grep -c '^wg' "${STUB_LOG}")" = 2 ]
	_wg_keys
	[ "$(grep -c '^wg' "${STUB_LOG}")" = 2 ]
}

# --- dns-resolver -----------------------------------------------------------------------------------------------

@test "dns-resolver checks access and the forward resolvers" {
	load_module dns-resolver
	mod_check
	config_set LSS_DNS_RESOLVER_FORWARD '1.1.1.1 2606:4700:4700::1111@53'
	mod_check
	config_set LSS_DNS_RESOLVER_FORWARD 'dns.example.com'
	run mod_check
	[[ ${output} == *"'dns.example.com' is not ADDRESS, ADDRESS@PORT or ADDRESS@PORT#NAME."* ]]
	config_set LSS_DNS_RESOLVER_FORWARD '1.1.1.1@853'
	config_set LSS_DNS_RESOLVER_FORWARD_TLS true
	run mod_check
	[[ ${output} == *"needs #NAME (the name in its certificate) with forward_tls."* ]]
	config_set LSS_DNS_RESOLVER_FORWARD ''
	run mod_check
	[[ ${output} == *"LSS_DNS_RESOLVER_FORWARD_TLS=true needs resolvers in LSS_DNS_RESOLVER_FORWARD."* ]]
	config_set LSS_DNS_RESOLVER_FORWARD_TLS false
	config_set LSS_DNS_RESOLVER_ACCESS public
	run mod_check
	[[ ${output} == *"LSS_DNS_RESOLVER_ACCESS must be local or vpn."* ]]
}

@test "Unbound validates on 127.0.0.1, refuses everyone else and forwards over TLS when asked" {
	load_module dns-resolver
	# shellcheck disable=SC2329 # called by the functions under test
	_dns_ipv6() {
		return 1
	}
	run _dns_config
	[[ ${output} == *$'\tinterface: 127.0.0.1\n'* ]]
	[[ ${output} != *'interface: ::1'* && ${output} != *ip-freebind* ]]
	[[ ${output} == *$'\tdo-ip6: no\n'* ]]
	[[ ${output} == *$'\taccess-control: 0.0.0.0/0 refuse\n'* ]]
	[[ ${output} == *'auto-trust-anchor-file: "/var/lib/unbound/root.key"'* ]]
	[[ ${output} == *'control-interface: /run/unbound.ctl'* ]]
	[[ ${output} != *forward-zone* ]]
	config_set LSS_DNS_RESOLVER_ACCESS vpn
	config_set LSS_DNS_RESOLVER_FORWARD '9.9.9.9@853#dns.quad9.net'
	config_set LSS_DNS_RESOLVER_FORWARD_TLS true
	use_os rocky-9
	run _dns_config
	[[ ${output} == *$'\tinterface: 10.66.0.1\n\tip-freebind: yes\n'* ]]
	[[ ${output} == *$'\taccess-control: 10.66.0.0/24 allow\n'* ]]
	[[ ${output} == *'tls-cert-bundle: "/etc/pki/tls/certs/ca-bundle.crt"'* ]]
	[[ ${output} == *'control-interface: /run/unbound/unbound.ctl'* ]]
	[[ ${output} == *$'forward-zone:\n\tname: "."\n\tforward-tls-upstream: yes\n\tforward-addr: 9.9.9.9@853#dns.quad9.net'* ]]
}

@test "the resolv.conf for Unbound keeps the search domains of the original" {
	load_module dns-resolver
	DNS_SAVED=${BATS_TEST_TMPDIR}/resolv.conf.orig
	printf 'nameserver 192.0.2.53\nsearch corp.example\noptions rotate\n' >"${DNS_SAVED}"
	run _dns_resolv_conf
	[[ ${output} == *$'\nnameserver 127.0.0.1\nsearch corp.example\noptions edns0 trust-ad'* ]]
	[[ ${output} != *192.0.2.53* ]]
}

@test "the server resolves through systemd-resolved, NetworkManager or resolv.conf, and not inside a container" {
	load_module dns-resolver
	export STUB_EXIT_systemd_detect_virt=1
	[ "$(_dns_system_mode)" = file ]
	export STUB_ACTIVE_UNITS=NetworkManager
	[ "$(_dns_system_mode)" = networkmanager ]
	export STUB_ACTIVE_UNITS='NetworkManager systemd-resolved'
	[ "$(_dns_system_mode)" = resolved ]
	export STUB_EXIT_systemd_detect_virt=0
	[ "$(_dns_system_mode)" = none ]
	export STUB_EXIT_systemd_detect_virt=1
	config_set LSS_DNS_RESOLVER_SYSTEM false
	[ "$(_dns_system_mode)" = none ]
}

@test "with systemd-resolved, its stub forwards every name to Unbound" {
	load_module dns-resolver
	DNS_RESOLVED_DROPIN=${BATS_TEST_TMPDIR}/resolved.conf
	_dns_system_apply resolved
	grep -qxF "== 0644 root:root ${DNS_RESOLVED_DROPIN}" "${WRITES}"
	grep -qxF 'DNS=127.0.0.1' "${WRITES}"
	grep -qxF 'Domains=~.' "${WRITES}"
	grep -q 'systemctl restart systemd-resolved' "${STUB_LOG}"
}

@test "DNS queries are built label by label with the AD bit, and replies are read back" {
	load_module dns-resolver
	[ "$(_dns_packet example.com 1)" = '\x4c\x53\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' ]
	[ "$(_dns_packet . 6)" = '\x4c\x53\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x01' ]
	local reply='4c 53 81 a0 00 01 00 02 00 00 00 01'
	[ "$(_dns_reply_rcode "${reply}")" = 0 ]
	[ "$(_dns_reply_answers "${reply}")" = 2 ]
	_dns_reply_ad "${reply}"
	reply='4c 53 81 83 00 01 00 00 00 00 00 00'
	[ "$(_dns_reply_rcode "${reply}")" = 3 ]
	run ! _dns_reply_ad "${reply}"
	run _dns_reply_rcode '12 34 81 80 00 01 00 01 00 00 00 00'
	[ "${status}" -eq 1 ]
	run _dns_reply_rcode ''
	[ "${status}" -eq 1 ]
	run _dns_reply_answers '4c 53'
	[ "${status}" -eq 1 ]
}

@test "dns-resolver counts Unbound as online only when the root zone resolves" {
	load_module dns-resolver
	# shellcheck disable=SC2329 # called by the function under test
	_dns_query() {
		echo "query" >>"${BATS_TEST_TMPDIR}/queries"
		printf '%s' "${STUB_REPLY}"
	}
	STUB_REPLY='4c 53 81 a0 00 01 00 01 00 00 00 00'
	_dns_online
	STUB_REPLY='4c 53 81 82 00 01 00 00 00 00 00 00'
	run ! _dns_online
	# Silence (blocked outgoing DNS) is retried, three times in all.
	rm -f "${BATS_TEST_TMPDIR}/queries"
	STUB_REPLY=''
	run ! _dns_online
	[ "$(grep -c . "${BATS_TEST_TMPDIR}/queries")" = 3 ]
}

# --- ntp-server -------------------------------------------------------------------------------------------------

@test "ntp-server opens port 123 to the WireGuard network or to everyone, rate-limited" {
	load_module ntp-server
	mod_check
	run _ntp_config
	[[ ${output} == *$'port 123\nallow 10.66.0.0/24\nallow 127.0.0.1\nallow ::1\nratelimit interval 1 burst 16 leak 2'* ]]
	config_set LSS_NTP_SERVER_ACCESS public
	config_set LSS_NTP_SERVER_RATELIMIT false
	run _ntp_config
	[[ ${output} == *$'allow all\n'* && ${output} != *ratelimit* ]]
	config_set LSS_NTP_SERVER_ACCESS local
	run mod_check
	[[ ${output} == *"LSS_NTP_SERVER_ACCESS must be vpn or public."* ]]
	[ "$(_ntp_conf)" = /etc/chrony/conf.d/lss-ntp-server.conf ]
	use_os rocky-9
	[ "$(_ntp_conf)" = /etc/chrony.d/lss-ntp-server.conf ]
	[ "$(_ntp_unit)" = chronyd ]
}

@test "inside a container chronyd serves the time without setting the clock" {
	load_module ntp-server
	export STUB_EXIT_systemd_detect_virt=0
	# The command line comes from the distribution's unit, which systemctl names.
	local unit_file=${BATS_TEST_TMPDIR}/chrony.service
	printf '[Service]\nUser=_chrony\nExecStart=!/usr/sbin/chronyd -n $DAEMON_OPTS\n' >"${unit_file}"
	# shellcheck disable=SC2329 # called by the functions under test
	systemctl() {
		printf '%s\n' "${unit_file}"
	}
	_ntp_container_dropin
	grep -qxF '== 0644 root:root /etc/systemd/system/chrony.service.d/lss-ntp-server.conf' "${WRITES}"
	grep -qxF 'ConditionCapability=' "${WRITES}"
	grep -qxF 'ConditionVirtualization=' "${WRITES}"
	grep -qxF "ExecStart=!/usr/sbin/chronyd -n \$DAEMON_OPTS -x" "${WRITES}"
	grep -qxF "Type=simple" "${WRITES}"
	use_os rocky-9
	printf '[Service]\nExecStart=/usr/sbin/chronyd $OPTIONS\n' >"${unit_file}"
	_ntp_container_dropin
	grep -qxF "ExecStart=/usr/sbin/chronyd \$OPTIONS -x" "${WRITES}"
	[ "$(grep -c "^Type=simple$" "${WRITES}")" = 1 ]
	: >"${unit_file}"
	run _ntp_container_dropin
	[ "${status}" -eq 1 ]
	[[ ${output} == *"chronyd.service has no command line in ${unit_file}."* ]]
	export STUB_EXIT_systemd_detect_virt=1
	_ntp_container_dropin
	[ "${LSS_FILE_CHANGED}" = 0 ]
}

@test "the time module's chrony configuration reads the confdir of ntp-server last" {
	load_module time
	# shellcheck disable=SC2329 # called by the functions under test
	install() {
		printf 'install %s\n' "$*" >>"${STUB_LOG}"
	}
	_time_chrony_config
	grep -qxF '== 0644 root:root /etc/chrony/chrony.conf' "${WRITES}"
	grep -qxF 'server time.cloudflare.com iburst nts' "${WRITES}"
	grep -qxF 'port 0' "${WRITES}"
	[ "$(tail -n 1 "${WRITES}")" = 'confdir /etc/chrony/conf.d' ]
	grep -qxF 'install -d -m 0755 /etc/chrony/conf.d' "${STUB_LOG}"
	use_os rocky-9
	_time_chrony_config
	grep -qxF 'confdir /etc/chrony.d' "${WRITES}"
}
