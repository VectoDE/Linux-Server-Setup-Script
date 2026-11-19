#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The nftables and iptables backends of lib/firewall.sh: choice of the backend, the rule sets rendered from the
# records, loading, enabling and disabling. ufw and firewalld are covered in system.bats. nft, iptables and their
# restore tools are stubs (tests/fixtures/bin) that record their calls in $STUB_LOG.

setup() {
	load helpers
	lss_test_setup
	export FW_NFT_FILE=${BATS_TEST_TMPDIR}/nftables.d/lss.nft
	export FW_NFT_CONF=${BATS_TEST_TMPDIR}/nftables.conf
	export FW_IPT_DIR=${BATS_TEST_TMPDIR}/firewall
	export FW_LOCAL_D=${BATS_TEST_TMPDIR}/local.d
	OS_FAMILY=arch
	LSS_MODULE=web
	# Writes below /etc go to the test directory; file_write runs as the test user.
	# shellcheck disable=SC2329 # replaces file_write of lib/files.sh
	file_write() {
		local dest=$3 tmp
		LSS_FILE_CHANGED=0
		mkdir -p "$(dirname "${dest}")"
		tmp=$(mktemp)
		cat >"${tmp}"
		if [[ -f ${dest} ]] && cmp -s "${tmp}" "${dest}"; then
			rm -f -- "${tmp}"
			return 0
		fi
		mv -f -- "${tmp}" "${dest}"
		LSS_FILE_CHANGED=1
	}
	return
}

# records: the rules of two modules and a trusted network.
records() {
	mkdir -p "${LSS_STATE_DIR}/firewall" "${LSS_STATE_DIR}/firewall-trusted"
	printf '22/tcp\n443/tcp\n3000-3010/tcp:vpn\n5432/tcp:local\n' >"${LSS_STATE_DIR}/firewall/web"
	printf '51820/udp:public\n' >"${LSS_STATE_DIR}/firewall/wireguard"
	printf '10.42.0.0/16 cni0\nfd42::/48 cni0\n' >"${LSS_STATE_DIR}/firewall-trusted/k3s"
}

@test "the backend follows the family and LSS_FIREWALL; iptables only where nft is missing" {
	OS_FAMILY=debian
	[ "$(fw_backend)" = ufw ]
	OS_FAMILY=rhel
	[ "$(fw_backend)" = firewalld ]
	OS_FAMILY=suse
	[ "$(fw_backend)" = firewalld ]
	OS_FAMILY=alpine
	[ "$(fw_backend)" = nftables ]
	fw_declarative
	export LSS_FIREWALL=iptables
	[ "$(fw_backend)" = iptables ]
	OS_FAMILY=debian
	export LSS_FIREWALL=nftables
	[ "$(fw_backend)" = nftables ]
	export LSS_FIREWALL=pf
	run fw_backend
	[ "${status}" -eq 1 ]
	[[ ${output} == *"LSS_FIREWALL 'pf' is none of ufw, firewalld, nftables and iptables."* ]]
	unset LSS_FIREWALL
	# Without nft but with iptables-restore: iptables.
	local bin=${BATS_TEST_TMPDIR}/bin
	mkdir -p "${bin}"
	ln -s "${REPO_ROOT}/tests/fixtures/bin/iptables-restore" "${bin}/iptables-restore"
	OS_FAMILY=arch
	PATH="${bin}:$(printf '%s' "${PATH}" | tr ':' '\n' | grep -v fixtures/bin | grep -v -e '^/usr/sbin$' -e '^/sbin$' | paste -sd:)"
	if ! type -P nft >/dev/null; then
		[ "$(fw_backend)" = iptables ]
	fi
}

@test "nftables: one table of lss, everything else dropped, rules from every record" {
	records
	local ruleset
	ruleset=$(fw_nft_ruleset)
	[[ ${ruleset} == *$'table inet lss\ndelete table inet lss\ntable inet lss {'* ]]
	[[ ${ruleset} == *'type filter hook input priority filter; policy drop;'* ]]
	[[ ${ruleset} == *'ct state established,related accept'* ]]
	[[ ${ruleset} == *'iifname "lo" accept'* ]]
	grep -qxF $'\t\ttcp dport 22 accept' <<<"${ruleset}"
	grep -qxF $'\t\ttcp dport 443 accept' <<<"${ruleset}"
	grep -qxF $'\t\tudp dport 51820 accept' <<<"${ruleset}"
	grep -qxF $'\t\tip saddr 10.66.0.0/24 tcp dport 3000-3010 accept' <<<"${ruleset}"
	grep -qxF $'\t\tiifname "cni0" ip saddr 10.42.0.0/16 accept' <<<"${ruleset}"
	grep -qxF $'\t\tiifname "cni0" ip6 saddr fd42::/48 accept' <<<"${ruleset}"
	# Local rules open nothing.
	run ! grep -q 5432 <<<"${ruleset}"
	# The same records give the same rule set.
	[ "$(fw_nft_ruleset)" = "${ruleset}" ]
}

@test "iptables: a chain of lss per family, the WireGuard rules only in IPv4" {
	records
	local v4 v6
	v4=$(fw_ipt_ruleset 4)
	v6=$(fw_ipt_ruleset 6)
	grep -qxF ':LSS-INPUT - [0:0]' <<<"${v4}"
	grep -qxF -- '-F LSS-INPUT' <<<"${v4}"
	grep -qxF -- '-A LSS-INPUT -p icmp -j ACCEPT' <<<"${v4}"
	grep -qxF -- '-A LSS-INPUT -p ipv6-icmp -j ACCEPT' <<<"${v6}"
	grep -qxF -- '-A LSS-INPUT -p tcp -m tcp --dport 443 -j ACCEPT' <<<"${v4}"
	grep -qxF -- '-A LSS-INPUT -p tcp -m tcp --dport 443 -j ACCEPT' <<<"${v6}"
	grep -qxF -- '-A LSS-INPUT -s 10.66.0.0/24 -p tcp -m tcp --dport 3000:3010 -j ACCEPT' <<<"${v4}"
	run ! grep -q 10.66.0.0 <<<"${v6}"
	grep -qxF -- '-A LSS-INPUT -i cni0 -s 10.42.0.0/16 -j ACCEPT' <<<"${v4}"
	grep -qxF -- '-A LSS-INPUT -i cni0 -s fd42::/48 -j ACCEPT' <<<"${v6}"
	run ! grep -q fd42 <<<"${v4}"
	run ! grep -q 10.42.0.0 <<<"${v6}"
	[ "$(tail -n 2 <<<"${v4}")" = $'-A LSS-INPUT -j DROP\nCOMMIT' ]
}

@test "nftables: fw_allow writes the rule set and loads it only while the table is there" {
	OS_FAMILY=alpine
	# The table is not loaded (nft list fails): only the file is written.
	STUB_EXIT_nft=1 fw_allow 443/tcp
	grep -qxF $'\t\ttcp dport 443 accept' "${FW_NFT_FILE}"
	run ! grep -q 'nft -f' "${STUB_LOG}"
	# Loaded: the new rule set replaces the table.
	fw_allow 8443/tcp
	grep -qxF "nft -f ${FW_NFT_FILE}" "${STUB_LOG}"
	# Nothing new: nothing is loaded.
	: >"${STUB_LOG}"
	fw_allow 8443/tcp
	run ! grep -q 'nft -f' "${STUB_LOG}"
	# Removing the module closes its ports.
	fw_remove_module
	run ! grep -q 443 "${FW_NFT_FILE}"
	grep -qxF "nft -f ${FW_NFT_FILE}" "${STUB_LOG}"
	# nftables refuses the rule set: the run stops.
	STUB_EXIT_nft=1 fw_allow 22/tcp || true
	# shellcheck disable=SC2329 # called by fw_sync
	nft() {
		[[ $1 == list ]] && return 0
		return 1
	}
	run fw_allow 2222/tcp
	[ "${status}" -eq 1 ]
	[[ ${output} == *"nftables does not take the rules in ${FW_NFT_FILE}."* ]]
}

@test "iptables: fw_trust writes both rule sets and loads them while the chain is hooked in" {
	export LSS_FIREWALL=iptables
	# shellcheck disable=SC2329 # called by fw_trust
	_fw_host_addresses() { printf '192.168.1.10\n'; }
	STUB_EXIT_iptables=1 fw_trust 10.42.0.0/16 cni0
	grep -qxF -- '-A LSS-INPUT -i cni0 -s 10.42.0.0/16 -j ACCEPT' "${FW_IPT_DIR}/rules.v4"
	[ -f "${FW_IPT_DIR}/rules.v6" ]
	run ! grep -q 'restore' "${STUB_LOG}"
	fw_allow 443/tcp
	grep -qxF "iptables-restore --noflush ${FW_IPT_DIR}/rules.v4" "${STUB_LOG}"
	grep -qxF "ip6tables-restore --noflush ${FW_IPT_DIR}/rules.v6" "${STUB_LOG}"
	STUB_EXIT_iptables_restore=1 run fw_allow 80/tcp
	[ "${status}" -eq 1 ]
	[[ ${output} == *"iptables does not take the rules in ${FW_IPT_DIR}/rules.v4."* ]]
	STUB_EXIT_ip6tables_restore=1 run fw_allow 8080/tcp
	[ "${status}" -eq 1 ]
	[[ ${output} == *"ip6tables does not take the rules in ${FW_IPT_DIR}/rules.v6."* ]]
}

@test "the declarative backends never call ufw or firewalld" {
	export LSS_FIREWALL=nftables
	records
	fw_apply_all
	_fw_parse 443/tcp
	_fw_apply add
	_fw_trust_apply add 10.42.0.0/16 cni0
	run ! grep -q -e '^ufw' -e '^firewall' "${STUB_LOG}"
	grep -qxF $'\t\ttcp dport 443 accept' "${FW_NFT_FILE}"
}

@test "nothing is written while the tool is missing" {
	export LSS_FIREWALL=nftables
	PATH=$(printf '%s' "${PATH}" | tr ':' '\n' | grep -v fixtures/bin | paste -sd:)
	type -P nft >/dev/null && skip "nft is installed on this machine"
	fw_allow 443/tcp
	[ ! -e "${FW_NFT_FILE}" ]
	[ "$(cat "${LSS_STATE_DIR}/firewall/web")" = 443/tcp ]
}

@test "fw_enable loads nftables, adds the include once and enables the service" {
	export LSS_FIREWALL=nftables
	printf '#!/usr/sbin/nft -f\nflush ruleset\n' >"${FW_NFT_CONF}"
	chmod 0755 "${FW_NFT_CONF}"
	records
	fw_enable
	grep -qxF "nft -f ${FW_NFT_FILE}" "${STUB_LOG}"
	grep -qxF "include \"${FW_NFT_FILE}\"" "${FW_NFT_CONF}"
	grep -q 'systemctl enable --now nftables' "${STUB_LOG}"
	fw_enable
	[ "$(grep -c include "${FW_NFT_CONF}")" -eq 1 ]
	# A configuration that includes the whole directory needs no line of its own.
	printf 'include "%s/*.nft"\n' "${FW_NFT_FILE%/*}" >"${FW_NFT_CONF}"
	fw_enable
	[ "$(grep -c include "${FW_NFT_CONF}")" -eq 1 ]
	# Refused rules stop the run.
	STUB_EXIT_nft=1 run fw_enable
	[ "${status}" -eq 1 ]
	[[ ${output} == *"nftables does not take the rules"* ]]
}

@test "fw_enable hooks iptables into INPUT and loads the rules at boot with systemd or OpenRC" {
	export LSS_FIREWALL=iptables
	records
	local writes=${BATS_TEST_TMPDIR}/units
	# shellcheck disable=SC2329 # called by fw_enable
	svc_unit() {
		printf '== %s\n' "$1" >>"${writes}"
		cat >>"${writes}"
	}
	# iptables -C fails: the jump is inserted.
	# shellcheck disable=SC2329 # called by fw_enable
	iptables() {
		printf 'iptables %s\n' "$*" >>"${STUB_LOG}"
		[[ $1 != -C ]]
	}
	# shellcheck disable=SC2329 # called by fw_enable
	ip6tables() {
		printf 'ip6tables %s\n' "$*" >>"${STUB_LOG}"
		[[ $1 != -C ]]
	}
	fw_enable
	unset -f iptables ip6tables
	grep -qxF "iptables-restore --noflush ${FW_IPT_DIR}/rules.v4" "${STUB_LOG}"
	grep -qxF 'iptables -I INPUT 1 -j LSS-INPUT' "${STUB_LOG}"
	grep -qxF 'ip6tables -I INPUT 1 -j LSS-INPUT' "${STUB_LOG}"
	grep -qxF '== lss-firewall.service' "${writes}"
	grep -q "^ExecStart=/bin/sh -c 'iptables-restore --noflush ${FW_IPT_DIR}/rules.v4 && ip6tables-restore" "${writes}"
	grep -q 'systemctl enable --now lss-firewall.service' "${STUB_LOG}"
	# Hooked in already: no second jump.
	: >"${STUB_LOG}"
	fw_enable
	run ! grep -q 'INPUT 1' "${STUB_LOG}"
	# OpenRC: a start script of the local service.
	export LSS_INIT=openrc
	fw_enable
	grep -qx 'iptables-restore --noflush .*rules.v4 && .*' "${FW_LOCAL_D}/lss-firewall.start"
	grep -qx 'rc-service local start' "${STUB_LOG}"
	# SysV: a warning, the rules are not loaded at boot.
	export LSS_INIT=sysv
	run fw_enable
	[ "${status}" -eq 0 ]
	[[ ${output} == *"sysv has no boot hook lss knows; the iptables rules are gone after a reboot."* ]]
	STUB_EXIT_iptables_restore=1 run fw_enable
	[ "${status}" -eq 1 ]
	STUB_EXIT_ip6tables_restore=1 run fw_enable
	[ "${status}" -eq 1 ]
	export LSS_FIREWALL=ufw
	run fw_enable
	[ "${status}" -eq 1 ]
	[[ ${output} == *"fw_enable is for nftables and iptables; ufw is switched on by the firewall module."* ]]
}

@test "fw_disable takes the table or every jump away, and the boot hooks with it" {
	export LSS_FIREWALL=nftables
	fw_disable
	grep -qxF 'nft delete table inet lss' "${STUB_LOG}"
	: >"${STUB_LOG}"
	STUB_EXIT_nft=1 fw_disable
	run ! grep -q 'nft delete' "${STUB_LOG}"
	export LSS_FIREWALL=iptables
	# shellcheck disable=SC2329 # called by fw_disable
	file_remove() { printf 'file_remove %s\n' "$1" >>"${STUB_LOG}"; }
	# iptables -C succeeds twice, then fails: two jumps are deleted.
	local count=${BATS_TEST_TMPDIR}/count
	printf '0' >"${count}"
	# shellcheck disable=SC2329 # called by fw_disable
	iptables() {
		printf 'iptables %s\n' "$*" >>"${STUB_LOG}"
		if [[ $1 == -C ]]; then
			local n
			n=$(<"${count}")
			printf '%s' $((n + 1)) >"${count}"
			((n < 2))
			return
		fi
	}
	STUB_EXIT_ip6tables=1 fw_disable
	[ "$(grep -c 'iptables -D INPUT -j LSS-INPUT' "${STUB_LOG}")" -eq 2 ]
	grep -qxF 'file_remove /etc/systemd/system/lss-firewall.service' "${STUB_LOG}"
	grep -qxF "file_remove ${FW_LOCAL_D}/lss-firewall.start" "${STUB_LOG}"
	export LSS_FIREWALL=ufw
	run fw_disable
	[ "${status}" -eq 1 ]
}

@test "the rollback switches the declarative backends off as well" {
	export SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 22'
	export LSS_FIREWALL=nftables
	fw_rollback_arm 60 2>/dev/null
	grep -q 'systemd-run .*--on-active=60 /bin/sh -c nft delete table inet lss' "${STUB_LOG}"
	export LSS_FIREWALL=iptables
	fw_rollback_arm 60 2>/dev/null
	grep -q 'systemd-run .*/bin/sh -c while iptables -D INPUT -j LSS-INPUT; do :; done;' "${STUB_LOG}"
}

@test "fw_enable refuses to add rules next to an active ufw, firewalld or Proxmox VE firewall" {
	export LSS_FIREWALL=nftables
	STUB_OUT_ufw='Status: active' run fw_enable
	[ "${status}" -eq 1 ]
	[[ ${output} == *"ufw is active; switch it off or set LSS_FIREWALL=ufw instead of nftables."* ]]
	local unit
	for unit in firewalld pve-firewall; do
		STUB_ACTIVE_UNITS=${unit} run fw_enable
		[ "${status}" -eq 1 ]
		[[ ${output} == *"${unit} is active; switch it off or use it instead of nftables."* ]]
	done
	run ! grep -q 'nft -f' "${STUB_LOG}"
}
