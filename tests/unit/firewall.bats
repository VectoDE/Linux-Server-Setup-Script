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

# A rollback job a failed test left behind would keep bats waiting (it holds the output of bats open).
teardown() {
	fw_rollback_cancel 2>/dev/null || true
	return 0
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

# distro_default ID VERSION [forward]: writes FW_NFT_CONF as the default of a distribution (a table "inet filter" that
# drops input, like Alpine's and Arch's, with a forward chain that drops as well if the third argument is "forward") and
# lists its checksum in a defaults file of the test.
distro_default() {
	local forward=''
	export FW_NFT_DEFAULTS=${BATS_TEST_TMPDIR}/nftables-defaults.conf
	[[ ${3:-} != forward ]] || forward='\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n\t}\n'
	printf '#!/usr/sbin/nft -f\nflush ruleset\ntable inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n%b}\ninclude "%s/*.nft"\n' \
		"${forward}" "${FW_NFT_FILE%/*}" >"${FW_NFT_CONF}"
	chmod 0755 "${FW_NFT_CONF}"
	printf '# A comment\n%s %s /etc/%s %s\n' "$1" "$2" "${FW_NFT_CONF##*/}" "$(sha256sum "${FW_NFT_CONF}" | cut -d ' ' -f 1)" \
		>"${FW_NFT_DEFAULTS}"
}

@test "fw_enable replaces the unchanged default of the distribution by a configuration that loads only lss's table" {
	export LSS_FIREWALL=nftables
	OS_ID=alpine
	OS_VERSION=3.24.2
	OS_NAME='Alpine Linux v3.24'
	records
	distro_default alpine 3.24
	local original
	original=$(<"${FW_NFT_CONF}")
	fw_enable
	# The default is saved with a time stamp, then replaced: the include of lss, no flush, no other table.
	local -a backups=("${FW_NFT_CONF}".lss-*)
	[ "${#backups[@]}" -eq 1 ]
	[ "$(<"${backups[0]}")" = "${original}" ]
	grep -qxF "include \"${FW_NFT_FILE}\"" "${FW_NFT_CONF}"
	run ! grep -q -e '^[[:space:]]*flush' -e '^[[:space:]]*table' -e '\*\.nft' "${FW_NFT_CONF}"
	head -n 1 "${FW_NFT_CONF}" | grep -q '^# Managed by lss (module firewall)\.'
	# The table of the default that is loaded now goes; lss's rules are loaded and the service is enabled.
	grep -qxF 'nft delete table inet filter' "${STUB_LOG}"
	grep -qxF "nft -f ${FW_NFT_FILE}" "${STUB_LOG}"
	grep -q 'systemctl enable --now nftables' "${STUB_LOG}"
	# Again: lss's own configuration stays, nothing is saved or deleted a second time.
	: >"${STUB_LOG}"
	fw_enable
	backups=("${FW_NFT_CONF}".lss-*)
	[ "${#backups[@]}" -eq 1 ]
	run ! grep -q 'nft delete' "${STUB_LOG}"
	[ "$(grep -c include "${FW_NFT_CONF}")" -eq 1 ]
	# A configuration that is missing is written as well.
	rm -f -- "${FW_NFT_CONF}"
	fw_enable
	grep -qxF "include \"${FW_NFT_FILE}\"" "${FW_NFT_CONF}"
	# Refused rules stop the run.
	STUB_EXIT_nft=1 run fw_enable
	[ "${status}" -eq 1 ]
	[[ ${output} == *"nftables does not take the rules"* ]]
}

@test "a default is recognised by its checksum, the ID and the version of the system" {
	OS_ID=alpine
	distro_default alpine 3.24
	OS_VERSION=3.24.2
	_fw_nft_is_default "${FW_NFT_CONF}"
	OS_VERSION=3.24
	_fw_nft_is_default "${FW_NFT_CONF}"
	OS_VERSION=3.240.1
	run ! _fw_nft_is_default "${FW_NFT_CONF}"
	OS_VERSION=3.23.4
	run ! _fw_nft_is_default "${FW_NFT_CONF}"
	OS_ID=arch
	OS_VERSION=''
	run ! _fw_nft_is_default "${FW_NFT_CONF}"
	distro_default arch '*'
	_fw_nft_is_default "${FW_NFT_CONF}"
	# One changed byte and it is the administrator's file.
	printf '# mine\n' >>"${FW_NFT_CONF}"
	run ! _fw_nft_is_default "${FW_NFT_CONF}"
}

@test "fw_enable stops at every changed configuration before it loads anything" {
	export LSS_FIREWALL=nftables
	OS_ID=alpine
	OS_VERSION=3.24.2
	OS_NAME='Alpine Linux v3.24'
	local before conf
	# Changed, with or without an include of lss: the run stops, the file stays and nothing is deleted or loaded.
	for conf in 'include "%s/*.nft"
table inet mine {
}
' '#!/usr/sbin/nft -f
flush ruleset
table inet filter {
}
'; do
		distro_default alpine 3.24
		# shellcheck disable=SC2059 # the format is the content
		printf "${conf}" "${FW_NFT_FILE%/*}" >"${FW_NFT_CONF}"
		before=$(<"${FW_NFT_CONF}")
		: >"${STUB_LOG}"
		run fw_enable
		[ "${status}" -eq 1 ]
		[[ ${output} == *"firewall: lss leaves ${FW_NFT_CONF} as it is: it is not the unchanged default of Alpine Linux v3.24."* ]]
		[[ ${output} == *"Move the file away (keep your own rules elsewhere), and lss writes a configuration"* ]]
		[ "$(<"${FW_NFT_CONF}")" = "${before}" ]
		run ! grep -q -e 'nft delete' -e 'enable --now nftables' "${STUB_LOG}"
	done
	# The unchanged default, but the administrator's rules sit in the directory it loads: the run stops as well.
	distro_default alpine 3.24
	mkdir -p "${FW_NFT_FILE%/*}"
	printf 'table inet mine {
}
' >"${FW_NFT_FILE%/*}/mine.nft"
	run fw_enable
	[ "${status}" -eq 1 ]
	[[ ${output} == *"it loads ${FW_NFT_FILE%/*}/mine.nft as well, which lss's configuration would leave out"* ]]
	local -a backups=("${FW_NFT_CONF}".lss-*)
	[ ! -e "${backups[0]}" ]
}

@test "a default with the include line an older lss appended counts as the default and is replaced" {
	export LSS_FIREWALL=nftables
	OS_ID=arch
	OS_VERSION=''
	distro_default arch '*'
	printf 'include "%s"
' "${FW_NFT_FILE}" >>"${FW_NFT_CONF}"
	_fw_nft_is_default "${FW_NFT_CONF}"
	fw_enable
	_fw_nft_is_own "${FW_NFT_CONF}"
	grep -qxF 'nft delete table inet filter' "${STUB_LOG}"
	# Another line after the default is a change.
	distro_default arch '*'
	printf 'tcp dport 2222 accept
' >>"${FW_NFT_CONF}"
	run ! _fw_nft_is_default "${FW_NFT_CONF}"
}

@test "fw_disable leaves lss's configuration of the service without the include" {
	export LSS_FIREWALL=nftables
	fw_enable
	grep -qxF "include \"${FW_NFT_FILE}\"" "${FW_NFT_CONF}"
	fw_disable
	_fw_nft_is_own "${FW_NFT_CONF}"
	run ! grep -q include "${FW_NFT_CONF}"
	fw_enable
	grep -qxF "include \"${FW_NFT_FILE}\"" "${FW_NFT_CONF}"
}

@test "an input chain of another table with policy drop is found, lss's own is not" {
	export LSS_FIREWALL=nftables
	# shellcheck disable=SC2329 # called by fw_nft_foreign_drop
	nft() {
		[[ $* == 'list chains' ]] || return 0
		printf '%s\n' 'table inet filter {' '	chain input {' \
			'		type filter hook input priority filter; policy drop;' '	}' '	chain output {' \
			'		type filter hook output priority filter; policy drop;' '	}' '}' 'table ip nat {' '	chain prerouting {' \
			'		type nat hook prerouting priority dstnat; policy accept;' '	}' '}' 'table inet lss {' '	chain input {' \
			'		type filter hook input priority filter; policy drop;' '	}' '}' 'table inet docker {' '	chain input {' \
			'		type filter hook input priority filter; policy accept;' '	}' '}'
	}
	[ "$(fw_nft_foreign_drop)" = 'inet filter input' ]
	# shellcheck source=modules/security/firewall.sh
	source "${REPO_ROOT}/modules/security/firewall.sh"
	run _fw_no_foreign_drop
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the input chain inet filter input of another nftables table drops by default (policy drop)"* ]]
	# The SSH rule of lss does not count while that chain drops.
	# shellcheck disable=SC2329 # called by _fw_is_open
	nft() {
		case $* in
		'list table inet lss') printf '\t\ttcp dport 22 accept\n' ;;
		'list chains') printf 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n' ;;
		*) ;;
		esac
	}
	run ! _fw_is_open 22
	# shellcheck disable=SC2329 # called by _fw_is_open
	nft() {
		[[ $* != 'list table inet lss' ]] || printf '\t\ttcp dport 22 accept\n'
		return 0
	}
	_fw_is_open 22
	_fw_no_foreign_drop
	run ! _fw_is_open 443
}

@test "every default configuration in data/nftables-defaults.conf names a system, a file below /etc and a SHA-256" {
	local id version file checksum count=0
	while read -r id version file checksum; do
		[[ -n ${id} && ${id} != '#'* ]] || continue
		[[ ${id} =~ ^[a-z]+$ && ${version} =~ ^([0-9]+(\.[0-9]+)?|\*)$ && ${file} == /etc/* && ${checksum} =~ ^[0-9a-f]{64}$ ]]
		count=$((count + 1))
	done <"${REPO_ROOT}/data/nftables-defaults.conf"
	((count > 0))
	# Alpine and Arch, whose defaults drop input, are there.
	grep -q '^alpine 3\.24 /etc/nftables.nft ' "${REPO_ROOT}/data/nftables-defaults.conf"
	grep -q '^arch \* /etc/nftables.conf ' "${REPO_ROOT}/data/nftables-defaults.conf"
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
	run fw_rollback_arm 1m
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the rollback needs a number of seconds, got '1m'."* ]]
}

# gone PID: the process has ended (a child of the test that nobody waited for stays a zombie until the test ends).
gone() {
	[[ ! -e /proc/$1 ]] || grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
}

# rollback_job: the process ID of the rollback job, once its shell runs (the PID file exists before the exec).
rollback_job() {
	local pid i
	pid=$(<"${FW_RUN_DIR}/firewall-rollback.pid")
	for ((i = 0; i < 50; i++)); do
		tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null | grep -qF ': lss-firewall-rollback;' && break
		sleep 0.1
	done
	printf '%s' "${pid}"
}

@test "without systemd the rollback is a job of its own that cancelling stops, and it fires when nobody does" {
	export SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 22' LSS_FIREWALL=nftables LSS_INIT=openrc
	export FW_RUN_DIR=${BATS_TEST_TMPDIR}/run
	# The lock of the run (descriptor 9) stays with lss: a run after a failed one must not wait for the rollback.
	exec 9>"${BATS_TEST_TMPDIR}/lock"
	fw_rollback_arm 600 2>/dev/null
	exec 9>&-
	run ! grep -q -e systemd-run -e systemctl "${STUB_LOG}"
	local pid
	pid=$(rollback_job)
	[ ! -e "/proc/${pid}/fd/9" ]
	[ ! -e "/proc/${pid}/fd/3" ]
	tr '\0' ' ' <"/proc/${pid}/cmdline" | grep -qF ': lss-firewall-rollback; sleep 600; nft delete table inet lss;'
	[ "$(stat -c '%a' "${FW_RUN_DIR}")" = 700 ]
	fw_rollback_cancel
	local i
	for ((i = 0; i < 50; i++)); do
		gone "${pid}" && break
		sleep 0.1
	done
	gone "${pid}"
	[ ! -e "${FW_RUN_DIR}/firewall-rollback.pid" ]
	run ! grep -q 'nft delete' "${STUB_LOG}"
	# A process ID that is not the job (left from before a reboot) is not killed; the file goes.
	sleep 600 3>&- &
	local other=$!
	printf '%s\n' "${other}" >"${FW_RUN_DIR}/firewall-rollback.pid"
	fw_rollback_cancel
	kill -0 "${other}"
	kill "${other}"
	[ ! -e "${FW_RUN_DIR}/firewall-rollback.pid" ]
	# Nobody cancels: after a second the table of lss goes (the stub nft records it) and the job removes its file.
	fw_rollback_arm 1 2>/dev/null
	for ((i = 0; i < 100; i++)); do
		grep -qxF 'nft delete table inet lss' "${STUB_LOG}" && [[ ! -e ${FW_RUN_DIR}/firewall-rollback.pid ]] && break
		sleep 0.1
	done
	grep -qxF 'nft delete table inet lss' "${STUB_LOG}"
	[ ! -e "${FW_RUN_DIR}/firewall-rollback.pid" ]
	# firewalld without systemd is stopped through its init script.
	: >"${STUB_LOG}"
	export LSS_FIREWALL=firewalld
	fw_rollback_arm 600 2>/dev/null
	pid=$(rollback_job)
	tr '\0' ' ' <"/proc/${pid}/cmdline" | grep -qF 'sleep 600; rc-service firewalld stop || service firewalld stop;'
	fw_rollback_cancel
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

@test "fw_enable warns when the default it replaces dropped forwarded packets, and only then" {
	export LSS_FIREWALL=nftables
	OS_ID=alpine
	OS_VERSION=3.24.2
	OS_NAME='Alpine Linux v3.24'
	records
	distro_default alpine 3.24 forward
	run fw_enable
	[ "${status}" -eq 0 ]
	[[ ${output} == *"dropped forwarded packets (chain forward, policy drop); lss's table has no forward chain"* ]]
	# The default without a forward chain: nothing to warn about.
	rm -f -- "${FW_NFT_CONF}".lss-* "${FW_NFT_CONF}"
	distro_default alpine 3.24
	run fw_enable
	[ "${status}" -eq 0 ]
	[[ ${output} != *"forwarded packets"* ]]
}

@test "the header of lss's nftables configuration claims no saved default" {
	[[ $(_fw_nft_conf_content on) == *"If it replaced a default of the distribution, a copy is next"* ]]
	[[ $(_fw_nft_conf_content on) != *"lss saved the default"* ]]
}

@test "fw_nft_conf is FW_NFT_CONF, else the file the nftables service of the family loads" {
	[ "$(fw_nft_conf)" = "${FW_NFT_CONF}" ]
	FW_NFT_CONF=
	OS_FAMILY=alpine
	[ "$(fw_nft_conf)" = /etc/nftables.nft ]
	OS_FAMILY=rhel
	[ "$(fw_nft_conf)" = /etc/sysconfig/nftables.conf ]
	for OS_FAMILY in debian arch suse; do
		[ "$(fw_nft_conf)" = /etc/nftables.conf ]
	done
}

@test "without systemd and without setsid the rollback is a job under nohup alone" {
	export SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 22' LSS_FIREWALL=nftables LSS_INIT=openrc
	export FW_RUN_DIR=${BATS_TEST_TMPDIR}/run
	# shellcheck disable=SC2329 # hides setsid from fw_rollback_arm
	type() {
		[[ $1 == -P && $2 == setsid ]] && return 1
		builtin type "$@"
	}
	fw_rollback_arm 600 2>/dev/null
	unset -f type
	local pid i
	pid=$(rollback_job)
	tr '\0' ' ' <"/proc/${pid}/cmdline" | grep -qF ': lss-firewall-rollback; sleep 600; nft delete table inet lss;'
	fw_rollback_cancel
	for ((i = 0; i < 50; i++)); do
		gone "${pid}" && break
		sleep 0.1
	done
	gone "${pid}"
	[ ! -e "${FW_RUN_DIR}/firewall-rollback.pid" ]
	run ! grep -q 'nft delete' "${STUB_LOG}"
}

# module_stubs: the module firewall with everything around mod_configure replaced by recorders in $STUB_LOG.
module_stubs() {
	# shellcheck source=modules/security/firewall.sh
	source "${REPO_ROOT}/modules/security/firewall.sh"
	# shellcheck disable=SC2329 # called by mod_configure
	opt() { :; }
	# shellcheck disable=SC2329 # called by mod_configure
	opt_int() { printf '120'; }
	# shellcheck disable=SC2329 # called by mod_configure
	fw_ssh_port() { printf '22'; }
	# shellcheck disable=SC2329 # called by mod_configure
	fw_allow() { printf 'allow %s\n' "$1" >>"${STUB_LOG}"; }
	# shellcheck disable=SC2329 # called by mod_configure
	fw_apply_all() { return 0; }
	# shellcheck disable=SC2329 # called by mod_configure
	fw_rollback_arm() { printf 'arm %s\n' "$1" >>"${STUB_LOG}"; }
	# shellcheck disable=SC2329 # called by mod_configure
	fw_rollback_cancel() { printf 'cancel\n' >>"${STUB_LOG}"; }
	# shellcheck disable=SC2329 # called by mod_configure
	fw_enable() { printf 'enable\n' >>"${STUB_LOG}"; }
	# shellcheck disable=SC2329 # called by mod_configure
	_fw_is_open() { printf 'open %s\n' "$1" >>"${STUB_LOG}"; }
}

@test "mod_configure switches nftables on through fw_enable inside the rollback window and keeps it up to date" {
	export LSS_FIREWALL=nftables
	module_stubs
	# shellcheck disable=SC2329 # called by mod_configure
	fw_is_enabled() { return 1; }
	mod_configure
	[ "$(grep -E '^(allow|arm|enable|open|cancel)' "${STUB_LOG}" | paste -sd ' ' -)" = 'allow 22/tcp arm 120 enable open 22 cancel' ]
	# Already on: no rollback window, but fw_enable brings the configuration up to date.
	: >"${STUB_LOG}"
	# shellcheck disable=SC2329 # called by mod_configure
	fw_is_enabled() { return 0; }
	mod_configure
	[ "$(grep -E '^(allow|arm|enable|open|cancel)' "${STUB_LOG}" | paste -sd ' ' -)" = 'allow 22/tcp enable' ]
}

@test "mod_configure and mod_verify fail while another table drops input, and the rollback stays armed" {
	export LSS_FIREWALL=nftables
	module_stubs
	# shellcheck disable=SC2329 # called by _fw_no_foreign_drop
	nft() {
		[[ $* == 'list chains' ]] || return 0
		printf '%s\n' 'table inet filter {' '	chain input {' '		type filter hook input priority filter; policy drop;' '	}' '}'
	}
	# shellcheck disable=SC2329 # called by mod_configure
	fw_is_enabled() { return 1; }
	run mod_configure
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the input chain inet filter input of another nftables table drops by default"* ]]
	run ! grep -qx -e cancel -e 'open 22' "${STUB_LOG}"
	# shellcheck disable=SC2329 # called by mod_verify
	fw_is_enabled() { return 0; }
	run mod_verify
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the input chain inet filter input of another nftables table drops by default"* ]]
}
