#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Packages, services, firewall, repositories and downloads against stub commands (tests/fixtures/bin).

setup() {
	load helpers
	lss_test_setup
}

calls() {
	cat "${STUB_LOG}"
}

# --- packages ---------------------------------------------------------------------------------------------------

@test "apt installs only missing packages, non-interactively" {
	use_os debian-12
	export STUB_EXIT_dpkg_query=1
	pkg_install nginx curl
	grep -q 'apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold update' "${STUB_LOG}"
	grep -q 'install --no-install-recommends nginx curl' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 1 ]
}

@test "nothing is installed when every package is present" {
	use_os ubuntu-24.04
	export STUB_OUT_dpkg_query='install ok installed'
	pkg_install nginx
	run ! grep -q 'apt-get' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 0 ]
}

@test "dnf is used on the RHEL family and family lists pick the right names" {
	use_os rocky-9
	export STUB_EXIT_rpm=1
	pkg_install_family 'apache2' 'httpd mod_ssl'
	grep -q 'dnf -y -q install httpd mod_ssl' "${STUB_LOG}"
	run ! grep -q apache2 "${STUB_LOG}"
}

@test "remove purges only installed packages" {
	use_os debian-13
	export STUB_OUT_dpkg_query='install ok installed'
	pkg_remove fail2ban
	grep -q 'purge fail2ban' "${STUB_LOG}"
	grep -q 'autoremove --purge' "${STUB_LOG}"
}

# --- services ---------------------------------------------------------------------------------------------------

@test "enabling a running service changes nothing" {
	export STUB_ACTIVE_UNITS='nginx'
	svc_enable nginx
	run ! grep -q 'enable --now' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 0 ]
	unset STUB_ACTIVE_UNITS
	svc_enable chronyd
	grep -q 'systemctl enable --now chronyd' "${STUB_LOG}"
}

# --- firewall ---------------------------------------------------------------------------------------------------

@test "ufw: public and vpn rules, recorded once per module" {
	use_os ubuntu-24.04
	LSS_MODULE=web
	fw_allow 443/tcp 80/tcp:public 3000/tcp:vpn 5432/tcp:local
	fw_allow 443/tcp
	[ "$(grep -c 'ufw allow proto tcp from any to any port 443' "${STUB_LOG}")" = 1 ]
	grep -q 'ufw allow from 10.66.0.0/24 to any port 3000 proto tcp comment lss:web' "${STUB_LOG}"
	run ! grep -q 5432 "${STUB_LOG}"
	[ "$(cat "${LSS_STATE_DIR}/firewall/web")" = $'443/tcp\n80/tcp:public\n3000/tcp:vpn' ]
}

@test "firewalld: offline command while the service is stopped, live command while it runs" {
	use_os almalinux-10
	LSS_MODULE=mail
	fw_allow 25/tcp
	grep -q 'firewall-offline-cmd --add-port=25/tcp' "${STUB_LOG}"
	export STUB_ACTIVE_UNITS=firewalld
	fw_allow 3000/tcp:vpn
	grep -q 'firewall-cmd --permanent --add-rich-rule=rule family=ipv4 source address=10.66.0.0/24 port port=3000 protocol=tcp accept' "${STUB_LOG}"
	grep -q 'firewall-cmd --reload' "${STUB_LOG}"
}

@test "removing a module closes its ports; a failed removal keeps the record" {
	use_os ubuntu-22.04
	LSS_MODULE=web
	fw_allow 443/tcp
	export STUB_EXIT_ufw=1 STUB_OUT_ufw='ERROR: problem running iptables'
	run fw_remove_module
	[ "${status}" -eq 1 ]
	[ -f "${LSS_STATE_DIR}/firewall/web" ]
	export STUB_OUT_ufw='Could not delete non-existent rule'
	fw_remove_module
	[ ! -f "${LSS_STATE_DIR}/firewall/web" ]
}

@test "firewalld rules are removed while the service is stopped" {
	use_os rocky-9
	LSS_MODULE=web
	fw_allow 8443/tcp
	fw_remove_module
	grep -q 'firewall-offline-cmd --remove-port=8443/tcp' "${STUB_LOG}"
}

@test "without a firewall tool rules are only recorded and applied later" {
	use_os debian-12
	PATH=$(printf '%s' "${PATH}" | tr ':' '\n' | grep -v fixtures/bin | paste -sd:)
	command -v ufw >/dev/null && skip "ufw is installed on this machine"
	LSS_MODULE=web
	fw_allow 443/tcp
	[ "$(cat "${LSS_STATE_DIR}/firewall/web")" = 443/tcp ]
}

@test "invalid rules are refused" {
	use_os debian-12
	run fw_allow '22;rm -rf /'
	[ "${status}" -eq 1 ]
	run fw_allow 22/icmp
	[ "${status}" -eq 1 ]
	run fw_allow 22/tcp:world
	[ "${status}" -eq 1 ]
}

@test "the rollback timer is armed only over SSH" {
	use_os debian-12
	unset SSH_CONNECTION
	fw_rollback_arm 120
	run ! grep -q systemd-run "${STUB_LOG}"
	SSH_CONNECTION='1.2.3.4 5 6.7.8.9 22' fw_rollback_arm 120
	grep -q 'systemd-run --quiet --unit=lss-firewall-rollback --on-active=120 /bin/sh -c ufw --force disable' "${STUB_LOG}"
}

# --- repositories -----------------------------------------------------------------------------------------------

make_key() {
	export GNUPGHOME=${BATS_TEST_TMPDIR}/gnupg-$1
	mkdir -p "${GNUPGHOME}"
	chmod 700 "${GNUPGHOME}"
	gpg --batch --quiet --passphrase '' --quick-gen-key "$1 <$1@example.invalid>" ed25519 sign never
	gpg --batch --armor --export "$1@example.invalid" >"${BATS_TEST_TMPDIR}/$1.asc"
	gpg --batch --with-colons --fingerprint "$1@example.invalid" | awk -F: '$1 == "fpr" { print $10; exit }'
}

@test "a key is accepted only with the pinned fingerprint" {
	command -v gpg >/dev/null || skip "gpg not installed"
	PATH=$(printf '%s' "${PATH}" | tr ':' '\n' | grep -v fixtures/bin | paste -sd:)
	local good bad
	good=$(make_key good)
	bad=$(make_key bad)
	repo_key_verify "${BATS_TEST_TMPDIR}/good.asc" "${good}"
	run repo_key_verify "${BATS_TEST_TMPDIR}/bad.asc" "${good}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"unexpected key ${bad}"* ]]
	cat "${BATS_TEST_TMPDIR}/good.asc" "${BATS_TEST_TMPDIR}/bad.asc" >"${BATS_TEST_TMPDIR}/both.asc"
	run repo_key_verify "${BATS_TEST_TMPDIR}/both.asc" "${good}"
	[ "${status}" -eq 1 ]
	printf 'not a key\n' >"${BATS_TEST_TMPDIR}/empty.asc"
	run repo_key_verify "${BATS_TEST_TMPDIR}/empty.asc" "${good}"
	[ "${status}" -eq 1 ]
}

# --- downloads --------------------------------------------------------------------------------------------------

fake_root() {
	export LSS_ROOT=${BATS_TEST_TMPDIR}/root
	mkdir -p "${LSS_ROOT}/data"
	local sum
	sum=$(printf 'payload' | sha256sum | cut -d ' ' -f 1)
	cat >"${LSS_ROOT}/data/checksums.txt" <<EOF
# name arch sha256 url
tool x86_64 ${sum} https://example.invalid/tool-amd64
tool aarch64 0000 https://example.invalid/tool-arm64
plain any ${sum} http://example.invalid/plain
EOF
}

@test "a download is kept only with the listed checksum" {
	fake_root
	use_os debian-12
	export STUB_CURL_BODY=payload
	fetch_verified tool "${BATS_TEST_TMPDIR}/tool"
	[ "$(cat "${BATS_TEST_TMPDIR}/tool")" = payload ]
	export STUB_CURL_BODY=tampered
	rm "${BATS_TEST_TMPDIR}/tool"
	run fetch_verified tool "${BATS_TEST_TMPDIR}/tool"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Checksum mismatch for tool"* ]]
	[ ! -e "${BATS_TEST_TMPDIR}/tool" ]
	[ ! -e "${BATS_TEST_TMPDIR}/tool.part" ]
}

@test "downloads need HTTPS and an entry for the architecture" {
	fake_root
	use_os debian-12 armv7l
	run fetch_verified tool "${BATS_TEST_TMPDIR}/x"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"No checksum for tool on armv7l"* ]]
	use_os debian-12
	run fetch_verified plain "${BATS_TEST_TMPDIR}/x"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"downloads must use HTTPS"* ]]
}
