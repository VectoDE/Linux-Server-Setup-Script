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
	grep -q 'apt-get -y -q -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold update' "${STUB_LOG}"
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

@test "apt output drops the notices that report nothing to do and keeps the exit status" {
	use_os ubuntu-24.04
	export STUB_OUT_apt_get=$'No services need to be restarted.\nSetting up nginx (1.24.0)\nNo containers need to be restarted.\nNo user sessions are running outdated binaries.\nNo VM guests are running outdated hypervisor (qemu) binaries on this host.\nNot building database; man-db/auto-update is not \'true\'.'
	export STUB_EXIT_apt_get=100
	run _pkg_apt install nginx
	[ "${status}" -eq 100 ]
	[ "${output}" = 'Setting up nginx (1.24.0)' ]
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

@test "dnf refreshes metadata, and the index is refreshed once per run" {
	use_os rocky-9
	pkg_update
	grep -q 'dnf -y -q makecache' "${STUB_LOG}"
	[ -f "${LSS_STATE_DIR}/runs/test-run/pkg-updated" ]
	: >"${STUB_LOG}"
	LSS_PKG_UPDATED=0
	pkg_update_once
	LSS_PKG_UPDATED=1
	pkg_update_once
	[ ! -s "${STUB_LOG}" ]
}

@test "removal on the RHEL family and family lists for removal" {
	use_os almalinux-10
	pkg_remove_family 'apache2' 'httpd'
	grep -q 'dnf -y -q remove httpd' "${STUB_LOG}"
	use_os debian-12
	export STUB_OUT_dpkg_query='install ok installed'
	pkg_remove_family 'apache2' 'httpd'
	grep -q 'purge apache2' "${STUB_LOG}"
	unset STUB_OUT_dpkg_query
	: >"${STUB_LOG}"
	pkg_remove nginx
	pkg_install_family '' 'httpd'
	run ! grep -q apt-get "${STUB_LOG}"
	[ "$(files_changes_of core)" = 2 ]
}

@test "upgrades use the tool of the family" {
	use_os ubuntu-24.04
	pkg_upgrade
	grep -q 'apt-get -y -q .* update' "${STUB_LOG}"
	grep -q 'apt-get -y -q .* full-upgrade' "${STUB_LOG}"
	use_os rhel-9
	pkg_upgrade
	grep -q 'dnf -y -q upgrade --refresh' "${STUB_LOG}"
}

@test "EPEL is enabled once, with CRB or CodeReady Builder" {
	use_os debian-12
	pkg_enable_epel
	[ ! -s "${STUB_LOG}" ]
	use_os rocky-9
	pkg_enable_epel
	run ! grep -q dnf "${STUB_LOG}"
	export STUB_EXIT_rpm=1
	pkg_enable_epel
	grep -q 'dnf config-manager --set-enabled crb' "${STUB_LOG}"
	grep -q 'dnf -y -q install epel-release' "${STUB_LOG}"
	use_os rhel-9
	pkg_enable_epel
	grep -q 'subscription-manager repos --enable codeready-builder-for-rhel-9-' "${STUB_LOG}"
	grep -q 'dnf -y -q install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 2 ]
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

@test "service queries follow systemctl" {
	export STUB_ACTIVE_UNITS='nginx'
	svc_exists nginx
	svc_is_active nginx
	svc_is_enabled nginx
	run ! svc_exists nope
	run ! svc_is_active nope
	run ! svc_is_enabled nope
}

@test "a unit that does not start stops the run" {
	export STUB_EXIT_systemctl=1
	run svc_enable broken
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Could not start broken."* ]]
	grep -q 'systemctl status --no-pager broken' "${STUB_LOG}"
}

@test "disable only touches existing units that are enabled or running" {
	svc_disable nope
	run ! grep -q 'disable --now' "${STUB_LOG}"
	export STUB_ACTIVE_UNITS='rpcbind'
	svc_disable rpcbind
	grep -q 'systemctl disable --now rpcbind' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 1 ]
}

@test "restart and reload show the unit status on failure" {
	svc_restart nginx
	svc_reload nginx
	svc_daemon_reload
	grep -q 'systemctl restart nginx' "${STUB_LOG}"
	grep -q 'systemctl reload-or-restart nginx' "${STUB_LOG}"
	grep -q 'systemctl daemon-reload' "${STUB_LOG}"
	export STUB_EXIT_systemctl=1
	run svc_restart nginx
	[ "${status}" -eq 1 ]
	grep -q 'journalctl -u nginx -n 30 --no-pager' "${STUB_LOG}"
	run svc_reload nginx
	[ "${status}" -eq 1 ]
	[ "$(grep -c 'systemctl status --no-pager nginx' "${STUB_LOG}")" = 2 ]
}

# Replaces file_write for code that writes below /etc: records "== MODE OWNER DEST" and the content in
# $BATS_TEST_TMPDIR/writes and reports a change unless TEST_FILE_CHANGED=0.
record_writes() {
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${BATS_TEST_TMPDIR}/writes"
		cat >>"${BATS_TEST_TMPDIR}/writes"
		LSS_FILE_CHANGED=${TEST_FILE_CHANGED:-1}
	}
}

@test "drop-ins are managed files and reload systemd only when changed" {
	record_writes
	svc_dropin nginx.service lss <<<"[Service]"
	grep -qxF '== 0644 root:root /etc/systemd/system/nginx.service.d/lss.conf' "${BATS_TEST_TMPDIR}/writes"
	grep -qxF '[Service]' "${BATS_TEST_TMPDIR}/writes"
	grep -q 'systemctl daemon-reload' "${STUB_LOG}"
	: >"${STUB_LOG}"
	TEST_FILE_CHANGED=0 svc_dropin nginx.service lss <<<"[Service]"
	svc_dropin_remove nginx.service never-written
	run ! grep -q daemon-reload "${STUB_LOG}"
}

@test "removing a drop-in deletes it with a backup and reloads systemd" {
	[ -d /etc/systemd/system ] || skip "no /etc/systemd/system on this machine"
	# The unit name leads back into the test directory, so a real file is removed without root.
	mkdir -p "${BATS_TEST_TMPDIR}/demo.service.d"
	printf 'x\n' >"${BATS_TEST_TMPDIR}/demo.service.d/lss.conf"
	svc_dropin_remove "../../..${BATS_TEST_TMPDIR}/demo.service" lss
	[ ! -e "${BATS_TEST_TMPDIR}/demo.service.d" ]
	grep -q 'systemctl daemon-reload' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 1 ]
}

@test "waiting for a port gives up after the timeout" {
	run ! svc_wait_port 127.0.0.1 1 1
}

@test "waiting for a port returns once it accepts connections" {
	command -v python3 >/dev/null || skip "python3 not installed"
	local port_file=${BATS_TEST_TMPDIR}/port port='' pid i
	python3 -c 'import socket, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(5)
print(s.getsockname()[1], flush=True)
time.sleep(30)' >"${port_file}" 2>/dev/null 3>&- &
	pid=$!
	for ((i = 0; i < 50; i++)); do
		port=$(cat "${port_file}")
		[ -z "${port}" ] || break
		sleep 0.1
	done
	svc_wait_port 127.0.0.1 "${port}" 5
	kill "${pid}"
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

@test "the rollback on the RHEL family stops firewalld and can be cancelled" {
	use_os rocky-9
	SSH_CONNECTION='1.2.3.4 5 6.7.8.9 22' fw_rollback_arm 60
	grep -q 'systemd-run --quiet --unit=lss-firewall-rollback --on-active=60 /bin/sh -c systemctl stop firewalld' "${STUB_LOG}"
	fw_rollback_cancel
	grep -q 'systemctl reset-failed lss-firewall-rollback.service' "${STUB_LOG}"
}

@test "the firewall counts as enabled when ufw is active or firewalld runs" {
	use_os debian-12
	run ! fw_is_enabled
	export STUB_OUT_ufw='Status: active'
	fw_is_enabled
	use_os rocky-9
	run ! fw_is_enabled
	export STUB_ACTIVE_UNITS=firewalld
	fw_is_enabled
}

@test "recorded rules of every module are applied when the firewall arrives" {
	use_os ubuntu-24.04
	mkdir -p "${LSS_STATE_DIR}/firewall/not-a-registry"
	printf '443/tcp\n\n3000/tcp:vpn\n' >"${LSS_STATE_DIR}/firewall/web"
	printf '6000-6010/udp\n' >"${LSS_STATE_DIR}/firewall/mail"
	fw_apply_all
	grep -q 'ufw allow proto tcp from any to any port 443 comment lss:web' "${STUB_LOG}"
	grep -q 'ufw allow from 10.66.0.0/24 to any port 3000 proto tcp comment lss:web' "${STUB_LOG}"
	grep -q 'ufw allow proto udp from any to any port 6000:6010 comment lss:mail' "${STUB_LOG}"
}

@test "vpn rules are removed with the rule they were added with" {
	use_os debian-12
	LSS_MODULE=app
	fw_remove_module
	fw_allow 3000/tcp:vpn
	fw_remove_module
	grep -q 'ufw delete allow from 10.66.0.0/24 to any port 3000 proto tcp' "${STUB_LOG}"
	[ ! -e "${LSS_STATE_DIR}/firewall/app" ]
}

@test "a firewalld error stops the run" {
	use_os rocky-9
	export STUB_EXIT_firewall_offline_cmd=1 STUB_OUT_firewall_offline_cmd='Error: INVALID_PORT'
	run fw_allow 25/tcp
	[ "${status}" -eq 1 ]
	[[ ${output} == *"firewalld: Error: INVALID_PORT"* ]]
	run fw_allow 3000/tcp:vpn
	[ "${status}" -eq 1 ]
}

@test "the SSH port comes from the effective sshd configuration" {
	export STUB_OUT_sshd=$'addressfamily any\nport 2222\nport 22'
	[ "$(fw_ssh_port)" = 2222 ]
	unset STUB_OUT_sshd
	[ "$(fw_ssh_port)" = 22 ]
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
	PATH=$(printf '%s' "${PATH}" | tr ':' '\n' | grep -v fixtures/bin | paste -sd:)
	command -v gpg >/dev/null || skip "gpg not installed"
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

# A repository root with data/repos/demo.conf (both families) and empty.conf (no packages), the gpg stub listing the
# pinned key, all packages present and no directories created below /etc.
repo_root() {
	export LSS_ROOT=${BATS_TEST_TMPDIR}/root
	command mkdir -p "${LSS_ROOT}/data/repos" "${LSS_ROOT}/data/keys"
	printf 'KEYDATA\n' >"${LSS_ROOT}/data/keys/demo.asc"
	cat >"${LSS_ROOT}/data/repos/demo.conf" <<'EOF'
KEY=demo.asc
FINGERPRINTS=AAAA1111 BBBB2222
DEB_URL=https://repo.example.invalid/{{id}}
DEB_SUITE={{codename}}
DEB_COMPONENTS=main
RPM_BASEURL=https://repo.example.invalid/el/{{major}}/{{arch}}
RPM_REPO_GPGCHECK=1
EOF
	printf 'KEY=demo.asc\nFINGERPRINTS=AAAA1111\n' >"${LSS_ROOT}/data/repos/empty.conf"
	export STUB_OUT_gpg=$'pub:u:255:22:0123456789ABCDEF:1:::u:::scESC:::::ed25519:::0:\nfpr:::::::::AAAA1111:\nsub:u:255:18:FEDCBA9876543210:1::::::e:::::cv25519::\nfpr:::::::::CCCC3333:'
	export STUB_OUT_dpkg_query='install ok installed'
	record_writes
	mkdir() {
		[[ ${*: -1} == /etc/* ]] || command mkdir "$@"
	}
}

@test "repository helpers read values and fill in the distribution" {
	repo_root
	use_os ubuntu-22.04 aarch64
	[ "$(_kv "${LSS_ROOT}/data/repos/demo.conf" KEY)" = demo.asc ]
	[ -z "$(_kv "${LSS_ROOT}/data/repos/demo.conf" MISSING)" ]
	[ "$(_repo_value "${LSS_ROOT}/data/repos/demo.conf" DEB_URL)" = https://repo.example.invalid/ubuntu ]
	[ "$(_repo_value "${LSS_ROOT}/data/repos/demo.conf" RPM_BASEURL)" = https://repo.example.invalid/el/22/arm64 ]
	[ "$(repo_key_fingerprints "${LSS_ROOT}/data/keys/demo.asc")" = AAAA1111 ]
}

@test "repo_add writes a Signed-By source on Debian and Ubuntu" {
	repo_root
	use_os ubuntu-24.04
	repo_add demo
	local writes=${BATS_TEST_TMPDIR}/writes
	grep -qxF '== 0644 root:root /etc/apt/keyrings/lss-demo.gpg' "${writes}"
	grep -qxF '== 0644 root:root /etc/apt/sources.list.d/lss-demo.sources' "${writes}"
	grep -qxF 'URIs: https://repo.example.invalid/ubuntu' "${writes}"
	grep -qxF 'Suites: noble' "${writes}"
	grep -qxF 'Components: main' "${writes}"
	grep -qxF 'Architectures: amd64' "${writes}"
	grep -qxF 'Signed-By: /etc/apt/keyrings/lss-demo.gpg' "${writes}"
	grep -q 'gpg --batch --dearmor' "${STUB_LOG}"
	grep -q 'apt-get .* update' "${STUB_LOG}"
	: >"${STUB_LOG}"
	TEST_FILE_CHANGED=0 repo_add demo
	run ! grep -q apt-get "${STUB_LOG}"
}

@test "repo_add writes a gpg-checked repository on the RHEL family" {
	repo_root
	use_os rocky-9
	repo_add demo
	local writes=${BATS_TEST_TMPDIR}/writes
	grep -qxF '== 0644 root:root /etc/pki/rpm-gpg/lss-demo.asc' "${writes}"
	grep -qxF 'KEYDATA' "${writes}"
	grep -qxF '== 0644 root:root /etc/yum.repos.d/lss-demo.repo' "${writes}"
	grep -qxF '[lss-demo]' "${writes}"
	grep -qxF 'baseurl=https://repo.example.invalid/el/9/amd64' "${writes}"
	grep -qxF 'repo_gpgcheck=1' "${writes}"
	grep -qxF 'gpgkey=file:///etc/pki/rpm-gpg/lss-demo.asc' "${writes}"
}

@test "repo_add uses the RPM key of vendors that sign packages with another key" {
	repo_root
	printf 'RPMKEYDATA\n' >"${LSS_ROOT}/data/keys/demo-rpm.asc"
	printf 'KEY=demo.asc\nFINGERPRINTS=BBBB2222\nRPM_KEY=demo-rpm.asc\nRPM_FINGERPRINTS=AAAA1111\n' >"${LSS_ROOT}/data/repos/split.conf"
	printf 'DEB_URL=https://repo.example.invalid\nDEB_SUITE=stable\nDEB_COMPONENTS=main\n' >>"${LSS_ROOT}/data/repos/split.conf"
	printf 'RPM_BASEURL=https://repo.example.invalid/el\n' >>"${LSS_ROOT}/data/repos/split.conf"
	use_os rocky-9
	repo_add split
	grep -qxF 'RPMKEYDATA' "${BATS_TEST_TMPDIR}/writes"
	run ! grep -qxF 'KEYDATA' "${BATS_TEST_TMPDIR}/writes"
	# The apt key is pinned to BBBB2222, which the key stub does not contain.
	use_os debian-12
	run repo_add split
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Refusing repository split"* ]]
}

@test "repo_add refuses unknown repositories, foreign keys and missing packages" {
	repo_root
	use_os debian-12
	run repo_add nope
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Unknown repository nope."* ]]
	run repo_add empty
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Repository empty has no packages for debian."* ]]
	use_os almalinux-10
	run repo_add empty
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Repository empty has no packages for almalinux."* ]]
	export STUB_OUT_gpg=$'pub:u:255:22:0123456789ABCDEF:1::::::\nfpr:::::::::DDDD4444:'
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Key demo.asc contains unexpected key DDDD4444."* ]]
	[[ ${output} == *"Refusing repository demo"* ]]
	unset STUB_OUT_gpg
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Key demo.asc contains no key."* ]]
	[ ! -e "${BATS_TEST_TMPDIR}/writes" ]
}

@test "repo_remove leaves nothing behind and changes nothing that is absent" {
	repo_remove demo
	[ "$(files_changes_of core)" = 0 ]
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

@test "a file that already matches is kept; a failed download stops" {
	fake_root
	use_os debian-12
	printf 'payload' >"${BATS_TEST_TMPDIR}/tool"
	fetch_verified tool "${BATS_TEST_TMPDIR}/tool"
	run ! grep -q curl "${STUB_LOG}"
	export STUB_EXIT_curl=22
	run fetch_verified tool "${BATS_TEST_TMPDIR}/new/tool"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Download of tool failed: https://example.invalid/tool-amd64"* ]]
	[ ! -e "${BATS_TEST_TMPDIR}/new/tool" ]
}

@test "svc_timer_skip_missed stamps only a stopped timer" {
	export LSS_SYSTEMD_TIMER_DIR=${BATS_TEST_TMPDIR}/timers
	export STUB_ACTIVE_UNITS=apt-daily.timer
	svc_timer_skip_missed apt-daily-upgrade.timer
	[ -f "${LSS_SYSTEMD_TIMER_DIR}/stamp-apt-daily-upgrade.timer" ]
	svc_timer_skip_missed apt-daily.timer
	[ ! -e "${LSS_SYSTEMD_TIMER_DIR}/stamp-apt-daily.timer" ]
	ln -s /etc/passwd "${LSS_SYSTEMD_TIMER_DIR}/stamp-other.timer"
	run svc_timer_skip_missed other.timer
	[ "${status}" -eq 1 ]
}

@test "svc_unit writes an own unit and reloads systemd only on change" {
	record_writes
	svc_unit test.swap <<<"[Swap]"
	grep -qxF '== 0644 root:root /etc/systemd/system/test.swap' "${BATS_TEST_TMPDIR}/writes"
	grep -qxF '[Swap]' "${BATS_TEST_TMPDIR}/writes"
	grep -q 'systemctl daemon-reload' "${STUB_LOG}"
	: >"${STUB_LOG}"
	TEST_FILE_CHANGED=0 svc_unit test.swap <<<"[Swap]"
	run ! grep -q 'daemon-reload' "${STUB_LOG}"
}

@test "svc_scanner_sandbox confines writes but keeps /tmp and the kernel views of the scanners" {
	run svc_scanner_sandbox strict /var/lib/aide /var/log
	[ "${status}" -eq 0 ]
	[ "${lines[0]}" = ProtectSystem=strict ]
	grep -qxF 'ProtectHome=read-only' <<<"${output}"
	grep -qxF 'NoNewPrivileges=yes' <<<"${output}"
	grep -qxF 'ReadWritePaths=-/var/lib/aide' <<<"${output}"
	grep -qxF 'ReadWritePaths=-/var/log' <<<"${output}"
	run ! grep -qE '^(PrivateTmp|ProtectKernelTunables|ProtectKernelModules|ProtectKernelLogs)=' <<<"${output}"
	run svc_scanner_sandbox full
	[ "${lines[0]}" = ProtectSystem=full ]
	run ! grep -q ReadWritePaths <<<"${output}"
}

@test "svc_scanner_sandbox lets scanners enter their SELinux domain" {
	export STUB_EXIT_selinuxenabled=0
	run svc_scanner_sandbox strict /var/lib/aide
	[ "${status}" -eq 0 ]
	grep -qxF 'NoNewPrivileges=no' <<<"${output}"
	run ! grep -qxF 'NoNewPrivileges=yes' <<<"${output}"
}

@test "svc_apparmor_confined needs an enforcing profile, from the list or the label of a running process" {
	export SVC_APPARMOR_ENABLED=${BATS_TEST_TMPDIR}/enabled SVC_APPARMOR_PROFILES=${BATS_TEST_TMPDIR}/profiles
	export SVC_PROC=${BATS_TEST_TMPDIR}/proc
	# shellcheck disable=SC2329 # called by svc_apparmor_confined
	pidof() {
		printf '%s\n' "${TEST_PIDS:-}"
		return
	}
	run svc_apparmor_confined /usr/sbin/mysqld
	[ "${status}" -eq 1 ]
	echo Y >"${SVC_APPARMOR_ENABLED}"
	# No profile list and no running process: unconfined, the full sandbox stays.
	run svc_apparmor_confined /usr/sbin/mysqld
	[ "${status}" -eq 1 ]
	mkdir -p "${SVC_PROC}/42/attr"
	echo '/usr/sbin/mysqld (complain)' >"${SVC_PROC}/42/attr/current"
	TEST_PIDS=42 run svc_apparmor_confined /usr/sbin/mysqld
	[ "${status}" -eq 1 ]
	echo '/usr/sbin/mysqld (enforce)' >"${SVC_PROC}/42/attr/current"
	TEST_PIDS=42 svc_apparmor_confined /usr/sbin/mysqld
	printf '/usr/sbin/chronyd (enforce)\n/usr/sbin/mysqld (complain)\n' >"${SVC_APPARMOR_PROFILES}"
	run svc_apparmor_confined /usr/sbin/mysqld
	[ "${status}" -eq 1 ]
	printf '/usr/sbin/mysqld (enforce)\n' >>"${SVC_APPARMOR_PROFILES}"
	svc_apparmor_confined /usr/sbin/mysqld
	[[ " ${SVC_SANDBOX_NO_MOUNTS[*]} " == *' ProtectSystem=no '*' ReadWritePaths= '* ]]
}

@test "fw_ssh_port falls back to 22 when sshd fails" {
	STUB_EXIT_sshd=255 run fw_ssh_port
	[ "${status}" -eq 0 ]
	[ "${output}" = 22 ]
	STUB_OUT_sshd=$'port 2222\nport 2223' run fw_ssh_port
	[ "${output}" = 2222 ]
}

@test "repo_add uses a per-release suite and the package signature switch" {
	repo_root
	printf 'DEB_SUITE_trixie=bookworm\nRPM_GPGCHECK=0\n' >>"${LSS_ROOT}/data/repos/demo.conf"
	use_os debian-13
	repo_add demo
	grep -qxF 'Suites: bookworm' "${BATS_TEST_TMPDIR}/writes"
	use_os rocky-9
	repo_add demo
	grep -qxF 'gpgcheck=0' "${BATS_TEST_TMPDIR}/writes"
	grep -qxF 'repo_gpgcheck=1' "${BATS_TEST_TMPDIR}/writes"
}

@test "repo_add uses a per-major base URL when the conf has one" {
	repo_root
	printf 'RPM_BASEURL_10=https://repo.example.invalid/el/9/{{arch}}\n' >>"${LSS_ROOT}/data/repos/demo.conf"
	use_os almalinux-10
	repo_add demo
	grep -qxF 'baseurl=https://repo.example.invalid/el/9/amd64' "${BATS_TEST_TMPDIR}/writes"
	: >"${BATS_TEST_TMPDIR}/writes"
	use_os rocky-9
	repo_add demo
	grep -qxF 'baseurl=https://repo.example.invalid/el/9/amd64' "${BATS_TEST_TMPDIR}/writes"
	use_os rhel-9
	printf 'RPM_BASEURL_9=https://other.example.invalid/\n' >>"${LSS_ROOT}/data/repos/demo.conf"
	repo_add demo
	grep -qxF 'baseurl=https://other.example.invalid/' "${BATS_TEST_TMPDIR}/writes"
}

@test "repo_add refuses a repository that checks no signature" {
	repo_root
	sed -i 's/^RPM_REPO_GPGCHECK=1$/RPM_REPO_GPGCHECK=0/' "${LSS_ROOT}/data/repos/demo.conf"
	printf 'RPM_GPGCHECK=0\n' >>"${LSS_ROOT}/data/repos/demo.conf"
	use_os rocky-9
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Repository demo checks no signature."* ]]
}
