#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Third-party repositories on zypper, apk and pacman (lib/repo.sh), and the HTTPS rule for every backend. apt and dnf
# are covered in system.bats. The package managers are stubs (tests/fixtures/bin) that record their calls.

setup() {
	load helpers
	lss_test_setup
	PKG_RETRY_DELAY=0
	export LSS_ROOT=${BATS_TEST_TMPDIR}/root
	command mkdir -p "${LSS_ROOT}/data/repos" "${LSS_ROOT}/data/keys"
	printf 'KEYDATA\n' >"${LSS_ROOT}/data/keys/demo.asc"
	printf 'RSAKEY\n' >"${LSS_ROOT}/data/keys/demo@example.invalid-1.rsa.pub"
	APK_SUM=$(sha256sum "${LSS_ROOT}/data/keys/demo@example.invalid-1.rsa.pub" | cut -d ' ' -f 1)
	cat >"${LSS_ROOT}/data/repos/demo.conf" <<EOF
KEY=demo.asc
FINGERPRINTS=AAAA1111
SUSE_BASEURL=https://repo.example.invalid/opensuse/{{version}}
SUSE_PKG_GPGCHECK=1
SUSE_REPO_GPGCHECK=0
APK_URL=https://repo.example.invalid/alpine/v{{major_minor}}/main
APK_KEY=demo@example.invalid-1.rsa.pub
APK_KEY_SHA256=${APK_SUM}
PACMAN_REPO=demo
PACMAN_SERVER=https://repo.example.invalid/arch/\$repo/os/\$arch
EOF
	export STUB_OUT_gpg=$'pub:u:255:22:0123456789ABCDEF:1:::u:::scESC:::::ed25519:::0:\nfpr:::::::::AAAA1111:'
	export STUB_INSTALLED='gpg2 gnupg ca-certificates'
	export LSS_APK_REPOSITORIES=${BATS_TEST_TMPDIR}/apk-repositories
	export LSS_PACMAN_CONF=${BATS_TEST_TMPDIR}/pacman.conf
	printf 'https://dl-cdn.alpinelinux.org/alpine/v3.21/main\n' >"${LSS_APK_REPOSITORIES}"
	printf '[options]\nSigLevel = Required DatabaseOptional\n\n[core]\nInclude = /etc/pacman.d/mirrorlist\n' >"${LSS_PACMAN_CONF}"
	WRITES=${BATS_TEST_TMPDIR}/writes
	# shellcheck disable=SC2329 # replaces file_write of lib/files.sh
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${WRITES}"
		cat >>"${WRITES}"
		LSS_FILE_CHANGED=${TEST_FILE_CHANGED:-1}
	}
	return
}

# use_system FAMILY ID VERSION: the detected system without an os-release file.
use_system() {
	OS_FAMILY=$1
	OS_ID=$2
	OS_VERSION=$3
	OS_MAJOR=${3%%.*}
	OS_CODENAME=''
	OS_ARCH=x86_64
	LSS_PKG_UPDATED=0
	: >"${STUB_LOG}"
	rm -f -- "${WRITES}" "${LSS_STATE_DIR}/runs/${LSS_RUN_ID}/pkg-updated"
	return
}

@test "zypper gets an rpm-md repository whose key is imported into rpm" {
	use_system suse opensuse-leap 15.6
	repo_add demo
	grep -qxF '== 0644 root:root /etc/pki/rpm-gpg/lss-demo.asc' "${WRITES}"
	grep -qxF '== 0644 root:root /etc/zypp/repos.d/lss-demo.repo' "${WRITES}"
	grep -qxF 'baseurl=https://repo.example.invalid/opensuse/15.6' "${WRITES}"
	grep -qxF 'type=rpm-md' "${WRITES}"
	grep -qxF 'pkg_gpgcheck=1' "${WRITES}"
	grep -qxF 'repo_gpgcheck=0' "${WRITES}"
	grep -qxF 'gpgkey=file:///etc/pki/rpm-gpg/lss-demo.asc' "${WRITES}"
	grep -qxF 'rpm --import /etc/pki/rpm-gpg/lss-demo.asc' "${STUB_LOG}"
	grep -q '^zypper .* refresh' "${STUB_LOG}"
	# Nothing changed and the index is fresh: no import, no refresh.
	: >"${STUB_LOG}"
	TEST_FILE_CHANGED=0 repo_add demo
	run ! grep -q -e '^rpm --import' -e '^zypper' "${STUB_LOG}"
}

@test "zypper refuses a repository without a signature check or without packages" {
	use_system suse sles 15.6
	printf 'KEY=demo.asc\nFINGERPRINTS=AAAA1111\nSUSE_BASEURL=https://x.invalid\nSUSE_PKG_GPGCHECK=0\nSUSE_REPO_GPGCHECK=0\n' \
		>"${LSS_ROOT}/data/repos/unsigned.conf"
	run repo_add unsigned
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Repository unsigned checks no signature."* ]]
	printf 'KEY=demo.asc\nFINGERPRINTS=AAAA1111\n' >"${LSS_ROOT}/data/repos/none.conf"
	run repo_add none
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Repository none has no packages for sles."* ]]
	export STUB_EXIT_rpm=1
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"rpm does not take the key of repository demo."* ]]
}

@test "apk gets the RSA key under its own name and a block in /etc/apk/repositories" {
	use_system alpine alpine 3.21.2
	repo_add demo
	grep -qxF '== 0644 root:root /etc/apk/keys/demo@example.invalid-1.rsa.pub' "${WRITES}"
	grep -qxF 'RSAKEY' "${WRITES}"
	[ "$(cat "${LSS_APK_REPOSITORIES}")" = "$(printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.21/main' \
		'# BEGIN lss repository demo' 'https://repo.example.invalid/alpine/v3.21/main' '# END lss repository demo')" ]
	grep -qx 'apk --no-progress --quiet update' "${STUB_LOG}"
	# gpg is not needed for an RSA key.
	run ! grep -q '^gpg' "${STUB_LOG}"
	# A second run with fresh metadata changes nothing.
	: >"${STUB_LOG}"
	LSS_PKG_UPDATED=1 TEST_FILE_CHANGED=0 repo_add demo
	run ! grep -q '^apk --no-progress' "${STUB_LOG}"
	[ "$(grep -c 'lss repository demo' "${LSS_APK_REPOSITORIES}")" -eq 2 ]
	# Removing the repository leaves the administrator's lines alone.
	repo_remove demo
	[ "$(cat "${LSS_APK_REPOSITORIES}")" = 'https://dl-cdn.alpinelinux.org/alpine/v3.21/main' ]
}

@test "apk refuses a key with another checksum, a missing key and a key name apk cannot use" {
	use_system alpine alpine 3.21.2
	printf 'OTHER\n' >"${LSS_ROOT}/data/keys/demo@example.invalid-1.rsa.pub"
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Refusing repository demo: the key demo@example.invalid-1.rsa.pub has the SHA-256"*"not the pinned ${APK_SUM}."* ]]
	rm "${LSS_ROOT}/data/keys/demo@example.invalid-1.rsa.pub"
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the key demo@example.invalid-1.rsa.pub is missing."* ]]
	sed -i 's/^APK_KEY=.*/APK_KEY=..\/..\/etc\/passwd/' "${LSS_ROOT}/data/repos/demo.conf"
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"needs APK_KEY (a file name ending in .rsa.pub) and APK_KEY_SHA256."* ]]
	[ "$(cat "${LSS_APK_REPOSITORIES}")" = 'https://dl-cdn.alpinelinux.org/alpine/v3.21/main' ]
}

@test "the shared file must exist and must not be a symbolic link" {
	use_system alpine alpine 3.21.2
	rm "${LSS_APK_REPOSITORIES}"
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Cannot add repository demo: ${LSS_APK_REPOSITORIES} is missing."* ]]
	# Removing from a missing file is fine.
	repo_remove demo
	printf 'x\n' >"${BATS_TEST_TMPDIR}/target"
	ln -s "${BATS_TEST_TMPDIR}/target" "${LSS_APK_REPOSITORIES}"
	if [[ -L ${LSS_APK_REPOSITORIES} ]]; then
		run repo_add demo
		[ "${status}" -eq 1 ]
		[[ ${output} == *"Refusing to change ${LSS_APK_REPOSITORIES}: it is a symbolic link."* ]]
	fi
}

@test "pacman gets the key signed locally and a section that requires signed packages" {
	use_system arch arch ''
	repo_add demo
	grep -qxF '== 0644 root:root /etc/pacman.d/lss-demo.asc' "${WRITES}"
	grep -qxF 'pacman-key --add /etc/pacman.d/lss-demo.asc' "${STUB_LOG}"
	grep -qxF 'pacman-key --lsign-key AAAA1111' "${STUB_LOG}"
	grep -qxF '[demo]' "${LSS_PACMAN_CONF}"
	grep -qxF 'SigLevel = Required DatabaseOptional' "${LSS_PACMAN_CONF}"
	grep -qxF "Server = https://repo.example.invalid/arch/\$repo/os/\$arch" "${LSS_PACMAN_CONF}"
	grep -qxF '[core]' "${LSS_PACMAN_CONF}"
	grep -qxF 'pacman --noconfirm --noprogressbar -Sy' "${STUB_LOG}"
	# The key is known and nothing changed: no pacman-key, no refresh.
	: >"${STUB_LOG}"
	LSS_PKG_UPDATED=1 TEST_FILE_CHANGED=0 STUB_PACMAN_KEYS=AAAA1111 repo_add demo
	run ! grep -q -e '^pacman-key --add' -e '^pacman --noconfirm' "${STUB_LOG}"
	# A key that left the keyring is added again.
	: >"${STUB_LOG}"
	LSS_PKG_UPDATED=1 TEST_FILE_CHANGED=0 repo_add demo
	grep -qxF 'pacman-key --lsign-key AAAA1111' "${STUB_LOG}"
}

@test "pacman refuses weak signature levels, Arch's own repository names and a key pacman-key rejects" {
	use_system arch arch ''
	local level
	for level in 'Optional' 'Never' 'Required PackageOptional' 'Required TrustAll' 'DatabaseRequired'; do
		sed -i '/^PACMAN_SIGLEVEL=/d' "${LSS_ROOT}/data/repos/demo.conf"
		printf 'PACMAN_SIGLEVEL=%s\n' "${level}" >>"${LSS_ROOT}/data/repos/demo.conf"
		run repo_add demo
		[ "${status}" -eq 1 ]
		[[ ${output} == *"SigLevel '${level}' does not require signed packages."* ]]
	done
	sed -i 's/^PACMAN_SIGLEVEL=.*/PACMAN_SIGLEVEL=Required DatabaseRequired/; s/^PACMAN_REPO=.*/PACMAN_REPO=core/' \
		"${LSS_ROOT}/data/repos/demo.conf"
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"needs PACMAN_REPO, the name of its database (not one of Arch's own)."* ]]
	sed -i 's/^PACMAN_REPO=.*/PACMAN_REPO=demo/' "${LSS_ROOT}/data/repos/demo.conf"
	STUB_EXIT_pacman_key=1 run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"pacman-key does not take the key of repository demo."* ]]
	run ! grep -q '^\[demo\]' "${LSS_PACMAN_CONF}"
}

@test "pacman takes a key of its own when the vendor names one" {
	use_system arch arch ''
	printf 'PACKEY\n' >"${LSS_ROOT}/data/keys/demo-pacman.asc"
	printf 'PACMAN_KEY=demo-pacman.asc\nPACMAN_FINGERPRINTS=AAAA1111\n' >>"${LSS_ROOT}/data/repos/demo.conf"
	sed -i 's/^FINGERPRINTS=.*/FINGERPRINTS=BBBB2222/' "${LSS_ROOT}/data/repos/demo.conf"
	repo_add demo
	grep -qxF 'PACKEY' "${WRITES}"
	grep -qxF 'pacman-key --lsign-key AAAA1111' "${STUB_LOG}"
}

@test "repo_remove takes the pacman section, the keys and the files of every backend with it" {
	use_system arch arch ''
	repo_add demo
	# shellcheck disable=SC2329 # called by repo_remove
	file_remove() { printf 'file_remove %s\n' "$1" >>"${STUB_LOG}"; }
	: >"${STUB_LOG}"
	STUB_PACMAN_KEYS=AAAA1111 repo_remove demo
	run ! grep -q 'lss repository demo' "${LSS_PACMAN_CONF}"
	grep -qxF '[core]' "${LSS_PACMAN_CONF}"
	grep -qxF 'pacman-key --delete AAAA1111' "${STUB_LOG}"
	local path
	for path in /etc/pacman.d/lss-demo.asc /etc/zypp/repos.d/lss-demo.repo /etc/apk/keys/demo@example.invalid-1.rsa.pub \
		/etc/yum.repos.d/lss-demo.repo /etc/apt/sources.list.d/lss-demo.sources; do
		grep -qxF "file_remove ${path}" "${STUB_LOG}"
	done
	# A key pacman-key does not know is left alone; one it keeps is reported.
	: >"${STUB_LOG}"
	repo_remove demo
	run ! grep -q 'pacman-key --delete' "${STUB_LOG}"
	STUB_PACMAN_KEYS=AAAA1111 STUB_EXIT_pacman_key=1 run repo_remove demo
	[ "${status}" -eq 0 ]
	[[ ${output} == *"pacman-key keeps the key AAAA1111."* ]]
}

@test "every backend refuses a repository URL without HTTPS" {
	printf 'KEY=demo.asc\nFINGERPRINTS=AAAA1111\nDEB_URL=http://x.invalid\nDEB_SUITE=s\nRPM_BASEURL=http://x.invalid\n' \
		>"${LSS_ROOT}/data/repos/plain.conf"
	printf 'SUSE_BASEURL=ftp://x.invalid\nAPK_URL=http://x.invalid\nPACMAN_REPO=plain\nPACMAN_SERVER=http://x.invalid\n' \
		>>"${LSS_ROOT}/data/repos/plain.conf"
	local system
	for system in 'debian debian 12' 'rhel rocky 9' 'suse opensuse-leap 15.6' 'alpine alpine 3.21.2' 'arch arch 0'; do
		# shellcheck disable=SC2086 # three words
		use_system ${system}
		run repo_add plain
		[ "${status}" -eq 1 ]
		[[ ${output} == *"Refusing repository plain: "*"does not use HTTPS."* ]]
	done
	[ ! -e "${WRITES}" ]
}

@test "repo_add needs a package manager and a key" {
	use_system unknown unknown 1
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"lss cannot manage the packages of this system."* ]]
	use_system suse opensuse-leap 15.6
	sed -i '/^KEY=/d' "${LSS_ROOT}/data/repos/demo.conf"
	run repo_add demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Repository demo names no key."* ]]
}

@test "major_minor keeps the first two parts of the version" {
	OS_VERSION=3.21.2
	[ "$(_repo_major_minor)" = 3.21 ]
	OS_VERSION=15.6
	[ "$(_repo_major_minor)" = 15.6 ]
	OS_VERSION=12
	[ "$(_repo_major_minor)" = 12 ]
}
