#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The package backends of lib/pkg.sh: apt, dnf, yum, zypper, apk and pacman. The package managers are stubs
# (tests/fixtures/bin) that record their calls in $STUB_LOG.

setup() {
	load helpers
	lss_test_setup
	PKG_RETRY_DELAY=0
	PKG_APT_DELAY=0
	return
}

# use_family FAMILY [MAJOR [ID]]: the detected system without an os-release file.
use_family() {
	OS_FAMILY=$1
	OS_MAJOR=${2:-9}
	OS_ID=${3:-test}
	OS_NAME="Test ${OS_FAMILY}"
	LSS_PKG_UPDATED=0
	: >"${STUB_LOG}"
	return
}

@test "the package manager follows the family, and yum serves the RHEL family before release 8" {
	use_family debian
	[ "$(pkg_backend)" = apt ]
	use_family rhel 9
	[ "$(pkg_backend)" = dnf ]
	use_family rhel 8
	[ "$(pkg_backend)" = dnf ]
	use_family rhel 7
	[ "$(pkg_backend)" = yum ]
	use_family suse
	[ "$(pkg_backend)" = zypper ]
	use_family alpine
	[ "$(pkg_backend)" = apk ]
	use_family arch
	[ "$(pkg_backend)" = pacman ]
	use_family unknown
	run pkg_backend
	[ "${status}" -eq 1 ]
	[[ ${output} == *"The package manager of Test unknown (family unknown) is unknown to lss."* ]]
	run pkg_install curl
	[ "${status}" -eq 1 ]
	[[ ${output} == *"lss cannot manage the packages of this system."* ]]
}

@test "missing packages are installed with the package manager of each family, present ones are left alone" {
	use_family rhel 9
	STUB_EXIT_rpm=1 pkg_install curl jq
	grep -qx 'dnf -y -q install curl jq' "${STUB_LOG}"
	use_family rhel 7
	STUB_EXIT_rpm=1 pkg_install curl
	grep -qx 'yum -y -q install curl' "${STUB_LOG}"
	use_family suse
	STUB_EXIT_rpm=1 pkg_install curl
	grep -qx 'zypper --non-interactive --quiet install --no-recommends curl (lock 600)' "${STUB_LOG}"
	use_family alpine
	STUB_INSTALLED=jq pkg_install curl jq
	grep -qx 'apk --no-progress --quiet update' "${STUB_LOG}"
	grep -qx 'apk --no-progress --quiet add curl' "${STUB_LOG}"
	use_family arch
	STUB_INSTALLED=jq pkg_install curl jq
	grep -qx 'pacman --noconfirm --noprogressbar -Syu --needed curl' "${STUB_LOG}"
	run ! grep -q -- '-Sy$' "${STUB_LOG}"
	# Nothing to do: no package manager runs.
	use_family arch
	STUB_INSTALLED='curl jq' pkg_install curl jq
	run ! grep -q -- '--noconfirm' "${STUB_LOG}"
	use_family suse
	pkg_install curl
	run ! grep -q '^zypper' "${STUB_LOG}"
}

@test "installed packages are removed with the package manager of each family" {
	use_family rhel 7
	pkg_remove curl
	grep -qx 'yum -y -q remove curl' "${STUB_LOG}"
	use_family suse
	pkg_remove curl
	grep -qx 'zypper --non-interactive --quiet remove --clean-deps curl (lock 600)' "${STUB_LOG}"
	use_family alpine
	STUB_INSTALLED=curl pkg_remove curl jq
	grep -qx 'apk --no-progress --quiet del curl' "${STUB_LOG}"
	use_family arch
	STUB_INSTALLED=curl pkg_remove curl
	grep -qx 'pacman --noconfirm --noprogressbar -Rns curl' "${STUB_LOG}"
	use_family alpine
	pkg_remove curl
	run ! grep -q 'del' "${STUB_LOG}"
}

@test "the package index is refreshed with the package manager of each family" {
	local family expected
	for family in 'rhel:dnf -y -q makecache' 'suse:zypper --non-interactive --quiet refresh (lock 600)' \
		'alpine:apk --no-progress --quiet update' 'arch:pacman --noconfirm --noprogressbar -Sy'; do
		use_family "${family%%:*}"
		expected=${family#*:}
		pkg_update
		grep -qxF "${expected}" "${STUB_LOG}"
		[ "${LSS_PKG_UPDATED}" = 1 ]
	done
	use_family rhel 7
	pkg_update
	grep -qx 'yum -y -q makecache' "${STUB_LOG}"
}

@test "every update: rolling openSUSE takes dist-upgrade, Leap and SLES take update" {
	use_family suse 16 opensuse-leap
	pkg_upgrade
	grep -qx 'zypper --non-interactive --quiet update (lock 600)' "${STUB_LOG}"
	use_family suse 0 opensuse-tumbleweed
	pkg_upgrade
	grep -qx 'zypper --non-interactive --quiet dist-upgrade (lock 600)' "${STUB_LOG}"
	use_family rhel 9
	pkg_upgrade
	grep -qx 'dnf -y -q upgrade --refresh' "${STUB_LOG}"
	use_family rhel 7
	pkg_upgrade
	grep -qx 'yum -y -q update' "${STUB_LOG}"
	use_family alpine
	pkg_upgrade
	grep -qx 'apk --no-progress --quiet upgrade' "${STUB_LOG}"
	use_family arch
	pkg_upgrade
	grep -qx 'pacman --noconfirm --noprogressbar -Syu' "${STUB_LOG}"
}

@test "security updates only: advisories on dnf and yum, patches on zypper, the security archive on apt" {
	use_family rhel 9
	pkg_upgrade_security
	grep -qx 'dnf -y -q upgrade --refresh --security' "${STUB_LOG}"
	use_family rhel 7
	pkg_upgrade_security
	grep -qx 'yum -y -q update --security' "${STUB_LOG}"
	use_family suse 16 opensuse-leap
	pkg_upgrade_security
	grep -qx 'zypper --non-interactive --quiet patch --category security (lock 600)' "${STUB_LOG}"
	use_family debian
	export STUB_OUT_apt_get='Inst openssl [3.0.15-1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
Inst libssl3 [3.0.15-1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
Inst tzdata [2024a-0] (2025b-0 Debian:12.12/stable [all])
Inst curl [8.5.0-2ubuntu10] (8.5.0-2ubuntu10.6 Ubuntu:24.04/noble-security [amd64])
Conf openssl (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])'
	pkg_upgrade_security
	grep -q '^apt-get .* install --only-upgrade curl libssl3 openssl$' "${STUB_LOG}"
	run ! grep -q 'tzdata' "${STUB_LOG}"
	# Nothing from a security archive: nothing is installed.
	use_family debian
	STUB_OUT_apt_get='Inst tzdata [2024a-0] (2025b-0 Debian:12.12/stable [all])'
	pkg_upgrade_security
	run ! grep -q 'install' "${STUB_LOG}"
	unset STUB_OUT_apt_get
}

@test "Alpine and Arch mark no update as a security fix and install every update" {
	use_family alpine
	run pkg_upgrade_security
	[ "${status}" -eq 0 ]
	grep -qx 'apk --no-progress --quiet upgrade' "${STUB_LOG}"
	grep -q 'apk marks no update as a security fix; installing every update.' "${LSS_LOG_FILE}"
	use_family arch
	pkg_upgrade_security
	grep -qx 'pacman --noconfirm --noprogressbar -Syu' "${STUB_LOG}"
}

@test "a failed command is tried three times with fresh metadata in between" {
	# Under run, set -e is off: the caller carries on after the failure, which lss (set -e) would not.
	use_family rhel 9
	STUB_EXIT_rpm=1 STUB_EXIT_dnf=1 run pkg_install_family 'curl' 'curl-minimal'
	[ "$(grep -c '^dnf -y -q install curl-minimal$' "${STUB_LOG}")" -eq 3 ]
	[ "$(grep -c '^dnf -q clean metadata$' "${STUB_LOG}")" -eq 2 ]
	[[ ${output} == *'dnf install failed (attempt 2 of 3); trying again in 0 seconds with fresh metadata.'* ]]
	use_family alpine
	STUB_INSTALLED=curl STUB_EXIT_apk=1 run pkg_remove curl
	[ "$(grep -c '^apk --no-progress --quiet del curl$' "${STUB_LOG}")" -eq 3 ]
	[ "$(grep -c '^apk --no-progress --quiet update$' "${STUB_LOG}")" -eq 2 ]
	use_family arch
	STUB_EXIT_pacman=1 run pkg_upgrade
	[ "$(grep -c '^pacman --noconfirm --noprogressbar -Syu$' "${STUB_LOG}")" -eq 3 ]
	[ "$(grep -c '^pacman --noconfirm --noprogressbar -Sy$' "${STUB_LOG}")" -eq 2 ]
	use_family rhel 7
	STUB_EXIT_yum=1 run pkg_update
	[ "$(grep -c '^yum -y -q makecache$' "${STUB_LOG}")" -eq 3 ]
	[ "$(grep -c '^yum -q clean metadata$' "${STUB_LOG}")" -eq 2 ]
	# The first attempt that works ends the retries.
	use_family rhel 9
	_pkg_retry dnf true true makecache
	run _pkg_retry dnf true false makecache
	[ "${status}" -eq 1 ]
}

@test "zypper: a needed reboot counts as success, a zypper that updated itself runs once more" {
	use_family suse 16 opensuse-leap
	export STUB_ZYPPER_EXITS=${BATS_TEST_TMPDIR}/zypper-exits
	printf '102\n' >"${STUB_ZYPPER_EXITS}"
	pkg_upgrade
	[ "$(grep -c 'update (lock 600)' "${STUB_LOG}")" -eq 1 ]
	use_family suse 16 opensuse-leap
	printf '103\n0\n' >"${STUB_ZYPPER_EXITS}"
	pkg_upgrade_security
	[ "$(grep -c 'patch --category security (lock 600)' "${STUB_LOG}")" -eq 2 ]
	# Any other failure is tried again after a forced refresh.
	use_family suse 16 opensuse-leap
	printf '4\n0\n0\n' >"${STUB_ZYPPER_EXITS}"
	pkg_upgrade
	[ "$(grep -c 'update (lock 600)' "${STUB_LOG}")" -eq 2 ]
	grep -qx 'zypper --non-interactive --quiet refresh --force (lock 600)' "${STUB_LOG}"
}

@test "package lists per family: SUSE, Alpine and Arch lists must be given" {
	use_family suse
	STUB_EXIT_rpm=1 pkg_install_family 'apt-name' 'rpm-name' 'suse-name' 'alpine-name' 'arch-name'
	grep -qx 'zypper --non-interactive --quiet install --no-recommends suse-name (lock 600)' "${STUB_LOG}"
	use_family alpine
	pkg_install_family 'apt-name' 'rpm-name' 'suse-name' 'alpine-name' 'arch-name'
	grep -qx 'apk --no-progress --quiet add alpine-name' "${STUB_LOG}"
	use_family arch
	pkg_install_family 'apt-name' 'rpm-name' 'suse-name' 'alpine-name' 'arch-name'
	grep -qx 'pacman --noconfirm --noprogressbar -Syu --needed arch-name' "${STUB_LOG}"
	STUB_INSTALLED=arch-name pkg_remove_family 'apt-name' 'rpm-name' 'suse-name' 'alpine-name' 'arch-name'
	grep -qx 'pacman --noconfirm --noprogressbar -Rns arch-name' "${STUB_LOG}"
	# An empty list for the family installs nothing.
	use_family alpine
	pkg_install_family 'apt-name' 'rpm-name' 'suse-name' '' 'arch-name'
	run ! grep -q 'add' "${STUB_LOG}"
	# A module that names no packages for the family stops instead of guessing.
	use_family arch
	LSS_MODULE=demo run pkg_install_family 'apt-name' 'rpm-name'
	[ "${status}" -eq 1 ]
	[[ ${output} == *'demo: the package names for the arch family are missing.'* ]]
	use_family unknown
	LSS_MODULE=demo run pkg_remove_family 'apt-name' 'rpm-name'
	[ "${status}" -eq 1 ]
	[[ ${output} == *'demo: the package names for unknown are unknown.'* ]]
}

@test "packages are found as installed by the query tool of each package manager" {
	use_family suse
	pkg_is_installed curl
	grep -qx 'rpm -q --whatprovides curl' "${STUB_LOG}"
	use_family alpine
	STUB_INSTALLED=curl pkg_is_installed curl
	run ! pkg_is_installed jq
	grep -qx 'apk info -e jq' "${STUB_LOG}"
	use_family arch
	STUB_INSTALLED=curl pkg_is_installed curl
	run ! pkg_is_installed jq
	use_family unknown
	run ! pkg_is_installed curl
	[ "$(pkg_missing curl)" = curl ]
}

@test "EPEL comes with yum where the RHEL release has no dnf" {
	use_family rhel 7 centos
	STUB_EXIT_rpm=1 pkg_enable_epel
	grep -qx 'yum -y -q install epel-release' "${STUB_LOG}"
	use_family rhel 9 rocky
	STUB_EXIT_rpm=1 pkg_enable_epel
	grep -qx 'dnf -y -q install epel-release' "${STUB_LOG}"
	use_family debian
	pkg_enable_epel
	[ ! -s "${STUB_LOG}" ]
}

@test "systems outside the matrix still get the family of their package manager" {
	local release=${BATS_TEST_TMPDIR}/os-release entry
	export LSS_OS_RELEASE=${release}
	for entry in 'opensuse-leap::suse' 'sles::suse' 'opensuse-tumbleweed::suse' 'alpine::alpine' 'arch::arch' \
		'archarm::arch' 'manjaro:arch:arch' 'geckolinux:opensuse suse:suse' 'gentoo::unknown'; do
		printf 'ID=%s\nID_LIKE="%s"\nVERSION_ID=1\nPRETTY_NAME="Test"\n' "${entry%%:*}" \
			"$(cut -d : -f 2 <<<"${entry}")" >"${release}"
		os_detect
		[ "${OS_FAMILY}" = "${entry##*:}" ]
		[ "${OS_SUPPORTED}" = 0 ]
	done
}
