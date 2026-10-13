# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Package management for apt (Debian, Ubuntu) and dnf (RHEL family). Only packages that are missing are installed,
# so a second run changes nothing.

LSS_PKG_UPDATED=${LSS_PKG_UPDATED:-0}

_pkg_apt() {
	DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -y -q \
		-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

pkg_update() {
	if os_is_debian; then
		_pkg_apt update
	else
		dnf -y -q makecache
	fi
	LSS_PKG_UPDATED=1
}

# Refreshes the package index once per run (after a repository was added, call pkg_update directly).
pkg_update_once() {
	[[ ${LSS_PKG_UPDATED} == 1 ]] || pkg_update
}

pkg_is_installed() {
	if os_is_debian; then
		[[ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null) == 'install ok installed' ]]
	else
		rpm -q --whatprovides "$1" >/dev/null 2>&1
	fi
}

pkg_missing() {
	local package
	for package in "$@"; do
		pkg_is_installed "${package}" || printf '%s\n' "${package}"
	done
}

pkg_install() {
	local -a missing=()
	mapfile -t missing < <(pkg_missing "$@")
	[[ ${#missing[@]} -gt 0 ]] || return 0
	log_info "Installing ${missing[*]}"
	if os_is_debian; then
		pkg_update_once
		_pkg_apt install --no-install-recommends "${missing[@]}"
	else
		dnf -y -q install "${missing[@]}"
	fi
	files_note_change "installed ${missing[*]}"
}

# pkg_install_family DEBIAN_PACKAGES RHEL_PACKAGES (space-separated lists).
pkg_install_family() {
	local -a list=()
	if os_is_debian; then
		read -ra list <<<"$1"
	else
		read -ra list <<<"$2"
	fi
	[[ ${#list[@]} -eq 0 ]] || pkg_install "${list[@]}"
}

pkg_remove() {
	local -a present=() package
	for package in "$@"; do
		pkg_is_installed "${package}" && present+=("${package}")
	done
	[[ ${#present[@]} -gt 0 ]] || return 0
	log_info "Removing ${present[*]}"
	if os_is_debian; then
		_pkg_apt purge "${present[@]}"
		_pkg_apt autoremove --purge
	else
		dnf -y -q remove "${present[@]}"
	fi
	files_note_change "removed ${present[*]}"
}

pkg_remove_family() {
	local -a list=()
	if os_is_debian; then
		read -ra list <<<"$1"
	else
		read -ra list <<<"$2"
	fi
	[[ ${#list[@]} -eq 0 ]] || pkg_remove "${list[@]}"
}

# Installs all available updates (used by the system module).
pkg_upgrade() {
	if os_is_debian; then
		pkg_update
		_pkg_apt full-upgrade
	else
		dnf -y -q upgrade --refresh
	fi
}

# EPEL on the RHEL family (needed by fail2ban, aide extras, rkhunter, clamav, ...).
pkg_enable_epel() {
	os_is_rhel || return 0
	pkg_is_installed epel-release && return 0
	if [[ ${OS_ID} == rhel ]]; then
		subscription-manager repos --enable "codeready-builder-for-rhel-${OS_MAJOR}-$(uname -m)-rpms" >/dev/null 2>&1 || true
		dnf -y -q install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_MAJOR}.noarch.rpm"
	else
		dnf config-manager --set-enabled crb >/dev/null 2>&1 || true
		dnf -y -q install epel-release
	fi
	files_note_change "enabled EPEL"
}
