# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Package management with the package manager of the system (pkg_backend): apt (Debian, Ubuntu), dnf (RHEL 8 and
# later), yum (RHEL 7 and older), zypper (openSUSE, SLES), apk (Alpine) and pacman (Arch). Only packages that are
# missing are installed, so a second run changes nothing.

LSS_PKG_UPDATED=${LSS_PKG_UPDATED:-0}

# pkg_backend: the package manager of the detected system (from OS_FAMILY and, for the RHEL family, OS_MAJOR).
pkg_backend() {
	case ${OS_FAMILY} in
	debian) printf 'apt' ;;
	rhel)
		if [[ ${OS_MAJOR} =~ ^[0-9]+$ ]] && ((OS_MAJOR < 8)); then
			printf 'yum'
		else
			printf 'dnf'
		fi
		;;
	suse) printf 'zypper' ;;
	alpine) printf 'apk' ;;
	arch) printf 'pacman' ;;
	*)
		log_error "The package manager of ${OS_NAME:-${OS_ID:-this system}} (family ${OS_FAMILY:-unknown}) is unknown to lss."
		return 1
		;;
	esac
	return 0
}

# DPkg::Lock::Timeout waits for unattended-upgrades or apt-daily instead of failing on their lock; they start on
# their own on a fresh server and as soon as the auto-updates module enables them.
# The filter drops the notices that report nothing to do: the needrestart summaries and the man-db trigger on images
# that switched off man-db/auto-update, and adduser skipping the home directory of a package's system user. Errors and
# everything else stay in the log.
_pkg_apt() {
	DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -y -q -o DPkg::Lock::Timeout=600 \
		-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" 2>&1 |
		sed -E '/^(No (services|containers) need to be restarted\.|No user sessions are running outdated binaries\.|No VM guests are running outdated hypervisor|Not building database; man-db\/auto-update is not|Not creating (home directory )?`)/d'
	return "${PIPESTATUS[0]}"
}

# Third-party archives (Launchpad PPAs, vendor repositories) answer 503 for minutes at a time. apt-get update only
# warns when an index cannot be fetched (W: Failed to fetch), so a package of that source looks missing; apt-get
# install fails on the first archive it cannot download. Both are tried again; apt changes nothing when a download
# fails. A warning that stays after the last attempt is left to the caller, as apt-get itself does.
PKG_APT_DELAY=30
_pkg_apt_retry() {
	local attempt output status
	for attempt in 1 2 3; do
		status=0
		output=$(_pkg_apt "$@") || status=$?
		[[ -z ${output} ]] || printf '%s\n' "${output}"
		if ((status == 0 && attempt < 3)) && grep -qE '^[WE]: Failed to fetch' <<<"${output}"; then
			status=1
		fi
		((status != 0)) || return 0
		((attempt < 3)) || break
		printf 'apt-get %s failed (attempt %s of 3); trying again in %s seconds.\n' "$1" "${attempt}" "${PKG_APT_DELAY}"
		sleep "${PKG_APT_DELAY}"
	done
	return "${status}"
}

# Mirrors drop out for minutes at a time, and dnf, yum, zypper, apk and pacman give up on the first broken one, so a
# failed command is tried again with fresh metadata. None of them changes anything when a transaction fails.
PKG_RETRY_DELAY=20

# _pkg_retry TOOL REFRESH RUN ARG...: RUN ARG... up to three times; before each new attempt REFRESH fetches fresh
# metadata and the run waits PKG_RETRY_DELAY seconds.
_pkg_retry() {
	local tool=$1 refresh=$2 run=$3 attempt
	shift 3
	for attempt in 1 2 3; do
		"${run}" "$@" && return 0
		((attempt < 3)) || break
		printf '%s %s failed (attempt %s of 3); trying again in %s seconds with fresh metadata.\n' \
			"${tool}" "$1" "${attempt}" "${PKG_RETRY_DELAY}"
		"${refresh}" >/dev/null 2>&1 || true
		sleep "${PKG_RETRY_DELAY}"
	done
	return 1
}

_pkg_dnf_run() {
	dnf -y -q "$@"
	return
}
_pkg_dnf_refresh() {
	dnf -q clean metadata
	return
}
_pkg_dnf() {
	_pkg_retry dnf _pkg_dnf_refresh _pkg_dnf_run "$@"
	return
}

_pkg_yum_run() {
	yum -y -q "$@"
	return
}
_pkg_yum_refresh() {
	yum -q clean metadata
	return
}
_pkg_yum() {
	_pkg_retry yum _pkg_yum_refresh _pkg_yum_run "$@"
	return
}

# zypper waits up to ZYPP_LOCK_TIMEOUT seconds for another zypper or PackageKit instead of failing on the lock. Exit
# status 102 means a reboot is needed (the update itself worked); 103 means zypper updated itself and has to run once
# more for the rest.
_pkg_zypper_run() {
	local status=0
	ZYPP_LOCK_TIMEOUT=600 zypper --non-interactive --quiet "$@" || status=$?
	if ((status == 103)); then
		status=0
		ZYPP_LOCK_TIMEOUT=600 zypper --non-interactive --quiet "$@" || status=$?
	fi
	((status != 102)) || status=0
	return "${status}"
}
_pkg_zypper_refresh() {
	ZYPP_LOCK_TIMEOUT=600 zypper --non-interactive --quiet refresh --force
	return
}
_pkg_zypper() {
	_pkg_retry zypper _pkg_zypper_refresh _pkg_zypper_run "$@"
	return
}

_pkg_apk_run() {
	apk --no-progress --quiet "$@"
	return
}
_pkg_apk_refresh() {
	apk --no-progress --quiet update
	return
}
_pkg_apk() {
	_pkg_retry apk _pkg_apk_refresh _pkg_apk_run "$@"
	return
}

# Arch supports no partial upgrades: packages are installed together with every pending update (-Syu), never after a
# bare -Sy.
_pkg_pacman_run() {
	pacman --noconfirm --noprogressbar "$@"
	return
}
_pkg_pacman_refresh() {
	pacman --noconfirm --noprogressbar -Sy
	return
}
_pkg_pacman() {
	_pkg_retry pacman _pkg_pacman_refresh _pkg_pacman_run "$@"
	return
}

# _pkg_rhel ARG...: dnf, or yum where the release has no dnf (RHEL 7 and older).
_pkg_rhel() {
	if [[ $(pkg_backend) == yum ]]; then
		_pkg_yum "$@"
	else
		_pkg_dnf "$@"
	fi
	return
}

pkg_update() {
	local backend
	backend=$(pkg_backend) || die "lss cannot manage the packages of this system."
	case ${backend} in
	apt) log_command _pkg_apt_retry update ;;
	dnf) log_command _pkg_dnf makecache ;;
	yum) log_command _pkg_yum makecache ;;
	zypper) log_command _pkg_zypper refresh ;;
	apk) log_command _pkg_apk update ;;
	*) log_command _pkg_pacman -Sy ;;
	esac
	LSS_PKG_UPDATED=1
	if [[ -n ${LSS_RUN_ID:-} ]]; then
		mkdir -p "${LSS_STATE_DIR:-/var/lib/lss}/runs/${LSS_RUN_ID}"
		: >"${LSS_STATE_DIR:-/var/lib/lss}/runs/${LSS_RUN_ID}/pkg-updated"
	fi
	return
}

# Refreshes the package index once per run (after a repository was added, call pkg_update directly).
pkg_update_once() {
	[[ ${LSS_PKG_UPDATED} == 1 ]] && return 0
	[[ -n ${LSS_RUN_ID:-} && -f ${LSS_STATE_DIR:-/var/lib/lss}/runs/${LSS_RUN_ID}/pkg-updated ]] && return 0
	pkg_update
}

# pkg_is_installed PACKAGE: the package, or with rpm and pacman a package that provides it, is installed.
pkg_is_installed() {
	local package=$1
	case $(pkg_backend 2>/dev/null) in
	apt) [[ $(dpkg-query -W -f='${Status}' "${package}" 2>/dev/null) == 'install ok installed' ]] ;;
	dnf | yum | zypper) rpm -q --whatprovides "${package}" >/dev/null 2>&1 ;;
	apk) apk info -e "${package}" >/dev/null 2>&1 ;;
	pacman) pacman -T "${package}" >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
	return
}

pkg_missing() {
	local package
	for package in "$@"; do
		pkg_is_installed "${package}" || printf '%s\n' "${package}"
	done
	return
}

pkg_install() {
	local backend
	local -a missing=()
	mapfile -t missing < <(pkg_missing "$@")
	[[ ${#missing[@]} -gt 0 ]] || return 0
	backend=$(pkg_backend) || die "lss cannot manage the packages of this system."
	log_info "Installing ${missing[*]}"
	case ${backend} in
	apt)
		pkg_update_once
		log_command _pkg_apt_retry install --no-install-recommends "${missing[@]}"
		;;
	dnf) log_command _pkg_dnf install "${missing[@]}" ;;
	yum) log_command _pkg_yum install "${missing[@]}" ;;
	zypper) log_command _pkg_zypper install --no-recommends "${missing[@]}" ;;
	apk)
		pkg_update_once
		log_command _pkg_apk add "${missing[@]}"
		;;
	*) log_command _pkg_pacman -Syu --needed "${missing[@]}" ;;
	esac
	files_note_change "installed ${missing[*]}"
}

# _pkg_family_list DEBIAN RHEL [SUSE [ALPINE [ARCH]]]: the list for the family of the system. A module that runs on
# SUSE, Alpine or Arch names their packages itself; the names differ too often to borrow those of another family.
_pkg_family_list() {
	local index
	case ${OS_FAMILY} in
	debian) index=1 ;;
	rhel) index=2 ;;
	suse) index=3 ;;
	alpine) index=4 ;;
	arch) index=5 ;;
	*) die "${LSS_MODULE:-lss}: the package names for ${OS_FAMILY:-this system} are unknown." ;;
	esac
	(($# >= index)) || die "${LSS_MODULE:-lss}: the package names for the ${OS_FAMILY} family are missing."
	printf '%s' "${!index}"
	return
}

# pkg_install_family DEBIAN RHEL [SUSE [ALPINE [ARCH]]] (space-separated lists).
pkg_install_family() {
	local packages
	local -a list=()
	packages=$(_pkg_family_list "$@") || exit 1
	read -ra list <<<"${packages}"
	[[ ${#list[@]} -eq 0 ]] || pkg_install "${list[@]}"
	return
}

pkg_remove() {
	local -a present=() package
	local backend
	for package in "$@"; do
		pkg_is_installed "${package}" && present+=("${package}")
	done
	[[ ${#present[@]} -gt 0 ]] || return 0
	backend=$(pkg_backend) || die "lss cannot manage the packages of this system."
	log_info "Removing ${present[*]}"
	case ${backend} in
	apt)
		log_command _pkg_apt purge "${present[@]}"
		log_command _pkg_apt autoremove --purge
		;;
	dnf) log_command _pkg_dnf remove "${present[@]}" ;;
	yum) log_command _pkg_yum remove "${present[@]}" ;;
	zypper) log_command _pkg_zypper remove --clean-deps "${present[@]}" ;;
	apk) log_command _pkg_apk del "${present[@]}" ;;
	*) log_command _pkg_pacman -Rns "${present[@]}" ;;
	esac
	files_note_change "removed ${present[*]}"
}

# pkg_remove_family DEBIAN RHEL [SUSE [ALPINE [ARCH]]] (space-separated lists).
pkg_remove_family() {
	local packages
	local -a list=()
	packages=$(_pkg_family_list "$@") || exit 1
	read -ra list <<<"${packages}"
	[[ ${#list[@]} -eq 0 ]] || pkg_remove "${list[@]}"
	return
}

# Installs all available updates (used by the system module). openSUSE Tumbleweed and Slowroll are rolling releases
# and take dist-upgrade; Leap and SLES take update.
pkg_upgrade() {
	local backend
	backend=$(pkg_backend) || die "lss cannot manage the packages of this system."
	case ${backend} in
	apt)
		pkg_update
		log_command _pkg_apt_retry full-upgrade
		;;
	dnf) log_command _pkg_dnf upgrade --refresh ;;
	yum) log_command _pkg_yum update ;;
	zypper)
		if [[ ${OS_ID} == opensuse-tumbleweed || ${OS_ID} == opensuse-slowroll ]]; then
			log_command _pkg_zypper dist-upgrade
		else
			log_command _pkg_zypper update
		fi
		;;
	apk)
		pkg_update
		log_command _pkg_apk upgrade
		;;
	*) log_command _pkg_pacman -Syu ;;
	esac
	return
}

# _pkg_apt_security: the upgradable packages whose new version comes from a security archive (Debian-Security,
# <codename>-security, Ubuntu ESM), from a simulated upgrade.
_pkg_apt_security() {
	_pkg_apt -s upgrade | awk '$1 == "Inst" && /[Ss]ecurity/ { print $2 }' | sort -u
	return
}

# pkg_upgrade_security: installs only the security updates. apt takes the packages a simulated upgrade gets from a
# security archive; dnf and yum use the advisory data (--security), zypper the security patches. Alpine and Arch
# publish no security classification for their packages, so they install every update.
pkg_upgrade_security() {
	local backend
	local -a packages=()
	backend=$(pkg_backend) || die "lss cannot manage the packages of this system."
	case ${backend} in
	apt)
		pkg_update
		mapfile -t packages < <(_pkg_apt_security)
		[[ ${#packages[@]} -gt 0 ]] || return 0
		log_info "Installing the security updates of ${packages[*]}"
		log_command _pkg_apt_retry install --only-upgrade "${packages[@]}"
		;;
	dnf) log_command _pkg_dnf upgrade --refresh --security ;;
	yum) log_command _pkg_yum update --security ;;
	zypper) log_command _pkg_zypper patch --category security ;;
	*)
		log_info "${backend} marks no update as a security fix; installing every update."
		pkg_upgrade
		;;
	esac
	return
}

# EPEL on the RHEL family (needed by fail2ban, aide extras, rkhunter, clamav, ...).
pkg_enable_epel() {
	os_is_rhel || return 0
	pkg_is_installed epel-release && return 0
	if [[ ${OS_ID} == rhel ]]; then
		subscription-manager repos --enable "codeready-builder-for-rhel-${OS_MAJOR}-$(uname -m)-rpms" >/dev/null 2>&1 || true
		log_command _pkg_rhel install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_MAJOR}.noarch.rpm"
	else
		dnf config-manager --set-enabled crb >/dev/null 2>&1 || true
		log_command _pkg_rhel install epel-release
	fi
	files_note_change "enabled EPEL"
}
