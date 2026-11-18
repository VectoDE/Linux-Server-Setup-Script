# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Operating system detection. /etc/os-release is parsed line by line, never sourced. Which releases lss supports, and
# until when their vendors do, comes from the release lines of data/systems.conf (the support matrix); the system is
# found there by ID and VERSION_ID only.

LSS_OS_RELEASE=${LSS_OS_RELEASE:-/etc/os-release}
# Proxmox VE says Debian in os-release; /etc/pve (its cluster file system) and pveversion tell it apart.
LSS_PVE_DIR=${LSS_PVE_DIR:-/etc/pve}
OS_ID=''
OS_LIKE=''
OS_VERSION=''
OS_MAJOR=''
OS_CODENAME=''
OS_FAMILY=''
OS_NAME=''
OS_ARCH=''
# From the support matrix: the release is listed (1 or 0), its display name and version, the end of vendor support and
# the extended support after it.
OS_SUPPORTED=0
OS_LABEL=''
OS_EOL=''
OS_EXTENDED=''
OS_EXTENDED_UNTIL=''
# shellcheck disable=SC2034 # read by the modules of stage 9d (Proxmox VE) and the tests
OS_PROXMOX=0

_os_value() {
	local key=$1 line value
	while IFS= read -r line || [[ -n ${line} ]]; do
		[[ ${line} == "${key}="* ]] || continue
		value=${line#*=}
		value=${value#\"}
		value=${value%\"}
		value=${value#\'}
		value=${value%\'}
		printf '%s' "${value}"
		return 0
	done <"${LSS_OS_RELEASE}"
	return 0
}

os_detect() {
	[[ -r ${LSS_OS_RELEASE} ]] || die "Cannot read ${LSS_OS_RELEASE}; lss needs a systemd-based Linux distribution."
	OS_ID=$(_os_value ID)
	OS_ID=${OS_ID,,}
	OS_LIKE=$(_os_value ID_LIKE)
	OS_LIKE=${OS_LIKE,,}
	OS_VERSION=$(_os_value VERSION_ID)
	OS_MAJOR=${OS_VERSION%%.*}
	OS_CODENAME=$(_os_value VERSION_CODENAME)
	OS_NAME=$(_os_value PRETTY_NAME)
	OS_ARCH=${LSS_ARCH:-$(uname -m)}
	OS_PROXMOX=0
	if [[ -d ${LSS_PVE_DIR} ]] && command -v pveversion >/dev/null 2>&1; then
		OS_PROXMOX=1
	fi
	_os_matrix
	if [[ ${OS_SUPPORTED} != 1 ]]; then
		# Outside the matrix the family still tells the caller which backends would apply (and is "unknown" if none).
		case ${OS_ID} in
		debian | ubuntu) OS_FAMILY=debian ;;
		rhel | rocky | almalinux | centos) OS_FAMILY=rhel ;;
		*)
			if [[ " ${OS_LIKE} " == *" debian "* ]]; then
				OS_FAMILY=debian
			elif [[ " ${OS_LIKE} " == *" rhel "* || " ${OS_LIKE} " == *" fedora "* ]]; then
				OS_FAMILY=rhel
			else
				OS_FAMILY=unknown
			fi
			;;
		esac
	fi
	if [[ -z ${OS_CODENAME} && ${OS_FAMILY} == debian ]]; then
		OS_CODENAME=$(_os_value UBUNTU_CODENAME)
	fi
	return
}

# _os_systems: the support matrix.
_os_systems() {
	printf '%s' "${LSS_SYSTEMS:-${LSS_ROOT}/data/systems.conf}"
	return
}

# _os_matrix: looks the detected release up in the support matrix and sets OS_SUPPORTED, OS_FAMILY, OS_LABEL, OS_EOL,
# OS_EXTENDED and OS_EXTENDED_UNTIL. A version with a dot matches VERSION_ID as it is (Ubuntu 24.04, not 24.10), the
# others the major version (Debian 12 for 12.8, RHEL 9 for 9.5).
_os_matrix() {
	local type id name version family eol extended until
	OS_SUPPORTED=0
	OS_LABEL=''
	OS_EOL=''
	OS_EXTENDED=''
	OS_EXTENDED_UNTIL=''
	[[ -r $(_os_systems) ]] || die "Cannot read the support matrix $(_os_systems)."
	while IFS='|' read -r type id name version family eol extended until; do
		[[ ${type} == release && ${id} == "${OS_ID}" ]] || continue
		if [[ ${version} == *.* ]]; then
			[[ ${version} == "${OS_VERSION}" ]] || continue
		else
			[[ ${version} == "${OS_MAJOR}" ]] || continue
		fi
		OS_SUPPORTED=1
		OS_FAMILY=${family}
		OS_LABEL="${name} ${version}"
		OS_EOL=${eol}
		OS_EXTENDED=${extended}
		OS_EXTENDED_UNTIL=${until}
		return 0
	done <"$(_os_systems)"
	return 0
}

# os_supported_list: the supported releases of the matrix, grouped by distribution ("Debian 12, 13; Ubuntu 22.04, ...").
os_supported_list() {
	awk -F '|' '$1 == "release" {
		if (!($3 in versions)) { order[++count] = $3; versions[$3] = $4 } else { versions[$3] = versions[$3] ", " $4 }
	} END {
		for (i = 1; i <= count; i++) { printf "%s%s %s", (i > 1 ? "; " : ""), order[i], versions[order[i]] }
	}' "$(_os_systems)"
	return
}

# Prints why the detected system is not supported, or nothing.
os_unsupported_reason() {
	if [[ ${OS_SUPPORTED} != 1 ]]; then
		printf '%s is not supported. Supported: %s.' "${OS_NAME:-${OS_ID} ${OS_VERSION}}" "$(os_supported_list)"
		return 0
	fi
	case ${OS_ARCH} in
	x86_64 | aarch64) ;;
	*) printf 'Architecture %s is not supported; use x86_64 or aarch64.' "${OS_ARCH}" ;;
	esac
}

os_require_supported() {
	local reason
	reason=$(os_unsupported_reason)
	[[ -z ${reason} ]] || die "${reason}"
	return
}

# os_support_status: one line on the vendor support of the detected (supported) release. Returns 0 while the vendor
# supports it and 2 after the end of vendor support, when the line is a warning that names the extended support.
# LSS_TODAY (YYYY-MM-DD) replaces today's date in the tests.
os_support_status() {
	local today=${LSS_TODAY:-$(date -u +%F)}
	[[ -n ${OS_EOL} ]] || return 0
	if [[ ! ${today} > ${OS_EOL} ]]; then
		printf '%s: security support from the vendor until %s%s.\n' "${OS_LABEL}" "${OS_EOL}" \
			"${OS_EXTENDED:+, then ${OS_EXTENDED} until ${OS_EXTENDED_UNTIL}}"
		return 0
	fi
	if [[ -z ${OS_EXTENDED} ]]; then
		printf '%s left the security support of its vendor on %s and has no extended support; upgrade to a newer release.\n' \
			"${OS_LABEL}" "${OS_EOL}"
	elif [[ ${today} > ${OS_EXTENDED_UNTIL} ]]; then
		printf '%s left the security support of its vendor on %s and %s on %s; upgrade to a newer release.\n' \
			"${OS_LABEL}" "${OS_EOL}" "${OS_EXTENDED}" "${OS_EXTENDED_UNTIL}"
	else
		printf '%s left the security support of its vendor on %s; %s covers it until %s, otherwise upgrade to a newer release.\n' \
			"${OS_LABEL}" "${OS_EOL}" "${OS_EXTENDED}" "${OS_EXTENDED_UNTIL}"
	fi
	return 2
}

os_is_debian() {
	[[ ${OS_FAMILY} == debian ]]
	return
}
os_is_rhel() {
	[[ ${OS_FAMILY} == rhel ]]
	return
}

# Debian architecture name (amd64/arm64) for repository lines and downloads.
os_deb_arch() {
	case ${OS_ARCH} in
	x86_64) printf 'amd64' ;;
	aarch64) printf 'arm64' ;;
	*) printf '%s' "${OS_ARCH}" ;;
	esac
	return
}

# True inside a container (Docker, Podman, LXC, systemd-nspawn). Modules that change the kernel or block devices
# refuse to run there, because the change would hit the host or fail.
os_in_container() {
	systemd-detect-virt --container --quiet 2>/dev/null
	return
}
