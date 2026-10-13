# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Operating system detection. /etc/os-release is parsed line by line, never sourced.

LSS_OS_RELEASE=${LSS_OS_RELEASE:-/etc/os-release}
OS_ID=''
OS_LIKE=''
OS_VERSION=''
OS_MAJOR=''
OS_CODENAME=''
OS_FAMILY=''
OS_NAME=''
OS_ARCH=''

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
	if [[ -z ${OS_CODENAME} && ${OS_FAMILY} == debian ]]; then
		OS_CODENAME=$(_os_value UBUNTU_CODENAME)
	fi
}

# Prints why the detected system is not supported, or nothing.
os_unsupported_reason() {
	case ${OS_ID}:${OS_MAJOR} in
	debian:12 | debian:13) ;;
	ubuntu:22 | ubuntu:24 | ubuntu:26)
		[[ ${OS_VERSION} == "${OS_MAJOR}.04" ]] ||
			printf '%s %s is not an LTS release; use Ubuntu 22.04, 24.04 or 26.04.' "${OS_ID}" "${OS_VERSION}"
		;;
	rhel:9 | rhel:10 | rocky:9 | rocky:10 | almalinux:9 | almalinux:10) ;;
	*)
		printf '%s is not supported. Supported: Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, RHEL, Rocky Linux and AlmaLinux 9 and 10.' \
			"${OS_NAME:-${OS_ID} ${OS_VERSION}}"
		return 0
		;;
	esac
	case ${OS_ARCH} in
	x86_64 | aarch64) ;;
	*) printf 'Architecture %s is not supported; use x86_64 or aarch64.' "${OS_ARCH}" ;;
	esac
}

os_require_supported() {
	local reason
	reason=$(os_unsupported_reason)
	[[ -z ${reason} ]] || die "${reason}"
}

os_is_debian() { [[ ${OS_FAMILY} == debian ]]; }
os_is_rhel() { [[ ${OS_FAMILY} == rhel ]]; }

# Debian architecture name (amd64/arm64) for repository lines and downloads.
os_deb_arch() {
	case ${OS_ARCH} in
	x86_64) printf 'amd64' ;;
	aarch64) printf 'arm64' ;;
	*) printf '%s' "${OS_ARCH}" ;;
	esac
}

# True inside a container (Docker, Podman, LXC, systemd-nspawn). Modules that change the kernel or block devices
# refuse to run there, because the change would hit the host or fail.
os_in_container() {
	systemd-detect-virt --container --quiet 2>/dev/null
}
