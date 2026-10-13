# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="dotnet"
MOD_GROUP="runtime"
MOD_DESCRIPTION=".NET SDK (LTS) with telemetry switched off system-wide"
MOD_REQUIRES="system"
MOD_OPTIONS="version|10.0|.NET SDK version: 10.0 (LTS, the default), 9.0 or 8.0 (LTS until November 2026)"

# Sources: Ubuntu's archive (24.04 and 26.04 ship .NET 10), Canonical's backports PPA for what the archive lacks
# (.NET 10 on 22.04), AppStream on the RHEL family, Microsoft's repository on Debian (amd64: every version, arm64:
# .NET 10 only).
DOTNET_ENV_LINE=DOTNET_CLI_TELEMETRY_OPTOUT=1
DOTNET_PROFILE=/etc/profile.d/lss-dotnet.sh
DOTNET_ENVIRONMENT_D=/etc/environment.d/90-lss-dotnet.conf

mod_check() {
	[[ $(opt version) =~ ^[0-9]{1,2}\.0$ ]] || die "LSS_DOTNET_VERSION must look like 10.0, got '$(opt version)'."
	return
}

# True when the package sources offer PACKAGE.
_dotnet_available() {
	local package=$1 candidate
	if os_is_debian; then
		candidate=$(apt-cache policy "${package}" 2>/dev/null | awk '$1 == "Candidate:" { print $2 }')
		[[ -n ${candidate} && ${candidate} != '(none)' ]]
	else
		[[ -n $(dnf -q repoquery "${package}" 2>/dev/null) ]]
	fi
	return
}

mod_install() {
	local version package
	version=$(opt version)
	package="dotnet-sdk-${version}"
	pkg_is_installed "${package}" && return 0
	if os_is_debian; then
		pkg_update_once
		if ! _dotnet_available "${package}"; then
			if [[ ${OS_ID} == ubuntu ]]; then
				repo_add dotnet-backports
			else
				repo_add microsoft
			fi
		fi
	fi
	_dotnet_available "${package}" || die "dotnet: .NET ${version} is not available for ${OS_NAME} on $(os_deb_arch)."
	pkg_install "${package}"
	# Remembered, so remove takes away only what lss installed.
	state_set "${LSS_MODULE}" packages "$(state_get "${LSS_MODULE}" packages) ${package}"
	return
}

# The .NET CLI sends usage data to Microsoft unless DOTNET_CLI_TELEMETRY_OPTOUT is set. Set for login shells
# (profile.d), for every PAM session including sudo, su and cron (/etc/environment) and for systemd user services
# (environment.d).
mod_configure() {
	file_write 0644 root:root "${DOTNET_PROFILE}" <<EOF
# Managed by lss (module dotnet). No usage data from the .NET CLI to Microsoft.
export ${DOTNET_ENV_LINE}
EOF
	file_write 0644 root:root "${DOTNET_ENVIRONMENT_D}" <<EOF
# Managed by lss (module dotnet). No usage data from the .NET CLI to Microsoft.
${DOTNET_ENV_LINE}
EOF
	file_ensure_lines 0644 root:root /etc/environment <<<"${DOTNET_ENV_LINE}"
	return
}

mod_verify() {
	local version sdks output
	version=$(opt version)
	sdks=$(DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet --list-sdks 2>/dev/null) || die "dotnet: dotnet does not run."
	grep -q "^${version//./\\.}\." <<<"${sdks}" || die "dotnet: dotnet --list-sdks shows no .NET ${version} SDK."
	output=$(env -i HOME=/root PATH=/usr/bin:/bin bash -lc 'printf "%s" "${DOTNET_CLI_TELEMETRY_OPTOUT:-}"' 2>/dev/null) || true
	[[ ${output##*$'\n'} == 1 ]] || die "dotnet: DOTNET_CLI_TELEMETRY_OPTOUT is not set for login shells."
	grep -qxF "${DOTNET_ENV_LINE}" /etc/environment || die "dotnet: /etc/environment does not switch telemetry off."
	return
}

mod_remove() {
	local -a installed=()
	local remaining
	read -ra installed <<<"$(state_get "${LSS_MODULE}" packages)"
	if [[ ${#installed[@]} -gt 0 ]]; then
		pkg_remove "${installed[@]}"
	fi
	repo_remove microsoft
	repo_remove dotnet-backports
	file_remove "${DOTNET_PROFILE}"
	file_remove "${DOTNET_ENVIRONMENT_D}"
	if [[ -f /etc/environment ]] && grep -qxF "${DOTNET_ENV_LINE}" /etc/environment; then
		files_backup /etc/environment
		remaining=$(grep -vxF "${DOTNET_ENV_LINE}" /etc/environment || true)
		# Rewritten in place, so the file keeps its owner, mode and SELinux label.
		if [[ -n ${remaining} ]]; then
			printf '%s\n' "${remaining}" >/etc/environment
		else
			: >/etc/environment
		fi
		files_note_change "removed ${DOTNET_ENV_LINE} from /etc/environment"
	fi
	return
}
