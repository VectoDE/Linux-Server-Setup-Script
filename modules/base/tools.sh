# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="tools"
MOD_GROUP="base"
MOD_DESCRIPTION="Administration tools: editor, shell multiplexer, network and disk diagnostics"
MOD_REQUIRES="system"
MOD_OPTIONS="extra||More packages to install, separated by spaces (names as in the distribution)"

TOOLS_DEB="vim-tiny nano less htop tmux jq git rsync unzip zip lsof bind9-dnsutils tcpdump traceroute ncdu tree bash-completion psmisc"
TOOLS_RPM="vim-minimal nano less htop tmux jq git rsync unzip zip lsof bind-utils tcpdump traceroute ncdu tree bash-completion psmisc"

_tools_wanted() {
	local list extra
	if os_is_debian; then list=${TOOLS_DEB}; else list=${TOOLS_RPM}; fi
	extra=$(opt extra)
	printf '%s %s' "${list}" "${extra}"
	return
}

mod_check() {
	local package
	for package in $(opt extra); do
		[[ ${package} =~ ^[A-Za-z0-9][A-Za-z0-9.+_-]*$ ]] || die "LSS_TOOLS_EXTRA: '${package}' is not a package name."
	done
	return
}

mod_install() {
	local -a missing=()
	# htop and ncdu come from EPEL on the RHEL family.
	pkg_enable_epel
	# shellcheck disable=SC2046 # one package per word
	mapfile -t missing < <(pkg_missing $(_tools_wanted))
	if [[ ${#missing[@]} -gt 0 ]]; then
		pkg_install "${missing[@]}"
		# Remember what lss installed, so remove takes away only those packages.
		state_set tools packages "$(
			state_get tools packages
			printf ' %s' "${missing[@]}"
		)"
	fi
	return
}

mod_verify() {
	local -a missing=()
	# shellcheck disable=SC2046 # one package per word
	mapfile -t missing < <(pkg_missing $(_tools_wanted))
	[[ ${#missing[@]} -eq 0 ]] || die "tools: not installed: ${missing[*]}"
	tmux -V >/dev/null || die "tools: tmux does not run."
	jq --version >/dev/null || die "tools: jq does not run."
	return
}

mod_remove() {
	local -a installed=()
	read -ra installed <<<"$(state_get tools packages)"
	if [[ ${#installed[@]} -gt 0 ]]; then
		pkg_remove "${installed[@]}"
	fi
	return
}
