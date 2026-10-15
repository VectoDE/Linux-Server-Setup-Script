# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="node"
MOD_GROUP="runtime"
MOD_DESCRIPTION="Node.js (LTS) with npm from the NodeSource repository"
MOD_REQUIRES="system"
MOD_OPTIONS="version|24|Node.js major version: 22, 24 (the active LTS line until 26 takes over in late October 2026) or 26"

# Major versions NodeSource builds for every supported system and both architectures (data/repos/nodesource-*.conf).
NODE_MAJORS="22 24 26"
# The distributions ship their own, older nodejs; the NodeSource package must win even where its version is lower.
NODE_PIN=/etc/apt/preferences.d/lss-nodesource

mod_check() {
	local version
	version=$(opt version)
	[[ " ${NODE_MAJORS} " == *" ${version} "* ]] || die "LSS_NODE_VERSION must be one of ${NODE_MAJORS}, got '${version}'."
	return
}

_node_repo_present() {
	local name=$1
	[[ -e /etc/apt/sources.list.d/lss-${name}.sources || -e /etc/yum.repos.d/lss-${name}.repo ]]
	return
}

# Major version of the installed node, or nothing.
_node_major() {
	local version
	command -v node >/dev/null 2>&1 || return 0
	version=$(node --version 2>/dev/null) || return 0
	version=${version#v}
	printf '%s' "${version%%.*}"
	return
}

mod_install() {
	local major other installed
	major=$(opt version)
	# One NodeSource repository at a time: the one of the major version asked for.
	for other in ${NODE_MAJORS}; do
		if [[ ${other} != "${major}" ]] && _node_repo_present "nodesource-${other}"; then
			repo_remove "nodesource-${other}"
		fi
	done
	if os_is_debian; then
		file_write 0644 root:root "${NODE_PIN}" <<'EOF'
# Managed by lss (module node). nodejs comes from NodeSource, never from the distribution.
Package: nodejs
Pin: origin deb.nodesource.com
Pin-Priority: 600
EOF
	fi
	repo_add "nodesource-${major}"
	if ! pkg_is_installed nodejs; then
		pkg_install nodejs
		# Remembered, so remove takes away only a nodejs that lss installed.
		state_set "${LSS_MODULE}" packages nodejs
		return 0
	fi
	installed=$(_node_major)
	if [[ ${installed} != "${major}" ]]; then
		log_info "Switching Node.js ${installed:-?} to ${major}"
		if os_is_debian; then
			log_command _pkg_apt install --allow-downgrades nodejs
		else
			log_command dnf -y -q distro-sync nodejs
		fi
		files_note_change "nodejs ${major}"
	fi
	return
}

mod_verify() {
	local major output
	major=$(opt version)
	[[ $(_node_major) == "${major}" ]] || die "node: node --version does not report Node.js ${major}."
	output=$(node -e 'process.stdout.write(String(6 * 7))' 2>/dev/null) || true
	[[ ${output} == 42 ]] || die "node: node does not run JavaScript."
	NPM_CONFIG_UPDATE_NOTIFIER=false npm --version >/dev/null 2>&1 || die "node: npm does not run."
	return
}

mod_remove() {
	local major
	if [[ $(state_get "${LSS_MODULE}" packages) == nodejs ]]; then
		pkg_remove nodejs
	fi
	for major in ${NODE_MAJORS}; do
		repo_remove "nodesource-${major}"
	done
	file_remove "${NODE_PIN}"
	return
}
