# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="python"
MOD_GROUP="runtime"
MOD_DESCRIPTION="Python 3 from the distribution with venv, pip and pipx"
MOD_REQUIRES="system"
MOD_OPTIONS=""

# The RHEL family has venv in python3 itself and pipx in EPEL.
PYTHON_DEB="python3 python3-venv python3-pip pipx"
PYTHON_RPM="python3 python3-pip pipx"

mod_install() {
	local -a wanted=() missing=() remembered=()
	local package
	if os_is_debian; then
		read -ra wanted <<<"${PYTHON_DEB}"
	else
		pkg_enable_epel
		read -ra wanted <<<"${PYTHON_RPM}"
	fi
	mapfile -t missing < <(pkg_missing "${wanted[@]}")
	[[ ${#missing[@]} -gt 0 ]] || return 0
	pkg_install "${missing[@]}"
	# Remembered, so remove takes away only what lss installed. python3 itself stays: the system and other packages
	# (fail2ban, dnf, ...) depend on it, and removing it would take them along.
	for package in "${missing[@]}"; do
		[[ ${package} == python3 ]] || remembered+=("${package}")
	done
	state_set "${LSS_MODULE}" packages "$(state_get "${LSS_MODULE}" packages) ${remembered[*]}"
	return
}

mod_verify() {
	local tmp status=0
	python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "python: python3 does not run or is older than 3.9."
	# A virtual environment with its own pip proves venv and ensurepip work.
	tmp=$(mktemp -d)
	{
		python3 -m venv "${tmp}/venv" &&
			"${tmp}/venv/bin/python" -m pip --version &&
			"${tmp}/venv/bin/python" -c 'import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)'
	} >/dev/null 2>&1 || status=1
	rm -rf -- "${tmp}"
	[[ ${status} == 0 ]] || die "python: python3 -m venv does not create a working environment."
	python3 -m pip --version >/dev/null 2>&1 || die "python: pip does not run."
	pipx --version >/dev/null 2>&1 || die "python: pipx does not run."
	return
}

mod_remove() {
	local -a installed=()
	read -ra installed <<<"$(state_get "${LSS_MODULE}" packages)"
	if [[ ${#installed[@]} -gt 0 ]]; then
		pkg_remove "${installed[@]}"
	fi
	return
}
