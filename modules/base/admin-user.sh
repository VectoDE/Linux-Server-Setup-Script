# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="admin-user"
MOD_GROUP="base"
MOD_DESCRIPTION="Administrator account with SSH keys and sudo; hardened sudo defaults"
MOD_REQUIRES="system"
MOD_SECRETS="admin-user-password"
MOD_OPTIONS="name|admin|Login name of the administrator
ssh_key||Public SSH keys, separated by ';' (ssh-ed25519, ecdsa, sk-* or ssh-rsa with 3072+ bits)
github_user||Also take the public keys of this GitHub account (https://github.com/NAME.keys)
shell|/bin/bash|Login shell
sudo_nopasswd|false|sudo without password (the generated password is then only needed for the console)"

ADMIN_KEY_PATTERN='^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}( [^[:cntrl:]]*)?$'

_admin_name() { opt name; }

_admin_group() {
	if os_is_debian; then printf 'sudo'; else printf 'wheel'; fi
}

# Home directory of the administrator; empty if the account does not exist yet.
_admin_home() {
	local entry
	entry=$(getent passwd "$(_admin_name)") || return 0
	cut -d ':' -f 6 <<<"${entry}"
}

# Prints the wanted public keys, one per line, after validating each.
_admin_keys() {
	local keys github line fetched bits
	local -a list=()
	keys=$(opt ssh_key)
	github=$(opt github_user)
	IFS=';' read -ra list <<<"${keys}"
	if [[ -n ${github} ]]; then
		[[ ${github} =~ ^[A-Za-z0-9-]{1,39}$ ]] || die "LSS_ADMIN_USER_GITHUB_USER '${github}' is not a GitHub user name."
		fetched=$(curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 20 \
			"https://github.com/${github}.keys") || die "Could not fetch the SSH keys of GitHub user ${github}."
		mapfile -t -O "${#list[@]}" list <<<"${fetched}"
	fi
	for line in "${list[@]}"; do
		line=${line#"${line%%[![:space:]]*}"}
		line=${line%"${line##*[![:space:]]}"}
		[[ -n ${line} ]] || continue
		[[ ${line} =~ ${ADMIN_KEY_PATTERN} ]] || die "Not an SSH public key: '${line:0:40}...'"
		if [[ ${line} == ssh-rsa* ]] && command -v ssh-keygen >/dev/null 2>&1; then
			bits=$(ssh-keygen -l -f /dev/stdin <<<"${line}" | awk '{ print $1 }')
			((bits >= 3072)) || die "RSA key with ${bits} bits is too weak; use ssh-ed25519 or RSA with 3072+ bits."
		fi
		printf '%s\n' "${line}"
	done
}

mod_check() {
	local name shell keys home
	name=$(_admin_name)
	shell=$(opt shell)
	[[ ${name} =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || die "LSS_ADMIN_USER_NAME '${name}' is not a valid user name."
	[[ ${name} != root ]] || die "LSS_ADMIN_USER_NAME must not be root."
	[[ -x ${shell} ]] || die "LSS_ADMIN_USER_SHELL ${shell} does not exist."
	opt_bool sudo_nopasswd || true
	keys=$(_admin_keys)
	if [[ -z ${keys} ]]; then
		home=$(_admin_home)
		if [[ -z ${home} || ! -s ${home}/.ssh/authorized_keys ]]; then
			die "admin-user needs a public key: set LSS_ADMIN_USER_SSH_KEY or LSS_ADMIN_USER_GITHUB_USER."
		fi
	fi
}

mod_install() {
	pkg_install sudo
}

# Writes a sudoers file only after visudo accepted it; a broken sudoers file would lock every administrator out.
_admin_sudoers() {
	local dest=$1 content=$2 tmp
	tmp=$(mktemp)
	printf '%s\n' "${content}" >"${tmp}"
	if ! visudo -c -q -f "${tmp}" >/dev/null; then
		rm -f -- "${tmp}"
		die "admin-user: the generated sudoers file is invalid; nothing was changed."
	fi
	rm -f -- "${tmp}"
	file_write 0440 root:root "${dest}" <<<"${content}"
}

mod_configure() {
	local name group shell home keys primary password status sudoers
	name=$(_admin_name)
	group=$(_admin_group)
	shell=$(opt shell)
	if ! getent passwd "${name}" >/dev/null; then
		useradd --create-home --shell "${shell}" --comment "Administrator (lss)" "${name}"
		files_note_change "created user ${name}"
	elif [[ $(getent passwd "${name}" | cut -d ':' -f 7) != "${shell}" ]]; then
		usermod --shell "${shell}" "${name}"
		files_note_change "shell of ${name}"
	fi
	if ! id -nG "${name}" | tr ' ' '\n' | grep -qxF "${group}"; then
		usermod --append --groups "${group}" "${name}"
		files_note_change "added ${name} to ${group}"
	fi
	# A password exists for sudo and the console; it is generated once and readable with "lss secrets show".
	status=$(passwd --status "${name}" 2>/dev/null | awk '{ print $2 }')
	if [[ ! ${status} =~ ^PS?$ ]]; then
		secret_load admin-user-password password 24
		chpasswd <<<"${name}:${password}"
		files_note_change "set password of ${name}"
		log_info "Password of ${name}: lss secrets show admin-user-password"
	fi

	home=$(_admin_home)
	primary=$(id -gn "${name}")
	chmod 0750 "${home}"
	install -d -m 0700 -o "${name}" -g "${primary}" "${home}/.ssh"
	keys=$(_admin_keys)
	if [[ -n ${keys} ]]; then
		file_ensure_lines 0600 "${name}:${primary}" "${home}/.ssh/authorized_keys" <<<"${keys}"
	fi

	sudoers="# Managed by lss (module admin-user).
Defaults use_pty
Defaults logfile=\"/var/log/sudo.log\"
Defaults timestamp_timeout=5
Defaults passwd_tries=3
Defaults env_reset"
	if opt_bool sudo_nopasswd; then
		sudoers+=$'\n'"${name} ALL=(ALL:ALL) NOPASSWD: ALL"
	fi
	_admin_sudoers /etc/sudoers.d/00-lss "${sudoers}"
}

mod_verify() {
	local name home
	name=$(_admin_name)
	getent passwd "${name}" >/dev/null || die "admin-user: ${name} does not exist."
	id -nG "${name}" | tr ' ' '\n' | grep -qxF "$(_admin_group)" || die "admin-user: ${name} is not in $(_admin_group)."
	home=$(_admin_home)
	[[ -s ${home}/.ssh/authorized_keys ]] || die "admin-user: ${name} has no SSH key."
	[[ $(stat -c '%a %U' "${home}/.ssh/authorized_keys") == "600 ${name}" ]] ||
		die "admin-user: ${home}/.ssh/authorized_keys must be mode 600 and owned by ${name}."
	visudo -c -q >/dev/null || die "admin-user: the sudoers configuration is invalid."
	sudo -l -U "${name}" | grep -qE '\(ALL( : ALL)?\) (NOPASSWD: )?ALL' || die "admin-user: ${name} cannot use sudo."
}

# The account stays (removing it could lock the administrator out); --purge deletes it unless it is in use.
mod_remove() {
	local name
	name=$(_admin_name)
	file_remove /etc/sudoers.d/00-lss
	if [[ ${LSS_PURGE:-0} == 1 ]] && getent passwd "${name}" >/dev/null; then
		if [[ ${SUDO_USER:-} == "${name}" ]] || who | awk '{ print $1 }' | grep -qxF "${name}"; then
			die "admin-user: ${name} is logged in; log in as another administrator to purge it."
		fi
		userdel --remove "${name}" 2>/dev/null || userdel "${name}"
		secret_remove admin-user-password
		log_info "Deleted user ${name}"
	fi
}
