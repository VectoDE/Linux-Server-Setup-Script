# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="ssh-hardening"
MOD_GROUP="security"
MOD_DESCRIPTION="OpenSSH server: keys only, no root login, modern algorithms, strong moduli, login banner"
MOD_REQUIRES="admin-user"
MOD_OPTIONS="port|22|SSH port
allow_groups|ssh-users|Groups allowed to log in besides the administrators (sudo/wheel), separated by spaces
tcp_forwarding|local|Port forwarding: no, local (ssh -L, for admin interfaces bound to localhost) or yes
max_sessions|4|Sessions per connection
idle_timeout|900|Seconds without traffic before an idle session is closed
banner|Authorised access only. All activity is logged.|Text shown before login"

SSH_CONFIG=/etc/ssh/sshd_config.d/00-lss.conf
SSH_BANNER=/etc/ssh/lss-banner

# Algorithms in order of preference; only those the installed OpenSSH knows are used.
SSH_KEX="mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group18-sha512 diffie-hellman-group16-sha512 diffie-hellman-group-exchange-sha256"
SSH_CIPHERS="chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr"
SSH_MACS="hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com"
SSH_HOSTKEYS="ssh-ed25519 sk-ssh-ed25519@openssh.com rsa-sha2-512 rsa-sha2-256"
SSH_PUBKEYS="ssh-ed25519 sk-ssh-ed25519@openssh.com ecdsa-sha2-nistp521 ecdsa-sha2-nistp384 ecdsa-sha2-nistp256 sk-ecdsa-sha2-nistp256@openssh.com rsa-sha2-512 rsa-sha2-256"

_ssh_unit() {
	if os_is_debian; then printf 'ssh'; else printf 'sshd'; fi
}

_ssh_admin_group() {
	if os_is_debian; then printf 'sudo'; else printf 'wheel'; fi
}

# _ssh_supported QUERY WANTED: comma-separated list of the WANTED algorithms that "ssh -Q QUERY" knows.
_ssh_supported() {
	local query=$1 wanted=$2 known algorithm result=''
	known=$(ssh -Q "${query}" 2>/dev/null)
	for algorithm in ${wanted}; do
		if grep -qxF -- "${algorithm}" <<<"${known}"; then
			result+="${algorithm},"
		fi
	done
	[[ -n ${result} ]] || die "ssh-hardening: OpenSSH supports none of: ${wanted}"
	printf '%s' "${result%,}"
}

# Lockout protection: at least one administrator must be able to log in with a key once passwords are off.
_ssh_key_admins() {
	local group member home
	group=$(_ssh_admin_group)
	for member in $(getent group "${group}" | cut -d ':' -f 4 | tr ',' ' '); do
		home=$(getent passwd "${member}" | cut -d ':' -f 6)
		if [[ -n ${home} && -s ${home}/.ssh/authorized_keys ]]; then
			printf '%s\n' "${member}"
		fi
	done
}

mod_check() {
	local port forwarding group
	port=$(opt port)
	forwarding=$(opt tcp_forwarding)
	if [[ ! ${port} =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
		die "LSS_SSH_HARDENING_PORT '${port}' is not a port."
	fi
	[[ ${forwarding} =~ ^(no|local|yes)$ ]] || die "LSS_SSH_HARDENING_TCP_FORWARDING must be no, local or yes."
	opt_int max_sessions >/dev/null
	opt_int idle_timeout >/dev/null
	for group in $(opt allow_groups); do
		[[ ${group} =~ ^[a-z_][a-z0-9_-]*$ ]] || die "LSS_SSH_HARDENING_ALLOW_GROUPS: '${group}' is not a group name."
	done
	[[ $(opt banner) != *$'\n'* ]] || die "LSS_SSH_HARDENING_BANNER must be one line."
}

mod_install() {
	pkg_install_family "openssh-server openssh-client" "openssh-server openssh-clients"
	if os_is_rhel && [[ $(opt port) != 22 ]]; then
		pkg_install policycoreutils-python-utils
	fi
}

_ssh_render() {
	local port forwarding groups idle
	port=$(opt port)
	forwarding=$(opt tcp_forwarding)
	groups="$(_ssh_admin_group) $(opt allow_groups)"
	idle=$(opt_int idle_timeout)
	cat <<EOF
# Managed by lss (module ssh-hardening). Settings here win over sshd_config (first match counts).
Port ${port}
AddressFamily any
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
AuthenticationMethods publickey
AllowGroups ${groups% }
MaxAuthTries 3
MaxSessions $(opt_int max_sessions)
MaxStartups 10:30:60
LoginGraceTime 30
ClientAliveInterval $((idle / 3 > 0 ? idle / 3 : 1))
ClientAliveCountMax 3
TCPKeepAlive no
AllowTcpForwarding ${forwarding}
AllowStreamLocalForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
UseDNS no
Compression no
LogLevel VERBOSE
Banner ${SSH_BANNER}
KexAlgorithms ${SSH_KEX_LIST}
Ciphers ${SSH_CIPHER_LIST}
MACs ${SSH_MAC_LIST}
HostKeyAlgorithms ${SSH_HOSTKEY_LIST}
PubkeyAcceptedAlgorithms ${SSH_PUBKEY_LIST}
EOF
}

# Diffie-Hellman group exchange only with moduli of 3072 bits or more.
_ssh_moduli() {
	[[ -f /etc/ssh/moduli ]] || return 0
	local strong
	strong=$(awk '$1 ~ /^#/ || $5 >= 3071' /etc/ssh/moduli)
	file_write 0644 root:root /etc/ssh/moduli <<<"${strong}"
}

# Ubuntu 22.10+ starts sshd through ssh.socket, which ignores the Port setting; lss runs sshd as a plain service.
_ssh_plain_service() {
	os_is_debian || return 0
	if svc_is_enabled ssh.socket || svc_is_active ssh.socket; then
		systemctl disable --now ssh.socket >/dev/null 2>&1
		files_note_change "disabled ssh.socket"
		systemctl enable ssh.service >/dev/null 2>&1
		systemctl restart ssh.service
	fi
}

mod_configure() {
	local port changed=0 group
	port=$(opt port)
	ssh-keygen -A >/dev/null
	# sshd -t needs its privilege separation directory, which only exists once ssh.service ran (not yet with
	# socket activation on Ubuntu 24.04).
	install -d -m 0755 /run/sshd
	# Computed here, outside the process substitution of _ssh_render, so a failure stops the step.
	SSH_KEX_LIST=$(_ssh_supported kex "${SSH_KEX}")
	SSH_CIPHER_LIST=$(_ssh_supported cipher "${SSH_CIPHERS}")
	SSH_MAC_LIST=$(_ssh_supported mac "${SSH_MACS}")
	SSH_HOSTKEY_LIST=$(_ssh_supported key "${SSH_HOSTKEYS}")
	SSH_PUBKEY_LIST=$(_ssh_supported key "${SSH_PUBKEYS}")
	for group in ssh-users $(opt allow_groups); do
		if ! getent group "${group}" >/dev/null; then
			groupadd --system "${group}"
			files_note_change "created group ${group}"
		fi
	done
	if [[ -z $(_ssh_key_admins) ]]; then
		die "ssh-hardening: no member of $(_ssh_admin_group) has an SSH key; refusing to switch off passwords (lockout)."
	fi

	file_write 0644 root:root "${SSH_BANNER}" <<<"$(opt banner)"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0600 root:root "${SSH_CONFIG}" < <(_ssh_render)
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_ssh_moduli
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1

	if os_is_rhel && [[ ${port} != 22 ]] && command -v semanage >/dev/null 2>&1 &&
		! semanage port -l | awk '$1 == "ssh_port_t"' | grep -qwF "${port}"; then
		semanage port -a -t ssh_port_t -p tcp "${port}" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "${port}"
		files_note_change "SELinux ssh port ${port}"
	fi
	# The new port is open in the firewall before sshd moves to it. The rule belongs to the firewall module, so
	# removing ssh-hardening never closes the SSH port.
	LSS_MODULE=firewall fw_allow "${port}/tcp"

	sshd -t || die "ssh-hardening: sshd rejects the configuration; the previous files are restored."
	_ssh_plain_service
	svc_enable "$(_ssh_unit)"
	if [[ ${changed} == 1 ]]; then
		svc_reload "$(_ssh_unit)"
	fi
}

mod_verify() {
	local effective port
	port=$(opt port)
	sshd -t || die "ssh-hardening: sshd configuration is invalid."
	svc_is_active "$(_ssh_unit)" || die "ssh-hardening: $(_ssh_unit) is not running."
	effective=$(sshd -T -C user=lss-verify,host=localhost,addr=127.0.0.1 2>/dev/null)
	grep -qx 'passwordauthentication no' <<<"${effective}" || die "ssh-hardening: password login is still allowed."
	grep -qx 'permitrootlogin no' <<<"${effective}" || die "ssh-hardening: root login is still allowed."
	grep -qx "port ${port}" <<<"${effective}" || die "ssh-hardening: sshd does not use port ${port}."
	svc_wait_port 127.0.0.1 "${port}" 10 || die "ssh-hardening: nothing listens on port ${port}."
	[[ -n $(_ssh_key_admins) ]] || die "ssh-hardening: no administrator with an SSH key (lockout risk)."
}

# Back to the distribution's defaults: the lss settings go, sshd keeps running.
mod_remove() {
	file_remove "${SSH_CONFIG}"
	file_remove "${SSH_BANNER}"
	sshd -t || die "ssh-hardening: sshd configuration is invalid without the lss settings."
	svc_reload "$(_ssh_unit)"
}
