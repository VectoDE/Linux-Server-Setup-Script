# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="ssh-2fa"
MOD_GROUP="security"
MOD_DESCRIPTION="Second factor for SSH: key plus a one-time code (TOTP app such as Aegis or a password manager)"
MOD_REQUIRES="ssh-hardening"
MOD_SECRETS="ssh-2fa-<user>"
MOD_OPTIONS="users||Users that get a TOTP secret now (default: the admin-user account)
enforce|false|true: every login needs a code; false: users without a TOTP secret still log in with their key"

TFA_SSHD=/etc/ssh/sshd_config.d/00-lss-2fa.conf
TFA_PAM=/etc/pam.d/sshd
TFA_ORIGINAL=${LSS_STATE_DIR:-/var/lib/lss}/ssh-2fa/pam-sshd.orig

_tfa_users() {
	local users
	users=$(opt users)
	if [[ -z ${users} ]]; then
		users=$(config_get LSS_ADMIN_USER_NAME admin)
	fi
	printf '%s' "${users}"
	return
}

_tfa_unit() {
	if os_is_debian; then printf 'ssh'; else printf 'sshd'; fi
	return
}

mod_check() {
	local user
	opt_bool enforce || true
	for user in $(_tfa_users); do
		[[ ${user} =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || die "LSS_SSH_2FA_USERS: '${user}' is not a user name."
	done
	return
}

mod_install() {
	pkg_enable_epel
	pkg_install_family "libpam-google-authenticator qrencode" "google-authenticator qrencode"
	return
}

# The PAM stack for sshd: the one-time code replaces the password (keys are checked by sshd before PAM runs).
_tfa_pam() {
	local option=''
	opt_bool enforce || option=' nullok'
	if [[ ! -f ${TFA_ORIGINAL} ]]; then
		mkdir -p "$(dirname "${TFA_ORIGINAL}")"
		cp -a "${TFA_PAM}" "${TFA_ORIGINAL}"
	fi
	awk -v line="auth required pam_google_authenticator.so${option} echo_verification_code" '
		/^[[:space:]]*@include[[:space:]]+common-auth/ || /^[[:space:]]*auth[[:space:]]+substack[[:space:]]+password-auth/ {
			print "# " $0 "  (disabled by lss ssh-2fa: no password, a one-time code instead)"
			print line
			# With nullok the code module answers "ignore" for users without a secret; pam_permit then lets the
			# key login through. A wrong code still fails, because the code module is "required".
			print "auth required pam_permit.so"
			done = 1
			next
		}
		{ print }
		END { if (!done) { print line; print "auth required pam_permit.so" } }
	' "${TFA_ORIGINAL}"
	return
}

# Creates a TOTP secret for USER once and keeps the otpauth URI as lss secret ssh-2fa-USER.
_tfa_enrol() {
	local user=$1 home file secret uri
	home=$(getent passwd "${user}") || die "ssh-2fa: user ${user} does not exist."
	home=$(cut -d ':' -f 6 <<<"${home}")
	file=${home}/.google_authenticator
	# The home directory belongs to the user, who could plant a symlink there; root never follows it. The secret is
	# created and read with the user's own rights (google-authenticator writes it with mode 0400).
	[[ ! -L ${file} ]] || die "ssh-2fa: ${file} is a symbolic link; remove it and run lss configure ssh-2fa."
	if runuser -u "${user}" -- test -s "${file}"; then
		return 0
	fi
	runuser -u "${user}" -- google-authenticator --time-based --disallow-reuse --force --rate-limit=3 --rate-time=30 \
		--window-size=3 --no-confirm --quiet --secret="${file}" --label="${user}@$(hostname)" --issuer=lss >/dev/null
	secret=$(runuser -u "${user}" -- head -n 1 "${file}")
	[[ ${secret} =~ ^[A-Z2-7]{16,}$ ]] || die "ssh-2fa: ${file} does not hold a TOTP secret."
	log_mask "${secret}"
	uri="otpauth://totp/lss:${user}@$(hostname)?secret=${secret}&issuer=lss"
	secret_set "ssh-2fa-${user}" "${uri}"
	files_note_change "TOTP secret for ${user}"
	log_info "TOTP for ${user}: lss secrets show ssh-2fa-${user} (scan as QR code: ... | qrencode -t ansiutf8)"
}

mod_configure() {
	local user changed=0
	for user in $(_tfa_users); do
		_tfa_enrol "${user}"
	done
	file_write 0644 root:root "${TFA_PAM}" < <(_tfa_pam)
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0600 root:root "${TFA_SSHD}" <<'EOF'
# Managed by lss (module ssh-2fa). Sorted before 00-lss.conf, so these values win.
KbdInteractiveAuthentication yes
UsePAM yes
AuthenticationMethods publickey,keyboard-interactive
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	sshd -t || die "ssh-2fa: sshd rejects the configuration; the previous files are restored."
	if [[ ${changed} == 1 ]]; then
		svc_reload "$(_tfa_unit)"
	fi
	return
}

mod_verify() {
	local effective user
	effective=$(sshd -T -C user=lss-verify,host=localhost,addr=127.0.0.1 2>/dev/null)
	grep -qx 'authenticationmethods publickey,keyboard-interactive' <<<"${effective}" ||
		die "ssh-2fa: sshd does not ask for the one-time code."
	grep -q '^auth required pam_google_authenticator.so' "${TFA_PAM}" || die "ssh-2fa: PAM does not check the code."
	for user in $(_tfa_users); do
		[[ -s $(getent passwd "${user}" | cut -d ':' -f 6)/.google_authenticator ]] ||
			die "ssh-2fa: ${user} has no TOTP secret."
	done
	svc_is_active "$(_tfa_unit)" || die "ssh-2fa: sshd is not running."
	return
}

# Back to key-only logins; the users' TOTP files stay (they are harmless without the PAM line).
mod_remove() {
	file_remove "${TFA_SSHD}"
	if [[ -f ${TFA_ORIGINAL} ]]; then
		file_write 0644 root:root "${TFA_PAM}" <"${TFA_ORIGINAL}"
		rm -f -- "${TFA_ORIGINAL}"
	fi
	sshd -t || die "ssh-2fa: sshd configuration is invalid without the 2FA settings."
	svc_reload "$(_tfa_unit)"
	return
}
