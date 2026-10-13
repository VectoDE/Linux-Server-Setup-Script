# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="password-policy"
MOD_GROUP="security"
MOD_DESCRIPTION="Strong passwords, lockout after failed logins, password ageing, umask 027, idle shell logout"
MOD_REQUIRES="system"
MOD_OPTIONS="min_length|14|Minimum password length
lockout_attempts|5|Failed logins before an account is locked
lockout_minutes|15|How long a locked account stays locked
max_days|365|Days until a password must be changed
shell_timeout|900|Seconds of inactivity before an interactive shell logs out (0 = never)"

PP_PWQUALITY=/etc/security/pwquality.conf.d/60-lss.conf
PP_FAILLOCK=/etc/security/faillock.conf
PP_PROFILE=/etc/profile.d/60-lss-login.sh
PP_PAM_CONFIGS="lss-faillock lss-faillock-notify"

mod_check() {
	local option
	for option in min_length lockout_attempts lockout_minutes max_days shell_timeout; do
		opt_int "${option}" >/dev/null
	done
	(($(opt_int min_length) >= 8)) || die "LSS_PASSWORD_POLICY_MIN_LENGTH must be at least 8."
}

mod_install() {
	pkg_install_family "libpam-pwquality libpam-modules" "libpwquality authselect"
}

# Sets KEY VALUE pairs in /etc/login.defs and keeps everything else.
_pp_login_defs() {
	local content key value
	content=$(</etc/login.defs)
	while [[ $# -gt 1 ]]; do
		key=$1 value=$2
		shift 2
		if grep -qE "^[[:space:]]*${key}[[:space:]]" <<<"${content}"; then
			content=$(sed -E "s|^[[:space:]]*${key}[[:space:]].*|${key}\t${value}|" <<<"${content}")
		else
			content+=$'\n'"${key}"$'\t'"${value}"
		fi
	done
	file_write 0644 root:root /etc/login.defs <<<"${content}"
}

_pp_faillock_debian() {
	file_write 0644 root:root /usr/share/pam-configs/lss-faillock <<'EOF'
Name: Lock accounts after repeated failed logins (lss)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
EOF
	file_write 0644 root:root /usr/share/pam-configs/lss-faillock-notify <<'EOF'
Name: Check and reset failed login counters (lss)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
Account-Type: Primary
Account:
	required pam_faillock.so
EOF
	if ! grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth; then
		# shellcheck disable=SC2086 # one profile per word
		DEBIAN_FRONTEND=noninteractive pam-auth-update --enable ${PP_PAM_CONFIGS}
		files_note_change "PAM faillock enabled"
	fi
}

# Every authselect profile has pam_pwquality built in; faillock is a feature. The profile for local accounts is
# called "minimal" up to authselect 1.4 (EL9) and "local" from 1.5 (EL10).
_pp_faillock_rhel() {
	local profile=local
	if ! authselect current >/dev/null 2>&1; then
		authselect show local >/dev/null 2>&1 || profile=minimal
		authselect select "${profile}" with-faillock --force >/dev/null
		files_note_change "authselect profile ${profile}"
	elif ! authselect current | grep -q with-faillock; then
		authselect enable-feature with-faillock >/dev/null
		files_note_change "authselect with-faillock"
	fi
}

mod_configure() {
	file_write 0644 root:root "${PP_PWQUALITY}" <<EOF
# Managed by lss (module password-policy).
minlen = $(opt_int min_length)
minclass = 3
maxrepeat = 3
maxsequence = 3
dictcheck = 1
usercheck = 1
difok = 4
enforce_for_root
EOF
	file_write 0644 root:root "${PP_FAILLOCK}" <<EOF
# Managed by lss (module password-policy).
deny = $(opt_int lockout_attempts)
unlock_time = $(($(opt_int lockout_minutes) * 60))
fail_interval = 900
audit
silent
EOF
	if os_is_debian; then
		_pp_faillock_debian
	else
		_pp_faillock_rhel
	fi
	_pp_login_defs PASS_MAX_DAYS "$(opt_int max_days)" PASS_MIN_DAYS 1 PASS_WARN_AGE 14 UMASK 027 \
		ENCRYPT_METHOD "$(_pp_hash)"
	local timeout
	timeout=$(opt_int shell_timeout)
	file_write 0644 root:root "${PP_PROFILE}" < <(
		printf '# Managed by lss (module password-policy).\n'
		printf 'umask 027\n'
		if ((timeout > 0)); then
			# shellcheck disable=SC2016 # written literally into the profile script
			printf 'if [ -n "${BASH_VERSION:-}${ZSH_VERSION:-}" ] && [ -z "${TMOUT:-}" ]; then\n'
			printf '\treadonly TMOUT=%s\n\texport TMOUT\nfi\n' "${timeout}"
		fi
	)
}

# yescrypt where the system supports it (Debian 11+, Ubuntu 22.04+, RHEL 9 does too), else SHA512.
_pp_hash() {
	if grep -qiE '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+YESCRYPT' /etc/login.defs || os_is_debian; then
		printf 'YESCRYPT'
	else
		printf 'SHA512'
	fi
}

mod_verify() {
	[[ -f ${PP_PWQUALITY} ]] || die "password-policy: ${PP_PWQUALITY} is missing."
	if os_is_debian; then
		grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth || die "password-policy: faillock is not in PAM."
		grep -q 'pam_pwquality.so' /etc/pam.d/common-password || die "password-policy: pwquality is not in PAM."
	else
		authselect current | grep -q with-faillock || die "password-policy: faillock is not enabled (authselect)."
		grep -q 'pam_pwquality.so' /etc/pam.d/system-auth || die "password-policy: pwquality is not in PAM."
	fi
	grep -qE '^UMASK[[:space:]]+027' /etc/login.defs || die "password-policy: UMASK is not 027."
	if command -v pwscore >/dev/null 2>&1; then
		if pwscore <<<"password1" >/dev/null 2>&1; then
			die "password-policy: a weak password is accepted."
		fi
	fi
}

mod_remove() {
	file_remove "${PP_PWQUALITY}"
	file_remove "${PP_PROFILE}"
	if os_is_debian; then
		# shellcheck disable=SC2086 # one profile per word
		DEBIAN_FRONTEND=noninteractive pam-auth-update --remove ${PP_PAM_CONFIGS}
		file_remove /usr/share/pam-configs/lss-faillock
		file_remove /usr/share/pam-configs/lss-faillock-notify
	elif authselect current 2>/dev/null | grep -q with-faillock; then
		authselect disable-feature with-faillock >/dev/null
	fi
}
