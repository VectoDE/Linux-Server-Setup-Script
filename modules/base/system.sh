# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="system"
MOD_GROUP="base"
MOD_DESCRIPTION="Base system: updates, hostname, locale and the packages every other module relies on"
MOD_OPTIONS="hostname||Host name (FQDN allowed); empty keeps the current one
locale|C.UTF-8|System locale, for example C.UTF-8, en_US.UTF-8 or de_DE.UTF-8
upgrade|true|Install all available updates on every run"

# Packages lss itself needs on every server. They are never removed again.
SYSTEM_PACKAGES_DEB="ca-certificates curl gnupg sudo cron logrotate procps iproute2 openssl"
SYSTEM_PACKAGES_RPM="ca-certificates curl gnupg2 sudo cronie logrotate procps-ng iproute openssl"

mod_check() {
	local hostname locale
	hostname=$(opt hostname)
	locale=$(opt locale)
	if [[ -n ${hostname} && ! ${hostname} =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$ ]]; then
		die "LSS_SYSTEM_HOSTNAME '${hostname}' is not a valid host name (lower case letters, digits, '-' and '.')."
	fi
	[[ ${locale} =~ ^(C|[a-z]{2,3}_[A-Z]{2})\.UTF-8$ ]] ||
		die "LSS_SYSTEM_LOCALE '${locale}' must look like C.UTF-8 or de_DE.UTF-8."
	opt_bool upgrade || true
}

mod_install() {
	pkg_update_once
	pkg_install_family "${SYSTEM_PACKAGES_DEB}" "${SYSTEM_PACKAGES_RPM}"
	if opt_bool upgrade; then
		log_info "Installing available updates"
		pkg_upgrade
	fi
}

_system_hostname() {
	local hostname short current
	hostname=$(opt hostname)
	[[ -n ${hostname} ]] || return 0
	short=${hostname%%.*}
	current=$(hostname)
	if [[ ${current} != "${short}" && ${current} != "${hostname}" ]]; then
		hostnamectl set-hostname "${hostname}"
		files_note_change "host name ${hostname}"
	fi
	# The host name must resolve locally (sudo and many services look it up).
	if ! grep -qE "^[0-9.:a-f]+[[:space:]].*[[:space:]]${short}([[:space:]]|$)" /etc/hosts; then
		if [[ ${hostname} == "${short}" ]]; then
			file_ensure_lines 0644 root:root /etc/hosts <<<"127.0.1.1 ${short}"
		else
			file_ensure_lines 0644 root:root /etc/hosts <<<"127.0.1.1 ${hostname} ${short}"
		fi
	fi
}

_system_locale() {
	local locale wanted language
	locale=$(opt locale)
	if [[ ${locale} != C.UTF-8 ]]; then
		wanted=${locale%.UTF-8}.utf8
		if ! locale -a 2>/dev/null | grep -qixF "${wanted}"; then
			if os_is_debian; then
				pkg_install locales
				localedef -i "${locale%.UTF-8}" -c -f UTF-8 -A /usr/share/locale/locale.alias "${locale}"
				files_note_change "generated locale ${locale}"
			else
				language=${locale%%_*}
				pkg_install "glibc-langpack-${language}"
			fi
		fi
	fi
	if os_is_debian; then
		file_write 0644 root:root /etc/default/locale <<<"LANG=${locale}"
	else
		file_write 0644 root:root /etc/locale.conf <<<"LANG=${locale}"
	fi
}

_system_cron() {
	if os_is_debian; then printf 'cron'; else printf 'crond'; fi
}

mod_configure() {
	_system_hostname
	_system_locale
	svc_enable "$(_system_cron)"
}

mod_verify() {
	local locale
	locale=$(opt locale)
	local tool
	for tool in curl sudo gpg openssl; do
		command -v "${tool}" >/dev/null || die "system: ${tool} is missing."
	done
	if [[ ${locale} != C.UTF-8 ]]; then
		locale -a 2>/dev/null | grep -qixF "${locale%.UTF-8}.utf8" || die "system: locale ${locale} is not available."
	fi
	getent hosts "$(hostname)" >/dev/null || die "system: the host name $(hostname) does not resolve."
	svc_is_active "$(_system_cron)" || die "system: cron is not running."
}

# Base packages, host name and locale stay: other software depends on them, and they were set on purpose.
mod_remove() {
	log_info "system: base packages, host name and locale stay as they are."
}
