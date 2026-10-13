# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="firewall"
MOD_GROUP="security"
MOD_DESCRIPTION="Host firewall (ufw or firewalld): inbound closed except SSH and the ports of installed modules"
MOD_REQUIRES="system"
MOD_OPTIONS="allow||Extra rules, separated by spaces: PORT/tcp|udp[:public|vpn]
rollback|120|Seconds after which the firewall switches itself off again if lss cannot confirm SSH access"

_fw_unit() {
	if [[ $(fw_backend) == ufw ]]; then printf 'ufw'; else printf 'firewalld'; fi
	return
}

mod_check() {
	local spec
	for spec in $(opt allow); do
		_fw_parse "${spec}"
	done
	opt_int rollback >/dev/null
	return
}

mod_install() {
	if [[ $(fw_backend) == ufw ]]; then
		pkg_install ufw
	else
		pkg_install firewalld
	fi
	return
}

_fw_defaults_ufw() {
	local changed=0
	if ! ufw status verbose 2>/dev/null | grep -q 'Default: deny (incoming), allow (outgoing)'; then
		ufw default deny incoming >/dev/null
		ufw default allow outgoing >/dev/null
		ufw default deny routed >/dev/null
		changed=1
	fi
	if ! grep -qx 'IPV6=yes' /etc/default/ufw; then
		file_write 0644 root:root /etc/default/ufw < <(sed 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw)
	fi
	if ! ufw status verbose 2>/dev/null | grep -q '^Logging: on (low)'; then
		ufw logging low >/dev/null
		changed=1
	fi
	[[ ${changed} == 0 ]] || files_note_change "ufw defaults"
	return
}

# firewalld: public zone with nothing open but what lss records (no cockpit, no dhcpv6-client by default).
_fw_defaults_firewalld() {
	local service zone
	zone=$(firewall-offline-cmd --get-default-zone 2>/dev/null || printf 'public')
	if [[ ${zone} != public ]]; then
		_fw_firewalld --set-default-zone=public >/dev/null 2>&1 || firewall-cmd --set-default-zone=public >/dev/null
		files_note_change "firewalld default zone public"
	fi
	for service in cockpit dhcpv6-client ssh; do
		if _fw_firewalld --zone=public --query-service="${service}" >/dev/null 2>&1; then
			# firewall-offline-cmd reads --remove-service as a lokkit option, which cannot be combined with --zone.
			if svc_is_active firewalld; then
				firewall-cmd --permanent --zone=public --remove-service="${service}" >/dev/null
			else
				firewall-offline-cmd --zone=public --remove-service-from-zone="${service}" >/dev/null
			fi
			files_note_change "firewalld: closed service ${service}"
		fi
	done
	return
}

mod_configure() {
	local ssh_port spec
	ssh_port=$(fw_ssh_port)
	# SSH first: recorded and applied before the firewall is switched on.
	fw_allow "${ssh_port}/tcp"
	for spec in $(opt allow); do
		fw_allow "${spec}"
	done
	if [[ $(fw_backend) == ufw ]]; then
		_fw_defaults_ufw
	else
		_fw_defaults_firewalld
	fi
	# Rules other modules recorded before the firewall existed.
	fw_apply_all >/dev/null

	if ! fw_is_enabled; then
		fw_rollback_arm "$(opt_int rollback)"
		if [[ $(fw_backend) == ufw ]]; then
			ufw --force enable >/dev/null
			svc_enable ufw
		else
			svc_enable firewalld
		fi
		files_note_change "firewall enabled"
		_fw_is_open "${ssh_port}" || die "firewall: SSH port ${ssh_port} is not open; the firewall stays off."
		fw_rollback_cancel
	elif [[ $(fw_backend) == firewalld ]]; then
		firewall-cmd --reload >/dev/null
	fi
	return
}

# _fw_is_open PORT [PROTO]: the port is open to everyone.
_fw_is_open() {
	local port=$1 proto=${2:-tcp}
	if [[ $(fw_backend) == ufw ]]; then
		ufw status | grep -qE "^${port/-/:}/${proto}[[:space:]]+ALLOW"
	else
		firewall-cmd --zone=public --query-port="${port}/${proto}" >/dev/null
	fi
	return
}

mod_verify() {
	local ssh_port spec
	fw_is_enabled || die "firewall: $(_fw_unit) is not active."
	ssh_port=$(fw_ssh_port)
	_fw_is_open "${ssh_port}" || die "firewall: the SSH port ${ssh_port} is not open."
	if [[ $(fw_backend) == ufw ]]; then
		ufw status verbose | grep -q 'Default: deny (incoming)' || die "firewall: inbound traffic is not denied by default."
	else
		[[ $(firewall-cmd --get-default-zone) == public ]] || die "firewall: default zone is not public."
		[[ $(firewall-cmd --zone=public --get-target) =~ ^(default|DROP|REJECT|%%REJECT%%)$ ]] ||
			die "firewall: the public zone accepts everything."
	fi
	for spec in $(opt allow); do
		_fw_parse "${spec}"
		if [[ ${FW_SCOPE} == public ]]; then
			_fw_is_open "${FW_PORT}" "${FW_PROTO}" || die "firewall: ${spec} is not open."
		fi
	done
	return
}

# Switches the firewall off. The rules of other modules stay recorded, so installing the module again restores them.
mod_remove() {
	fw_rollback_cancel
	if [[ $(fw_backend) == ufw ]]; then
		if command -v ufw >/dev/null 2>&1; then
			ufw --force disable >/dev/null
		fi
		svc_disable ufw
	else
		svc_disable firewalld
	fi
	return
}
