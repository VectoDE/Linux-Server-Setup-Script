# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="crowdsec"
MOD_GROUP="security"
MOD_DESCRIPTION="CrowdSec: behaviour-based intrusion prevention with a shared blocklist, nftables bouncer"
MOD_REQUIRES="system"
MOD_CONFLICTS="fail2ban"
MOD_OPTIONS="collections|crowdsecurity/linux crowdsecurity/sshd|Detection collections, separated by spaces (web modules add theirs)
enroll_key||Optional key to enrol this engine in the CrowdSec console (app.crowdsec.net)"
MOD_SECRETS="crowdsec-enroll-key"

CS_BOUNCER=crowdsec-firewall-bouncer

mod_check() {
	local collection
	for collection in $(opt collections); do
		[[ ${collection} =~ ^[a-z0-9_-]+/[a-z0-9_.-]+$ ]] || die "LSS_CROWDSEC_COLLECTIONS: '${collection}' is not a collection name."
	done
	[[ -z $(opt enroll_key) || $(opt enroll_key) =~ ^[A-Za-z0-9]+$ ]] || die "LSS_CROWDSEC_ENROLL_KEY is not a CrowdSec key."
}

mod_install() {
	repo_add crowdsec
	pkg_install_family "crowdsec crowdsec-firewall-bouncer-nftables" "crowdsec crowdsec-firewall-bouncer-nftables"
}

mod_configure() {
	local collection installed key
	svc_enable crowdsec
	# The hub index and parsers come over HTTPS from the CrowdSec hub; signatures are checked by cscli.
	cscli hub update >/dev/null 2>&1 || log_warn "crowdsec: hub index update failed; using the installed index."
	installed=$(cscli collections list -o raw 2>/dev/null | cut -d ',' -f 1)
	for collection in $(opt collections); do
		if ! grep -qxF "${collection}" <<<"${installed}"; then
			cscli collections install "${collection}" >/dev/null
			files_note_change "crowdsec collection ${collection}"
		fi
	done
	# SSH logs come from the journal on journal-only systems.
	file_write 0644 root:root /etc/crowdsec/acquis.d/lss-journal.yaml <<'EOF'
# Managed by lss (module crowdsec).
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
EOF
	local changed=${LSS_FILE_CHANGED}
	key=$(opt enroll_key)
	if [[ -n ${key} ]] && ! secret_exists crowdsec-enroll-key; then
		secret_set crowdsec-enroll-key "${key}"
		cscli console enroll --name "$(hostname)" "${key}" >/dev/null
		files_note_change "crowdsec console enrolment"
	fi
	if [[ ${changed} == 1 || $(files_changes_of crowdsec) != 0 ]]; then
		svc_reload crowdsec
	fi
	svc_enable "${CS_BOUNCER}"
}

mod_verify() {
	svc_is_active crowdsec || die "crowdsec: the engine is not running."
	svc_is_active "${CS_BOUNCER}" || die "crowdsec: the firewall bouncer is not running."
	cscli lapi status >/dev/null 2>&1 || die "crowdsec: the local API does not answer."
	cscli bouncers list -o raw 2>/dev/null | grep -q 'firewall' || die "crowdsec: the firewall bouncer is not registered."
	cscli collections list -o raw 2>/dev/null | grep -q '^crowdsecurity/sshd,' || die "crowdsec: the sshd collection is missing."
}

mod_remove() {
	svc_disable "${CS_BOUNCER}"
	svc_disable crowdsec
	file_remove /etc/crowdsec/acquis.d/lss-journal.yaml
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		pkg_remove crowdsec-firewall-bouncer-nftables crowdsec
		repo_remove crowdsec
		secret_remove crowdsec-enroll-key
	fi
}
