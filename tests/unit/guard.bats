#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The daily guard script (libexec/lss-guard): its checks against stub functions for systemctl, journalctl and the
# security tools.

setup() {
	load helpers
	lss_test_setup
	export LSS_GUARD_CONF=${BATS_TEST_TMPDIR}/guard.conf
	: >"${LSS_GUARD_CONF}"
	# shellcheck source=/dev/null
	source "${REPO_ROOT}/libexec/lss-guard"
	FINDINGS=()
	NOTES=()
	SCAN_UNIT=''
	SCAN_STATUS=0
	SCAN_EXITED=$(date -d '-1 hour' '+%a %Y-%m-%d %H:%M:%S %Z')
	SCAN_OUTPUT=''
}

# One scanner unit (SCAN_UNIT) that ran at SCAN_EXITED with SCAN_STATUS; every other unit does not exist.
systemctl() {
	local unit=${*: -1}
	[[ ${unit} == "${SCAN_UNIT}.service" ]] || return 1
	case $* in
	cat\ *) return 0 ;;
	*ExecMainExitTimestamp*) printf '%s\n' "${SCAN_EXITED}" ;;
	*ExecMainStatus*) printf '%s\n' "${SCAN_STATUS}" ;;
	*InvocationID*) printf 'abc123\n' ;;
	*) return 1 ;;
	esac
}

journalctl() {
	printf '%s\n' "${SCAN_OUTPUT}"
}

@test "AIDE changes reach the summary with the numbers from the report" {
	SCAN_UNIT=lss-aide-check
	SCAN_STATUS=5
	SCAN_OUTPUT=$'  Total number of entries:\t4211\n  Added entries:\t\t1\n  Removed entries:\t\t0\n  Changed entries:\t\t2'
	check_scanners
	[ "${#FINDINGS[@]}" -eq 1 ]
	[[ ${FINDINGS[0]} == "AIDE found changed files on "*"(1 added, 0 removed, 2 changed): review them with journalctl -u lss-aide-check, then accept them by rebuilding the database (aideinit --yes --force on Debian and Ubuntu, aide --init and moving aide.db.new.gz to aide.db.gz in /var/lib/aide on the RHEL family)." ]]
}

@test "ClamAV names the infected files" {
	SCAN_UNIT=lss-clamscan
	SCAN_STATUS=1
	SCAN_OUTPUT=$'/home/alice/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n/tmp/x.pdf: Pdf.Exploit FOUND'
	check_scanners
	[[ ${FINDINGS[0]} == "ClamAV found 2 infected file(s) on "*": /home/alice/eicar.com, /tmp/x.pdf (journalctl -u lss-clamscan)." ]]
}

@test "rkhunter warnings are counted and the first one is quoted" {
	SCAN_UNIT=lss-rkhunter
	SCAN_STATUS=1
	SCAN_OUTPUT=$'Warning: The command \'/usr/bin/lwp-request\' has been replaced by a script\nWarning: Hidden file found'
	check_scanners
	[[ ${FINDINGS[0]} == "rkhunter reported 2 warning(s) on "*", the first: The command '/usr/bin/lwp-request' has been replaced by a script (journalctl -u lss-rkhunter)." ]]
}

@test "a clean scan reports nothing and a scan that stopped running is a finding" {
	SCAN_UNIT=lss-clamscan
	check_scanners
	[ "${#FINDINGS[@]}" -eq 0 ]
	SCAN_EXITED=$(date -d '-3 days' '+%a %Y-%m-%d %H:%M:%S %Z')
	check_scanners
	[[ ${FINDINGS[0]} == "The daily ClamAV check has not run since "*"(systemctl status lss-clamscan.timer)." ]]
}

@test "failed SSH logins above the threshold name the busiest sources; logins are a note" {
	printf 'GUARD_LOGIN_THRESHOLD=2\n' >"${LSS_GUARD_CONF}"
	SCAN_OUTPUT=$'Failed password for root from 203.0.113.9 port 4711 ssh2\nInvalid user admin from 203.0.113.9 port 4712\nFailed publickey for bob from 198.51.100.4 port 22 ssh2\nAccepted publickey for alice from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:x'
	check_logins
	[ "${FINDINGS[0]}" = "3 failed SSH logins in the last 24 hours, most from 203.0.113.9 (2), 198.51.100.4 (1)." ]
	[ "${NOTES[0]}" = "SSH logins in the last 24 hours: alice from 192.0.2.10 (1)." ]
}

@test "failed logins at or below the threshold are no finding" {
	SCAN_OUTPUT='Failed password for root from 203.0.113.9 port 4711 ssh2'
	check_logins
	[ "${#FINDINGS[@]}" -eq 0 ]
}

@test "active fail2ban bans are a note, not a finding" {
	fail2ban-client() { printf "[{'sshd': ['192.0.2.1', '2001:db8::7']}, {'recidive': []}]\n"; }
	check_bans
	[ "${#FINDINGS[@]}" -eq 0 ]
	[ "${NOTES[0]}" = "fail2ban currently bans 2 address(es)." ]
}

@test "debsecan: fixable high-urgency vulnerabilities are a finding, unfixed ones a note" {
	export LSS_OS_RELEASE=${REPO_ROOT}/tests/fixtures/os-release/debian-13
	OS_RELEASE=${LSS_OS_RELEASE}
	debsecan() {
		printf '%s\n' "$*" >>"${STUB_LOG}"
		if [[ $* == *--only-fixed* ]]; then
			printf 'CVE-2026-1 openssl (fixed, remotely exploitable, high urgency)\n'
		else
			printf 'CVE-2026-1 openssl (fixed, remotely exploitable, high urgency)\nCVE-2026-2 curl (remotely exploitable, high urgency)\nCVE-2026-3 vim (low urgency)\n'
		fi
	}
	check_vulnerabilities
	grep -q -- '--suite trixie' "${STUB_LOG}"
	[ "${FINDINGS[0]}" = "1 high-urgency vulnerabilities in installed packages have a fix: install the security updates." ]
	[ "${NOTES[0]}" = "1 high-urgency vulnerabilities in installed packages have no fix yet (debsecan)." ]
}
