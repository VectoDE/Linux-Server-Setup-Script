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

# shellcheck disable=SC2329 # called by the guard functions under test
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

@test "text that users control cannot add lines to the summary" {
	finding $'/tmp/evil\n.\n- All checks passed'
	[ "${FINDINGS[0]}" = '/tmp/evil?.?- All checks passed' ]
}

@test "logins are read from the sshd processes recorded by journald, not from a forgeable syslog identifier" {
	journalctl() { printf '%s\n' "$*" >>"${STUB_LOG}"; }
	check_logins
	grep -q -- '_COMM=sshd _COMM=sshd-session _UID=0' "${STUB_LOG}"
	run ! grep -q -- '-t sshd' "${STUB_LOG}"
}

@test "a certificate close to its end is a finding, a fresh one is not" {
	command -v openssl >/dev/null || skip 'openssl is not installed'
	export LSS_TLS_DIR=${BATS_TEST_TMPDIR}/tls
	TLS_DIR=${LSS_TLS_DIR}
	mkdir -p "${TLS_DIR}/old" "${TLS_DIR}/fresh"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3 -subj /CN=old.test \
		-keyout "${TLS_DIR}/old/privkey.pem" -out "${TLS_DIR}/old/fullchain.pem" 2>/dev/null
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 90 -subj /CN=fresh.test \
		-keyout "${TLS_DIR}/fresh/privkey.pem" -out "${TLS_DIR}/fresh/fullchain.pem" 2>/dev/null
	check_certificates
	[ "${#FINDINGS[@]}" -eq 1 ]
	[[ ${FINDINGS[0]} == "Certificate old expires "* ]]
}

@test "container images with HIGH or CRITICAL vulnerabilities are a finding with the numbers; a failed scan is a note" {
	TRIVY=${BATS_TEST_TMPDIR}/trivy
	cat >"${TRIVY}" <<'STUB'
#!/usr/bin/env bash
case ${*: -1} in
docker.io/library/nginx:1.27) printf 'HIGH\nCRITICAL\nHIGH\n' ;;
ccc) exit 1 ;;
*) ;;
esac
STUB
	chmod +x "${TRIVY}"
	# shellcheck disable=SC2329 # called by check_containers
	docker() {
		printf 'aaa docker.io/library/nginx 1.27\naaa docker.io/library/nginx latest\nbbb docker.io/library/redis 8\nccc <none> <none>\n'
	}
	# shellcheck disable=SC2329 # called by check_containers
	podman() {
		return 0
	}
	check_containers
	[ "${#FINDINGS[@]}" -eq 1 ]
	[ "${FINDINGS[0]}" = "The docker image docker.io/library/nginx:1.27 has 1 critical and 2 high vulnerabilities (trivy image docker.io/library/nginx:1.27); update the image." ]
	[ "${#NOTES[@]}" -eq 1 ]
	[ "${NOTES[0]}" = "Trivy could not scan the docker image ccc." ]
}

@test "the container image scan is skipped without Trivy" {
	TRIVY=${BATS_TEST_TMPDIR}/missing
	# shellcheck disable=SC2329 # would be called by check_containers
	docker() {
		printf 'aaa docker.io/library/nginx 1.27\n'
	}
	check_containers
	[ "${#FINDINGS[@]}" -eq 0 ]
	[ "${#NOTES[@]}" -eq 0 ]
}

# --- backup and metrics -----------------------------------------------------------------------------------------

# A backup script that records its call and exits with $BACKUP_EXIT; stamps of the last run in $BACKUP_STATE.
fake_backup() {
	BACKUP=${BATS_TEST_TMPDIR}/backup
	BACKUP_STATE=${BATS_TEST_TMPDIR}/restic
	mkdir -p "${BACKUP_STATE}"
	printf '#!/bin/sh\necho "backup $*" >>"%s"\nexit ${BACKUP_EXIT:-0}\n' "${STUB_LOG}" >"${BACKUP}"
	chmod +x "${BACKUP}"
	return
}

@test "without the restic module the backup is not checked" {
	BACKUP=${BATS_TEST_TMPDIR}/missing
	check_backup
	[ "${#FINDINGS[@]}" -eq 0 ]
}

@test "a backup older than GUARD_BACKUP_MAX_AGE is a finding, also when none ever succeeded" {
	fake_backup
	printf 'GUARD_BACKUP_MAX_AGE=24\n' >"${LSS_GUARD_CONF}"
	date -d '-30 hours' +%s >"${BACKUP_STATE}/last-success"
	date +%s >"${BACKUP_STATE}/restore-test"
	check_backup
	[ "${#FINDINGS[@]}" -eq 1 ]
	[[ ${FINDINGS[0]} == "The last successful backup is 30 hours old, more than 24 (journalctl -u lss-backup)." ]]
	FINDINGS=()
	rm -f "${BACKUP_STATE}/last-success"
	mkdir -p "${STATE_DIR}/modules"
	printf 'status=installed\ninstalled_at=%s\n' "$(date -u -d '-2 days' +%Y-%m-%dT%H:%M:%SZ)" >"${STATE_DIR}/modules/restic"
	check_backup
	[[ ${FINDINGS[0]} == "The last successful backup is 48 hours old, more than 24 (journalctl -u lss-backup)." ]]
	run ! grep -qxF "backup restore-test" "${STUB_LOG}"
}

@test "the restore test runs weekly; a failed one is a finding until the next one passes" {
	fake_backup
	date +%s >"${BACKUP_STATE}/last-success"
	check_backup
	grep -qxF 'backup restore-test' "${STUB_LOG}"
	[ "${#FINDINGS[@]}" -eq 0 ]
	: >"${STUB_LOG}"
	date -d '-2 days' +%s >"${BACKUP_STATE}/restore-test"
	printf '0\n' >"${BACKUP_STATE}/restore-test-success"
	check_backup
	run ! grep -qxF "backup restore-test" "${STUB_LOG}"
	[[ ${FINDINGS[0]} == "The last restore test of the backup failed (${BACKUP} restore-test shows why)." ]]
	FINDINGS=()
	date -d '-8 days' +%s >"${BACKUP_STATE}/restore-test"
	BACKUP_EXIT=1 check_backup
	[[ ${FINDINGS[0]} == "The weekly restore test of the backup failed (${BACKUP} restore-test shows why)." ]]
}

@test "the result of the run goes to the node exporter when it is installed" {
	TEXTFILE_DIR=${BATS_TEST_TMPDIR}/textfile
	export_metrics
	[ ! -e "${TEXTFILE_DIR}" ]
	mkdir -p "${TEXTFILE_DIR}"
	FINDINGS=(one two)
	FIXED=(ssh-hardening)
	NOTES=()
	export_metrics
	grep -qxF 'lss_guard_findings 2' "${TEXTFILE_DIR}/lss_guard.prom"
	grep -qxF 'lss_guard_fixed 1' "${TEXTFILE_DIR}/lss_guard.prom"
	grep -qxF 'lss_guard_notes 0' "${TEXTFILE_DIR}/lss_guard.prom"
	grep -q '^lss_guard_last_run_timestamp_seconds [0-9]*$' "${TEXTFILE_DIR}/lss_guard.prom"
	[ "$(stat -c '%a' "${TEXTFILE_DIR}/lss_guard.prom")" = 644 ]
}
