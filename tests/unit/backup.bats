#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The backup scripts (libexec/lss-backup, libexec/lss-db-dumps, libexec/lss-app-backup) against a restic stub, and the checks of the restic
# module.

setup() {
	load helpers
	lss_test_setup
	use_os debian-13
	export TMPDIR=${BATS_TEST_TMPDIR}
	export LSS_BACKUP_CONF=${BATS_TEST_TMPDIR}/backup.conf
	export LSS_BACKUP_STATE=${BATS_TEST_TMPDIR}/restic-state
	export LSS_BACKUP_CACHE=${BATS_TEST_TMPDIR}/cache
	export LSS_TEXTFILE_DIR=${BATS_TEST_TMPDIR}/textfile
	export LSS_DB_DUMPS=${BATS_TEST_TMPDIR}/db-dumps
	export LSS_DB_DUMPS_CONF=${BATS_TEST_TMPDIR}/db-dumps.conf
	export LSS_DB_DUMPS_STATE=${BATS_TEST_TMPDIR}/db-dumps-state
	export LSS_RESTIC=restic_stub
	export LSS_APP_BACKUP=${BATS_TEST_TMPDIR}/app-backup
	export LSS_APP_BACKUP_STATE=${BATS_TEST_TMPDIR}/app-backup-state
	export LSS_APP_BACKUP_REGISTRY=${BATS_TEST_TMPDIR}/app-backup.d
	export LSS_APP_BACKUP_DIR=${BATS_TEST_TMPDIR}/lss-apps
	mkdir -p "${LSS_TEXTFILE_DIR}" "${LSS_SECRETS_DIR}"
	printf 'BACKUP_REPOSITORY=/srv/repo\nBACKUP_PATHS=/etc /does-not-exist\nBACKUP_EXCLUDE=*.tmp\n' >"${LSS_BACKUP_CONF}"
	printf 'password' >"${LSS_SECRETS_DIR}/restic-password"
	RESTORED=''
}

# restic stub: records the call (without --quiet), fails the subcommand named in $RESTIC_FAIL with $RESTIC_CODE, and
# "restore" writes $RESTORED as the canary below --target.
restic_stub() {
	local args=" $* " target='' previous='' arg line
	line=${args/ --quiet / }
	printf 'restic%s\n' "${line% }" >>"${STUB_LOG}"
	for arg in "$@"; do
		[[ ${previous} != --target ]] || target=${arg}
		previous=${arg}
	done
	if [[ -n ${RESTIC_FAIL:-} && ${args} == *" ${RESTIC_FAIL} "* ]]; then
		return "${RESTIC_CODE:-1}"
	fi
	if [[ ${args} == *' restore '* && -n ${RESTORED} ]]; then
		mkdir -p "${target}${LSS_BACKUP_STATE}/canary"
		printf '%s\n' "${RESTORED}" >"${target}${LSS_BACKUP_STATE}/canary/canary"
	fi
	return 0
}

load_backup() {
	# shellcheck source=/dev/null
	source "${REPO_ROOT}/libexec/lss-backup"
	export -f restic_stub
	return
}

@test "sftp repositories give restic an ssh command with the key and the pinned host" {
	load_backup
	[ "$(sftp_target sftp:backup@nas.example.com:/srv/restic)" = backup@nas.example.com ]
	[ "$(sftp_target sftp://backup@nas.example.com:2222//srv/restic)" = 'backup@nas.example.com -p 2222' ]
	run sftp_target 'sftp:;rm -rf /:/x'
	[ "${status}" -eq 1 ]
	printf 'BACKUP_REPOSITORY=sftp:backup@nas.example.com:/srv/restic\n' >"${LSS_BACKUP_CONF}"
	prepare
	[ "${RESTIC_ENV[0]}" = RESTIC_REPOSITORY=sftp:backup@nas.example.com:/srv/restic ]
	[ "${RESTIC_ENV[1]}" = "RESTIC_PASSWORD_FILE=${LSS_SECRETS_DIR}/restic-password" ]
	[[ ${RESTIC_OPTIONS[2]} == "sftp.command=ssh -i ${LSS_SECRETS_DIR}/restic-ssh-key "*"-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${LSS_BACKUP_STATE}/known_hosts backup@nas.example.com -s sftp" ]]
}

@test "s3 repositories take their keys from the secrets, through the environment of restic alone" {
	load_backup
	printf 'BACKUP_REPOSITORY=s3:https://s3.example.com/bucket/host\nBACKUP_S3_REGION=eu-central-1\n' >"${LSS_BACKUP_CONF}"
	printf 'KEYID' >"${LSS_SECRETS_DIR}/restic-s3-key-id"
	printf 'SECRET' >"${LSS_SECRETS_DIR}/restic-s3-secret"
	prepare
	[[ " ${RESTIC_ENV[*]} " == *' AWS_ACCESS_KEY_ID=KEYID AWS_SECRET_ACCESS_KEY=SECRET AWS_DEFAULT_REGION=eu-central-1 '* ]]
	[ "${RESTIC_OPTIONS[*]}" = --quiet ]
	# Nothing of it is exported: restic gets it, nothing else does.
	[ -z "$(printenv AWS_SECRET_ACCESS_KEY)" ]
	[ -z "$(printenv RESTIC_PASSWORD_FILE)" ]
	# shellcheck disable=SC2329 # called by run_restic
	env_stub() {
		printenv AWS_SECRET_ACCESS_KEY
	}
	[ "$(RESTIC=env_stub run_restic snapshots)" = SECRET ]
	printf 'BACKUP_REPOSITORY=\n' >"${LSS_BACKUP_CONF}"
	run prepare
	[ "${status}" -eq 1 ]
	[[ ${output} == *"BACKUP_REPOSITORY is empty"* ]]
}

@test "a run dumps the databases, backs up the existing paths, applies the retention, checks and records success" {
	load_backup
	printf '#!/bin/sh\necho dumps >>"%s"\n' "${STUB_LOG}" >"${LSS_DB_DUMPS}"
	chmod +x "${LSS_DB_DUMPS}"
	: >"${LSS_DB_DUMPS_CONF}"
	cmd_run
	grep -qxF 'dumps' "${STUB_LOG}"
	grep -qxF 'restic cat config' "${STUB_LOG}"
	grep -qxF "restic backup --tag lss --exclude-caches --exclude *.tmp /etc ${LSS_BACKUP_STATE}/canary" "${STUB_LOG}"
	grep -qxF 'restic forget --tag lss --group-by host,tags --prune --keep-daily 7 --keep-weekly 4 --keep-monthly 6' "${STUB_LOG}"
	grep -qxF 'restic check' "${STUB_LOG}"
	[ "$(cat "${LSS_BACKUP_STATE}/last-run-success")" = 1 ]
	[ "$(cat "${LSS_BACKUP_STATE}/canary-last")" = "$(cat "${LSS_BACKUP_STATE}/canary/canary")" ]
	grep -q '^lss_backup_last_success_timestamp_seconds [0-9]*$' "${LSS_TEXTFILE_DIR}/lss_backup.prom"
	grep -qxF 'lss_backup_last_run_success 1' "${LSS_TEXTFILE_DIR}/lss_backup.prom"
}

@test "a repository that does not exist yet is created" {
	load_backup
	RESTIC_FAIL='cat' cmd_init
	grep -qxF 'restic init' "${STUB_LOG}"
}

@test "a backup with unreadable files or a failed check counts as failed and keeps the last success" {
	load_backup
	RESTIC_FAIL=backup RESTIC_CODE=3 run cmd_run
	[ "${status}" -eq 1 ]
	[[ ${output} == *"restic could not read some files"* ]]
	[ "$(cat "${LSS_BACKUP_STATE}/last-run-success")" = 0 ]
	[ ! -e "${LSS_BACKUP_STATE}/last-success" ]
	[ -s "${LSS_BACKUP_STATE}/canary-last" ]
	RESTIC_FAIL=backup RESTIC_CODE=1 run cmd_run
	[[ ${output} == *"restic backup failed (exit code 1)."* ]]
	RESTIC_FAIL=check run cmd_run
	[[ ${output} == *"restic check reports errors in the repository."* ]]
	RESTIC_FAIL=forget run cmd_run
	[[ ${output} == *"restic forget and prune failed."* ]]
	grep -qxF 'lss_backup_last_run_success 0' "${LSS_TEXTFILE_DIR}/lss_backup.prom"
}

@test "the database dumps never see the credentials of the repository" {
	load_backup
	printf 'BACKUP_REPOSITORY=s3:https://s3.example.com/bucket/host\nBACKUP_PATHS=/etc\n' >"${LSS_BACKUP_CONF}"
	printf 'KEYID' >"${LSS_SECRETS_DIR}/restic-s3-key-id"
	printf 'SECRET' >"${LSS_SECRETS_DIR}/restic-s3-secret"
	printf '#!/bin/sh\nenv >"%s/dumps.env"\n' "${BATS_TEST_TMPDIR}" >"${LSS_DB_DUMPS}"
	chmod +x "${LSS_DB_DUMPS}"
	: >"${LSS_DB_DUMPS_CONF}"
	cmd_run
	[ -s "${BATS_TEST_TMPDIR}/dumps.env" ]
	run grep -E '^(AWS_|RESTIC_)' "${BATS_TEST_TMPDIR}/dumps.env"
	[ "${status}" -eq 1 ]
	run ! grep -q '=SECRET$' "${BATS_TEST_TMPDIR}/dumps.env"
}

@test "failed database dumps fail the run but the files are still backed up" {
	load_backup
	printf '#!/bin/sh\nexit 1\n' >"${LSS_DB_DUMPS}"
	chmod +x "${LSS_DB_DUMPS}"
	: >"${LSS_DB_DUMPS_CONF}"
	run cmd_run
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the database dumps failed; the backup goes on with the files."* ]]
	grep -q '^restic backup ' "${STUB_LOG}"
}

@test "the restore test compares the canary of the latest snapshot and reads part of the data" {
	load_backup
	printf 'abc 123\n' >"${BATS_TEST_TMPDIR}/expected"
	mkdir -p "${LSS_BACKUP_STATE}"
	printf 'abc 123\n' >"${LSS_BACKUP_STATE}/canary-last"
	RESTORED='abc 123'
	cmd_restore_test
	grep -q "^restic restore latest --host .* --tag lss --target .* --include ${LSS_BACKUP_STATE}/canary/canary$" "${STUB_LOG}"
	grep -qxF 'restic check --read-data-subset=5%' "${STUB_LOG}"
	[ "$(cat "${LSS_BACKUP_STATE}/restore-test-success")" = 1 ]
	grep -qxF 'lss_backup_restore_test_success 1' "${LSS_TEXTFILE_DIR}/lss_backup.prom"
	RESTORED='something else'
	run cmd_restore_test
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the restored canary file differs from the one backed up last."* ]]
	[ "$(cat "${LSS_BACKUP_STATE}/restore-test-success")" = 0 ]
	RESTORED='abc 123'
	RESTIC_FAIL=restore run cmd_restore_test
	[[ ${output} == *"restic restore of the latest snapshot failed."* ]]
	RESTIC_FAIL=check run cmd_restore_test
	[[ ${output} == *"restic check --read-data-subset=5% reports errors."* ]]
}

@test "the probe backs up the canary alone, restores it and keeps one probe snapshot" {
	load_backup
	# shellcheck disable=SC2329 # called by the functions under test
	canary() {
		mkdir -p "${CANARY_DIR}"
		printf 'probe 1\n' >"${CANARY}"
		printf 'probe 1'
	}
	RESTORED='probe 1'
	run cmd_probe
	[ "${status}" -eq 0 ]
	grep -qxF "restic backup --tag lss-probe ${LSS_BACKUP_STATE}/canary" "${STUB_LOG}"
	grep -q '^restic restore latest .* --tag lss-probe ' "${STUB_LOG}"
	grep -qxF 'restic forget --tag lss-probe --keep-last 1' "${STUB_LOG}"
}

@test "the backup script needs root and a known command" {
	load_backup
	run main
	if [[ ${EUID} -ne 0 ]]; then
		[ "${status}" -eq 1 ]
		[[ ${output} == *"must run as root."* ]]
	fi
	run dispatch unknown
	[ "${status}" -eq 2 ]
	[[ ${output} == *"usage: backup run|init|restore-test|probe|restic ARGS"* ]]
}

@test "backup restic runs restic with the repository and its password, without --quiet" {
	load_backup
	# shellcheck disable=SC2329 # called by dispatch
	env_stub() {
		printf '%s|%s|%s\n' "${RESTIC_REPOSITORY:-}" "${RESTIC_PASSWORD_FILE:-}" "$*"
	}
	[ "$(RESTIC=env_stub dispatch restic cat config)" = "/srv/repo|${LSS_SECRETS_DIR}/restic-password|cat config" ]
}

# --- db-dumps ---------------------------------------------------------------------------------------------------

load_dumps() {
	# shellcheck source=/dev/null
	source "${REPO_ROOT}/libexec/lss-db-dumps"
	CONF=${BATS_TEST_TMPDIR}/db-dumps.conf
	printf 'DB_DUMPS_DIR=%s/dumps\nDB_POSTGRESQL_PORT=5433\n' "${BATS_TEST_TMPDIR}" >"${CONF}"
	return
}

@test "only the engines lss installed are dumped, each to a file of its own" {
	load_dumps
	state_set mariadb status installed
	state_set postgresql status installed
	state_set redis status failed
	# shellcheck disable=SC2329 # called by the functions under test
	dump() {
		printf 'dump %s\n' "$1" >>"${STUB_LOG}"
		printf 'DATA\n' >"$2"
	}
	run_dumps
	grep -qxF 'dump mariadb' "${STUB_LOG}"
	grep -qxF 'dump postgresql' "${STUB_LOG}"
	run ! grep -q 'dump redis' "${STUB_LOG}"
	[ -s "${BATS_TEST_TMPDIR}/dumps/mariadb.sql" ]
	[ -s "${BATS_TEST_TMPDIR}/dumps/postgresql.sql" ]
	grep -q '^mariadb ok [0-9]*$' "${LSS_DB_DUMPS_STATE}/status"
	[ "$(stat -c '%a' "${BATS_TEST_TMPDIR}/dumps")" = 700 ]
}

@test "a failed dump keeps the previous file and fails the run" {
	load_dumps
	state_set postgresql status installed
	mkdir -p "${BATS_TEST_TMPDIR}/dumps"
	printf 'OLD\n' >"${BATS_TEST_TMPDIR}/dumps/postgresql.sql"
	# shellcheck disable=SC2329 # called by the functions under test
	dump() {
		printf 'PART' >"$2"
		return 1
	}
	run run_dumps
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the dump of postgresql failed; ${BATS_TEST_TMPDIR}/dumps/postgresql.sql keeps the previous one."* ]]
	[ "$(cat "${BATS_TEST_TMPDIR}/dumps/postgresql.sql")" = OLD ]
	[ ! -e "${BATS_TEST_TMPDIR}/dumps/postgresql.sql.part" ]
	grep -q '^postgresql failed ' "${LSS_DB_DUMPS_STATE}/status"
}

@test "without databases nothing is dumped" {
	load_dumps
	run run_dumps
	[ "${status}" -eq 0 ]
	[[ ${output} == *"lss installed 0 databases here; nothing to dump."* ]]
}

@test "each engine is dumped with its own tool and options" {
	load_dumps
	# shellcheck disable=SC2329 # called by the functions under test
	first_program() {
		printf '%s' "$1"
	}
	# env -i PATH=... COMMAND: the stub runs COMMAND, so the functions below stand in for the programs.
	# shellcheck disable=SC2329 # called by the functions under test
	env() {
		[[ $1 == -i && $2 == "PATH=${CLEAN_PATH}" ]] || return 1
		shift 2
		"$@"
	}
	# shellcheck disable=SC2329 # called by the functions under test
	mariadb-dump() {
		printf 'mariadb-dump %s\n' "$*" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by the functions under test
	runuser() {
		printf 'runuser %s\n' "$*" >>"${STUB_LOG}"
	}
	dump mariadb "${BATS_TEST_TMPDIR}/m.sql"
	grep -qxF 'mariadb-dump --user=root --all-databases --single-transaction --routines --events --triggers --hex-blob' "${STUB_LOG}"
	dump postgresql "${BATS_TEST_TMPDIR}/p.sql"
	grep -qxF "runuser -u postgres -- env -i PATH=${CLEAN_PATH} pg_dumpall -p 5433 --clean --if-exists" "${STUB_LOG}"
	[ "$(file_of mongodb)" = mongodb.archive ]
	[ "$(file_of valkey)" = valkey.rdb ]
	[ "$(file_of mysql)" = mysql.sql ]
	run dump other "${BATS_TEST_TMPDIR}/o"
	[ "${status}" -eq 1 ]
}

@test "Redis and Valkey are dumped once a fresh snapshot is saved, with the password in the environment" {
	load_dumps
	ETC_DIR=${BATS_TEST_TMPDIR}/etc
	DATA_ROOT=${BATS_TEST_TMPDIR}/lib
	mkdir -p "${ETC_DIR}" "${DATA_ROOT}/valkey"
	printf 'pw\n' >"${ETC_DIR}/valkey-password"
	printf 'RDB\n' >"${DATA_ROOT}/valkey/dump.rdb"
	# shellcheck disable=SC2329 # called by the functions under test
	first_program() {
		printf 'cli_stub'
	}
	SAVES=0
	# shellcheck disable=SC2329 # called by the functions under test
	cli_stub() {
		printf 'cli %s auth=%s\n' "$*" "${VALKEYCLI_AUTH:-}" >>"${STUB_LOG}"
		case ${*: -1} in
		lastsave) printf '%s\n' "$((1000 + SAVES))" ;;
		bgsave) SAVES=${TEST_SAVES:-1} ;;
		*) ;;
		esac
	}
	# shellcheck disable=SC2329 # called by the functions under test
	sleep() {
		:
	}
	dump_rdb valkey "${BATS_TEST_TMPDIR}/v.rdb"
	grep -qxF 'cli -p 6379 --no-auth-warning bgsave auth=pw' "${STUB_LOG}"
	[ "$(cat "${BATS_TEST_TMPDIR}/v.rdb")" = RDB ]
	SAVES=0
	TEST_SAVES=0
	run dump_rdb valkey "${BATS_TEST_TMPDIR}/w.rdb"
	[ "${status}" -eq 1 ]
	[ ! -e "${BATS_TEST_TMPDIR}/w.rdb" ]
}

@test "a run saves the data of the apps first and backs up the paths they list" {
	load_backup
	mkdir -p "${LSS_APP_BACKUP_STATE}" "${BATS_TEST_TMPDIR}/volume"
	printf '#!/bin/sh\necho apps >>"%s"\n' "${STUB_LOG}" >"${LSS_APP_BACKUP}"
	chmod +x "${LSS_APP_BACKUP}"
	printf '%s\n' "${BATS_TEST_TMPDIR}/volume" /does-not-exist-either >"${LSS_APP_BACKUP_STATE}/paths"
	cmd_run
	grep -qxF apps "${STUB_LOG}"
	grep -qxF "restic backup --tag lss --exclude-caches --exclude *.tmp /etc ${BATS_TEST_TMPDIR}/volume ${LSS_BACKUP_STATE}/canary" "${STUB_LOG}"
	printf '#!/bin/sh\nexit 1\n' >"${LSS_APP_BACKUP}"
	run cmd_run
	[ "${status}" -eq 1 ]
	[[ ${output} == *"saving the data of the apps failed; the backup goes on with the rest."* ]]
}

load_apps() {
	# shellcheck source=/dev/null
	source "${REPO_ROOT}/libexec/lss-app-backup"
	DOCKER=docker_stub
	mkdir -p "${REGISTRY}" "${BATS_TEST_TMPDIR}/volumes/lss-demo_data" "${BATS_TEST_TMPDIR}/volumes/lss-demo_html"
	printf 'app.db\n' >"${BATS_TEST_TMPDIR}/volumes/lss-demo_data/app.db"
	return
}

# docker stub for lss-app-backup: records the call; volume inspect prints the directory below volumes/ (missing
# ones fail), exec prints $DUMP (fails with $DUMP_EXIT), pause and unpause fail with $PAUSE_EXIT.
docker_stub() {
	printf 'docker %s\n' "$*" >>"${STUB_LOG}"
	case $* in
	'volume inspect'*)
		[[ -d ${BATS_TEST_TMPDIR}/volumes/${*: -1} ]] || return 1
		printf '%s\n' "${BATS_TEST_TMPDIR}/volumes/${*: -1}"
		;;
	*' exec '*)
		printf '%s' "${DUMP:-}"
		return "${DUMP_EXIT:-0}"
		;;
	*' pause '* | *' unpause '*) return "${PAUSE_EXIT:-0}" ;;
	*) ;;
	esac
	return 0
}

register() {
	printf 'PROJECT=lss-%s\nCOMPOSE=/etc/lss/containers/lss-%s/compose.yaml\n%s\n' "$1" "$1" "$2" >"${REGISTRY}/$1.conf"
	return
}

@test "app data: database dumps, copies of paused apps and the paths restic takes as they are" {
	load_apps
	register demo $'DB=postgres\nDB_USER=demo\nCOPY=data\nLIVE=html\nPATHS=/etc /does-not-exist'
	DUMP='SQL' run_backups
	local compose='docker compose --project-name lss-demo -f /etc/lss/containers/lss-demo/compose.yaml'
	grep -qxF "${compose} exec -T db pg_dumpall --username=demo --clean --if-exists" "${STUB_LOG}"
	grep -qxF "${compose} pause app" "${STUB_LOG}"
	grep -qxF "${compose} unpause app" "${STUB_LOG}"
	[ "$(cat "${OUT_ROOT}/demo/db.sql")" = SQL ]
	[ "$(cat "${OUT_ROOT}/demo/data/app.db")" = app.db ]
	[ "$(stat -c '%a' "${OUT_ROOT}/demo")" = 700 ]
	[ "$(cat "${STATE}/paths")" = "$(printf '%s\n' "${BATS_TEST_TMPDIR}/volumes/lss-demo_html" /etc "${OUT_ROOT}")" ]
	grep -q '^demo ok [0-9]*$' "${STATE}/status"
	# MariaDB: mariadb-dump as root with the password from the secret file, inside the container.
	register shop $'DB=mariadb'
	DUMP='SQL' run_backups shop
	grep -qF 'compose --project-name lss-shop -f /etc/lss/containers/lss-shop/compose.yaml exec -T db sh -c MYSQL_PWD=$(cat /run/secrets/db-root-password) exec mariadb-dump --user=root' "${STUB_LOG}"
	[ -s "${OUT_ROOT}/shop/db.sql" ]
}

@test "a failed dump or copy keeps the previous one, unpauses the app and fails the run" {
	load_apps
	register demo $'DB=postgres\nDB_USER=demo\nCOPY=data'
	mkdir -p "${OUT_ROOT}/demo/data"
	printf 'OLD\n' >"${OUT_ROOT}/demo/db.sql"
	printf 'OLD\n' >"${OUT_ROOT}/demo/data/app.db"
	# shellcheck disable=SC2329 # called by the functions under test
	cp() {
		return 1
	}
	DUMP='PART' DUMP_EXIT=1 run run_backups
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the database dump of demo failed; ${OUT_ROOT}/demo/db.sql keeps the previous one."* ]]
	[[ ${output} == *"the copy of the data of demo failed; ${OUT_ROOT}/demo keeps the previous one."* ]]
	[ "$(cat "${OUT_ROOT}/demo/db.sql")" = OLD ]
	[ "$(cat "${OUT_ROOT}/demo/data/app.db")" = OLD ]
	[ ! -e "${OUT_ROOT}/demo/db.sql.part" ]
	grep -q 'unpause app' "${STUB_LOG}"
	grep -q '^demo failed ' "${STATE}/status"
}

@test "an app that cannot be paused or unpaused, and a missing volume, fail the run" {
	load_apps
	# shellcheck disable=SC2329 # called by the functions under test
	sleep() {
		:
	}
	register demo $'COPY=data'
	PAUSE_EXIT=1 run run_backups demo
	[ "${status}" -eq 1 ]
	[[ ${output} == *"the copy of the data of demo failed"* ]]
	run ! grep -q 'unpause' "${STUB_LOG}"
	register demo $'COPY=data\nLIVE=gone'
	# Pausing works, unpausing never does.
	# shellcheck disable=SC2329 # called by the functions under test
	compose() {
		[[ $2 != unpause ]]
	}
	run run_backups demo
	[[ ${output} == *"the app of lss-demo stays paused; run docker compose unpause app."* ]]
	[[ ${output} == *"the volume gone of demo is missing."* ]]
	register demo $'COPY=gone'
	run run_backups demo
	[ "${status}" -eq 1 ]
}

@test "a run for named apps leaves the full list alone; unknown names and an empty registry are reported" {
	load_apps
	register demo $'LIVE=html'
	run_backups
	local before
	before=$(cat "${STATE}/paths")
	register other $'LIVE=data'
	mkdir -p "${BATS_TEST_TMPDIR}/volumes/lss-other_data"
	run_backups other
	[ "$(cat "${STATE}/paths")" = "${before}" ]
	run run_backups '../etc'
	[ "${status}" -eq 1 ]
	[[ ${output} == *"../etc is not registered"* ]]
	rm -f -- "${REGISTRY}"/*.conf
	run run_backups
	[ "${status}" -eq 0 ]
	[[ ${output} == *"0 apps are registered here; nothing to save."* ]]
	[ ! -s "${STATE}/paths" ]
	register bad $'DB=sqlite'
	run run_backups bad
	[ "${status}" -eq 1 ]
}

@test "the app backup script needs root" {
	if [[ ${EUID} -eq 0 ]]; then
		skip "runs as root"
	fi
	run bash "${REPO_ROOT}/libexec/lss-app-backup"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"must run as root."* ]]
}
