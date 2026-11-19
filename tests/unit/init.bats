#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Init systems in lib/service.sh: detection, OpenRC, SysV and Upstart services, and svc_schedule (systemd timer or cron
# job). The service tools are stubs (tests/fixtures/bin) that record their calls in $STUB_LOG.

setup() {
	load helpers
	lss_test_setup
	unset LSS_INIT
	export SVC_SYSTEMD_RUN=${BATS_TEST_TMPDIR}/run-systemd
	export SVC_OPENRC_RUN=${BATS_TEST_TMPDIR}/run-openrc
	export SVC_INITD=${BATS_TEST_TMPDIR}/init.d
	export SVC_UPSTART_DIR=${BATS_TEST_TMPDIR}/init
	export SVC_RC_DIR=${BATS_TEST_TMPDIR}/etc
	export SVC_CRON_DIR=${BATS_TEST_TMPDIR}/cron.d
	export LSS_SYSTEMD_TIMER_DIR=${BATS_TEST_TMPDIR}/timers
	mkdir -p "${SVC_INITD}" "${SVC_UPSTART_DIR}" "${SVC_RC_DIR}/rc2.d"
	printf '#!/bin/sh\n' >"${SVC_INITD}/nginx"
	chmod +x "${SVC_INITD}/nginx"
	WRITES=${BATS_TEST_TMPDIR}/writes
	return
}

record_writes() {
	# shellcheck disable=SC2329 # replaces file_write of lib/files.sh
	file_write() {
		printf '== %s %s %s\n' "$1" "$2" "$3" >>"${WRITES}"
		cat >>"${WRITES}"
		LSS_FILE_CHANGED=1
	}
}

@test "the init system is detected from its runtime directory, Upstart from initctl, SysV from /etc/init.d" {
	mkdir -p "${SVC_SYSTEMD_RUN}" "${SVC_OPENRC_RUN}"
	[ "$(svc_init)" = systemd ]
	svc_is_systemd
	rmdir "${SVC_SYSTEMD_RUN}"
	[ "$(svc_init)" = openrc ]
	rmdir "${SVC_OPENRC_RUN}"
	STUB_OUT_initctl='initctl (upstart 1.12.1)' run svc_init
	[ "${output}" = upstart ]
	[ "$(svc_init)" = sysv ]
	rm -rf -- "${SVC_INITD}"
	[ "$(svc_init)" = unknown ]
	run ! svc_is_systemd
	LSS_INIT=openrc run svc_init
	[ "${output}" = openrc ]
}

@test "an unknown init system has no services" {
	export LSS_INIT=unknown
	run ! svc_exists nginx
	run ! svc_is_active nginx
	run ! svc_is_enabled nginx
	run svc_enable nginx
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Could not start nginx."* ]]
}

@test "OpenRC: rc-update enables, rc-service starts, restarts, reloads and stops" {
	export LSS_INIT=openrc
	svc_exists nginx.service
	run ! svc_exists nope
	STUB_EXIT_rc_service=3 run ! svc_is_active nginx
	svc_is_active nginx
	STUB_OUT_rc_update=' nginx | default' svc_is_enabled nginx
	STUB_OUT_rc_update=' sshd | default' run ! svc_is_enabled nginx
	# Not enabled yet: enable and start.
	svc_enable nginx.service
	grep -qx 'rc-update add nginx default' "${STUB_LOG}"
	grep -qx 'rc-service nginx start' "${STUB_LOG}"
	[ "$(files_changes_of core)" = 1 ]
	# Enabled and running: nothing happens.
	: >"${STUB_LOG}"
	STUB_OUT_rc_update=' nginx | default' svc_enable nginx
	run ! grep -q 'rc-update add' "${STUB_LOG}"
	svc_restart nginx
	grep -qx 'rc-service nginx restart' "${STUB_LOG}"
	svc_reload nginx
	grep -qx 'rc-service nginx reload' "${STUB_LOG}"
	STUB_OUT_rc_update=' nginx | default' svc_disable nginx
	grep -qx 'rc-service nginx stop' "${STUB_LOG}"
	grep -qx 'rc-update del nginx default' "${STUB_LOG}"
	# A service that does not start stops the run.
	STUB_EXIT_rc_service=1 run svc_enable nginx
	[ "${status}" -eq 1 ]
	[[ ${output} == *"nginx is not running."* ]]
	[[ ${output} == *"Could not start nginx."* ]]
	STUB_EXIT_rc_service=1 run svc_restart nginx
	[ "${status}" -eq 1 ]
}

@test "a service that cannot reload is restarted" {
	export LSS_INIT=openrc
	: >"${STUB_LOG}"
	STUB_EXIT_rc_service=1 run svc_reload nginx
	[ "${status}" -eq 1 ]
	grep -qx 'rc-service nginx reload' "${STUB_LOG}"
	grep -qx 'rc-service nginx restart' "${STUB_LOG}"
}

@test "SysV: start links decide what is enabled; update-rc.d or chkconfig set them" {
	export LSS_INIT=sysv
	run ! svc_is_enabled nginx
	ln -s ../init.d/nginx "${SVC_RC_DIR}/rc2.d/S01nginx"
	svc_is_enabled nginx
	svc_is_active nginx
	STUB_EXIT_service=3 run ! svc_is_active nginx
	rm "${SVC_RC_DIR}/rc2.d/S01nginx"
	svc_enable nginx
	grep -qx 'update-rc.d nginx defaults' "${STUB_LOG}"
	grep -qx 'service nginx start' "${STUB_LOG}"
	ln -s ../init.d/nginx "${SVC_RC_DIR}/rc2.d/S01nginx"
	svc_restart nginx
	grep -qx 'service nginx restart' "${STUB_LOG}"
	svc_reload nginx
	grep -qx 'service nginx reload' "${STUB_LOG}"
	svc_disable nginx
	grep -qx 'service nginx stop' "${STUB_LOG}"
	grep -qx 'update-rc.d nginx disable' "${STUB_LOG}"
	# chkconfig where update-rc.d is missing (RHEL family).
	: >"${STUB_LOG}"
	# shellcheck disable=SC2329 # called by _svc_sysv_on and _svc_sysv_off
	command() {
		[[ $1 == -v && $2 == update-rc.d ]] && return 1
		builtin command "$@"
	}
	_svc_sysv_on nginx
	_svc_sysv_off nginx
	grep -qx 'chkconfig nginx on' "${STUB_LOG}"
	grep -qx 'chkconfig nginx off' "${STUB_LOG}"
}

@test "Upstart: jobs start with initctl and are disabled with a manual override" {
	export LSS_INIT=upstart
	printf 'start on runlevel [2345]\n' >"${SVC_UPSTART_DIR}/redis.conf"
	svc_exists redis
	svc_exists nginx
	svc_is_enabled redis
	STUB_OUT_initctl='redis start/running, process 42' svc_is_active redis
	STUB_OUT_initctl='redis stop/waiting' run ! svc_is_active redis
	svc_enable redis
	grep -qx 'initctl start redis' "${STUB_LOG}"
	svc_restart redis
	grep -qx 'initctl restart redis' "${STUB_LOG}"
	svc_reload redis
	grep -qx 'initctl reload redis' "${STUB_LOG}"
	STUB_OUT_initctl='redis start/running, process 42' svc_disable redis
	[ "$(cat "${SVC_UPSTART_DIR}/redis.override")" = manual ]
	grep -qx 'initctl stop redis' "${STUB_LOG}"
	run ! svc_is_enabled redis
	# Enabling removes the override again.
	STUB_OUT_initctl='redis start/running, process 42' svc_enable redis
	[ ! -e "${SVC_UPSTART_DIR}/redis.override" ]
	# A job that fails to restart is started instead.
	: >"${STUB_LOG}"
	STUB_EXIT_initctl=1 run svc_restart redis
	grep -qx 'initctl start redis' "${STUB_LOG}"
}

@test "Upstart runs the SysV scripts of services without a job" {
	export LSS_INIT=upstart
	svc_is_active nginx
	run ! svc_is_enabled nginx
	svc_enable nginx
	grep -qx 'service nginx start' "${STUB_LOG}"
	svc_restart nginx
	grep -qx 'service nginx restart' "${STUB_LOG}"
	svc_reload nginx
	grep -qx 'service nginx reload' "${STUB_LOG}"
	svc_disable nginx
	grep -qx 'service nginx stop' "${STUB_LOG}"
}

@test "without systemd there are no drop-ins, units, timer stamps or daemon reloads" {
	export LSS_INIT=openrc
	record_writes
	svc_dropin nginx.service lss <<<'[Service]'
	svc_unit lss-demo.service <<<'[Unit]'
	svc_daemon_reload
	svc_timer_skip_missed demo.timer
	[ ! -e "${WRITES}" ]
	run ! grep -q systemctl "${STUB_LOG}"
}

@test "OnCalendar expressions become cron times" {
	[ "$(svc_calendar_cron '*-*-* 03:30:00')" = '30 3 * * *' ]
	[ "$(svc_calendar_cron '*-*-* 3:05')" = '5 3 * * *' ]
	[ "$(svc_calendar_cron 'Sun *-*-* 06:00:00')" = '0 6 * * 0' ]
	[ "$(svc_calendar_cron 'Mon,Thu *-*-* 06:00:00')" = '0 6 * * 1,4' ]
	[ "$(svc_calendar_cron 'Mon..Fri *-*-* 22:15')" = '15 22 * * 1-5' ]
	[ "$(svc_calendar_cron '*-*-* 0,12:00:00')" = '0 0,12 * * *' ]
	[ "$(svc_calendar_cron '*-*-* *:15:00')" = '15 * * * *' ]
	[ "$(svc_calendar_cron daily)" = '0 0 * * *' ]
	[ "$(svc_calendar_cron weekly)" = '0 0 * * 1' ]
	[ "$(svc_calendar_cron monthly)" = '0 0 1 * *' ]
	[ "$(svc_calendar_cron hourly)" = '0 * * * *' ]
	local bad
	for bad in '*-*-* 03:30:15' '2026-*-* 03:00' 'Funday *-*-* 03:00' '*-*-* 24:00' '*-*-* 03:60' 'yearly' '*-*-*' \
		'*-*-* 3/2:00'; do
		run svc_calendar_cron "${bad}"
		[ "${status}" -eq 1 ]
	done
}

@test "svc_schedule writes a persistent systemd timer, or a cron job without systemd" {
	record_writes
	export LSS_INIT=systemd
	LSS_MODULE=demo svc_schedule lss-demo '*-*-* 03:30:00' 'Demo check' /usr/local/sbin/lss-demo --quiet
	grep -qxF '== 0644 root:root /etc/systemd/system/lss-demo.service' "${WRITES}"
	grep -qxF 'ExecStart=/usr/local/sbin/lss-demo --quiet' "${WRITES}"
	grep -qxF '== 0644 root:root /etc/systemd/system/lss-demo.timer' "${WRITES}"
	grep -qxF 'OnCalendar=*-*-* 03:30:00' "${WRITES}"
	grep -qxF 'Persistent=true' "${WRITES}"
	grep -q 'systemctl enable --now lss-demo.timer' "${STUB_LOG}"
	rm "${WRITES}"
	export LSS_INIT=openrc
	LSS_MODULE=demo svc_schedule lss-demo 'Sun *-*-* 06:00:00' 'Demo check' /usr/local/sbin/lss-demo --quiet
	grep -qxF "== 0644 root:root ${SVC_CRON_DIR}/lss-demo" "${WRITES}"
	grep -qxF '0 6 * * 0 root /usr/local/sbin/lss-demo --quiet' "${WRITES}"
	run ! grep -q systemd "${WRITES}"
}

@test "svc_schedule refuses bad names, empty commands, percent signs and schedules cron cannot express" {
	record_writes
	export LSS_INIT=sysv
	run svc_schedule 'bad name' daily 'x' /bin/true
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Invalid schedule name 'bad name'."* ]]
	run svc_schedule demo daily 'x'
	[ "${status}" -eq 1 ]
	[[ ${output} == *"The schedule demo has no command."* ]]
	run svc_schedule demo daily 'x' date +%F
	[ "${status}" -eq 1 ]
	[[ ${output} == *"contains % or a line break."* ]]
	run svc_schedule demo '*-*-* 03:30:15' 'x' /bin/true
	[ "${status}" -eq 1 ]
	[[ ${output} == *"The schedule '*-*-* 03:30:15' of demo has no cron form."* ]]
	[ ! -e "${WRITES}" ]
}

@test "svc_schedule_remove takes the timer, the service and the cron job away" {
	# shellcheck disable=SC2329 # called by svc_schedule_remove
	file_remove() { printf 'file_remove %s\n' "$1" >>"${STUB_LOG}"; }
	export LSS_INIT=systemd STUB_ACTIVE_UNITS=lss-demo.timer
	svc_schedule_remove lss-demo
	grep -q 'systemctl disable --now lss-demo.timer' "${STUB_LOG}"
	grep -qxF 'file_remove /etc/systemd/system/lss-demo.timer' "${STUB_LOG}"
	grep -qxF 'file_remove /etc/systemd/system/lss-demo.service' "${STUB_LOG}"
	grep -qxF "file_remove ${SVC_CRON_DIR}/lss-demo" "${STUB_LOG}"
	: >"${STUB_LOG}"
	export LSS_INIT=openrc
	svc_schedule_remove lss-demo
	run ! grep -q systemctl "${STUB_LOG}"
	grep -qxF "file_remove ${SVC_CRON_DIR}/lss-demo" "${STUB_LOG}"
}
