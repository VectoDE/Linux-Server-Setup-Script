# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="db-dumps"
MOD_GROUP="backup"
MOD_DESCRIPTION="Consistent dumps of the MariaDB, MySQL, PostgreSQL, MongoDB, Redis and Valkey servers lss installed, before every restic backup"
MOD_REQUIRES="restic"
MOD_OPTIONS="dir|/var/backups/lss-db|Directory of the dumps (root only); restic backs it up when it is in LSS_RESTIC_PATHS"
MOD_PORTS="none"

# A copy of a database's files taken while it runs may not load again; a dump does. libexec/lss-db-dumps finds the
# installed engines at run time, so databases added later are dumped without lss configure db-dumps.
DUMPS_SCRIPT=/usr/local/lib/lss/db-dumps
DUMPS_CONF=/etc/lss/db-dumps.conf
DUMPS_STATUS=/var/lib/lss/db-dumps/status

mod_check() {
	[[ $(opt dir) =~ ^/var/backups/[A-Za-z0-9._-]+$ ]] || die "LSS_DB_DUMPS_DIR must be a directory below /var/backups."
	if [[ " $(config_option restic paths '') " != *" $(opt dir) "* && -n $(config_option restic paths '') ]]; then
		log_warn "db-dumps: $(opt dir) is not in LSS_RESTIC_PATHS, so the dumps stay on this server only."
	fi
	return
}

# mongodump is a separate package from the MongoDB repository the mongodb module set up; configure installs it too,
# for a mongodb module that came later.
mod_install() {
	if state_installed mongodb; then
		pkg_install mongodb-database-tools
	fi
	return
}

mod_configure() {
	mod_install
	install -d -m 0700 "$(opt dir)"
	file_write 0755 root:root "${DUMPS_SCRIPT}" <"${LSS_ROOT}/libexec/lss-db-dumps"
	file_write 0600 root:root "${DUMPS_CONF}" <<EOF
# Managed by lss (module db-dumps). Change LSS_DB_DUMPS_* (and the ports of the database modules) in /etc/lss/lss.conf
# and run lss configure db-dumps.
DB_DUMPS_DIR=$(opt dir)
DB_POSTGRESQL_PORT=$(config_option postgresql port 5432)
DB_MONGODB_PORT=$(config_option mongodb port 27017)
DB_REDIS_PORT=$(config_option redis port 6379)
DB_VALKEY_PORT=$(config_option valkey port 6379)
EOF
	return
}

# _dumps_missing: the installed engines without a successful dump in the status file.
_dumps_missing() {
	local engine
	for engine in mariadb mysql postgresql mongodb redis valkey; do
		state_installed "${engine}" || continue
		[[ -f ${DUMPS_STATUS} ]] && grep -q "^${engine} ok " "${DUMPS_STATUS}" && continue
		printf '%s ' "${engine}"
	done
	return
}

mod_verify() {
	[[ -x ${DUMPS_SCRIPT} ]] || die "db-dumps: ${DUMPS_SCRIPT} is missing."
	[[ $(stat -c '%a' "${DUMPS_CONF}") == 600 ]] || die "db-dumps: ${DUMPS_CONF} must be mode 600."
	if state_installed mongodb && ! command -v mongodump >/dev/null 2>&1; then
		die "db-dumps: mongodump is missing; run lss configure db-dumps."
	fi
	# Dumps run with the backup; here only for engines that have never been dumped, so a second verify stays quiet.
	if [[ -n $(_dumps_missing) ]]; then
		"${DUMPS_SCRIPT}" || die "db-dumps: the dump of $(_dumps_missing)failed; see above."
	fi
	return
}

mod_remove() {
	file_remove "${DUMPS_SCRIPT}"
	file_remove "${DUMPS_CONF}"
	pkg_remove mongodb-database-tools
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	rm -rf -- "$(opt dir)"
	mon_delete /var/lib/lss/db-dumps
	files_note_change "deleted the database dumps"
	return
}
