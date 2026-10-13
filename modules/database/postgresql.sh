# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="postgresql"
MOD_GROUP="database"
MOD_DESCRIPTION="PostgreSQL on localhost with SCRAM passwords (peer only for postgres), TLS, optional databases and users"
MOD_REQUIRES="system"
MOD_OPTIONS="version||Major version from the PostgreSQL project's repository (14 to 18); empty installs the distribution's version
listen|localhost|listen_addresses: localhost, * or addresses separated by commas
port|5432|TCP port
access|local|Firewall: local (no rule), vpn (WireGuard network only) or public
allow||Networks that may connect from other hosts (TLS and password only), CIDR, separated by spaces
databases||Databases to create, separated by spaces
users||Application users as user:database, separated by spaces; each owns its database and gets a generated password (lss secrets show postgresql-user-USER)"
MOD_PORTS="5432/tcp on localhost"
MOD_SECRETS="postgresql-user-<user>"

# Versions without a version option: Debian 12: 15, Debian 13: 17, Ubuntu 22.04: 14, 24.04: 16, 26.04: 18,
# RHEL 9: 16 (module stream; the default 13 is past its upstream end of life), RHEL 10: 16.

PG_SETTINGS=zz-lss.conf
PG_HBA=lss_hba.conf
PG_INITDB_OPTIONS="--auth-local=peer --auth-host=scram-sha-256"

_pg_name_ok() {
	local name=$1
	[[ ${name} =~ ^[a-z][a-z0-9_]{0,62}$ ]]
	return
}

# _pg_version: the major version in use (Debian family and PGDG installs; empty for the RHEL distribution package).
_pg_version() {
	local version dir
	version=$(opt version)
	if [[ -z ${version} ]] && os_is_debian; then
		for dir in /usr/lib/postgresql/*/bin/postgres; do
			[[ -x ${dir} ]] || continue
			dir=${dir%/bin/postgres}
			dir=${dir##*/}
			if [[ -z ${version} || ${dir} -gt ${version} ]]; then
				version=${dir}
			fi
		done
	fi
	printf '%s' "${version}"
	return
}

_pg_unit() {
	local version
	version=$(_pg_version)
	if os_is_debian; then
		printf 'postgresql@%s-main' "${version}"
	elif [[ -n $(opt version) ]]; then
		printf 'postgresql-%s' "${version}"
	else
		printf 'postgresql'
	fi
	return
}

_pg_data() {
	local version
	version=$(_pg_version)
	if os_is_debian; then
		printf '/var/lib/postgresql/%s/main' "${version}"
	elif [[ -n $(opt version) ]]; then
		printf '/var/lib/pgsql/%s/data' "${version}"
	else
		printf '/var/lib/pgsql/data'
	fi
	return
}

# Directory of the configuration files: /etc/postgresql/VERSION/main on the Debian family, the data directory on RHEL.
_pg_confdir() {
	if os_is_debian; then
		printf '/etc/postgresql/%s/main' "$(_pg_version)"
	else
		_pg_data
	fi
	return
}

_pg_packages() {
	local version
	version=$(opt version)
	if os_is_debian; then
		if [[ -n ${version} ]]; then printf 'postgresql-%s' "${version}"; else printf 'postgresql'; fi
	elif [[ -n ${version} ]]; then
		printf 'postgresql%s-server postgresql%s' "${version}" "${version}"
	else
		printf 'postgresql-server postgresql'
	fi
	return
}

_pg_psql() {
	local version
	version=$(opt version)
	if os_is_rhel && [[ -n ${version} ]]; then
		printf '/usr/pgsql-%s/bin/psql' "${version}"
	else
		printf 'psql'
	fi
	return
}

mod_check() {
	local version listen port access network database entry user dir
	version=$(opt version)
	listen=$(opt listen)
	port=$(opt_int port)
	access=$(opt access)
	[[ -z ${version} || ${version} =~ ^1[4-8]$ ]] || die "LSS_POSTGRESQL_VERSION must be empty or 14 to 18."
	[[ ${listen} =~ ^[A-Za-z0-9.:*-]+(,[A-Za-z0-9.:*-]+)*$ ]] ||
		die "LSS_POSTGRESQL_LISTEN must be localhost, * or addresses separated by commas."
	[[ ${port} -ge 1 && ${port} -le 65535 ]] || die "LSS_POSTGRESQL_PORT must be between 1 and 65535."
	[[ ${access} =~ ^(local|vpn|public)$ ]] || die "LSS_POSTGRESQL_ACCESS must be local, vpn or public."
	for network in $(opt allow); do
		[[ ${network} =~ ^[0-9A-Fa-f:.]+/[0-9]{1,3}$ ]] ||
			die "LSS_POSTGRESQL_ALLOW: '${network}' is not a network like 10.66.0.0/24."
	done
	if [[ ${access} != local ]]; then
		[[ ${listen} != localhost && ${listen} != 127.0.0.1 ]] ||
			die "LSS_POSTGRESQL_ACCESS=${access} needs LSS_POSTGRESQL_LISTEN set to an address other hosts can reach."
		[[ -n $(opt allow) ]] || die "LSS_POSTGRESQL_ACCESS=${access} needs the client networks in LSS_POSTGRESQL_ALLOW."
	fi
	for database in $(opt databases); do
		_pg_name_ok "${database}" || die "LSS_POSTGRESQL_DATABASES: '${database}' is not a valid name (a-z, 0-9, _)."
		[[ ! ${database} =~ ^(postgres|template0|template1)$ ]] ||
			die "LSS_POSTGRESQL_DATABASES: '${database}' is a reserved database."
	done
	for entry in $(opt users); do
		[[ ${entry} == *:* ]] || die "LSS_POSTGRESQL_USERS: '${entry}' must look like user:database."
		user=${entry%%:*}
		database=${entry#*:}
		_pg_name_ok "${user}" || die "LSS_POSTGRESQL_USERS: '${user}' is not a valid user name (a-z, 0-9, _)."
		_pg_name_ok "${database}" || die "LSS_POSTGRESQL_USERS: '${database}' is not a valid database name."
		[[ ! ${user} =~ ^(postgres|root|pg_.*)$ ]] || die "LSS_POSTGRESQL_USERS: '${user}' is a reserved role."
		[[ ! ${database} =~ ^(postgres|template0|template1)$ ]] ||
			die "LSS_POSTGRESQL_USERS: '${database}' is a reserved database."
	done
	[[ $(opt users | tr ' ' '\n' | cut -d ':' -f 2 | sort | uniq -d) == '' ]] ||
		die "LSS_POSTGRESQL_USERS: each database can belong to one user only."
	# Two clusters would fight for the port; moving to another version is a pg_upgrade, not a setting.
	if [[ -n ${version} ]]; then
		if os_is_debian; then
			for dir in /etc/postgresql/*/main; do
				[[ -d ${dir} && ${dir} != "/etc/postgresql/${version}/main" ]] || continue
				die "postgresql: a cluster of another version exists (${dir});" \
					"upgrade it with pg_upgradecluster or remove it first."
			done
		elif [[ -s /var/lib/pgsql/data/PG_VERSION ]]; then
			die "postgresql: the distribution's cluster in /var/lib/pgsql/data exists; upgrade it or remove it first."
		fi
	fi
	return
}

# RHEL 9 installs PostgreSQL 13 by default, whose upstream support ended in November 2025; lss takes the 16 stream,
# the version RHEL 10 ships. An existing installation keeps its version.
_pg_el9_stream() {
	local enabled
	pkg_is_installed postgresql-server && return 0
	enabled=$(dnf -q module list --enabled postgresql 2>/dev/null || true)
	[[ ${enabled} != *16* ]] || return 0
	log_command dnf -y -q module enable postgresql:16
	files_note_change "enabled the postgresql:16 module stream"
	return
}

mod_install() {
	local version
	version=$(opt version)
	if [[ -n ${version} ]]; then
		if os_is_debian; then repo_add pgdg; else repo_add "pgdg-${version}"; fi
	elif os_is_rhel && [[ ${OS_MAJOR} == 9 ]]; then
		_pg_el9_stream
	fi
	pkg_install_family "$(_pg_packages)" "$(_pg_packages)"
	if os_is_debian; then
		pkg_install ssl-cert
	else
		pkg_install openssl
	fi
	return
}

# The Debian family creates the main cluster with the package (peer and SCRAM, no trust); the RHEL family needs an
# explicit initdb, told not to fall back to trust. lss replaces the authentication with its own pg_hba before the
# first start either way.
_pg_cluster() {
	local version data
	version=$(_pg_version)
	data=$(_pg_data)
	[[ -s ${data}/PG_VERSION ]] && return 0
	if os_is_debian; then
		log_command pg_createcluster "${version}" main || die "postgresql: pg_createcluster ${version} main failed."
	elif [[ -n $(opt version) ]]; then
		PGSETUP_INITDB_OPTIONS=${PG_INITDB_OPTIONS} \
			log_command "/usr/pgsql-${version}/bin/postgresql-${version}-setup" initdb ||
			die "postgresql: initdb failed (see /var/lib/pgsql/initdb_postgresql-${version}.log)."
	else
		PGSETUP_INITDB_OPTIONS=${PG_INITDB_OPTIONS} log_command postgresql-setup --initdb ||
			die "postgresql: initdb failed (see /var/lib/pgsql/initdb_postgresql.log)."
	fi
	files_note_change "created the PostgreSQL cluster in ${data}"
	return
}

# Prints "CERT KEY": the snakeoil certificate of the ssl-cert package on the Debian family, else a self-signed one in
# the data directory, generated once by the postgres user (so root never writes into a directory postgres owns).
_pg_tls() {
	local data name
	if [[ -r /etc/ssl/certs/ssl-cert-snakeoil.pem && -r /etc/ssl/private/ssl-cert-snakeoil.key ]]; then
		printf '/etc/ssl/certs/ssl-cert-snakeoil.pem /etc/ssl/private/ssl-cert-snakeoil.key'
		return 0
	fi
	data=$(_pg_data)
	if [[ ! -s ${data}/server.crt || ! -s ${data}/server.key ]]; then
		name=$(hostname -f 2>/dev/null || hostname)
		(
			umask 077
			cd / && log_command runuser -u postgres -- openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 3650 \
				-subj "/CN=${name}" -keyout "${data}/server.key" -out "${data}/server.crt"
		) || die "postgresql: generating the TLS certificate failed."
		files_note_change "generated a self-signed TLS certificate in ${data}"
	fi
	printf '%s %s' "${data}/server.crt" "${data}/server.key"
	return
}

_pg_hba_content() {
	local network
	cat <<'EOF'
# Managed by lss (module postgresql). Only the postgres system user logs in without a password (peer, as the
# postgres role); every other role needs its SCRAM password, also on the local socket. No trust anywhere. Change
# LSS_POSTGRESQL_ALLOW and run lss configure postgresql.
# TYPE   DATABASE     USER      ADDRESS        METHOD
local    all          postgres                 peer
local    all          all                      scram-sha-256
host     all          all       127.0.0.1/32   scram-sha-256
host     all          all       ::1/128        scram-sha-256
local    replication  postgres                 peer
host     replication  all       127.0.0.1/32   scram-sha-256
host     replication  all       ::1/128        scram-sha-256
EOF
	for network in $(opt allow); do
		printf 'hostssl  all          all       %-14s scram-sha-256\n' "${network}"
	done
	return
}

# _pg_sql: runs the SQL on standard input as the postgres user over the local socket and prints the rows.
_pg_sql() {
	local psql port
	psql=$(_pg_psql)
	port=$(opt_int port)
	(cd / && runuser -u postgres -- "${psql}" -X -q -A -t -v ON_ERROR_STOP=1 -p "${port}" -d postgres)
	return
}

_pg_query() {
	local sql=$1
	_pg_sql <<<"${sql}"
	return
}

_pg_wait() {
	local i
	for ((i = 0; i < 60; i++)); do
		if [[ $(_pg_query 'SELECT 1' 2>/dev/null) == 1 ]]; then
			return 0
		fi
		sleep 1
	done
	die "postgresql: the server does not answer on its local socket."
}

# A port other than 5432 needs the postgresql_port_t label on SELinux systems.
_pg_selinux_port() {
	local port=$1 custom
	[[ ${port} != 5432 ]] || return 0
	os_is_rhel || return 0
	if ! command -v selinuxenabled >/dev/null 2>&1 || ! selinuxenabled; then
		return 0
	fi
	pkg_install policycoreutils-python-utils
	custom=$(semanage port -l -C 2>/dev/null | awk '$1 == "postgresql_port_t" && $2 == "tcp" { print $3 }')
	grep -qxF "${port}" <<<"${custom}" && return 0
	semanage port -a -t postgresql_port_t -p tcp "${port}" 2>/dev/null ||
		semanage port -m -t postgresql_port_t -p tcp "${port}"
	files_note_change "SELinux port ${port}/tcp for PostgreSQL"
	return
}

# Databases of LSS_POSTGRESQL_DATABASES (owned by postgres) and of LSS_POSTGRESQL_USERS (owned by their user).
_pg_databases() {
	local database entry owner current
	for database in $(opt databases); do
		if [[ -z $(_pg_query "SELECT 1 FROM pg_database WHERE datname = '${database}'") ]]; then
			_pg_query "CREATE DATABASE \"${database}\""
			files_note_change "created database ${database}"
		fi
	done
	for entry in $(opt users); do
		owner=${entry%%:*}
		database=${entry#*:}
		current=$(_pg_query "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = '${database}'")
		if [[ -z ${current} ]]; then
			_pg_query "CREATE DATABASE \"${database}\" OWNER \"${owner}\""
			files_note_change "created database ${database}"
		elif [[ ${current} != "${owner}" ]]; then
			_pg_query "ALTER DATABASE \"${database}\" OWNER TO \"${owner}\""
			files_note_change "database ${database} belongs to ${owner}"
		fi
	done
	return
}

# Each role is created once with its generated password, sent on standard input and hashed by the server with SCRAM.
_pg_users() {
	local entry user password
	for entry in $(opt users); do
		user=${entry%%:*}
		[[ -z $(_pg_query "SELECT 1 FROM pg_roles WHERE rolname = '${user}'") ]] || continue
		secret_load "postgresql-user-${user}" password
		_pg_sql <<<"SET password_encryption = 'scram-sha-256'; CREATE ROLE \"${user}\" LOGIN PASSWORD '${password}';"
		files_note_change "created database role ${user}"
		log_info "Password of ${user}: lss secrets show postgresql-user-${user}"
	done
	return
}

mod_configure() {
	local before changed=0 port unit confdir data tls cert key
	port=$(opt_int port)
	before=$(files_changes_of postgresql)
	_pg_cluster
	unit=$(_pg_unit)
	confdir=$(_pg_confdir)
	data=$(_pg_data)
	_pg_selinux_port "${port}"
	tls=$(_pg_tls)
	cert=${tls% *}
	key=${tls#* }
	if os_is_rhel; then
		# The RHEL configuration has no include directory; one line in postgresql.conf adds conf.d.
		[[ ! -L ${data}/conf.d ]] || die "postgresql: ${data}/conf.d is a symbolic link."
		install -d -m 0700 -o postgres -g postgres "${data}/conf.d"
		file_ensure_lines 0600 postgres:postgres "${data}/postgresql.conf" <<<"include_dir = 'conf.d'"
	fi
	file_write 0640 postgres:postgres "${confdir}/${PG_HBA}" < <(_pg_hba_content)
	file_write 0644 postgres:postgres "${confdir}/conf.d/${PG_SETTINGS}" <<EOF
# Managed by lss (module postgresql). Change LSS_POSTGRESQL_* in /etc/lss/lss.conf and run lss configure postgresql.
listen_addresses = '$(opt listen)'
port = ${port}
hba_file = '${confdir}/${PG_HBA}'
password_encryption = 'scram-sha-256'
ssl = on
ssl_cert_file = '${cert}'
ssl_key_file = '${key}'
ssl_min_protocol_version = 'TLSv1.2'
EOF
	if os_is_debian; then
		svc_sandbox "${unit}.service" ReadWritePaths=/var/lib/postgresql
	else
		svc_sandbox "${unit}.service" ReadWritePaths=/var/lib/pgsql
	fi
	[[ $(files_changes_of postgresql) == "${before}" ]] || changed=1
	svc_enable "${unit}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${unit}"
	fi
	_pg_wait
	_pg_users
	_pg_databases
	fw_allow "${port}/tcp:$(opt access)"
	return
}

# Every TCP socket on the port must be on a configured address: localhost means 127.0.0.1 and ::1; *, 0.0.0.0, :: and
# host names are not checked.
_pg_check_listen() {
	local port=$1 listen=$2 listeners address entry
	local -a allowed=()
	listeners=$(ss -Hltn "sport = :${port}" | awk '{ address = $4; sub(/:[0-9]+$/, "", address)
		sub(/%.*/, "", address); gsub(/[][]/, "", address); print address }')
	[[ -n ${listeners} ]] || die "postgresql: nothing listens on port ${port}."
	for entry in ${listen//,/ }; do
		case ${entry} in
		localhost) allowed+=(127.0.0.1 ::1) ;;
		'*' | 0.0.0.0 | ::) return 0 ;;
		*)
			[[ ${entry} =~ ^[0-9A-Fa-f:.]+$ ]] || return 0
			allowed+=("${entry}")
			;;
		esac
	done
	while IFS= read -r address; do
		[[ " ${allowed[*]} " == *" ${address} "* ]] ||
			die "postgresql: port ${port} is open on ${address}, expected ${allowed[*]} only."
	done <<<"${listeners}"
	return
}

mod_verify() {
	local unit result
	unit=$(_pg_unit)
	svc_is_active "${unit}" || die "postgresql: the service ${unit} is not running."
	result=$(_pg_query 'SELECT 1') || die "postgresql: psql as postgres fails."
	[[ ${result} == 1 ]] || die "postgresql: SELECT 1 returned '${result}'."
	result=$(_pg_query 'SHOW password_encryption')
	[[ ${result} == scram-sha-256 ]] || die "postgresql: password_encryption is ${result}, expected scram-sha-256."
	[[ $(_pg_query 'SHOW ssl') == on ]] || die "postgresql: TLS is off."
	result=$(_pg_query "SELECT count(*) FROM pg_hba_file_rules WHERE auth_method NOT IN ('peer', 'scram-sha-256')
		OR (auth_method = 'peer' AND user_name <> '{postgres}')")
	[[ ${result} == 0 ]] || die "postgresql: pg_hba allows more than peer for postgres and SCRAM passwords."
	_pg_check_listen "$(opt_int port)" "$(opt listen)"
	return
}

mod_remove() {
	local unit confdir path version
	version=$(opt version)
	unit=$(_pg_unit)
	confdir=$(_pg_confdir)
	svc_disable "${unit}"
	svc_dropin_remove "${unit}.service" lss-sandbox
	# Without these two files the cluster falls back to the configuration and pg_hba.conf of the distribution.
	file_remove "${confdir}/conf.d/${PG_SETTINGS}"
	file_remove "${confdir}/${PG_HBA}"
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	pkg_remove_family "$(_pg_packages) postgresql-common" "$(_pg_packages)"
	if [[ -n ${version} ]]; then
		if os_is_debian; then repo_remove pgdg; else repo_remove "pgdg-${version}"; fi
	fi
	# Only these fixed directories, never through a symbolic link.
	for path in /var/lib/postgresql /etc/postgresql /var/lib/pgsql; do
		[[ ! -L ${path} ]] || die "postgresql: refusing to delete ${path}: it is a symbolic link."
		if [[ -d ${path} ]]; then
			rm -rf -- "${path}"
			files_note_change "deleted ${path}"
		fi
	done
	for path in "${LSS_SECRETS_DIR}"/postgresql-user-*; do
		[[ -f ${path} ]] || continue
		secret_remove "${path##*/}"
	done
	return
}
