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
databases||Databases to create, owned by postgres, separated by spaces
users||Application users as user:database, separated by spaces; each owns its database, can reach only that one and gets a generated password (lss secrets show postgresql-user-USER)"
MOD_PORTS="5432/tcp on localhost"
MOD_SECRETS="postgresql-user-<user>"

# Versions without a version option: Debian 12: 15, Debian 13: 17, Ubuntu 22.04: 14, 24.04: 16, 26.04: 18,
# RHEL 9: 16 (module stream; the default 13 is past its upstream end of life), RHEL 10: 16.

PG_SETTINGS=/etc/lss/postgresql/postgresql.conf
PG_HBA=/etc/lss/postgresql/pg_hba.conf
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
		[[ -n $(opt users) ]] || die "LSS_POSTGRESQL_ACCESS=${access} needs the remote roles in LSS_POSTGRESQL_USERS."
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
	if ! _pg_as_postgres test -s "${data}/server.crt" || ! _pg_as_postgres test -s "${data}/server.key"; then
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

# _pg_as_postgres COMMAND...: runs a command as the postgres user from /. Everything lss does inside directories that
# postgres owns (data directory, /etc/postgresql/VERSION/main) goes through here, so a link planted there can never
# make root write, chmod or chown another file.
_pg_as_postgres() {
	(cd / && runuser -u postgres -- "$@")
	return
}

# _pg_include FILE: appends "include_if_exists = '/etc/lss/postgresql/postgresql.conf'" to the cluster's
# postgresql.conf once, as the postgres user. The line is harmless after the module is removed (the file is gone).
_pg_include() {
	local file=$1 line
	line="include_if_exists = '${PG_SETTINGS}'"
	_pg_as_postgres grep -qxF -- "${line}" "${file}" && return 0
	_pg_as_postgres sh -c 'printf "%s\n" "$2" >>"$1"' sh "${file}" "${line}" ||
		die "postgresql: could not add the lss settings to ${file}."
	files_note_change "included ${PG_SETTINGS} in ${file}"
	return
}

# pg_hba: only the postgres system user logs in without a password (peer); each application role reaches only its
# own database, with its SCRAM password, on the local socket, over loopback and (TLS only) from LSS_POSTGRESQL_ALLOW.
# No "all" for application roles and no trust anywhere.
_pg_hba_content() {
	local entry user database network
	cat <<'EOF'
# Managed by lss (module postgresql). Change LSS_POSTGRESQL_USERS or LSS_POSTGRESQL_ALLOW and run
# lss configure postgresql.
# TYPE   DATABASE     USER      ADDRESS          METHOD
local    all          postgres                   peer
local    replication  postgres                   peer
EOF
	for entry in $(opt users); do
		user=${entry%%:*}
		database=${entry#*:}
		printf '%-8s %-12s %-9s %-16s %s\n' local "${database}" "${user}" '' scram-sha-256 \
			host "${database}" "${user}" 127.0.0.1/32 scram-sha-256 host "${database}" "${user}" ::1/128 scram-sha-256
		for network in $(opt allow); do
			printf '%-8s %-12s %-9s %-16s %s\n' hostssl "${database}" "${user}" "${network}" scram-sha-256
		done
	done
	return
}

# _pg_sql [DATABASE]: runs the SQL on standard input as the postgres user over the local socket and prints the rows.
_pg_sql() {
	local database=${1:-postgres} psql port
	psql=$(_pg_psql)
	port=$(opt_int port)
	_pg_as_postgres "${psql}" -X -q -A -t -v ON_ERROR_STOP=1 -p "${port}" -d "${database}"
	return
}

# _pg_query SQL [DATABASE]
_pg_query() {
	local sql=$1 database=${2:-postgres}
	_pg_sql "${database}" <<<"${sql}"
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

# Nobody but the owner (and superusers) may connect to a database lss created: CONNECT is revoked from PUBLIC.
_pg_private() {
	local database=$1 public
	public=$(_pg_query "SELECT count(*) FROM pg_database d, aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a
		WHERE d.datname = '${database}' AND a.grantee = 0 AND a.privilege_type = 'CONNECT'")
	if [[ ${public} != 0 ]]; then
		_pg_query "REVOKE CONNECT ON DATABASE \"${database}\" FROM PUBLIC"
		files_note_change "revoked CONNECT on ${database} from PUBLIC"
	fi
	return
}

# Before PostgreSQL 15 every role may create objects in the public schema of every database; lss revokes that and
# hands the schema to the database's user, which is what PostgreSQL 15 and later do by default.
_pg_public_schema() {
	local database=$1 owner=$2 result
	result=$(_pg_query "SELECT has_schema_privilege('public', 'public', 'CREATE')" "${database}")
	if [[ ${result} == t ]]; then
		_pg_query 'REVOKE CREATE ON SCHEMA public FROM PUBLIC' "${database}"
		files_note_change "revoked CREATE on the public schema of ${database} from PUBLIC"
	fi
	[[ -n ${owner} ]] || return 0
	result=$(_pg_query "SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'" \
		"${database}")
	if [[ ${result} != "${owner}" && ${result} != pg_database_owner ]]; then
		_pg_query "ALTER SCHEMA public OWNER TO \"${owner}\"" "${database}"
		files_note_change "the public schema of ${database} belongs to ${owner}"
	fi
	return
}

# Databases of LSS_POSTGRESQL_DATABASES (owned by postgres) and of LSS_POSTGRESQL_USERS (owned by their user), each
# private to its owner.
_pg_databases() {
	local database entry owner current
	for database in $(opt databases); do
		if [[ -z $(_pg_query "SELECT 1 FROM pg_database WHERE datname = '${database}'") ]]; then
			_pg_query "CREATE DATABASE \"${database}\""
			files_note_change "created database ${database}"
		fi
		_pg_private "${database}"
		_pg_public_schema "${database}" ''
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
		_pg_private "${database}"
		_pg_public_schema "${database}" "${owner}"
	done
	return
}

# Each role is created once with its generated password, sent on standard input and hashed by the server with SCRAM.
# Application roles never get superuser, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS; every run takes them away again.
_pg_users() {
	local entry user password powers
	for entry in $(opt users); do
		user=${entry%%:*}
		if [[ -z $(_pg_query "SELECT 1 FROM pg_roles WHERE rolname = '${user}'") ]]; then
			secret_load "postgresql-user-${user}" password
			_pg_sql <<<"SET password_encryption = 'scram-sha-256';
CREATE ROLE \"${user}\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}';"
			files_note_change "created database role ${user}"
			log_info "Password of ${user}: lss secrets show postgresql-user-${user}"
		fi
		powers=$(_pg_query "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
			FROM pg_roles WHERE rolname = '${user}'")
		if [[ ${powers} == t ]]; then
			_pg_query "ALTER ROLE \"${user}\" NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
			files_note_change "took the extra powers of role ${user} away"
		fi
	done
	return
}

mod_configure() {
	local before changed=0 port unit tls cert key hba
	port=$(opt_int port)
	before=$(files_changes_of postgresql)
	_pg_cluster
	unit=$(_pg_unit)
	_pg_selinux_port "${port}"
	tls=$(_pg_tls)
	cert=${tls% *}
	key=${tls#* }
	# The lss files live in /etc/lss/postgresql (root-owned, readable by the postgres group); only the include line
	# goes into postgresql.conf, written as the postgres user.
	hba=$(_pg_hba_content)
	file_write 0640 root:postgres "${PG_HBA}" <<<"${hba}"
	file_write 0640 root:postgres "${PG_SETTINGS}" <<EOF
# Managed by lss (module postgresql). Change LSS_POSTGRESQL_* in /etc/lss/lss.conf and run lss configure postgresql.
listen_addresses = '$(opt listen)'
port = ${port}
hba_file = '${PG_HBA}'
password_encryption = 'scram-sha-256'
ssl = on
ssl_cert_file = '${cert}'
ssl_key_file = '${key}'
ssl_min_protocol_version = 'TLSv1.2'
EOF
	_pg_include "$(_pg_confdir)/postgresql.conf"
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
	[[ $(_pg_query 'SHOW hba_file') == "${PG_HBA}" ]] || die "postgresql: the server does not use ${PG_HBA}."
	result=$(_pg_query "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL
		OR auth_method NOT IN ('peer', 'scram-sha-256')
		OR (auth_method = 'peer' AND user_name <> '{postgres}')
		OR (user_name <> '{postgres}' AND ('all' = ANY (user_name) OR 'all' = ANY (database)))")
	[[ ${result} == 0 ]] ||
		die "postgresql: pg_hba allows more than peer for postgres and SCRAM for each role on its own database."
	_pg_check_listen "$(opt_int port)" "$(opt listen)"
	return
}

mod_remove() {
	local unit path version
	version=$(opt version)
	unit=$(_pg_unit)
	svc_disable "${unit}"
	svc_dropin_remove "${unit}.service" lss-sandbox
	# Without these files the include line in postgresql.conf finds nothing, and the cluster falls back to the
	# configuration and pg_hba.conf of the distribution.
	file_remove "${PG_SETTINGS}"
	file_remove "${PG_HBA}"
	rmdir "${PG_SETTINGS%/*}" 2>/dev/null || true
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
