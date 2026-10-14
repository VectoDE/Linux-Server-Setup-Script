# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="mariadb"
MOD_GROUP="database"
MOD_DESCRIPTION="MariaDB server on 127.0.0.1, secured like mysql_secure_installation, root through the Unix socket, optional databases and users"
MOD_REQUIRES="system"
MOD_CONFLICTS="mysql"
MOD_OPTIONS="bind|127.0.0.1|Address the server listens on (0.0.0.0 or :: for every address)
port|3306|TCP port
access|local|Firewall: local (no rule), vpn (WireGuard network only) or public
databases||Databases to create, separated by spaces
users||Application users as user:database, separated by spaces; each gets all privileges on its database from localhost and a generated password (lss secrets show mariadb-user-USER)"
MOD_PORTS="3306/tcp on 127.0.0.1"
MOD_SECRETS="mariadb-user-<user>"

MARIADB_UNIT=mariadb
# Where MySQL keeps its data; MariaDB used the same directory until Ubuntu 26.04 moved it to /var/lib/mariadb.
MARIADB_MYSQL_DATA=/var/lib/mysql

# _mariadb_data: the data directory the installed server is configured for, one of the two the packages use.
_mariadb_data() {
	local dir='' tool
	for tool in mariadb-print-defaults my_print_defaults; do
		command -v "${tool}" >/dev/null 2>&1 || continue
		dir=$("${tool}" --mysqld 2>/dev/null | sed -n 's/^--datadir=//p' | tail -n 1)
		break
	done
	dir=${dir%/}
	case ${dir} in
	'') printf '%s' "${MARIADB_MYSQL_DATA}" ;;
	/var/lib/mysql | /var/lib/mariadb) printf '%s' "${dir}" ;;
	*) die "mariadb: the data directory ${dir} is not one lss manages (/var/lib/mysql or /var/lib/mariadb)." ;;
	esac
	return
}

_mariadb_conf() {
	if os_is_debian; then
		printf '/etc/mysql/mariadb.conf.d/zz-lss.cnf'
	else
		printf '/etc/my.cnf.d/zz-lss.cnf'
	fi
	return
}

_mariadb_name_ok() {
	local name=$1
	[[ ${name} =~ ^[a-z][a-z0-9_]{0,31}$ ]]
	return
}

_mariadb_is_loopback() {
	local address=$1
	[[ ${address} == 127.* || ${address} == ::1 ]]
	return
}

mod_check() {
	local bind port access database entry user
	bind=$(opt bind)
	port=$(opt_int port)
	access=$(opt access)
	[[ ${bind} =~ ^[0-9A-Fa-f:.]+$ ]] || die "LSS_MARIADB_BIND '${bind}' is not an IP address."
	[[ ${port} -ge 1 && ${port} -le 65535 ]] || die "LSS_MARIADB_PORT must be between 1 and 65535."
	[[ ${access} =~ ^(local|vpn|public)$ ]] || die "LSS_MARIADB_ACCESS must be local, vpn or public."
	if [[ ${access} != local ]] && _mariadb_is_loopback "${bind}"; then
		die "LSS_MARIADB_ACCESS=${access} needs LSS_MARIADB_BIND set to an address other hosts can reach."
	fi
	for database in $(opt databases); do
		_mariadb_name_ok "${database}" || die "LSS_MARIADB_DATABASES: '${database}' is not a valid name (a-z, 0-9, _)."
		[[ ! ${database} =~ ^(mysql|information_schema|performance_schema|sys|test)$ ]] ||
			die "LSS_MARIADB_DATABASES: '${database}' is a reserved database."
	done
	for entry in $(opt users); do
		[[ ${entry} == *:* ]] || die "LSS_MARIADB_USERS: '${entry}' must look like user:database."
		user=${entry%%:*}
		database=${entry#*:}
		_mariadb_name_ok "${user}" || die "LSS_MARIADB_USERS: '${user}' is not a valid user name (a-z, 0-9, _)."
		_mariadb_name_ok "${database}" || die "LSS_MARIADB_USERS: '${database}' is not a valid database name."
		[[ ! ${user} =~ ^(root|mysql|mariadb)$ ]] || die "LSS_MARIADB_USERS: '${user}' is a reserved account."
		[[ ! ${database} =~ ^(mysql|information_schema|performance_schema|sys|test)$ ]] ||
			die "LSS_MARIADB_USERS: '${database}' is a reserved database."
	done
	# MySQL 8 keeps its data dictionary in mysql.ibd; MariaDB cannot open such a data directory.
	[[ ! -e ${MARIADB_MYSQL_DATA}/mysql.ibd ]] ||
		die "mariadb: ${MARIADB_MYSQL_DATA} holds MySQL data. Remove it with 'lss remove --purge mysql' or move it away first."
	return
}

# RHEL 9 installs MariaDB 10.5 by default, whose upstream support ended in 2025; the 10.11 LTS stream is maintained
# for the life of RHEL 9. An existing installation keeps its version.
_mariadb_el9_stream() {
	local enabled
	pkg_is_installed mariadb-server && return 0
	enabled=$(dnf -q module list --enabled mariadb 2>/dev/null || true)
	[[ ${enabled} != *10.11* ]] || return 0
	log_command dnf -y -q module enable mariadb:10.11
	files_note_change "enabled the mariadb:10.11 module stream"
	return
}

mod_install() {
	if os_is_rhel && [[ ${OS_MAJOR} == 9 ]]; then
		_mariadb_el9_stream
	fi
	pkg_install_family "mariadb-server mariadb-client" "mariadb-server mariadb"
	return
}

_mariadb_client() {
	if command -v mariadb >/dev/null 2>&1; then
		printf 'mariadb'
	else
		printf 'mysql'
	fi
	return
}

# _mariadb_sql: runs the SQL on standard input as root through the Unix socket and prints the rows, tab-separated.
_mariadb_sql() {
	local client
	client=$(_mariadb_client)
	"${client}" --protocol=socket --user=root --batch --skip-column-names
	return
}

_mariadb_query() {
	local sql=$1
	_mariadb_sql <<<"${sql}"
	return
}

_mariadb_wait() {
	local i
	for ((i = 0; i < 60; i++)); do
		if _mariadb_query 'SELECT 1' >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	die "mariadb: root cannot log in through the Unix socket."
}

# A port other than 3306 needs the mysqld_port_t label on SELinux systems, or the server may not bind it.
_mariadb_selinux_port() {
	local port=$1 custom
	[[ ${port} != 3306 ]] || return 0
	os_is_rhel || return 0
	if ! command -v selinuxenabled >/dev/null 2>&1 || ! selinuxenabled; then
		return 0
	fi
	pkg_install policycoreutils-python-utils
	custom=$(semanage port -l -C 2>/dev/null | awk '$1 == "mysqld_port_t" && $2 == "tcp" { print $3 }')
	grep -qxF "${port}" <<<"${custom}" && return 0
	semanage port -a -t mysqld_port_t -p tcp "${port}" 2>/dev/null ||
		semanage port -m -t mysqld_port_t -p tcp "${port}"
	files_note_change "SELinux port ${port}/tcp for MariaDB"
	return
}

# What mysql_secure_installation does, kept true on every run: root only through the Unix socket, no anonymous
# accounts, root only on localhost, no test database.
_mariadb_secure() {
	local create accounts account sql
	create=$(_mariadb_query "SHOW CREATE USER 'root'@'localhost'")
	if [[ ${create} != *unix_socket* ]]; then
		_mariadb_query "ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket"
		files_note_change "root@localhost authenticates through the Unix socket"
	fi
	accounts=$(_mariadb_query "SELECT CONCAT(QUOTE(User), '@', QUOTE(Host)) FROM mysql.user
		WHERE User = '' OR (User = 'root' AND Host <> 'localhost')")
	while IFS= read -r account; do
		[[ -n ${account} ]] || continue
		_mariadb_query "DROP USER ${account}"
		files_note_change "dropped the account ${account}"
	done <<<"${accounts}"
	if [[ -n $(_mariadb_query "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'test'") ]]; then
		_mariadb_query 'DROP DATABASE test'
		files_note_change "dropped the test database"
	fi
	# The stored pattern is the literal test\_% (the escaped underscore of the old default grant).
	sql="FROM mysql.db WHERE Db = 'test' OR Db = 'test\\\\_%'"
	if [[ $(_mariadb_query "SELECT COUNT(*) ${sql}") != 0 ]]; then
		_mariadb_query "DELETE ${sql}; FLUSH PRIVILEGES"
		files_note_change "removed the grants on test databases"
	fi
	return
}

# Databases of LSS_MARIADB_DATABASES and of LSS_MARIADB_USERS, each once.
_mariadb_wanted_databases() {
	local entry
	local -a list=()
	read -ra list <<<"$(opt databases)"
	for entry in $(opt users); do
		list+=("${entry#*:}")
	done
	if [[ ${#list[@]} -gt 0 ]]; then
		printf '%s\n' "${list[@]}" | awk '!seen[$0]++'
	fi
	return
}

_mariadb_databases() {
	local database databases
	databases=$(_mariadb_wanted_databases)
	for database in ${databases}; do
		if [[ -z $(_mariadb_query "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '${database}'") ]]; then
			_mariadb_query "CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
			files_note_change "created database ${database}"
		fi
	done
	return
}

# Each user is created once with its generated password (sent on standard input, never on a command line) and keeps
# all privileges on its database.
_mariadb_users() {
	local entry user database password grants
	for entry in $(opt users); do
		user=${entry%%:*}
		database=${entry#*:}
		if [[ -z $(_mariadb_query "SELECT User FROM mysql.user WHERE User = '${user}' AND Host = 'localhost'") ]]; then
			secret_load "mariadb-user-${user}" password
			_mariadb_sql <<<"CREATE USER '${user}'@'localhost' IDENTIFIED BY '${password}';"
			files_note_change "created database user ${user}"
			log_info "Password of ${user}: lss secrets show mariadb-user-${user}"
		fi
		grants=$(_mariadb_query "SHOW GRANTS FOR '${user}'@'localhost'")
		if [[ ${grants} != *"ON \`${database}\`.*"* ]]; then
			_mariadb_query "GRANT ALL PRIVILEGES ON \`${database}\`.* TO '${user}'@'localhost'"
			files_note_change "granted ${user} all privileges on ${database}"
		fi
	done
	return
}

mod_configure() {
	local before changed=0 port data
	port=$(opt_int port)
	before=$(files_changes_of mariadb)
	_mariadb_selinux_port "${port}"
	file_write 0644 root:root "$(_mariadb_conf)" <<EOF
# Managed by lss (module mariadb). Change LSS_MARIADB_* in /etc/lss/lss.conf and run lss configure mariadb.
[mysqld]
bind-address = $(opt bind)
port = ${port}
local-infile = 0
symbolic-links = 0
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

[client]
default-character-set = utf8mb4
EOF
	# The data directory is the only place the server writes outside /run and /var/log. Newer packages (Ubuntu 26.04)
	# create it on the first start, but the sandbox needs it before.
	data=$(_mariadb_data)
	[[ -d ${data} ]] || install -d -m 0750 -o mysql -g mysql "${data}"
	svc_sandbox "${MARIADB_UNIT}.service" "ReadWritePaths=${data}"
	[[ $(files_changes_of mariadb) == "${before}" ]] || changed=1
	svc_enable "${MARIADB_UNIT}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${MARIADB_UNIT}"
	fi
	_mariadb_wait
	_mariadb_secure
	_mariadb_databases
	_mariadb_users
	fw_allow "${port}/tcp:$(opt access)"
	return
}

# Every TCP socket on PORT must be on the configured address; 0.0.0.0 and :: allow every address.
_mariadb_check_listen() {
	local port=$1 bind=$2 listeners address
	listeners=$(ss -Hltn "sport = :${port}" | awk '{ address = $4; sub(/:[0-9]+$/, "", address)
		sub(/%.*/, "", address); gsub(/[][]/, "", address); print address }')
	[[ -n ${listeners} ]] || die "mariadb: nothing listens on port ${port}."
	if [[ ${bind} == 0.0.0.0 || ${bind} == :: ]]; then
		return 0
	fi
	while IFS= read -r address; do
		[[ ${address} == "${bind}" ]] || die "mariadb: port ${port} is open on ${address}, expected ${bind} only."
	done <<<"${listeners}"
	return
}

mod_verify() {
	local result
	svc_is_active "${MARIADB_UNIT}" || die "mariadb: the service is not running."
	result=$(_mariadb_query 'SELECT 1') || die "mariadb: root cannot log in through the Unix socket."
	[[ ${result} == 1 ]] || die "mariadb: SELECT 1 returned '${result}'."
	result=$(_mariadb_query 'SELECT @@local_infile')
	[[ ${result} == 0 ]] || die "mariadb: local_infile is on."
	result=$(_mariadb_query "SELECT COUNT(*) FROM mysql.user WHERE User = '' OR (User = 'root' AND Host <> 'localhost')")
	[[ ${result} == 0 ]] || die "mariadb: anonymous or remote root accounts exist."
	_mariadb_check_listen "$(opt_int port)" "$(opt bind)"
	return
}

mod_remove() {
	local path data
	# Read while the server's tools are still installed.
	data=$(_mariadb_data)
	svc_disable "${MARIADB_UNIT}"
	svc_dropin_remove "${MARIADB_UNIT}.service" lss-sandbox
	file_remove "$(_mariadb_conf)"
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		pkg_remove_family "mariadb-server mariadb-client" "mariadb-server mariadb"
		# Only the fixed data directory, never through a symbolic link.
		if [[ -L ${data} ]]; then
			die "mariadb: refusing to delete ${data}: it is a symbolic link."
		elif [[ -d ${data} ]]; then
			rm -rf -- "${data}"
			files_note_change "deleted ${data}"
		fi
		for path in "${LSS_SECRETS_DIR}"/mariadb-user-*; do
			[[ -f ${path} ]] || continue
			secret_remove "${path##*/}"
		done
	fi
	return
}
