# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="mysql"
MOD_GROUP="database"
MOD_DESCRIPTION="MySQL server (8.4 LTS where available) on 127.0.0.1, secured like mysql_secure_installation, optional databases and users"
MOD_REQUIRES="system"
MOD_CONFLICTS="mariadb"
MOD_OPTIONS="bind|127.0.0.1|Address the server listens on (0.0.0.0 or :: for every address)
port|3306|TCP port
access|local|Firewall: local (no rule), vpn (WireGuard network only) or public
databases||Databases to create, separated by spaces
users||Application users as user:database, separated by spaces; each gets all privileges on its database from localhost and a generated password (lss secrets show mysql-user-USER)"
MOD_PORTS="3306/tcp on 127.0.0.1, X Protocol 33060/tcp on 127.0.0.1"
MOD_SECRETS="mysql-root (RHEL family) mysql-user-<user>"

# Sources, newest LTS where the system offers it:
#   Ubuntu             the distribution (8.0 on 22.04 and 24.04, 8.4 on 26.04); its root logs in through auth_socket
#   Debian amd64       Oracle's APT repository, 8.4 LTS (Debian ships no MySQL)
#   Debian arm64       Oracle's generic glibc 2.28 build of 8.4 LTS in /opt (the APT repository is amd64 only)
#   RHEL family        the distribution: the mysql:8.4 module stream on 9, mysql8.4 on 10; root has a password
MYSQL_DATA=/var/lib/mysql
MYSQL_GENERIC_VERSION=8.4.11
MYSQL_GENERIC_DIR=/opt/mysql-${MYSQL_GENERIC_VERSION}
MYSQL_GENERIC_LINK=/opt/mysql
MYSQL_GENERIC_CNF=/etc/mysql/my.cnf
MYSQL_ROOT_CNF=/root/.my.cnf

_mysql_source() {
	if os_is_rhel; then
		printf 'rhel'
	elif [[ ${OS_ID} == ubuntu ]]; then
		printf 'ubuntu'
	elif [[ ${OS_ARCH} == aarch64 ]]; then
		printf 'generic'
	else
		printf 'oracle'
	fi
	return
}

_mysql_unit() {
	if os_is_rhel; then printf 'mysqld'; else printf 'mysql'; fi
	return
}

_mysql_conf() {
	if os_is_rhel; then
		printf '/etc/my.cnf.d/zz-lss.cnf'
	else
		printf '/etc/mysql/mysql.conf.d/zz-lss.cnf'
	fi
	return
}

_mysql_socket() {
	if os_is_rhel; then
		printf '/var/lib/mysql/mysql.sock'
	else
		printf '/run/mysqld/mysqld.sock'
	fi
	return
}

# _mysql_bin NAME: the program from the generic build when it is installed, else from the PATH.
_mysql_bin() {
	local name=$1
	if [[ -x ${MYSQL_GENERIC_LINK}/bin/${name} ]]; then
		printf '%s' "${MYSQL_GENERIC_LINK}/bin/${name}"
	else
		printf '%s' "${name}"
	fi
	return
}

_mysql_packages() {
	case $(_mysql_source) in
	rhel)
		if [[ ${OS_MAJOR} == 9 ]]; then printf 'mysql-server mysql'; else printf 'mysql8.4-server mysql8.4'; fi
		;;
	generic) printf '' ;;
	*) printf 'mysql-server mysql-client' ;;
	esac
	return
}

_mysql_name_ok() {
	local name=$1
	[[ ${name} =~ ^[a-z][a-z0-9_]{0,31}$ ]]
	return
}

_mysql_is_loopback() {
	local address=$1
	[[ ${address} == 127.* || ${address} == ::1 ]]
	return
}

mod_check() {
	local bind port access database entry user
	bind=$(opt bind)
	port=$(opt_int port)
	access=$(opt access)
	[[ ${bind} =~ ^[0-9A-Fa-f:.]+$ ]] || die "LSS_MYSQL_BIND '${bind}' is not an IP address."
	[[ ${port} -ge 1 && ${port} -le 65535 && ${port} != 33060 ]] ||
		die "LSS_MYSQL_PORT must be between 1 and 65535 (33060 is the X Protocol port)."
	[[ ${access} =~ ^(local|vpn|public)$ ]] || die "LSS_MYSQL_ACCESS must be local, vpn or public."
	if [[ ${access} != local ]] && _mysql_is_loopback "${bind}"; then
		die "LSS_MYSQL_ACCESS=${access} needs LSS_MYSQL_BIND set to an address other hosts can reach."
	fi
	for database in $(opt databases); do
		_mysql_name_ok "${database}" || die "LSS_MYSQL_DATABASES: '${database}' is not a valid name (a-z, 0-9, _)."
		[[ ! ${database} =~ ^(mysql|information_schema|performance_schema|sys|test)$ ]] ||
			die "LSS_MYSQL_DATABASES: '${database}' is a reserved database."
	done
	for entry in $(opt users); do
		[[ ${entry} == *:* ]] || die "LSS_MYSQL_USERS: '${entry}' must look like user:database."
		user=${entry%%:*}
		database=${entry#*:}
		_mysql_name_ok "${user}" || die "LSS_MYSQL_USERS: '${user}' is not a valid user name (a-z, 0-9, _)."
		_mysql_name_ok "${database}" || die "LSS_MYSQL_USERS: '${database}' is not a valid database name."
		[[ ! ${user} =~ ^(root|mysql)$ ]] || die "LSS_MYSQL_USERS: '${user}' is a reserved account."
		[[ ! ${database} =~ ^(mysql|information_schema|performance_schema|sys|test)$ ]] ||
			die "LSS_MYSQL_USERS: '${database}' is a reserved database."
	done
	# MariaDB leaves Aria control files in its data directory; MySQL cannot open it.
	[[ ! -e ${MYSQL_DATA}/aria_log_control ]] ||
		die "mysql: ${MYSQL_DATA} holds MariaDB data. Remove it with 'lss remove --purge mariadb' or move it away first."
	return
}

# RHEL 9 defaults to MySQL 8.0, whose upstream support ended in April 2026; the 8.4 LTS stream replaces it. An
# existing installation keeps its version.
_mysql_el9_stream() {
	local enabled
	pkg_is_installed mysql-server && return 0
	enabled=$(dnf -q module list --enabled mysql 2>/dev/null || true)
	[[ ${enabled} != *8.4* ]] || return 0
	log_command dnf -y -q module enable mysql:8.4
	files_note_change "enabled the mysql:8.4 module stream"
	return
}

# Oracle's generic build: unpacked once per version into /opt (without debug binaries, static libraries, headers and
# manuals), linked as /opt/mysql, run by an lss unit. The archive is checked against data/checksums.txt.
_mysql_generic_install() {
	local archive=/var/cache/lss/mysql-generic.tar.xz aio=libaio1 aio_target
	# trixie renamed libaio's soname in the 64-bit time_t transition; the ABI on arm64 did not change.
	[[ ${OS_CODENAME} == bookworm ]] || aio=libaio1t64
	pkg_install "${aio}" libnuma1 libncurses6 xz-utils
	if [[ ! -x ${MYSQL_GENERIC_DIR}/bin/mysqld ]]; then
		fetch_verified mysql-generic "${archive}"
		rm -rf -- "${MYSQL_GENERIC_DIR}.part"
		mkdir -p "${MYSQL_GENERIC_DIR}.part"
		log_command tar -xJf "${archive}" -C "${MYSQL_GENERIC_DIR}.part" --strip-components=1 --no-same-owner \
			--exclude='*/bin/mysqld-debug' --exclude='*/lib/plugin/debug' --exclude='*/include' \
			--exclude='*/man' --exclude='*/docs' --exclude='*.a'
		mv -- "${MYSQL_GENERIC_DIR}.part" "${MYSQL_GENERIC_DIR}"
		rm -f -- "${archive}"
		files_note_change "unpacked MySQL ${MYSQL_GENERIC_VERSION} to ${MYSQL_GENERIC_DIR}"
	fi
	if [[ ${aio} == libaio1t64 ]]; then
		aio_target="/usr/lib/aarch64-linux-gnu/libaio.so.1t64"
		if [[ $(readlink "${MYSQL_GENERIC_DIR}/lib/private/libaio.so.1" 2>/dev/null) != "${aio_target}" ]]; then
			ln -sfn "${aio_target}" "${MYSQL_GENERIC_DIR}/lib/private/libaio.so.1"
			files_note_change "linked libaio.so.1 for MySQL"
		fi
	fi
	if [[ $(readlink "${MYSQL_GENERIC_LINK}" 2>/dev/null) != "${MYSQL_GENERIC_DIR}" ]]; then
		ln -sfn "${MYSQL_GENERIC_DIR}" "${MYSQL_GENERIC_LINK}"
		files_note_change "linked ${MYSQL_GENERIC_LINK} to ${MYSQL_GENERIC_DIR}"
	fi
	_mysql_generic_links
	if ! getent passwd mysql >/dev/null; then
		useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin mysql
		files_note_change "created user mysql"
	fi
	return
}

_mysql_generic_links() {
	local program
	for program in mysql mysqladmin mysqldump mysqlcheck mysqlbinlog; do
		if [[ $(readlink "/usr/local/bin/${program}" 2>/dev/null) != "${MYSQL_GENERIC_LINK}/bin/${program}" ]]; then
			ln -sfn "${MYSQL_GENERIC_LINK}/bin/${program}" "/usr/local/bin/${program}"
			files_note_change "linked /usr/local/bin/${program}"
		fi
	done
	return
}

mod_install() {
	local packages
	case $(_mysql_source) in
	rhel)
		if [[ ${OS_MAJOR} == 9 ]]; then
			_mysql_el9_stream
		fi
		;;
	oracle) repo_add mysql ;;
	generic) _mysql_generic_install ;;
	*) ;;
	esac
	packages=$(_mysql_packages)
	if [[ -n ${packages} ]]; then
		pkg_install_family "${packages}" "${packages}"
	fi
	return
}

# The generic build has no package scripts: lss writes its base configuration and unit and creates the data
# directory once (root starts with an empty password and is switched to auth_socket right after).
_mysql_generic_configure() {
	install -d -m 0750 -o mysql -g mysql "${MYSQL_DATA}" /var/lib/mysql-files
	install -d -m 0750 -o mysql -g adm /var/log/mysql
	file_write 0644 root:root "${MYSQL_GENERIC_CNF}" <<EOF
# Managed by lss (module mysql): Oracle's generic MySQL build in ${MYSQL_GENERIC_LINK}. Settings of lss are in
# $(_mysql_conf); put your own into another file in /etc/mysql/mysql.conf.d.
[mysqld]
user = mysql
basedir = ${MYSQL_GENERIC_LINK}
datadir = ${MYSQL_DATA}
socket = $(_mysql_socket)
pid-file = /run/mysqld/mysqld.pid
log-error = /var/log/mysql/error.log
secure-file-priv = /var/lib/mysql-files

[client]
socket = $(_mysql_socket)

!includedir /etc/mysql/mysql.conf.d/
EOF
	svc_unit mysql.service <<EOF
# Managed by lss (module mysql).
[Unit]
Description=MySQL Community Server (Oracle generic build)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=mysql
Group=mysql
RuntimeDirectory=mysqld
RuntimeDirectoryMode=0755
ExecStart=${MYSQL_GENERIC_LINK}/bin/mysqld --defaults-file=${MYSQL_GENERIC_CNF}
LimitNOFILE=10000
TimeoutSec=600
Restart=on-failure
RestartPreventExitStatus=1

[Install]
WantedBy=multi-user.target
EOF
	if [[ ! -e ${MYSQL_DATA}/mysql.ibd ]]; then
		log_command "${MYSQL_GENERIC_LINK}/bin/mysqld" "--defaults-file=${MYSQL_GENERIC_CNF}" --initialize-insecure \
			--user=mysql || die "mysql: initialising ${MYSQL_DATA} failed (see /var/log/mysql/error.log)."
		files_note_change "initialised ${MYSQL_DATA}"
	fi
	return
}

# _mysql_sql: runs the SQL on standard input as root through the Unix socket and prints the rows, tab-separated.
# On the RHEL family the password comes from /root/.my.cnf.
_mysql_sql() {
	local -a defaults=()
	if os_is_rhel; then
		defaults=("--defaults-extra-file=${MYSQL_ROOT_CNF}")
	fi
	"$(_mysql_bin mysql)" "${defaults[@]}" --socket="$(_mysql_socket)" --user=root --batch --skip-column-names
	return
}

_mysql_query() {
	local sql=$1
	_mysql_sql <<<"${sql}"
	return
}

# mysqladmin ping succeeds once the server accepts connections, even when the login itself is refused.
_mysql_wait() {
	local i
	for ((i = 0; i < 90; i++)); do
		if "$(_mysql_bin mysqladmin)" --no-defaults --socket="$(_mysql_socket)" ping >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	die "mysql: the server does not answer on $(_mysql_socket)."
}

# Debian and Ubuntu: root logs in through auth_socket, as the distribution and Oracle's packages set it up.
_mysql_root_socket() {
	local plugin active
	plugin=$(_mysql_query "SELECT plugin FROM mysql.user WHERE User = 'root' AND Host = 'localhost'") ||
		die "mysql: root cannot log in through the Unix socket."
	[[ ${plugin} != auth_socket ]] || return 0
	active=$(_mysql_query "SELECT PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME = 'auth_socket'")
	if [[ ${active} != ACTIVE ]]; then
		_mysql_query "INSTALL PLUGIN auth_socket SONAME 'auth_socket.so'"
	fi
	_mysql_query "ALTER USER 'root'@'localhost' IDENTIFIED WITH auth_socket"
	files_note_change "root@localhost authenticates through the Unix socket"
	return
}

# RHEL family: the server creates root with an empty password. lss sets a generated one and writes it to
# /root/.my.cnf (mode 0600), so the client logs in without a password on the command line.
_mysql_root_password() {
	local password client
	secret_load mysql-root password
	file_write 0600 root:root "${MYSQL_ROOT_CNF}" <<EOF
# Managed by lss (module mysql). Password of the MySQL root account (lss secrets show mysql-root).
[client]
user = root
password = ${password}
EOF
	if _mysql_query 'SELECT 1' >/dev/null 2>&1; then
		return 0
	fi
	client=$(_mysql_bin mysql)
	if "${client}" --no-defaults --socket="$(_mysql_socket)" --user=root --batch <<<'SELECT 1' >/dev/null 2>&1; then
		"${client}" --no-defaults --socket="$(_mysql_socket)" --user=root --batch \
			<<<"ALTER USER 'root'@'localhost' IDENTIFIED BY '${password}';"
		files_note_change "set the MySQL root password"
		log_info "Password of the MySQL root account: lss secrets show mysql-root (also in ${MYSQL_ROOT_CNF})"
		return 0
	fi
	die "mysql: root cannot log in with the password in ${MYSQL_ROOT_CNF} (lss secrets show mysql-root)."
}

# What mysql_secure_installation does, kept true on every run: no anonymous accounts, root only on localhost, no
# test database.
_mysql_secure() {
	local accounts account sql
	accounts=$(_mysql_query "SELECT CONCAT(QUOTE(User), '@', QUOTE(Host)) FROM mysql.user
		WHERE User = '' OR (User = 'root' AND Host <> 'localhost')")
	while IFS= read -r account; do
		[[ -n ${account} ]] || continue
		_mysql_query "DROP USER ${account}"
		files_note_change "dropped the account ${account}"
	done <<<"${accounts}"
	if [[ -n $(_mysql_query "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'test'") ]]; then
		_mysql_query 'DROP DATABASE test'
		files_note_change "dropped the test database"
	fi
	# The stored pattern is the literal test\_% (the escaped underscore of the old default grant).
	sql="FROM mysql.db WHERE Db = 'test' OR Db = 'test\\\\_%'"
	if [[ $(_mysql_query "SELECT COUNT(*) ${sql}") != 0 ]]; then
		_mysql_query "DELETE ${sql}; FLUSH PRIVILEGES"
		files_note_change "removed the grants on test databases"
	fi
	return
}

# Databases of LSS_MYSQL_DATABASES and of LSS_MYSQL_USERS, each once.
_mysql_wanted_databases() {
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

_mysql_databases() {
	local database databases
	databases=$(_mysql_wanted_databases)
	for database in ${databases}; do
		if [[ -z $(_mysql_query "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '${database}'") ]]; then
			_mysql_query "CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
			files_note_change "created database ${database}"
		fi
	done
	return
}

# Each user is created once with its generated password (sent on standard input, never on a command line) and keeps
# all privileges on its database.
_mysql_users() {
	local entry user database password grants
	for entry in $(opt users); do
		user=${entry%%:*}
		database=${entry#*:}
		if [[ -z $(_mysql_query "SELECT User FROM mysql.user WHERE User = '${user}' AND Host = 'localhost'") ]]; then
			secret_load "mysql-user-${user}" password
			_mysql_sql <<<"CREATE USER '${user}'@'localhost' IDENTIFIED BY '${password}';"
			files_note_change "created database user ${user}"
			log_info "Password of ${user}: lss secrets show mysql-user-${user}"
		fi
		grants=$(_mysql_query "SHOW GRANTS FOR '${user}'@'localhost'")
		if [[ ${grants} != *"ON \`${database}\`.*"* ]]; then
			_mysql_query "GRANT ALL PRIVILEGES ON \`${database}\`.* TO '${user}'@'localhost'"
			files_note_change "granted ${user} all privileges on ${database}"
		fi
	done
	return
}

# A port other than 3306 needs the mysqld_port_t label on SELinux systems, or the server may not bind it.
_mysql_selinux_port() {
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
	files_note_change "SELinux port ${port}/tcp for MySQL"
	return
}

mod_configure() {
	local before changed=0 port unit
	port=$(opt_int port)
	unit=$(_mysql_unit)
	before=$(files_changes_of mysql)
	_mysql_selinux_port "${port}"
	# The X Protocol (33060) stays on localhost whatever LSS_MYSQL_BIND says; nothing in lss uses it.
	file_write 0644 root:root "$(_mysql_conf)" <<EOF
# Managed by lss (module mysql). Change LSS_MYSQL_* in /etc/lss/lss.conf and run lss configure mysql.
[mysqld]
bind-address = $(opt bind)
port = ${port}
mysqlx-bind-address = 127.0.0.1
local-infile = 0
character-set-server = utf8mb4
collation-server = utf8mb4_0900_ai_ci

[client]
default-character-set = utf8mb4
EOF
	if [[ $(_mysql_source) == generic ]]; then
		_mysql_generic_configure
	fi
	svc_sandbox "${unit}.service" "ReadWritePaths=${MYSQL_DATA}" ReadWritePaths=-/var/lib/mysql-files \
		ReadWritePaths=-/var/lib/mysql-keyring
	[[ $(files_changes_of mysql) == "${before}" ]] || changed=1
	svc_enable "${unit}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${unit}"
	fi
	_mysql_wait
	if os_is_rhel; then
		_mysql_root_password
	else
		_mysql_root_socket
	fi
	_mysql_secure
	_mysql_databases
	_mysql_users
	fw_allow "${port}/tcp:$(opt access)"
	return
}

# Every TCP socket on PORT must be on one of the ALLOWED addresses; 0.0.0.0 and :: allow every address.
_mysql_check_listen() {
	local port=$1 allowed=$2 listeners address
	listeners=$(ss -Hltn "sport = :${port}" | awk '{ address = $4; sub(/:[0-9]+$/, "", address)
		sub(/%.*/, "", address); gsub(/[][]/, "", address); print address }')
	[[ -n ${listeners} ]] || die "mysql: nothing listens on port ${port}."
	if [[ ${allowed} == 0.0.0.0 || ${allowed} == :: ]]; then
		return 0
	fi
	while IFS= read -r address; do
		[[ ${address} == "${allowed}" ]] || die "mysql: port ${port} is open on ${address}, expected ${allowed} only."
	done <<<"${listeners}"
	return
}

mod_verify() {
	local result unit
	unit=$(_mysql_unit)
	svc_is_active "${unit}" || die "mysql: the service ${unit} is not running."
	result=$(_mysql_query 'SELECT 1') || die "mysql: root cannot log in."
	[[ ${result} == 1 ]] || die "mysql: SELECT 1 returned '${result}'."
	result=$(_mysql_query 'SELECT @@local_infile')
	[[ ${result} == 0 ]] || die "mysql: local_infile is on."
	result=$(_mysql_query "SELECT COUNT(*) FROM mysql.user WHERE User = '' OR (User = 'root' AND Host <> 'localhost')")
	[[ ${result} == 0 ]] || die "mysql: anonymous or remote root accounts exist."
	if ! os_is_rhel; then
		result=$(_mysql_query "SELECT plugin FROM mysql.user WHERE User = 'root' AND Host = 'localhost'")
		[[ ${result} == auth_socket ]] || die "mysql: root does not authenticate through the Unix socket."
	fi
	_mysql_check_listen "$(opt_int port)" "$(opt bind)"
	_mysql_check_listen 33060 127.0.0.1
	return
}

mod_remove() {
	local unit path packages
	unit=$(_mysql_unit)
	svc_disable "${unit}"
	svc_dropin_remove "${unit}.service" lss-sandbox
	file_remove "$(_mysql_conf)"
	# /root/.my.cnf stays unless purged: the data stays too, and root needs the password to reach it.
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	packages=$(_mysql_packages)
	if [[ -n ${packages} ]]; then
		pkg_remove_family "${packages}" "${packages}"
	fi
	repo_remove mysql
	if [[ $(_mysql_source) == generic ]]; then
		file_remove /etc/systemd/system/mysql.service
		file_remove "${MYSQL_GENERIC_CNF}"
		for path in mysql mysqladmin mysqldump mysqlcheck mysqlbinlog; do
			file_remove "/usr/local/bin/${path}"
		done
		svc_daemon_reload
		# The unpacked build (about 1 GB) is deleted, not backed up like a configuration file.
		if [[ -e ${MYSQL_GENERIC_DIR} || -L ${MYSQL_GENERIC_LINK} ]]; then
			rm -rf -- "${MYSQL_GENERIC_LINK}" "${MYSQL_GENERIC_DIR}"
			files_note_change "deleted ${MYSQL_GENERIC_DIR}"
		fi
	fi
	file_remove "${MYSQL_ROOT_CNF}"
	for path in "${MYSQL_DATA}" /var/lib/mysql-files /var/lib/mysql-keyring; do
		if [[ -d ${path} ]]; then
			rm -rf -- "${path}"
			files_note_change "deleted ${path}"
		fi
	done
	secret_remove mysql-root
	for path in "${LSS_SECRETS_DIR}"/mysql-user-*; do
		[[ -f ${path} ]] || continue
		secret_remove "${path##*/}"
	done
	return
}
