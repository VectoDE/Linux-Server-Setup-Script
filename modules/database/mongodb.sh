# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="mongodb"
MOD_GROUP="database"
MOD_DESCRIPTION="MongoDB Community on 127.0.0.1 with authorization on, an administrator and optional application users"
MOD_REQUIRES="system"
MOD_CONFLICTS=""
MOD_OPTIONS="version|9.0|MongoDB release series: 9.0 or 8.0 (changing it later needs a manual upgrade)
bind|127.0.0.1|Addresses mongod listens on, separated by spaces; 127.0.0.1 must stay in the list
port|27017|TCP port
access|local|Firewall: local (no rule), vpn (WireGuard network only) or public
javascript|false|Allow server-side JavaScript (\$where, \$function, mapReduce); off closes a whole class of injections
users||Application users as user:database, separated by spaces; each gets readWrite on its database and a generated password (lss secrets show mongodb-user-USER)"
MOD_PORTS="27017/tcp on localhost"
MOD_SECRETS="mongodb-admin mongodb-user-<user>"

# Source: MongoDB's own repository (repo.mongodb.org, keys pinned in data/repos/mongodb-*.conf). Its Debian suites
# carry amd64 builds only and the 8.0 series has no trixie build, so Ubuntu, Debian on arm64 and 8.0 on Debian 13 use
# the Ubuntu suites (jammy build on Debian 12, noble build on Debian 13).
# lss's configuration lives in root-owned /etc/lss, the unit reads it through a drop-in; /etc/mongod.conf of the
# package stays untouched and unused.
MONGO_CONF=/etc/lss/mongod.conf
MONGO_UNIT=mongod
MONGO_ADMIN=lss-admin
MONGO_ROOTRC=/root/.mongoshrc.js
MONGO_SHELL_CONF=/etc/mongosh.conf
MONGO_REPOS="mongodb-8.0 mongodb-8.0-ubuntu mongodb-9.0 mongodb-9.0-ubuntu"

_mongo_name_ok() {
	local name=$1
	[[ ${name} =~ ^[a-z][a-z0-9_]{0,31}$ ]]
	return
}

_mongo_data() {
	if os_is_debian; then printf '/var/lib/mongodb'; else printf '/var/lib/mongo'; fi
	return
}

_mongo_user() {
	if os_is_debian; then printf 'mongodb'; else printf 'mongod'; fi
	return
}

_mongo_repo() {
	local version
	version=$(opt version)
	if os_is_rhel; then
		printf 'mongodb-%s' "${version}"
	elif [[ ${OS_ID} == ubuntu || ${OS_ARCH} == aarch64 || (${version} == 8.0 && ${OS_CODENAME} == trixie) ]]; then
		printf 'mongodb-%s-ubuntu' "${version}"
	else
		printf 'mongodb-%s' "${version}"
	fi
	return
}

# The installed release series (9.0, 8.0), empty without mongod.
_mongo_installed_series() {
	local output
	command -v mongod >/dev/null 2>&1 || return 0
	output=$(mongod --version 2>/dev/null || true)
	[[ ${output} =~ db\ version\ v([0-9]+\.[0-9]+) ]] || return 0
	printf '%s' "${BASH_REMATCH[1]}"
	return
}

mod_check() {
	local version address port access entry user database installed flags
	version=$(opt version)
	port=$(opt_int port)
	access=$(opt access)
	[[ ${version} =~ ^(9\.0|8\.0)$ ]] || die "LSS_MONGODB_VERSION must be 9.0 or 8.0."
	[[ ${port} -ge 1 && ${port} -le 65535 ]] || die "LSS_MONGODB_PORT must be between 1 and 65535."
	[[ ${access} =~ ^(local|vpn|public)$ ]] || die "LSS_MONGODB_ACCESS must be local, vpn or public."
	# Checks the value; an invalid one stops here.
	opt_bool javascript || true
	for address in $(opt bind); do
		[[ ${address} =~ ^[0-9A-Fa-f:.]+$ ]] || die "LSS_MONGODB_BIND: '${address}' is not an IP address."
	done
	# lss creates the administrator through MongoDB's localhost exception and checks the server over 127.0.0.1.
	[[ " $(opt bind) " == *" 127.0.0.1 "* || " $(opt bind) " == *" 0.0.0.0 "* ]] ||
		die "LSS_MONGODB_BIND must contain 127.0.0.1."
	if [[ ${access} != local && " $(opt bind) " != *" 0.0.0.0 "* && $(wc -w <<<"$(opt bind)") -lt 2 ]]; then
		die "LSS_MONGODB_ACCESS=${access} needs an address in LSS_MONGODB_BIND that other hosts can reach."
	fi
	for entry in $(opt users); do
		[[ ${entry} == *:* ]] || die "LSS_MONGODB_USERS: '${entry}' must look like user:database."
		user=${entry%%:*}
		database=${entry#*:}
		_mongo_name_ok "${user}" || die "LSS_MONGODB_USERS: '${user}' is not a valid user name (a-z, 0-9, _)."
		_mongo_name_ok "${database}" || die "LSS_MONGODB_USERS: '${database}' is not a valid database name."
		[[ ! ${database} =~ ^(admin|local|config)$ ]] || die "LSS_MONGODB_USERS: '${database}' is a reserved database."
	done
	# MongoDB 5.0 and later need AVX on x86_64; the arm64 builds need ARMv8.2-A, whose large-system extensions
	# show up as the atomics flag. Older CPUs stop mongod with an illegal instruction.
	flags=$(grep -m 1 -E '^(flags|Features)[[:space:]]*:' /proc/cpuinfo 2>/dev/null || true)
	case "${OS_ARCH}" in
	x86_64) [[ " ${flags} " == *" avx "* ]] || die "mongodb: this CPU lacks AVX, which MongoDB needs on x86_64." ;;
	aarch64) [[ " ${flags} " == *" atomics "* ]] || die "mongodb: this CPU predates ARMv8.2-A, which MongoDB needs on arm64." ;;
	*) die "mongodb: MongoDB has no build for ${OS_ARCH}." ;;
	esac
	# A downgrade or an upgrade across series needs setFeatureCompatibilityVersion steps lss does not take.
	installed=$(_mongo_installed_series)
	if [[ -n ${installed} && ${installed} != "${version}" ]]; then
		die "mongodb: MongoDB ${installed} is installed; moving to ${version} needs a manual upgrade (see MongoDB's upgrade guide)."
	fi
	return
}

mod_install() {
	local repo name
	repo=$(_mongo_repo)
	for name in ${MONGO_REPOS}; do
		[[ ${name} == "${repo}" ]] || repo_remove "${name}"
	done
	repo_add "${repo}"
	pkg_install mongodb-org-server mongodb-mongosh
	return
}

_mongo_selinux_port() {
	local port=$1 custom
	[[ ${port} != 27017 ]] || return 0
	os_is_rhel || return 0
	if ! command -v selinuxenabled >/dev/null 2>&1 || ! selinuxenabled; then
		return 0
	fi
	pkg_install policycoreutils-python-utils
	custom=$(semanage port -l -C 2>/dev/null | awk '$1 == "mongod_port_t" && $2 == "tcp" { print $3 }')
	grep -qxF "${port}" <<<"${custom}" && return 0
	semanage port -a -t mongod_port_t -p tcp "${port}" 2>/dev/null ||
		semanage port -m -t mongod_port_t -p tcp "${port}"
	files_note_change "SELinux port ${port}/tcp for MongoDB"
	return
}

_mongo_config() {
	local address ipv6=false javascript=false bind_list
	local -a list=()
	for address in $(opt bind); do
		list+=("${address}")
		[[ ${address} != *:* ]] || ipv6=true
	done
	if opt_bool javascript; then
		javascript=true
	fi
	bind_list=$(
		IFS=,
		printf '%s' "${list[*]}"
	)
	cat <<EOF
# Managed by lss (module mongodb). Change LSS_MONGODB_* in /etc/lss/lss.conf and run lss configure mongodb.
storage:
  dbPath: $(_mongo_data)
systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
  logAppend: true
net:
  port: $(opt_int port)
  bindIp: ${bind_list}
  ipv6: ${ipv6}
  unixDomainSocket:
    enabled: false
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
security:
  authorization: enabled
  javascriptEnabled: ${javascript}
EOF
	return
}

_mongo_uri() {
	printf 'mongodb://127.0.0.1:%s/admin' "$(opt_int port)"
	return
}

# A JavaScript string literal in single quotes.
_mongo_quote() {
	local value=$1
	value=${value//\\/\\\\}
	value=${value//\'/\\\'}
	printf "'%s'" "${value}"
	return
}

# Runs the mongosh script on stdin as root. It goes through a file in a private directory under root-owned /run,
# because it may hold passwords, which never go on a command line.
_mongo_js() {
	local dir status=0 output
	dir=$(mktemp -d /run/lss-mongosh.XXXXXX)
	[[ ${dir} == /run/lss-mongosh.* && -d ${dir} && ! -L ${dir} ]] || die "mongodb: mktemp returned '${dir}'."
	chmod 0700 "${dir}"
	(
		umask 077
		cat >"${dir}/script.js"
	)
	output=$(mongosh --quiet --norc "$(_mongo_uri)" "${dir}/script.js" 2>&1) || status=$?
	rm -rf -- "${dir}"
	printf '%s' "${output}"
	return "${status}"
}

_mongo_wait() {
	local i output
	for ((i = 0; i < 60; i++)); do
		output=$(mongosh --quiet --norc "$(_mongo_uri)" --eval 'db.runCommand({ ping: 1 }).ok' 2>/dev/null || true)
		[[ ${output} != 1 ]] || return 0
		sleep 1
	done
	die "mongodb: mongod does not answer on 127.0.0.1:$(opt_int port)."
}

# The script prefix that logs in as the lss administrator.
_mongo_login() {
	local password=$1
	printf "db.getSiblingDB('admin').auth('%s', %s);\n" "${MONGO_ADMIN}" "$(_mongo_quote "${password}")"
	return
}

# The administrator is created once, through the localhost exception that MongoDB grants while no user exists.
_mongo_admin() {
	local password=$1 output
	output=$(_mongo_js <<EOF || true
try { $(_mongo_login "${password}") print('lss:auth-ok'); } catch (e) { print('lss:auth-failed'); }
EOF
	)
	[[ ${output} != *lss:auth-ok* ]] || return 0
	output=$(_mongo_js <<EOF
db.getSiblingDB('admin').createUser({ user: '${MONGO_ADMIN}', pwd: $(_mongo_quote "${password}"), roles: ['root'] });
print('lss:created');
EOF
	) || die "mongodb: cannot create ${MONGO_ADMIN}. MongoDB allows it only while no user exists; with existing users, create it yourself with the password from 'lss secrets show mongodb-admin'. ${output}"
	[[ ${output} == *lss:created* ]] || die "mongodb: creating ${MONGO_ADMIN} returned '${output}'."
	files_note_change "created MongoDB user ${MONGO_ADMIN}"
	return
}

# Each application user gets readWrite on its own database and nothing else; extra roles are taken away again.
_mongo_users() {
	local admin=$1 entry user database password output
	for entry in $(opt users); do
		user=${entry%%:*}
		database=${entry#*:}
		secret_load "mongodb-user-${user}" password
		output=$(_mongo_js <<EOF
$(_mongo_login "${admin}")
const target = db.getSiblingDB('${database}');
const roles = [{ role: 'readWrite', db: '${database}' }];
const existing = target.getUser('${user}');
if (existing === null) {
  target.createUser({ user: '${user}', pwd: $(_mongo_quote "${password}"), roles: roles });
  print('lss:created');
} else if (existing.roles.length !== 1 || existing.roles[0].role !== 'readWrite' || existing.roles[0].db !== '${database}') {
  target.updateUser('${user}', { roles: roles });
  print('lss:updated');
}
EOF
		) || die "mongodb: cannot set up the user ${user}: ${output}"
		case "${output}" in
		*lss:created*) files_note_change "created MongoDB user ${user}" ;;
		*lss:updated*) files_note_change "reset the roles of MongoDB user ${user}" ;;
		*) ;;
		esac
	done
	return
}

mod_configure() {
	local before changed=0 password config port
	port=$(opt_int port)
	before=$(files_changes_of mongodb)
	_mongo_selinux_port "${port}"
	# mongosh sends usage data to MongoDB unless the global configuration turns it off.
	file_write 0644 root:root "${MONGO_SHELL_CONF}" <<EOF
# Managed by lss (module mongodb).
mongosh:
  enableTelemetry: false
EOF
	config=$(_mongo_config)
	file_write 0644 root:root "${MONGO_CONF}" <<<"${config}"
	svc_dropin "${MONGO_UNIT}.service" lss-config <<EOF
# Managed by lss (module mongodb): mongod reads the lss configuration instead of /etc/mongod.conf.
[Service]
ExecStart=
ExecStart=/usr/bin/mongod --config ${MONGO_CONF}
EOF
	svc_sandbox "${MONGO_UNIT}.service" "ReadWritePaths=$(_mongo_data)"
	[[ $(files_changes_of mongodb) == "${before}" ]] || changed=1
	svc_enable "${MONGO_UNIT}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${MONGO_UNIT}"
	fi
	_mongo_wait
	secret_load mongodb-admin password
	_mongo_admin "${password}"
	# root's interactive mongosh logs in as the administrator, like /root/.my.cnf for MySQL.
	file_write 0600 root:root "${MONGO_ROOTRC}" <<EOF
// Managed by lss (module mongodb): logs root's interactive mongosh in as ${MONGO_ADMIN}.
$(_mongo_login "${password}")
EOF
	_mongo_users "${password}"
	fw_allow "${port}/tcp:$(opt access)"
	return
}

# Every TCP socket on the port must be on a configured address.
_mongo_check_listen() {
	local port=$1 listeners address bind
	bind=" $(opt bind) "
	listeners=$(ss -Hltn "sport = :${port}" | awk '{ address = $4; sub(/:[0-9]+$/, "", address)
		sub(/%.*/, "", address); gsub(/[][]/, "", address); print address }')
	[[ -n ${listeners} ]] || die "mongodb: nothing listens on port ${port}."
	[[ ${bind} != *" 0.0.0.0 "* && ${bind} != *" :: "* ]] || return 0
	while IFS= read -r address; do
		[[ ${bind} == *" ${address} "* ]] || die "mongodb: port ${port} is open on ${address}, expected $(opt bind) only."
	done <<<"${listeners}"
	return
}

mod_verify() {
	local password output
	svc_is_active "${MONGO_UNIT}" || die "mongodb: the service ${MONGO_UNIT} is not running."
	_mongo_wait
	secret_load mongodb-admin password
	output=$(_mongo_js <<EOF
$(_mongo_login "${password}")
const options = db.adminCommand({ getCmdLineOpts: 1 }).parsed;
print('lss:ping=' + db.adminCommand({ ping: 1 }).ok);
print('lss:authorization=' + options.security.authorization);
print('lss:javascript=' + options.security.javascriptEnabled);
EOF
	) || die "mongodb: login as ${MONGO_ADMIN} failed: ${output}"
	[[ ${output} == *lss:ping=1* ]] || die "mongodb: ping as ${MONGO_ADMIN} returned '${output}'."
	[[ ${output} == *lss:authorization=enabled* ]] || die "mongodb: authorization is off ('${output}')."
	if ! opt_bool javascript; then
		[[ ${output} == *lss:javascript=false* ]] || die "mongodb: server-side JavaScript is on ('${output}')."
	fi
	# Without credentials, listing the databases must be refused.
	output=$(mongosh --quiet --norc "$(_mongo_uri)" --eval 'db.adminCommand({ listDatabases: 1 }).ok' 2>&1 || true)
	[[ ${output} == *requires\ authentication* || ${output} == *nauthorized* ]] ||
		die "mongodb: listDatabases without a login was accepted ('${output}')."
	_mongo_check_listen "$(opt_int port)"
	return
}

# Deletes the data directory of the module; anything else, or a symbolic link in its place, stops the removal.
_mongo_delete_data() {
	local path
	path=$(_mongo_data)
	case "${path}" in
	/var/lib/mongodb | /var/lib/mongo) ;;
	*) die "mongodb: refusing to delete ${path}: it is not a directory of the module." ;;
	esac
	[[ ! -L ${path} ]] || die "mongodb: refusing to delete ${path}: it is a symbolic link."
	[[ -d ${path} ]] || return 0
	rm -rf -- "${path}"
	files_note_change "deleted ${path}"
	return
}

mod_remove() {
	local entry name
	svc_disable "${MONGO_UNIT}"
	svc_dropin_remove "${MONGO_UNIT}.service" lss-sandbox
	svc_dropin_remove "${MONGO_UNIT}.service" lss-config
	file_remove "${MONGO_CONF}"
	file_remove "${MONGO_SHELL_CONF}"
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	pkg_remove mongodb-org-server mongodb-mongosh
	for name in ${MONGO_REPOS}; do
		repo_remove "${name}"
	done
	_mongo_delete_data
	file_remove "${MONGO_ROOTRC}"
	secret_remove mongodb-admin
	for entry in $(opt users); do
		secret_remove "mongodb-user-${entry%%:*}"
	done
	return
}
