# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="redis"
MOD_GROUP="database"
MOD_DESCRIPTION="Redis on localhost with a generated password and dangerous commands blocked by ACL"
MOD_REQUIRES="system"
MOD_CONFLICTS="valkey"
MOD_OPTIONS="bind|127.0.0.1 ::1|Addresses Redis listens on, separated by spaces (::1 is left out where IPv6 is off)
port|6379|TCP port
access|local|Firewall: local (no rule), vpn (WireGuard network only) or public
maxmemory||Memory limit such as 256mb or 2gb; empty means no limit
maxmemory_policy|noeviction|What happens at the limit: noeviction, allkeys-lru, volatile-lru, allkeys-lfu, volatile-lfu, allkeys-random, volatile-random or volatile-ttl
blocked_commands|FLUSHALL CONFIG DEBUG SHUTDOWN MODULE MONITOR REPLICAOF SLAVEOF SYNC PSYNC MIGRATE ACL|Commands the clients may not run, separated by spaces"
MOD_PORTS="6379/tcp on localhost"
MOD_SECRETS="redis-password"

# Sources: the distribution on Debian, Ubuntu and RHEL 9 (redis-server, redis); on RHEL 10, which replaced Redis with
# Valkey, the Redis project's own RPM repository (packages.redis.io, data/repos/redis.conf).
# The configuration lives in root-owned /etc/lss: /etc/redis belongs to the redis user on some systems, and root does
# not write into a directory a service account controls.
REDIS_CONF=/etc/lss/redis.conf
REDIS_PASSWORD_FILE=/etc/lss/redis-password
REDIS_GROUP=lss-redis
REDIS_DATA=/var/lib/redis

_redis_unit() {
	if os_is_debian; then printf 'redis-server'; else printf 'redis'; fi
	return
}

_redis_is_loopback() {
	local address=$1
	[[ ${address} == 127.* || ${address} == ::1 || ${address} == localhost ]]
	return
}

mod_check() {
	local address port access command remote=0
	for address in $(opt bind); do
		[[ ${address} =~ ^[0-9A-Fa-f:.]+$ ]] || die "LSS_REDIS_BIND: '${address}' is not an IP address."
		_redis_is_loopback "${address}" || remote=1
	done
	[[ -n $(opt bind) ]] || die "LSS_REDIS_BIND needs at least one address."
	port=$(opt_int port)
	access=$(opt access)
	[[ ${port} -ge 1 && ${port} -le 65535 ]] || die "LSS_REDIS_PORT must be between 1 and 65535."
	[[ ${access} =~ ^(local|vpn|public)$ ]] || die "LSS_REDIS_ACCESS must be local, vpn or public."
	if [[ ${access} != local && ${remote} == 0 ]]; then
		die "LSS_REDIS_ACCESS=${access} needs an address in LSS_REDIS_BIND that other hosts can reach."
	fi
	[[ -z $(opt maxmemory) || $(opt maxmemory) =~ ^[0-9]+([kmg]b?)?$ ]] ||
		die "LSS_REDIS_MAXMEMORY must look like 256mb or 2gb."
	[[ $(opt maxmemory_policy) =~ ^(noeviction|(allkeys|volatile)-(lru|lfu|random)|volatile-ttl)$ ]] ||
		die "LSS_REDIS_MAXMEMORY_POLICY '$(opt maxmemory_policy)' is not a Redis eviction policy."
	for command in $(opt blocked_commands); do
		[[ ${command} =~ ^[A-Za-z]+$ ]] || die "LSS_REDIS_BLOCKED_COMMANDS: '${command}' is not a command name."
	done
	return
}

mod_install() {
	if os_is_rhel && [[ ${OS_MAJOR} -ge 10 ]]; then
		repo_add redis
	fi
	pkg_install_family "redis-server redis-tools" "redis"
	return
}

# The addresses to bind: ::1 only where the loopback interface has it (Redis before 6.2 cannot skip a missing one).
_redis_bind() {
	local address
	local -a list=()
	for address in $(opt bind); do
		if [[ ${address} == ::1 ]] && ! grep -q '^0\{31\}1 ' /proc/net/if_inet6 2>/dev/null; then
			continue
		fi
		list+=("${address}")
	done
	printf '%s' "${list[*]}"
	return
}

# Major.minor of the installed server, for ACL syntax that older versions lack.
_redis_version() {
	local output
	output=$(redis-server --version)
	[[ ${output} =~ v=([0-9]+)\.([0-9]+) ]] || die "redis: cannot read the version from '${output}'."
	printf '%s' "$((BASH_REMATCH[1] * 100 + BASH_REMATCH[2]))"
	return
}

# The ACL rule of the default user: the password as its SHA-256 (so the configuration holds no clear text), all keys,
# all channels (Redis 6.2 and later), all commands except the blocked ones.
_redis_acl() {
	local password=$1 hash command rule
	hash=$(printf '%s' "${password}" | sha256sum | cut -d ' ' -f 1)
	rule="user default on #${hash} ~*"
	if [[ $(_redis_version) -ge 602 ]]; then
		rule+=' &*'
	fi
	rule+=' +@all'
	for command in $(opt blocked_commands); do
		rule+=" -${command,,}"
	done
	printf '%s' "${rule}"
	return
}

_redis_config() {
	local password=$1 maxmemory
	maxmemory=$(opt maxmemory)
	cat <<EOF
# Managed by lss (module redis). Change LSS_REDIS_* in /etc/lss/lss.conf and run lss configure redis.
# Clients authenticate with the password in ${REDIS_PASSWORD_FILE} (group ${REDIS_GROUP}).
bind $(_redis_bind)
protected-mode yes
port $(opt_int port)
tcp-backlog 511
timeout 0
tcp-keepalive 300
daemonize no
supervised systemd
loglevel notice
logfile ""
databases 16
dir ${REDIS_DATA}
dbfilename dump.rdb
save 3600 1
save 300 100
save 60 10000
maxmemory-policy $(opt maxmemory_policy)
EOF
	if [[ -n ${maxmemory} ]]; then
		printf 'maxmemory %s\n' "${maxmemory}"
	fi
	printf '%s\n' "$(_redis_acl "${password}")"
	return
}

# A non-default port needs the redis_port_t label under SELinux (the RHEL policy confines Redis as redis_t).
_redis_selinux_port() {
	local port=$1 custom
	[[ ${port} != 6379 ]] || return 0
	os_is_rhel || return 0
	if ! command -v selinuxenabled >/dev/null 2>&1 || ! selinuxenabled; then
		return 0
	fi
	pkg_install policycoreutils-python-utils
	custom=$(semanage port -l -C 2>/dev/null | awk '$1 == "redis_port_t" && $2 == "tcp" { print $3 }')
	grep -qxF "${port}" <<<"${custom}" && return 0
	semanage port -a -t redis_port_t -p tcp "${port}" 2>/dev/null ||
		semanage port -m -t redis_port_t -p tcp "${port}"
	files_note_change "SELinux port ${port}/tcp for Redis"
	return
}

mod_configure() {
	local before changed=0 password unit config
	unit=$(_redis_unit)
	before=$(files_changes_of redis)
	_redis_selinux_port "$(opt_int port)"
	secret_load redis-password password
	if ! getent group "${REDIS_GROUP}" >/dev/null; then
		groupadd --system "${REDIS_GROUP}"
		files_note_change "created group ${REDIS_GROUP}"
	fi
	# Clients read the password from this file (add their user to the group); it never appears on a command line.
	file_write 0640 "root:${REDIS_GROUP}" "${REDIS_PASSWORD_FILE}" <<<"${password}"
	config=$(_redis_config "${password}")
	file_write 0640 root:redis "${REDIS_CONF}" <<<"${config}"
	svc_dropin "${unit}.service" lss-config <<EOF
# Managed by lss (module redis): the server reads the lss configuration instead of the distribution's.
[Service]
ExecStart=
ExecStart=/usr/bin/redis-server ${REDIS_CONF} --supervised systemd --daemonize no
EOF
	svc_sandbox "${unit}.service" "ReadWritePaths=${REDIS_DATA}"
	[[ $(files_changes_of redis) == "${before}" ]] || changed=1
	svc_enable "${unit}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${unit}"
	fi
	fw_allow "$(opt_int port)/tcp:$(opt access)"
	return
}

# Every TCP socket on the port must be on a configured address.
_redis_check_listen() {
	local port=$1 listeners address
	local -a allowed=()
	read -ra allowed <<<"$(_redis_bind)"
	listeners=$(ss -Hltn "sport = :${port}" | awk '{ address = $4; sub(/:[0-9]+$/, "", address)
		sub(/%.*/, "", address); gsub(/[][]/, "", address); print address }')
	[[ -n ${listeners} ]] || die "redis: nothing listens on port ${port}."
	if [[ " ${allowed[*]} " == *" 0.0.0.0 "* || " ${allowed[*]} " == *" :: "* ]]; then
		return 0
	fi
	while IFS= read -r address; do
		[[ " ${allowed[*]} " == *" ${address} "* ]] ||
			die "redis: port ${port} is open on ${address}, expected ${allowed[*]} only."
	done <<<"${listeners}"
	return
}

mod_verify() {
	local unit port host password output i
	unit=$(_redis_unit)
	port=$(opt_int port)
	host=$(_redis_bind)
	host=${host%% *}
	[[ ${host} != 0.0.0.0 ]] || host=127.0.0.1
	[[ ${host} != :: ]] || host=::1
	svc_is_active "${unit}" || die "redis: the service ${unit} is not running."
	[[ $(stat -c '%a %G' "${REDIS_PASSWORD_FILE}") == "640 ${REDIS_GROUP}" ]] ||
		die "redis: ${REDIS_PASSWORD_FILE} must be mode 640 and group ${REDIS_GROUP}."
	password=$(<"${REDIS_PASSWORD_FILE}")
	log_mask "${password}"
	# The password goes through the environment (REDISCLI_AUTH), never on the command line.
	for ((i = 0; i < 30; i++)); do
		output=$(REDISCLI_AUTH=${password} redis-cli -h "${host}" -p "${port}" ping 2>&1 || true)
		[[ ${output} != PONG ]] || break
		sleep 1
	done
	[[ ${output} == PONG ]] || die "redis: PING with the password returned '${output}'."
	output=$(redis-cli -h "${host}" -p "${port}" get lss-probe 2>&1 || true)
	[[ ${output} == *NOAUTH* ]] || die "redis: a command without the password was accepted ('${output}')."
	if [[ " $(opt blocked_commands) " == *" CONFIG "* ]]; then
		output=$(REDISCLI_AUTH=${password} redis-cli -h "${host}" -p "${port}" config get maxmemory 2>&1 || true)
		[[ ${output} == *NOPERM* ]] || die "redis: CONFIG is not blocked ('${output}')."
	fi
	_redis_check_listen "${port}"
	return
}

mod_remove() {
	local unit
	unit=$(_redis_unit)
	svc_disable "${unit}"
	svc_dropin_remove "${unit}.service" lss-sandbox
	svc_dropin_remove "${unit}.service" lss-config
	file_remove "${REDIS_CONF}"
	file_remove "${REDIS_PASSWORD_FILE}"
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	pkg_remove_family "redis-server redis-tools" "redis"
	repo_remove redis
	[[ ! -L ${REDIS_DATA} ]] || die "redis: refusing to delete ${REDIS_DATA}: it is a symbolic link."
	if [[ -d ${REDIS_DATA} ]]; then
		rm -rf -- "${REDIS_DATA}"
		files_note_change "deleted ${REDIS_DATA}"
	fi
	if getent group "${REDIS_GROUP}" >/dev/null; then
		groupdel "${REDIS_GROUP}"
		files_note_change "deleted group ${REDIS_GROUP}"
	fi
	secret_remove redis-password
	return
}
