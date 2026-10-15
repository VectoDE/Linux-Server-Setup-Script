# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="valkey"
MOD_GROUP="database"
MOD_DESCRIPTION="Valkey on localhost with a generated password and dangerous commands blocked by ACL"
MOD_REQUIRES="system"
MOD_CONFLICTS="redis"
MOD_OPTIONS="bind|127.0.0.1 ::1|Addresses Valkey listens on, separated by spaces (::1 is left out where IPv6 is off)
port|6379|TCP port
access|local|Firewall: local (no rule), vpn (WireGuard network only) or public
maxmemory||Memory limit such as 256mb or 2gb; empty means no limit
maxmemory_policy|noeviction|What happens at the limit: noeviction, allkeys-lru, volatile-lru, allkeys-lfu, volatile-lfu, allkeys-random, volatile-random or volatile-ttl
blocked_commands|FLUSHALL CONFIG DEBUG SHUTDOWN MODULE MONITOR REPLICAOF SLAVEOF SYNC PSYNC MIGRATE ACL|Commands the clients may not run, separated by spaces"
MOD_PORTS="6379/tcp on localhost"
MOD_SECRETS="valkey-password"

# Sources: the distribution where it has Valkey (Debian 13, Ubuntu 24.04 and 26.04, RHEL 9 and 10 AppStream),
# bookworm-backports on Debian 12 and the Valkey project's build for Ubuntu 22.04 (data/checksums.txt), which has no
# package at all.
# The package and service name on the RHEL family (Debian and Ubuntu call both valkey-server).
VALKEY_RPM=valkey
# The configuration lives in root-owned /etc/lss: root does not write into /etc/valkey, which the valkey user may
# control.
VALKEY_CONF=/etc/lss/valkey.conf
VALKEY_PASSWORD_FILE=/etc/lss/valkey-password
VALKEY_GROUP=lss-valkey
VALKEY_DATA=/var/lib/valkey
VALKEY_UPSTREAM_VERSION=8.1.10
VALKEY_UPSTREAM_DIR=/opt/valkey-${VALKEY_UPSTREAM_VERSION}
VALKEY_UPSTREAM_LINK=/opt/valkey
VALKEY_BACKPORTS_SOURCE=/etc/apt/sources.list.d/lss-bookworm-backports.sources
VALKEY_BACKPORTS_PIN=/etc/apt/preferences.d/lss-valkey

# upstream (Ubuntu 22.04), backports (Debian 12) or distribution.
_valkey_source() {
	if [[ ${OS_ID} == ubuntu && ${OS_CODENAME} == jammy ]]; then
		printf 'upstream'
	elif [[ ${OS_ID} == debian && ${OS_CODENAME} == bookworm ]]; then
		printf 'backports'
	else
		printf 'distribution'
	fi
	return
}

_valkey_unit() {
	if os_is_debian; then printf 'valkey-server'; else printf '%s' "${VALKEY_RPM}"; fi
	return
}

_valkey_bin() {
	if [[ $(_valkey_source) == upstream ]]; then
		printf '%s/bin' "${VALKEY_UPSTREAM_LINK}"
	else
		printf '/usr/bin'
	fi
	return
}

_valkey_is_loopback() {
	local address=$1
	[[ ${address} == 127.* || ${address} == ::1 || ${address} == localhost ]]
	return
}

mod_check() {
	local address port access command remote=0
	for address in $(opt bind); do
		[[ ${address} =~ ^[0-9A-Fa-f:.]+$ ]] || die "LSS_VALKEY_BIND: '${address}' is not an IP address."
		_valkey_is_loopback "${address}" || remote=1
	done
	[[ -n $(opt bind) ]] || die "LSS_VALKEY_BIND needs at least one address."
	port=$(opt_int port)
	access=$(opt access)
	[[ ${port} -ge 1 && ${port} -le 65535 ]] || die "LSS_VALKEY_PORT must be between 1 and 65535."
	[[ ${access} =~ ^(local|vpn|public)$ ]] || die "LSS_VALKEY_ACCESS must be local, vpn or public."
	if [[ ${access} != local && ${remote} == 0 ]]; then
		die "LSS_VALKEY_ACCESS=${access} needs an address in LSS_VALKEY_BIND that other hosts can reach."
	fi
	[[ -z $(opt maxmemory) || $(opt maxmemory) =~ ^[0-9]+([kmg]b?)?$ ]] ||
		die "LSS_VALKEY_MAXMEMORY must look like 256mb or 2gb."
	[[ $(opt maxmemory_policy) =~ ^(noeviction|(allkeys|volatile)-(lru|lfu|random)|volatile-ttl)$ ]] ||
		die "LSS_VALKEY_MAXMEMORY_POLICY '$(opt maxmemory_policy)' is not a Valkey eviction policy."
	for command in $(opt blocked_commands); do
		[[ ${command} =~ ^[A-Za-z]+$ ]] || die "LSS_VALKEY_BLOCKED_COMMANDS: '${command}' is not a command name."
	done
	return
}

# Debian 12 has Valkey only in bookworm-backports, signed with the Debian archive key the system already trusts. The
# pin raises just the valkey packages to the normal priority, so nothing else comes from backports.
_valkey_backports() {
	local changed=0 file
	for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
		[[ -f ${file} && ${file} != "${VALKEY_BACKPORTS_SOURCE}" ]] || continue
		if grep -qs '^[^#]*bookworm-backports' "${file}"; then
			changed=-1
			break
		fi
	done
	if [[ ${changed} == 0 ]]; then
		file_write 0644 root:root "${VALKEY_BACKPORTS_SOURCE}" <<EOF
# Managed by lss (module valkey): Debian 12 has Valkey in backports only.
Types: deb
URIs: https://deb.debian.org/debian
Suites: bookworm-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
		[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	fi
	file_write 0644 root:root "${VALKEY_BACKPORTS_PIN}" <<EOF
# Managed by lss (module valkey): only the valkey packages come from bookworm-backports.
Package: valkey*
Pin: release n=bookworm-backports
Pin-Priority: 500
EOF
	if [[ ${changed} == 1 || ${LSS_FILE_CHANGED} == 1 ]]; then
		pkg_update
	fi
	return
}

# Ubuntu 22.04: the Valkey project's build for jammy, checksum-verified, with a user and a unit of lss's own.
_valkey_upstream_install() {
	local archive=/var/cache/lss/valkey-jammy.tar.gz program
	pkg_install libssl3 libsystemd0
	if [[ ! -x ${VALKEY_UPSTREAM_DIR}/bin/valkey-server ]]; then
		fetch_verified valkey-jammy "${archive}"
		rm -rf -- "${VALKEY_UPSTREAM_DIR}.part"
		mkdir -p "${VALKEY_UPSTREAM_DIR}.part"
		log_command tar -xzf "${archive}" -C "${VALKEY_UPSTREAM_DIR}.part" --strip-components=1 --no-same-owner
		[[ -x ${VALKEY_UPSTREAM_DIR}.part/bin/valkey-server ]] ||
			die "valkey: the archive has no bin/valkey-server; the layout of the upstream build changed."
		chmod -R go-w "${VALKEY_UPSTREAM_DIR}.part"
		mv -- "${VALKEY_UPSTREAM_DIR}.part" "${VALKEY_UPSTREAM_DIR}"
		rm -f -- "${archive}"
		files_note_change "unpacked Valkey ${VALKEY_UPSTREAM_VERSION} to ${VALKEY_UPSTREAM_DIR}"
	fi
	if [[ $(readlink "${VALKEY_UPSTREAM_LINK}" 2>/dev/null) != "${VALKEY_UPSTREAM_DIR}" ]]; then
		ln -sfn "${VALKEY_UPSTREAM_DIR}" "${VALKEY_UPSTREAM_LINK}"
		files_note_change "linked ${VALKEY_UPSTREAM_LINK} to ${VALKEY_UPSTREAM_DIR}"
	fi
	for program in valkey-server valkey-cli; do
		if [[ $(readlink "/usr/local/bin/${program}" 2>/dev/null) != "${VALKEY_UPSTREAM_LINK}/bin/${program}" ]]; then
			ln -sfn "${VALKEY_UPSTREAM_LINK}/bin/${program}" "/usr/local/bin/${program}"
			files_note_change "linked /usr/local/bin/${program}"
		fi
	done
	if ! getent passwd valkey >/dev/null; then
		useradd --system --user-group --home-dir "${VALKEY_DATA}" --no-create-home --shell /usr/sbin/nologin valkey
		files_note_change "created user valkey"
	fi
	if [[ ! -d ${VALKEY_DATA} ]]; then
		install -d -m 0750 -o valkey -g valkey "${VALKEY_DATA}"
		files_note_change "created ${VALKEY_DATA}"
	fi
	svc_unit valkey-server.service <<EOF
# Managed by lss (module valkey): the Valkey project's build in ${VALKEY_UPSTREAM_LINK}.
[Unit]
Description=Valkey key-value store
After=network.target

[Service]
Type=notify
User=valkey
Group=valkey
ExecStart=${VALKEY_UPSTREAM_LINK}/bin/valkey-server ${VALKEY_CONF} --supervised systemd --daemonize no
ExecStop=/bin/kill -s TERM \$MAINPID
TimeoutStartSec=60
TimeoutStopSec=60
Restart=on-failure
UMask=0077
LimitNOFILE=10032

[Install]
WantedBy=multi-user.target
EOF
	return
}

mod_install() {
	case "$(_valkey_source)" in
	upstream)
		_valkey_upstream_install
		return
		;;
	backports) _valkey_backports ;;
	*) ;;
	esac
	pkg_install_family "valkey-server valkey-tools" "${VALKEY_RPM}"
	return
}

# The addresses to bind: ::1 only where the loopback interface has it.
_valkey_bind() {
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

# The ACL rule of the default user: the password as its SHA-256 (so the configuration holds no clear text), all keys
# and channels, all commands except the blocked ones.
_valkey_acl() {
	local password=$1 hash command rule
	hash=$(printf '%s' "${password}" | sha256sum | cut -d ' ' -f 1)
	rule="user default on #${hash} ~* &* +@all"
	for command in $(opt blocked_commands); do
		rule+=" -${command,,}"
	done
	printf '%s' "${rule}"
	return
}

_valkey_config() {
	local password=$1 maxmemory
	maxmemory=$(opt maxmemory)
	cat <<EOF
# Managed by lss (module valkey). Change LSS_VALKEY_* in /etc/lss/lss.conf and run lss configure valkey.
# Clients authenticate with the password in ${VALKEY_PASSWORD_FILE} (group ${VALKEY_GROUP}).
bind $(_valkey_bind)
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
dir ${VALKEY_DATA}
dbfilename dump.rdb
save 3600 1
save 300 100
save 60 10000
maxmemory-policy $(opt maxmemory_policy)
EOF
	if [[ -n ${maxmemory} ]]; then
		printf 'maxmemory %s\n' "${maxmemory}"
	fi
	printf '%s\n' "$(_valkey_acl "${password}")"
	return
}

# A non-default port needs the redis_port_t label under SELinux (the RHEL policy confines Valkey as redis_t).
_valkey_selinux_port() {
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
	files_note_change "SELinux port ${port}/tcp for Valkey"
	return
}

mod_configure() {
	local before changed=0 password unit config
	unit=$(_valkey_unit)
	before=$(files_changes_of valkey)
	_valkey_selinux_port "$(opt_int port)"
	secret_load valkey-password password
	if ! getent group "${VALKEY_GROUP}" >/dev/null; then
		groupadd --system "${VALKEY_GROUP}"
		files_note_change "created group ${VALKEY_GROUP}"
	fi
	# Clients read the password from this file (add their user to the group); it never appears on a command line.
	file_write 0640 "root:${VALKEY_GROUP}" "${VALKEY_PASSWORD_FILE}" <<<"${password}"
	config=$(_valkey_config "${password}")
	file_write 0640 root:valkey "${VALKEY_CONF}" <<<"${config}"
	svc_dropin "${unit}.service" lss-config <<EOF
# Managed by lss (module valkey): the server reads the lss configuration instead of the distribution's.
[Service]
ExecStart=
ExecStart=$(_valkey_bin)/valkey-server ${VALKEY_CONF} --supervised systemd --daemonize no
EOF
	svc_sandbox "${unit}.service" "ReadWritePaths=${VALKEY_DATA}"
	[[ $(files_changes_of valkey) == "${before}" ]] || changed=1
	svc_enable "${unit}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${unit}"
	fi
	fw_allow "$(opt_int port)/tcp:$(opt access)"
	return
}

# Every TCP socket on the port must be on a configured address.
_valkey_check_listen() {
	local port=$1 listeners address
	local -a allowed=()
	read -ra allowed <<<"$(_valkey_bind)"
	listeners=$(ss -Hltn "sport = :${port}" | awk '{ address = $4; sub(/:[0-9]+$/, "", address)
		sub(/%.*/, "", address); gsub(/[][]/, "", address); print address }')
	[[ -n ${listeners} ]] || die "valkey: nothing listens on port ${port}."
	if [[ " ${allowed[*]} " == *" 0.0.0.0 "* || " ${allowed[*]} " == *" :: "* ]]; then
		return 0
	fi
	while IFS= read -r address; do
		[[ " ${allowed[*]} " == *" ${address} "* ]] ||
			die "valkey: port ${port} is open on ${address}, expected ${allowed[*]} only."
	done <<<"${listeners}"
	return
}

# valkey-cli with the password from the environment: VALKEYCLI_AUTH for Valkey 8, REDISCLI_AUTH for 7.2.
_valkey_cli_auth() {
	local password=$1
	shift
	VALKEYCLI_AUTH=${password} REDISCLI_AUTH=${password} "$(_valkey_bin)/valkey-cli" "$@"
	return
}

mod_verify() {
	local unit port host password output i
	unit=$(_valkey_unit)
	port=$(opt_int port)
	host=$(_valkey_bind)
	host=${host%% *}
	[[ ${host} != 0.0.0.0 ]] || host=127.0.0.1
	[[ ${host} != :: ]] || host=::1
	svc_is_active "${unit}" || die "valkey: the service ${unit} is not running."
	[[ $(stat -c '%a %G' "${VALKEY_PASSWORD_FILE}") == "640 ${VALKEY_GROUP}" ]] ||
		die "valkey: ${VALKEY_PASSWORD_FILE} must be mode 640 and group ${VALKEY_GROUP}."
	password=$(<"${VALKEY_PASSWORD_FILE}")
	log_mask "${password}"
	for ((i = 0; i < 30; i++)); do
		output=$(_valkey_cli_auth "${password}" -h "${host}" -p "${port}" ping 2>&1 || true)
		[[ ${output} != PONG ]] || break
		sleep 1
	done
	[[ ${output} == PONG ]] || die "valkey: PING with the password returned '${output}'."
	output=$("$(_valkey_bin)/valkey-cli" -h "${host}" -p "${port}" get lss-probe 2>&1 || true)
	[[ ${output} == *NOAUTH* ]] || die "valkey: a command without the password was accepted ('${output}')."
	if [[ " $(opt blocked_commands) " == *" CONFIG "* ]]; then
		output=$(_valkey_cli_auth "${password}" -h "${host}" -p "${port}" config get maxmemory 2>&1 || true)
		[[ ${output} == *NOPERM* ]] || die "valkey: CONFIG is not blocked ('${output}')."
	fi
	_valkey_check_listen "${port}"
	return
}

# Deletes a fixed directory of the module; anything else, or a symbolic link in its place, stops the removal.
_valkey_delete() {
	local path=$1
	case "${path}" in
	"${VALKEY_DATA}" | "${VALKEY_UPSTREAM_DIR}") ;;
	*) die "valkey: refusing to delete ${path}: it is not a directory of the module." ;;
	esac
	[[ ! -L ${path} ]] || die "valkey: refusing to delete ${path}: it is a symbolic link."
	[[ -d ${path} ]] || return 0
	rm -rf -- "${path}"
	files_note_change "deleted ${path}"
	return
}

_valkey_upstream_remove() {
	local program
	_valkey_delete "${VALKEY_UPSTREAM_DIR}"
	if [[ -L ${VALKEY_UPSTREAM_LINK} ]]; then
		rm -f -- "${VALKEY_UPSTREAM_LINK}"
		files_note_change "deleted ${VALKEY_UPSTREAM_LINK}"
	fi
	for program in valkey-server valkey-cli; do
		if [[ $(readlink "/usr/local/bin/${program}" 2>/dev/null) == "${VALKEY_UPSTREAM_LINK}/bin/${program}" ]]; then
			rm -f -- "/usr/local/bin/${program}"
			files_note_change "deleted /usr/local/bin/${program}"
		fi
	done
	if getent passwd valkey >/dev/null; then
		userdel valkey
		files_note_change "deleted user valkey"
	fi
	return
}

mod_remove() {
	local unit source
	unit=$(_valkey_unit)
	source=$(_valkey_source)
	svc_disable "${unit}"
	svc_dropin_remove "${unit}.service" lss-sandbox
	svc_dropin_remove "${unit}.service" lss-config
	file_remove "${VALKEY_CONF}"
	file_remove "${VALKEY_PASSWORD_FILE}"
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	case "${source}" in
	upstream)
		file_remove /etc/systemd/system/valkey-server.service
		svc_daemon_reload
		_valkey_upstream_remove
		;;
	backports)
		pkg_remove valkey-server valkey-tools
		file_remove "${VALKEY_BACKPORTS_PIN}"
		file_remove "${VALKEY_BACKPORTS_SOURCE}"
		;;
	*) pkg_remove_family "valkey-server valkey-tools" "${VALKEY_RPM}" ;;
	esac
	_valkey_delete "${VALKEY_DATA}"
	if getent group "${VALKEY_GROUP}" >/dev/null; then
		groupdel "${VALKEY_GROUP}"
		files_note_change "deleted group ${VALKEY_GROUP}"
	fi
	secret_remove valkey-password
	return
}
