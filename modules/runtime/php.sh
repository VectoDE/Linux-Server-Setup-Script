# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="php"
MOD_GROUP="runtime"
MOD_DESCRIPTION="PHP-FPM with the common extensions and one hardened pool on a Unix socket for the web server"
MOD_REQUIRES="system"
MOD_OPTIONS="version||PHP version such as 8.4; empty takes the distribution's (on RHEL 9 its newest module stream)
memory_limit|256M|Memory a PHP request may use
upload_max_filesize|64M|Largest file a form may upload
post_max_size|64M|Largest request body (at least upload_max_filesize)
max_children|10|Most PHP worker processes at the same time
disable_functions|exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec|Functions the web pool refuses, separated by commas (the command line keeps them); empty allows all
writable_paths|/var/www /srv|Directories PHP may write to (uploads, caches), separated by spaces; the sandbox keeps the rest read-only"

PHP_USER=lss-php
# Below /var/lib/php, which carries the SELinux label PHP-FPM may write to on the RHEL family.
PHP_SESSIONS=/var/lib/php/lss-sessions
PHP_PING=/lss-ping
PHP_TMPFILES=/etc/tmpfiles.d/lss-php-fpm.conf
# Ubuntu releases the ondrej/php PPA builds for (it has no suite for 26.04 yet).
PHP_PPA_SUITES="jammy noble"

# _php_bytes SIZE: a php.ini size (64M) in bytes.
_php_bytes() {
	local size=$1 number unit
	number=${size%[KMG]}
	unit=${size#"${number}"}
	case ${unit} in
	K) printf '%s' "$((number * 1024))" ;;
	M) printf '%s' "$((number * 1024 * 1024))" ;;
	G) printf '%s' "$((number * 1024 * 1024 * 1024))" ;;
	*) printf '%s' "${number}" ;;
	esac
	return
}

mod_check() {
	local version size path
	version=$(opt version)
	[[ -z ${version} || ${version} =~ ^[78]\.[0-9]$ ]] || die "LSS_PHP_VERSION must look like 8.4, got '${version}'."
	for size in "$(opt memory_limit)" "$(opt upload_max_filesize)" "$(opt post_max_size)"; do
		[[ ${size} =~ ^[1-9][0-9]{0,5}[KMG]?$ ]] || die "php: '${size}' is not a size like 256M."
	done
	(($(_php_bytes "$(opt post_max_size)") >= $(_php_bytes "$(opt upload_max_filesize)"))) ||
		die "LSS_PHP_POST_MAX_SIZE must be at least LSS_PHP_UPLOAD_MAX_FILESIZE."
	(($(opt_int max_children) >= 1)) || die "LSS_PHP_MAX_CHILDREN must be at least 1."
	[[ $(opt disable_functions) =~ ^[a-z0-9_,]*$ ]] || die "LSS_PHP_DISABLE_FUNCTIONS must be function names separated by commas."
	for path in $(opt writable_paths); do
		[[ ${path} =~ ^/[A-Za-z0-9._/-]+$ && ${path} != *..* ]] || die "LSS_PHP_WRITABLE_PATHS: '${path}' is not an absolute path."
	done
	return
}

# True when apt can install PACKAGE from the configured sources.
_php_apt_has() {
	local package=$1 candidate
	candidate=$(apt-cache policy "${package}" 2>/dev/null | awk '$1 == "Candidate:" { print $2 }')
	[[ -n ${candidate} && ${candidate} != '(none)' ]]
	return
}

# Ondřej Surý's packages: a repository for Debian, a PPA for Ubuntu.
_php_extra_repo() {
	if [[ ${OS_ID} == ubuntu ]]; then
		printf 'ondrej-php'
	else
		printf 'sury-php'
	fi
	return
}

# Sets PHP_VERSION on Debian and Ubuntu: the distribution's, or the one asked for (from Ondřej Surý's packages when
# the distribution has another one).
_php_resolve_debian() {
	local wanted repo
	wanted=$(opt version)
	repo=$(_php_extra_repo)
	pkg_update_once
	if [[ -z ${wanted} ]]; then
		# With the extra repository in place, php-fpm would point at its newest PHP instead of the distribution's.
		if [[ -e /etc/apt/sources.list.d/lss-${repo}.sources ]]; then
			repo_remove "${repo}"
			pkg_update
		fi
		PHP_VERSION=$(apt-cache depends php-fpm 2>/dev/null |
			awk '!found && $1 == "Depends:" && $2 ~ /^php[0-9.]+-fpm$/ { sub(/^php/, "", $2); sub(/-fpm$/, "", $2); print $2; found = 1 }')
		[[ -n ${PHP_VERSION} ]] || die "php: the package sources offer no php-fpm."
		return 0
	fi
	if ! _php_apt_has "php${wanted}-fpm"; then
		if [[ ${OS_ID} == ubuntu && " ${PHP_PPA_SUITES} " != *" ${OS_CODENAME} "* ]]; then
			die "php: PHP ${wanted} is not available for ${OS_NAME}; leave LSS_PHP_VERSION empty for the distribution's PHP."
		fi
		repo_add "${repo}"
		_php_apt_has "php${wanted}-fpm" || die "php: PHP ${wanted} is not available for ${OS_NAME}."
	fi
	PHP_VERSION=${wanted}
	return
}

# The enabled PHP module stream on the RHEL family, or nothing.
_php_enabled_stream() {
	{ dnf -q module list --enabled php 2>/dev/null || true; } | awk '$1 == "php" { print $2; exit }'
	return
}

# Installed PHP packages follow a change of the module stream.
_php_sync_stream() {
	if pkg_is_installed php-common; then
		log_command dnf -y -q distro-sync 'php*'
	fi
	return
}

# Sets PHP_VERSION on the RHEL family. RHEL 9 ships PHP 8.0 plus newer versions as module streams; RHEL 10 ships one
# version without streams.
_php_resolve_rhel() {
	local wanted streams enabled available
	wanted=$(opt version)
	streams=$({ dnf -q module list php 2>/dev/null || true; } | awk '$1 == "php" && $2 ~ /^[0-9]+\.[0-9]+$/ { print $2 }' | sort -uV)
	if [[ -z ${wanted} && -n ${streams} ]]; then
		wanted=$(tail -n 1 <<<"${streams}")
	fi
	enabled=$(_php_enabled_stream)
	if [[ -n ${wanted} ]] && grep -qxF "${wanted}" <<<"${streams}"; then
		if [[ ${enabled} != "${wanted}" ]]; then
			log_info "Enabling the PHP ${wanted} module stream"
			log_command dnf -y -q module reset php
			log_command dnf -y -q module enable "php:${wanted}"
			files_note_change "enabled module stream php:${wanted}"
			_php_sync_stream
		fi
	elif [[ -n ${enabled} ]]; then
		# The version asked for is the one without a stream (PHP 8.0 on RHEL 9).
		log_command dnf -y -q module reset php
		files_note_change "reset module stream php:${enabled}"
		_php_sync_stream
	fi
	available=$({ dnf -q repoquery --latest-limit 1 --queryformat '%{version}\n' php-fpm 2>/dev/null || true; } | head -n 1)
	available=${available%.*}
	[[ -n ${available} ]] || die "php: the package sources offer no php-fpm."
	if [[ -n ${wanted} && ${wanted} != "${available}" ]]; then
		die "php: PHP ${wanted} is not available for ${OS_NAME} (it offers ${available}${streams:+ and the streams $(tr '\n' ' ' <<<"${streams}")})."
	fi
	PHP_VERSION=${available}
	return
}

# Installs the packages that are missing and remembers them, so remove takes away only what lss installed.
_php_install() {
	local -a wanted=("$@") missing=()
	mapfile -t missing < <(pkg_missing "${wanted[@]}")
	[[ ${#missing[@]} -gt 0 ]] || return 0
	pkg_install "${missing[@]}"
	state_set "${LSS_MODULE}" packages "$(state_get "${LSS_MODULE}" packages) ${missing[*]}"
	return
}

mod_install() {
	local extension
	local -a packages=()
	if os_is_debian; then
		_php_resolve_debian
		for extension in fpm cli curl gd intl mbstring xml zip mysql pgsql bcmath; do
			packages+=("php${PHP_VERSION}-${extension}")
		done
		# PHP 8.5 has OPcache built in; older versions package it separately.
		if _php_apt_has "php${PHP_VERSION}-opcache"; then
			packages+=("php${PHP_VERSION}-opcache")
		fi
	else
		_php_resolve_rhel
		# php-common carries curl. The zip extension is in neither AppStream nor EPEL; composer unpacks with unzip.
		packages=(php-fpm php-cli php-common php-gd php-intl php-mbstring php-xml php-mysqlnd php-pgsql php-opcache
			php-bcmath php-pdo)
	fi
	_php_install "${packages[@]}"
	state_set "${LSS_MODULE}" php_version "${PHP_VERSION}"
	return
}

# Paths of the installed PHP version (recorded by mod_install).
_php_load() {
	PHP_VERSION=$(state_get "${LSS_MODULE}" php_version)
	[[ -n ${PHP_VERSION} ]] || die "php: the installed PHP version is unknown; run lss install php."
	if os_is_debian; then
		PHP_UNIT="php${PHP_VERSION}-fpm"
		PHP_FPM="/usr/sbin/php-fpm${PHP_VERSION}"
		PHP_CLI="/usr/bin/php${PHP_VERSION}"
		PHP_POOL_DIR="/etc/php/${PHP_VERSION}/fpm/pool.d"
		PHP_INI="/etc/php/${PHP_VERSION}/fpm/conf.d/99-lss.ini"
	else
		PHP_UNIT=php-fpm
		PHP_FPM=/usr/sbin/php-fpm
		PHP_CLI=/usr/bin/php
		PHP_POOL_DIR=/etc/php-fpm.d
		# Shared with the command line on the RHEL family, which has no FPM-only directory.
		PHP_INI=/etc/php.d/99-lss.ini
	fi
	return
}

_php_user() {
	if ! getent passwd "${PHP_USER}" >/dev/null; then
		useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
			--comment "PHP-FPM pool (lss)" "${PHP_USER}"
		files_note_change "created user ${PHP_USER}"
	fi
	if [[ $(stat -c '%U:%G %a' "${PHP_SESSIONS}" 2>/dev/null) != "${PHP_USER}:${PHP_USER} 700" ]]; then
		[[ ! -L ${PHP_SESSIONS} ]] || die "php: ${PHP_SESSIONS} is a symbolic link."
		install -d -m 0700 -o "${PHP_USER}" -g "${PHP_USER}" "${PHP_SESSIONS}"
		if command -v restorecon >/dev/null 2>&1; then
			restorecon -F "${PHP_SESSIONS}" 2>/dev/null || true
		fi
		files_note_change "created ${PHP_SESSIONS}"
	fi
	return
}

# The distribution's "www" pool would listen on a socket of its own; lss keeps a copy of the original and leaves a
# comment in its place (deleting it would make an RPM update put it back). Sets PHP_WWW_CHANGED.
_php_disable_www() {
	local www="${PHP_POOL_DIR}/www.conf"
	PHP_WWW_CHANGED=0
	if [[ -f ${www} ]] && ! grep -q '^; Managed by lss' "${www}" && [[ ! -e ${www}.lss-orig ]]; then
		cp -a "${www}" "${www}.lss-orig"
	fi
	file_write 0644 root:root "${www}" <<'EOF'
; Managed by lss (module php). The distribution's "www" pool is switched off; lss runs its pool "lss" (lss.conf).
; The original is kept as www.conf.lss-orig and comes back with "lss remove php".
EOF
	PHP_WWW_CHANGED=${LSS_FILE_CHANGED}
	return
}

# After a change of LSS_PHP_VERSION the old version's FPM would still serve the lss pool on the same socket.
_php_retire_other_versions() {
	local pool version
	os_is_debian || return 0
	for pool in /etc/php/*/fpm/pool.d/lss.conf; do
		[[ -f ${pool} ]] || continue
		version=${pool#/etc/php/}
		version=${version%%/*}
		[[ ${version} != "${PHP_VERSION}" ]] || continue
		svc_disable "php${version}-fpm"
		file_remove "${pool}"
		file_remove "/etc/php/${version}/fpm/conf.d/99-lss.ini"
		svc_dropin_remove "php${version}-fpm.service" lss-sandbox
	done
	return
}

mod_configure() {
	local changed=0 path socket_dir
	local -a writable=()
	_php_load
	# The socket group must exist before PHP-FPM creates the socket.
	web_group_ensure
	_php_user
	_php_retire_other_versions

	# The RHEL family's php-fpm unit creates /run/php-fpm (with the SELinux label web servers may connect to);
	# Debian and Ubuntu have no such directory, so lss creates it at boot.
	socket_dir=$(dirname "${WEB_PHP_SOCKET}")
	if os_is_debian && [[ ${socket_dir} != /run ]]; then
		file_write 0644 root:root "${PHP_TMPFILES}" <<<"d ${socket_dir} 0755 root root -"
		if [[ ${LSS_FILE_CHANGED} == 1 || ! -d ${socket_dir} ]]; then
			systemd-tmpfiles --create "${PHP_TMPFILES}"
		fi
	fi

	PHP_MAX_CHILDREN=$(opt_int max_children)
	PHP_MEMORY_LIMIT=$(opt memory_limit)
	PHP_UPLOAD_MAX=$(opt upload_max_filesize)
	PHP_POST_MAX=$(opt post_max_size)
	if [[ -n $(opt disable_functions) ]]; then
		PHP_DISABLE_LINE="php_admin_value[disable_functions] = $(opt disable_functions)"
	else
		PHP_DISABLE_LINE='; LSS_PHP_DISABLE_FUNCTIONS is empty: no function is disabled.'
	fi
	template_install php pool.conf 0644 root:root "${PHP_POOL_DIR}/lss.conf"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	template_install php lss.ini 0644 root:root "${PHP_INI}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	_php_disable_www
	[[ ${PHP_WWW_CHANGED} == 0 ]] || changed=1

	# The workers write sessions and whatever the applications in LSS_PHP_WRITABLE_PATHS write; the rest of the system
	# stays read-only for them.
	writable=("ReadWritePaths=-/var/lib/php")
	for path in $(opt writable_paths); do
		writable+=("ReadWritePaths=-${path}")
	done
	svc_sandbox "${PHP_UNIT}.service" "${writable[@]}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1

	if ! "${PHP_FPM}" -t >/dev/null 2>&1; then
		"${PHP_FPM}" -t >&2 || true
		die "php: the PHP-FPM configuration does not load."
	fi
	svc_enable "${PHP_UNIT}"
	if [[ ${changed} == 1 ]]; then
		svc_restart "${PHP_UNIT}" || die "php: ${PHP_UNIT} does not start."
	fi
	return
}

mod_verify() {
	local i extension modules info answer
	_php_load
	svc_is_active "${PHP_UNIT}" || die "php: ${PHP_UNIT} is not running."
	for ((i = 0; i < 10; i++)); do
		[[ -S ${WEB_PHP_SOCKET} ]] && break
		sleep 1
	done
	[[ -S ${WEB_PHP_SOCKET} ]] || die "php: the socket ${WEB_PHP_SOCKET} is missing."
	[[ $(stat -c '%U:%G %a' "${WEB_PHP_SOCKET}") == "root:${WEB_GROUP} 660" ]] ||
		die "php: ${WEB_PHP_SOCKET} is not owned by root:${WEB_GROUP} with mode 0660."
	"${PHP_FPM}" -t >/dev/null 2>&1 || die "php: the PHP-FPM configuration does not load."
	[[ $("${PHP_CLI}" -r 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;' 2>/dev/null) == "${PHP_VERSION}" ]] ||
		die "php: the PHP command line does not run PHP ${PHP_VERSION}."
	modules=$("${PHP_FPM}" -m 2>/dev/null)
	for extension in curl gd intl mbstring xml mysqli pdo_pgsql bcmath 'Zend OPcache'; do
		grep -qixF "${extension}" <<<"${modules}" || die "php: the extension ${extension} is not loaded."
	done
	# Captured first: grep -q would stop reading early and fail the pipeline with SIGPIPE.
	info=$("${PHP_FPM}" -i 2>/dev/null) || true
	grep -q '^expose_php => Off' <<<"${info}" || die "php: the lss settings (${PHP_INI}) are not in effect."
	# A real FastCGI request over the socket; the pool answers its ping path without running a script.
	answer=$("${PHP_CLI}" -n "${LSS_ROOT}/templates/php/fcgi-ping.php" "${WEB_PHP_SOCKET}" "${PHP_PING}" 2>&1) || true
	[[ ${answer} == *pong* ]] || die "php: the pool does not answer FastCGI requests on ${WEB_PHP_SOCKET}: ${answer}"
	return
}

mod_remove() {
	local www package
	local -a installed=()
	PHP_VERSION=$(state_get "${LSS_MODULE}" php_version)
	if [[ -n ${PHP_VERSION} ]]; then
		_php_load
		svc_disable "${PHP_UNIT}"
		svc_dropin_remove "${PHP_UNIT}.service" lss-sandbox
		file_remove "${PHP_POOL_DIR}/lss.conf"
		file_remove "${PHP_INI}"
		www="${PHP_POOL_DIR}/www.conf"
		if [[ -f ${www}.lss-orig ]]; then
			files_backup "${www}"
			mv -f -- "${www}.lss-orig" "${www}"
			files_note_change "restored ${www}"
		fi
	fi
	file_remove "${PHP_TMPFILES}"
	read -ra installed <<<"$(state_get "${LSS_MODULE}" packages)"
	if [[ ${#installed[@]} -gt 0 ]]; then
		pkg_remove "${installed[@]}"
	fi
	if os_is_rhel && [[ -n $(_php_enabled_stream) ]]; then
		log_command dnf -y -q module reset php
		files_note_change "reset module stream php"
	fi
	if os_is_debian; then
		for package in sury-php ondrej-php; do
			if [[ -e /etc/apt/sources.list.d/lss-${package}.sources ]]; then
				repo_remove "${package}"
				pkg_update
			fi
		done
	fi
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		rm -rf -- "${PHP_SESSIONS}"
		if getent passwd "${PHP_USER}" >/dev/null; then
			userdel "${PHP_USER}"
			files_note_change "removed user ${PHP_USER}"
		fi
	fi
	return
}
