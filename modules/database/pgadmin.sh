# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="pgadmin"
MOD_GROUP="database"
MOD_DESCRIPTION="pgAdmin 4 9.18 in server mode for PostgreSQL, behind the admin port (127.0.0.1:8090/pgadmin4/), own sandboxed service"
MOD_REQUIRES="system nginx|apache|caddy postgresql"
MOD_OPTIONS="email|admin@localhost.localdomain|Login e-mail of the first pgAdmin user (password: lss secrets show pgadmin-admin-password); used when pgAdmin's database is created
port|5050|Port pgAdmin listens on, on 127.0.0.1 only; the web server forwards /pgadmin4/ on the admin port to it"
MOD_SECRETS="pgadmin-admin-password"

# Why a virtual environment from PyPI on every system: pgAdmin's own packages exist for x86_64 only (apt and dnf),
# so aarch64 needs this path anyway, and one path is tested the same way on all systems. The packages also leave out
# a WSGI server. pgadmin4 and gunicorn are pinned wheels checked against the SHA-256 PyPI publishes
# (data/checksums.txt); pip resolves their dependencies over HTTPS within the narrow version ranges pgAdmin pins.
# Python 3.12 on the RHEL 9 family, because the system Python 3.9 is too old for gunicorn.
PGADMIN_VERSION=9.18
PGADMIN_GUNICORN=26.2.0
PGADMIN_VENV=/opt/lss/pgadmin
PGADMIN_DATA=/var/lib/lss-pgadmin
PGADMIN_LOGDIR=/var/log/lss-pgadmin
# pgAdmin reads /etc/pgadmin/config_system.py last, after the configuration files inside its installation, so the
# settings survive a rebuild of the virtual environment.
PGADMIN_CONFIG=/etc/pgadmin/config_system.py
PGADMIN_USER=lss-pgadmin
PGADMIN_UNIT=lss-pgadmin
PGADMIN_PATH=pgadmin4

mod_check() {
	local email port
	email=$(opt email)
	[[ ${email} =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] ||
		die "LSS_PGADMIN_EMAIL '${email}' is not an e-mail address with a dotted domain (pgAdmin needs one)."
	port=$(opt_int port)
	((port >= 1024 && port <= 65535)) || die "LSS_PGADMIN_PORT must be a port number from 1024 to 65535."
	[[ ${port} != "${WEB_ADMIN_PORT}" ]] || die "LSS_PGADMIN_PORT must differ from the admin port ${WEB_ADMIN_PORT}."
	fetch_entry "pgadmin4-${PGADMIN_VERSION}" >/dev/null ||
		die "pgadmin: data/checksums.txt has no checksum for pgAdmin ${PGADMIN_VERSION}."
	fetch_entry "gunicorn-${PGADMIN_GUNICORN}" >/dev/null ||
		die "pgadmin: data/checksums.txt has no checksum for gunicorn ${PGADMIN_GUNICORN}."
	return
}

_pgadmin_python() {
	if os_is_rhel && [[ ${OS_MAJOR} == 9 ]]; then printf 'python3.12'; else printf 'python3'; fi
	return
}

# What the virtual environment was built from; a change (new pins, new Python) rebuilds it.
_pgadmin_release() {
	local python=$1 version
	version=$("${python}" -I -c 'import sys; print("%d.%d" % sys.version_info[:2])')
	printf 'pgadmin4 %s gunicorn %s python %s' "${PGADMIN_VERSION}" "${PGADMIN_GUNICORN}" "${version}"
	return
}

mod_install() {
	local python release tmp
	if os_is_debian; then
		pkg_install curl python3 python3-venv
	elif [[ ${OS_MAJOR} == 9 ]]; then
		pkg_install curl python3.12 python3.12-pip
	else
		pkg_install curl python3 python3-pip
	fi
	python=$(_pgadmin_python)
	release=$(_pgadmin_release "${python}")
	if [[ -f ${PGADMIN_VENV}/.lss-release && $(<"${PGADMIN_VENV}/.lss-release") == "${release}" ]]; then
		return 0
	fi
	tmp=$(mktemp -d)
	# pip takes the version from the file name, so the wheels keep their published names.
	fetch_verified "pgadmin4-${PGADMIN_VERSION}" "${tmp}/pgadmin4-${PGADMIN_VERSION}-py3-none-any.whl"
	fetch_verified "gunicorn-${PGADMIN_GUNICORN}" "${tmp}/gunicorn-${PGADMIN_GUNICORN}-py3-none-any.whl"
	# A virtual environment cannot be moved, so the old one goes first; pgAdmin's data stays in PGADMIN_DATA.
	if svc_is_active "${PGADMIN_UNIT}"; then
		systemctl stop "${PGADMIN_UNIT}"
	fi
	rm -rf -- "${PGADMIN_VENV}"
	install -d -m 0755 "$(dirname "${PGADMIN_VENV}")"
	log_info "Installing pgAdmin ${PGADMIN_VERSION} into ${PGADMIN_VENV} (a few minutes)"
	log_command "${python}" -m venv "${PGADMIN_VENV}" ||
		die "pgadmin: ${python} could not create the virtual environment ${PGADMIN_VENV}."
	if ! PIP_ROOT_USER_ACTION=ignore log_command "${PGADMIN_VENV}/bin/pip" install --no-cache-dir --no-input \
		--disable-pip-version-check --prefer-binary "${tmp}/pgadmin4-${PGADMIN_VERSION}-py3-none-any.whl" \
		"${tmp}/gunicorn-${PGADMIN_GUNICORN}-py3-none-any.whl"; then
		rm -rf -- "${PGADMIN_VENV}" "${tmp}"
		die "pgadmin: pip could not install pgAdmin ${PGADMIN_VERSION} and its dependencies; see the log."
	fi
	printf '%s\n' "${release}" >"${PGADMIN_VENV}/.lss-release"
	rm -rf -- "${tmp}"
	files_note_change "installed pgAdmin ${PGADMIN_VERSION} in ${PGADMIN_VENV}"
	return
}

# The directory with pgAdmin4.py (the WSGI application) inside the virtual environment.
_pgadmin_app_dir() {
	local dir
	for dir in "${PGADMIN_VENV}"/lib/python3*/site-packages/pgadmin4; do
		if [[ -f ${dir}/pgAdmin4.py ]]; then
			printf '%s' "${dir}"
			return 0
		fi
	done
	die "pgadmin: pgAdmin is missing in ${PGADMIN_VENV}; run lss install pgadmin."
}

_pgadmin_user() {
	getent passwd "${PGADMIN_USER}" >/dev/null && return 0
	useradd --system --user-group --home-dir "${PGADMIN_DATA}" --no-create-home --shell /usr/sbin/nologin \
		--comment "pgAdmin (lss)" "${PGADMIN_USER}"
	files_note_change "created user ${PGADMIN_USER}"
	return
}

# Session cookies only over HTTPS when the admin port is public (it speaks HTTPS then); on 127.0.0.1 it is plain HTTP
# through an SSH tunnel.
_pgadmin_cookie_secure() {
	if config_bool "$(config_key "$(web_server)" admin_public)"; then printf 'True'; else printf 'False'; fi
	return
}

# The configuration database and the first user, created once, as the service user. The password reaches pgAdmin
# through the environment of that one command, never through its command line.
_pgadmin_setup_db() {
	local app=$1 email password
	[[ ! -s ${PGADMIN_DATA}/pgadmin4.db ]] || return 0
	email=$(opt email)
	secret_load pgadmin-admin-password password 32
	log_info "Creating pgAdmin's database with the user ${email} (lss secrets show pgadmin-admin-password)"
	(
		cd "${PGADMIN_DATA}"
		export PGADMIN_SETUP_EMAIL=${email}
		export PGADMIN_SETUP_PASSWORD=${password}
		log_command runuser -u "${PGADMIN_USER}" -- "${PGADMIN_VENV}/bin/python3" -B "${app}/setup.py" setup-db
	) || die "pgadmin: pgAdmin could not create its database in ${PGADMIN_DATA}; see the log."
	[[ -s ${PGADMIN_DATA}/pgadmin4.db ]] || die "pgadmin: pgAdmin created no database in ${PGADMIN_DATA}."
	files_note_change "pgAdmin database and user ${email}"
	return
}

mod_configure() {
	local app port secure
	app=$(_pgadmin_app_dir)
	port=$(opt_int port)
	secure=$(_pgadmin_cookie_secure)
	_pgadmin_user
	install -d -m 0700 -o "${PGADMIN_USER}" -g "${PGADMIN_USER}" "${PGADMIN_DATA}"
	install -d -m 0750 -o "${PGADMIN_USER}" -g "${PGADMIN_USER}" "${PGADMIN_LOGDIR}"
	install -d -m 0755 "$(dirname "${PGADMIN_CONFIG}")"
	file_write 0640 "root:${PGADMIN_USER}" "${PGADMIN_CONFIG}" <<EOF
# Managed by lss (module pgadmin). Change LSS_PGADMIN_* in /etc/lss/lss.conf and run lss configure pgadmin.
SERVER_MODE = True
DATA_DIR = '${PGADMIN_DATA}'
LOG_FILE = '${PGADMIN_LOGDIR}/pgadmin4.log'
DEFAULT_SERVER = '127.0.0.1'
DEFAULT_SERVER_PORT = ${port}

# No calls home; the version is pinned by lss.
UPGRADE_CHECK_ENABLED = False

# Sessions are bound to the client address, and cookies need HTTPS when the admin port is public.
ENHANCED_COOKIE_PROTECTION = True
SESSION_COOKIE_SECURE = ${secure}
SESSION_COOKIE_HTTPONLY = True

# No shell access (PSQL tool) and no browsing of the server's file system for binaries.
ENABLE_PSQL = False
ENABLE_BINARY_PATH_BROWSING = False
EOF
	_pgadmin_setup_db "${app}"
	# One worker: pgAdmin keeps connections and Socket.IO sessions in memory; threads serve parallel requests.
	svc_unit "${PGADMIN_UNIT}.service" <<EOF
# Managed by lss (module pgadmin).
[Unit]
Description=pgAdmin 4 (lss)
After=network.target postgresql.service

[Service]
Type=simple
User=${PGADMIN_USER}
Group=${PGADMIN_USER}
WorkingDirectory=${PGADMIN_DATA}
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=${PGADMIN_VENV}/bin/gunicorn --bind 127.0.0.1:${port} --workers 1 --threads 25 --timeout 300 --chdir ${app} pgAdmin4:app
UMask=0077
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
	svc_sandbox "${PGADMIN_UNIT}.service" "ReadWritePaths=${PGADMIN_DATA}" "ReadWritePaths=${PGADMIN_LOGDIR}" \
		CapabilityBoundingSet= AmbientCapabilities= ProtectProc=invisible
	if [[ $(files_changes_of pgadmin) != 0 ]] && svc_is_active "${PGADMIN_UNIT}"; then
		svc_restart "${PGADMIN_UNIT}" || die "pgadmin: ${PGADMIN_UNIT} does not start; see journalctl -u ${PGADMIN_UNIT}."
	fi
	svc_enable "${PGADMIN_UNIT}"
	web_admin_write pgadmin "${PGADMIN_PATH}" proxy "http://127.0.0.1:${port}"
	if [[ ${LSS_FILE_CHANGED} == 1 ]]; then
		web_reload
	fi
	return
}

# _pgadmin_get PATH: the page PATH on the admin port as the web server serves it, followed by a line with the HTTP
# status. A public admin port speaks HTTPS with the default certificate and asks for the admin password, which curl
# reads from standard input, so it never shows in the process list.
_pgadmin_get() {
	local path=$1 password
	if config_bool "$(config_key "$(web_server)" admin_public)"; then
		secret_load web-admin-password password 32
		curl -sk --max-time 30 -K - -w '\n%{http_code}' "https://127.0.0.1:${WEB_ADMIN_PORT}/${path}" \
			<<<"user = \"admin:${password}\""
	else
		curl -s --max-time 30 -w '\n%{http_code}' "http://127.0.0.1:${WEB_ADMIN_PORT}/${path}"
	fi
	return
}

mod_verify() {
	local port i answer='' page status
	port=$(opt_int port)
	svc_is_active "${PGADMIN_UNIT}" || die "pgadmin: ${PGADMIN_UNIT} is not running; see journalctl -u ${PGADMIN_UNIT}."
	svc_wait_port 127.0.0.1 "${port}" 120 || die "pgadmin: nothing listens on 127.0.0.1:${port}."
	# pgAdmin answers its health check once the application is loaded, a few seconds after the port opens.
	for ((i = 0; i < 60; i++)); do
		answer=$(curl -s --max-time 10 -H "X-Script-Name: /${PGADMIN_PATH}" \
			"http://127.0.0.1:${port}/${PGADMIN_PATH}/misc/ping" 2>/dev/null) || true
		[[ ${answer} != PING ]] || break
		sleep 2
	done
	[[ ${answer} == PING ]] || die "pgadmin: pgAdmin does not answer on 127.0.0.1:${port}; see journalctl -u ${PGADMIN_UNIT}."
	page=$(_pgadmin_get "${PGADMIN_PATH}/login") || true
	status=${page##*$'\n'}
	[[ ${status} == 200 ]] ||
		die "pgadmin: the admin port answers ${status:-nothing} for /${PGADMIN_PATH}/login instead of the login page."
	grep -qi 'pgadmin' <<<"${page}" || die "pgadmin: /${PGADMIN_PATH}/login is not pgAdmin's login page."
	return
}

mod_remove() {
	web_admin_remove pgadmin
	web_reload
	svc_disable "${PGADMIN_UNIT}"
	svc_dropin_remove "${PGADMIN_UNIT}.service" lss-sandbox
	file_remove "/etc/systemd/system/${PGADMIN_UNIT}.service"
	svc_daemon_reload
	file_remove "${PGADMIN_CONFIG}"
	rmdir "$(dirname "${PGADMIN_CONFIG}")" 2>/dev/null || true
	if [[ -d ${PGADMIN_VENV} ]]; then
		rm -rf -- "${PGADMIN_VENV}"
		files_note_change "removed ${PGADMIN_VENV}"
	fi
	rmdir "$(dirname "${PGADMIN_VENV}")" 2>/dev/null || true
	# Users, saved servers and preferences stay unless purged; the service user keeps owning them.
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		rm -rf -- "${PGADMIN_DATA}" "${PGADMIN_LOGDIR}"
		if getent passwd "${PGADMIN_USER}" >/dev/null; then
			userdel "${PGADMIN_USER}" >/dev/null 2>&1 || true
		fi
		if getent group "${PGADMIN_USER}" >/dev/null; then
			groupdel "${PGADMIN_USER}" >/dev/null 2>&1 || true
		fi
		secret_remove pgadmin-admin-password
		files_note_change "removed pgAdmin's data"
	fi
	return
}
