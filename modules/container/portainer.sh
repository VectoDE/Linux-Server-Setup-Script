# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="portainer"
MOD_GROUP="container"
MOD_DESCRIPTION="Portainer CE 2.45 LTS (pinned image) to manage Docker or Podman in the browser, on 127.0.0.1:9443 or the WireGuard network, optionally below /portainer/ on the admin port"
MOD_REQUIRES="system docker|podman"
MOD_OPTIONS="access|local|Who reaches https://SERVER:9443: local (127.0.0.1 only; SSH tunnel) or vpn (WireGuard network only)
web_admin|false|Also publish Portainer below /portainer/ on the admin port of the web server (needs nginx, apache or caddy)
http_port|9000|Port of Portainer's plain HTTP listener on 127.0.0.1, which the web server forwards /portainer/ to (web_admin only)"
MOD_SECRETS="portainer-admin-password"
MOD_PORTS="9443/tcp from the WireGuard network with access vpn; none with access local"

# Portainer CE 2.45.2 LTS, the multi-architecture index (amd64 and arm64), checked 2026-10-13. A new release means a
# new digest here.
PORTAINER_IMAGE=docker.io/portainer/portainer-ce@sha256:03f94a406496dc84d37b552795fc424ccad8d0d7200353b6a82915f6e8f73ab0
PORTAINER_NAME=lss-portainer
PORTAINER_VOLUME=lss-portainer-data
PORTAINER_PORT=9443
PORTAINER_DIR=/etc/lss/portainer
PORTAINER_PASSWORD_FILE=${PORTAINER_DIR}/admin-password
PORTAINER_PATH=portainer

mod_check() {
	local port
	[[ $(opt access) =~ ^(local|vpn)$ ]] || die "LSS_PORTAINER_ACCESS must be local or vpn."
	opt_bool web_admin || true
	port=$(opt_int http_port)
	((port >= 1024 && port <= 65535)) || die "LSS_PORTAINER_HTTP_PORT must be a port number from 1024 to 65535."
	[[ ${port} != "${WEB_ADMIN_PORT}" && ${port} != "${PORTAINER_PORT}" ]] ||
		die "LSS_PORTAINER_HTTP_PORT must differ from ${WEB_ADMIN_PORT} and ${PORTAINER_PORT}."
	return
}

# _portainer_web: Portainer is published on the admin port of the web server.
_portainer_web() {
	opt_bool web_admin && [[ -n $(web_server) ]]
	return
}

mod_install() {
	# Podman serves the Docker API only through its socket unit.
	if [[ $(ctr_engine) == podman ]]; then
		svc_enable podman.socket
	fi
	return
}

mod_configure() {
	local password address=127.0.0.1 changed=0
	local -a options=() command=()
	# The first start creates the admin user with this password (lss secrets show portainer-admin-password). The file
	# is the only part of the secrets a container sees; Portainer reads it from a read-only mount.
	secret_load portainer-admin-password password 32
	install -d -m 0700 "${PORTAINER_DIR}"
	file_write 0600 root:root "${PORTAINER_PASSWORD_FILE}" <<<"${password}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	if [[ $(opt access) == vpn ]]; then
		# Every address; the container firewall lets only the WireGuard network through (fw_allow below).
		address=0.0.0.0
	fi
	command=(--admin-password-file /run/lss/admin-password)
	options=(--publish "${address}:${PORTAINER_PORT}:${PORTAINER_PORT}"
		--volume "${PORTAINER_VOLUME}:/data"
		--volume "${PORTAINER_PASSWORD_FILE}:/run/lss/admin-password:ro"
		--socket)
	if _portainer_web; then
		options+=(--publish "127.0.0.1:$(opt_int http_port):9000")
		command+=(--base-url "/${PORTAINER_PATH}")
	else
		command+=(--http-disabled)
	fi
	# Exception to the container rules, on purpose (lib/container.sh, CTR_SOCKET_CONTAINERS): Portainer manages the
	# engine through its socket, which makes it as powerful as root. So it stays on 127.0.0.1 or the WireGuard network.
	ctr_run "${PORTAINER_NAME}" "${PORTAINER_IMAGE}" "${options[@]}" -- "${command[@]}"
	fw_allow "${PORTAINER_PORT}/tcp:$(opt access)"
	if _portainer_web; then
		web_admin_write portainer "${PORTAINER_PATH}" proxy "http://127.0.0.1:$(opt_int http_port)"
		[[ ${LSS_FILE_CHANGED} == 0 ]] || web_reload
	elif [[ -n $(web_server) ]]; then
		web_admin_remove portainer
		[[ ${LSS_FILE_CHANGED} == 0 ]] || web_reload
	fi
	if [[ ${changed} == 1 ]]; then
		log_info "portainer: the admin password applies when Portainer creates its admin user; later changes go through Portainer."
	fi
	return
}

# _portainer_get PATH: the status code of https://127.0.0.1:9443/PATH, or 000 while Portainer starts.
_portainer_get() {
	local path=$1 base=''
	if _portainer_web; then
		base=/${PORTAINER_PATH}
	fi
	curl -sk --max-time 10 -o /dev/null -w '%{http_code}' "https://127.0.0.1:${PORTAINER_PORT}${base}/${path}" 2>/dev/null || true
	return
}

mod_verify() {
	local i status=''
	ctr_running "${PORTAINER_NAME}" || die "portainer: the container ${PORTAINER_NAME} is not running."
	for ((i = 0; i < 60; i++)); do
		status=$(_portainer_get api/system/status)
		[[ ${status} != 200 ]] || break
		sleep 2
	done
	[[ ${status} == 200 ]] || die "portainer: https://127.0.0.1:${PORTAINER_PORT} does not answer (${status:-nothing})."
	# 204: the admin user exists, so nobody can claim the instance with a password of their own.
	status=$(_portainer_get api/users/admin/check)
	[[ ${status} == 204 ]] || die "portainer: Portainer has no admin user yet (${status})."
	if [[ $(opt access) == vpn ]]; then
		[[ $(<"$(fw_container_list)") == *"tcp ${PORTAINER_PORT} "* ]] ||
			die "portainer: the container firewall does not limit ${PORTAINER_PORT}/tcp to the WireGuard network."
	fi
	return
}

mod_remove() {
	if [[ -n $(web_server) ]]; then
		web_admin_remove portainer
		web_reload
	fi
	ctr_remove "${PORTAINER_NAME}"
	file_remove "${PORTAINER_PASSWORD_FILE}"
	rmdir "${PORTAINER_DIR}" 2>/dev/null || true
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	local engine
	engine=$(ctr_engine) || engine=''
	if [[ -n ${engine} ]] && "${engine}" volume inspect "${PORTAINER_VOLUME}" >/dev/null 2>&1; then
		log_command "${engine}" volume rm "${PORTAINER_VOLUME}" || die "portainer: ${engine} cannot delete ${PORTAINER_VOLUME}."
		files_note_change "deleted the volume ${PORTAINER_VOLUME}"
	fi
	secret_remove portainer-admin-password
	return
}
