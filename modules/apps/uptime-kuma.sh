# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="uptime-kuma"
MOD_GROUP="apps"
MOD_DESCRIPTION="Uptime Kuma 2 (status pages and uptime checks) as a rootless Docker Compose stack behind the web server, with SQLite and the first administrator already created"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the Uptime Kuma site, separated by spaces; empty: uptime-kuma.<host name of the server>
port|8084|Port of the Uptime Kuma container on 127.0.0.1, which the web server forwards to
admin_user|admin|Name of the first administrator (the password is the secret uptime-kuma-admin-password)
memory|512m|Memory limit of the Uptime Kuma container"
MOD_SECRETS="uptime-kuma-admin-password"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# Uptime Kuma 2.5.6, the slim rootless variant (runs as node, 1000:1000; no bundled Chromium or MariaDB), the
# multi-architecture index (amd64 and arm64), checked 2026-10-15.
KUMA_IMAGE=docker.io/louislam/uptime-kuma@sha256:6eb4e96a7cbdb8a5d6779aa26dce2cb97dcea65b486856b9b2280f73a1d0adf4
KUMA_USER=1000:1000

mod_check() {
	app_check_domains
	app_check_port port
	[[ $(opt admin_user) =~ ^[a-zA-Z][a-zA-Z0-9._-]{1,31}$ ]] || die "LSS_UPTIME_KUMA_ADMIN_USER must be a login name."
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_UPTIME_KUMA_MEMORY must be a size such as 512m or 1g."
	return
}

mod_install() {
	app_compose_ready
	return
}

_kuma_compose() {
	cat <<EOF
# Managed by lss (module uptime-kuma). Change LSS_UPTIME_KUMA_* in /etc/lss/lss.conf and run lss configure uptime-kuma.
name: $(app_project)
services:
  app:
    image: ${KUMA_IMAGE}
    user: "${KUMA_USER}"
    environment:
      UPTIME_KUMA_DB_TYPE: sqlite
      UPTIME_KUMA_PORT: "3001"
      UPTIME_KUMA_ADMIN_USER: "$(opt admin_user)"
    ports:
      - 127.0.0.1:$(opt_int port):3001
    volumes:
      - data:/app/data
$(app_mount secrets/admin-password /run/secrets/admin-password)
$(app_mount config/lss-kuma.js /opt/lss/lss-kuma.js)
    tmpfs:
      - /tmp:mode=1777,size=128m
$(app_hardening "$(opt memory)" 256)
volumes:
  data:
EOF
	return
}

# _kuma_script: a Socket.IO client for the container (Uptime Kuma has no HTTP API for this). It reads the user from
# the environment and the password from the mounted secret, never from its command line:
#   setup   creates the first administrator, unless one exists
#   check   logs in, adds an HTTP monitor for Uptime Kuma itself, waits for its first heartbeat and deletes it again
_kuma_script() {
	cat <<'EOF'
// Managed by lss (module uptime-kuma).
"use strict";
const { io } = require("/app/node_modules/socket.io-client");
const fs = require("fs");
const action = process.argv[2];
const username = process.env.UPTIME_KUMA_ADMIN_USER;
const password = fs.readFileSync("/run/secrets/admin-password", "utf8").trim();
const socket = io("http://127.0.0.1:3001", { transports: ["websocket"], reconnection: false });
const fail = (message) => { console.error(message); process.exit(1); };
const call = (event, ...args) => new Promise((resolve) => socket.emit(event, ...args, resolve));
// The server registers its handlers only after it has answered the connection, so the first question is asked
// again until an answer comes.
const ask = async (event, ...args) => {
	for (let attempt = 0; attempt < 20; attempt++) {
		const answer = await Promise.race([call(event, ...args), new Promise((resolve) => setTimeout(resolve, 3000))]);
		if (answer !== undefined) return answer;
	}
	fail(`no answer to ${event}`);
};
setTimeout(() => fail("timeout"), 120000);
socket.on("connect_error", (error) => fail(`connect: ${error.message}`));
socket.on("connect", async () => {
	if (action === "setup") {
		const needed = await ask("needSetup");
		if (!needed) { console.log("exists"); process.exit(0); }
		const result = await call("setup", username, password);
		if (!result.ok) fail(`setup: ${result.msg}`);
		console.log("created");
		process.exit(0);
	}
	const login = await ask("login", { username, password, token: "" });
	if (!login.ok) fail(`login: ${login.msg}`);
	const added = await call("add", {
		type: "http", name: "lss verify", url: "http://127.0.0.1:3001/", method: "GET", interval: 20,
		retryInterval: 20, resendInterval: 0, maxretries: 0, timeout: 16, maxredirects: 10,
		accepted_statuscodes: ["200-399"], notificationIDList: {}, ignoreTls: false, upsideDown: false,
		expiryNotification: false, kafkaProducerBrokers: [], kafkaProducerSaslOptions: { mechanism: "None" },
		conditions: [], rabbitmqNodes: [], active: true,
	});
	if (!added.ok) fail(`add monitor: ${added.msg}`);
	socket.on("heartbeat", async (beat) => {
		if (beat.monitorID !== added.monitorID) return;
		const removed = await call("deleteMonitor", added.monitorID, false);
		if (!removed.ok) fail(`delete monitor: ${removed.msg}`);
		if (beat.status !== 1) fail(`the monitor reports down: ${beat.msg}`);
		console.log("up");
		process.exit(0);
	});
});
EOF
	return
}

# _kuma ACTION: runs the client in the container.
_kuma() {
	local action=$1
	app_exec app node /opt/lss/lss-kuma.js "${action}"
	return
}

mod_configure() {
	local result
	app_secret uptime-kuma-admin-password "${KUMA_USER}" 32 admin-password
	_kuma_script | app_file config/lss-kuma.js "${KUMA_USER}" 0444
	_kuma_compose | app_compose
	app_backup COPY=data
	app_up
	app_site "$(opt_int port)"
	app_wait '' 302 >/dev/null || die "uptime-kuma: https://$(app_domain)/ does not answer."
	result=$(_kuma setup 2>&1) || die "uptime-kuma: the administrator cannot be created: ${result}"
	if [[ ${result} == *created* ]]; then
		log_info "uptime-kuma: created the administrator $(opt admin_user); password in $(secret_path uptime-kuma-admin-password)"
		files_note_change "created the Uptime Kuma administrator"
	fi
	return
}

mod_verify() {
	local page result
	app_verify_stack
	app_verify_backup
	page=$(app_wait '' 302) || die "uptime-kuma: https://$(app_domain)/ does not answer."
	page=$(app_wait dashboard 200 60) || die "uptime-kuma: the dashboard does not answer."
	grep -qi 'uptime kuma' <<<"${page}" || die "uptime-kuma: https://$(app_domain)/dashboard is not Uptime Kuma."
	# Used, not only running: the administrator logs in and a monitor checks Uptime Kuma itself.
	result=$(_kuma check 2>&1) || die "uptime-kuma: the check as $(opt admin_user) failed: ${result}"
	[[ ${result} == *up* ]] || die "uptime-kuma: the check as $(opt admin_user) failed: ${result}"
	return
}

mod_remove() {
	app_remove
	return
}
