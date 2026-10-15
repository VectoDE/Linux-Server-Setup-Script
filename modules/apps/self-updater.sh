# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="self-updater"
MOD_GROUP="apps"
MOD_DESCRIPTION="Self-Updater 4.2 (VectoDE): keeps a checkout of a Git repository on this server current, restarts its service, checks its health and rolls back on failure"
MOD_REQUIRES="system node"
MOD_MODES="native"
MOD_OPTIONS="repo||Repository to deploy (HTTPS URL, git@host:owner/repo.git or a local path); required
branch|main|Branch to follow (track branch)
track|branch|branch (deploy the newest commit of the branch) or tag (deploy the newest release tag matching v*)
path|/srv/app|Directory of the deployed checkout; created on the first run, owned by the user self-updater
service|none|What restarts after a deployment: none, or systemd:UNIT (a sudo rule allows exactly that restart)
health_url||URL that must answer 200 after a deployment, otherwise the previous commit comes back; empty: no check
interval|60|Seconds between two polls of the repository (at least 15)
port|8093|Port of the webhook receiver (/hooks/self-updater, signed with the secret self-updater-webhook-secret) and the status endpoint (/status) on 127.0.0.1
token||Access token for a private HTTPS repository (GitHub: fine-grained, Contents read), stored in the lss secrets (self-updater-token)"
MOD_SECRETS="self-updater-webhook-secret self-updater-token"
MOD_PORTS="none (the status endpoint and the webhook receiver listen on 127.0.0.1)"

# A new version is a new entry self-updater-<version> in data/checksums.txt and a new SU_VERSION.
SU_VERSION=4.2.1
SU_USER=self-updater
SU_HOME=/var/lib/self-updater
SU_CONFIG_DIR=/etc/self-updater
SU_CONFIG=${SU_CONFIG_DIR}/updater.config.json
SU_ENV=${SU_CONFIG_DIR}/.env
SU_UNIT=self-updater
SU_SUDOERS=/etc/sudoers.d/lss-self-updater
SU_STATUS_PATH=/status

mod_check() {
	local repo path service interval
	repo=$(opt repo)
	[[ -n ${repo} ]] || die "LSS_SELF_UPDATER_REPO must name the repository to deploy (https://github.com/owner/repo.git)."
	[[ ${repo} =~ ^(https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/~-]+|git@[A-Za-z0-9.-]+:[A-Za-z0-9._/~-]+|/[A-Za-z0-9._/-]+)$ ]] ||
		die "LSS_SELF_UPDATER_REPO: '${repo}' is not an HTTPS URL, git@host:owner/repo.git or an absolute path."
	[[ $(opt branch) =~ ^[A-Za-z0-9._/-]+$ ]] || die "LSS_SELF_UPDATER_BRANCH: '$(opt branch)' is not a branch name."
	[[ $(opt track) =~ ^(branch|tag)$ ]] || die "LSS_SELF_UPDATER_TRACK must be branch or tag."
	path=$(opt path)
	[[ ${path} =~ ^/[A-Za-z0-9._/-]+$ && /${path}/ != */../* ]] || die "LSS_SELF_UPDATER_PATH must be an absolute path."
	case ${path%/} in
	/ | /etc* | /usr* | /bin* | /sbin* | /lib* | /boot* | /proc* | /sys* | /dev* | /root* | /var/lib/lss* | /opt/lss*)
		die "LSS_SELF_UPDATER_PATH must not be a system directory (${path})."
		;;
	*) ;;
	esac
	service=$(opt service)
	[[ ${service} == none || ${service} =~ ^systemd:[A-Za-z0-9@._-]+$ ]] ||
		die "LSS_SELF_UPDATER_SERVICE must be none or systemd:UNIT."
	[[ -z $(opt health_url) || $(opt health_url) =~ ^https?://[A-Za-z0-9.:\[\]-]+(/[A-Za-z0-9._/?=\&%~-]*)?$ ]] ||
		die "LSS_SELF_UPDATER_HEALTH_URL: '$(opt health_url)' is not an http(s) URL."
	interval=$(opt_int interval)
	((interval >= 15)) || die "LSS_SELF_UPDATER_INTERVAL must be at least 15 seconds."
	[[ $(opt token) != *[[:space:]]* ]] || die "LSS_SELF_UPDATER_TOKEN must not contain spaces."
	app_check_port port
	fetch_entry "self-updater-${SU_VERSION}" >/dev/null ||
		die "self-updater: data/checksums.txt has no checksum for Self-Updater ${SU_VERSION}."
	return
}

# _su_installed: the version of the installed self-updater, or nothing.
_su_installed() {
	local package
	package="$(npm root --global 2>/dev/null)/@vectode/self-updater/package.json"
	[[ -f ${package} ]] || return 0
	jq -r '.version // empty' "${package}" 2>/dev/null || true
	return
}

# The release archive from GitHub, checked against data/checksums.txt and installed with npm (no install scripts; the
# package has no dependencies). Node.js comes from the node module.
mod_install() {
	local tmp
	pkg_install git jq sudo
	if [[ $(_su_installed) != "${SU_VERSION}" ]]; then
		tmp=$(mktemp -d)
		fetch_verified "self-updater-${SU_VERSION}" "${tmp}/self-updater.tgz"
		log_command npm install --global --ignore-scripts --no-audit --no-fund "${tmp}/self-updater.tgz" ||
			die "self-updater: npm cannot install Self-Updater ${SU_VERSION}."
		rm -rf -- "${tmp}"
		files_note_change "installed Self-Updater ${SU_VERSION}"
	fi
	mon_user "${SU_USER}" "${SU_HOME}"
	return
}

# _su_token_flag: true when the repository needs the token.
_su_token_flag() {
	if [[ -n $(opt token) ]]; then printf 'true'; else printf 'false'; fi
	return
}

# _su_config: updater.config.json. Secrets stay in .env (${SELF_UPDATER_WEBHOOK_SECRET}, ${GITHUB_TOKEN}).
_su_config() {
	local service unit=''
	service=$(opt service)
	[[ ${service} == none ]] || unit=${service#systemd:}
	jq -n --arg repo "$(opt repo)" --arg branch "$(opt branch)" --arg track "$(opt track)" --arg path "$(opt path)" \
		--arg unit "${unit}" --arg health "$(opt health_url)" --argjson interval "$(opt_int interval)" \
		--argjson port "$(opt_int port)" --arg status "${SU_STATUS_PATH}" --arg token "$(_su_token_flag)" '
	{
		version: 3,
		repo: ({url: $repo, branch: $branch} + (if $token == "true" then {token: "${GITHUB_TOKEN}"} else {} end)),
		track: {mode: $track, tagPattern: "v*"},
		workspace: {path: $path},
		service: (if $unit == "" then {type: "none"} else {type: "systemd", name: $unit, sudo: true} end),
		rollback: {enabled: true},
		schedule: {enabled: true, intervalSeconds: $interval, jitterSeconds: 10},
		webhook: {enabled: true, host: "127.0.0.1", port: $port, statusPath: $status, secret: "${SELF_UPDATER_WEBHOOK_SECRET}"},
		logging: {level: "info", format: "text"}
	} + (if $health == "" then {} else {healthCheck: {url: $health}} end)'
	return
}

# _su_env: the environment file with the secrets the configuration refers to.
_su_env() {
	local secret token
	secret_load self-updater-webhook-secret secret 48
	printf 'SELF_UPDATER_WEBHOOK_SECRET=%s\n' "${secret}"
	token=$(opt token)
	if [[ -n ${token} ]]; then
		log_mask "${token}"
		if ! secret_exists self-updater-token || [[ $(secret_get self-updater-token) != "${token}" ]]; then
			secret_set self-updater-token "${token}"
		fi
		printf 'GITHUB_TOKEN=%s\n' "${token}"
	fi
	return
}

_su_unit() {
	local path nnp=yes
	path=$(opt path)
	# sudo for the restart of a systemd unit needs new privileges.
	[[ $(opt service) == none ]] || nnp=no
	cat <<EOF
# Managed by lss (module self-updater). Deploys new commits of $(opt repo) to ${path}.
[Unit]
Description=Self-Updater: deploys new commits of the configured repository
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SU_USER}
Group=${SU_USER}
WorkingDirectory=${SU_CONFIG_DIR}
Environment=SELF_UPDATER_CONFIG=${SU_CONFIG} HOME=${SU_HOME}
ExecStart=$(command -v self-updater || printf '/usr/bin/self-updater') start --immediate
Restart=on-failure
RestartSec=10
# A running deployment finishes before the service stops.
TimeoutStopSec=15min
KillMode=mixed
StateDirectory=self-updater
StateDirectoryMode=0750
UMask=0027
NoNewPrivileges=${nnp}

[Install]
WantedBy=multi-user.target
EOF
	return
}

mod_configure() {
	local before path service
	before=$(files_changes_of self-updater)
	path=$(opt path)
	# The state file (updater.state.json) lives next to the configuration, so the user writes the directory; the
	# configuration itself belongs to root.
	mon_dir "${SU_CONFIG_DIR}" "root:${SU_USER}" 0770
	mon_dir "${path}" "${SU_USER}:${SU_USER}" 0755
	_su_config | file_write 0640 "root:${SU_USER}" "${SU_CONFIG}"
	_su_env | file_write 0640 "root:${SU_USER}" "${SU_ENV}"
	service=$(opt service)
	if [[ ${service} == none ]]; then
		file_remove "${SU_SUDOERS}"
	else
		pkg_install sudo
		printf '# Managed by lss (module self-updater).\n%s ALL=(root) NOPASSWD: %s restart %s\n' "${SU_USER}" \
			"$(command -v systemctl)" "${service#systemd:}" | file_write 0440 root:root "${SU_SUDOERS}"
		visudo -cf "${SU_SUDOERS}" >/dev/null || die "self-updater: visudo rejects ${SU_SUDOERS}."
	fi
	log_command runuser -u "${SU_USER}" -- env SELF_UPDATER_CONFIG="${SU_CONFIG}" HOME="${SU_HOME}" \
		self-updater validate --config "${SU_CONFIG}" --env-file "${SU_ENV}" ||
		die "self-updater: the configuration does not validate; see the log."
	_su_unit | svc_unit "${SU_UNIT}.service"
	local -a sandbox=("ReadWritePaths=${SU_CONFIG_DIR}" "ReadWritePaths=${path}" "ReadWritePaths=${SU_HOME}")
	if [[ ${service} != none ]]; then
		# sudo needs its setuid bit and to read /etc/sudoers.d.
		sandbox+=(NoNewPrivileges=no RestrictSUIDSGID=no)
	fi
	svc_sandbox "${SU_UNIT}.service" "${sandbox[@]}"
	svc_enable "${SU_UNIT}"
	if [[ $(files_changes_of self-updater) != "${before}" ]]; then
		svc_restart "${SU_UNIT}" || die "self-updater: ${SU_UNIT} does not start; see journalctl -u ${SU_UNIT}."
	fi
	return
}

# _su_status: the JSON of the status endpoint, or nothing.
_su_status() {
	curl -fs --max-time 10 "http://127.0.0.1:$(opt_int port)${SU_STATUS_PATH}" 2>/dev/null || true
	return
}

mod_verify() {
	local status='' i commit
	[[ $(_su_installed) == "${SU_VERSION}" ]] || die "self-updater: Self-Updater ${SU_VERSION} is not installed."
	svc_is_active "${SU_UNIT}" || die "self-updater: ${SU_UNIT} is not running; see journalctl -u ${SU_UNIT}."
	[[ $(stat -c '%a %U:%G' "${SU_ENV}") == "640 root:${SU_USER}" ]] || die "self-updater: ${SU_ENV} must be mode 640, root:${SU_USER}."
	# The first deployment runs right after the start (--immediate): a clone of the repository into the workspace.
	for ((i = 0; i < 100; i++)); do
		status=$(_su_status)
		commit=$(jq -r '.workspaces[0].deployed.commit // empty' <<<"${status}" 2>/dev/null) || commit=''
		[[ -z ${commit} ]] || break
		sleep 3
	done
	[[ -n ${status} ]] || die "self-updater: the status endpoint http://127.0.0.1:$(opt_int port)${SU_STATUS_PATH} does not answer."
	[[ -n ${commit} ]] ||
		die "self-updater: nothing is deployed from $(opt repo) yet (last attempt: $(jq -c '.workspaces[0].lastAttempt' <<<"${status}" 2>/dev/null))."
	[[ $(runuser -u "${SU_USER}" -- git -C "$(opt path)" rev-parse HEAD 2>/dev/null) == "${commit}"* ]] ||
		die "self-updater: $(opt path) is not at the deployed commit ${commit}."
	return
}

mod_remove() {
	svc_disable "${SU_UNIT}"
	svc_dropin_remove "${SU_UNIT}.service" lss-sandbox
	file_remove "/etc/systemd/system/${SU_UNIT}.service"
	svc_daemon_reload
	file_remove "${SU_SUDOERS}"
	file_remove "${SU_CONFIG}"
	file_remove "${SU_ENV}"
	if [[ -n $(_su_installed) ]]; then
		log_command npm uninstall --global @vectode/self-updater || die "self-updater: npm cannot remove Self-Updater."
		files_note_change "removed Self-Updater"
	fi
	# The deployed checkout and the state of the updater stay unless --purge.
	[[ ${LSS_PURGE:-0} == 1 ]] || return 0
	rm -rf -- "${SU_CONFIG_DIR}" "${SU_HOME}"
	secret_remove self-updater-webhook-secret
	secret_remove self-updater-token
	files_note_change "deleted the state of Self-Updater"
	return
}
