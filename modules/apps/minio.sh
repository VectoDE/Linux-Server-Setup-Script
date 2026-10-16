# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="minio"
MOD_GROUP="apps"
MOD_DESCRIPTION="S3-compatible object storage with the MinIO server code (PGSTY Silo, the maintained fork, since MinIO archived its community edition) behind the web server: the S3 API and the web console as two HTTPS sites"
MOD_REQUIRES="system nginx|apache|caddy"
MOD_MODES="native docker"
MOD_OPTIONS="domains||Host names of the S3 API, separated by spaces; empty: minio.<host name of the server>
console_domains||Host names of the web console, separated by spaces; empty: minio-console.<host name of the server>
api_port|8091|Port of the S3 API on 127.0.0.1, which the web server forwards to
console_port|8092|Port of the web console on 127.0.0.1, which the web server forwards to
root_user|lssadmin|Name of the root user (the password is the secret minio-root-password)
memory|1g|Memory limit of the container (docker mode)"
MOD_SECRETS="minio-root-password"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# Silo RELEASE.2026-09-16T00-00-00Z: the image (multi-architecture index, amd64 and arm64) for the docker mode, the
# packages of the same release (data/checksums.txt) for the native mode. Checked 2026-10-15.
SILO_IMAGE=docker.io/pgsty/silo@sha256:635197cb9f36d01bee221d34d1c7d7960f6a95c48b0b6c01d99cd13bdae51a46
SILO_VERSION=20260916000000
# Not the root user of the image: an unprivileged user that owns only the data volume.
SILO_USER=1000:1000
SILO_ENV=/etc/default/silo
SILO_ETC=/etc/silo
SILO_DATA=/var/lib/silo
# Silo falls back to the well-known minioadmin:minioadmin when it finds no credentials; mod_verify makes sure it did not.
SILO_DEFAULT_LOGIN=minioadmin

mod_check() {
	local domain
	app_check_domains
	for domain in $(opt console_domains); do
		app_valid_domain "${domain}" || die "LSS_MINIO_CONSOLE_DOMAINS: '${domain}' is not a host name like minio-console.example.com."
	done
	app_check_port api_port
	app_check_port console_port
	[[ $(opt_int api_port) != "$(opt_int console_port)" ]] || die "LSS_MINIO_API_PORT and LSS_MINIO_CONSOLE_PORT must differ."
	[[ $(opt root_user) =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$ && $(opt root_user) != "${SILO_DEFAULT_LOGIN}" ]] ||
		die "LSS_MINIO_ROOT_USER must be 3 to 64 letters, digits, dots, dashes or underscores, other than ${SILO_DEFAULT_LOGIN}."
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_MINIO_MEMORY must be a size such as 1g or 768m."
	return
}

_minio_docker() {
	[[ $(module_mode minio) == docker ]]
	return
}

# _minio_console_domains: the host names of the web console.
_minio_console_domains() {
	local domains host
	domains=$(opt console_domains)
	if [[ -z ${domains} ]]; then
		host=$(hostname -f 2>/dev/null || true)
		[[ -n ${host} ]] || host=$(hostname)
		domains=minio-console.${host,,}
	fi
	printf '%s' "${domains}"
	return
}

_minio_console_domain() {
	local first
	read -r first _ <<<"$(_minio_console_domains)"
	printf '%s' "${first}"
	return
}

# _minio_package_installed: the pinned Silo release is installed.
_minio_package_installed() {
	if os_is_debian; then
		[[ $(dpkg-query -W -f='${Status} ${Version}' silo 2>/dev/null) == "install ok installed ${SILO_VERSION}"* ]]
	else
		[[ $(rpm -q --qf '%{VERSION}' silo 2>/dev/null) == "${SILO_VERSION}"* ]]
	fi
	return
}

mod_install() {
	local tmp
	if _minio_docker; then
		app_compose_ready
		return 0
	fi
	_minio_package_installed && return 0
	tmp=$(mktemp -d)
	if os_is_debian; then
		fetch_verified silo-deb "${tmp}/silo.deb"
		pkg_update_once
		log_command _pkg_apt install --no-install-recommends "${tmp}/silo.deb" || die "minio: apt cannot install Silo; see the log."
	else
		fetch_verified silo-rpm "${tmp}/silo.rpm"
		log_command _pkg_dnf install "${tmp}/silo.rpm" || die "minio: dnf cannot install Silo; see the log."
	fi
	rm -rf -- "${tmp}"
	_minio_package_installed || die "minio: Silo ${SILO_VERSION} is not installed after the package installation."
	files_note_change "installed Silo ${SILO_VERSION}"
	return
}

# _minio_compose: the stack of the docker mode. The image reads the root user and password from the files
# /run/secrets/access_key and /run/secrets/secret_key (MINIO_ROOT_USER_FILE and MINIO_ROOT_PASSWORD_FILE).
_minio_compose() {
	cat <<EOF
# Managed by lss (module minio). Change LSS_MINIO_* in /etc/lss/lss.conf and run lss configure minio.
name: $(app_project)
services:
  app:
    image: ${SILO_IMAGE}
    user: "${SILO_USER}"
    command: ["server", "/data", "--address", ":9000", "--console-address", ":9001"]
    depends_on:
      init:
        condition: service_completed_successfully
    environment:
      MINIO_SERVER_URL: https://$(app_domain)
      MINIO_BROWSER_REDIRECT_URL: https://$(_minio_console_domain)
      MINIO_API_TRUSTED_PROXIES: 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
    ports:
      - 127.0.0.1:$(opt_int api_port):9000
      - 127.0.0.1:$(opt_int console_port):9001
    volumes:
      - data:/data:z
$(app_mount config/root-user /run/secrets/access_key)
$(app_mount secrets/root-password /run/secrets/secret_key)
    tmpfs:
      - /tmp:mode=1777,size=128m
$(app_hardening "$(opt memory)" 512)
$(app_init data /data "${SILO_USER}")
volumes:
  data:
EOF
	return
}

# _minio_native: the service of the package with lss settings in /etc/default/silo; the password stays in a file that
# only root and silo read (MINIO_ROOT_PASSWORD_FILE), not in the environment.
_minio_native() {
	local password changed=0
	secret_load minio-root-password password 40
	id silo >/dev/null 2>&1 || die "minio: the package did not create the user silo."
	install -d -m 0750 -o root -g silo "${SILO_ETC}"
	install -d -m 0750 -o silo -g silo "${SILO_DATA}"
	file_write 0440 root:silo "${SILO_ETC}/root-password" <<<"${password}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	file_write 0644 root:root "${SILO_ENV}" <<EOF
# Managed by lss (module minio). Change LSS_MINIO_* in /etc/lss/lss.conf and run lss configure minio.
MINIO_VOLUMES="${SILO_DATA}"
MINIO_OPTS="--address 127.0.0.1:$(opt_int api_port) --console-address 127.0.0.1:$(opt_int console_port)"
MINIO_ROOT_USER="$(opt root_user)"
MINIO_ROOT_PASSWORD_FILE="${SILO_ETC}/root-password"
MINIO_SERVER_URL="https://$(app_domain)"
MINIO_BROWSER_REDIRECT_URL="https://$(_minio_console_domain)"
MINIO_API_TRUSTED_PROXIES="127.0.0.0/8,::1/128"
EOF
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	svc_sandbox silo.service "ReadWritePaths=${SILO_DATA}" "ReadOnlyPaths=${SILO_ETC}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	svc_enable silo.service
	if [[ ${changed} == 1 ]]; then
		svc_restart silo.service
	fi
	svc_wait_port 127.0.0.1 "$(opt_int api_port)" 60 || die "minio: Silo does not listen on 127.0.0.1:$(opt_int api_port)."
	return
}

mod_configure() {
	local -a console=()
	read -ra console <<<"$(_minio_console_domains)"
	if _minio_docker; then
		printf '%s' "$(opt root_user)" | app_file config/root-user "${SILO_USER}" 0444
		app_secret minio-root-password "${SILO_USER}" 40 root-password
		_minio_compose | app_compose
		app_backup LIVE=data
		app_up
	else
		_minio_native
		app_backup "PATHS=${SILO_DATA}"
	fi
	app_site "$(opt_int api_port)"
	app_site "$(opt_int console_port)" minio-console "${console[@]}"
	app_wait minio/health/ready 200 >/dev/null || die "minio: https://$(app_domain)/minio/health/ready does not answer."
	log_info "minio: S3 API https://$(app_domain), console https://$(_minio_console_domain); user $(opt root_user), password in $(secret_path minio-root-password)"
	return
}

# _minio_s3 USER SECRET METHOD PATH [CURL OPTION...]: an S3 request signed with AWS Signature V4 by curl; the login
# comes from a netrc file. SECRET empty: the default login of the server.
_minio_s3() {
	local user=$1 secret=$2 method=$3 path=$4 netrc page
	shift 4
	if [[ -n ${secret} ]]; then
		netrc=$(app_netrc "${user}" "${secret}")
	else
		netrc=$(mktemp)
		chmod 600 "${netrc}"
		printf 'machine %s login %s password %s\n' "$(app_domain)" "${SILO_DEFAULT_LOGIN}" "${SILO_DEFAULT_LOGIN}" >"${netrc}"
	fi
	page=$(app_get "${path}" --netrc-file "${netrc}" --aws-sigv4 aws:amz:us-east-1:s3 -X "${method}" "$@") || true
	rm -f -- "${netrc}"
	printf '%s' "${page}"
	return
}

# _minio_error PAGE: the S3 error code in the XML answer PAGE (such as SignatureDoesNotMatch).
_minio_error() {
	local page=$1
	sed -n 's:.*<Code>\([A-Za-z]*\)</Code>.*:\1:p' <<<"${page}" | head -n 1
	return
}

mod_verify() {
	local page bucket probe user status
	user=$(opt root_user)
	app_verify_backup
	if _minio_docker; then
		app_verify_stack
	else
		svc_is_active silo.service || die "minio: silo.service is not running."
		[[ $(stat -c '%a %U:%G' "${SILO_ETC}/root-password") == '440 root:silo' ]] ||
			die "minio: ${SILO_ETC}/root-password must be mode 440, owned by root:silo."
		page=$(app_get '' --head) || true
		grep -qi '^strict-transport-security:' <<<"${page}" || die "minio: https://$(app_domain)/ sends no Strict-Transport-Security header."
	fi
	page=$(app_wait minio/health/ready 200) || die "minio: the S3 API does not answer."
	page=$(APP_GET_DOMAIN=$(_minio_console_domain) app_wait '' 200 60) || die "minio: the web console does not answer."
	grep -qi '<html' <<<"${page}" || die "minio: https://$(_minio_console_domain)/ is not the web console."
	status=$(app_status "$(_minio_s3 "${SILO_DEFAULT_LOGIN}" '' GET '')")
	[[ ${status} == 403 ]] || die "minio: the default login ${SILO_DEFAULT_LOGIN} is not refused (HTTP ${status}); the root credentials did not apply."
	# Used, not only running: the root user creates a bucket, stores an object, reads it back and deletes both.
	bucket="lss-verify-$(date +%s)"
	probe=$(mktemp)
	printf '%s' "${bucket}" >"${probe}"
	status=$(app_status "$(_minio_s3 "${user}" minio-root-password PUT "${bucket}")")
	[[ ${status} == 200 ]] || die "minio: creating the bucket ${bucket} answers ${status}."
	# The hash of the body goes along explicitly: curl before 8.x leaves x-amz-content-sha256 out, and the server then
	# checks the signature against the hash of an empty body.
	page=$(_minio_s3 "${user}" minio-root-password PUT "${bucket}/probe.txt" --data-binary "@${probe}" \
		-H "x-amz-content-sha256: $(sha256sum "${probe}" | cut -d ' ' -f 1)")
	rm -f -- "${probe}"
	status=$(app_status "${page}")
	[[ ${status} == 200 ]] || die "minio: storing an object answers ${status} ($(_minio_error "${page}"))."
	page=$(_minio_s3 "${user}" minio-root-password GET "${bucket}/probe.txt")
	[[ ${page%$'\n'*} == "${bucket}" ]] || die "minio: the stored object does not come back."
	status=$(app_status "$(_minio_s3 "${user}" minio-root-password DELETE "${bucket}/probe.txt")")
	[[ ${status} == 204 ]] || die "minio: deleting the object answers ${status}."
	status=$(app_status "$(_minio_s3 "${user}" minio-root-password DELETE "${bucket}")")
	[[ ${status} == 204 ]] || die "minio: deleting the bucket answers ${status}."
	return
}

mod_remove() {
	app_site_remove minio-console
	if _minio_docker; then
		app_remove
		return 0
	fi
	app_site_remove minio
	app_backup_remove
	svc_disable silo.service
	svc_dropin_remove silo.service lss-sandbox
	file_remove "${SILO_ETC}"
	file_remove "${SILO_ENV}"
	pkg_remove silo
	if [[ ${LSS_PURGE:-0} == 1 ]]; then
		file_remove "${SILO_DATA}"
		secret_remove minio-root-password
	fi
	return
}
