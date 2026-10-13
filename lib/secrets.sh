# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Secrets live in /etc/lss/secrets/<name>, one file each, mode 0600 in a 0700 directory. A secret is generated once
# and then reused, so a second run keeps every password. Every secret read is registered for masking in the logs.

LSS_SECRETS_DIR=${LSS_SECRETS_DIR:-/etc/lss/secrets}

secret_valid_name() {
	[[ $1 =~ ^[a-z0-9][a-z0-9._-]*$ ]]
}

secret_path() {
	secret_valid_name "$1" || die "Invalid secret name '$1'."
	printf '%s/%s' "${LSS_SECRETS_DIR}" "$1"
}

# Prints LENGTH random characters from A-Z a-z 0-9 (no characters that need quoting anywhere).
secret_random() {
	local length=${1:-32} value=''
	while [[ ${#value} -lt ${length} ]]; do
		value+=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$((length - ${#value}))" || true)
	done
	printf '%s' "${value}"
}

_secrets_prepare_dir() {
	if [[ ! -d ${LSS_SECRETS_DIR} ]]; then
		mkdir -p "${LSS_SECRETS_DIR}"
	fi
	chmod 700 "${LSS_SECRETS_DIR}"
}

# secret_get NAME [LENGTH]: prints the secret, creating it if needed.
secret_get() {
	local name=$1 length=${2:-32} path value
	path=$(secret_path "${name}")
	_secrets_prepare_dir
	if [[ ! -s ${path} ]]; then
		(
			umask 077
			secret_random "${length}" >"${path}.tmp"
		)
		mv -f -- "${path}.tmp" "${path}"
		log_info "Generated secret ${name} (lss secrets show ${name})"
	fi
	chmod 600 "${path}"
	value=$(<"${path}")
	log_mask "${value}"
	printf '%s' "${value}"
}

# secret_load NAME VARIABLE [LENGTH]: like secret_get, but assigns the value in the calling shell, so the masking
# registration survives (a command substitution would lose it).
secret_load() {
	local value
	value=$(secret_get "$1" "${3:-32}")
	log_mask "${value}"
	printf -v "$2" '%s' "${value}"
}

# secret_set NAME VALUE: stores a given secret (from configuration), for example an API token.
secret_set() {
	local path
	path=$(secret_path "$1")
	_secrets_prepare_dir
	(
		umask 077
		printf '%s' "$2" >"${path}.tmp"
	)
	mv -f -- "${path}.tmp" "${path}"
	chmod 600 "${path}"
	log_mask "$2"
}

secret_exists() {
	[[ -s $(secret_path "$1") ]]
}

secret_remove() {
	rm -f -- "$(secret_path "$1")"
}
