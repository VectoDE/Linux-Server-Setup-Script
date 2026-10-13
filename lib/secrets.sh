# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Secrets live in /etc/lss/secrets/<name>, one file each, mode 0600 in a 0700 directory. A secret is generated once
# and then reused, so a second run keeps every password. Every secret read is registered for masking in the logs.

LSS_SECRETS_DIR=${LSS_SECRETS_DIR:-/etc/lss/secrets}

secret_valid_name() {
	local name=$1
	[[ ${name} =~ ^[a-z0-9][a-z0-9._-]*$ ]]
	return
}

secret_path() {
	local name=$1
	secret_valid_name "${name}" || die "Invalid secret name '${name}'."
	printf '%s/%s' "${LSS_SECRETS_DIR}" "${name}"
	return
}

# Prints LENGTH random characters from A-Z a-z 0-9 (no characters that need quoting anywhere).
secret_random() {
	local length=${1:-32} value=''
	while [[ ${#value} -lt ${length} ]]; do
		# head closes the pipe early; tr's broken-pipe error is expected and silenced.
		value+=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "$((length - ${#value}))" || true)
	done
	printf '%s' "${value}"
	return
}

_secrets_prepare_dir() {
	if [[ ! -d ${LSS_SECRETS_DIR} ]]; then
		mkdir -p "${LSS_SECRETS_DIR}"
	fi
	chmod 700 "${LSS_SECRETS_DIR}"
	return
}

# secret_get NAME [LENGTH]: prints the secret, creating it if needed.
secret_get() {
	local name=$1 length=${2:-32} path value
	secret_valid_name "${name}" || die "Invalid secret name '${name}'."
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
	return
}

# secret_load NAME VARIABLE [LENGTH]: like secret_get, but assigns the value in the calling shell, so the masking
# registration survives (a command substitution would lose it).
secret_load() {
	# The local name must not collide with the caller's variable name, or printf -v would assign the local.
	local _lss_secret_name=$1 _lss_secret_variable=$2 _lss_secret_value
	_lss_secret_value=$(secret_get "${_lss_secret_name}" "${3:-32}") ||
		die "Could not read secret '${_lss_secret_name}'."
	log_mask "${_lss_secret_value}"
	printf -v "${_lss_secret_variable}" '%s' "${_lss_secret_value}"
	return
}

# secret_set NAME VALUE: stores a given secret (from configuration), for example an API token.
secret_set() {
	local name=$1 value=$2 path
	secret_valid_name "${name}" || die "Invalid secret name '${name}'."
	path=$(secret_path "${name}")
	_secrets_prepare_dir
	(
		umask 077
		printf '%s' "${value}" >"${path}.tmp"
	)
	mv -f -- "${path}.tmp" "${path}"
	chmod 600 "${path}"
	log_mask "${value}"
	return
}

secret_exists() {
	local name=$1
	[[ -s $(secret_path "${name}") ]]
	return
}

secret_remove() {
	local name=$1
	rm -f -- "$(secret_path "${name}")"
	return
}
