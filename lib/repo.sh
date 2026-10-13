# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Third-party package repositories. Each one is described in data/repos/<name>.conf; its signing key ships in
# data/keys/ and must carry exactly the fingerprints listed there, so a replaced key is refused before apt or dnf
# ever trusts it. apt sources are limited to that key with Signed-By, dnf repositories use gpgcheck and
# repo_gpgcheck where the vendor signs the metadata.

# _kv FILE KEY: value of KEY in a KEY=value file (parsed, not sourced).
_kv() {
	local file=$1 key=$2 line
	while IFS= read -r line || [[ -n ${line} ]]; do
		[[ ${line} == "${key}="* ]] || continue
		printf '%s' "${line#*=}"
		return 0
	done <"${file}"
}

# repo_key_fingerprints KEYFILE: prints the primary key fingerprints in the file.
repo_key_fingerprints() {
	local keyfile=$1
	gpg --batch --quiet --show-keys --with-colons "${keyfile}" 2>/dev/null |
		awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }'
	return
}

# repo_key_verify KEYFILE "FPR1 FPR2 ...": every key in the file must be one of the expected fingerprints.
repo_key_verify() {
	local file=$1 expected=$2 found=0 fingerprint
	while IFS= read -r fingerprint; do
		[[ -n ${fingerprint} ]] || continue
		found=1
		if [[ " ${expected} " != *" ${fingerprint} "* ]]; then
			log_error "Key ${file##*/} contains unexpected key ${fingerprint}."
			return 1
		fi
	done < <(repo_key_fingerprints "${file}")
	[[ ${found} == 1 ]] || {
		log_error "Key ${file##*/} contains no key."
		return 1
	}
}

_repo_value() {
	local value
	value=$(_kv "$1" "$2")
	value=${value//\{\{codename\}\}/${OS_CODENAME}}
	value=${value//\{\{major\}\}/${OS_MAJOR}}
	value=${value//\{\{arch\}\}/$(os_deb_arch)}
	value=${value//\{\{id\}\}/${OS_ID}}
	printf '%s' "${value}"
	return
}

# repo_add NAME: installs the key and the source of data/repos/NAME.conf for the current distribution.
repo_add() {
	local name=$1 conf key fingerprints keyring
	conf="${LSS_ROOT}/data/repos/${name}.conf"
	[[ -r ${conf} ]] || die "Unknown repository ${name}."
	key="${LSS_ROOT}/data/keys/$(_kv "${conf}" KEY)"
	fingerprints=$(_kv "${conf}" FINGERPRINTS)
	pkg_install_family 'gnupg ca-certificates' 'gnupg2 ca-certificates'
	repo_key_verify "${key}" "${fingerprints}" || die "Refusing repository ${name}: its key does not match the pinned fingerprints."

	if os_is_debian; then
		local url suites components
		url=$(_repo_value "${conf}" DEB_URL)
		# DEB_SUITE_<codename> overrides the suite for one release (vendors without packages for it yet).
		suites=$(_repo_value "${conf}" "DEB_SUITE_${OS_CODENAME}")
		[[ -n ${suites} ]] || suites=$(_repo_value "${conf}" DEB_SUITE)
		components=$(_repo_value "${conf}" DEB_COMPONENTS)
		[[ -n ${url} ]] || die "Repository ${name} has no packages for ${OS_ID}."
		keyring="/etc/apt/keyrings/lss-${name}.gpg"
		mkdir -p /etc/apt/keyrings
		file_write 0644 root:root "${keyring}" < <(gpg --batch --dearmor <"${key}")
		local changed=${LSS_FILE_CHANGED}
		file_write 0644 root:root "/etc/apt/sources.list.d/lss-${name}.sources" <<EOF
# Managed by lss (repository ${name}).
Types: deb
URIs: ${url}
Suites: ${suites}
Components: ${components}
Architectures: $(os_deb_arch)
Signed-By: ${keyring}
EOF
		if [[ ${changed} == 1 || ${LSS_FILE_CHANGED} == 1 || ${LSS_PKG_UPDATED} != 1 ]]; then
			pkg_update
		fi
	else
		local baseurl gpgcheck repo_gpgcheck
		# RPM_BASEURL_<major> overrides the URL for one major release (vendors without packages for it yet).
		baseurl=$(_repo_value "${conf}" "RPM_BASEURL_${OS_MAJOR}")
		[[ -n ${baseurl} ]] || baseurl=$(_repo_value "${conf}" RPM_BASEURL)
		gpgcheck=$(_kv "${conf}" RPM_GPGCHECK)
		repo_gpgcheck=$(_kv "${conf}" RPM_REPO_GPGCHECK)
		# At least one signature must be checked: the packages, the metadata or both.
		[[ ${gpgcheck:-1} == 1 || ${repo_gpgcheck:-0} == 1 ]] || die "Repository ${name} checks no signature."
		[[ -n ${baseurl} ]] || die "Repository ${name} has no packages for ${OS_ID}."
		keyring="/etc/pki/rpm-gpg/lss-${name}.asc"
		file_write 0644 root:root "${keyring}" <"${key}"
		file_write 0644 root:root "/etc/yum.repos.d/lss-${name}.repo" <<EOF
# Managed by lss (repository ${name}).
[lss-${name}]
name=${name} (added by lss)
baseurl=${baseurl}
enabled=1
gpgcheck=${gpgcheck:-1}
repo_gpgcheck=${repo_gpgcheck:-0}
gpgkey=file://${keyring}
EOF
	fi
	return
}

repo_remove() {
	local name=$1
	file_remove "/etc/apt/sources.list.d/lss-${name}.sources"
	file_remove "/etc/apt/keyrings/lss-${name}.gpg"
	file_remove "/etc/yum.repos.d/lss-${name}.repo"
	file_remove "/etc/pki/rpm-gpg/lss-${name}.asc"
	return
}
