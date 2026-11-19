# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Third-party package repositories. Each one is described in data/repos/<name>.conf; its signing key ships in
# data/keys/ and must carry exactly the fingerprints listed there, so a replaced key is refused before the package
# manager ever trusts it. apt sources are limited to that key with Signed-By, dnf and yum repositories use gpgcheck
# and repo_gpgcheck where the vendor signs the metadata, zypper imports the key into rpm and checks it the same way.
# pacman signs with OpenPGP too: the key is added to pacman's keyring and signed locally, and the repository needs a
# signature on every package (SigLevel Required). Alpine signs with plain RSA keys; such a key is pinned by its
# SHA-256 (APK_KEY_SHA256) instead of a fingerprint. Every repository URL must use HTTPS.
#
# Keys of a repository file (KEY and FINGERPRINTS are needed except on Alpine, which needs APK_KEY and APK_KEY_SHA256):
#   DEB_URL DEB_SUITE[_<codename>] DEB_COMPONENTS          apt
#   RPM_BASEURL[_<major>] RPM_GPGCHECK RPM_REPO_GPGCHECK    dnf and yum; RPM_KEY and RPM_FINGERPRINTS for another key
#   SUSE_BASEURL SUSE_PKG_GPGCHECK SUSE_REPO_GPGCHECK      zypper (with the RPM key, like dnf)
#   APK_URL APK_KEY APK_KEY_SHA256                         apk
#   PACMAN_REPO PACMAN_SERVER PACMAN_SIGLEVEL              pacman; PACMAN_KEY and PACMAN_FINGERPRINTS for another key
# Placeholders: {{codename}}, {{major}}, {{version}} (VERSION_ID), {{major_minor}} (3.21 for 3.21.2), {{arch}} (Debian
# names) and {{id}}. pacman's own $repo and $arch stay as they are.

# Files lss shares with the administrator: lss changes only its own block in them (_repo_block).
LSS_APK_REPOSITORIES=${LSS_APK_REPOSITORIES:-/etc/apk/repositories}
LSS_PACMAN_CONF=${LSS_PACMAN_CONF:-/etc/pacman.conf}

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
	value=${value//\{\{version\}\}/${OS_VERSION}}
	value=${value//\{\{major_minor\}\}/$(_repo_major_minor)}
	printf '%s' "${value}"
	return
}

# _repo_major_minor: the first two parts of VERSION_ID (3.21 for 3.21.2; 15.6 and 12 stay as they are).
_repo_major_minor() {
	local rest
	if [[ ${OS_VERSION} != *.* ]]; then
		printf '%s' "${OS_VERSION}"
		return 0
	fi
	rest=${OS_VERSION#*.}
	printf '%s.%s' "${OS_VERSION%%.*}" "${rest%%.*}"
	return
}

# _repo_https NAME URL: refuses a repository URL that does not use HTTPS.
_repo_https() {
	[[ $2 == https://* ]] || die "Refusing repository $1: ${2:-its URL} does not use HTTPS."
	return
}

# _repo_block_strip FILE NAME: FILE without the block of repository NAME.
_repo_block_strip() {
	[[ -f $1 ]] || return 0
	awk -v begin="# BEGIN lss repository $2" -v end="# END lss repository $2" '
		$0 == begin { skip = 1; next }
		skip && $0 == end { skip = 0; next }
		!skip' "$1"
	return
}

# _repo_block FILE NAME, lines on stdin: puts the lines between markers of repository NAME at the end of FILE, a file
# lss shares with the administrator (/etc/apk/repositories, /etc/pacman.conf). No lines remove the block. The rest of
# the file, its mode and its owner stay as they are, and the file is not checksummed, because others change it too.
# Sets LSS_FILE_CHANGED.
_repo_block() {
	local file=$1 name=$2 body current new tmp
	body=$(cat)
	LSS_FILE_CHANGED=0
	if [[ ! -f ${file} ]]; then
		[[ -z ${body} ]] || die "Cannot add repository ${name}: ${file} is missing."
		return 0
	fi
	[[ ! -L ${file} ]] || die "Refusing to change ${file}: it is a symbolic link."
	current=$(<"${file}")
	new=$(_repo_block_strip "${file}" "${name}")
	if [[ -n ${body} ]]; then
		new+="${new:+$'\n'}# BEGIN lss repository ${name}"$'\n'"${body}"$'\n'"# END lss repository ${name}"
	fi
	[[ ${new} != "${current}" ]] || return 0
	files_backup "${file}"
	tmp=$(mktemp "${file}.lss.XXXXXX")
	printf '%s\n' "${new}" >"${tmp}"
	chmod --reference="${file}" "${tmp}"
	chown --reference="${file}" "${tmp}"
	mv -f -- "${tmp}" "${file}"
	# shellcheck disable=SC2034 # read by callers
	LSS_FILE_CHANGED=1
	files_note_change "repository ${name} in ${file}"
	return
}

# repo_add NAME: installs the key and the source of data/repos/NAME.conf for the package manager of the system.
repo_add() {
	local name=$1 conf backend
	conf="${LSS_ROOT}/data/repos/${name}.conf"
	[[ -r ${conf} ]] || die "Unknown repository ${name}."
	backend=$(pkg_backend) || die "lss cannot manage the packages of this system."
	case ${backend} in
	apt) _repo_add_apt "${name}" "${conf}" ;;
	dnf | yum) _repo_add_rpm "${name}" "${conf}" ;;
	zypper) _repo_add_zypper "${name}" "${conf}" ;;
	apk) _repo_add_apk "${name}" "${conf}" ;;
	*) _repo_add_pacman "${name}" "${conf}" ;;
	esac
	return
}

# _repo_key NAME CONF [PREFIX]: verifies the OpenPGP key of the repository and prints its path. PREFIX (RPM, PACMAN)
# names a key of its own for that package format, for vendors that sign it with another key than their apt
# repository.
_repo_key() {
	local name=$1 conf=$2 prefix=${3:-} key fingerprints
	key=$(_kv "${conf}" KEY)
	fingerprints=$(_kv "${conf}" FINGERPRINTS)
	if [[ -n ${prefix} && -n $(_kv "${conf}" "${prefix}_KEY") ]]; then
		key=$(_kv "${conf}" "${prefix}_KEY")
		fingerprints=$(_kv "${conf}" "${prefix}_FINGERPRINTS")
	fi
	[[ -n ${key} ]] || die "Repository ${name} names no key."
	key="${LSS_ROOT}/data/keys/${key}"
	pkg_install_family 'gnupg ca-certificates' 'gnupg2 ca-certificates' 'gpg2 ca-certificates' 'gnupg ca-certificates' \
		'gnupg ca-certificates' >&2
	repo_key_verify "${key}" "${fingerprints}" || die "Refusing repository ${name}: its key does not match the pinned fingerprints."
	printf '%s' "${key}"
	return
}

# _repo_fingerprints CONF PREFIX: the pinned fingerprints of the key _repo_key chose.
_repo_fingerprints() {
	if [[ -n $(_kv "$1" "$2_KEY") ]]; then
		_kv "$1" "$2_FINGERPRINTS"
	else
		_kv "$1" FINGERPRINTS
	fi
	return
}

_repo_add_apt() {
	local name=$1 conf=$2 key keyring url suites components changed
	url=$(_repo_value "${conf}" DEB_URL)
	[[ -n ${url} ]] || die "Repository ${name} has no packages for ${OS_ID}."
	_repo_https "${name}" "${url}"
	key=$(_repo_key "${name}" "${conf}") || exit 1
	# DEB_SUITE_<codename> overrides the suite for one release (vendors without packages for it yet).
	suites=$(_repo_value "${conf}" "DEB_SUITE_${OS_CODENAME}")
	[[ -n ${suites} ]] || suites=$(_repo_value "${conf}" DEB_SUITE)
	components=$(_repo_value "${conf}" DEB_COMPONENTS)
	keyring="/etc/apt/keyrings/lss-${name}.gpg"
	mkdir -p /etc/apt/keyrings
	file_write 0644 root:root "${keyring}" < <(gpg --batch --dearmor <"${key}")
	changed=${LSS_FILE_CHANGED}
	# A flat repository (a suite ending in /, no DEB_COMPONENTS) must not name components.
	file_write 0644 root:root "/etc/apt/sources.list.d/lss-${name}.sources" < <(
		printf '# Managed by lss (repository %s).\nTypes: deb\nURIs: %s\nSuites: %s\n' "${name}" "${url}" "${suites}"
		[[ -z ${components} ]] || printf 'Components: %s\n' "${components}"
		printf 'Architectures: %s\nSigned-By: %s\n' "$(os_deb_arch)" "${keyring}"
	)
	if [[ ${changed} == 1 || ${LSS_FILE_CHANGED} == 1 || ${LSS_PKG_UPDATED} != 1 ]]; then
		pkg_update
	fi
	return
}

_repo_add_rpm() {
	local name=$1 conf=$2 key keyring baseurl gpgcheck repo_gpgcheck
	# RPM_BASEURL_<major> overrides the URL for one major release (vendors without packages for it yet).
	baseurl=$(_repo_value "${conf}" "RPM_BASEURL_${OS_MAJOR}")
	[[ -n ${baseurl} ]] || baseurl=$(_repo_value "${conf}" RPM_BASEURL)
	gpgcheck=$(_kv "${conf}" RPM_GPGCHECK)
	repo_gpgcheck=$(_kv "${conf}" RPM_REPO_GPGCHECK)
	# At least one signature must be checked: the packages, the metadata or both.
	[[ ${gpgcheck:-1} == 1 || ${repo_gpgcheck:-0} == 1 ]] || die "Repository ${name} checks no signature."
	[[ -n ${baseurl} ]] || die "Repository ${name} has no packages for ${OS_ID}."
	_repo_https "${name}" "${baseurl}"
	key=$(_repo_key "${name}" "${conf}" RPM) || exit 1
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
	return
}

# zypper: the key goes into the rpm database (rpm --import), so a non-interactive refresh never has to ask whether to
# trust it; pkg_gpgcheck and repo_gpgcheck say what is signed, and one of them must be on.
_repo_add_zypper() {
	local name=$1 conf=$2 key keyring baseurl pkg_check repo_check changed
	baseurl=$(_repo_value "${conf}" SUSE_BASEURL)
	pkg_check=$(_kv "${conf}" SUSE_PKG_GPGCHECK)
	repo_check=$(_kv "${conf}" SUSE_REPO_GPGCHECK)
	[[ ${pkg_check:-1} == 1 || ${repo_check:-1} == 1 ]] || die "Repository ${name} checks no signature."
	[[ -n ${baseurl} ]] || die "Repository ${name} has no packages for ${OS_ID}."
	_repo_https "${name}" "${baseurl}"
	key=$(_repo_key "${name}" "${conf}" RPM) || exit 1
	keyring="/etc/pki/rpm-gpg/lss-${name}.asc"
	file_write 0644 root:root "${keyring}" <"${key}"
	changed=${LSS_FILE_CHANGED}
	if [[ ${changed} == 1 ]]; then
		log_command rpm --import "${keyring}" || die "rpm does not take the key of repository ${name}."
	fi
	file_write 0644 root:root "/etc/zypp/repos.d/lss-${name}.repo" <<EOF
# Managed by lss (repository ${name}).
[lss-${name}]
name=${name} (added by lss)
baseurl=${baseurl}
type=rpm-md
enabled=1
autorefresh=1
gpgcheck=1
pkg_gpgcheck=${pkg_check:-1}
repo_gpgcheck=${repo_check:-1}
gpgkey=file://${keyring}
EOF
	if [[ ${changed} == 1 || ${LSS_FILE_CHANGED} == 1 || ${LSS_PKG_UPDATED} != 1 ]]; then
		pkg_update
	fi
	return
}

# apk: the RSA key goes to /etc/apk/keys under the name the vendor signs with (apk finds it by that name), the URL into
# lss's block of /etc/apk/repositories.
_repo_add_apk() {
	local name=$1 conf=$2 url key sum actual changed
	url=$(_repo_value "${conf}" APK_URL)
	key=$(_kv "${conf}" APK_KEY)
	sum=$(_kv "${conf}" APK_KEY_SHA256)
	[[ -n ${url} ]] || die "Repository ${name} has no packages for ${OS_ID}."
	_repo_https "${name}" "${url}"
	[[ ${key} =~ ^[A-Za-z0-9@._-]+\.rsa\.pub$ && ${sum} =~ ^[0-9a-f]{64}$ ]] ||
		die "Repository ${name} needs APK_KEY (a file name ending in .rsa.pub) and APK_KEY_SHA256."
	[[ -r ${LSS_ROOT}/data/keys/${key} ]] || die "Repository ${name}: the key ${key} is missing."
	actual=$(sha256sum "${LSS_ROOT}/data/keys/${key}" | cut -d ' ' -f 1)
	[[ ${actual} == "${sum}" ]] ||
		die "Refusing repository ${name}: the key ${key} has the SHA-256 ${actual}, not the pinned ${sum}."
	pkg_install_family '' '' '' 'ca-certificates'
	file_write 0644 root:root "/etc/apk/keys/${key}" <"${LSS_ROOT}/data/keys/${key}"
	changed=${LSS_FILE_CHANGED}
	_repo_block "${LSS_APK_REPOSITORIES}" "${name}" <<<"${url}"
	if [[ ${changed} == 1 || ${LSS_FILE_CHANGED} == 1 || ${LSS_PKG_UPDATED} != 1 ]]; then
		pkg_update
	fi
	return
}

# _repo_siglevel_ok LEVEL: the pacman SigLevel requires a valid signature on every package (Required, never Optional,
# Never or TrustAll).
_repo_siglevel_ok() {
	local word
	[[ $1 == Required* ]] || return 1
	for word in $1; do
		case ${word} in
		Never | Optional | PackageNever | PackageOptional | TrustAll | PackageTrustAll) return 1 ;;
		*) ;;
		esac
	done
	return 0
}

# pacman: the key is added to pacman's keyring and signed locally (pacman-key --lsign-key), which is how Arch trusts
# a key that is not one of its own; the repository section goes into lss's block of /etc/pacman.conf.
_repo_add_pacman() {
	local name=$1 conf=$2 key keyring repo server siglevel fingerprint changed
	repo=$(_kv "${conf}" PACMAN_REPO)
	server=$(_repo_value "${conf}" PACMAN_SERVER)
	siglevel=$(_kv "${conf}" PACMAN_SIGLEVEL)
	siglevel=${siglevel:-Required DatabaseOptional}
	[[ -n ${server} ]] || die "Repository ${name} has no packages for ${OS_ID}."
	_repo_https "${name}" "${server}"
	[[ ${repo} =~ ^[A-Za-z0-9_-]+$ && ! ${repo} =~ ^(options|core|extra|multilib|testing|core-testing|extra-testing|multilib-testing)$ ]] ||
		die "Repository ${name} needs PACMAN_REPO, the name of its database (not one of Arch's own)."
	_repo_siglevel_ok "${siglevel}" || die "Repository ${name}: SigLevel '${siglevel}' does not require signed packages."
	key=$(_repo_key "${name}" "${conf}" PACMAN) || exit 1
	keyring="/etc/pacman.d/lss-${name}.asc"
	file_write 0644 root:root "${keyring}" <"${key}"
	changed=${LSS_FILE_CHANGED}
	for fingerprint in $(_repo_fingerprints "${conf}" PACMAN); do
		if [[ ${changed} == 1 ]] || ! pacman-key --list-keys "${fingerprint}" >/dev/null 2>&1; then
			log_command pacman-key --add "${keyring}" || die "pacman-key does not take the key of repository ${name}."
			log_command pacman-key --lsign-key "${fingerprint}" || die "pacman-key cannot sign the key ${fingerprint}."
			changed=1
		fi
	done
	_repo_block "${LSS_PACMAN_CONF}" "${name}" <<EOF
[${repo}]
SigLevel = ${siglevel}
Server = ${server}
EOF
	if [[ ${changed} == 1 || ${LSS_FILE_CHANGED} == 1 || ${LSS_PKG_UPDATED} != 1 ]]; then
		pkg_update
	fi
	return
}

# repo_remove NAME: removes the source and the key of every backend; what is absent stays absent.
repo_remove() {
	local name=$1 conf key fingerprint
	conf="${LSS_ROOT}/data/repos/${name}.conf"
	file_remove "/etc/apt/sources.list.d/lss-${name}.sources"
	file_remove "/etc/apt/keyrings/lss-${name}.gpg"
	file_remove "/etc/yum.repos.d/lss-${name}.repo"
	file_remove "/etc/zypp/repos.d/lss-${name}.repo"
	file_remove "/etc/pki/rpm-gpg/lss-${name}.asc"
	_repo_block "${LSS_APK_REPOSITORIES}" "${name}" </dev/null
	_repo_block "${LSS_PACMAN_CONF}" "${name}" </dev/null
	if [[ -r ${conf} ]]; then
		key=$(_kv "${conf}" APK_KEY)
		[[ -z ${key} ]] || file_remove "/etc/apk/keys/${key}"
		if command -v pacman-key >/dev/null 2>&1; then
			for fingerprint in $(_repo_fingerprints "${conf}" PACMAN); do
				if pacman-key --list-keys "${fingerprint}" >/dev/null 2>&1; then
					log_command pacman-key --delete "${fingerprint}" || log_warn "pacman-key keeps the key ${fingerprint}."
				fi
			done
		fi
	fi
	file_remove "/etc/pacman.d/lss-${name}.asc"
	return
}
