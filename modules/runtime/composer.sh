# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="composer"
MOD_GROUP="runtime"
MOD_DESCRIPTION="Composer, the PHP dependency manager, as a checksum-verified release in /usr/local/bin"
MOD_REQUIRES="system php"
MOD_OPTIONS=""

COMPOSER_BIN=/usr/local/bin/composer

# The pinned release (data/checksums.txt) replaces the binary only when it differs, so "composer self-update" by an
# administrator is undone on the next lss run; raise the pinned version in lss instead.
mod_install() {
	local entry sum tmp
	# Composer unpacks archives with unzip when PHP has no zip extension (the RHEL family) and git for sources.
	# Both are left in place by remove: other modules and the administrator use them too.
	pkg_install unzip git
	entry=$(fetch_entry composer) || die "composer: data/checksums.txt has no entry for composer."
	sum=${entry%% *}
	if [[ -f ${COMPOSER_BIN} && ! -L ${COMPOSER_BIN} ]] && [[ $(sha256sum "${COMPOSER_BIN}" | cut -d ' ' -f 1) == "${sum}" ]] &&
		[[ $(stat -c '%a %U:%G' "${COMPOSER_BIN}") == '755 root:root' ]]; then
		return 0
	fi
	tmp=$(mktemp -d)
	fetch_verified composer "${tmp}/composer.phar"
	file_write 0755 root:root "${COMPOSER_BIN}" <"${tmp}/composer.phar"
	rm -rf -- "${tmp}"
	return
}

mod_verify() {
	local version home status=0
	[[ -x ${COMPOSER_BIN} ]] || die "composer: ${COMPOSER_BIN} is missing."
	# Composer refuses to run as root without COMPOSER_ALLOW_SUPERUSER; a throwaway home keeps root's untouched.
	home=$(mktemp -d)
	version=$(COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_HOME=${home} COMPOSER_NO_INTERACTION=1 \
		"${COMPOSER_BIN}" --version --no-ansi 2>/dev/null) || status=$?
	rm -rf -- "${home}"
	[[ ${status} == 0 ]] || die "composer: ${COMPOSER_BIN} does not run."
	[[ ${version} == Composer* ]] || die "composer: unexpected version output '${version}'."
	return
}

mod_remove() {
	file_remove "${COMPOSER_BIN}"
	return
}
