# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="go"
MOD_GROUP="runtime"
MOD_DESCRIPTION="Go from the official release archive (checksum-verified) in /usr/local/go"
MOD_REQUIRES="system"
MOD_OPTIONS=""

# The distributions lag behind the Go releases (the Go team supports the two newest only), so lss installs the
# official archive. Raising the version means updating GO_VERSION and both lines in data/checksums.txt.
GO_VERSION=1.27.2
GO_ROOT=/usr/local/go
GO_PROFILE=/etc/profile.d/lss-go.sh

_go_installed_version() {
	[[ -f ${GO_ROOT}/VERSION ]] || return 0
	head -n 1 "${GO_ROOT}/VERSION"
	return
}

mod_install() {
	local tmp
	if [[ $(_go_installed_version) == "go${GO_VERSION}" ]]; then
		return 0
	fi
	log_info "Installing Go ${GO_VERSION}"
	# Unpacked next to the target and swapped in with one rename, so a failed download never leaves half a Go behind.
	tmp=$(mktemp -d /usr/local/.lss-go.XXXXXX)
	fetch_verified go "${tmp}/go.tar.gz"
	tar -xzf "${tmp}/go.tar.gz" -C "${tmp}" --no-same-owner --no-same-permissions
	[[ -x ${tmp}/go/bin/go ]] || {
		rm -rf -- "${tmp}"
		die "go: the archive holds no go/bin/go."
	}
	chmod -R u=rwX,go=rX "${tmp}/go"
	rm -rf -- "${GO_ROOT}"
	mv -- "${tmp}/go" "${GO_ROOT}"
	rm -rf -- "${tmp}"
	files_note_change "installed Go ${GO_VERSION} in ${GO_ROOT}"
	return
}

mod_configure() {
	file_write 0644 root:root "${GO_PROFILE}" <<EOF
# Managed by lss (module go). Puts the Go toolchain on the PATH of login shells.
case ":\${PATH}:" in
*:${GO_ROOT}/bin:*) ;;
*) PATH="\${PATH}:${GO_ROOT}/bin" ;;
esac
export PATH
EOF
	return
}

mod_verify() {
	local output
	output=$("${GO_ROOT}/bin/go" version 2>/dev/null) || die "go: ${GO_ROOT}/bin/go does not run."
	[[ ${output} == "go version go${GO_VERSION} "* ]] || die "go: ${GO_ROOT}/bin/go is not Go ${GO_VERSION} (${output})."
	# A login shell finds go through the profile entry.
	output=$(env -i HOME=/root PATH=/usr/bin:/bin bash -lc 'command -v go' 2>/dev/null) || true
	# The last line: a profile script may print something before.
	[[ ${output##*$'\n'} == "${GO_ROOT}/bin/go" ]] || die "go: ${GO_PROFILE} does not put go on the PATH."
	return
}

mod_remove() {
	if [[ -d ${GO_ROOT} ]]; then
		rm -rf -- "${GO_ROOT}"
		files_note_change "removed ${GO_ROOT}"
	fi
	file_remove "${GO_PROFILE}"
	return
}
