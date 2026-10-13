# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Direct downloads. Every file lss downloads is listed in data/checksums.txt as
#   <name> <arch|any> <sha256> <url>
# fetch_verified downloads over HTTPS only, checks the SHA-256 and deletes the file on a mismatch.

# fetch_entry NAME: prints "sha256 url" for the current architecture.
fetch_entry() {
	local name=$1 arch entry_name entry_arch sum url
	arch=${OS_ARCH:-$(uname -m)}
	while read -r entry_name entry_arch sum url; do
		[[ ${entry_name} == "${name}" ]] || continue
		[[ ${entry_arch} == "${arch}" || ${entry_arch} == any ]] || continue
		printf '%s %s' "${sum}" "${url}"
		return 0
	done < <(grep -v '^[[:space:]]*#' "${LSS_ROOT}/data/checksums.txt")
	return 1
}

# fetch_verified NAME DEST
fetch_verified() {
	local name=$1 dest=$2 entry sum url actual
	entry=$(fetch_entry "${name}") || die "No checksum for ${name} on ${OS_ARCH:-$(uname -m)} in data/checksums.txt."
	sum=${entry%% *}
	url=${entry#* }
	[[ ${url} == https://* ]] || die "Refusing ${url}: downloads must use HTTPS."
	if [[ -f ${dest} ]] && [[ $(sha256sum "${dest}" | cut -d ' ' -f 1) == "${sum}" ]]; then
		return 0
	fi
	mkdir -p "$(dirname "${dest}")"
	log_info "Downloading ${name}"
	curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 -o "${dest}.part" "${url}" ||
		die "Download of ${name} failed: ${url}"
	actual=$(sha256sum "${dest}.part" | cut -d ' ' -f 1)
	if [[ ${actual} != "${sum}" ]]; then
		rm -f -- "${dest}.part"
		die "Checksum mismatch for ${name}: expected ${sum}, got ${actual}. The file was deleted."
	fi
	mv -f -- "${dest}.part" "${dest}"
}
