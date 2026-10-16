#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# bootstrap.sh: installs lss from a signed release, and is what `lss update` runs.
#
#   sudo bash bootstrap.sh [VERSION]       install VERSION (default: the latest release) and make it the active one
#   sudo bash bootstrap.sh --rollback      switch back to the version that was active before
#   sudo bash bootstrap.sh --dry-run [V]   download and verify only
#
# Nothing from a download runs before two checks pass: the SHA-256 of the archive matches SHA256SUMS of the release,
# and the GitHub build attestation (Sigstore, SLSA provenance) of both files proves that the release workflow of
# VectoDE/Linux-Server-Setup-Script built them from main on a GitHub-hosted runner. The attestation is checked with
# the GitHub CLI, downloaded at a pinned version and checked against its pinned SHA-256 first.
#
# Layout: every version in /opt/lss/<version> (root-owned, not writable for others), the active one behind the
# symbolic link /opt/lss/current, the one before it behind /opt/lss/previous, and /usr/local/sbin/lss pointing to
# /opt/lss/current/lss. Links are replaced with rename(2), so a reader sees the old or the new version, never none.
# Older versions than these two are deleted.

set -Eeuo pipefail
shopt -s inherit_errexit

BS_REPO=VectoDE/Linux-Server-Setup-Script
# GitHub CLI used to check attestations. A new version needs both checksums from its gh_<version>_checksums.txt.
BS_GH_VERSION=2.102.0
BS_GH_SHA256_AMD64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
BS_GH_SHA256_ARM64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484
BS_VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

LSS_PREFIX=${LSS_PREFIX:-/opt/lss}
LSS_BIN_LINK=${LSS_BIN_LINK:-/usr/local/sbin/lss}
LSS_LOCK=${LSS_LOCK:-/run/lss.lock}
# Where releases come from: https:// (the GitHub releases of this repository, or a mirror of them) or file:// (a
# directory with the same layout, used by the tests). The files are checked the same way wherever they come from.
LSS_RELEASE_URL=${LSS_RELEASE_URL:-https://github.com/${BS_REPO}/releases}
# The workflow and git ref that must have signed a release. The tests of this repository sign test builds with their
# own workflow on the pull request ref and set these two; releases are signed by release.yml on main.
LSS_RELEASE_WORKFLOW=${LSS_RELEASE_WORKFLOW:-release.yml}
LSS_RELEASE_REF=${LSS_RELEASE_REF:-refs/heads/main}
LSS_DRY_RUN=${LSS_DRY_RUN:-0}

# --- output -------------------------------------------------------------------------------------------------------

# Same format as lss itself: terminal, the run log of `lss update` and the journal (identifier "lss").
bs_log() {
	local level=$1
	shift
	printf '%-5s %s\n' "${level}" "$*" >&2
	if [[ -n ${LSS_LOG_FILE:-} ]]; then
		printf '%s %-5s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${level}" "$*" >>"${LSS_LOG_FILE}" 2>/dev/null || true
	fi
	if [[ ${LSS_JOURNAL:-1} == 1 ]] && command -v logger >/dev/null 2>&1; then
		logger -t lss -- "${level} $*" 2>/dev/null || true
	fi
	return
}

bs_info() {
	bs_log INFO "$*"
	return
}

bs_ok() {
	bs_log OK "$*"
	return
}

bs_warn() {
	bs_log WARN "$*"
	return
}

bs_die() {
	bs_log ERROR "$*"
	exit 1
}

# --- versions -----------------------------------------------------------------------------------------------------

bs_valid_version() {
	local version=$1
	[[ ${version} =~ ${BS_VERSION_RE} ]]
	return
}

# _bs_ident_cmp A B: compares two pre-release identifiers by SemVer rules (numbers numerically and below words).
_bs_ident_cmp() {
	local a=$1 b=$2
	if [[ ${a} =~ ^[0-9]+$ && ${b} =~ ^[0-9]+$ ]]; then
		if ((10#${a} > 10#${b})); then
			printf '1'
		elif ((10#${a} < 10#${b})); then
			printf -- '-1'
		else
			printf '0'
		fi
	elif [[ ${a} =~ ^[0-9]+$ ]]; then
		printf -- '-1'
	elif [[ ${b} =~ ^[0-9]+$ ]]; then
		printf '1'
	elif [[ ${a} > "${b}" ]]; then
		printf '1'
	elif [[ ${a} < "${b}" ]]; then
		printf -- '-1'
	else
		printf '0'
	fi
	return
}

# bs_version_cmp A B: prints 1, 0 or -1 when version A is newer than, equal to or older than B (SemVer precedence:
# 2.1.0 > 2.1.0-rc.2 > 2.1.0-rc.1 > 2.0.9).
bs_version_cmp() {
	local a=$1 b=$2 a_pre='' b_pre='' i result
	local -a x=() y=()
	[[ ${a} != *-* ]] || a_pre=${a#*-}
	[[ ${b} != *-* ]] || b_pre=${b#*-}
	IFS=. read -ra x <<<"${a%%-*}"
	IFS=. read -ra y <<<"${b%%-*}"
	for i in 0 1 2; do
		result=$(_bs_ident_cmp "${x[i]}" "${y[i]}")
		if [[ ${result} != 0 ]]; then
			printf '%s' "${result}"
			return 0
		fi
	done
	if [[ -z ${a_pre} || -z ${b_pre} ]]; then
		# A release ranks above its own pre-releases.
		if [[ -z ${a_pre} && -n ${b_pre} ]]; then
			printf '1'
		elif [[ -n ${a_pre} && -z ${b_pre} ]]; then
			printf -- '-1'
		else
			printf '0'
		fi
		return 0
	fi
	IFS=. read -ra x <<<"${a_pre}"
	IFS=. read -ra y <<<"${b_pre}"
	for ((i = 0; i < ${#x[@]} || i < ${#y[@]}; i++)); do
		if ((i >= ${#x[@]})); then
			printf -- '-1'
			return 0
		fi
		if ((i >= ${#y[@]})); then
			printf '1'
			return 0
		fi
		result=$(_bs_ident_cmp "${x[i]}" "${y[i]}")
		if [[ ${result} != 0 ]]; then
			printf '%s' "${result}"
			return 0
		fi
	done
	printf '0'
	return
}

# --- downloads and checks -----------------------------------------------------------------------------------------

# bs_fetch URL DEST: HTTPS only (redirects included), or file:// for a local release directory.
bs_fetch() {
	local url=$1 dest=$2 proto
	case ${url} in
	https://*) proto='=https' ;;
	file://*) proto='=file' ;;
	*) bs_die "Refusing ${url}: releases are downloaded over HTTPS." ;;
	esac
	# 9>&- here and for gh: helpers must not inherit the run lock (fd 9 of lss and bootstrap.sh). A helper process that
	# outlives the run would keep the lock and refuse the next lss run.
	curl --proto "${proto}" --proto-redir "${proto}" --tlsv1.2 -fsSL --retry 3 --retry-delay 2 -o "${dest}" -- "${url}" 9>&- ||
		bs_die "Download failed: ${url}"
	return
}

# bs_sum_of SUMS NAME: the SHA-256 that a SHA256SUMS file lists for NAME.
bs_sum_of() {
	local sums=$1 name=$2
	awk -v name="${name}" '$2 == name || $2 == "*" name { print $1; exit }' "${sums}"
	return
}

# bs_check_sum FILE SUMS: the file's SHA-256 must be the one SHA256SUMS lists for its name.
bs_check_sum() {
	local file=$1 sums=$2 expected actual
	expected=$(bs_sum_of "${sums}" "${file##*/}")
	[[ ${expected} =~ ^[0-9a-f]{64}$ ]] || bs_die "SHA256SUMS lists ${file##*/} without a SHA-256; the release is incomplete."
	actual=$(sha256sum -- "${file}" | cut -d ' ' -f 1)
	[[ ${actual} == "${expected}" ]] ||
		bs_die "Checksum mismatch for ${file##*/}: SHA256SUMS lists ${expected}, the download has ${actual}."
	return
}

# bs_latest_version DIR: the version of the latest release, read from the file list in its SHA256SUMS.
bs_latest_version() {
	local dir=$1 version
	bs_fetch "${LSS_RELEASE_URL}/latest/download/SHA256SUMS" "${dir}/latest.sums"
	version=$(sed -nE 's/^[0-9a-f]{64} [ *]lss-(.+)\.tar\.gz$/\1/p' "${dir}/latest.sums")
	bs_valid_version "${version}" || bs_die "The latest release at ${LSS_RELEASE_URL} names its version unclearly ('${version}')."
	printf '%s' "${version}"
	return
}

bs_arch() {
	local machine
	machine=$(uname -m)
	case ${machine} in
	x86_64 | amd64) printf 'amd64' ;;
	aarch64 | arm64) printf 'arm64' ;;
	*) bs_die "lss runs on x86_64 and aarch64; this machine is ${machine}." ;;
	esac
	return
}

# bs_fetch_gh DIR: downloads the pinned GitHub CLI, checks its SHA-256 and prints the path of the gh binary.
bs_fetch_gh() {
	local dir=$1 arch name sum actual
	arch=$(bs_arch)
	name="gh_${BS_GH_VERSION}_linux_${arch}"
	if [[ ${arch} == arm64 ]]; then sum=${BS_GH_SHA256_ARM64}; else sum=${BS_GH_SHA256_AMD64}; fi
	bs_fetch "https://github.com/cli/cli/releases/download/v${BS_GH_VERSION}/${name}.tar.gz" "${dir}/gh.tar.gz"
	actual=$(sha256sum -- "${dir}/gh.tar.gz" | cut -d ' ' -f 1)
	[[ ${actual} == "${sum}" ]] ||
		bs_die "Checksum mismatch for the GitHub CLI ${BS_GH_VERSION}: expected ${sum}, got ${actual}."
	mkdir -p "${dir}/gh"
	tar -xzf "${dir}/gh.tar.gz" -C "${dir}/gh" --strip-components=2 "${name}/bin/gh"
	printf '%s' "${dir}/gh/gh"
	return
}

# bs_signer: the certificate identity a release must be signed with (the workflow file and the ref it ran on).
bs_signer() {
	[[ ${LSS_RELEASE_WORKFLOW} =~ ^[A-Za-z0-9._-]+\.ya?ml$ ]] ||
		bs_die "LSS_RELEASE_WORKFLOW '${LSS_RELEASE_WORKFLOW}' is a workflow file name like release.yml."
	[[ ${LSS_RELEASE_REF} =~ ^refs/(heads|tags|pull)/[A-Za-z0-9._/-]+$ && ${LSS_RELEASE_REF} != *..* ]] ||
		bs_die "LSS_RELEASE_REF '${LSS_RELEASE_REF}' is a git ref like refs/heads/main."
	printf 'https://github.com/%s/.github/workflows/%s@%s' "${BS_REPO}" "${LSS_RELEASE_WORKFLOW}" "${LSS_RELEASE_REF}"
	return
}

# bs_check_attestation GH FILE BUNDLE: the Sigstore bundle must hold a valid SLSA provenance attestation for the
# file, signed for the release workflow of this repository on a GitHub-hosted runner.
bs_check_attestation() {
	local gh=$1 file=$2 bundle=$3 dir output signer
	dir=$(dirname -- "${bundle}")
	signer=$(bs_signer)
	output=$(
		GH_CONFIG_DIR="${dir}/.gh" XDG_CACHE_HOME="${dir}/.cache" XDG_STATE_HOME="${dir}/.state" \
			XDG_DATA_HOME="${dir}/.data" GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1 NO_COLOR=1 \
			"${gh}" attestation verify "${file}" --bundle "${bundle}" --repo "${BS_REPO}" \
			--cert-identity "${signer}" --source-ref "${LSS_RELEASE_REF}" --deny-self-hosted-runners 2>&1 9>&-
	) || {
		printf '%s\n' "${output}" | tail -n 5 | sed 's/^/  gh: /' >&2
		bs_die "The attestation of ${file##*/} does not verify; it was not built by ${BS_REPO} (${LSS_RELEASE_WORKFLOW} on ${LSS_RELEASE_REF}). Nothing was installed."
	}
	return
}

# bs_download VERSION DIR: downloads and checks one release; prints the path of its verified archive.
bs_download() {
	local version=$1 dir=$2 base archive gh
	base="${LSS_RELEASE_URL}/download/v${version}"
	archive="${dir}/lss-${version}.tar.gz"
	bs_info "Downloading lss ${version}"
	bs_fetch "${base}/SHA256SUMS" "${dir}/SHA256SUMS"
	bs_fetch "${base}/lss-${version}.tar.gz" "${archive}"
	bs_fetch "${base}/lss-${version}.intoto.jsonl" "${dir}/lss-${version}.intoto.jsonl"
	bs_check_sum "${archive}" "${dir}/SHA256SUMS"
	gh=$(bs_fetch_gh "${dir}")
	bs_check_attestation "${gh}" "${dir}/SHA256SUMS" "${dir}/lss-${version}.intoto.jsonl"
	bs_check_attestation "${gh}" "${archive}" "${dir}/lss-${version}.intoto.jsonl"
	bs_ok "lss ${version}: checksum and build attestation verified"
	printf '%s' "${archive}"
	return
}

# --- installed versions -------------------------------------------------------------------------------------------

# bs_link_target LINK: the version a link in the prefix points to, or nothing.
bs_link_target() {
	local link="${LSS_PREFIX}/$1" target
	[[ -L ${link} ]] || return 0
	target=$(readlink -- "${link}")
	if bs_valid_version "${target}" && [[ -d ${LSS_PREFIX}/${target} ]]; then
		printf '%s' "${target}"
	fi
	return
}

# bs_set_link TARGET LINK: points LINK to TARGET in one rename, so the link is never missing.
bs_set_link() {
	local target=$1 link=$2 next
	next="$(dirname -- "${link}")/.${link##*/}.next"
	rm -f -- "${next}"
	ln -s -- "${target}" "${next}"
	mv -fT -- "${next}" "${link}"
	return
}

# bs_write_manifest DIR: SHA-256 of every file of an installed version, checked again before a rollback.
bs_write_manifest() {
	local dir=$1
	(
		cd -- "${dir}"
		find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >"../.manifest.$$"
	)
	mv -f -- "${dir}/../.manifest.$$" "${dir}/.lss-manifest"
	chmod 0644 "${dir}/.lss-manifest"
	return
}

bs_check_manifest() {
	local dir=$1
	[[ -f ${dir}/.lss-manifest ]] || bs_die "${dir} has lost its file list (.lss-manifest); install that version again."
	(cd -- "${dir}" && sha256sum --quiet --strict -c .lss-manifest >/dev/null 2>&1) ||
		bs_die "Files in ${dir} changed after it was installed; install that version again instead of switching to it."
	return
}

# bs_unpack ARCHIVE VERSION: unpacks a verified archive into LSS_PREFIX/VERSION, replacing an earlier copy.
bs_unpack() {
	local archive=$1 version=$2 stage tree old
	mkdir -p -- "${LSS_PREFIX}"
	chmod 0755 "${LSS_PREFIX}"
	stage=$(mktemp -d "${LSS_PREFIX}/.stage-${version}.XXXXXX")
	tar -xzf "${archive}" -C "${stage}" --no-same-owner --no-same-permissions
	tree="${stage}/lss-${version}"
	[[ -f ${tree}/lss && -f ${tree}/VERSION ]] || bs_die "The archive of ${version} holds no lss-${version}/ directory with lss in it."
	[[ $(<"${tree}/VERSION") == "${version}" ]] ||
		bs_die "The archive of ${version} contains version $(<"${tree}/VERSION"); refusing to install it under the wrong name."
	if [[ ${EUID} -eq 0 ]]; then
		chown -R 0:0 -- "${tree}"
	fi
	chmod -R u+rwX,go+rX,go-w -- "${tree}"
	chmod 0755 "${tree}/lss"
	bs_write_manifest "${tree}"
	if [[ -e ${LSS_PREFIX}/${version} ]]; then
		old=$(mktemp -d "${LSS_PREFIX}/.old-${version}.XXXXXX")
		mv -- "${LSS_PREFIX}/${version}" "${old}/"
		rm -rf -- "${old}"
	fi
	mv -T -- "${tree}" "${LSS_PREFIX}/${version}"
	rm -rf -- "${stage}"
	return
}

# bs_activate VERSION: makes an installed version the active one and keeps the one before as "previous". The new
# version must answer `lss version` with its own version, or the links go back to what they were.
bs_activate() {
	local version=$1 current previous answer
	current=$(bs_link_target current)
	previous=$(bs_link_target previous)
	if [[ -n ${current} && ${current} != "${version}" ]]; then
		bs_set_link "${current}" "${LSS_PREFIX}/previous"
	fi
	bs_set_link "${version}" "${LSS_PREFIX}/current"
	mkdir -p -- "$(dirname -- "${LSS_BIN_LINK}")"
	bs_set_link "${LSS_PREFIX}/current/lss" "${LSS_BIN_LINK}"
	answer=$("${LSS_PREFIX}/current/lss" version 2>&1) || true
	if [[ ${answer} != "lss ${version}" ]]; then
		if [[ -n ${current} ]]; then
			bs_set_link "${current}" "${LSS_PREFIX}/current"
		fi
		if [[ -n ${previous} ]]; then
			bs_set_link "${previous}" "${LSS_PREFIX}/previous"
		else
			rm -f -- "${LSS_PREFIX}/previous"
		fi
		bs_die "lss ${version} does not start ('${answer}'); ${current:-the earlier state} stays active."
	fi
	return
}

# bs_prune: deletes versions other than the active and the previous one, and leftovers of interrupted runs.
bs_prune() {
	local current previous dir name
	current=$(bs_link_target current)
	previous=$(bs_link_target previous)
	for dir in "${LSS_PREFIX}"/* "${LSS_PREFIX}"/.stage-* "${LSS_PREFIX}"/.old-*; do
		[[ -d ${dir} && ! -L ${dir} ]] || continue
		name=${dir##*/}
		case ${name} in
		.stage-* | .old-*) ;;
		*)
			bs_valid_version "${name}" || continue
			[[ ${name} != "${current}" && ${name} != "${previous}" ]] || continue
			bs_info "Removing lss ${name}"
			;;
		esac
		rm -rf -- "${dir}"
	done
	return
}

# --- commands -----------------------------------------------------------------------------------------------------

bs_require() {
	local tool
	local -a missing=()
	if [[ ${EUID} -ne 0 ]]; then
		bs_die "bootstrap.sh installs lss for the whole system and must run as root (sudo bash bootstrap.sh)."
	fi
	for tool in curl tar gzip sha256sum flock mktemp readlink awk sed find xargs; do
		command -v "${tool}" >/dev/null 2>&1 || missing+=("${tool}")
	done
	[[ ${#missing[@]} -eq 0 ]] ||
		bs_die "bootstrap.sh needs ${missing[*]}; install them with apt-get or dnf first."
	return
}

# bs_check_layout: an lss checkout in the prefix (the way 2.0 development versions were installed) must move first.
bs_check_layout() {
	if [[ -e ${LSS_PREFIX}/lss && ! -L ${LSS_PREFIX}/current ]]; then
		bs_die "${LSS_PREFIX} holds an lss checkout, where releases go now. Move it away (mv ${LSS_PREFIX} ${LSS_PREFIX}.checkout) and run this again; /etc/lss and /var/lib/lss stay as they are."
	fi
	return
}

bs_lock() {
	# `lss update` holds the lock already and runs this script with LSS_LOCK_HELD=1.
	[[ ${LSS_LOCK_HELD:-0} != 1 ]] || return 0
	exec 9>"${LSS_LOCK}"
	flock -w 5 9 || bs_die "Another lss run is in progress."
	return
}

bs_install() {
	local requested=$1 dir=$2 version current archive order
	current=$(bs_link_target current)
	if [[ -n ${requested} ]]; then
		version=${requested#v}
		bs_valid_version "${version}" || bs_die "'${requested}' is a version like 2.0.1."
	else
		version=$(bs_latest_version "${dir}")
		if [[ -n ${current} && $(bs_version_cmp "${version}" "${current}") == -1 ]]; then
			bs_ok "lss ${current} is newer than the latest release ${version} and stays active."
			return 0
		fi
	fi
	if [[ ${version} == "${current}" ]]; then
		bs_ok "lss ${version} is installed and active."
		return 0
	fi
	if [[ -n ${current} ]]; then
		order=$(bs_version_cmp "${version}" "${current}")
		if [[ ${order} == -1 ]]; then
			bs_warn "Going back from ${current} to the older ${version}; settings that only ${current} knows produce a warning."
		fi
	fi
	archive=$(bs_download "${version}" "${dir}")
	if [[ ${LSS_DRY_RUN} == 1 ]]; then
		bs_ok "Dry run: lss ${version} verified; nothing was changed."
		return 0
	fi
	bs_unpack "${archive}" "${version}"
	bs_activate "${version}"
	bs_prune
	if [[ -n ${current} ]]; then
		bs_ok "lss ${version} is active (was ${current}; 'lss update --rollback' goes back)."
		bs_info "Run 'lss verify' now, and 'lss configure MODULE...' to apply what the new version changes in a module."
	else
		bs_ok "lss ${version} is installed: ${LSS_PREFIX}/${version}, command ${LSS_BIN_LINK}."
		bs_info "Next: sudo lss install --profile minimal-secure (see 'lss --help')."
	fi
	return
}

bs_rollback() {
	local current previous
	current=$(bs_link_target current)
	previous=$(bs_link_target previous)
	[[ -n ${previous} ]] || bs_die "There is only one installed version of lss; rollback needs the one before it."
	bs_check_manifest "${LSS_PREFIX}/${previous}"
	if [[ ${LSS_DRY_RUN} == 1 ]]; then
		bs_ok "Dry run: lss ${previous} is intact; nothing was changed."
		return 0
	fi
	bs_activate "${previous}"
	bs_ok "lss ${previous} is active again (was ${current}; 'lss update ${current}' returns to it)."
	return
}

bs_usage() {
	cat <<EOF
Usage: sudo bash bootstrap.sh [--dry-run] [VERSION]
       sudo bash bootstrap.sh [--dry-run] --rollback

Installs lss VERSION (default: the latest release) from a release whose checksum and GitHub build attestation
verify, and makes it the active version: ${LSS_PREFIX}/VERSION, ${LSS_PREFIX}/current, ${LSS_BIN_LINK}.
--rollback switches back to the version that was active before.
EOF
	return
}

bs_main() {
	local version='' rollback=0 dir arg
	while [[ $# -gt 0 ]]; do
		arg=$1
		case ${arg} in
		--rollback) rollback=1 ;;
		--dry-run) LSS_DRY_RUN=1 ;;
		-h | --help)
			bs_usage
			return 0
			;;
		-*) bs_die "Unknown option '${arg}'. See 'bootstrap.sh --help'." ;;
		*)
			[[ -z ${version} ]] || bs_die "Name one version, not '${version}' and '${arg}'."
			version=${arg}
			;;
		esac
		shift
	done
	[[ ${rollback} == 0 || -z ${version} ]] || bs_die "--rollback goes back to the previous version; it takes a version of its own."
	umask 022
	bs_require
	bs_check_layout
	bs_lock
	if [[ ${rollback} == 1 ]]; then
		bs_rollback
		return 0
	fi
	dir=$(mktemp -d)
	# shellcheck disable=SC2064 # the directory is fixed now
	trap "rm -rf -- '${dir}'" EXIT
	bs_install "${version}" "${dir}"
	return
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	bs_main "$@"
fi
