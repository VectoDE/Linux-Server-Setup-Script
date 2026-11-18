#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# bootstrap.sh: versions, checksums, attestation arguments, the installed layout, update, rollback and pruning. The
# releases here are small fake archives in a file:// release directory; downloading the GitHub CLI is replaced by a
# stub that accepts or refuses every attestation and records its arguments.

setup() {
	bats_require_minimum_version 1.5.0
	REPO_ROOT=$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)
	export LSS_JOURNAL=0
	export LSS_PREFIX=${BATS_TEST_TMPDIR}/opt/lss
	export LSS_BIN_LINK=${BATS_TEST_TMPDIR}/sbin/lss
	export LSS_LOCK=${BATS_TEST_TMPDIR}/lss.lock
	RELEASES=${BATS_TEST_TMPDIR}/releases
	export LSS_RELEASE_URL=file://${RELEASES}
	export GH_LOG=${BATS_TEST_TMPDIR}/gh.log
	export GH_EXIT=0
	WORK=${BATS_TEST_TMPDIR}/work
	mkdir -p "${WORK}" "${RELEASES}"
	# shellcheck source=bootstrap.sh
	source "${REPO_ROOT}/bootstrap.sh"
	# bootstrap.sh turns on nounset for itself; bats needs it off.
	set +u
	# The pinned GitHub CLI is replaced by a stub; bs_fetch reads file:// URLs without curl.
	# shellcheck disable=SC2329 # called by bs_download
	bs_fetch_gh() {
		mkdir -p "$1/gh"
		printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >>"${GH_LOG}"\nexit "${GH_EXIT}"\n' >"$1/gh/gh"
		chmod +x "$1/gh/gh"
		printf '%s' "$1/gh/gh"
		return
	}
	# shellcheck disable=SC2329 # called by bs_download and bs_latest_version
	bs_fetch() {
		[[ $1 == file://* ]] || bs_die "Refusing $1: releases are downloaded over HTTPS."
		cp -- "${1#file://}" "$2" 2>/dev/null || bs_die "Download failed: $1"
		return
	}
	return
}

# make_release VERSION [ANSWER]: a release directory with an archive whose lss answers "lss VERSION" (or ANSWER).
make_release() {
	local version=$1 answer=${2:-lss $1} tree dir
	tree=${BATS_TEST_TMPDIR}/build/lss-${version}
	dir=${RELEASES}/download/v${version}
	mkdir -p "${tree}" "${dir}"
	printf '#!/usr/bin/env bash\necho "%s"\n' "${answer}" >"${tree}/lss"
	printf '#!/usr/bin/env bash\n' >"${tree}/bootstrap.sh"
	printf '%s\n' "${version}" >"${tree}/VERSION"
	tar -czf "${dir}/lss-${version}.tar.gz" -C "${BATS_TEST_TMPDIR}/build" "lss-${version}"
	(cd "${dir}" && sha256sum "lss-${version}.tar.gz" >SHA256SUMS)
	printf '{}\n' >"${dir}/lss-${version}.intoto.jsonl"
	mkdir -p "${RELEASES}/latest/download"
	cp "${dir}/SHA256SUMS" "${RELEASES}/latest/download/SHA256SUMS"
	return
}

active() {
	readlink "${LSS_PREFIX}/current"
	return
}

# --- versions -----------------------------------------------------------------------------------------------------

@test "versions are compared by SemVer precedence" {
	local pair
	for pair in "2.0.1 2.0.0 1" "2.0.0 2.0.1 -1" "2.10.0 2.9.9 1" "2.0.0 2.0.0 0" "2.0.0 2.0.0-rc.1 1" \
		"2.0.0-rc.1 2.0.0 -1" "2.0.0-rc.2 2.0.0-rc.10 -1" "2.0.0-rc.1 2.0.0-beta 1" "2.0.0-alpha 2.0.0-alpha.1 -1" \
		"2.0.0-1 2.0.0-alpha -1" "2.0.0-ci.2 2.0.0-ci.1 1" "3.0.0 10.0.0 -1"; do
		read -r a b expected <<<"${pair}"
		[ "$(bs_version_cmp "${a}" "${b}")" = "${expected}" ] || {
			echo "${a} vs ${b}: $(bs_version_cmp "${a}" "${b}"), expected ${expected}"
			return 1
		}
	done
}

@test "only release versions are accepted" {
	bs_valid_version 2.0.1
	bs_valid_version 2.0.0-rc.1
	run ! bs_valid_version v2.0.1
	run ! bs_valid_version 2.0
	run ! bs_valid_version '2.0.1; rm -rf /'
	run ! bs_valid_version ../2.0.1
}

# --- checks -------------------------------------------------------------------------------------------------------

@test "the checksum of the archive must match SHA256SUMS" {
	printf 'release\n' >"${WORK}/lss-1.0.0.tar.gz"
	(cd "${WORK}" && sha256sum lss-1.0.0.tar.gz >SHA256SUMS)
	bs_check_sum "${WORK}/lss-1.0.0.tar.gz" "${WORK}/SHA256SUMS"
	printf 'changed\n' >"${WORK}/lss-1.0.0.tar.gz"
	run bs_check_sum "${WORK}/lss-1.0.0.tar.gz" "${WORK}/SHA256SUMS"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Checksum mismatch for lss-1.0.0.tar.gz"* ]]
	printf '%064d *other.tar.gz\n' 0 >"${WORK}/SHA256SUMS"
	run bs_check_sum "${WORK}/lss-1.0.0.tar.gz" "${WORK}/SHA256SUMS"
	[[ ${output} == *"lists lss-1.0.0.tar.gz without a SHA-256"* ]]
}

@test "downloads use HTTPS or a local release directory" {
	source "${REPO_ROOT}/bootstrap.sh"
	run bs_fetch http://example.com/lss.tar.gz "${WORK}/x"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Refusing http://example.com/lss.tar.gz"* ]]
	run bs_fetch ftp://example.com/lss.tar.gz "${WORK}/x"
	[ "${status}" -eq 1 ]
}

@test "the GitHub CLI is used only with its pinned checksum" {
	source "${REPO_ROOT}/bootstrap.sh"
	bs_fetch() {
		printf 'not the GitHub CLI' >"$2"
		return
	}
	run bs_fetch_gh "${WORK}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Checksum mismatch for the GitHub CLI ${BS_GH_VERSION}"* ]]
	[[ ${BS_GH_SHA256_AMD64} =~ ^[0-9a-f]{64}$ && ${BS_GH_SHA256_ARM64} =~ ^[0-9a-f]{64}$ ]]
}

@test "releases must be signed by the release workflow on main" {
	[ "$(bs_signer)" = "https://github.com/VectoDE/Linux-Server-Setup-Script/.github/workflows/release.yml@refs/heads/main" ]
	LSS_RELEASE_WORKFLOW=distribution.yml LSS_RELEASE_REF=refs/pull/12/merge
	[ "$(bs_signer)" = "https://github.com/VectoDE/Linux-Server-Setup-Script/.github/workflows/distribution.yml@refs/pull/12/merge" ]
	LSS_RELEASE_WORKFLOW='../other/repo/x.yml' run bs_signer
	[ "${status}" -eq 1 ]
	LSS_RELEASE_REF='refs/heads/../x' run bs_signer
	[ "${status}" -eq 1 ]
}

@test "the attestation is checked for the repository, workflow, ref and hosted runners" {
	make_release 1.0.0
	bs_download 1.0.0 "${WORK}" >/dev/null
	[ "$(grep -c . "${GH_LOG}")" -eq 2 ]
	grep -q "attestation verify ${WORK}/SHA256SUMS --bundle ${WORK}/lss-1.0.0.intoto.jsonl" "${GH_LOG}"
	grep -q "attestation verify ${WORK}/lss-1.0.0.tar.gz --bundle" "${GH_LOG}"
	grep -q -- "--repo VectoDE/Linux-Server-Setup-Script --cert-identity https://github.com/VectoDE/Linux-Server-Setup-Script/.github/workflows/release.yml@refs/heads/main --source-ref refs/heads/main --deny-self-hosted-runners" "${GH_LOG}"
}

# --- install, update, rollback -----------------------------------------------------------------------------------

@test "the latest release is installed with links, a file list and no writable files" {
	make_release 1.0.0
	run bs_install '' "${WORK}"
	[ "${status}" -eq 0 ]
	[[ ${output} == *"lss 1.0.0: checksum and build attestation verified"* ]]
	[[ ${output} == *"lss 1.0.0 is installed"* ]]
	[ "$(active)" = 1.0.0 ]
	[ ! -e "${LSS_PREFIX}/previous" ]
	[ "$(readlink "${LSS_BIN_LINK}")" = "${LSS_PREFIX}/current/lss" ]
	[ "$("${LSS_BIN_LINK}" version)" = "lss 1.0.0" ]
	grep -q ' ./lss$' "${LSS_PREFIX}/1.0.0/.lss-manifest"
	[ -z "$(find "${LSS_PREFIX}/1.0.0" -perm /022 ! -type l)" ]
	[ -z "$(find "${LSS_PREFIX}" -maxdepth 1 -name '.stage-*')" ]
}

@test "the active version is not downloaded again" {
	make_release 1.0.0
	bs_install 1.0.0 "${WORK}"
	: >"${GH_LOG}"
	run bs_install v1.0.0 "${WORK}"
	[[ ${output} == *"lss 1.0.0 is installed and active."* ]]
	[ ! -s "${GH_LOG}" ]
}

@test "an update keeps the version before it, a third version removes the oldest" {
	make_release 1.0.0
	bs_install '' "${WORK}"
	make_release 1.1.0
	run bs_install '' "${WORK}"
	[[ ${output} == *"lss 1.1.0 is active (was 1.0.0"* ]]
	[ "$(active)" = 1.1.0 ]
	[ "$(readlink "${LSS_PREFIX}/previous")" = 1.0.0 ]
	make_release 1.2.0
	bs_install 1.2.0 "${WORK}"
	[ "$(active)" = 1.2.0 ]
	[ "$(readlink "${LSS_PREFIX}/previous")" = 1.1.0 ]
	[ ! -e "${LSS_PREFIX}/1.0.0" ]
}

@test "other directories in the prefix survive the pruning" {
	mkdir -p "${LSS_PREFIX}/pgadmin" "${LSS_PREFIX}/.stage-0.9.0.abc"
	make_release 1.0.0
	bs_install '' "${WORK}"
	[ -d "${LSS_PREFIX}/pgadmin" ]
	[ ! -e "${LSS_PREFIX}/.stage-0.9.0.abc" ]
}

@test "lss update without a version never goes back" {
	make_release 1.0.0
	make_release 1.1.0
	bs_install 1.1.0 "${WORK}"
	cp "${RELEASES}/download/v1.0.0/SHA256SUMS" "${RELEASES}/latest/download/SHA256SUMS"
	run bs_install '' "${WORK}"
	[[ ${output} == *"lss 1.1.0 is newer than the latest release 1.0.0 and stays active."* ]]
	[ "$(active)" = 1.1.0 ]
}

@test "a named older version is a downgrade with a warning" {
	make_release 1.0.0
	make_release 1.1.0
	bs_install 1.1.0 "${WORK}"
	run bs_install 1.0.0 "${WORK}"
	[ "${status}" -eq 0 ]
	[[ ${output} == *"Going back from 1.1.0 to the older 1.0.0"* ]]
	[ "$(active)" = 1.0.0 ]
	[ "$(readlink "${LSS_PREFIX}/previous")" = 1.1.0 ]
}

@test "rollback switches to the previous version and back" {
	make_release 1.0.0
	make_release 1.1.0
	bs_install 1.0.0 "${WORK}"
	bs_install 1.1.0 "${WORK}"
	run bs_rollback
	[ "${status}" -eq 0 ]
	[[ ${output} == *"lss 1.0.0 is active again (was 1.1.0"* ]]
	[ "$(active)" = 1.0.0 ]
	[ "$(readlink "${LSS_PREFIX}/previous")" = 1.1.0 ]
	bs_rollback
	[ "$(active)" = 1.1.0 ]
}

@test "rollback refuses a version whose files changed, and needs a version to go back to" {
	make_release 1.0.0
	bs_install 1.0.0 "${WORK}"
	run bs_rollback
	[ "${status}" -eq 1 ]
	[[ ${output} == *"rollback needs the one before it"* ]]
	make_release 1.1.0
	bs_install 1.1.0 "${WORK}"
	printf 'echo changed\n' >>"${LSS_PREFIX}/1.0.0/lss"
	run bs_rollback
	[ "${status}" -eq 1 ]
	[[ ${output} == *"changed after it was installed"* ]]
	[ "$(active)" = 1.1.0 ]
}

@test "a release whose attestation does not verify installs nothing" {
	make_release 1.0.0
	GH_EXIT=1 run bs_install '' "${WORK}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"The attestation of SHA256SUMS does not verify"* ]]
	[[ ${output} == *"Nothing was installed."* ]]
	[ ! -e "${LSS_PREFIX}/1.0.0" ]
	[ ! -e "${LSS_PREFIX}/current" ]
}

@test "a changed archive is refused before its attestation is checked" {
	make_release 1.0.0
	printf '\0' >>"${RELEASES}/download/v1.0.0/lss-1.0.0.tar.gz"
	run bs_install 1.0.0 "${WORK}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"Checksum mismatch for lss-1.0.0.tar.gz"* ]]
	[ ! -s "${GH_LOG}" ]
	[ ! -e "${LSS_PREFIX}/1.0.0" ]
}

@test "an archive with another version inside is refused" {
	make_release 1.0.0
	mv "${RELEASES}/download/v1.0.0" "${RELEASES}/download/v1.0.1"
	mv "${RELEASES}/download/v1.0.1/lss-1.0.0.tar.gz" "${RELEASES}/download/v1.0.1/lss-1.0.1.tar.gz"
	(cd "${RELEASES}/download/v1.0.1" && sha256sum lss-1.0.1.tar.gz >SHA256SUMS)
	cp "${RELEASES}/download/v1.0.1/lss-1.0.0.intoto.jsonl" "${RELEASES}/download/v1.0.1/lss-1.0.1.intoto.jsonl"
	run bs_install 1.0.1 "${WORK}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"holds no lss-1.0.1/ directory"* ]]
	[ ! -e "${LSS_PREFIX}/1.0.1" ]
}

@test "a version that does not start leaves the active one in place" {
	make_release 1.0.0
	bs_install 1.0.0 "${WORK}"
	make_release 1.1.0 'broken'
	run bs_install 1.1.0 "${WORK}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"lss 1.1.0 does not start ('broken'); 1.0.0 stays active."* ]]
	[ "$(active)" = 1.0.0 ]
	[ ! -e "${LSS_PREFIX}/previous" ]
}

@test "a dry run verifies and changes nothing" {
	make_release 1.0.0
	LSS_DRY_RUN=1 run bs_install '' "${WORK}"
	[ "${status}" -eq 0 ]
	[[ ${output} == *"Dry run: lss 1.0.0 verified; nothing was changed."* ]]
	[ ! -e "${LSS_PREFIX}/1.0.0" ]
}

@test "the latest version comes from the file list of the latest release" {
	printf '%064d  lss-2.3.4.tar.gz\n%064d  vectode-lss-2.3.4.tar.gz\n%064d  bootstrap.sh\n' 1 2 3 \
		>"${BATS_TEST_TMPDIR}/sums"
	mkdir -p "${RELEASES}/latest/download"
	cp "${BATS_TEST_TMPDIR}/sums" "${RELEASES}/latest/download/SHA256SUMS"
	[ "$(bs_latest_version "${WORK}")" = 2.3.4 ]
	printf '%064d  other.tar.gz\n' 1 >"${RELEASES}/latest/download/SHA256SUMS"
	run bs_latest_version "${WORK}"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"names its version unclearly"* ]]
}

@test "an lss checkout in the prefix must move first" {
	mkdir -p "${LSS_PREFIX}"
	: >"${LSS_PREFIX}/lss"
	run bs_check_layout
	[ "${status}" -eq 1 ]
	[[ ${output} == *"holds an lss checkout"* ]]
	rm "${LSS_PREFIX}/lss"
	bs_check_layout
}

@test "arguments: one version, or --rollback alone" {
	run bs_main 1.0.0 1.1.0
	[[ ${output} == *"Name one version, not '1.0.0' and '1.1.0'."* ]]
	run bs_main --rollback 1.0.0
	[[ ${output} == *"--rollback goes back to the previous version"* ]]
	run bs_main --bogus
	[[ ${output} == *"Unknown option '--bogus'"* ]]
	run bs_main --help
	[ "${status}" -eq 0 ]
	[[ ${output} == *"Usage: sudo bash bootstrap.sh"* ]]
	run bs_install 'latest' "${WORK}"
	[[ ${output} == *"'latest' is a version like 2.0.1."* ]]
}

@test "a second run gives up after a short wait: the lock is taken once" {
	bs_lock
	(
		exec 9>&-
		LSS_LOCK_HELD=0 run bs_lock
		[ "${status}" -eq 1 ]
		[[ ${output} == *"Another lss run is in progress."* ]]
	)
	LSS_LOCK_HELD=1 bs_lock
}

@test "bootstrap.sh output and errors never start with Not or No" {
	run ! grep -nE 'bs_(info|ok|warn|die|log [A-Z]+) "(Not|No)[ t]' "${REPO_ROOT}/bootstrap.sh"
}
