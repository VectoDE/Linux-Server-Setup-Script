#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Integration test of bootstrap.sh and `lss update`: tests/integration/update.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B
#
# RELEASE_DIR holds two test releases built by scripts/release/build.sh and attested by the CI workflow, in the
# layout of GitHub releases (download/vVERSION/..., latest/download/SHA256SUMS). LSS_RELEASE_WORKFLOW and
# LSS_RELEASE_REF name the workflow run that signed them. In a systemd container: install A with bootstrap.sh, update
# to the latest (B), roll back, update and downgrade by version, and refuse a release whose attestation does not
# match, one whose checksum does not match, one signed by another workflow and a rollback to a changed version.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

SYSTEM=${1:?usage: update.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B}
source_dir=${2:?usage: update.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B}
A=${3:?usage: update.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B}
B=${4:?usage: update.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B}
: "${LSS_RELEASE_WORKFLOW:?the workflow file that signed the test releases}" "${LSS_RELEASE_REF:?its git ref}"
export LSS_RELEASE_WORKFLOW LSS_RELEASE_REF
RELEASE_DIR=$(mktemp -d)
# shellcheck source=tests/integration/target.sh
source tests/integration/target.sh

# Two broken copies of B: C has a changed archive with a matching SHA256SUMS (its attestation cannot match), D a
# SHA256SUMS that lists another checksum for an archive that is otherwise genuine.
C=${B}.tampered
D=${B}.badsum
cp -R "${source_dir}/." "${RELEASE_DIR}/"
chmod -R a+rX "${RELEASE_DIR}"
for version in "${C}" "${D}"; do
	dir="${RELEASE_DIR}/download/v${version}"
	mkdir -p "${dir}"
	cp "${RELEASE_DIR}/download/v${B}/lss-${B}.tar.gz" "${dir}/lss-${version}.tar.gz"
	cp "${RELEASE_DIR}/download/v${B}/lss-${B}.intoto.jsonl" "${dir}/lss-${version}.intoto.jsonl"
done
printf '\0' >>"${RELEASE_DIR}/download/v${C}/lss-${C}.tar.gz"
(cd "${RELEASE_DIR}/download/v${C}" && sha256sum "lss-${C}.tar.gz" >SHA256SUMS)
printf '%064d  lss-%s.tar.gz\n' 0 "${D}" >"${RELEASE_DIR}/download/v${D}/SHA256SUMS"

# expect_active VERSION [PREVIOUS]: the links and the command point where they should, and lss answers.
expect_active() {
	local version=$1 previous=${2:-}
	in_target "set -e
		[[ \$(readlink /opt/lss/current) == '${version}' ]] || { echo \"current is \$(readlink /opt/lss/current), expected ${version}\"; exit 1; }
		[[ -z '${previous}' || \$(readlink /opt/lss/previous) == '${previous}' ]] || { echo \"previous is \$(readlink /opt/lss/previous)\"; exit 1; }
		[[ \$(readlink /usr/local/sbin/lss) == /opt/lss/current/lss ]]
		[[ \$(lss version) == 'lss ${version}' ]]
		[[ -z \$(find /opt/lss/${version} -perm /022 ! -type l) && \$(stat -c %U /opt/lss/${version}/lss) == root ]] || { echo 'writable or foreign files'; exit 1; }
		ls /opt/lss"
	return
}

# expect_refused COMMAND MESSAGE: the command fails with the message, and nothing changed.
expect_refused() {
	local command=$1 message=$2 output
	if output=$(in_target "${command}" 2>&1); then
		printf '%s\n' "${output}"
		echo "'${command}' should have been refused." >&2
		exit 1
	fi
	printf '%s\n' "${output}"
	grep -qF -- "${message}" <<<"${output}" || {
		echo "'${command}' failed without '${message}'." >&2
		exit 1
	}
	return
}

# target_stop reads the exit status of the test, so the cleanup before it passes the status on.
trap 'status=$?; rm -rf -- "${RELEASE_DIR}"; target_stop "${status}"' EXIT
target_start

group_start "${SYSTEM}: bootstrap.sh installs ${A}"
in_target "bash /srv/release/download/v${A}/bootstrap.sh ${A}"
expect_active "${A}"
in_target "bash /srv/release/download/v${A}/bootstrap.sh ${A} 2>&1 | tee /dev/stderr | grep -q 'is installed and active'"
group_end

group_start "${SYSTEM}: lss update to the latest release"
in_target 'lss --yes --dry-run update'
expect_active "${A}"
in_target 'lss --yes update'
expect_active "${B}" "${A}"
in_target 'lss --no-color list >/dev/null && lss --yes --no-color verify && lss --yes --dry-run install tools'
group_end

group_start "${SYSTEM}: rollback, update and downgrade by version"
in_target 'lss --yes update --rollback'
expect_active "${A}" "${B}"
in_target "lss --yes update ${B}"
expect_active "${B}" "${A}"
in_target "lss --yes update ${A}"
expect_active "${A}" "${B}"
group_end

group_start "${SYSTEM}: refused releases"
expect_refused "lss --yes update ${C}" 'does not verify'
expect_refused "lss --yes update ${D}" 'Checksum mismatch'
expect_refused "LSS_RELEASE_WORKFLOW=release.yml lss --yes update ${B}" 'does not verify'
expect_active "${A}" "${B}"
in_target "[[ ! -e /opt/lss/${C} && ! -e /opt/lss/${D} ]]"
in_target "echo '# changed' >>/opt/lss/${B}/lss"
expect_refused 'lss --yes update --rollback' 'changed after it was installed'
expect_active "${A}" "${B}"
group_end

group_start "${SYSTEM}: a fresh copy replaces a changed version"
in_target 'lss --yes update'
expect_active "${B}" "${A}"
group_end
echo "${SYSTEM}: bootstrap and update passed"
