#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The release scripts: scripts/release/prepare.sh in a scratch repository, scripts/release/build.sh with a stub
# ansible-galaxy, and the version that VERSION, the collection and the role must share.

setup() {
	bats_require_minimum_version 1.5.0
	REPO_ROOT=$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)
	BIN=${BATS_TEST_TMPDIR}/bin
	mkdir -p "${BIN}"
	# Pull request labels come from the GitHub API; the stub answers with $LABELS for every commit.
	printf '#!/usr/bin/env bash\n[[ -n ${LABELS:-} ]] || exit 1\nprintf "%%s\\n" ${LABELS}\n' >"${BIN}/gh"
	chmod +x "${BIN}/gh"
	export PATH="${BIN}:${PATH}" LABELS=''
	return
}

# scratch_repo VERSION: a repository with the files prepare.sh changes, one tagged release and one commit after it.
scratch_repo() {
	command -v git >/dev/null || skip 'git is missing'
	REPO=${BATS_TEST_TMPDIR}/repo
	cd "${BATS_TEST_TMPDIR}" || return 1
	rm -rf -- "${REPO}"
	mkdir -p "${REPO}/scripts/release" "${REPO}/ansible/roles/lss/defaults"
	cp "${REPO_ROOT}/scripts/release/prepare.sh" "${REPO}/scripts/release/"
	cd "${REPO}" || return 1
	git init -q
	git config user.email test@example.com
	git config user.name test
	git config commit.gpgsign false
	git config tag.gpgsign false
	printf '%s\n' "$1" >VERSION
	printf 'version: "%s"\n' "$1" >ansible/galaxy.yml
	printf 'lss_version: "%s"\n' "$1" >ansible/roles/lss/defaults/main.yml
	printf '# Changelog\n\n## Unreleased\n\n## [1.0.0] - 2025-01-01\n\n- First.\n\n[1.0.0]: https://example.com/1.0.0\n' >CHANGELOG.md
	git add -A
	git commit -qm 'Release 1.0.0'
	git tag v1.0.0
	return
}

commit() {
	git commit -q --allow-empty -m "$1" ${2:+-m "$2"}
	return
}

prepare() {
	RELEASE_NOTES=${BATS_TEST_TMPDIR}/notes.md GITHUB_OUTPUT=${BATS_TEST_TMPDIR}/output bash scripts/release/prepare.sh
	return
}

@test "a fix makes a patch release, with the commit subjects as notes" {
	scratch_repo 1.0.0
	commit 'fix(ssh): keep the port'
	prepare
	[ "$(cat VERSION)" = 1.0.1 ]
	grep -qx 'version: "1.0.1"' ansible/galaxy.yml
	grep -qx 'lss_version: "1.0.1"' ansible/roles/lss/defaults/main.yml
	grep -qx 'release=true' "${BATS_TEST_TMPDIR}/output"
	grep -qx 'tag=v1.0.1' "${BATS_TEST_TMPDIR}/output"
	grep -qx -- '- fix(ssh): keep the port' "${BATS_TEST_TMPDIR}/notes.md"
	grep -q '^## \[1.0.1\] - ' CHANGELOG.md
	grep -qx '\[1.0.1\]: https://github.com/VectoDE/Linux-Server-Setup-Script/compare/v1.0.0...v1.0.1' CHANGELOG.md
	[ "$(grep -c '^## Unreleased$' CHANGELOG.md)" -eq 1 ]
}

@test "features and labels raise the version step" {
	scratch_repo 1.0.0
	commit 'feat: new module'
	prepare
	[ "$(cat VERSION)" = 1.1.0 ]
	scratch_repo 1.0.0
	commit 'something'
	LABELS='enhancement' prepare
	[ "$(cat VERSION)" = 1.1.0 ]
	scratch_repo 1.0.0
	commit 'fix!: rename a setting'
	prepare
	[ "$(cat VERSION)" = 2.0.0 ]
	scratch_repo 1.0.0
	commit 'refactor' 'BREAKING CHANGE: the old name is gone'
	prepare
	[ "$(cat VERSION)" = 2.0.0 ]
	scratch_repo 1.0.0
	commit 'something'
	LABELS='documentation breaking-change' prepare
	[ "$(cat VERSION)" = 2.0.0 ]
}

@test "a pre-release VERSION is released as its version, with the written notes" {
	scratch_repo 2.0.0-dev
	sed -i 's/^## Unreleased$/## Unreleased\n\nVersion 2.0.0 is new.\n\n### Added\n\n- lss/' CHANGELOG.md
	commit 'feat!: everything new'
	prepare
	[ "$(cat VERSION)" = 2.0.0 ]
	[ "$(head -n 1 "${BATS_TEST_TMPDIR}/notes.md")" = 'Version 2.0.0 is new.' ]
	grep -qx -- '- lss' "${BATS_TEST_TMPDIR}/notes.md"
	# The written notes moved under the release; Unreleased is empty again.
	[ "$(sed -n '/^## Unreleased$/,/^## \[2.0.0\]/p' CHANGELOG.md | grep -c .)" -eq 2 ]
}

@test "the requested step wins, [skip release] commits are left out" {
	scratch_repo 1.0.0
	commit 'fix: small'
	RELEASE_BUMP=major prepare
	[ "$(cat VERSION)" = 2.0.0 ]
	scratch_repo 1.0.0
	commit 'Release 1.0.1' '[skip release]'
	run prepare
	[[ ${output} == *"Since v1.0.0 there is nothing to release."* ]]
	grep -qx 'release=false' "${BATS_TEST_TMPDIR}/output"
	[ "$(cat VERSION)" = 1.0.0 ]
	RELEASE_BUMP=huge run prepare
	[ "${status}" -eq 2 ]
}

@test "a pre-release for a test of the release leaves the changelog alone" {
	scratch_repo 2.0.0-dev
	commit 'feat: new'
	cp CHANGELOG.md "${BATS_TEST_TMPDIR}/before"
	RELEASE_PRERELEASE=rc.1 prepare
	[ "$(cat VERSION)" = 2.0.0-rc.1 ]
	grep -qx 'tag=v2.0.0-rc.1' "${BATS_TEST_TMPDIR}/output"
	cmp CHANGELOG.md "${BATS_TEST_TMPDIR}/before"
	git commit -qam 'Release v2.0.0-rc.1' -m '[skip release]'
	git tag v2.0.0-rc.1
	commit 'fix: after the candidate'
	prepare
	[ "$(cat VERSION)" = 2.0.0 ]
	grep -qx '\[2.0.0\]: https://github.com/VectoDE/Linux-Server-Setup-Script/compare/v2.0.0-rc.1...v2.0.0' CHANGELOG.md
	RELEASE_PRERELEASE='rc 1' run prepare
	[ "${status}" -eq 2 ]
}

@test "VERSION, the collection and the role default name the same version" {
	local version
	version=$(<"${REPO_ROOT}/VERSION")
	grep -qx "version: \"${version}\"" "${REPO_ROOT}/ansible/galaxy.yml"
	grep -qx "lss_version: \"${version}\"" "${REPO_ROOT}/ansible/roles/lss/defaults/main.yml"
}

@test "build.sh builds the archive, bootstrap.sh, the collection, the SBOM and SHA256SUMS" {
	command -v jq >/dev/null || skip "jq is missing"
	# ansible-galaxy stub: checks what the collection gets and packs it under the expected name.
	cat >"${BIN}/ansible-galaxy" <<'EOF'
#!/usr/bin/env bash
dir=$3 out=$5
grep -qx 'version: "9.9.9-test"' "${dir}/galaxy.yml" || exit 3
grep -qx 'lss_version: "9.9.9-test"' "${dir}/roles/lss/defaults/main.yml" || exit 4
cmp -s "${dir}/roles/lss/files/bootstrap.sh" "${REPO_ROOT}/bootstrap.sh" || exit 5
tar -czf "${out}/vectode-lss-9.9.9-test.tar.gz" -C "${dir}" .
EOF
	chmod +x "${BIN}/ansible-galaxy"
	export REPO_ROOT
	local out=${BATS_TEST_TMPDIR}/dist
	run bash "${REPO_ROOT}/scripts/release/build.sh" --version 9.9.9-test "${out}"
	[ "${status}" -eq 0 ]
	(cd "${out}" && sha256sum --strict -c SHA256SUMS)
	[ "$(awk '{ print $2 }' "${out}/SHA256SUMS" | tr '\n' ' ')" = 'lss-9.9.9-test.tar.gz bootstrap.sh vectode-lss-9.9.9-test.tar.gz lss-9.9.9-test.cdx.json ' ]
	[ "$(tar -xzOf "${out}/lss-9.9.9-test.tar.gz" lss-9.9.9-test/VERSION)" = 9.9.9-test ]
	tar -tzf "${out}/lss-9.9.9-test.tar.gz" | grep -qx 'lss-9.9.9-test/lss'
	tar -tzf "${out}/lss-9.9.9-test.tar.gz" | grep -qx 'lss-9.9.9-test/bootstrap.sh'
	tar -tzf "${out}/lss-9.9.9-test.tar.gz" >"${BATS_TEST_TMPDIR}/files"
	run ! grep -qE '^lss-9.9.9-test/(tests|\.github|ansible)/' "${BATS_TEST_TMPDIR}/files"
	jq -e '.bomFormat == "CycloneDX" and .metadata.component.version == "9.9.9-test"' "${out}/lss-9.9.9-test.cdx.json"
	jq -e '[.components[] | select(.name == "gh")] | length == 2' "${out}/lss-9.9.9-test.cdx.json"
	jq -e '[.components[] | select(.type == "file")] | length > 10' "${out}/lss-9.9.9-test.cdx.json"
	jq -e '[.components[].hashes[].content | test("^[0-9a-f]{64}$")] | all' "${out}/lss-9.9.9-test.cdx.json"
	# The same commit gives the same archive.
	sum=$(sha256sum "${out}/lss-9.9.9-test.tar.gz" | cut -d ' ' -f 1)
	bash "${REPO_ROOT}/scripts/release/build.sh" --version 9.9.9-test "${out}" >/dev/null
	[ "$(sha256sum "${out}/lss-9.9.9-test.tar.gz" | cut -d ' ' -f 1)" = "${sum}" ]
}
