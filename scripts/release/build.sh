#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Builds the files of a release: scripts/release/build.sh [--version VERSION] OUT_DIR
#
#   lss-V.tar.gz           lss itself (the committed tree of HEAD without tests and CI files), unpacked to /opt/lss/V
#   bootstrap.sh           the installer, which verifies a release before it installs it
#   vectode-lss-V.tar.gz   the Ansible collection vectode.lss, installing exactly this version
#   lss-V.cdx.json         CycloneDX SBOM: lss and everything it downloads onto a server by a fixed checksum
#   SHA256SUMS             SHA-256 of the four files above
#
# The release workflow attests all five files. --version builds a test release under another version (the CI tests
# install one version and update to the next); a real release uses VERSION, which must match ansible/galaxy.yml.
# Archive order, owners and times come from the commit, so the same commit gives the same lss archive.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

REPOSITORY=VectoDE/Linux-Server-Setup-Script
VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

usage() {
	echo "usage: scripts/release/build.sh [--version VERSION] OUT_DIR" >&2
	exit 2
}

version=$(<VERSION)
release=1
if [[ ${1:-} == --version ]]; then
	[[ $# -ge 2 ]] || usage
	version=$2
	release=0
	shift 2
fi
[[ $# -eq 1 ]] || usage
out=$1
[[ ${version} =~ ${VERSION_RE} ]] || {
	echo "'${version}' is a version like 2.0.1." >&2
	exit 2
}
command -v ansible-galaxy >/dev/null 2>&1 || {
	echo "ansible-galaxy (ansible-core) builds the collection; install tests/ansible/requirements.txt first." >&2
	exit 1
}
mkdir -p "${out}"
out=$(cd "${out}" && pwd)
stage=$(mktemp -d)
# shellcheck disable=SC2064 # the directory is fixed now
trap "rm -rf -- '${stage}'" EXIT
commit_time=$(git log -1 --format=%ct HEAD)

# yaml_value FILE KEY: a top-level "key: value" of a YAML file, without quotes.
yaml_value() {
	sed -nE "s/^$2: *\"?([^\"]*)\"? *$/\1/p" "$1"
	return
}

# set_yaml_value FILE KEY VALUE
set_yaml_value() {
	sed -i -E "s/^$2: .*/$2: \"$3\"/" "$1"
	return
}

check_versions() {
	local galaxy role
	galaxy=$(yaml_value ansible/galaxy.yml version)
	role=$(yaml_value ansible/roles/lss/defaults/main.yml lss_version)
	if [[ ${galaxy} != "${version}" || ${role} != "${version}" ]]; then
		echo "VERSION is ${version}, but ansible/galaxy.yml has ${galaxy} and the role default ${role}." >&2
		exit 1
	fi
	return
}

build_archive() {
	local tree="${stage}/lss-${version}"
	git archive --format=tar --prefix="lss-${version}/" HEAD | tar -x -C "${stage}"
	printf '%s\n' "${version}" >"${tree}/VERSION"
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${commit_time}" \
		--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
		-C "${stage}" -cf - "lss-${version}" | gzip -n -9 >"${out}/lss-${version}.tar.gz"
	cp bootstrap.sh "${out}/bootstrap.sh"
	chmod 0755 "${out}/bootstrap.sh"
	return
}

build_collection() {
	local collection="${stage}/collection"
	cp -R ansible "${collection}"
	cp LICENSE "${collection}/LICENSE"
	mkdir -p "${collection}/roles/lss/files"
	cp bootstrap.sh "${collection}/roles/lss/files/bootstrap.sh"
	set_yaml_value "${collection}/galaxy.yml" version "${version}"
	set_yaml_value "${collection}/roles/lss/defaults/main.yml" lss_version "${version}"
	ansible-galaxy collection build "${collection}" --output-path "${out}" --force >/dev/null
	[[ -f ${out}/vectode-lss-${version}.tar.gz ]] || {
		echo "ansible-galaxy built no vectode-lss-${version}.tar.gz." >&2
		exit 1
	}
	return
}

# sbom_components: one JSON object per line for every file lss downloads by checksum (data/checksums.txt), every
# container image it pins by digest, and the GitHub CLI bootstrap.sh uses to check attestations.
sbom_components() {
	local name arch sum url image gh_version
	while read -r name arch sum url; do
		[[ -n ${name} && ${name} != \#* ]] || continue
		jq -cn --arg name "${name}" --arg arch "${arch}" --arg sum "${sum}" --arg url "${url}" '{
			type: "file", "bom-ref": "download:\($name):\($arch)", name: $name,
			hashes: [{ alg: "SHA-256", content: $sum }],
			externalReferences: [{ type: "distribution", url: $url }],
			properties: [{ name: "lss:architecture", value: $arch }]
		}'
	done <data/checksums.txt
	while read -r image; do
		jq -cn --arg image "${image}" '($image | split("@sha256:")) as [$name, $digest] | {
			type: "container", "bom-ref": "image:\($image)", name: $name,
			hashes: [{ alg: "SHA-256", content: $digest }],
			purl: "pkg:oci/\($name | split("/") | last)@sha256%3A\($digest)?repository_url=\($name | split("/") | .[:-1] | join("/"))"
		}'
	done < <(grep -rhoE '[a-z0-9.-]+(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}' modules lib data profiles 2>/dev/null | sort -u)
	gh_version=$(sed -n 's/^BS_GH_VERSION=//p' bootstrap.sh)
	for arch in AMD64 ARM64; do
		sum=$(sed -n "s/^BS_GH_SHA256_${arch}=//p" bootstrap.sh)
		jq -cn --arg version "${gh_version}" --arg arch "${arch,,}" --arg sum "${sum}" '{
			type: "application", "bom-ref": "gh:\($arch)", name: "gh", version: $version,
			purl: "pkg:github/cli/cli@v\($version)",
			hashes: [{ alg: "SHA-256", content: $sum }],
			externalReferences: [{ type: "distribution",
				url: "https://github.com/cli/cli/releases/download/v\($version)/gh_\($version)_linux_\($arch).tar.gz" }],
			properties: [{ name: "lss:architecture", value: $arch }, { name: "lss:used-by", value: "bootstrap.sh" }]
		}'
	done
	return
}

build_sbom() {
	local serial timestamp
	serial=$(printf 'lss-%s' "${version}" | sha256sum | cut -c 1-32)
	serial="${serial:0:8}-${serial:8:4}-5${serial:13:3}-a${serial:17:3}-${serial:20:12}"
	timestamp=$(date -u -d "@${commit_time}" +%Y-%m-%dT%H:%M:%SZ)
	sbom_components | jq -s --arg version "${version}" --arg serial "${serial}" --arg timestamp "${timestamp}" \
		--arg repo "${REPOSITORY}" '{
		bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: "urn:uuid:\($serial)", version: 1,
		metadata: {
			timestamp: $timestamp,
			tools: { components: [{ type: "application", name: "scripts/release/build.sh" }] },
			component: {
				type: "application", "bom-ref": "lss", name: "lss", version: $version,
				purl: "pkg:github/\($repo | ascii_downcase)@v\($version)",
				licenses: [{ license: { id: "MIT" } }],
				externalReferences: [{ type: "vcs", url: "https://github.com/\($repo)" }]
			}
		},
		components: .,
		dependencies: [{ ref: "lss", dependsOn: [.[]."bom-ref"] }]
	}' >"${out}/lss-${version}.cdx.json"
	return
}

[[ ${release} == 0 ]] || check_versions
build_archive
build_collection
build_sbom
(
	cd "${out}"
	sha256sum -- "lss-${version}.tar.gz" bootstrap.sh "vectode-lss-${version}.tar.gz" "lss-${version}.cdx.json" >SHA256SUMS
)
echo "Built lss ${version} in ${out}:"
cat "${out}/SHA256SUMS"
