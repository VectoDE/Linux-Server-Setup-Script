#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Prepares the next release from the commits on main since the last version tag: picks the version, writes it to
# VERSION, ansible/galaxy.yml and the default of the role vectode.lss.lss, turns "## Unreleased" in CHANGELOG.md
# into the section of the release and writes its notes.
#
# RELEASE_BUMP=auto|patch|minor|major (default auto). In auto mode a pull request labelled breaking-change (or a
# commit marked "type!:" or "BREAKING CHANGE") makes a major release, the label enhancement (or a "feat:" commit) a
# minor one, anything else a patch. While VERSION carries a pre-release suffix (2.0.0-dev), the release is that
# version without the suffix: the suffix says which release is being prepared. Commits whose message contains
# "[skip release]" are left out. Results go to $GITHUB_OUTPUT (release, version, tag), the notes to $RELEASE_NOTES
# (default release-notes.md). RELEASE_PRERELEASE=rc.1 makes the pre-release 2.1.0-rc.1 of the version picked, for
# a test of the release workflow or a release candidate; it leaves CHANGELOG.md as it is.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

REPOSITORY=VectoDE/Linux-Server-Setup-Script
VERSION_RE='^([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?$'

output() {
	local line
	for line in "$@"; do
		printf '%s\n' "${line}"
		if [[ -n ${GITHUB_OUTPUT:-} ]]; then
			printf '%s\n' "${line}" >>"${GITHUB_OUTPUT}"
		fi
	done
	return
}

# labels SHA: labels of the pull request a commit came from; none without the GitHub CLI or for direct pushes.
labels() {
	local sha=$1
	gh api "repos/${REPOSITORY}/commits/${sha}/pulls" --jq '.[].labels[].name' 2>/dev/null || true
	return
}

# bump_of SUBJECT BODY LABELS
bump_of() {
	local subject=$1 body=$2 labels=$3
	if [[ $'\n'${labels}$'\n' == *$'\n'breaking-change$'\n'* || ${body} =~ BREAKING[\ -]CHANGE ||
		${subject} =~ ^[a-z]+(\(.*\))?!: ]]; then
		printf 'major'
	elif [[ $'\n'${labels}$'\n' == *$'\n'enhancement$'\n'* || ${subject} =~ ^feat(\(.*\))?: ]]; then
		printf 'minor'
	else
		printf 'patch'
	fi
	return
}

rank() {
	case $1 in
	major) printf '2' ;;
	minor) printf '1' ;;
	*) printf '0' ;;
	esac
	return
}

# next_version CURRENT BUMP
next_version() {
	local current=$1 bump=$2
	[[ ${current} =~ ${VERSION_RE} ]] || {
		echo "VERSION '${current}' is a version like 2.0.1." >&2
		exit 1
	}
	local major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]} patch=${BASH_REMATCH[3]} pre=${BASH_REMATCH[4]}
	if [[ -n ${pre} ]]; then
		printf '%s.%s.%s' "${major}" "${minor}" "${patch}"
	elif [[ ${bump} == major ]]; then
		printf '%s.0.0' "$((major + 1))"
	elif [[ ${bump} == minor ]]; then
		printf '%s.%s.0' "${major}" "$((minor + 1))"
	else
		printf '%s.%s.%s' "${major}" "${minor}" "$((patch + 1))"
	fi
	return
}

# write_notes NOTES_FILE: the notes of the release are the Unreleased section of CHANGELOG.md; without written notes,
# the commit subjects are listed.
write_notes() {
	local notes=$1
	awk '/^## Unreleased$/ { found = 1; next } found && /^## \[/ { exit } found' CHANGELOG.md |
		sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}' >"${notes}.written"
	if grep -q '[^[:space:]]' "${notes}.written"; then
		mv -f "${notes}.written" "${notes}"
	else
		rm -f "${notes}.written"
		printf '### Changed\n\n- %s\n' "${SUBJECTS//$'\n'/$'\n'- }" >"${notes}"
	fi
	return
}

# update_changelog VERSION LAST_TAG NOTES_FILE: the Unreleased section becomes the section of the release.
update_changelog() {
	local version=$1 last_tag=$2 notes=$3 date link
	date=$(date -u +%Y-%m-%d)
	if [[ -n ${last_tag} ]]; then
		link="[${version}]: https://github.com/${REPOSITORY}/compare/${last_tag}...v${version}"
	else
		link="[${version}]: https://github.com/${REPOSITORY}/releases/tag/v${version}"
	fi
	awk -v version="${version}" -v date="${date}" -v link="${link}" -v notes="${notes}" '
		/^## Unreleased$/ && !done {
			print; print ""; print "## [" version "] - " date; print ""
			while ((getline line < notes) > 0) print line
			print ""; skipping = 1; done = 1; next
		}
		skipping && /^## \[/ { skipping = 0 }
		skipping { next }
		/^\[[^]]+\]: / && !linked { print link; linked = 1 }
		{ print }
		END { if (!linked) print link }
	' CHANGELOG.md >CHANGELOG.md.next
	mv -f CHANGELOG.md.next CHANGELOG.md
	return
}

main() {
	local requested=${RELEASE_BUMP:-auto} notes=${RELEASE_NOTES:-release-notes.md} pre=${RELEASE_PRERELEASE:-}
	local last_tag range current version
	local bump=patch sha subject body entry commit_bump count=0
	SUBJECTS=''
	[[ ${requested} =~ ^(auto|patch|minor|major)$ ]] || {
		echo "RELEASE_BUMP must be auto, patch, minor or major, not '${requested}'." >&2
		exit 2
	}
	[[ -z ${pre} || ${pre} =~ ^[0-9A-Za-z]+(\.[0-9A-Za-z]+)*$ ]] || {
		echo "RELEASE_PRERELEASE '${pre}' is a pre-release name like rc.1." >&2
		exit 2
	}
	current=$(<VERSION)
	# A pre-release VERSION names the release already; the labels cannot change it.
	[[ ${current} != *-* || ${requested} != auto ]] || requested='patch'
	last_tag=$(git describe --tags --abbrev=0 --match 'v[0-9]*' --match '[0-9]*' 2>/dev/null || true)
	range=HEAD
	[[ -z ${last_tag} ]] || range="${last_tag}..HEAD"
	while IFS=$'\x1f' read -r -d $'\x1e' sha subject body; do
		sha=${sha//[[:space:]]/}
		[[ -n ${sha} ]] || continue
		entry="${subject}"$'\n'"${body}"
		[[ ${entry} != *'[skip release]'* ]] || continue
		count=$((count + 1))
		SUBJECTS+="${subject}"$'\n'
		if [[ ${requested} == auto ]]; then
			commit_bump=$(bump_of "${subject}" "${body}" "$(labels "${sha}")")
			if (($(rank "${commit_bump}") > $(rank "${bump}"))); then
				bump=${commit_bump}
			fi
		fi
	done < <(git log --no-merges --format='%H%x1f%s%x1f%b%x1e' "${range}")
	SUBJECTS=${SUBJECTS%$'\n'}
	if [[ ${count} -eq 0 ]]; then
		echo "Since ${last_tag} there is nothing to release."
		output release=false
		return 0
	fi
	[[ ${requested} == auto ]] || bump=${requested}
	version=$(next_version "${current}" "${bump}")
	[[ -z ${pre} ]] || version+="-${pre}"
	printf '%s\n' "${version}" >VERSION
	sed -i -E "s/^version: .*/version: \"${version}\"/" ansible/galaxy.yml
	sed -i -E "s/^lss_version: .*/lss_version: \"${version}\"/" ansible/roles/lss/defaults/main.yml
	write_notes "${notes}"
	# A pre-release (a test of the release, or a candidate) leaves the changelog to the release it precedes.
	[[ -n ${pre} ]] || update_changelog "${version}" "${last_tag}" "${notes}"
	echo "${current} -> ${version} (${bump}, ${count} commits since ${last_tag:-the start})"
	output release=true "version=${version}" "tag=v${version}"
	return
}

main "$@"
