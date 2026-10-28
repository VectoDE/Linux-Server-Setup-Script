#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The website generator (scripts/build-site.sh): everything on the page comes from the repository, the Content
# Security Policy allows exactly the inlined stylesheet, and the README tables have to match data/systems.conf.

setup_file() {
	bats_require_minimum_version 1.5.0
	REPO_ROOT=$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)
	export REPO_ROOT
	"${REPO_ROOT}/scripts/build-site.sh" "${BATS_FILE_TMPDIR}/site" >/dev/null
	export PAGE=${BATS_FILE_TMPDIR}/site/index.html
}

# copy_repo: the files the generator reads, in a directory of their own, so a test can change them.
copy_repo() {
	ROOT=${BATS_TEST_TMPDIR}/repo
	mkdir -p "${ROOT}/lib"
	cp -r "${REPO_ROOT}/scripts" "${REPO_ROOT}/site" "${REPO_ROOT}/modules" "${REPO_ROOT}/profiles" "${ROOT}/"
	mkdir -p "${ROOT}/data"
	cp "${REPO_ROOT}/data/systems.conf" "${ROOT}/data/"
	cp "${REPO_ROOT}/lib/ui.sh" "${ROOT}/lib/"
	cp "${REPO_ROOT}/lss" "${REPO_ROOT}/VERSION" "${REPO_ROOT}/README.md" "${ROOT}/"
}

@test "the page has every module, group and profile of the repository" {
	local file name group
	for file in "${REPO_ROOT}"/modules/*/*.sh; do
		name=$(basename "${file}" .sh)
		group=$(basename "$(dirname "${file}")")
		grep -qF "<span class=\"m-name\">${name}</span>" "${PAGE}"
		grep -qF "id=\"group-${group}\"" "${PAGE}"
	done
	for file in "${REPO_ROOT}"/profiles/*.conf; do
		grep -qF "<h3>$(basename "${file}" .conf)</h3>" "${PAGE}"
	done
}

@test "every scene is in the chapter list" {
	local scenes chapters
	scenes=$(grep -c '^<section class="scene' "${PAGE}")
	chapters=$(sed -n '/<nav class="hud-nav"/,/<\/nav>/p' "${PAGE}" | grep -c '^<li><a href="#')
	[ "${scenes}" -eq "${chapters}" ]
	grep -qF "<span class=\"hud-of\">/${scenes}</span>" "${PAGE}"
}

@test "the settings shown are the options of the modules with their defaults" {
	grep -qF '<code>LSS_GUARD_TIME=07:00</code>' "${PAGE}"
	grep -qF '<code>LSS_KERNEL_HARDENING_BLOCK_USB_STORAGE=true</code>' "${PAGE}"
	grep -qF '<span class="m-alt">Instead of apache, caddy</span>' "${PAGE}"
	grep -qF '<h2 id="guard-h">Every morning at 07:00</h2>' "${PAGE}"
}

@test "the help text comes from lss and the menu from lib/ui.sh" {
	grep -qF 'install --profile NAME         install a profile' "${PAGE}"
	grep -qF "lss $(<"${REPO_ROOT}/VERSION"): modular, hardened Linux server setup" "${PAGE}"
	grep -qF 'Install a profile (a ready-made set of modules)</li>' "${PAGE}"
}

@test "the policy allows exactly the inlined stylesheet and the page loads nothing from elsewhere" {
	local css hash page
	command -v openssl >/dev/null || skip "openssl is missing, which checks the hash independently"
	css=$(<"${REPO_ROOT}/site/styles.css")
	hash=$(printf '%s' "${css}" | openssl dgst -sha256 -binary | openssl base64 -A)
	page=$(<"${PAGE}")
	[[ ${page} == *"<style>${css}</style>"* ]]
	grep -qF "style-src 'sha256-${hash}'" "${PAGE}"
	grep -qF "default-src 'none'; script-src 'self';" "${PAGE}"
	[ "$(grep -c '<script' "${PAGE}")" -eq 1 ]
	grep -qF '<script src="film.js" defer></script>' "${PAGE}"
	run grep -E '(src|href)="(https?:)?//' "${PAGE}"
	[ "${status}" -eq 0 ]
	# Links to the repository are the only absolute URLs, and none of them is a resource the page loads.
	run grep -E '<(script|link|img)[^>]+(src|href)="(https?:)?//' "${PAGE}"
	[ "${status}" -eq 1 ]
	[ -f "${BATS_FILE_TMPDIR}/site/film.js" ]
	[ -f "${BATS_FILE_TMPDIR}/site/favicon.svg" ]
}

@test "a module in a new group gets a scene of its own" {
	copy_repo
	mkdir -p "${ROOT}/modules/edge"
	cat >"${ROOT}/modules/edge/gateway.sh" <<'EOF'
MOD_NAME="gateway"
MOD_GROUP="edge"
MOD_DESCRIPTION="Gateway in front of <everything> & more"
MOD_REQUIRES="system"
MOD_OPTIONS="port|8443|Port it listens on
mode||Optional mode"
EOF
	run "${ROOT}/scripts/build-site.sh" "${ROOT}/out"
	[ "${status}" -eq 0 ]
	grep -qF 'id="group-edge"' "${ROOT}/out/index.html"
	grep -qF '<span class="m-desc">Gateway in front of &lt;everything&gt; &amp; more</span>' "${ROOT}/out/index.html"
	grep -qF '<code>LSS_GATEWAY_PORT=8443</code> <code>LSS_GATEWAY_MODE=</code>' "${ROOT}/out/index.html"
	grep -qF '<li><a href="#group-edge">modules/edge</a></li>' "${ROOT}/out/index.html"
	# Known groups keep their order; the new one comes after them.
	[ "$(grep -n 'id="group-apps"' "${ROOT}/out/index.html" | cut -d: -f1)" -lt \
		"$(grep -n 'id="group-edge"' "${ROOT}/out/index.html" | cut -d: -f1)" ]
}

@test "a module whose MOD_GROUP differs from its directory stops the build" {
	copy_repo
	sed -i 's/^MOD_GROUP="base"/MOD_GROUP="security"/' "${ROOT}/modules/base/swap.sh"
	run "${ROOT}/scripts/build-site.sh" "${ROOT}/out"
	[ "${status}" -eq 1 ]
	[[ ${output} == *"modules/base/swap.sh: MOD_GROUP is 'security'."* ]]
}

@test "the README tables have to match data/systems.conf" {
	copy_repo
	run "${ROOT}/scripts/build-site.sh" --check
	[ "${status}" -eq 0 ]
	sed -i 's/^system|Debian|12, 13|12, 13$/system|Debian|11, 12, 13|12, 13/' "${ROOT}/data/systems.conf"
	sed -i 's/^requirement|Profile `devops`|1 GB; 1.5 GB on the RHEL family|7 GB|/requirement|Profile `devops`|1 GB|7 GB|/' \
		"${ROOT}/data/systems.conf"
	run "${ROOT}/scripts/build-site.sh" --check
	[ "${status}" -eq 1 ]
	[[ ${output} == *'README.md "Supported systems" differs'* ]]
	[[ ${output} == *'README.md "System requirements" differs'* ]]
	run "${ROOT}/scripts/build-site.sh" "${ROOT}/out"
	[ "${status}" -eq 1 ]
	[ ! -e "${ROOT}/out/index.html" ]
}
