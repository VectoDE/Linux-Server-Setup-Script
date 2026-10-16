#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Builds the website, a film of full-screen scenes that plays while scrolling:
#
#   scripts/build-site.sh [OUT_DIR]   write index.html, film.js, favicon.svg and robots.txt to OUT_DIR (default _site)
#   scripts/build-site.sh --check     only compare the README tables with data/systems.conf
#
# The text comes from the repository itself: MOD_NAME, MOD_GROUP, MOD_DESCRIPTION, MOD_REQUIRES, MOD_CONFLICTS and
# MOD_OPTIONS of every module, the profiles, data/systems.conf, the help text of lss and the menu items of lib/ui.sh.
# The Pages workflow runs this on every deploy and the page is never committed, so a new module or profile is on the
# site with the next deploy. The stylesheet is inlined and allowed by its SHA-256 in the Content Security Policy;
# film.js is the only script.
set -Eeuo pipefail
shopt -s inherit_errexit
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SITE_SRC=site
SYSTEMS=data/systems.conf
REPO_URL=https://github.com/VectoDE/Linux-Server-Setup-Script
read -r LSS_SITE_VERSION <VERSION
# Order of the groups in the film. A group missing here still gets its scene, after these, in alphabetical order.
GROUP_ORDER="base security web runtime database container backup monitoring network mail apps"

declare -A M_GROUP=() M_DESC=() M_REQUIRES=() M_CONFLICTS=() M_OPTIONS=()
declare -a MODULES=() GROUPS_SORTED=() SCENE_IDS=() SCENE_TITLES=()

fail() {
	printf 'build-site: %s\n' "$*" >&2
	exit 1
}

# The text helpers assign to a variable named by the caller instead of printing: every command substitution costs a
# fork, and the page has a few thousand values.

# esc VAR TEXT: VAR is TEXT with the HTML special characters escaped. The quoted replacements keep "&" literal in
# bash 5.2.
esc() {
	local -n _esc_out=$1
	local _esc_text=$2
	_esc_text=${_esc_text//'&'/'&amp;'}
	_esc_text=${_esc_text//'<'/'&lt;'}
	_esc_text=${_esc_text//'>'/'&gt;'}
	_esc_text=${_esc_text//'"'/'&quot;'}
	_esc_out=${_esc_text}
	return
}

# inline VAR TEXT: VAR is the escaped TEXT with `code` spans as <code>.
inline() {
	local -n _inline_out=$1
	# shellcheck disable=SC2016 # literal backticks, nothing to expand
	local _inline_text _inline_html="" _inline_re='^([^`]*)`([^`]*)`(.*)$'
	esc _inline_text "$2"
	while [[ ${_inline_text} =~ ${_inline_re} ]]; do
		_inline_html+="${BASH_REMATCH[1]}<code>${BASH_REMATCH[2]}</code>"
		_inline_text=${BASH_REMATCH[3]}
	done
	_inline_out=${_inline_html}${_inline_text}
	return
}

# --- sources ------------------------------------------------------------------------------------------------------

# Prints the metadata of every module, read the way lss reads it (module_meta): this runs in a subshell, which sources
# the module files one after the other, so nothing of them reaches the rest of the script. Records end with \x1e,
# fields are separated by \x1f.
read_metadata() {
	set +eu
	export LSS_ROOT=${PWD}
	local file
	for file in modules/*/*.sh; do
		unset MOD_NAME MOD_GROUP MOD_DESCRIPTION MOD_REQUIRES MOD_CONFLICTS MOD_OPTIONS
		# shellcheck source=/dev/null
		source "${file}" >/dev/null 2>&1
		printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1e' "${file}" "${MOD_NAME-}" "${MOD_GROUP-}" \
			"${MOD_DESCRIPTION-}" "${MOD_REQUIRES-}" "${MOD_CONFLICTS-}" "${MOD_OPTIONS-}"
	done
	return 0
}

load_modules() {
	local file name group desc requires conflicts options expected
	while IFS=$'\x1f' read -r -d $'\x1e' file name group desc requires conflicts options; do
		expected=${file##*/}
		[[ ${name} == "${expected%.sh}" ]] || fail "${file}: MOD_NAME is '${name}'."
		expected=${file%/*}
		[[ ${group} == "${expected##*/}" ]] || fail "${file}: MOD_GROUP is '${group}'."
		[[ -n ${desc} ]] || fail "${file}: MOD_DESCRIPTION is empty."
		MODULES+=("${name}")
		M_GROUP[${name}]=${group}
		M_DESC[${name}]=${desc}
		M_REQUIRES[${name}]=${requires}
		M_CONFLICTS[${name}]=${conflicts}
		M_OPTIONS[${name}]=${options}
	done < <(read_metadata)
	[[ ${#MODULES[@]} -gt 0 ]] || fail "modules/ has an empty module list."
	local -A present=()
	for name in "${MODULES[@]}"; do
		present[${M_GROUP[${name}]}]=1
	done
	for group in ${GROUP_ORDER}; do
		if [[ -n ${present[${group}]-} ]]; then
			GROUPS_SORTED+=("${group}")
			unset 'present[${group}]'
		fi
	done
	mapfile -t -O "${#GROUPS_SORTED[@]}" GROUPS_SORTED < <(printf '%s\n' "${!present[@]}" | sed '/^$/d' | sort)
	return
}

# option_default VAR MODULE OPTION: VAR is the default value of OPTION from MOD_OPTIONS.
option_default() {
	local -n _default_out=$1
	local _od_name _od_default _
	while IFS='|' read -r _od_name _od_default _; do
		if [[ ${_od_name} == "$3" ]]; then
			_default_out=${_od_default}
			return 0
		fi
	done <<<"${M_OPTIONS[$2]}"
	fail "$2 has the option '$3' missing from MOD_OPTIONS."
}

# install_order VAR MODULE...: VAR is the list of the modules with their requirements first, like module_resolve
# (the first of alternatives).
install_order() {
	local -n _order_out=$1
	shift
	local -A _seen=()
	local -a _order=()
	_visit() {
		local name=$1 requirement
		[[ -z ${_seen[${name}]-} ]] || return 0
		_seen[${name}]=1
		for requirement in ${M_REQUIRES[${name}]-}; do
			_visit "${requirement%%|*}"
		done
		_order+=("${name}")
		return
	}
	local name
	for name in "$@"; do
		_visit "${name}"
	done
	_order_out=${_order[*]}
	return
}

# profiles: "name|description|modules" per profile, the smallest first.
profiles() {
	local file description modules name
	local -a words=()
	for file in profiles/*.conf; do
		description=$(sed -n 's/^# Profile: //p' "${file}")
		modules=$(sed -n 's/^LSS_MODULES=//p' "${file}")
		[[ -n ${description} && -n ${modules} ]] || fail "${file} needs '# Profile:' and LSS_MODULES."
		read -ra words <<<"${modules}"
		name=${file##*/}
		printf '%s %s|%s|%s\n' "${#words[@]}" "${name%.conf}" "${description}" "${modules}"
	done | sort -n | cut -d' ' -f2-
	return
}

# The help text of `lss --help`, from the usage function of lss.
help_text() {
	local text
	text=$(sed -n '/^usage() {/,/^}/p' lss | sed -n '/cat <<EOF/,/^EOF/{//!p}')
	[[ -n ${text} ]] || fail "lss: the usage text was not found."
	# shellcheck disable=SC2016 # the literal placeholder of the heredoc
	printf '%s' "${text//'${LSS_VERSION}'/${LSS_SITE_VERSION}}"
	return
}

# The items of the main menu, "tag|text" per line, from ui_menu in lib/ui.sh.
menu_items() {
	local items
	items=$(sed -n '/^ui_menu() {/,/^}/p' lib/ui.sh | sed -n 's/^[[:space:]]*\([a-z]*\) "\([^"]*\)" \\$/\1|\2/p')
	[[ -n ${items} ]] || fail "lib/ui.sh: the menu items were not found."
	printf '%s\n' "${items}"
	return
}

menu_prompt() {
	sed -n 's/.*--menu "\([^"]*\)".*/\1/p' lib/ui.sh | head -1
	return
}

# systems_rows TYPE: the fields of every TYPE line of data/systems.conf, "|"-separated.
systems_rows() {
	sed -n "s/^$1|//p" "${SYSTEMS}"
	return
}

# --- README check -------------------------------------------------------------------------------------------------

# readme_rows HEADING: the body rows of the first table under "## HEADING", cells trimmed and joined with "|".
readme_rows() {
	awk -v heading="## $1" '
		$0 == heading { inside = 1; next }
		inside && /^## / { exit }
		inside && /^\|/ { rows++; if (rows > 2) print; next }
		inside && rows > 0 { exit }
	' README.md | sed -e 's/^|[[:space:]]*//' -e 's/[[:space:]]*|[[:space:]]*$//' -e 's/[[:space:]]*|[[:space:]]*/|/g'
	return
}

check_readme() {
	local status=0
	if ! diff <(systems_rows system) <(readme_rows "Supported systems") >&2; then
		printf 'build-site: README.md "Supported systems" differs from the system lines of %s (above).\n' "${SYSTEMS}" >&2
		status=1
	fi
	if ! diff <(systems_rows requirement) <(readme_rows "System requirements") >&2; then
		printf 'build-site: README.md "System requirements" differs from the requirement lines of %s (above).\n' "${SYSTEMS}" >&2
		status=1
	fi
	return "${status}"
}

# --- scenes -------------------------------------------------------------------------------------------------------

# scene_open ID TITLE KIND LENGTH: starts a scene. KIND tells film.js what the progress drives (steps: lines appear,
# roll: the stage rolls past, switch: one item at a time, still: the stage only rolls when it is taller than the
# screen). LENGTH is the scroll length in screens, 1 to 6.
scene_open() {
	local id=$1 title=$2 kind=$3 length=$4 number html
	if ((length > 6)); then
		length=6
	fi
	SCENE_IDS+=("${id}")
	SCENE_TITLES+=("${title}")
	printf -v number '%02d' "${#SCENE_IDS[@]}"
	esc html "${title}"
	printf '<section class="scene l%s" id="%s" data-kind="%s" data-title="%s" aria-labelledby="%s-h">\n' \
		"${length}" "${id}" "${kind}" "${html}" "${id}"
	printf '<div class="frame">\n<p class="splice" aria-hidden="true"><span>%s</span><span>%s</span></p>\n' \
		"${number}" "${html}"
	return
}

# scene_close CAPTION: the caption (subtitle) of the scene and the end of it.
scene_close() {
	printf '<p class="cap">%s</p>\n</div>\n</section>\n' "$1"
	return
}

stage_open() {
	printf '<div class="win">\n<div class="stage">\n'
	return
}

stage_close() {
	printf '</div>\n</div>\n'
	return
}

scene_hero() {
	scene_open top "lss" still 1
	cat <<'EOF'
<h1 id="top-h"><span class="h1-word">lss</span><span class="h1-sub">Linux Server Setup</span></h1>
EOF
	stage_open
	cat <<'EOF'
<p class="cmd"><span class="prompt" aria-hidden="true">$ </span><span class="t-hero">sudo lss install --profile minimal-secure</span></p>
<p class="lead">Sets up and hardens Linux servers from modules. Install a whole profile in one run, or only the
modules you need, and come back later to add, change or remove one.</p>
EOF
	stage_close
	scene_close "Scroll to play the film. Every scene is plain text, so it reads the same with motion turned off."
	return
}

log_line() {
	local level text class=${3:-}
	esc level "$1"
	inline text "$2"
	printf '<li class="s%s"><span class="lv">%s</span><span>%s</span></li>\n' "${class:+ ${class}}" "${level}" "${text}"
	return
}

scene_run() {
	local order name last
	install_order order firewall fail2ban
	last=${order##* }
	scene_open run "A run" steps 3
	printf '<h2 id="run-h">One module at a time</h2>\n'
	stage_open
	printf '<ol class="log" aria-label="Output of lss install firewall fail2ban">\n'
	log_line '$' 'sudo lss install firewall fail2ban' cmdline
	log_line INFO "Modules in order: ${order}"
	for name in ${order}; do
		log_line '==>' "${name}"
		if [[ ${name} == "${last}" ]]; then
			log_line OK "${name}: done (6 changes)" ok
		elif [[ ${name} == system ]]; then
			log_line OK "${name}: unchanged" ok
		else
			log_line OK "${name}: done (3 changes)" ok
		fi
	done
	log_line OK 'Finished. Log: /var/log/lss/<run id>.log' ok
	printf '</ol>\n<p class="log-head s">When a step fails</p>\n<ol class="log" aria-label="The same run when the last module fails">\n'
	log_line '==>' "${last}"
	log_line ERROR "${last}: verification failed; changed files were restored. Details: /var/log/lss/<run id>.log" deny
	printf '</ol>\n'
	stage_close
	scene_close "Each module checks its settings before it changes anything. When a step fails, lss puts back every
file that module touched in the run. Later, <code>lss verify</code> shows whether it still works."
	return
}

scene_profiles() {
	local -a rows=()
	local row name description modules html
	local -a words=()
	mapfile -t rows < <(profiles)
	scene_open profiles "Profiles" switch "${#rows[@]}"
	printf '<h2 id="profiles-h">%s profiles</h2>\n' "${#rows[@]}"
	stage_open
	printf '<div class="sw">\n<ol class="sw-names" data-switch aria-hidden="true">\n'
	for row in "${rows[@]}"; do
		esc html "${row%%|*}"
		printf '<li class="o">%s</li>\n' "${html}"
	done
	printf '</ol>\n<div class="sw-items" data-switch>\n'
	for row in "${rows[@]}"; do
		IFS='|' read -r name description modules <<<"${row}"
		esc name "${name}"
		inline description "${description}"
		esc modules "${modules}"
		read -ra words <<<"${modules}"
		# One span per module keeps "kernel-hardening" on one line.
		printf -v modules '<span>%s</span> ' "${words[@]}"
		printf '<div class="o">\n<h3>%s</h3>\n<p class="o-desc">%s</p>\n' "${name}" "${description}"
		printf '<p class="o-count">%s modules, in this order</p>\n<p class="o-mods">%s</p>\n</div>\n' \
			"${#words[@]}" "${modules}"
	done
	printf '</div>\n</div>\n'
	stage_close
	scene_close "A profile is a list of modules for one kind of server. Start from one, then add or remove single
modules with <code>lss install</code> and <code>lss remove</code>."
	return
}

group_caption() {
	case $1 in
	base) printf 'The ground floor: host name, locale and updates, time over NTS, swap, the administrator account, tools and a persistent journal.' ;;
	security) printf 'The hardening and the checks that keep it in place. One of fail2ban and CrowdSec; ssh-2fa, clamav and usbguard are opt-in.' ;;
	web) printf 'One web server owns ports 80 and 443, HTTPS only, with certificates from Let&#39;s Encrypt and sites from a single setting.' ;;
	runtime) printf 'Language runtimes from the distribution or the vendor, each in the version you pick.' ;;
	database) printf 'Every database listens on 127.0.0.1 with hardened authentication until you open it.' ;;
	container) printf 'Docker or Podman, Portainer, or single-server Kubernetes with k3s. Published ports pass a firewall chain of their own.' ;;
	backup) printf 'Encrypted daily backups with restic, database dumps before each run and a restore test every week.' ;;
	monitoring) printf 'Metrics, logs and alerts with Prometheus, Grafana, Loki and Alloy, or Netdata on its own.' ;;
	network) printf 'A WireGuard VPN for the admin interfaces, a validating DNS resolver and a time server.' ;;
	mail) printf 'The server sends its own mail through a relay, or runs a mail server for your domains with webmail.' ;;
	apps) printf 'Self-hosted apps as Docker Compose stacks behind the web server, each on its own host name.' ;;
	*) printf 'The modules in modules/%s.' "$1" ;;
	esac
	return
}

scene_group() {
	local group=$1 name option default _ count noun html text
	local -a names=()
	for name in "${MODULES[@]}"; do
		[[ ${M_GROUP[${name}]} != "${group}" ]] || names+=("${name}")
	done
	count=${#names[@]}
	scene_open "group-${group}" "modules/${group}" roll "$((2 + (count + 3) / 4))"
	printf '<h2 id="group-%s-h"><span class="path">modules/</span>%s</h2>\n' "${group}" "${group}"
	noun=modules
	if ((count == 1)); then
		noun=module
	fi
	printf '<p class="meta">%s %s</p>\n' "${count}" "${noun}"
	stage_open
	printf '<ul class="mods">\n'
	for name in "${names[@]}"; do
		inline text "${M_DESC[${name}]}"
		printf '<li class="m">\n<span class="m-name">%s</span>\n<span class="m-desc">%s</span>\n' "${name}" "${text}"
		if [[ -n ${M_CONFLICTS[${name}]} ]]; then
			esc text "${M_CONFLICTS[${name}]// /, }"
			printf '<span class="m-alt">Instead of %s</span>\n' "${text}"
		fi
		if [[ -n ${M_OPTIONS[${name}]} ]]; then
			printf '<span class="m-opt">'
			while IFS='|' read -r option default _; do
				[[ -n ${option} ]] || continue
				text="LSS_${name}_${option}"
				text=${text//-/_}
				esc html "${default}"
				printf '<code>%s=%s</code> ' "${text^^}" "${html}"
			done <<<"${M_OPTIONS[${name}]}"
			printf '</span>\n'
		fi
		printf '</li>\n'
	done
	printf '</ul>\n'
	stage_close
	scene_close "$(group_caption "${group}")"
	return
}

rule_row() {
	printf '<tr class="s%s"><td>%s</td><td>%s</td><td>%s</td></tr>\n' "${4:+ $4}" "$1" "$2" "$3"
	return
}

scene_security() {
	scene_open security "Security model" steps 3
	printf '<h2 id="security-h">Closed by default</h2>\n'
	stage_open
	cat <<'EOF'
<table class="rules">
<caption>Inbound rules of a web server with the profile <code>webhosting</code></caption>
<thead><tr><th scope="col">Port</th><th scope="col">Rule</th><th scope="col">Why</th></tr></thead>
<tbody>
EOF
	rule_row 22/tcp allow "<code>ssh-hardening</code>: keys only, no root, no passwords"
	rule_row "80/tcp 443/tcp" allow "<code>nginx</code>: HTTPS only, TLS 1.2 and 1.3"
	rule_row 8090/tcp 127.0.0.1 "admin port of the web server, through an SSH tunnel or WireGuard"
	rule_row 3306/tcp 127.0.0.1 "<code>mariadb</code> until <code>LSS_MARIADB_ACCESS</code> opens it"
	rule_row "everything else" drop "<code>firewall</code>, with a timer that turns it off again if SSH stops answering" deny
	printf '</tbody>\n</table>\n'
	cat <<'EOF'
<p class="note s">Modules never open ports themselves; they ask lss, which records the rule per module and closes it
when the module goes. The kernel is locked down, AppArmor or SELinux enforces, auditd records changes to accounts,
sudo and the network, and AIDE checks the files every day. The settings file is parsed and never run, and secrets
are files only root can read.</p>
EOF
	stage_close
	scene_close "Inbound traffic stays closed except SSH and the ports of installed modules. Databases and admin
interfaces listen on 127.0.0.1 or the WireGuard network."
	return
}

scene_guard() {
	local time threshold max_age
	option_default time guard time
	option_default threshold guard login_threshold
	option_default max_age guard backup_max_age
	[[ ${time} =~ ^[0-9:]+$ ]] || fail "guard: the default time '${time}' is not HH:MM."
	scene_open guard "Guard" steps 3
	printf '<h2 id="guard-h">Every morning at %s</h2>\n' "${time}"
	stage_open
	printf '<pre class="unit s"><span class="u-c"># systemctl cat lss-guard.timer</span>\n[Timer]\nOnCalendar=*-*-* %s:00\nRandomizedDelaySec=10min</pre>\n' \
		"${time}"
	printf '<ol class="log report" aria-label="An example report of the guard">\n'
	# shellcheck disable=SC2016 # backticks mark code
	log_line verify 'every installed module, `lss verify`' ok
	log_line repair 'nginx: a managed file was changed outside lss, configured again'
	log_line report '3 security updates pending, reboot needed'
	log_line report "71 failed SSH logins in 24 hours (more than ${threshold}), most from 203.0.113.0/24" deny
	log_line report "last backup 6 hours ago (limit ${max_age} hours), restore test passed"
	log_line sent 'webhook https://ntfy.sh/your-topic'
	printf '</ol>\n'
	stage_close
	scene_close "The <code>guard</code> module checks the server every day, repairs modules that drifted, and sends what
it found to a webhook or by e-mail. Failed services, full disks, vulnerable packages and container images are in the
report too."
	return
}

scene_install() {
	scene_open install "Verified install" steps 3
	printf '<h2 id="install-h">Verified before it runs</h2>\n'
	stage_open
	printf '<ol class="log" aria-label="Installing lss from a release">\n'
	log_line '$' 'gh release download -R VectoDE/Linux-Server-Setup-Script --pattern bootstrap.sh' cmdline
	log_line '$' "gh attestation verify bootstrap.sh --repo VectoDE/Linux-Server-Setup-Script --cert-identity ${REPO_URL}/.github/workflows/release.yml@refs/heads/main" cmdline
	log_line '$' 'sudo bash bootstrap.sh' cmdline
	log_line OK 'SHA-256 of the release archive matches SHA256SUMS' ok
	log_line OK 'attestation: built by release.yml from refs/heads/main on a GitHub-hosted runner' ok
	log_line OK 'installed to /opt/lss/<version>; /opt/lss/current points to it' ok
	printf '</ol>\n'
	stage_close
	scene_close "<code>bootstrap.sh</code> runs nothing it downloaded until the checksum matches and the Sigstore build
attestation proves the release workflow of this repository built it. <code>lss update</code> takes the same path, and
<code>--rollback</code> switches back."
	return
}

scene_cli() {
	scene_open cli "Commands" roll 3
	printf '<h2 id="cli-h">lss --help</h2>\n'
	stage_open
	local text
	esc text "$(help_text)"
	printf '<pre class="help">%s</pre>\n' "${text}"
	stage_close
	scene_close "Settings are <code>KEY=value</code> lines in <code>/etc/lss/lss.conf</code>, named
<code>LSS_&lt;MODULE&gt;_&lt;OPTION&gt;</code>. <code>--dry-run</code> shows what a command would do."
	return
}

scene_menu() {
	local -a items=()
	local item tag text prompt
	mapfile -t items < <(menu_items)
	scene_open menu "Menu" switch "${#items[@]}"
	printf '<h2 id="menu-h">Or the menu</h2>\n'
	stage_open
	esc prompt "$(menu_prompt)"
	esc text "${LSS_SITE_VERSION}"
	printf '<div class="tui">\n<p class="tui-title">lss %s</p>\n<p class="tui-prompt">%s</p>\n' "${text}" "${prompt}"
	printf '<ul class="tui-items" data-switch>\n'
	for item in "${items[@]}"; do
		esc tag "${item%%|*}"
		esc text "${item#*|}"
		printf '<li class="o"><span class="tui-tag">%s</span>%s</li>\n' "${tag}" "${text}"
	done
	printf '</ul>\n<p class="tui-buttons" aria-hidden="true"><span>&lt;Ok&gt;</span><span>&lt;Cancel&gt;</span></p>\n</div>\n'
	stage_close
	scene_close "Without a command, <code>sudo lss</code> opens this menu. Choosing modules there runs the same install
as the command line."
	return
}

scene_systems() {
	local distribution releases tested setup ram disk duration arch
	scene_open systems "Systems" still 2
	printf '<h2 id="systems-h">Where it runs</h2>\n'
	stage_open
	printf '<table class="sys">\n<caption>Supported systems</caption>\n'
	printf '<thead><tr><th scope="col">Distribution</th><th scope="col">Releases</th><th scope="col">Tested in CI</th></tr></thead>\n<tbody>\n'
	while IFS='|' read -r distribution releases tested; do
		inline distribution "${distribution}"
		inline releases "${releases}"
		inline tested "${tested}"
		printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' "${distribution}" "${releases}" "${tested}"
	done < <(systems_rows system)
	inline arch "$(systems_rows arch)"
	printf '</tbody>\n</table>\n<p class="note">%s</p>\n' "${arch}"
	printf '<table class="sys">\n<caption>System requirements</caption>\n'
	printf '<thead><tr><th scope="col">Setup</th><th scope="col">RAM</th><th scope="col">Free disk</th><th scope="col">Install time</th></tr></thead>\n<tbody>\n'
	while IFS='|' read -r setup ram disk duration; do
		inline setup "${setup}"
		inline ram "${ram}"
		inline disk "${disk}"
		inline duration "${duration}"
		printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' "${setup}" "${ram}" "${disk}" "${duration}"
	done < <(systems_rows requirement)
	printf '</tbody>\n</table>\n'
	stage_close
	scene_close "One CPU core is enough. The figures are the largest the integration tests measured on any tested
system; the README has them for every module."
	return
}

help_link() {
	printf '<li><a href="%s/%s">%s</a> %s</li>\n' "${REPO_URL}" "$1" "$2" "$3"
	return
}

scene_help() {
	scene_open help "Help" still 1
	printf '<h2 id="help-h">Help</h2>\n'
	stage_open
	cat <<'EOF'
<p class="cmd"><span class="prompt" aria-hidden="true">$ </span>lss info guard</p>
<p class="lead">On the server, <code>lss info MODULE</code> shows what a module does, what it needs, its settings and
their defaults.</p>
<ul class="links">
EOF
	help_link "#readme" "README" "installation, modules, profiles and settings"
	help_link "blob/main/docs/troubleshooting.md" "Troubleshooting" "locked out, failed modules, common messages"
	help_link "blob/main/docs/hardening.md" "Hardening guide" "what the security modules change, CIS mapping"
	help_link "blob/main/docs/assurance.md" "Assurance case" "threat model and trust boundaries"
	help_link "blob/main/docs/module-guide.md" "Writing a module" "the module format these pages are built from"
	help_link "discussions" "Discussions" "questions and ideas"
	help_link "issues/new/choose" "Report a bug" "with the bug template"
	help_link "security/policy" "Security policy" "report vulnerabilities privately"
	printf '</ul>\n'
	stage_close
	scene_close "lss is free software under the MIT license, maintained in spare time."
	return
}

# --- page ---------------------------------------------------------------------------------------------------------

chapters() {
	local index html
	printf '<ol>\n'
	for index in "${!SCENE_IDS[@]}"; do
		esc html "${SCENE_TITLES[${index}]}"
		printf '<li><a href="#%s">%s</a></li>\n' "${SCENE_IDS[${index}]}" "${html}"
	done
	printf '</ol>\n'
	return
}

build() {
	local out=$1 body body_file css hash group
	local file
	for file in styles.css film.js favicon.svg robots.txt; do
		[[ -f ${SITE_SRC}/${file} ]] || fail "${SITE_SRC}/${file} is missing."
	done
	load_modules
	# The scenes run in this shell, not in a command substitution, so SCENE_IDS and SCENE_TITLES survive for the
	# chapter list.
	body_file=$(mktemp)
	trap 'rm -f -- "${body_file}"' RETURN
	{
		scene_hero
		scene_run
		scene_profiles
		for group in "${GROUPS_SORTED[@]}"; do
			scene_group "${group}"
		done
		scene_security
		scene_guard
		scene_install
		scene_cli
		scene_menu
		scene_systems
		scene_help
	} >"${body_file}"
	body=$(<"${body_file}")
	[[ $(grep -c '^<section ' <<<"${body}") == "${#SCENE_IDS[@]}" ]] || fail "the chapter list and the scenes differ."

	# The stylesheet goes into the page byte for byte, and the policy allows exactly that content.
	css=$(<"${SITE_SRC}/styles.css")
	hash=$(printf '%s' "${css}" | openssl dgst -sha256 -binary | openssl base64 -A)
	mkdir -p "${out}"
	{
		cat <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'sha256-${hash}'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f3f5f8" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0b1a30" media="(prefers-color-scheme: dark)">
<title>lss: hardened Linux servers, one module at a time</title>
<meta name="description" content="lss sets up and hardens Debian, Ubuntu and RHEL-family servers from ${#MODULES[@]} modules and ${#GROUPS_SORTED[@]} groups, with profiles, a daily guard and verified releases.">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<style>${css}</style>
<script src="film.js" defer></script>
</head>
<body>
<a class="skip" href="#film">Skip to the film</a>
<header class="hud">
<a class="hud-mark" href="#top">lss</a>
<nav class="hud-nav" aria-label="Chapters">
<details>
<summary>Chapters</summary>
$(chapters)
</details>
</nav>
<p class="hud-tc" aria-hidden="true"><span id="tc-n">01</span><span class="hud-of">/${#SCENE_IDS[@]}</span> <span id="tc-title">lss</span></p>
</header>
<main id="film" tabindex="-1">
${body}
</main>
<footer class="foot">
<p>lss ${LSS_SITE_VERSION}, MIT license. <a href="${REPO_URL}">Source on GitHub</a>.</p>
<p>This page is built from the module files of the repository on every deploy. It loads nothing from other servers
and sets no cookies.</p>
</footer>
<div class="bar" aria-hidden="true"></div>
</body>
</html>
EOF
	} >"${out}/index.html"
	cp "${SITE_SRC}/film.js" "${SITE_SRC}/favicon.svg" "${SITE_SRC}/robots.txt" "${out}/"
	printf 'build-site: %s/index.html with %s scenes and %s modules\n' "${out}" "${#SCENE_IDS[@]}" "${#MODULES[@]}"
	return
}

case ${1:-} in
--check) check_readme ;;
-h | --help) sed -n '7,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,3\}//' ;;
-*) fail "unknown option '$1'." ;;
*)
	check_readme
	build "${1:-_site}"
	;;
esac
