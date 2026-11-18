#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# The first installation of the apps whose installer or setup page takes the first visitor as the administrator
# (WordPress, Matomo, n8n, Uptime Kuma) runs against the container on 127.0.0.1 before app_site publishes the app,
# and an instance that lss did not set up stops lss before it is published. Nextcloud installs with occ before its
# site and checks the administrator of an existing installation the same way.

setup() {
	load helpers
	lss_test_setup
	use_os debian-12
	INSTALLED=${BATS_TEST_TMPDIR}/installed
	SECRET_FILE=${BATS_TEST_TMPDIR}/secret
	printf 'secret\n' >"${SECRET_FILE}"
	SUPER_USERS='[{"login":"admin"}]'
	return
}

# load_app NAME: sources modules/apps/NAME.sh and replaces what touches Docker, secrets and the web server with stubs
# that write to $STUB_LOG; "site" marks the moment the app is published.
load_app() {
	LSS_MODULE=$1
	# shellcheck source=/dev/null
	source "${REPO_ROOT}/modules/apps/$1.sh"
	config_set "LSS_$(tr '[:lower:]-' '[:upper:]_' <<<"$1")_DOMAINS" app.example.com
	# shellcheck disable=SC2329 # called by mod_configure
	app_db_secrets() {
		return 0
	}
	# shellcheck disable=SC2329 # called by mod_configure
	app_secret() {
		return 0
	}
	# shellcheck disable=SC2329 # called by mod_configure
	app_compose() {
		cat >/dev/null
	}
	# shellcheck disable=SC2329 # called by mod_configure
	app_file() {
		cat >/dev/null
	}
	# shellcheck disable=SC2329 # called by mod_configure
	app_backup() {
		return 0
	}
	# shellcheck disable=SC2329 # called by mod_configure
	app_up() {
		printf 'up\n' >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by mod_configure
	app_site() {
		printf 'site %s\n' "$*" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by mod_configure
	app_waf_exclude() {
		return 0
	}
	# shellcheck disable=SC2329 # called by mod_configure
	app_timer() {
		return 0
	}
	# shellcheck disable=SC2329 # called by the module
	secret_exists() {
		[[ ${SECRET_MISSING:-0} == 0 ]]
	}
	# shellcheck disable=SC2329 # called by the module
	secret_get() {
		return 0
	}
	# shellcheck disable=SC2329 # called by the module
	secret_path() {
		printf '%s' "${SECRET_FILE}"
	}
	# shellcheck disable=SC2329 # called by app_wait
	sleep() {
		return 0
	}
	APP_START_TIMEOUT=1
	return
}

# line_of PATTERN: the number of the first line of $STUB_LOG that matches PATTERN.
line_of() {
	grep -n -m 1 -- "$1" "${STUB_LOG}" | cut -d : -f 1
}

# --- WordPress ----------------------------------------------------------------------------------------------------

wp_stubs() {
	# shellcheck disable=SC2329 # called by mod_configure
	_wp_compose() {
		return 0
	}
	# shellcheck disable=SC2329 # called by the module
	app_get() {
		printf 'get %s %s\n' "${APP_GET_LOCAL:-public}" "$*" >>"${STUB_LOG}"
		case $1 in
		wp-login.php)
			if [[ ! -e ${INSTALLED} ]]; then
				printf 'install\n302'
			elif [[ $* == *log=* ]]; then
				printf 'login\n%s' "${LOGIN_STATUS:-302}"
			else
				printf 'login\n200'
			fi
			;;
		wp-admin/install.php*)
			: >"${INSTALLED}"
			printf 'done\n200'
			;;
		*) printf 'ok\n200' ;;
		esac
	}
	return
}

@test "WordPress installs against the container before its site is published" {
	load_app wordpress
	wp_stubs
	mod_configure
	local install site
	install=$(line_of '^get 8088 wp-admin/install.php?step=2')
	site=$(line_of '^site ')
	[ -n "${install}" ] && [ -n "${site}" ]
	((install < site))
	run ! grep -q '^get public wp-admin/install' "${STUB_LOG}"
	grep -q '^get public wp-includes/css/buttons.min.css' "${STUB_LOG}"
}

@test "WordPress that somebody else installed stops lss before the site is published" {
	load_app wordpress
	wp_stubs
	: >"${INSTALLED}"
	LOGIN_STATUS=200 run mod_configure
	[ "${status}" -eq 1 ]
	[[ ${output} == *"wordpress: WordPress is installed already, but lssadmin cannot log in with the password of lss (HTTP 200)"* ]]
	run ! grep -q '^site ' "${STUB_LOG}"
	run ! grep -q 'install.php' "${STUB_LOG}"
	SECRET_MISSING=1 run mod_configure
	[ "${status}" -eq 1 ]
	[[ ${output} == *"lss has no password for lssadmin, so lss did not install it"* ]]
}

@test "WordPress installed by lss is configured again and published" {
	load_app wordpress
	wp_stubs
	: >"${INSTALLED}"
	mod_configure
	grep -q '^get 8088 wp-login.php -X POST --data-urlencode log=lssadmin' "${STUB_LOG}"
	grep -q '^site 8088' "${STUB_LOG}"
}

# --- n8n ----------------------------------------------------------------------------------------------------------

n8n_stubs() {
	# shellcheck disable=SC2329 # called by mod_configure
	_n8n_compose() {
		return 0
	}
	# shellcheck disable=SC2329 # called by _n8n_owner
	_n8n_body() {
		printf '{}' >"$1"
	}
	# shellcheck disable=SC2329 # called by the module
	app_get() {
		printf 'get %s %s\n' "${APP_GET_LOCAL:-public}" "$1" >>"${STUB_LOG}"
		case $1 in
		rest/owner/setup)
			if [[ -e ${INSTALLED} ]]; then
				printf '{"message":"Instance owner already setup"}\n400'
			else
				: >"${INSTALLED}"
				printf '{}\n200'
			fi
			;;
		rest/login) printf '{}\n%s' "${LOGIN_STATUS:-200}" ;;
		*) printf 'ok\n200' ;;
		esac
	}
	return
}

@test "n8n sets up its owner against the container before the editor is published" {
	load_app n8n
	n8n_stubs
	mod_configure
	local owner site
	owner=$(line_of '^get 8089 rest/owner/setup')
	site=$(line_of '^site ')
	[ -n "${owner}" ] && [ -n "${site}" ]
	((owner < site))
	run ! grep -q '^get public rest/owner' "${STUB_LOG}"
}

@test "an n8n owner that lss did not set up stops lss; the owner of lss passes" {
	load_app n8n
	n8n_stubs
	: >"${INSTALLED}"
	LOGIN_STATUS=401 run mod_configure
	[ "${status}" -eq 1 ]
	[[ ${output} == *"n8n: the owner is set up already, but admin@app.example.com cannot log in with the password of lss (HTTP 401)"* ]]
	run ! grep -q '^site ' "${STUB_LOG}"
	: >"${STUB_LOG}"
	mod_configure
	grep -q '^get 8089 rest/login' "${STUB_LOG}"
	grep -q '^site ' "${STUB_LOG}"
}

# --- Matomo -------------------------------------------------------------------------------------------------------

mt_stubs() {
	# shellcheck disable=SC2329 # called by mod_configure
	_mt_compose() {
		return 0
	}
	# shellcheck disable=SC2329 # called by mod_configure
	_mt_install() {
		printf 'install %s\n' "${APP_GET_LOCAL:-public}" >>"${STUB_LOG}"
	}
	# shellcheck disable=SC2329 # called by mod_configure
	_mt_set() {
		return 0
	}
	# shellcheck disable=SC2329 # called by mod_configure
	_mt_token() {
		return 0
	}
	# shellcheck disable=SC2329 # called by the module
	app_get() {
		printf 'get %s %s\n' "${APP_GET_LOCAL:-public}" "$1" >>"${STUB_LOG}"
		case $1 in
		index.php) printf '%s\n200' "${SUPER_USERS}" ;;
		*) printf 'ok\n200' ;;
		esac
	}
	return
}

@test "Matomo installs and checks its super user against the container before it is published" {
	command -v jq >/dev/null || skip "jq is not installed"
	load_app matomo
	mt_stubs
	mod_configure
	local install check site
	install=$(line_of '^install 8087')
	check=$(line_of '^get 8087 index.php')
	site=$(line_of '^site ')
	[ -n "${install}" ] && [ -n "${check}" ] && [ -n "${site}" ]
	((install < check && check < site))
}

@test "a Matomo whose super users lack the one of lss stops lss before it is published" {
	command -v jq >/dev/null || skip "jq is not installed"
	load_app matomo
	mt_stubs
	SUPER_USERS='[{"login":"intruder"}]' run mod_configure
	[ "${status}" -eq 1 ]
	[[ ${output} == *"matomo: admin of lss is missing among the super users of this Matomo (HTTP 200)"* ]]
	run ! grep -q '^site ' "${STUB_LOG}"
	SUPER_USERS='{"result":"error"}' run mod_configure
	[ "${status}" -eq 1 ]
}

# --- Uptime Kuma --------------------------------------------------------------------------------------------------

@test "Uptime Kuma sets up its administrator before it is published, and its script checks an existing one" {
	load_app uptime-kuma
	# shellcheck disable=SC2329 # called by mod_configure
	_kuma_compose() {
		return 0
	}
	# shellcheck disable=SC2329 # called by mod_configure
	_kuma() {
		printf 'kuma %s %s\n' "$1" "${APP_GET_LOCAL:-public}" >>"${STUB_LOG}"
		printf '%s' "${KUMA_RESULT:-created}"
		[[ ${KUMA_RESULT:-created} != fail* ]]
	}
	# shellcheck disable=SC2329 # called by the module
	app_get() {
		printf 'get %s %s\n' "${APP_GET_LOCAL:-public}" "$1" >>"${STUB_LOG}"
		printf 'redirect\n302'
	}
	mod_configure
	local setup site
	setup=$(line_of '^kuma setup 8084')
	site=$(line_of '^site ')
	[ -n "${setup}" ] && [ -n "${site}" ]
	((setup < site))
	: >"${STUB_LOG}"
	KUMA_RESULT='failed: the administrator exists already' run mod_configure
	[ "${status}" -eq 1 ]
	run ! grep -q '^site ' "${STUB_LOG}"
	# The script logs in when the setup is done already, and fails when the administrator of lss cannot.
	_kuma_script | grep -qF 'const login = await ask("login", { username, password, token: "" });'
	_kuma_script | grep -qF 'cannot log in with the password of lss'
}

# --- Nextcloud ----------------------------------------------------------------------------------------------------

@test "an installed Nextcloud without the administrator of lss in its admin group stops lss" {
	command -v jq >/dev/null || skip "jq is not installed"
	load_app nextcloud
	# shellcheck disable=SC2329 # called by _nc_owner_check
	_nc_occ() {
		printf '%s\n' "${NC_USER_INFO}"
	}
	NC_USER_INFO='{"groups":["admin","users"]}'
	_nc_owner_check
	NC_USER_INFO='{"groups":["users"]}' run _nc_owner_check
	[ "${status}" -eq 1 ]
	[[ ${output} == *"nextcloud: Nextcloud is installed already, but admin of lss is missing among its administrators"* ]]
}
