# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="matomo"
MOD_GROUP="apps"
MOD_DESCRIPTION="Matomo 5 (web analytics) with MariaDB as a Docker Compose stack behind the web server, installed with a super user and a first website, reports archived by a systemd timer"
MOD_REQUIRES="docker nginx|apache|caddy"
MOD_MODES="docker"
MOD_OPTIONS="domains||Host names of the Matomo site, separated by spaces; empty: matomo.<host name of the server>
port|8087|Port of the Matomo container on 127.0.0.1, which the web server forwards to
admin_user|admin|Name of the super user (the password is the secret matomo-admin-password)
admin_email||E-mail address of the super user; empty: ADMIN_USER@<first host name>
site_url||Address of the first website Matomo measures; empty: https://<first host name>
memory|1g|Memory limit of the Matomo container"
MOD_SECRETS="matomo-admin-password matomo-db-password matomo-db-root-password matomo-api-token"
MOD_PORTS="none of its own (the HTTPS port of the web server)"

# Matomo 5.14.0 (apache), the multi-architecture index (amd64 and arm64), checked 2026-10-15.
MT_IMAGE=docker.io/library/matomo@sha256:1e00192627025a9eb9108858a0d2fcedb495958adf8ee12cd2b2e4ec306efae4
# www-data in the image; the container runs as this user from the start, so it needs no capabilities.
MT_USER=33:33
# A browser user agent, so Matomo does not drop the test visit of mod_verify as a bot.
MT_AGENT='Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0'

mod_check() {
	app_check_domains
	app_check_port port
	[[ $(opt admin_user) =~ ^[a-zA-Z0-9._@-]{2,100}$ ]] || die "LSS_MATOMO_ADMIN_USER must be a login name."
	[[ -z $(opt admin_email) || $(opt admin_email) =~ ^[^@[:space:]]+@[^@[:space:]]+\.[a-z]+$ ]] ||
		die "LSS_MATOMO_ADMIN_EMAIL must be an e-mail address."
	[[ -z $(opt site_url) || $(opt site_url) =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[^[:space:]]*)?$ ]] ||
		die "LSS_MATOMO_SITE_URL must be an address such as https://www.example.com."
	[[ $(opt memory) =~ ^[1-9][0-9]*[mg]$ ]] || die "LSS_MATOMO_MEMORY must be a size such as 1g or 768m."
	return
}

mod_install() {
	app_compose_ready
	return
}

# _mt_compose: the stack. The installer of Matomo takes the database password from MATOMO_DATABASE_PASSWORD_FILE.
_mt_compose() {
	cat <<EOF
# Managed by lss (module matomo). Change LSS_MATOMO_* in /etc/lss/lss.conf and run lss configure matomo.
name: $(app_project)
services:
  app:
    image: ${MT_IMAGE}
    user: "${MT_USER}"
    depends_on:
      db:
        condition: service_healthy
    environment:
      MATOMO_DATABASE_HOST: db
      MATOMO_DATABASE_TABLES_PREFIX: matomo_
      MATOMO_DATABASE_USERNAME: matomo
      MATOMO_DATABASE_DBNAME: matomo
      MATOMO_DATABASE_PASSWORD_FILE: /run/secrets/db-password
      PHP_MEMORY_LIMIT: 512M
    ports:
      - 127.0.0.1:$(opt_int port):80
    volumes:
      - html:/var/www/html
$(app_mount secrets/db-password.app /run/secrets/db-password)
    tmpfs:
      - /tmp:mode=1777,size=256m
      - /var/run/apache2:mode=1777,size=16m
      - /var/lock/apache2:mode=1777,size=16m
    networks: [default, backend]
$(app_hardening "$(opt memory)" 512)
$(app_mariadb matomo)
volumes:
  html:
  db:
$(app_networks)
EOF
	return
}

# _mt_console ARG...: the Matomo console as www-data in the container.
_mt_console() {
	app_exec app php /var/www/html/console "$@"
	return
}

# _mt_installed: config.ini.php exists and the installation finished.
_mt_installed() {
	app_exec app sh -c 'test -s /var/www/html/config/config.ini.php && ! grep -q "^installation_in_progress" /var/www/html/config/config.ini.php' 2>/dev/null
	return
}

# _mt_step JAR STEP [CURL OPTION...]: one step of the web installer; prints the body and the status.
_mt_step() {
	local jar=$1 step=$2
	shift 2
	app_get "index.php?module=Installation&action=${step}" -b "${jar}" -c "${jar}" "$@"
	return
}

# _mt_post JAR STEP FIELD...: posts the form of STEP; fails unless Matomo moves on (redirect) or shows a page without a
# form error.
_mt_post() {
	local jar=$1 step=$2 page status
	shift 2
	page=$(_mt_step "${jar}" "${step}" -X POST "$@") || true
	status=$(app_status "${page}")
	if [[ ${status} != 302 && ${status} != 200 ]] || grep -q 'class="[^"]*form-errors\|class="[^"]*alert-danger' <<<"${page}"; then
		log_error "matomo: the installer step ${step} answers ${status}: $(sed -n 's/.*\(alert-danger\|form-errors\)[^>]*>\([^<]*\).*/\2/p' <<<"${page}" | head -3)"
		return 1
	fi
	return 0
}

# _mt_install: the web installer, step by step (Matomo has no installer on the command line). The passwords go to
# curl as files, so they never show up in the process list; "**********" makes the installer use the database
# password from MATOMO_DATABASE_PASSWORD_FILE.
_mt_install() {
	local jar email site domain password
	_mt_installed && return 0
	domain=$(app_domain)
	email=$(opt admin_email)
	[[ -n ${email} ]] || email=$(opt admin_user)@${domain}
	site=$(opt site_url)
	[[ -n ${site} ]] || site=https://${domain}
	secret_load matomo-admin-password password 32
	log_info "matomo: installing Matomo (super user $(opt admin_user), password in $(secret_path matomo-admin-password))"
	jar=$(mktemp)
	if ! {
		_mt_step "${jar}" '' >/dev/null &&
			_mt_step "${jar}" systemCheck >/dev/null &&
			_mt_post "${jar}" databaseSetup -d host=db -d username=matomo -d 'password=**********' -d dbname=matomo \
				-d tables_prefix=matomo_ --data-urlencode 'adapter=PDO\MYSQL' -d schema=Mariadb &&
			_mt_step "${jar}" tablesCreation >/dev/null &&
			_mt_post "${jar}" setupSuperUser --data-urlencode "login=$(opt admin_user)" \
				--data-urlencode "password@$(secret_path matomo-admin-password)" \
				--data-urlencode "password_bis@$(secret_path matomo-admin-password)" --data-urlencode "email=${email}" &&
			_mt_post "${jar}" firstWebsiteSetup --data-urlencode "siteName=${domain}" --data-urlencode "url=${site}" \
				-d timezone=UTC -d ecommerce=0 &&
			_mt_step "${jar}" trackingCode >/dev/null &&
			_mt_post "${jar}" finished -d anonymise_ip=1
	}; then
		rm -f -- "${jar}"
		die "matomo: the installation failed; see above."
	fi
	rm -f -- "${jar}"
	_mt_installed || die "matomo: Matomo is not installed after the web installer."
	files_note_change "installed Matomo"
	return
}

# _mt_set SECTION KEY VALUE: a setting of config.ini.php, changed only when it differs.
_mt_set() {
	local section=$1 key=$2 value=$3
	if ! app_exec app grep -qx "${key} = ${value}" /var/www/html/config/config.ini.php 2>/dev/null; then
		log_command _mt_console config:set --section="${section}" --key="${key}" --value="${value}" ||
			die "matomo: the console cannot set ${section}.${key}."
		files_note_change "matomo setting ${section}.${key}"
	fi
	return
}

# _mt_token: an app token of the super user for the reporting API (the secret matomo-api-token).
_mt_token() {
	local page token
	secret_exists matomo-api-token && return 0
	page=$(app_get index.php -X POST -d module=API -d method=UsersManager.createAppSpecificTokenAuth -d format=json \
		--data-urlencode "userLogin=$(opt admin_user)" --data-urlencode "passwordConfirmation@$(secret_path matomo-admin-password)" \
		-d description=lss) || true
	token=$(jq -r '.value // empty' <<<"${page%$'\n'*}" 2>/dev/null) || token=''
	[[ -n ${token} ]] || die "matomo: the reporting API gives the super user no token (HTTP $(app_status "${page}"))."
	secret_set matomo-api-token "${token}"
	files_note_change "created the Matomo API token"
	return
}

mod_configure() {
	app_db_secrets mariadb "${MT_USER}"
	_mt_compose | app_compose
	app_up
	app_site "$(opt_int port)"
	app_wait matomo.php 200 >/dev/null || die "matomo: https://$(app_domain)/matomo.php does not answer."
	_mt_install
	_mt_set General force_ssl 1
	_mt_set General assume_secure_protocol 1
	_mt_set General enable_browser_archiving_triggering 0
	_mt_token
	app_timer matomo-archive 1h "Matomo report archiving" app php /var/www/html/console core:archive --url="https://$(app_domain)/"
	return
}

# _mt_api METHOD [CURL OPTION...]: a call of the reporting API with the token (in the request body, not the URL).
_mt_api() {
	local method=$1 file
	shift
	file=$(secret_path matomo-api-token)
	app_get index.php -X POST -d module=API -d "method=${method}" -d format=json --data-urlencode "token_auth@${file}" "$@"
	return
}

mod_verify() {
	local page action
	app_verify_stack
	page=$(app_wait 'index.php?module=Login' 200) || die "matomo: the login page does not answer."
	grep -q 'form_password\|name="form_password"' <<<"${page}" || die "matomo: https://$(app_domain)/index.php?module=Login shows no login."
	# Used, not only running: a page view goes in through the tracker and comes out of the reporting API.
	action="lss-verify-$(date +%s)"
	page=$(app_get "matomo.php?idsite=1&rec=1&send_image=0&action_name=${action}&url=https%3A%2F%2F$(app_domain)%2F${action}" -A "${MT_AGENT}")
	[[ $(app_status "${page}") =~ ^(200|204)$ ]] || die "matomo: the tracker answers $(app_status "${page}")."
	page=$(_mt_api Live.getLastVisitsDetails -d idSite=1 -d period=day -d date=today -d filter_limit=20)
	[[ $(app_status "${page}") == 200 ]] || die "matomo: the reporting API answers $(app_status "${page}")."
	grep -q "${action}" <<<"${page}" || die "matomo: the test page view does not show up in the reporting API."
	svc_is_enabled lss-matomo-archive.timer || die "matomo: the timer lss-matomo-archive for the report archiving is off."
	timeout 600 systemctl start lss-matomo-archive.service || die "matomo: the report archiving fails (journalctl -u lss-matomo-archive)."
	return
}

mod_remove() {
	app_timer_remove matomo-archive
	app_remove
	return
}
