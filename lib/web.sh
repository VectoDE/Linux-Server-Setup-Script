# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Web layer shared by the web server modules (nginx, apache, caddy) and everything that publishes something through
# them (tls, vhost, php, phpmyadmin, adminer, pgadmin, apps). One web server owns ports 80 and 443; the others
# conflict with it.
#
# Conventions:
#   WEB_GROUP        group of every web server user; PHP-FPM's socket and the TLS keys are readable by it
#   WEB_PHP_SOCKET   the PHP-FPM pool of the php module listens here (owner root, group WEB_GROUP, mode 0660); the
#                    directory carries the SELinux label web servers may connect to on the RHEL family, and the
#                    php module creates it on Debian and Ubuntu
#   WEB_TLS_DIR      one directory per certificate (NAME/fullchain.pem, NAME/privkey.pem); "default" is a
#                    self-signed certificate for the host name that every web server creates
#   WEB_ACME_ROOT    webroot for ACME http-01 challenges, served on port 80 for every host name (below /var/www,
#                    where SELinux lets web servers read)
#   WEB_ADMIN_PORT   admin interfaces (phpMyAdmin, Adminer, pgAdmin) live on this port, on 127.0.0.1 by default
#
# A site or an admin path is written for the installed web server by web_site_write / web_admin_write; the web
# server modules include the directories below WEB_CONF (sites/ and admin/).

WEB_GROUP=lss-web
WEB_PHP_SOCKET=/run/php-fpm/lss.sock
WEB_TLS_DIR=/etc/lss/tls
WEB_ACME_ROOT=/var/www/lss-acme
WEB_DEFAULT_ROOT=/var/www/lss-default
# shellcheck disable=SC2034 # read by the web server and admin interface modules
WEB_ADMIN_PORT=8090
WEB_ADMIN_HTPASSWD=/etc/lss/web/admin.htpasswd
WEB_ADMIN_CADDY_AUTH=/etc/lss/web/admin-auth.caddy
# Mozilla "intermediate" (TLS 1.2 and 1.3) without the DHE suites, which would need a DH parameter file.
WEB_CERT_HOOK=/etc/letsencrypt/renewal-hooks/deploy/lss-deploy
# CA certificate of a private ACME server (LSS_TLS_CA_BUNDLE, for example Pebble or step-ca); certbot trusts it.
WEB_ACME_CA=/etc/letsencrypt/lss-acme-ca.pem
# certbot's certificate lineages (one directory per certificate name).
WEB_CERT_LIVE=/etc/letsencrypt/live
# The fail2ban jails and the CrowdSec log acquisition for the installed web server.
WEB_FAIL2BAN_JAIL=/etc/fail2ban/jail.d/lss-web.local
WEB_FAIL2BAN_FILTER=/etc/fail2ban/filter.d/lss-caddy-auth.conf
WEB_CROWDSEC_ACQUIS=/etc/crowdsec/acquis.d/lss-web.yaml
# shellcheck disable=SC2034 # read by the web server and haproxy modules
WEB_TLS_CIPHERS=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305

# The installed web server (nginx, apache or caddy), or nothing.
web_server() {
	local server
	for server in nginx apache caddy; do
		if state_installed "${server}"; then
			printf '%s' "${server}"
			return 0
		fi
	done
	return 0
}

# web_unit SERVER: systemd unit of a web server.
web_unit() {
	local server=$1
	case ${server} in
	apache) if os_is_debian; then printf 'apache2'; else printf 'httpd'; fi ;;
	*) printf '%s' "${server}" ;;
	esac
	return
}

# web_user SERVER: the account the web server's workers run as.
web_user() {
	local server=$1
	case ${server} in
	nginx) if os_is_debian; then printf 'www-data'; else printf 'nginx'; fi ;;
	apache) if os_is_debian; then printf 'www-data'; else printf 'apache'; fi ;;
	*) printf '%s' "${server}" ;;
	esac
	return
}

# web_conf_dir SERVER: directory with lss's configuration for that web server (sites/, admin/, snippets).
web_conf_dir() {
	local server=$1
	case ${server} in
	nginx) printf '/etc/nginx/lss' ;;
	apache) if os_is_debian; then printf '/etc/apache2/lss'; else printf '/etc/httpd/lss'; fi ;;
	*) printf '/etc/caddy/lss' ;;
	esac
	return
}

# web_log_dir SERVER: where the web server writes its access and error logs.
web_log_dir() {
	local server=$1
	case ${server} in
	apache) if os_is_debian; then printf '/var/log/apache2'; else printf '/var/log/httpd'; fi ;;
	*) printf '/var/log/%s' "${server}" ;;
	esac
	return
}

# web_log_file SERVER access|error: the access or error log of the web server (Apache on the RHEL family writes
# access_log and error_log).
web_log_file() {
	local server=$1 kind=$2
	if [[ ${server} == apache ]] && os_is_rhel; then
		printf '%s/%s_log' "$(web_log_dir "${server}")" "${kind}"
	else
		printf '%s/%s.log' "$(web_log_dir "${server}")" "${kind}"
	fi
	return
}

# web_group_ensure [USER...]: creates WEB_GROUP and adds the users to it.
web_group_ensure() {
	local user
	if ! getent group "${WEB_GROUP}" >/dev/null; then
		groupadd --system "${WEB_GROUP}"
		files_note_change "created group ${WEB_GROUP}"
	fi
	for user in "$@"; do
		getent passwd "${user}" >/dev/null || continue
		if ! id -nG "${user}" | tr ' ' '\n' | grep -qxF "${WEB_GROUP}"; then
			usermod --append --groups "${WEB_GROUP}" "${user}"
			files_note_change "added ${user} to ${WEB_GROUP}"
		fi
	done
	return
}

# True when the kernel has IPv6; web servers only listen on [::] then (kernel-hardening can switch it off).
web_ipv6() {
	[[ -f /proc/net/if_inet6 ]]
	return
}

# web_cert_dir NAME: the certificate directory for NAME, or the default certificate when NAME has none yet.
web_cert_dir() {
	local name=$1
	if [[ -s ${WEB_TLS_DIR}/${name}/fullchain.pem && -s ${WEB_TLS_DIR}/${name}/privkey.pem ]]; then
		printf '%s/%s' "${WEB_TLS_DIR}" "${name}"
	else
		printf '%s/default' "${WEB_TLS_DIR}"
	fi
	return
}

# web_cert_has_ocsp CERT: the certificate names an OCSP responder. Let's Encrypt stopped OCSP in 2025; stapling is
# switched on only for certificates that still have one, so the web servers log no warning about it.
web_cert_has_ocsp() {
	local cert=$1
	[[ -n $(openssl x509 -noout -ocsp_uri -in "${cert}" 2>/dev/null) ]]
	return
}

# web_default_cert: a self-signed certificate for the host name in WEB_TLS_DIR/default, so HTTPS answers before a
# real certificate exists. Renewed when it expires within 30 days; the key is readable by WEB_GROUP.
web_default_cert() {
	local dir="${WEB_TLS_DIR}/default" name tmp
	# The tls module's certificate for the host names (lineage "default") takes this place; certbot renews it.
	[[ ! -s ${WEB_CERT_LIVE}/default/fullchain.pem || ! -s ${dir}/fullchain.pem ]] || return 0
	if [[ -s ${dir}/fullchain.pem && -s ${dir}/privkey.pem ]] &&
		openssl x509 -checkend $((30 * 86400)) -noout -in "${dir}/fullchain.pem" >/dev/null 2>&1; then
		return 0
	fi
	name=$(hostname -f 2>/dev/null || hostname)
	tmp=$(mktemp -d)
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=${name}" \
		-addext "subjectAltName=DNS:${name}" -keyout "${tmp}/privkey.pem" -out "${tmp}/fullchain.pem" >/dev/null 2>&1 ||
		die "web: could not create the self-signed default certificate."
	install -d -m 0755 "${WEB_TLS_DIR}"
	# Certificates are state, not configuration: the tls module's deploy hook replaces them, so they are not
	# recorded as managed files (lss verify would report every renewal as a change made outside lss).
	install -d -m 0755 "${dir}"
	install -m 0640 -o root -g "${WEB_GROUP}" "${tmp}/privkey.pem" "${dir}/privkey.pem"
	install -m 0644 -o root -g root "${tmp}/fullchain.pem" "${dir}/fullchain.pem"
	files_note_change "self-signed default certificate"
	rm -rf -- "${tmp}"
	return
}

# web_cert_placeholder NAME: until NAME has a certificate of its own, its directory holds a copy of the default
# certificate, so a site can point at WEB_TLS_DIR/NAME from the start and keeps that path after the real one arrives.
web_cert_placeholder() {
	local name=$1 dir
	dir="${WEB_TLS_DIR}/${name}"
	[[ -s ${dir}/fullchain.pem && -s ${dir}/privkey.pem ]] && return 0
	install -d -m 0755 "${dir}"
	install -m 0644 -o root -g root "${WEB_TLS_DIR}/default/fullchain.pem" "${dir}/fullchain.pem"
	install -m 0640 -o root -g "${WEB_GROUP}" "${WEB_TLS_DIR}/default/privkey.pem" "${dir}/privkey.pem"
	files_note_change "placeholder certificate for ${name}"
	return
}

# web_cert_domains CERT: the DNS names of a certificate, sorted, one per line.
web_cert_domains() {
	local cert=$1
	openssl x509 -noout -ext subjectAltName -in "${cert}" 2>/dev/null | grep -oE 'DNS:[^,[:space:]]+' | cut -c 5- | sort -u
	return
}

# web_cert_issue NAME DOMAIN...: a certificate from the ACME server the tls module set up (/etc/letsencrypt/cli.ini:
# server, account, webroot), issued once and again only when the names change; certbot renews it, and the deploy
# hook copies it to WEB_TLS_DIR/NAME and reloads the web server.
web_cert_issue() {
	local name=$1 live wanted current
	shift
	live="${WEB_CERT_LIVE}/${name}/fullchain.pem"
	wanted=$(printf '%s\n' "$@" | sort -u)
	current=''
	[[ ! -s ${live} ]] || current=$(web_cert_domains "${live}")
	if [[ ${current} != "${wanted}" ]]; then
		local -a args=()
		local domain
		for domain in "$@"; do
			args+=(-d "${domain}")
		done
		local -a env=()
		[[ ! -s ${WEB_ACME_CA} ]] || env=("REQUESTS_CA_BUNDLE=${WEB_ACME_CA}")
		log_info "Requesting a certificate for $*"
		log_command env "${env[@]}" certbot certonly --cert-name "${name}" "${args[@]}" ||
			die "tls: the ACME server refused a certificate for $*; the names must resolve to this server and port 80 must be reachable."
		files_note_change "certificate ${name}"
	fi
	if ! cmp -s "${live}" "${WEB_TLS_DIR}/${name}/fullchain.pem"; then
		RENEWED_LINEAGE="${WEB_CERT_LIVE}/${name}" "${WEB_CERT_HOOK}"
		files_note_change "installed certificate ${name}"
	fi
	return
}

# web_prepare SERVER: what every web server needs before its configuration is written: the web group with the
# server's user in it, the default certificate, the ACME webroot and an empty default document root.
web_prepare() {
	local server=$1
	web_group_ensure "$(web_user "${server}")"
	web_default_cert
	install -d -m 0755 "${WEB_ACME_ROOT}" "${WEB_ACME_ROOT}/.well-known" "${WEB_ACME_ROOT}/.well-known/acme-challenge"
	install -d -m 0755 "${WEB_DEFAULT_ROOT}"
	install -d -m 0755 "$(web_conf_dir "${server}")" "$(web_conf_dir "${server}")/sites" "$(web_conf_dir "${server}")/admin"
	return
}

# web_test SERVER: checks the configuration; prints the problem and fails when it does not load.
web_test() {
	local server=$1 output
	case ${server} in
	nginx) output=$(nginx -t -q 2>&1) ;;
	apache) output=$(apachectl -t 2>&1) ;;
	*) output=$(caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1) ;;
	esac || {
		printf '%s\n' "${output}" >&2
		return 1
	}
	return 0
}

# web_reload: tests and reloads the installed web server after a site or admin path changed.
web_reload() {
	local server
	server=$(web_server)
	[[ -n ${server} ]] || return 0
	web_test "${server}" || die "web: the ${server} configuration does not load; see above."
	if svc_is_active "$(web_unit "${server}")"; then
		svc_reload "$(web_unit "${server}")"
	fi
	return
}

# web_headers SERVER: the security headers every HTTPS site sends.
web_headers() {
	local server=$1 header
	local -a headers=(
		'Strict-Transport-Security "max-age=63072000"'
		'X-Content-Type-Options "nosniff"'
		'X-Frame-Options "SAMEORIGIN"'
		'Referrer-Policy "strict-origin-when-cross-origin"'
		'Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"'
		'Cross-Origin-Opener-Policy "same-origin"'
	)
	for header in "${headers[@]}"; do
		case ${server} in
		nginx) printf '\tadd_header %s always;\n' "${header}" ;;
		apache) printf '\tHeader always set %s\n' "${header}" ;;
		*) printf '\t\t%s\n' "${header}" ;;
		esac
	done
	return
}

# True for nginx 1.25.1 and later, which takes "http2 on;" instead of the http2 flag on listen.
web_nginx_http2_directive() {
	local version
	version=$(nginx -v 2>&1 | sed -nE 's|.*nginx/([0-9]+\.[0-9]+\.[0-9]+).*|\1|p')
	[[ -n ${version} ]] || return 1
	printf '%s\n1.25.1\n' "${version}" | sort -V -C -r
	return
}

# web_nginx_ssl_flags: flags of an HTTPS listen line ("ssl" or "ssl http2" on nginx before 1.25.1).
web_nginx_ssl_flags() {
	if web_nginx_http2_directive; then printf 'ssl'; else printf 'ssl http2'; fi
	return
}

# _web_listen_nginx PORT [FLAGS]: listen lines for IPv4 and, when available, IPv6.
_web_listen_nginx() {
	local port=$1 flags=${2:-}
	printf '\tlisten %s%s;\n' "${port}" "${flags:+ ${flags}}"
	if web_ipv6; then
		printf '\tlisten [::]:%s%s;\n' "${port}" "${flags:+ ${flags}}"
	fi
	return
}

# _web_tls_nginx CERTDIR: certificate lines of an nginx server block.
_web_tls_nginx() {
	local dir=$1
	printf '\tssl_certificate %s/fullchain.pem;\n\tssl_certificate_key %s/privkey.pem;\n' "${dir}" "${dir}"
	if web_cert_has_ocsp "${dir}/fullchain.pem"; then
		printf '\tssl_stapling on;\n\tssl_stapling_verify on;\n'
	fi
	return
}

# _web_body_nginx KIND TARGET: what an nginx site serves (static files, PHP through PHP-FPM, or a proxied URL).
_web_body_nginx() {
	local kind=$1 target=$2
	case ${kind} in
	proxy)
		cat <<EOF
	location / {
		proxy_pass ${target};
		include /etc/nginx/lss/proxy.conf;
	}
EOF
		;;
	php)
		cat <<EOF
	root ${target};
	index index.php index.html;
	location / {
		try_files \$uri \$uri/ /index.php?\$query_string;
	}
	location ~ [^/]\\.php(/|\$) {
		fastcgi_split_path_info ^(.+?\\.php)(/.*)\$;
		try_files \$fastcgi_script_name =404;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
		fastcgi_param PATH_INFO \$fastcgi_path_info;
		fastcgi_param HTTPS on;
		fastcgi_pass unix:${WEB_PHP_SOCKET};
	}
	location ~ /\\.(?!well-known) {
		deny all;
	}
EOF
		;;
	*)
		cat <<EOF
	root ${target};
	index index.html;
	location / {
		try_files \$uri \$uri/ =404;
	}
	location ~ /\\.(?!well-known) {
		deny all;
	}
EOF
		;;
	esac
	return
}

# _web_site_nginx NAME KIND TARGET DOMAIN...
_web_site_nginx() {
	local name=$1 kind=$2 target=$3
	shift 3
	local domains="$*" cert
	cert=$(web_cert_dir "${name}")
	printf '# Managed by lss (site %s).\nserver {\n' "${name}"
	_web_listen_nginx 80
	printf '\tserver_name %s;\n' "${domains}"
	printf '\tlocation /.well-known/acme-challenge/ {\n\t\troot %s;\n\t}\n' "${WEB_ACME_ROOT}"
	# shellcheck disable=SC2016 # $host and $request_uri are nginx variables
	printf '\tlocation / {\n\t\treturn 301 https://$host$request_uri;\n\t}\n}\n\nserver {\n'
	_web_listen_nginx 443 "$(web_nginx_ssl_flags)"
	if web_nginx_http2_directive; then
		printf '\thttp2 on;\n'
	fi
	printf '\tserver_name %s;\n' "${domains}"
	_web_tls_nginx "${cert}"
	web_headers nginx
	printf '\taccess_log /var/log/nginx/access.log;\n'
	_web_body_nginx "${kind}" "${target}"
	printf '}\n'
	return
}

# _web_admin_nginx NAME PATH KIND TARGET: a location on the admin server.
_web_admin_nginx() {
	local name=$1 path=$2 kind=$3 target=$4
	printf '# Managed by lss (admin path of %s).\n' "${name}"
	if [[ ${kind} == proxy ]]; then
		cat <<EOF
location ^~ /${path}/ {
	proxy_pass ${target};
	include /etc/nginx/lss/proxy.conf;
	proxy_set_header X-Script-Name /${path};
}
EOF
	elif [[ ${kind} == strip ]]; then
		# A URI in proxy_pass replaces the matched /PATH/ prefix.
		cat <<EOF
location = /${path} {
	return 301 /${path}/;
}
location ^~ /${path}/ {
	proxy_pass ${target%/}/;
	include /etc/nginx/lss/proxy.conf;
}
EOF
	else
		cat <<EOF
location = /${path} {
	return 301 /${path}/;
}
location ^~ /${path}/ {
	alias ${target}/;
	index index.php;
	location ~ \\.php\$ {
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME \$request_filename;
		fastcgi_pass unix:${WEB_PHP_SOCKET};
	}
}
EOF
	fi
	return
}

# _web_body_apache KIND TARGET
_web_body_apache() {
	local kind=$1 target=$2
	case ${kind} in
	proxy)
		cat <<EOF
	ProxyPreserveHost On
	RequestHeader set X-Forwarded-Proto "https"
	ProxyPass / ${target%/}/ upgrade=websocket
	ProxyPassReverse / ${target%/}/
EOF
		;;
	*)
		cat <<EOF
	DocumentRoot ${target}
	<Directory ${target}>
		Options -Indexes +FollowSymLinks
		AllowOverride All
		Require all granted
	</Directory>
EOF
		if [[ ${kind} == php ]]; then
			cat <<EOF
	DirectoryIndex index.php index.html
	<FilesMatch "\\.php\$">
		SetHandler "proxy:unix:${WEB_PHP_SOCKET}|fcgi://localhost"
	</FilesMatch>
EOF
		fi
		;;
	esac
	return
}

# _web_site_apache NAME KIND TARGET DOMAIN...
_web_site_apache() {
	local name=$1 kind=$2 target=$3
	shift 3
	local first=$1 cert
	shift
	local aliases="$*"
	cert=$(web_cert_dir "${name}")
	cat <<EOF
# Managed by lss (site ${name}).
<VirtualHost *:80>
	ServerName ${first}
${aliases:+	ServerAlias ${aliases}
}	Alias /.well-known/acme-challenge/ ${WEB_ACME_ROOT}/.well-known/acme-challenge/
	RewriteEngine On
	RewriteCond %{REQUEST_URI} !^/\\.well-known/acme-challenge/
	RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>

<VirtualHost *:443>
	ServerName ${first}
${aliases:+	ServerAlias ${aliases}
}	Protocols h2 http/1.1
	SSLEngine on
	SSLCertificateFile ${cert}/fullchain.pem
	SSLCertificateKeyFile ${cert}/privkey.pem
EOF
	if web_cert_has_ocsp "${cert}/fullchain.pem"; then
		printf '\tSSLUseStapling on\n'
	fi
	web_headers apache
	printf '\tErrorLog %s\n\tCustomLog %s combined\n' "$(web_log_file apache error)" "$(web_log_file apache access)"
	_web_body_apache "${kind}" "${target}"
	printf '</VirtualHost>\n'
	return
}

# _web_admin_apache NAME PATH KIND TARGET
_web_admin_apache() {
	local name=$1 path=$2 kind=$3 target=$4
	printf '# Managed by lss (admin path of %s).\n' "${name}"
	if [[ ${kind} == proxy ]]; then
		cat <<EOF
<Location /${path}/>
	ProxyPass ${target%/}/${path}/ upgrade=websocket
	ProxyPassReverse ${target%/}/${path}/
	RequestHeader set X-Script-Name /${path}
</Location>
EOF
	elif [[ ${kind} == strip ]]; then
		cat <<EOF
RedirectMatch 301 ^/${path}\$ /${path}/
<Location /${path}/>
	ProxyPass ${target%/}/ upgrade=websocket
	ProxyPassReverse ${target%/}/
</Location>
EOF
	else
		cat <<EOF
Alias /${path} ${target}
<Directory ${target}>
	Options -Indexes +FollowSymLinks
	AllowOverride None
	Require all granted
	DirectoryIndex index.php
	<FilesMatch "\\.php\$">
		SetHandler "proxy:unix:${WEB_PHP_SOCKET}|fcgi://localhost"
	</FilesMatch>
</Directory>
EOF
	fi
	return
}

# _web_site_caddy NAME KIND TARGET DOMAIN...
_web_site_caddy() {
	local name=$1 kind=$2 target=$3
	shift 3
	local domains="$*" cert http_names='' https_names='' domain
	cert=$(web_cert_dir "${name}")
	for domain in ${domains}; do
		http_names+="http://${domain} "
		https_names+="https://${domain} "
	done
	printf '# Managed by lss (site %s).\n%s{\n' "${name}" "${http_names}"
	printf '\thandle /.well-known/acme-challenge/* {\n\t\troot * %s\n\t\tfile_server\n\t}\n' "${WEB_ACME_ROOT}"
	printf '\thandle {\n\t\tredir https://{host}{uri} permanent\n\t}\n}\n\n%s{\n' "${https_names}"
	printf '\ttls %s/fullchain.pem %s/privkey.pem\n\timport lss_tls_headers\n\timport lss_hidden\n\tlog\n' \
		"${cert}" "${cert}"
	case ${kind} in
	proxy) printf '\treverse_proxy %s\n' "${target}" ;;
	php) printf '\troot * %s\n\tphp_fastcgi unix/%s\n\tfile_server\n' "${target}" "${WEB_PHP_SOCKET}" ;;
	*) printf '\troot * %s\n\tfile_server\n' "${target}" ;;
	esac
	printf '}\n'
	return
}

# _web_admin_caddy NAME PATH KIND TARGET
_web_admin_caddy() {
	local name=$1 path=$2 kind=$3 target=$4
	printf '# Managed by lss (admin path of %s).\n' "${name}"
	if [[ ${kind} == proxy ]]; then
		printf 'handle /%s/* {\n\treverse_proxy %s {\n\t\theader_up X-Script-Name /%s\n\t}\n}\n' "${path}" "${target}" "${path}"
	elif [[ ${kind} == strip ]]; then
		printf 'redir /%s /%s/\nhandle_path /%s/* {\n\treverse_proxy %s\n}\n' "${path}" "${path}" "${path}" "${target}"
	else
		printf 'redir /%s /%s/\nhandle_path /%s/* {\n\troot * %s\n\tphp_fastcgi unix/%s\n\tfile_server\n}\n' \
			"${path}" "${path}" "${path}" "${target}" "${WEB_PHP_SOCKET}"
	fi
	return
}

# _web_name_check NAME: site and admin names become file names.
_web_name_check() {
	local name=$1
	[[ ${name} =~ ^[a-z0-9][a-z0-9.-]*$ ]] || die "web: '${name}' is not a valid site name."
	return
}

_web_ext() {
	local server=$1
	if [[ ${server} == caddy ]]; then printf 'caddy'; else printf 'conf'; fi
	return
}

# web_selinux_proxy: with SELinux enforcing, web servers may only connect to other ports once the boolean
# httpd_can_network_connect is on; sites and admin paths that proxy turn it on.
web_selinux_proxy() {
	command -v getsebool >/dev/null 2>&1 || return 0
	[[ $(getenforce 2>/dev/null) == Enforcing ]] || return 0
	if [[ $(getsebool httpd_can_network_connect 2>/dev/null) != *' on' ]]; then
		setsebool -P httpd_can_network_connect 1
		files_note_change "SELinux boolean httpd_can_network_connect"
	fi
	return
}

# web_site_write NAME static|php|proxy TARGET DOMAIN...: an HTTPS site for the installed web server, with HTTP
# redirected to HTTPS and the ACME challenge path served. TARGET is a document root or an upstream URL. Sets
# LSS_FILE_CHANGED; call web_reload afterwards.
web_site_write() {
	local name=$1 kind=$2 target=$3 server
	shift 3
	_web_name_check "${name}"
	server=$(web_server)
	[[ -n ${server} ]] || die "web: no web server is installed (nginx, apache or caddy)."
	[[ ${kind} != proxy ]] || web_selinux_proxy
	"_web_site_${server}" "${name}" "${kind}" "${target}" "$@" |
		file_write 0644 root:root "$(web_conf_dir "${server}")/sites/${name}.$(_web_ext "${server}")"
	return
}

web_site_remove() {
	local name=$1 server
	server=$(web_server)
	[[ -n ${server} ]] || return 0
	file_remove "$(web_conf_dir "${server}")/sites/${name}.$(_web_ext "${server}")"
	return
}

# web_admin_write NAME PATH php|proxy|strip TARGET: publishes an admin interface below /PATH/ on the admin server
# (WEB_ADMIN_PORT). TARGET is a directory with PHP files or an upstream URL. proxy passes the whole path on (the
# upstream serves below /PATH/), strip removes /PATH first (for upstreams that only serve their root, such as Netdata).
web_admin_write() {
	local name=$1 path=$2 kind=$3 target=$4 server
	_web_name_check "${name}"
	[[ ${path} =~ ^[a-z0-9-]+$ ]] || die "web: '${path}' is not a valid admin path."
	server=$(web_server)
	[[ -n ${server} ]] || die "web: no web server is installed (nginx, apache or caddy)."
	[[ ${kind} == php ]] || web_selinux_proxy
	"_web_admin_${server}" "${name}" "${path}" "${kind}" "${target}" |
		file_write 0644 root:root "$(web_conf_dir "${server}")/admin/${name}.$(_web_ext "${server}")"
	return
}

web_admin_remove() {
	local name=$1 server
	server=$(web_server)
	[[ -n ${server} ]] || return 0
	file_remove "$(web_conf_dir "${server}")/admin/${name}.$(_web_ext "${server}")"
	return
}

# web_php_fpm_units: the PHP-FPM units of the php module (php8.x-fpm on Debian and Ubuntu, php-fpm on the RHEL family).
web_php_fpm_units() {
	systemctl list-units --type=service --all --no-legend --plain '*php*fpm*' 2>/dev/null | awk '{ print $1 }'
	return
}

# _web_php_pool_value KEY: a setting (user, group) of the PHP-FPM pool on WEB_PHP_SOCKET, the php module's pool.
_web_php_pool_value() {
	local key=$1 file
	for file in /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf; do
		[[ -f ${file} ]] || continue
		grep -qE "^[[:space:]]*listen[[:space:]]*=[[:space:]]*${WEB_PHP_SOCKET}[[:space:]]*\$" "${file}" || continue
		sed -nE "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*([A-Za-z0-9_.-]+).*/\\1/p" "${file}" | head -n 1
		return 0
	done
	return 0
}

# web_php_pool_user: the user the PHP-FPM workers of the php module's pool run as, or nothing.
web_php_pool_user() {
	_web_php_pool_value user
	return
}

# web_php_pool_group: the group of the PHP-FPM pool on WEB_PHP_SOCKET, which reads the configuration of PHP
# applications; WEB_GROUP when the pool configuration does not name one.
web_php_pool_group() {
	local pool_user pool_group
	pool_user=$(_web_php_pool_value user)
	pool_group=$(_web_php_pool_value group)
	if [[ -z ${pool_group} && -n ${pool_user} ]]; then
		pool_group=$(id -gn "${pool_user}" 2>/dev/null || true)
	fi
	if [[ -z ${pool_group} ]] || ! getent group "${pool_group}" >/dev/null; then
		pool_group=${WEB_GROUP}
	fi
	printf '%s' "${pool_group}"
	return
}

# web_admin_htpasswd SERVER: the basic-auth file for a public admin server, user "admin" with the secret
# web-admin-password. SHA-512 crypt for nginx and apache, bcrypt for caddy in its own format (WEB_ADMIN_CADDY_AUTH).
web_admin_htpasswd() {
	local server=$1 password hash
	secret_load web-admin-password password 32
	if [[ ${server} == caddy ]]; then
		[[ -s ${WEB_ADMIN_CADDY_AUTH} ]] && return 0
		hash=$(caddy hash-password <<<"${password}" 2>/dev/null) || die "web: caddy could not hash the admin password."
		file_write 0640 "root:${WEB_GROUP}" "${WEB_ADMIN_CADDY_AUTH}" <<<"admin ${hash}"
		return 0
	fi
	if [[ -s ${WEB_ADMIN_HTPASSWD} ]] && [[ $(cut -d ':' -f 2- "${WEB_ADMIN_HTPASSWD}") == \$6\$* ]]; then
		return 0
	fi
	hash=$(openssl passwd -6 -stdin <<<"${password}") || die "web: openssl could not hash the admin password."
	file_write 0640 "root:${WEB_GROUP}" "${WEB_ADMIN_HTPASSWD}" <<<"admin:${hash}"
	return
}

# web_ids_configure: lets fail2ban or CrowdSec read the logs of the installed web server. Called by the web server
# modules and by fail2ban and crowdsec, whichever is installed last. A web server module counts while it is being
# installed, because its state is recorded only after it.
web_ids_configure() {
	local server logs
	server=$(web_server)
	case ${LSS_MODULE:-} in
	nginx | apache | caddy) server=${LSS_MODULE} ;;
	*) ;;
	esac
	if [[ -z ${server} ]]; then
		file_remove "${WEB_FAIL2BAN_JAIL}"
		file_remove "${WEB_FAIL2BAN_FILTER}"
		file_remove "${WEB_CROWDSEC_ACQUIS}"
		return 0
	fi
	logs=$(web_log_dir "${server}")
	install -d -m 0755 "${logs}"
	if state_installed fail2ban || [[ ${LSS_MODULE:-} == fail2ban ]]; then
		_web_fail2ban "${server}" "${logs}"
	fi
	if state_installed crowdsec || [[ ${LSS_MODULE:-} == crowdsec ]]; then
		_web_crowdsec "${server}" "${logs}"
	fi
	return
}

# web_ids_remove: drops the web server's jails and log acquisition (when the web server is removed).
web_ids_remove() {
	if [[ -e ${WEB_FAIL2BAN_JAIL} ]]; then
		file_remove "${WEB_FAIL2BAN_JAIL}"
		file_remove "${WEB_FAIL2BAN_FILTER}"
		if svc_is_active fail2ban; then
			svc_restart fail2ban
		fi
	fi
	if [[ -e ${WEB_CROWDSEC_ACQUIS} ]]; then
		file_remove "${WEB_CROWDSEC_ACQUIS}"
		if svc_is_active crowdsec; then
			svc_restart crowdsec
		fi
	fi
	return
}

# _web_fail2ban SERVER LOGDIR: jails for failed basic-auth logins and vulnerability scanners.
_web_fail2ban() {
	local server=$1 logs=$2 access error changed=0
	install -d -m 0755 "${logs}"
	access=$(web_log_file "${server}" access)
	error=$(web_log_file "${server}" error)
	[[ -e ${access} ]] || install -m 0640 /dev/null "${access}"
	[[ -e ${error} ]] || install -m 0640 /dev/null "${error}"
	case ${server} in
	nginx)
		file_write 0644 root:root "${WEB_FAIL2BAN_JAIL}" <<EOF
# Managed by lss (web server nginx).
[nginx-http-auth]
enabled = true
backend = auto
logpath = ${error}

[nginx-botsearch]
enabled = true
backend = auto
logpath = ${access}
EOF
		;;
	apache)
		file_write 0644 root:root "${WEB_FAIL2BAN_JAIL}" <<EOF
# Managed by lss (web server apache).
[apache-auth]
enabled = true
backend = auto
logpath = ${error}

[apache-botsearch]
enabled = true
backend = auto
logpath = ${access}
EOF
		;;
	*)
		file_write 0644 root:root "${WEB_FAIL2BAN_FILTER}" <<'EOF'
# Managed by lss (web server caddy). Caddy logs JSON; a 401 answer is a failed basic-auth login.
[Definition]
failregex = ^.*"remote_ip":"<HOST>".*"status":401\b
ignoreregex =
datepattern = "ts":{EPOCH}
EOF
		[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
		file_write 0644 root:root "${WEB_FAIL2BAN_JAIL}" <<EOF
# Managed by lss (web server caddy).
[lss-caddy-auth]
enabled = true
backend = auto
filter = lss-caddy-auth
logpath = ${access}
EOF
		;;
	esac
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	if [[ ${changed} == 1 ]] && svc_is_active fail2ban; then
		fail2ban-client --test >/dev/null 2>&1 || die "web: the fail2ban jails for ${server} do not load."
		svc_restart fail2ban
	fi
	return
}

# _web_crowdsec SERVER LOGDIR: the CrowdSec collection and log acquisition of the web server.
_web_crowdsec() {
	local server=$1 logs=$2 collection type changed=0
	local -a files=("$(web_log_file "${server}" access)")
	[[ -d ${logs} ]] || install -d -m 0755 "${logs}"
	case ${server} in
	nginx) collection=crowdsecurity/nginx type=nginx files+=("$(web_log_file nginx error)") ;;
	apache) collection=crowdsecurity/apache2 type=apache2 files+=("$(web_log_file apache error)") ;;
	*) collection=crowdsecurity/caddy type=caddy ;;
	esac
	if ! cscli collections list -o raw 2>/dev/null | cut -d ',' -f 1 | grep -qxF "${collection}"; then
		cscli collections install "${collection}" >/dev/null 2>&1 || die "web: CrowdSec could not install ${collection}."
		files_note_change "crowdsec collection ${collection}"
		changed=1
	fi
	{
		printf '# Managed by lss (web server %s).\nfilenames:\n' "${server}"
		printf '  - %s\n' "${files[@]}"
		printf 'labels:\n  type: %s\n' "${type}"
	} | file_write 0644 root:root "${WEB_CROWDSEC_ACQUIS}"
	[[ ${LSS_FILE_CHANGED} == 0 ]] || changed=1
	if [[ ${changed} == 1 ]] && svc_is_active crowdsec; then
		svc_restart crowdsec
	fi
	return
}
