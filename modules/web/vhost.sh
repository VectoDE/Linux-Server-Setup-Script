# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="vhost"
MOD_GROUP="web"
MOD_DESCRIPTION="Web sites for the installed web server: static files, PHP or a reverse proxy, HTTPS with a certificate per site"
MOD_REQUIRES="nginx|apache|caddy"
MOD_OPTIONS="sites||Sites, separated by spaces: NAME:static|php|proxy:DOMAIN[,DOMAIN...][:TARGET]. TARGET is the document root (default /var/www/NAME) or, for proxy, the backend URL such as http://127.0.0.1:3000. PHP sites need the php module, certificates the tls module"

VHOST_ROOT=/var/www

# _vhost_parse SPEC: sets VHOST_NAME, VHOST_KIND, VHOST_TARGET and VHOST_DOMAINS (array).
_vhost_parse() {
	local spec=$1 domains rest domain url
	IFS=':' read -r VHOST_NAME VHOST_KIND domains rest <<<"${spec}"
	[[ ${VHOST_NAME} =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "LSS_VHOST_SITES: '${spec}' does not start with a site name (a-z, 0-9, -)."
	case ${VHOST_KIND} in
	static | php)
		VHOST_TARGET=${rest:-${VHOST_ROOT}/${VHOST_NAME}}
		[[ ${VHOST_TARGET} =~ ^/[A-Za-z0-9._/-]+$ && ${VHOST_TARGET} != *..* ]] ||
			die "LSS_VHOST_SITES: '${VHOST_TARGET}' is not an absolute directory."
		;;
	proxy)
		VHOST_TARGET=${rest}
		url='^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$'
		[[ ${VHOST_TARGET} =~ ${url} ]] ||
			die "LSS_VHOST_SITES: the proxy site ${VHOST_NAME} needs a backend URL like http://127.0.0.1:3000."
		;;
	*) die "LSS_VHOST_SITES: '${VHOST_KIND}' in '${spec}' is not static, php or proxy." ;;
	esac
	IFS=',' read -ra VHOST_DOMAINS <<<"${domains}"
	((${#VHOST_DOMAINS[@]} > 0)) || die "LSS_VHOST_SITES: the site ${VHOST_NAME} has no domain."
	for domain in "${VHOST_DOMAINS[@]}"; do
		[[ ${domain} =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]] ||
			die "LSS_VHOST_SITES: '${domain}' is not a host name like www.example.com."
	done
	return
}

mod_check() {
	local spec
	local -A seen=()
	for spec in $(opt sites); do
		_vhost_parse "${spec}"
		[[ -z ${seen[${VHOST_NAME}]+x} ]] || die "LSS_VHOST_SITES: the site name ${VHOST_NAME} appears twice."
		seen[${VHOST_NAME}]=1
	done
	return
}

mod_install() {
	pkg_install curl openssl
	return
}

# A new document root gets a start page, so the site answers right away; existing content is never touched.
_vhost_docroot() {
	local name=$1 root=$2
	[[ -d ${root} ]] && return 0
	install -d -m 0755 "${root}"
	file_write 0644 root:root "${root}/index.html" <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${name}</title></head>
<body><h1>${name}</h1><p>This site is ready. Put its files into ${root}.</p></body></html>
EOF
	return
}

mod_configure() {
	local spec name previous current=''
	local -A wanted=()
	for spec in $(opt sites); do
		_vhost_parse "${spec}"
		[[ ${VHOST_KIND} != php ]] || state_installed php ||
			die "vhost: the site ${VHOST_NAME} runs PHP; install the php module first (lss install php)."
		[[ ${VHOST_KIND} == proxy ]] || _vhost_docroot "${VHOST_NAME}" "${VHOST_TARGET}"
		web_cert_placeholder "${VHOST_NAME}"
		web_site_write "${VHOST_NAME}" "${VHOST_KIND}" "${VHOST_TARGET}" "${VHOST_DOMAINS[@]}"
		wanted[${VHOST_NAME}]=1
		current+="${VHOST_NAME} "
	done
	# Sites that were removed from LSS_VHOST_SITES since the last run.
	previous=$(state_get vhost sites)
	for name in ${previous}; do
		[[ -n ${wanted[${name}]+x} ]] || web_site_remove "${name}"
	done
	state_set vhost sites "${current% }"
	if [[ $(files_changes_of vhost) != 0 ]]; then
		web_reload
	fi
	if state_installed tls; then
		for spec in $(opt sites); do
			_vhost_parse "${spec}"
			web_cert_issue "${VHOST_NAME}" "${VHOST_DOMAINS[@]}"
		done
	fi
	return
}

mod_verify() {
	local spec status served
	for spec in $(opt sites); do
		_vhost_parse "${spec}"
		[[ ${VHOST_KIND} == proxy || -d ${VHOST_TARGET} ]] || die "vhost: the document root ${VHOST_TARGET} is missing."
		# Any HTTP answer counts: a proxy site answers 502 while its backend is down, which is the backend's business.
		status=$(curl -ks --max-time 10 -o /dev/null -w '%{http_code}' \
			--resolve "${VHOST_DOMAINS[0]}:443:127.0.0.1" "https://${VHOST_DOMAINS[0]}/" || true)
		[[ ${status} =~ ^[1-5][0-9][0-9]$ ]] || die "vhost: https://${VHOST_DOMAINS[0]}/ does not answer on this server."
		served=$(openssl s_client -connect 127.0.0.1:443 -servername "${VHOST_DOMAINS[0]}" </dev/null 2>/dev/null |
			openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)
		[[ ${served} == "$(openssl x509 -noout -fingerprint -sha256 -in "${WEB_TLS_DIR}/${VHOST_NAME}/fullchain.pem")" ]] ||
			die "vhost: ${VHOST_DOMAINS[0]} is not served with the certificate in ${WEB_TLS_DIR}/${VHOST_NAME}."
	done
	return
}

# Document roots and their content stay; the configuration and certificates of the sites go.
mod_remove() {
	local name
	for name in $(state_get vhost sites); do
		web_site_remove "${name}"
		file_remove "${WEB_TLS_DIR}/${name}"
	done
	web_reload
	return
}
