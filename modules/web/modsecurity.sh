# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="modsecurity"
MOD_GROUP="web"
MOD_DESCRIPTION="ModSecurity web application firewall with the OWASP Core Rule Set for nginx or Apache (Caddy has no maintained ModSecurity connector)"
MOD_REQUIRES="apache|nginx"
MOD_OPTIONS="mode|On|On blocks attacks; DetectionOnly only logs them (to try the rules on a live site first)
paranoia|1|Paranoia level 1 to 4: higher levels catch more attacks and also block more legitimate requests
anomaly_inbound|5|Anomaly score from which a request is blocked (5: one critical rule matched; higher values block less)
exclusions||Rule exclusions for applications, separated by spaces: cpanel dokuwiki drupal nextcloud phpbb phpmyadmin wordpress xenforo (phpbb and phpmyadmin need CRS 4, which Apache on Ubuntu 22.04 does not get)
allowed_methods|GET HEAD POST OPTIONS PUT PATCH DELETE|HTTP methods the rules let through, separated by spaces
max_body||Largest request body ModSecurity accepts and inspects, for example 64m (at most 1g); empty takes max_body of the web server"

# Where the engine and the rules come from:
#   Apache  libapache2-mod-security2 (Debian, Ubuntu), mod_security (RHEL 9 AppStream, RHEL 10 EPEL).
#   nginx   libmodsecurity and the nginx connector, built by lss from checksum-verified sources on every system:
#           CRS 4.25.1 and 3.3.10 need libmodsecurity 3.0.16 (the fix against XML attribute injection), and the
#           distributions ship 3.0.6 to 3.0.14 (RHEL 10 none). The connector is a dynamic module (--with-compat)
#           for the installed nginx, built again only when the nginx version changes.
#   Rules   The OWASP Core Rule Set from its signed GitHub releases, pinned in data/checksums.txt, so every system
#           runs the same rules (the distributions ship CRS 3.3 of differing ages, RHEL 10 none). CRS 4 needs
#           ModSecurity 2.9.6 or 3.0.8; its long-term-support line 4.25 changes less between updates than the
#           monthly releases. Apache on Ubuntu 22.04 has ModSecurity 2.9.5 and therefore gets CRS 3.3, which is still
#           maintained.
MODSEC_CRS_VERSION=4.25.2
MODSEC_CRS_LEGACY_VERSION=3.3.10
MODSEC_LIB_VERSION=3.0.17
MODSEC_CONNECTOR_VERSION=1.0.4
# Below /usr/local/lib, so SELinux labels the self-built libraries as libraries.
MODSEC_PREFIX=/usr/local/lib/lss-modsecurity
MODSEC_CRS_ROOT=/usr/local/share/lss-modsecurity
MODSEC_PLUGINS="cpanel dokuwiki drupal nextcloud phpbb phpmyadmin wordpress xenforo"
MODSEC_LEGACY_EXCLUSIONS="cpanel dokuwiki drupal nextcloud wordpress xenforo"
# The web server modules serve this file on port 80 for every host name; verify sends its probes there.
MODSEC_PROBE=/.well-known/acme-challenge/lss-probe
MODSEC_BUILD_DEPS=()
MODSEC_WORK=''

# The web server ModSecurity is added to.
_modsecurity_server() {
	local server
	server=$(web_server)
	case ${server} in
	nginx | apache) printf '%s' "${server}" ;;
	*) die "modsecurity: needs nginx or Apache (Caddy has no maintained ModSecurity connector)." ;;
	esac
	return
}

# True for Apache on Ubuntu 22.04, whose ModSecurity 2.9.5 is too old for CRS 4.
_modsecurity_legacy() {
	[[ ${OS_ID} == ubuntu && ${OS_MAJOR} == 22 && $(web_server) == apache ]]
	return
}

_modsecurity_crs_version() {
	if _modsecurity_legacy; then printf '%s' "${MODSEC_CRS_LEGACY_VERSION}"; else printf '%s' "${MODSEC_CRS_VERSION}"; fi
	return
}

_modsecurity_crs_dir() {
	printf '%s/coreruleset-%s' "${MODSEC_CRS_ROOT}" "$(_modsecurity_crs_version)"
	return
}

# _modsecurity_conf_dir SERVER: lss's ModSecurity settings, next to the web server's other lss files.
_modsecurity_conf_dir() {
	local server=$1
	printf '%s/modsecurity' "$(web_conf_dir "${server}")"
	return
}

# _modsecurity_audit_log SERVER: in a directory of its own below the web server's logs, so SELinux allows the web
# server to write it and the distribution's logrotate rule for *.log (which only signals nginx) leaves it alone.
_modsecurity_audit_log() {
	local server=$1
	printf '%s/modsecurity/audit.log' "$(web_log_dir "${server}")"
	return
}

# Persistent collections of ModSecurity 2 (the directory the packages create).
_modsecurity_data_dir() {
	if os_is_debian; then printf '/var/cache/modsecurity'; else printf '/var/lib/mod_security'; fi
	return
}

_modsecurity_mode() {
	local mode
	mode=$(opt mode)
	case ${mode,,} in
	on) printf 'On' ;;
	detectiononly) printf 'DetectionOnly' ;;
	*) die "LSS_MODSECURITY_MODE must be On or DetectionOnly, got '${mode}'." ;;
	esac
	return
}

_modsecurity_max_body() {
	local value server
	value=$(opt max_body)
	if [[ -z ${value} ]]; then
		server=$(web_server)
		value=$(config_option "${server:-nginx}" max_body 64m)
	fi
	printf '%s' "${value}"
	return
}

# _modsecurity_bytes SIZE: 64m -> bytes, at most 1 GiB (the largest body ModSecurity 2 accepts).
_modsecurity_bytes() {
	local size=$1 number unit bytes
	number=${size%[kKmMgG]}
	unit=${size#"${number}"}
	case ${unit,,} in
	k) bytes=$((10#${number} * 1024)) ;;
	m) bytes=$((10#${number} * 1048576)) ;;
	g) bytes=$((10#${number} * 1073741824)) ;;
	*) bytes=$((10#${number})) ;;
	esac
	((bytes <= 1073741824)) || bytes=1073741824
	printf '%s' "${bytes}"
	return
}

_modsecurity_wanted() {
	local name=$1
	[[ " $(opt exclusions) " == *" ${name} "* ]]
	return
}

_modsecurity_nginx_so() {
	printf '%s/nginx/ngx_http_modsecurity_module.so' "${MODSEC_PREFIX}"
	return
}

_modsecurity_nginx_version() {
	nginx -v 2>&1 | sed -nE 's|.*nginx/([0-9]+\.[0-9]+\.[0-9]+).*|\1|p'
	return
}

# What the self-built nginx connector was built for; a different value means building it again.
_modsecurity_connector_id() {
	printf 'nginx %s, connector %s, libmodsecurity %s' "$(_modsecurity_nginx_version)" "${MODSEC_CONNECTOR_VERSION}" \
		"${MODSEC_LIB_VERSION}"
	return
}

# _modsecurity_json SERVER: true when the engine was built with YAJL, which parses JSON request bodies and writes the
# JSON audit log. RHEL 10 has no YAJL; ModSecurity there cannot split JSON bodies into arguments and logs natively.
_modsecurity_json() {
	local server=$1 engine
	if [[ ${server} == nginx ]]; then
		engine=$(_modsecurity_nginx_so)
	elif os_is_debian; then
		engine=/usr/lib/apache2/modules/mod_security2.so
	else
		engine=/usr/lib64/httpd/modules/mod_security2.so
	fi
	ldd "${engine}" 2>/dev/null | grep -q 'libyajl'
	return
}

_modsecurity_restorecon() {
	local path=$1
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -RF "${path}" 2>/dev/null || true
	fi
	return
}

# A private build directory below /var/tmp (sources and objects need more room than a tmpfs /tmp may have), deleted
# when the step ends.
_modsecurity_workdir() {
	[[ -z ${MODSEC_WORK} ]] || return 0
	MODSEC_WORK=$(mktemp -d /var/tmp/lss-modsecurity.XXXXXX)
	# shellcheck disable=SC2064 # the path is fixed now
	trap "rm -rf -- '${MODSEC_WORK}'" EXIT
	return
}

# CodeReady Builder holds nginx-mod-devel (the nginx sources for modules).
_modsecurity_crb_repo() {
	if [[ ${OS_ID} == rhel ]]; then
		printf 'codeready-builder-for-rhel-%s-%s-rpms' "${OS_MAJOR}" "$(uname -m)"
	else
		printf 'crb'
	fi
	return
}

# _modsecurity_build_deps PACKAGE...: installs build packages and remembers the ones that were missing, so
# _modsecurity_build_cleanup removes exactly those again. On the RHEL family CodeReady Builder is switched on for
# this transaction only.
_modsecurity_build_deps() {
	local -a missing=()
	mapfile -t missing < <(pkg_missing "$@")
	[[ ${#missing[@]} -gt 0 ]] || return 0
	MODSEC_BUILD_DEPS+=("${missing[@]}")
	if os_is_debian; then
		pkg_install "${missing[@]}"
	else
		log_info "Installing ${missing[*]}"
		log_command dnf -y -q --enablerepo="$(_modsecurity_crb_repo)" install "${missing[@]}" ||
			die "modsecurity: cannot install the build packages ${missing[*]}."
		files_note_change "installed ${missing[*]}"
	fi
	return
}

_modsecurity_build_cleanup() {
	[[ ${#MODSEC_BUILD_DEPS[@]} -eq 0 ]] || pkg_remove "${MODSEC_BUILD_DEPS[@]}"
	MODSEC_BUILD_DEPS=()
	return
}

# Parallel compiler runs, limited by memory: a single libmodsecurity file needs about 1.5 GiB.
_modsecurity_jobs() {
	local cpus memory jobs
	cpus=$(nproc)
	memory=$(awk '/^MemAvailable:/ { print int($2 / 1572864) }' /proc/meminfo)
	jobs=$((memory < cpus ? memory : cpus))
	((jobs >= 1)) || jobs=1
	printf '%s' "${jobs}"
	return
}

# libmodsecurity for nginx. Without curl, GeoIP, LMDB, Lua and ssdeep: the Core Rule Set needs none of them. With YAJL
# (JSON request bodies) where the distribution has it; RHEL 10 has none. Built again only for a new version.
# _modsecurity_deb_candidate PACKAGE...: the first of the names apt can install. Runtime libraries change their name
# with a new ABI (libxml2 is libxml2-16 from Ubuntu 26.04 on).
_modsecurity_deb_candidate() {
	local package candidate
	for package in "$@"; do
		candidate=$(apt-cache policy "${package}" 2>/dev/null | awk '$1 == "Candidate:" { print $2 }')
		if [[ -n ${candidate} && ${candidate} != '(none)' ]]; then
			printf '%s' "${package}"
			return 0
		fi
	done
	die "modsecurity: apt offers none of $*."
	return
}

_modsecurity_build_library() {
	local stamp="${MODSEC_PREFIX}/.libmodsecurity" src yajl=--without-yajl
	if [[ -f ${MODSEC_PREFIX}/lib/libmodsecurity.so.3 && -f ${stamp} && $(<"${stamp}") == "${MODSEC_LIB_VERSION}" ]]; then
		return 0
	fi
	# The runtime libraries first, so removing the build packages afterwards keeps them.
	if os_is_debian; then
		pkg_update_once
		pkg_install libpcre2-8-0 "$(_modsecurity_deb_candidate libxml2-16 libxml2)" libyajl2
		_modsecurity_build_deps g++ make pkg-config libpcre2-dev libxml2-dev libyajl-dev
		yajl=--with-yajl
	else
		pkg_install pcre2 libxml2
		_modsecurity_build_deps gcc-c++ make pkgconf-pkg-config pcre2-devel libxml2-devel
	fi
	_modsecurity_workdir
	fetch_verified "libmodsecurity-${MODSEC_LIB_VERSION}" "${MODSEC_WORK}/libmodsecurity.tar.gz"
	tar -xzf "${MODSEC_WORK}/libmodsecurity.tar.gz" -C "${MODSEC_WORK}" --no-same-owner
	src="${MODSEC_WORK}/modsecurity-v${MODSEC_LIB_VERSION}"
	log_info "Building libmodsecurity ${MODSEC_LIB_VERSION}; this takes a few minutes"
	(cd "${src}" && log_command ./configure --prefix="${MODSEC_PREFIX}" --disable-static --disable-examples \
		--disable-doxygen-doc --with-pcre2 --without-curl --without-geoip --without-maxmind --without-lmdb \
		--without-lua --without-ssdeep "${yajl}") || die "modsecurity: libmodsecurity does not configure; see the log."
	log_command make -C "${src}" -j "$(_modsecurity_jobs)" || die "modsecurity: libmodsecurity does not build; see the log."
	log_command make -C "${src}" install-strip || die "modsecurity: libmodsecurity does not install; see the log."
	printf '%s\n' "${MODSEC_LIB_VERSION}" >"${stamp}"
	_modsecurity_restorecon "${MODSEC_PREFIX}"
	files_note_change "built libmodsecurity ${MODSEC_LIB_VERSION}"
	return
}

# The nginx connector as a dynamic module for the installed nginx: from the nginx.org sources of that version on
# Debian and Ubuntu (verified by data/checksums.txt), from nginx-mod-devel on the RHEL family. --with-compat makes it
# load into the distribution's nginx, which is built with the same switch.
_modsecurity_build_connector() {
	local so="${MODSEC_PREFIX}/nginx/ngx_http_modsecurity_module.so" stamp="${MODSEC_PREFIX}/nginx/.build"
	local version src tree
	local -a env=("MODSECURITY_INC=${MODSEC_PREFIX}/include" "MODSECURITY_LIB=${MODSEC_PREFIX}/lib")
	if [[ -f ${so} && -f ${stamp} && $(<"${stamp}") == "$(_modsecurity_connector_id)" ]]; then
		return 0
	fi
	if os_is_debian; then
		_modsecurity_build_deps gcc make libc6-dev libpcre2-dev zlib1g-dev
	else
		# nginx-mod-devel requires the nginx of its own release and may update nginx; the version is read afterwards.
		_modsecurity_build_deps gcc make pcre2-devel zlib-devel nginx-mod-devel
	fi
	version=$(_modsecurity_nginx_version)
	[[ -n ${version} ]] || die "modsecurity: cannot read the version of nginx."
	_modsecurity_workdir
	fetch_verified "modsecurity-nginx-${MODSEC_CONNECTOR_VERSION}" "${MODSEC_WORK}/connector.tar.gz"
	tar -xzf "${MODSEC_WORK}/connector.tar.gz" -C "${MODSEC_WORK}" --no-same-owner
	if os_is_debian; then
		fetch_verified "nginx-${version}" "${MODSEC_WORK}/nginx.tar.gz"
		tar -xzf "${MODSEC_WORK}/nginx.tar.gz" -C "${MODSEC_WORK}" --no-same-owner
		src="${MODSEC_WORK}/nginx-${version}"
	else
		tree=$(rpm -E '%{_nginx_srcdir}')
		[[ -f ${tree}/configure ]] || die "modsecurity: nginx-mod-devel has no nginx sources in ${tree}."
		[[ $(rpm -E '%{_nginx_abiversion}') == "${version}" ]] ||
			die "modsecurity: nginx-mod-devel is for nginx $(rpm -E '%{_nginx_abiversion}'), but nginx ${version} is installed."
		src="${MODSEC_WORK}/nginx-src"
		cp -a "${tree}" "${src}"
	fi
	log_info "Building the ModSecurity module for nginx ${version}"
	(cd "${src}" && log_command env "${env[@]}" sh ./configure --with-compat \
		--add-dynamic-module="${MODSEC_WORK}/ModSecurity-nginx-v${MODSEC_CONNECTOR_VERSION}" \
		--with-cc-opt='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-z,relro -Wl,-z,now') ||
		die "modsecurity: the nginx module does not configure; see the log."
	log_command make -C "${src}" -j "$(_modsecurity_jobs)" modules || die "modsecurity: the nginx module does not build; see the log."
	# A new file and a rename: a running nginx keeps the old module mapped.
	install -d -m 0755 "${MODSEC_PREFIX}/nginx"
	install -m 0644 "${src}/objs/ngx_http_modsecurity_module.so" "${so}.new"
	mv -f -- "${so}.new" "${so}"
	printf '%s\n' "$(_modsecurity_connector_id)" >"${stamp}"
	_modsecurity_restorecon "${MODSEC_PREFIX}"
	files_note_change "built the ModSecurity module for nginx ${version}"
	return
}

_modsecurity_install_apache() {
	if os_is_debian; then
		pkg_install libapache2-mod-security2
	else
		# RHEL 10 has mod_security only in EPEL.
		[[ ${OS_MAJOR} -lt 10 ]] || pkg_enable_epel
		pkg_install mod_security
	fi
	return
}

_modsecurity_install_nginx() {
	# Packages of earlier lss versions: their module would be loaded next to the self-built one.
	pkg_remove_family "libnginx-mod-http-modsecurity" "nginx-mod-modsecurity"
	_modsecurity_build_library
	_modsecurity_build_connector
	return
}

# The Core Rule Set below MODSEC_CRS_ROOT, one directory per version; configure removes older ones.
_modsecurity_crs_install() {
	local version dir staging
	version=$(_modsecurity_crs_version)
	dir=$(_modsecurity_crs_dir)
	[[ ! -f ${dir}/rules/REQUEST-949-BLOCKING-EVALUATION.conf ]] || return 0
	_modsecurity_workdir
	fetch_verified "coreruleset-${version}" "${MODSEC_WORK}/coreruleset.tar.gz"
	install -d -m 0755 "${MODSEC_CRS_ROOT}"
	staging=$(mktemp -d "${MODSEC_CRS_ROOT}/.staging.XXXXXX")
	tar -xzf "${MODSEC_WORK}/coreruleset.tar.gz" -C "${staging}" --no-same-owner --no-same-permissions
	[[ -f ${staging}/coreruleset-${version}/rules/REQUEST-949-BLOCKING-EVALUATION.conf ]] ||
		die "modsecurity: the Core Rule Set archive has an unexpected layout."
	chmod -R u=rwX,go=rX "${staging}/coreruleset-${version}"
	rm -rf -- "${dir}"
	mv -- "${staging}/coreruleset-${version}" "${dir}"
	rm -rf -- "${staging}"
	_modsecurity_restorecon "${MODSEC_CRS_ROOT}"
	files_note_change "OWASP Core Rule Set ${version}"
	return
}

mod_check() {
	local name size
	_modsecurity_mode >/dev/null
	[[ $(opt paranoia) =~ ^[1-4]$ ]] || die "LSS_MODSECURITY_PARANOIA must be 1, 2, 3 or 4, got '$(opt paranoia)'."
	[[ $(opt anomaly_inbound) =~ ^[1-9][0-9]{0,3}$ ]] ||
		die "LSS_MODSECURITY_ANOMALY_INBOUND must be a number from 1 to 9999, got '$(opt anomaly_inbound)'."
	for name in $(opt exclusions); do
		[[ " ${MODSEC_PLUGINS} " == *" ${name} "* ]] ||
			die "LSS_MODSECURITY_EXCLUSIONS: '${name}' is unknown; available: ${MODSEC_PLUGINS}."
	done
	[[ -n $(opt allowed_methods) ]] || die "LSS_MODSECURITY_ALLOWED_METHODS is empty."
	for name in $(opt allowed_methods); do
		[[ ${name} =~ ^[A-Z][A-Z-]*$ ]] || die "LSS_MODSECURITY_ALLOWED_METHODS: '${name}' is not an HTTP method."
	done
	size=$(_modsecurity_max_body)
	[[ ${size} =~ ^[0-9]+[kKmMgG]?$ ]] || die "LSS_MODSECURITY_MAX_BODY '${size}' is not a size like 64m or 1g."
	return
}

mod_install() {
	local server
	server=$(_modsecurity_server)
	pkg_install curl logrotate
	if [[ ${server} == apache ]]; then
		_modsecurity_install_apache
	else
		_modsecurity_install_nginx
	fi
	_modsecurity_build_cleanup
	_modsecurity_crs_install
	return
}

# _modsecurity_engine_conf SERVER: the engine settings after modsecurity.conf-recommended of ModSecurity, limited to
# what the oldest engine in use understands (2.9.5 for Apache on Ubuntu 22.04).
_modsecurity_engine_conf() {
	local server=$1 bytes nofiles json=0 modern=1
	bytes=$(_modsecurity_bytes "$(_modsecurity_max_body)")
	# Bodies without uploads (forms, JSON) up to 1 MiB: the recommended 128 KiB turns away ordinary JSON documents.
	nofiles=$((bytes < 1048576 ? bytes : 1048576))
	if _modsecurity_json "${server}"; then
		json=1
	fi
	if _modsecurity_legacy; then
		modern=0
	fi
	printf '# Managed by lss (module modsecurity). Engine settings after modsecurity.conf-recommended.\n'
	printf 'SecRuleEngine %s\nSecRequestBodyAccess On\n' "$(_modsecurity_mode)"
	cat <<'EOF'
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
EOF
	if [[ ${json} == 1 ]]; then
		cat <<'EOF'
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
EOF
		if [[ ${server} == apache || ${modern} == 1 ]]; then
			printf 'SecRequestBodyJsonDepthLimit 512\n'
		fi
	fi
	printf 'SecRequestBodyLimit %s\nSecRequestBodyNoFilesLimit %s\nSecRequestBodyLimitAction Reject\n' "${bytes}" "${nofiles}"
	if [[ ${server} == nginx && ${modern} == 1 ]]; then
		cat <<'EOF'
SecArgumentsLimit 1000
SecRule &ARGS "@ge 1000" "id:'200007',phase:2,t:none,log,deny,status:400,msg:'Failed to fully parse request body due to large argument count',severity:2"
EOF
	fi
	cat <<'EOF'
SecRule REQBODY_ERROR "!@eq 0" "id:'200002',phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:'200003',phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation: PE %{REQBODY_PROCESSOR_ERROR}, BQ %{MULTIPART_BOUNDARY_QUOTED}, BW %{MULTIPART_BOUNDARY_WHITESPACE}, DB %{MULTIPART_DATA_BEFORE}, DA %{MULTIPART_DATA_AFTER}, HF %{MULTIPART_HEADER_FOLDING}, LF %{MULTIPART_LF_LINE}, SM %{MULTIPART_MISSING_SEMICOLON}, IQ %{MULTIPART_INVALID_QUOTING}, IP %{MULTIPART_INVALID_PART}, IH %{MULTIPART_INVALID_HEADER_FOLDING}, FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"
SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" "id:'200004',phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000
SecRule TX:/^MSC_/ "!@streq 0" "id:'200005',phase:2,t:none,log,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial
EOF
	if [[ ${server} == apache ]]; then
		printf 'SecTmpDir /tmp/\nSecDataDir %s\n' "$(_modsecurity_data_dir)"
	fi
	# Transactions with rule matches or errors (404 aside), without the bodies: they carry passwords and personal data.
	cat <<'EOF'
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABFHZ
SecAuditLogType Serial
EOF
	printf 'SecAuditLog %s\n' "$(_modsecurity_audit_log "${server}")"
	if [[ ${json} == 1 ]]; then
		printf 'SecAuditLogFormat JSON\n'
	fi
	printf 'SecArgumentSeparator &\nSecCookieFormat 0\nSecStatusEngine Off\n'
	return
}

# The CRS settings that crs-setup.conf.example of the release documents; everything else keeps its default.
_modsecurity_crs_setup() {
	local version tag='' paranoia=tx.blocking_paranoia_level phase name exclusions=''
	local -a methods=()
	version=$(_modsecurity_crs_version)
	read -ra methods <<<"$(opt allowed_methods)"
	printf '# Managed by lss (module modsecurity). OWASP CRS %s settings.\n' "${version}"
	if _modsecurity_legacy; then
		paranoia=tx.paranoia_level
		printf 'SecDefaultAction "phase:%s,log,auditlog,pass"\n' 1 2
		for name in $(opt exclusions); do
			if [[ " ${MODSEC_LEGACY_EXCLUSIONS} " == *" ${name} "* ]]; then
				exclusions+=",setvar:tx.crs_exclusions_${name}=1"
			fi
		done
	else
		tag=",tag:'OWASP_CRS',ver:'OWASP_CRS/${version}'"
		for phase in 1 2 3 4 5; do
			printf 'SecDefaultAction "phase:%s,log,auditlog,pass"\n' "${phase}"
		done
	fi
	printf 'SecAction "id:900000,phase:1,pass,t:none,nolog%s,setvar:%s=%s"\n' "${tag}" "${paranoia}" "$(opt paranoia)"
	printf 'SecAction "id:900110,phase:1,pass,t:none,nolog%s,setvar:tx.inbound_anomaly_score_threshold=%s,setvar:tx.outbound_anomaly_score_threshold=4"\n' \
		"${tag}" "$(opt anomaly_inbound)"
	if [[ -n ${exclusions} ]]; then
		printf 'SecAction "id:900130,phase:1,pass,t:none,nolog%s"\n' "${exclusions}"
	fi
	printf "SecAction \"id:900200,phase:1,pass,t:none,nolog%s,setvar:'tx.allowed_methods=%s'\"\n" "${tag}" "${methods[*]}"
	printf 'SecAction "id:900990,phase:1,pass,t:none,nolog%s,setvar:tx.crs_setup_version=%s"\n' "${tag}" "${version//./}"
	return
}

# CRS 4 ships the application exclusions as plugins, one repository each without release files; data/checksums.txt
# pins their files by commit. CRS 3.3 has them built in (crs-setup.conf switches them on).
_modsecurity_plugins() {
	local dir=$1 name kind file entry
	if _modsecurity_legacy; then
		file_remove "${dir}/plugins"
		for name in $(opt exclusions); do
			[[ " ${MODSEC_LEGACY_EXCLUSIONS} " == *" ${name} "* ]] ||
				log_warn "modsecurity: CRS 3.3 (Apache on Ubuntu 22.04) has no rule exclusions for ${name}; skipped."
		done
		return 0
	fi
	install -d -m 0755 "${dir}/plugins"
	for name in ${MODSEC_PLUGINS}; do
		for kind in config before after; do
			file="${dir}/plugins/${name}-rule-exclusions-${kind}.conf"
			entry=$(fetch_entry "crs-plugin-${name}-${kind}") || entry=''
			if [[ -z ${entry} ]] || ! _modsecurity_wanted "${name}"; then
				file_remove "${file}"
				continue
			fi
			if [[ -f ${file} && $(sha256sum "${file}" | cut -d ' ' -f 1) == "${entry%% *}" ]]; then
				continue
			fi
			_modsecurity_workdir
			fetch_verified "crs-plugin-${name}-${kind}" "${MODSEC_WORK}/${name}-${kind}.conf"
			file_write 0644 root:root "${file}" <"${MODSEC_WORK}/${name}-${kind}.conf"
		done
	done
	return
}

_modsecurity_plugin_includes() {
	local dir=$1 kind=$2 file
	for file in "${dir}/plugins/"*"-rule-exclusions-${kind}.conf"; do
		if [[ -f ${file} ]]; then
			printf 'Include %s\n' "${file}"
		fi
	done
	return
}

# The order CRS documents: engine, CRS setup, plugin settings, plugin rules before CRS, CRS, plugin rules after CRS.
# Every file is named, because ModSecurity 3 has no IncludeOptional for patterns without a match.
_modsecurity_main_conf() {
	local dir=$1
	printf '# Managed by lss (module modsecurity). ModSecurity with the OWASP Core Rule Set %s.\n' "$(_modsecurity_crs_version)"
	printf 'Include %s\n' "${dir}/modsecurity.conf" "${dir}/crs-setup.conf"
	_modsecurity_plugin_includes "${dir}" config
	_modsecurity_plugin_includes "${dir}" before
	find "$(_modsecurity_crs_dir)/rules" -maxdepth 1 -type f -name '*.conf' | LC_ALL=C sort | sed 's/^/Include /'
	_modsecurity_plugin_includes "${dir}" after
	return
}

# copytruncate: nginx and Apache keep the audit log open, and the reopen signal of nginx's own logrotate rule does not
# reach ModSecurity.
_modsecurity_logrotate() {
	local log=$1
	cat <<EOF
# Managed by lss (module modsecurity). The ModSecurity audit log.
${log} {
	daily
	rotate 14
	missingok
	notifempty
	compress
	delaycompress
	copytruncate
}
EOF
	return
}

# Apache: the package's own configuration file (security2.conf, mod_security.conf) loads lss's settings instead of
# the package defaults, so no second copy of any rules can come in through it.
_modsecurity_apache_file() {
	if os_is_debian; then printf '/etc/apache2/mods-available/security2.conf'; else printf '/etc/httpd/conf.d/mod_security.conf'; fi
	return
}

_modsecurity_apache_enable() {
	local dir=$1
	file_write 0644 root:root "$(_modsecurity_apache_file)" <<EOF
# Managed by lss (module modsecurity). Settings and rules: ${dir}.
<IfModule security2_module>
	Include ${dir}/main.conf
</IfModule>
EOF
	if os_is_debian && ! a2query -q -m security2 2>/dev/null; then
		a2enmod -q security2 >/dev/null
		files_note_change "apache module security2"
	fi
	return
}

# nginx: the module is loaded at the top of nginx.conf (by the distribution's module directory or, for a self-built
# module, by /etc/nginx/lss/modules) and switched on for every server in http{} (/etc/nginx/lss/http).
_modsecurity_nginx_enable() {
	local dir=$1 so modules
	grep -qF '/etc/nginx/lss/http/' /etc/nginx/nginx.conf ||
		die "modsecurity: /etc/nginx/nginx.conf does not include /etc/nginx/lss/http; run 'lss install nginx' with this lss version first."
	so=$(_modsecurity_nginx_so)
	[[ -f ${so} ]] || die "modsecurity: the nginx module ${so} is missing."
	if os_is_debian; then modules=/etc/nginx/modules-enabled; else modules=/usr/share/nginx/modules; fi
	! grep -qs 'ngx_http_modsecurity_module' "${modules}"/*.conf ||
		die "modsecurity: ${modules} still loads another ModSecurity module for nginx."
	file_write 0644 root:root /etc/nginx/lss/modules/modsecurity.conf <<EOF
# Managed by lss (module modsecurity).
load_module ${so};
EOF
	file_write 0644 root:root /etc/nginx/lss/http/modsecurity.conf <<EOF
# Managed by lss (module modsecurity). Settings and rules: ${dir}.
modsecurity on;
modsecurity_rules_file ${dir}/main.conf;
EOF
	return
}

# Removes Core Rule Set versions that are no longer in use.
_modsecurity_crs_prune() {
	local keep old
	keep=$(_modsecurity_crs_dir)
	for old in "${MODSEC_CRS_ROOT}"/coreruleset-*; do
		[[ -d ${old} && ${old} != "${keep}" ]] || continue
		rm -rf -- "${old}"
		files_note_change "removed ${old}"
	done
	return
}

mod_configure() {
	local server dir unit log installed restart=0
	server=$(_modsecurity_server)
	dir=$(_modsecurity_conf_dir "${server}")
	unit=$(web_unit "${server}")
	log=$(_modsecurity_audit_log "${server}")
	# Packages, builds and rules from mod_install in this run bring a new module: restart. Settings alone: reload.
	installed=$(files_changes_of modsecurity)
	if os_is_debian; then
		install -d -m 0750 -o root -g adm "$(dirname "${log}")"
	else
		install -d -m 0700 -o root -g root "$(dirname "${log}")"
	fi
	_modsecurity_restorecon "$(dirname "${log}")"
	install -d -m 0755 "${dir}"
	file_write 0644 root:root "${dir}/modsecurity.conf" < <(_modsecurity_engine_conf "${server}")
	file_write 0644 root:root "${dir}/crs-setup.conf" < <(_modsecurity_crs_setup)
	_modsecurity_plugins "${dir}"
	file_write 0644 root:root "${dir}/main.conf" < <(_modsecurity_main_conf "${dir}")
	file_write 0644 root:root /etc/logrotate.d/lss-modsecurity < <(_modsecurity_logrotate "${log}")
	if [[ ${server} == apache ]]; then
		_modsecurity_apache_enable "${dir}"
		# Under the sandbox of the apache module /var is read-only; ModSecurity 2 writes its collections here.
		[[ -d $(_modsecurity_data_dir) ]] || install -d -m 0750 -o "$(web_user apache)" -g root "$(_modsecurity_data_dir)"
		svc_dropin "${unit}.service" lss-modsecurity < <(printf '# Managed by lss (module modsecurity).\n[Service]\nReadWritePaths=-%s\n' "$(_modsecurity_data_dir)")
		[[ ${LSS_FILE_CHANGED} == 0 ]] || restart=1
	else
		_modsecurity_nginx_enable "${dir}"
	fi
	web_test "${server}" || die "modsecurity: the ${server} configuration does not load; see above."
	_modsecurity_crs_prune
	if [[ ${installed} != 0 || ${restart} == 1 ]]; then
		svc_restart "${unit}" || die "modsecurity: ${unit} does not start with ModSecurity."
	elif [[ $(files_changes_of modsecurity) != "${installed}" ]]; then
		svc_reload "${unit}" || die "modsecurity: ${unit} does not reload."
	fi
	return
}

# A harmless request must pass and one with a script tag must be blocked with 403 (or, in DetectionOnly, pass and be
# logged); both go to the ACME probe file, which every host name reaches on port 80 without a site.
mod_verify() {
	local server unit log url marker status config i found=0
	server=$(_modsecurity_server)
	unit=$(web_unit "${server}")
	log=$(_modsecurity_audit_log "${server}")
	svc_is_active "${unit}" || die "modsecurity: ${unit} is not running."
	web_test "${server}" || die "modsecurity: the ${server} configuration does not load."
	# Captured first: grep -q ends early, and the web server's output would hit a closed pipe (pipefail).
	if [[ ${server} == apache ]]; then
		# RHEL's apachectl takes only the service commands; httpd itself lists the modules there.
		if os_is_debian; then
			config=$(apache2ctl -M 2>/dev/null || true)
		else
			config=$(httpd -M 2>/dev/null || true)
		fi
		grep -q 'security2_module' <<<"${config}" || die "modsecurity: Apache has not loaded mod_security2."
	else
		config=$(nginx -T 2>/dev/null || true)
		grep -q 'ngx_http_modsecurity_module' <<<"${config}" || die "modsecurity: nginx does not load the ModSecurity module."
		grep -q '^modsecurity on;' <<<"${config}" || die "modsecurity: ModSecurity is not switched on in nginx."
	fi
	url="http://127.0.0.1${MODSEC_PROBE}"
	[[ $(curl -fsS --max-time 10 -H 'Host: localhost' "${url}" 2>/dev/null) == lss ]] ||
		die "modsecurity: a harmless request to ${MODSEC_PROBE} does not get through."
	marker="lss-verify-${RANDOM}${RANDOM}"
	status=$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
		"${url}?probe=${marker}&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" || true)
	if [[ $(_modsecurity_mode) == On ]]; then
		[[ ${status} == 403 ]] || die "modsecurity: a request with a script tag got ${status}, not 403."
	else
		[[ ${status} == 200 ]] || die "modsecurity: in DetectionOnly mode a request with a script tag got ${status}, not 200."
	fi
	# The audit log is written after the response.
	for ((i = 0; i < 10; i++)); do
		if grep -qF -- "${marker}" "${log}" 2>/dev/null; then
			found=1
			break
		fi
		sleep 1
	done
	[[ ${found} == 1 ]] || die "modsecurity: the request with a script tag is missing from the audit log ${log}."
	return
}

mod_remove() {
	local server unit
	server=$(web_server)
	case ${server} in
	nginx)
		file_remove /etc/nginx/lss/http/modsecurity.conf
		file_remove /etc/nginx/lss/modules/modsecurity.conf
		;;
	apache)
		if os_is_debian && a2query -q -m security2 2>/dev/null; then
			a2dismod -q -f security2 >/dev/null
			files_note_change "apache module security2 off"
		fi
		file_remove "$(_modsecurity_apache_file)"
		svc_dropin_remove "$(web_unit apache).service" lss-modsecurity
		;;
	*) ;;
	esac
	if [[ ${server} == nginx || ${server} == apache ]]; then
		file_remove "$(_modsecurity_conf_dir "${server}")"
		unit=$(web_unit "${server}")
		web_test "${server}" || die "modsecurity: the ${server} configuration does not load without ModSecurity; see above."
		if svc_is_active "${unit}"; then
			svc_restart "${unit}" || die "modsecurity: ${unit} does not start without ModSecurity."
		fi
	fi
	file_remove /etc/logrotate.d/lss-modsecurity
	if [[ ${server} == apache ]]; then
		pkg_remove_family "libapache2-mod-security2" "mod_security"
	else
		# Packages of earlier lss versions; the self-built engine goes with MODSEC_PREFIX below.
		pkg_remove_family "libnginx-mod-http-modsecurity" "nginx-mod-modsecurity"
	fi
	# Downloads and builds, reproducible from data/checksums.txt; the audit logs stay like the web server's own logs.
	if [[ -e ${MODSEC_PREFIX} || -e ${MODSEC_CRS_ROOT} ]]; then
		rm -rf -- "${MODSEC_PREFIX}" "${MODSEC_CRS_ROOT}"
		files_note_change "removed ${MODSEC_PREFIX} and ${MODSEC_CRS_ROOT}"
	fi
	return
}
