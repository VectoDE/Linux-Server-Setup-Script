# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="java"
MOD_GROUP="runtime"
MOD_DESCRIPTION="OpenJDK (JDK without the desktop parts) from the distribution, Eclipse Temurin where it has none"
MOD_REQUIRES="system"
MOD_OPTIONS="version|21|Java major version, for example 17, 21 or 25"

mod_check() {
	[[ $(opt version) =~ ^(8|1[1-9]|[2-9][0-9])$ ]] || die "LSS_JAVA_VERSION must be a Java major version like 21, got '$(opt version)'."
	return
}

# True when the package sources offer PACKAGE.
_java_available() {
	local package=$1 candidate
	if os_is_debian; then
		candidate=$(apt-cache policy "${package}" 2>/dev/null | awk '$1 == "Candidate:" { print $2 }')
		[[ -n ${candidate} && ${candidate} != '(none)' ]]
	else
		[[ -n $(dnf -q repoquery "${package}" 2>/dev/null) ]]
	fi
	return
}

# The distribution's JDK package: headless on Debian and Ubuntu; the RHEL family has no headless JDK, its -devel
# package pulls in the full runtime (a few font and X11 libraries).
_java_distribution_package() {
	local version=$1
	if os_is_debian; then
		printf 'openjdk-%s-jdk-headless' "${version}"
	else
		printf 'java-%s-openjdk-devel' "${version}"
	fi
	return
}

mod_install() {
	local version package temurin
	version=$(opt version)
	package=$(_java_distribution_package "${version}")
	temurin="temurin-${version}-jdk"
	pkg_is_installed "${package}" && return 0
	pkg_is_installed "${temurin}" && return 0
	if os_is_debian; then
		pkg_update_once
	fi
	if ! _java_available "${package}"; then
		# Debian 12 ships OpenJDK 17 only; Adoptium builds every version for every supported system.
		log_info "java: ${OS_NAME} has no OpenJDK ${version}; using Eclipse Temurin from Adoptium."
		repo_add adoptium
		_java_available "${temurin}" || die "java: Java ${version} is available neither from ${OS_NAME} nor from Adoptium."
		package=${temurin}
	fi
	pkg_install "${package}"
	# Remembered, so remove takes away only what lss installed.
	state_set "${LSS_MODULE}" packages "$(state_get "${LSS_MODULE}" packages) ${package}"
	return
}

# Prints the home of the installed JDK of VERSION (Debian: java-21-openjdk-amd64, RHEL: java-21-openjdk, Temurin:
# temurin-21-jdk[-amd64]).
_java_home() {
	local version=$1 home
	for home in /usr/lib/jvm/java-"${version}"-* /usr/lib/jvm/temurin-"${version}"-*; do
		if [[ -x ${home}/bin/java && -x ${home}/bin/javac ]]; then
			printf '%s' "${home}"
			return 0
		fi
	done
	return 1
}

mod_verify() {
	local version home expected output tmp status=0
	version=$(opt version)
	home=$(_java_home "${version}") || die "java: no JDK ${version} below /usr/lib/jvm."
	expected=${version}
	[[ ${version} != 8 ]] || expected=1.8
	output=$("${home}/bin/java" -version 2>&1) || true
	[[ ${output} =~ version\ \"${expected}[.\"] ]] || die "java: ${home}/bin/java is not Java ${version}."
	output=$("${home}/bin/javac" -version 2>&1) || true
	[[ ${output} == "javac ${expected}"* ]] || die "java: ${home}/bin/javac is not Java ${version}."
	command -v java >/dev/null 2>&1 || die "java: java is not on the PATH."
	# Compiling and running a class proves the JDK works, not only that it starts.
	tmp=$(mktemp -d)
	printf 'class Probe { public static void main(String[] a) { System.out.print(6 * 7); } }\n' >"${tmp}/Probe.java"
	output=$("${home}/bin/javac" -d "${tmp}" "${tmp}/Probe.java" 2>&1 && "${home}/bin/java" -cp "${tmp}" Probe 2>&1) || status=1
	rm -rf -- "${tmp}"
	[[ ${status} == 0 && ${output} == 42 ]] || die "java: compiling and running a test class failed: ${output}"
	return
}

mod_remove() {
	local -a installed=()
	read -ra installed <<<"$(state_get "${LSS_MODULE}" packages)"
	if [[ ${#installed[@]} -gt 0 ]]; then
		pkg_remove "${installed[@]}"
	fi
	repo_remove adoptium
	return
}
