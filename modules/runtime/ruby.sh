# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

MOD_NAME="ruby"
MOD_GROUP="runtime"
MOD_DESCRIPTION="Ruby from the distribution with Bundler and the headers and compiler for native gems"
MOD_REQUIRES="system"
MOD_OPTIONS=""

# Debian's "bundler" package carries the bundle command (ruby-bundler only the library).
RUBY_DEB="ruby ruby-dev bundler"
RUBY_RPM="ruby ruby-devel rubygem-bundler"
# Native gems need a compiler; it stays on remove, other software builds with it too.
RUBY_BUILD_DEB="gcc make libc6-dev"
RUBY_BUILD_RPM="gcc make redhat-rpm-config"

mod_install() {
	local -a wanted=() missing=()
	if os_is_debian; then
		read -ra wanted <<<"${RUBY_DEB}"
	else
		read -ra wanted <<<"${RUBY_RPM}"
	fi
	mapfile -t missing < <(pkg_missing "${wanted[@]}")
	if [[ ${#missing[@]} -gt 0 ]]; then
		pkg_install "${missing[@]}"
		# Remembered, so remove takes away only what lss installed.
		state_set "${LSS_MODULE}" packages "$(state_get "${LSS_MODULE}" packages) ${missing[*]}"
	fi
	pkg_install_family "${RUBY_BUILD_DEB}" "${RUBY_BUILD_RPM}"
	return
}

mod_verify() {
	local output
	output=$(ruby -e 'print 6 * 7' 2>/dev/null) || true
	[[ ${output} == 42 ]] || die "ruby: ruby does not run."
	bundle --version >/dev/null 2>&1 || die "ruby: bundle does not run."
	# The headers for native extensions.
	ruby -rrbconfig -e 'exit(File.exist?(File.join(RbConfig::CONFIG["rubyhdrdir"], "ruby.h")) ? 0 : 1)' ||
		die "ruby: the Ruby headers (ruby.h) are missing."
	return
}

mod_remove() {
	local -a installed=()
	read -ra installed <<<"$(state_get "${LSS_MODULE}" packages)"
	if [[ ${#installed[@]} -gt 0 ]]; then
		pkg_remove "${installed[@]}"
	fi
	return
}
