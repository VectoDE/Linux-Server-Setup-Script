# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Templates: {{NAME}} is replaced with the value of the shell variable NAME, literally (no eval, no sed). A
# placeholder without a set variable is an error, so a typo never ends up in a configuration file.

LSS_ROOT=${LSS_ROOT:-}

# template_path MODULE FILE -> templates/MODULE/FILE
template_path() {
	printf '%s/templates/%s/%s' "${LSS_ROOT:?LSS_ROOT is not set}" "$1" "$2"
	return
}

# template_render_string TEXT: prints TEXT with placeholders replaced.
template_render_string() {
	local rest=$1 output='' name
	while [[ ${rest} =~ \{\{([A-Za-z_][A-Za-z0-9_]*)\}\} ]]; do
		name=${BASH_REMATCH[1]}
		output+=${rest%%"{{${name}}}"*}
		[[ -n ${!name+set} ]] || die "Template placeholder {{${name}}} has no value."
		output+=${!name}
		rest=${rest#*"{{${name}}}"}
	done
	printf '%s' "${output}${rest}"
	return
}

# template_render FILE: prints the rendered file (keeps a trailing newline).
template_render() {
	local file=$1 text
	[[ -r ${file} ]] || die "Template ${file} not found."
	text=$(
		cat "${file}"
		printf x
	)
	text=${text%x}
	template_render_string "${text}"
	return
}

# template_install MODULE FILE MODE OWNER DEST: renders templates/MODULE/FILE into DEST as a managed file.
template_install() {
	local module=$1 file=$2 mode=$3 owner=$4 dest=$5 rendered
	rendered=$(
		template_render "$(template_path "${module}" "${file}")"
		printf x
	) || die "Rendering template ${module}/${file} failed."
	file_write "${mode}" "${owner}" "${dest}" < <(printf '%s' "${rendered%x}")
	return
}
