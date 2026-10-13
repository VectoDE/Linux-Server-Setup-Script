# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Interactive menu (whiptail). Choosing modules here runs the same install path as 'lss install'.

ui_menu() {
	[[ -t 0 && -t 1 ]] || die "The menu needs a terminal. Use 'lss install ...' or 'lss --help'."
	command -v whiptail >/dev/null 2>&1 || pkg_install_family whiptail newt
	local choice
	choice=$(whiptail --title "lss ${LSS_VERSION}" --menu "What do you want to do?" 18 70 8 \
		profile "Install a profile (a ready-made set of modules)" \
		modules "Choose single modules" \
		status "Show installed modules" \
		verify "Check installed modules" \
		audit "Run a security audit (Lynis)" \
		3>&1 1>&2 2>&3) || return 0
	case ${choice} in
	profile) _ui_profile ;;
	modules) _ui_modules ;;
	status) cmd_status ;;
	verify) cmd_verify ;;
	audit) cmd_audit ;;
	*) ;;
	esac
}

_ui_profile() {
	local -a items=()
	local file name
	for file in "${LSS_ROOT}"/profiles/*.conf; do
		name=$(basename "${file}" .conf)
		items+=("${name}" "$(sed -n 's/^# Profile: //p' "${file}")")
	done
	name=$(whiptail --title "Profiles" --menu "Choose a profile" 20 78 10 "${items[@]}" 3>&1 1>&2 2>&3) || return 0
	# shellcheck disable=SC2034 # globals of lss read by load_settings and cmd_install
	LSS_PROFILE=${name}
	load_settings
	ARGS=()
	whiptail --yesno "Install the profile '${name}'?" 8 60 || return 0
	# shellcheck disable=SC2034
	LSS_YES=1
	cmd_install
}

_ui_modules() {
	local -a items=() selected=()
	local group name state output
	while read -r group name; do
		state=OFF
		state_installed "${name}" && state=ON
		items+=("${name}" "[${group}] $(module_meta "${name}" MOD_DESCRIPTION)" "${state}")
	done < <(module_list --groups)
	output=$(whiptail --title "Modules" --separate-output --checklist \
		"Space selects, Enter confirms. Requirements are added automatically." 24 100 16 "${items[@]}" \
		3>&1 1>&2 2>&3) || return 0
	mapfile -t selected <<<"${output}"
	[[ -n ${selected[0]:-} ]] || return 0
	# shellcheck disable=SC2034
	ARGS=("${selected[@]}")
	cmd_install
}
