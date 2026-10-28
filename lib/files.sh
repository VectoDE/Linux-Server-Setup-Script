# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Managed files. file_write replaces a file only when the content, mode or owner differ, keeps a backup of what it
# replaced for this run, records the change and the checksum of the managed file. files_restore puts everything
# the current module changed in this run back.

LSS_STATE_DIR=${LSS_STATE_DIR:-/var/lib/lss}
LSS_RUN_ID=${LSS_RUN_ID:-}
LSS_MODULE=${LSS_MODULE:-}

_files_run_dir() {
	printf '%s/runs/%s' "${LSS_STATE_DIR}" "${LSS_RUN_ID:?LSS_RUN_ID is not set}"
	return
}

_files_backup_dir() {
	printf '%s/backup/%s/%s' "${LSS_STATE_DIR}" "${LSS_RUN_ID:?LSS_RUN_ID is not set}" "${LSS_MODULE:-core}"
	return
}

# Records that the current module changed something (counted by the runner for the "unchanged" report).
files_note_change() {
	local dir
	dir=$(_files_run_dir)
	mkdir -p "${dir}"
	printf '%s\t%s\n' "${LSS_MODULE:-core}" "$*" >>"${dir}/changes"
	return
}

files_changes_of() {
	local module=$1 file
	file="$(_files_run_dir)/changes"
	[[ -f ${file} ]] || {
		printf '0'
		return 0
	}
	awk -F '\t' -v module="${module}" '$1 == module { count++ } END { print count + 0 }' "${file}"
}

# Saves the current state of PATH (or that it did not exist) once per run and module.
files_backup() {
	local path=$1 dir manifest
	dir=$(_files_backup_dir)
	manifest="${dir}/manifest"
	mkdir -p "${dir}"
	chmod 700 "${dir}"
	if [[ -f ${manifest} ]] && grep -qxF -e "file	${path}" -e "new	${path}" "${manifest}"; then
		return 0
	fi
	if [[ -e ${path} || -L ${path} ]]; then
		mkdir -p "${dir}/files$(dirname "${path}")"
		cp -a "${path}" "${dir}/files${path}"
		printf 'file\t%s\n' "${path}" >>"${manifest}"
	else
		printf 'new\t%s\n' "${path}" >>"${manifest}"
	fi
}

# Restores every file the current module changed in this run, newest first.
files_restore() {
	local dir manifest kind path
	dir=$(_files_backup_dir)
	manifest="${dir}/manifest"
	[[ -f ${manifest} ]] || return 0
	while IFS=$'\t' read -r kind path; do
		case ${kind} in
		file)
			rm -rf -- "${path}"
			cp -a "${dir}/files${path}" "${path}"
			log_warn "Restored ${path}"
			;;
		new)
			rm -rf -- "${path}"
			log_warn "Removed ${path}"
			;;
		*) ;;
		esac
	done < <(tac "${manifest}")
}

_files_record_checksum() {
	local path=$1 dir list sum
	dir="${LSS_STATE_DIR}/managed"
	mkdir -p "${dir}"
	list="${dir}/${LSS_MODULE:-core}"
	sum=$(sha256sum "${path}" | cut -d ' ' -f 1)
	if [[ -f ${list} ]]; then
		awk -F '\t' -v path="${path}" '$2 != path' "${list}" >"${list}.tmp"
		mv "${list}.tmp" "${list}"
	fi
	printf '%s\t%s\n' "${sum}" "${path}" >>"${list}"
	return
}

# file_write MODE OWNER:GROUP DEST, content on stdin. Sets LSS_FILE_CHANGED to 1 or 0. OWNER:GROUP are names, or
# numbers (UID:GID) for IDs without an account, such as the users of a container in a user namespace.
file_write() {
	local mode=$1 owner=$2 dest=$3 tmp current_mode current_owner format='%U:%G'
	LSS_FILE_CHANGED=0
	[[ ! ${owner} =~ ^[0-9]+:[0-9]+$ ]] || format='%u:%g'
	mkdir -p "$(dirname "${dest}")"
	tmp=$(mktemp "${dest}.lss.XXXXXX")
	cat >"${tmp}"
	if [[ -f ${dest} ]] && cmp -s "${tmp}" "${dest}"; then
		current_mode=$(stat -c '%a' "${dest}")
		current_owner=$(stat -c "${format}" "${dest}")
		if [[ ${current_mode} == "${mode#0}" && ${current_owner} == "${owner}" ]]; then
			rm -f -- "${tmp}"
			_files_record_checksum "${dest}"
			return 0
		fi
	fi
	files_backup "${dest}"
	chmod "${mode}" "${tmp}"
	chown "${owner}" "${tmp}"
	mv -f -- "${tmp}" "${dest}"
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -F "${dest}" 2>/dev/null || true
	fi
	# shellcheck disable=SC2034 # read by callers
	LSS_FILE_CHANGED=1
	files_note_change "wrote ${dest}"
	_files_record_checksum "${dest}"
	log_debug "Wrote ${dest}"
}

# file_remove PATH: deletes a managed file with backup. lss verify no longer expects it, also when it was gone already
# (a drop-in a module stops writing, a file the web server took with it).
file_remove() {
	local path=$1
	files_forget_path "${path}"
	[[ -e ${path} || -L ${path} ]] || return 0
	files_backup "${path}"
	rm -rf -- "${path}"
	files_note_change "removed ${path}"
}

# files_forget_path PATH: drops PATH from the checksums of the current module.
files_forget_path() {
	local path=$1 list="${LSS_STATE_DIR}/managed/${LSS_MODULE:-core}"
	[[ -f ${list} ]] || return 0
	awk -F '\t' -v path="${path}" '$2 != path' "${list}" >"${list}.tmp"
	mv -f -- "${list}.tmp" "${list}"
	return
}

# Prints managed files of MODULE whose content no longer matches what lss wrote.
files_drifted() {
	local list="${LSS_STATE_DIR}/managed/$1" sum path
	[[ -f ${list} ]] || return 0
	while IFS=$'\t' read -r sum path; do
		if [[ ! -f ${path} ]]; then
			printf '%s (missing)\n' "${path}"
		elif [[ $(sha256sum "${path}" | cut -d ' ' -f 1) != "${sum}" ]]; then
			printf '%s\n' "${path}"
		fi
	done <"${list}"
}

files_forget() {
	local name=$1
	rm -f -- "${LSS_STATE_DIR}/managed/${name}"
	return
}

# file_ensure_lines MODE OWNER:GROUP DEST, lines on stdin: appends the lines DEST is missing, for files lss shares
# with the administrator (authorized_keys, ...). Not checksummed, because others may change the file.
file_ensure_lines() {
	local mode=$1 owner=$2 dest=$3 line
	local -a missing=()
	# DEST may sit in a directory its owner controls (~/.ssh); a planted symlink would make root write to, chmod
	# and chown another file.
	if [[ -L ${dest} || -L $(dirname "${dest}") ]]; then
		die "Refusing to change ${dest}: it or its directory is a symbolic link."
	fi
	while IFS= read -r line; do
		[[ -n ${line} ]] || continue
		if [[ ! -f ${dest} ]] || ! grep -qxF -- "${line}" "${dest}"; then
			missing+=("${line}")
		fi
	done
	LSS_FILE_CHANGED=0
	if [[ ${#missing[@]} -gt 0 ]]; then
		files_backup "${dest}"
		mkdir -p "$(dirname "${dest}")"
		printf '%s\n' "${missing[@]}" >>"${dest}"
		files_note_change "added ${#missing[@]} line(s) to ${dest}"
		# shellcheck disable=SC2034 # read by callers
		LSS_FILE_CHANGED=1
	fi
	if [[ $(stat -c '%a %U:%G' "${dest}" 2>/dev/null) != "${mode#0} ${owner}" ]]; then
		chmod "${mode}" "${dest}"
		chown --no-dereference "${owner}" "${dest}"
	fi
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -F "${dest}" 2>/dev/null || true
	fi
	return
}
