# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Logging: messages go to stderr, to the run log file and to the journal (identifier "lss"). Every value registered
# with log_mask is replaced by "***" before anything is written, so secrets never reach a log.

LSS_LOG_FILE=${LSS_LOG_FILE:-}
LSS_VERBOSE=${LSS_VERBOSE:-0}
LSS_COLOR=${LSS_COLOR:-auto}
declare -ga LSS_MASKED=()

log_mask() {
	local value=$1
	[[ ${#value} -ge 4 ]] || return 0
	LSS_MASKED+=("${value}")
}

_log_sanitize() {
	local text=$1 secret
	for secret in "${LSS_MASKED[@]}"; do
		text=${text//"${secret}"/***}
	done
	printf '%s' "${text}"
}

_log_color() {
	if [[ ${LSS_COLOR} == never ]]; then
		return 1
	fi
	if [[ ${LSS_COLOR} == always ]]; then
		return 0
	fi
	[[ -t 2 && -z ${NO_COLOR:-} ]]
}

_log() {
	local level=$1 color=$2
	shift 2
	local message stamp
	message=$(_log_sanitize "$*")
	stamp=$(date '+%Y-%m-%d %H:%M:%S')
	if _log_color; then
		printf '\033[%sm%-5s\033[0m %s\n' "${color}" "${level}" "${message}" >&2
	else
		printf '%-5s %s\n' "${level}" "${message}" >&2
	fi
	if [[ -n ${LSS_LOG_FILE} ]]; then
		printf '%s %-5s %s\n' "${stamp}" "${level}" "${message}" >>"${LSS_LOG_FILE}" 2>/dev/null || true
	fi
	if [[ ${LSS_JOURNAL:-1} == 1 ]] && command -v logger >/dev/null 2>&1; then
		local priority=info
		case ${level} in
		ERROR) priority=err ;;
		WARN) priority=warning ;;
		DEBUG) priority=debug ;;
		*) ;;
		esac
		logger -t lss -p "user.${priority}" -- "${level} ${message}" 2>/dev/null || true
	fi
}

log_debug() {
	[[ ${LSS_VERBOSE} == 1 ]] || return 0
	_log DEBUG '2' "$*"
}

log_info() { _log INFO '0' "$*"; }
log_step() { _log '==>' '1;34' "$*"; }
log_ok() { _log OK '32' "$*"; }
log_warn() { _log WARN '33' "$*"; }
log_error() { _log ERROR '31' "$*"; }

die() {
	log_error "$*"
	exit 1
}
