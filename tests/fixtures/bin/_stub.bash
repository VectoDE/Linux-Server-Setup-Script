# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Shared body of the stub commands: records the call in $STUB_LOG, prints $STUB_OUT_<name> and exits with
# $STUB_EXIT_<name> (default 0). <name> is the command name with - and . replaced by _.
stub_main() {
	local name=$1 var
	shift
	printf '%s %s\n' "${name}" "$*" >>"${STUB_LOG:-/dev/null}"
	var=${name//[-.]/_}
	local out="STUB_OUT_${var}" code="STUB_EXIT_${var}"
	[[ -z ${!out:-} ]] || printf '%s\n' "${!out}"
	exit "${!code:-0}"
}
