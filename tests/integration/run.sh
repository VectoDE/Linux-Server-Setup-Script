#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Integration test: tests/integration/run.sh SYSTEM|host MODULE...
#                   tests/integration/run.sh SYSTEM|host --profile NAME [LYNIS_MIN_INDEX]
#
# For every module: install (with its requirements), verify, install again (every module in the run must report
# "unchanged"), and remove. A comma joins modules that are tested together (nginx,tls,vhost: installed at once,
# removed in reverse order). With --profile: install the whole profile, verify, install again, then run the Lynis
# audit and fail below LYNIS_MIN_INDEX. SYSTEM is a directory in tests/integration/images (a systemd container),
# vm-NAME for a KVM virtual machine from tests/integration/vm-images.conf, or "host" for the machine itself (modules
# that need a real kernel; used on throwaway CI virtual machines only).
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

system=${1:?usage: run.sh SYSTEM|host MODULE...}
shift
[[ $# -gt 0 ]] || {
	echo "usage: run.sh SYSTEM|host MODULE... | --profile NAME [LYNIS_MIN_INDEX]" >&2
	exit 2
}
settings=tests/integration/settings.conf
container="lss-test-${system}"
# A run that hangs ends after 40 minutes, so the diagnostics below still show what it waited for.
LSS_RUN="timeout --kill-after=60 2400 lss"
# shellcheck source=tests/integration/vm.sh
source tests/integration/vm.sh
# shellcheck source=tests/integration/pebble.sh
source tests/integration/pebble.sh

# Collapsible sections in the GitHub Actions log.
group_start() {
	echo "::group::$1"
	return
}

group_end() {
	echo "::endgroup::"
	return
}

in_target() {
	local script=$1
	if [[ ${system} == host ]]; then
		sudo --preserve-env=SSH_CONNECTION bash -c "${script}"
	elif [[ ${system} == vm-* ]]; then
		vm_run "${script}"
	else
		docker exec -i "${container}" bash -c "${script}"
	fi
	return
}

start_target() {
	if [[ ${system} == host ]]; then
		sudo rm -rf /opt/lss-src
		sudo cp -a "${PWD}" /opt/lss-src
	elif [[ ${system} == vm-* ]]; then
		vm_start "${system#vm-}"
	else
		[[ -d tests/integration/images/${system} ]] || {
			echo "Unknown system ${system}" >&2
			exit 2
		}
		docker build -q -f "tests/integration/images/${system}/Containerfile" -t "lss-test:${system}" \
			"tests/integration/images/${system}" >/dev/null
		docker rm -f "${container}" >/dev/null 2>&1 || true
		docker run -d --name "${container}" --hostname lss-test --privileged --cgroupns=host \
			-v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp:exec \
			-v /var/lib/containers \
			-v "${PWD}:/src:ro" "lss-test:${system}" >/dev/null
		in_target 'for i in $(seq 60); do s=$(systemctl is-system-running 2>/dev/null || true); [[ $s == running || $s == degraded ]] && exit 0; sleep 1; done; exit 1'
		in_target 'cp -a /src /opt/lss-src'
	fi
	in_target 'ln -sf /opt/lss-src/lss /usr/local/sbin/lss && mkdir -p /etc/lss'
	in_target "cat > /etc/lss/lss.conf" <"${settings}"
	# A setting that no module reads is a typo in the test settings.
	if in_target 'lss --no-color list 2>&1' | grep 'is not a setting'; then
		exit 1
	fi
}

# Fails when a second install changed anything: every step must be idempotent.
install_again() {
	local second
	second=$(in_target "${LSS_RUN} --yes --no-color install $* 2>&1") || {
		printf '%s\n' "${second}"
		exit 1
	}
	printf '%s\n' "${second}"
	if grep -E 'OK +[a-z0-9-]+: done' <<<"${second}"; then
		# What changed: the notes of the run and, for rewritten files, the difference to the version before it.
		in_target 'run=$(ls -td /var/lib/lss/runs/*/ | head -n 1)
			cat "${run}changes"
			for backup in $(find "/var/lib/lss/backup/$(basename "${run}")" -path "*/files/*" -type f 2>/dev/null); do
				file=/${backup#*/files/}
				echo "--- ${file}"
				diff "${backup}" "${file}" | head -n 20
				stat -c "%a %U:%G" "${backup}" "${file}"
			done' || true
		echo "Second install of $* changed something; modules must be idempotent." >&2
		exit 1
	fi
}

stop_target() {
	local status=$? diagnostics=0
	# Diagnostics must never end the cleanup early.
	set +e
	if [[ ${status} -ne 0 ]]; then
		echo "Diagnostics (exit status ${status}):"
		in_target 'tail -n 200 /var/log/lss/*.log 2>/dev/null
			systemctl --failed --no-pager
			for unit in $(systemctl list-units --failed --plain --no-legend | cut -d " " -f 1); do
				echo "--- ${unit}"
				journalctl -u "${unit}" -n 40 --no-pager
			done
			for engine in docker podman; do
				command -v "${engine}" >/dev/null 2>&1 || continue
				"${engine}" ps --all
				for name in $("${engine}" ps --all --format "{{.Names}}"); do
					echo "--- ${engine} logs ${name}"
					"${engine}" logs --tail 40 "${name}"
				done
			done
			ss -ltnp
			ps -eo pid,ppid,etime,args --forest | tail -n 60
			tail -n 30 /var/log/mysql/error.log /var/log/mariadb/mariadb.log 2>/dev/null
			journalctl -p warning -n 80 --no-pager' </dev/null 2>&1 || diagnostics=$?
		# Containers share the kernel of the runner, whose AppArmor profiles still apply to them.
		if [[ ${system} != vm-* && ${system} != host ]]; then
			sudo dmesg 2>/dev/null | grep -F 'apparmor=' | tail -n 30
		fi
		echo "Diagnostics finished (status ${diagnostics})."
	fi
	if [[ ${system} == vm-* ]]; then
		vm_stop
	elif [[ ${system} != host ]]; then
		docker rm -f "${container}" >/dev/null 2>&1 || true
	fi
	exit "${status}"
}

# Available memory and used disk space in MiB, for the resource figures in the README.
resources_snapshot() {
	# Dropping the page cache first keeps cached files out of the figure (not possible in containers).
	in_target 'sync; echo 3 >/proc/sys/vm/drop_caches 2>/dev/null || true
		echo $(($(grep MemAvailable /proc/meminfo | tr -s " " | cut -d " " -f 2) / 1024)) $(df -m --output=used / | tail -n 1)'
	return
}

# Samples MemAvailable twice a second until resources_report stops it, for the peak memory of an install and verify.
memory_watch_start() {
	in_target 'rm -f /run/lss-memwatch /run/lss-memwatch.stop
		setsid sh -c "until [ -e /run/lss-memwatch.stop ]; do grep MemAvailable /proc/meminfo; sleep 0.5; done" \
			>/run/lss-memwatch 2>/dev/null </dev/null &'
	return
}

# Prints what an install and verify cost: time, memory in use afterwards and at the peak (from MemAvailable), disk
# space, and the largest processes.
resources_report() {
	local label=$1 before=$2 started=$3 mem_before disk_before mem_after disk_after mem_low
	read -r mem_before disk_before <<<"${before}"
	read -r mem_after disk_after <<<"$(resources_snapshot)"
	in_target 'touch /run/lss-memwatch.stop; sleep 1'
	mem_low=$(in_target "awk 'NR == 1 || \$2 < low { low = \$2 } END { print int(low / 1024) }' /run/lss-memwatch
		rm -f /run/lss-memwatch /run/lss-memwatch.stop")
	# Other processes on a shared runner can free memory meanwhile; a negative difference means "nothing measurable".
	local mem_used=$((mem_before - mem_after)) mem_peak=$((mem_before - mem_low))
	((mem_used > 0)) || mem_used=0
	((mem_peak > mem_used)) || mem_peak=${mem_used}
	echo "RESOURCES ${label}: $((SECONDS - started)) s, RAM ${mem_used} MiB after, ${mem_peak} MiB peak, disk $((disk_after - disk_before)) MiB"
	in_target 'ps -eo rss=,comm= --sort=-rss | head -n 8' | awk '{ printf "  %5d MiB  %s\n", $1 / 1024, $2 }'
	return
}

trap stop_target EXIT
start_target

if [[ $1 == --profile ]]; then
	profile=${2:?usage: run.sh SYSTEM|host --profile NAME [LYNIS_MIN_INDEX]}
	if grep -qE '^LSS_MODULES=(.* )?tls( |$)' "profiles/${profile}.conf"; then
		group_start "${system}: Pebble (ACME test server)"
		pebble_start
		group_end
	fi
	group_start "${system}: profile ${profile}"
	before=$(resources_snapshot)
	started=${SECONDS}
	memory_watch_start
	in_target "${LSS_RUN} --yes --no-color install --profile ${profile}"
	in_target "${LSS_RUN} --yes --no-color verify"
	resources_report "${system} profile ${profile}" "${before}" "${started}"
	install_again --profile "${profile}"
	group_end
	group_start "${system}: Lynis audit"
	in_target "${LSS_RUN} --yes --no-color --set LSS_LYNIS_MIN_INDEX=${3:-0} audit"
	group_end
	# The daily and weekly scans run once inside their systemd sandbox; a path the sandbox blocks fails the unit.
	group_start "${system}: scheduled scans"
	in_target 'for unit in lss-aide-check lss-rkhunter lss-clamscan lss-lynis; do
		systemctl cat "${unit}.service" >/dev/null 2>&1 || continue
		started=${SECONDS}
		if ! systemctl start --wait "${unit}.service"; then
			journalctl -u "${unit}.service" -n 60 --no-pager
			exit 1
		fi
		echo "${unit}: $(systemctl show -p ExecMainStatus --value "${unit}.service") after $((SECONDS - started)) s, $(systemd-analyze security "${unit}.service" 2>/dev/null | tail -n 1)"
	done'
	group_end
	# What Lynis would still change, as the starting point for raising the hardening index.
	group_start "${system}: Lynis details"
	in_target "grep -iE 'different value than expected|weak configuration state|incorrect file permissions|permissions .* (not|too)|Result: .*(unsafe|not hardened|exposed)' /var/log/lynis.log | sed -E 's/^[0-9: -]+//' | sort -u | head -n 150" || true
	# The tests that cost hardening points, which is what the index is made of.
	in_target "awk '/Performing test ID/ { test = \$0; sub(/.*Performing test ID /, \"\", test) }
		/Hardening: assigned/ { match(\$0, /assigned [0-9]+/); got = substr(\$0, RSTART + 9, RLENGTH - 9)
			match(\$0, /max for this item: [0-9]+/); max = substr(\$0, RSTART + 19, RLENGTH - 19)
			if (got + 0 < max + 0) print \"  -\" (max - got) \" \" test }' /var/log/lynis.log | sort | uniq -c" || true
	group_end
	echo "${system}: profile ${profile} passed"
	exit 0
fi

# The tls module gets its certificates from Pebble.
if [[ " $* " == *[\ ,]tls[\ ,]* ]]; then
	group_start "${system}: Pebble (ACME test server)"
	pebble_start
	group_end
fi

for item in "$@"; do
	IFS=',' read -ra set <<<"${item}"
	group_start "${system}: ${set[*]}"
	before=$(resources_snapshot)
	started=${SECONDS}
	memory_watch_start
	in_target "${LSS_RUN} --yes --no-color install ${set[*]}"
	in_target "${LSS_RUN} --yes --no-color verify"
	resources_report "${system} ${set[*]}" "${before}" "${started}"
	install_again "${set[@]}"
	if [[ ${LSS_TEST_KEEP:-0} != 1 ]]; then
		for ((i = ${#set[@]} - 1; i >= 0; i--)); do
			in_target "${LSS_RUN} --yes --no-color remove ${set[i]}"
			in_target "! lss status | grep -q '^${set[i]} '"
		done
	fi
	group_end
done
echo "${system}: ${*} passed"
