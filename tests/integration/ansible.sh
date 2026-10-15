#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Integration test of the Ansible collection: tests/integration/ansible.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B
#
# RELEASE_DIR holds two attested test releases (see update.sh); the collection of VERSION_A must be installed for
# ansible-playbook (ANSIBLE_COLLECTIONS_PATH). Over SSH into a systemd container, tests/ansible/site.yml installs lss A
# with the role vectode.lss.lss and the module tools, runs again without a change, updates lss to B through the
# role, removes tools in check mode (nothing changes) and for real.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

SYSTEM=${1:?usage: ansible.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B}
RELEASE_DIR=$(cd "${2:?usage: ansible.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B}" && pwd)
A=${3:?usage: ansible.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B}
B=${4:?usage: ansible.sh SYSTEM RELEASE_DIR VERSION_A VERSION_B}
: "${LSS_RELEASE_WORKFLOW:?the workflow file that signed the test releases}" "${LSS_RELEASE_REF:?its git ref}"
export LSS_RELEASE_WORKFLOW LSS_RELEASE_REF
# shellcheck source=tests/integration/target.sh
source tests/integration/target.sh
work=$(mktemp -d)

# play NAME EXPECTED_CHANGED [ansible-playbook options...]: runs the test playbook and checks the number of changed
# tasks in the recap ("any" for at least one).
play() {
	local name=$1 expected=$2 changed
	shift 2
	group_start "${SYSTEM}: ${name}"
	ansible-playbook -i "${work}/inventory" tests/ansible/site.yml "$@" | tee "${work}/play.log"
	changed=$(sed -nE 's/.*changed=([0-9]+) +unreachable=0 +failed=0 .*/\1/p' "${work}/play.log")
	group_end
	if [[ -z ${changed} ]] || { [[ ${expected} == any ]] && ((changed == 0)); } ||
		{ [[ ${expected} != any ]] && ((changed != expected)); }; then
		echo "${name}: expected ${expected} changed tasks, the recap says '${changed:-failed}'." >&2
		exit 1
	fi
	return
}

trap 'status=$?; rm -rf -- "${work}"; target_stop "${status}"' EXIT
target_start

# Python for Ansible and an SSH login for root with a key of this run, as on a fresh cloud server.
ssh-keygen -q -t ed25519 -N '' -f "${work}/id_ed25519"
in_target "set -e
	if command -v apt-get >/dev/null; then
		apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends python3 >/dev/null
	else
		dnf -y -q install python3 >/dev/null
	fi
	install -d -m 0700 /root/.ssh
	cat >/root/.ssh/authorized_keys
	chmod 0600 /root/.ssh/authorized_keys
	systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd" <"${work}/id_ed25519.pub"
address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${TARGET_CONTAINER}")
cat >"${work}/inventory" <<EOF
[target]
${address} ansible_user=root ansible_ssh_private_key_file=${work}/id_ed25519 ansible_python_interpreter=/usr/bin/python3 ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
EOF
export ANSIBLE_HOST_KEY_CHECKING=False ANSIBLE_NOCOLOR=1 ANSIBLE_FORCE_COLOR=0

ssh_works() {
	ssh -q -i "${work}/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-o ConnectTimeout=10 "root@${address}" true
	return
}

# The PAM account stack of the minimal rocky-9 image denies root ("Access denied for user root by PAM account
# configuration"), which is a property of the container image, not of lss. Where that happens, show the stack and let
# sshd skip PAM for the test, with the password of root set to "*" (no password, but the account is not locked).
if ! ssh_works; then
	in_target "ls -l /etc/pam.d/sshd /etc/pam.d/password-auth; grep -v '^#' /etc/pam.d/sshd
		grep '^account' /etc/pam.d/password-auth; getent shadow root | cut -d: -f1,3-"
	in_target "set -e
		printf 'UsePAM no\n' >/etc/ssh/sshd_config.d/00-lss-test.conf
		usermod -p '*' root
		systemctl restart sshd"
	ssh_works
fi

play "install lss ${A} and tools" any -e "lss_version=${A}"
in_target "[[ \$(lss version) == 'lss ${A}' ]] && lss status | grep -E '^tools +installed'"
play "the same again changes nothing" 0 -e "lss_version=${A}"
play "update lss to ${B}" any -e "lss_version=${B}"
in_target "[[ \$(lss version) == 'lss ${B}' && \$(readlink /opt/lss/previous) == '${A}' ]]"
play "remove tools in check mode" any -e "lss_version=${B}" -e '{"test_modules": [], "test_modules_absent": ["tools"]}' --check
in_target "lss status | grep -E '^tools +installed'"
play "remove tools" any -e "lss_version=${B}" -e '{"test_modules": [], "test_modules_absent": ["tools"]}'
in_target "! lss status | grep -E '^tools '"
echo "${SYSTEM}: Ansible collection passed"
