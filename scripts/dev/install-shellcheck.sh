#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Installs a pinned ShellCheck release into DIR after checking its SHA-256 (the distribution packages are older).
set -Eeuo pipefail

dir=${1:?usage: install-shellcheck.sh DIR}
version=v0.11.0
case $(uname -m) in
x86_64) sum=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198 arch=x86_64 ;;
aarch64) sum=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588 arch=aarch64 ;;
*)
	echo "Unsupported architecture $(uname -m)" >&2
	exit 1
	;;
esac
tmp=$(mktemp -d)
trap 'rm -rf -- "${tmp}"' EXIT
curl --proto '=https' -fsSL -o "${tmp}/sc.tar.xz" \
	"https://github.com/koalaman/shellcheck/releases/download/${version}/shellcheck-${version}.linux.${arch}.tar.xz"
echo "${sum}  ${tmp}/sc.tar.xz" | sha256sum -c --quiet
tar -xJf "${tmp}/sc.tar.xz" -C "${tmp}"
mkdir -p "${dir}"
install -m 0755 "${tmp}/shellcheck-${version}/shellcheck" "${dir}/shellcheck"
"${dir}/shellcheck" --version
