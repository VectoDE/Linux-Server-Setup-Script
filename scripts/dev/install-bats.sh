#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Installs bats-core at a pinned commit into DIR (DIR/bin/bats). The distribution packages lag behind.
set -Eeuo pipefail

dir=${1:?usage: install-bats.sh DIR}
commit=eb7f42f8d608ac693d7a4b67474f6714ea68cfc5 # v1.14.0
rm -rf -- "${dir}"
git init -q "${dir}"
git -C "${dir}" fetch -q --depth 1 https://github.com/bats-core/bats-core.git "${commit}"
git -C "${dir}" checkout -q FETCH_HEAD
[[ $(git -C "${dir}" rev-parse HEAD) == "${commit}" ]]
"${dir}/bin/bats" --version
