#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    scripts/ci/tools.sh
#  * @brief   CI toolchain preparation.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Installs host build and emulation dependencies and configures the pinned CI
#  * tool set.
#  *
#  * Copyright (C) 2026 frankischilling
#  *
#  * This program is free software: you can redistribute it and/or modify
#  * it under the terms of the GNU General Public License as published by
#  * the Free Software Foundation, either version 3 of the License, or
#  * (at your option) any later version.
#  *
#  * This program is distributed in the hope that it will be useful,
#  * but WITHOUT ANY WARRANTY; without even the implied warranty of
#  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  * GNU General Public License for more details.
#  *
#  * You should have received a copy of the GNU General Public License
#  * along with this program. If not, see <https://gnu.org/licenses/>.
#  */
set -euo pipefail

tools=(g++ libc6-dev make musl-tools linux-libc-dev nasm python3 perl bzip2 gpg gpgv openssl xorriso qemu-system-x86 qemu-utils xvfb libx11-6 x11-utils
       ovmf xfonts-utils e2fsprogs nbdkit nbdkit-plugin-python gdb iproute2 ethtool)
bundle=build/ci-packages
shopt -s nullglob

apt_options=(-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30
             -o Acquire::Retries=2 -o DPkg::Lock::Timeout=60
             -o APT::Update::Error-Mode=any -o Acquire::Languages=none)

apt_get() {
  timeout --kill-after=30s 10m sudo -n apt-get "${apt_options[@]}" "$@"
}

configure_repository() {
  if command -v lsb_release >/dev/null && [[ "$(lsb_release -is)" == Ubuntu ]]; then
    local release source
    release=$(lsb_release -cs)
    if [[ ! "$release" =~ ^[a-z][a-z0-9]*$ ]]; then
      echo 'Invalid Ubuntu release for package restoration.' >&2
      return 2
    fi
    source="$cache/ubuntu.sources"
    # A runner mirror stalled during metadata refresh after an offline miss.
    # Resolve missing Ubuntu dependencies through the signed HTTPS archive.
    cat > "$source" <<EOF
Types: deb
URIs: https://archive.ubuntu.com/ubuntu
Suites: $release $release-updates $release-backports $release-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
    apt_options+=(-o "Dir::Etc::sourcelist=$source" -o Dir::Etc::sourceparts=-)
  fi
}

case "${1:-}" in
  prepare)
    cache="${RUNNER_TEMP:?RUNNER_TEMP is required}/axiom64-apt"
    mkdir -p "$cache/partial" "$bundle"
    configure_repository
    apt_get update
    apt_get -o "Dir::Cache::archives=$cache" \
      -o APT::Keep-Downloaded-Packages=true \
      install -y --no-install-recommends "${tools[@]}"
    packages=("$cache"/*.deb)
    if ((${#packages[@]})); then
      cp "${packages[@]}" "$bundle/"
      sha256sum "$bundle"/*.deb > "$bundle/SHA256SUMS"
    fi
    dpkg-query -W -f='${binary:Package}\t${Version}\n' "${tools[@]}" > "$bundle/versions.txt"
    # Formatting runs once in the build job; its LLVM downloads are not shared.
    apt_get install -y --no-install-recommends clang-format-20
    ;;
  restore)
    packages=(./"$bundle"/*.deb)
    if ((${#packages[@]})); then
      sha256sum --check "$bundle/SHA256SUMS"
      # With downloads disabled, APT installs local archives from its cache path.
      if apt_get -o "Dir::Cache::archives=$PWD/$bundle" \
        install -y --no-install-recommends --no-download "${packages[@]}" &&
        dpkg-query -W -f='${db:Status-Status}\n' "${tools[@]}" |
          awk '$0 != "installed" {missing = 1} END {exit missing}'; then
        exit 0
      fi
      echo 'Local install needs repository resolution; reusing shared packages.'
    fi
    # Repository metadata or runner dependencies may differ from the build host.
    # Keep verified archives available so APT only downloads missing packages.
    cache="${RUNNER_TEMP:?RUNNER_TEMP is required}/axiom64-apt"
    mkdir -p "$cache/partial"
    if ((${#packages[@]})); then
      cp "${packages[@]}" "$cache/"
    fi
    configure_repository
    apt_get update
    apt_get -o "Dir::Cache::archives=$cache" \
      install -y --no-install-recommends "${tools[@]}"
    ;;
  *)
    echo 'Usage: tools.sh prepare|restore' >&2
    exit 2
    ;;
esac
