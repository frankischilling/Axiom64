#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

tools=(g++ make musl-tools linux-libc-dev nasm python3 xorriso qemu-system-x86 xvfb libx11-6
       ovmf xfonts-utils e2fsprogs nbdkit nbdkit-plugin-python gdb iproute2 ethtool)
bundle=build/ci-packages
shopt -s nullglob

case "${1:-}" in
  prepare)
    cache="${RUNNER_TEMP:?RUNNER_TEMP is required}/axiom64-apt"
    mkdir -p "$cache/partial" "$bundle"
    sudo apt-get update
    sudo apt-get -o "Dir::Cache::archives=$cache" \
      -o APT::Keep-Downloaded-Packages=true \
      install -y --no-install-recommends "${tools[@]}"
    packages=("$cache"/*.deb)
    if ((${#packages[@]})); then
      cp "${packages[@]}" "$bundle/"
      sha256sum "$bundle"/*.deb > "$bundle/SHA256SUMS"
    fi
    dpkg-query -W -f='${binary:Package}\t${Version}\n' "${tools[@]}" > "$bundle/versions.txt"
    # Formatting runs once in the build job; its LLVM downloads are not shared.
    sudo apt-get install -y --no-install-recommends clang-format-20
    ;;
  restore)
    packages=(./"$bundle"/*.deb)
    if ((${#packages[@]})); then
      sha256sum --check "$bundle/SHA256SUMS"
      if sudo apt-get install -y --no-install-recommends --no-download "${packages[@]}" &&
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
    sudo apt-get update
    sudo apt-get -o "Dir::Cache::archives=$cache" \
      install -y --no-install-recommends "${tools[@]}"
    ;;
  *)
    echo 'Usage: tools.sh prepare|restore' >&2
    exit 2
    ;;
esac
