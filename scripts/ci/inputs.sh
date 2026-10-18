#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

case "${1:-}" in
  full) name=ci-inputs ;;
  rotation) name=ci-rotation-inputs ;;
  *) echo 'Usage: inputs.sh full|rotation' >&2; exit 2 ;;
esac
workspace=$(pwd -P)
output=$(cd "${RUNNER_TEMP:?RUNNER_TEMP is required}" && pwd -P)
case "$output/" in
  "$workspace/"*) echo 'Input archives must be written outside the workspace.' >&2; exit 2 ;;
esac
archive="$output/$name.tar"
if [[ -e "$archive" || -e "$archive.gz" ]]; then
  echo 'Input archive already exists.' >&2
  exit 2
fi
busybox_dir=$(python3 -c "import json; print('build/busybox-' + json.load(open('dependencies.json'))['busybox']['version'])")
excludes=(
  --exclude='./.git' --exclude='./.local' --exclude='__pycache__'
  --exclude='./downloads/sources' --exclude='./build/axiom64-sources.tar'
  --exclude='./build/axiom64.iso' --exclude='./build/iso*'
  --exclude='./build/busybox-*' --exclude='./build/uapi'
  --exclude='./build/openssl/source'
  --exclude='./build/openssl/*/*/*/build/test'
  --exclude='./build/openssl/*/*/*/build/fuzz'
  --exclude='./build/openssl/*/*/*/build/*.o'
  --exclude='./build/openssl/*/*/*/build/*.a'
)
if [[ "$1" == rotation ]]; then
  excludes+=(--exclude='./build/curl' --exclude='./build/openssl'
             --exclude='./build/rootfs.cpio' --exclude='./build/rootfs-desktop.cpio')
fi
# Keep source/output times and modes, including the prepared BusyBox inputs.
tar -cf "$archive" "${excludes[@]}" . \
  "$busybox_dir/busybox" "$busybox_dir/.config" "$busybox_dir/LICENSE" "$busybox_dir/.axiom64-toolchain"
gzip -1 "$archive"
