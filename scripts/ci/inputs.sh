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
extra_inputs=()
if [[ "$1" == rotation ]]; then
  excludes+=(--exclude='./build/curl' --exclude='./build/openssl'
             --exclude='./build/rootfs.cpio' --exclude='./build/rootfs-desktop.cpio'
             --exclude='./build/ext2-xattr-codec'
             --exclude='./build/gnu-reader-controls'
             --exclude='./build/gnu-reader-public-controls'
             --exclude='./downloads/ports')
  # Storage fixtures use the prepared libc/password products, not the desktop
  # or guest compiler packages. Keep the pinned UAPI archive used to verify
  # those products, and leave the complete profile's downloads unchanged.
  profile_paths=$(python3 - <<'PY'
import json
dependencies = json.load(open('dependencies.json'))
packages = json.load(open('ports.lock.json'))['packages']
headers, = (package for package in packages if package['name'] == 'linux-headers')
for name in ('openssl', 'curl'):
    print('./downloads/' + dependencies[name]['archive'])
print('downloads/ports/' + headers['archive'])
PY
)
  mapfile -t paths <<< "$profile_paths"
  excludes+=("--exclude=${paths[0]}" "--exclude=${paths[1]}")
  extra_inputs+=("${paths[2]}")
fi
# Keep source/output times and modes, including the prepared BusyBox inputs.
tar -cf "$archive" "${excludes[@]}" . \
  "$busybox_dir/busybox" "$busybox_dir/.config" "$busybox_dir/LICENSE" "$busybox_dir/.axiom64-toolchain" \
  "${extra_inputs[@]}"
gzip -1 "$archive"
