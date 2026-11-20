#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    scripts/ci/inputs.sh
#  * @brief   CI input archive preparation.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Packages the complete, rotation, or storage build inputs for isolated CI
#  * jobs.
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
else
  # Isolated download tests recheck these two pinned CA inputs with the
  # restored bundle. Share the verified bytes from the build.
  extra_inputs+=(downloads/sources/ca-bundle/certdata.txt
                 downloads/sources/ca-bundle/MPL-2.0.txt)
  for input in "${extra_inputs[@]}"; do
    if [[ ! -f "$input" ]]; then
      echo "Missing prepared input: $input" >&2
      exit 1
    fi
  done
  # Use the same completed outputs for cold builds and cache restores. Leave
  # the workspace intact for the build's own evidence and failure diagnostics.
  crypto_excludes=$(mktemp "$output/axiom64-crypto-excludes.XXXXXXXX")
  trap 'rm -f -- "$crypto_excludes"' EXIT
  script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  python3 -B "$script_dir/crypto_input_excludes.py" > "$crypto_excludes"
  excludes+=(--anchored --no-wildcards --exclude-from="$crypto_excludes")
fi
# Keep source/output times and modes, including the prepared BusyBox inputs.
tar -cf "$archive" "${excludes[@]}" . \
  "$busybox_dir/busybox" "$busybox_dir/.config" "$busybox_dir/LICENSE" "$busybox_dir/.axiom64-toolchain" \
  "${extra_inputs[@]}"
gzip -1 "$archive"
