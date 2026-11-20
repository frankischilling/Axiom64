#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ci/storage_evidence.sh
# @brief   CI storage evidence publication.
# @author  frankischilling
# @date    2026-11-18
#
# Validates completed evidence directories and prepares them for publication by
# the runner.
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.
set -euo pipefail

if ((EUID != 0 || $# < 3)); then
  echo 'Use root, the runner UID/GID and completed evidence directories.' >&2
  exit 1
fi
target_uid=$1
target_gid=$2
shift 2
[[ $target_uid =~ ^[1-9][0-9]*$ && $target_gid =~ ^[1-9][0-9]*$ ]]
[[ -d build && ! -L build ]]
storage_workspace=$(pwd -P)
storage_build_root=$(realpath -e -- build)
[[ $storage_build_root == "$storage_workspace/build" ]]
storage_corpora=()

# Validate every selected root before changing ownership of any evidence.
for storage_corpus in "$@"; do
  [[ $storage_corpus =~ ^build/(account-(management|rotation-storage)-[A-Za-z0-9-]+|http-downloads|http-download-controls|http-download-normal|http-download-normal-audit)$ ]]
  [[ ! -L $storage_corpus ]]
  if [[ -e $storage_corpus ]]; then
    [[ -d $storage_corpus ]]
    [[ $(realpath -e -- "$storage_corpus") == "$storage_build_root/${storage_corpus#build/}" ]]
    storage_corpora+=("$storage_corpus")
  fi
done

# Producers and collectors have exited. Keep private modes and all bytes;
# let the ordinary artifact uploader read the completed root-created traces.
for storage_corpus in "${storage_corpora[@]}"; do
  chown -R -P -h -- "$target_uid:$target_gid" "$storage_corpus"
done
