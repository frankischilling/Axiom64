#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# @file    userspace/tests/toolchain/build-tools.sh
# @brief   Build GNU Make and NASM inside Axiom64.
# @author  frankischilling
# @date    2026-11-19
#
# Checks the supplied source digests and builds native Make, NASM, and NDISASM.
# The kernel build runner uses the rebuilt Make and NASM binaries.
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

set -eu
cd /root/kernel-build/tool-sources
sha512sum -c sources.sha512
tools=/tmp/guest-tools
workspace=/tmp/guest-tool-source
mkdir "$tools" "$workspace"
mount -t ramfs none "$workspace"
export TMPDIR="$workspace/tmp"
mkdir "$TMPDIR"
tar xf make-*.tar.gz -C "$workspace"
tar xf nasm-*.tar.xz -C "$workspace"

# These temporary tools build the test system. Keep compilation work small
# when the guest runs under software emulation.
tool_cflags='-O0 -g0'
# GNU config.guess does not recognize the Axiom64 uname string.
cd "$workspace"/make-*/
patch -p1 < /root/kernel-build/make-environment-prefix.patch
/bin/sh ./configure --build=x86_64-pc-linux-musl --prefix=/usr CC=gcc CFLAGS="$tool_cflags"
/usr/bin/make -j2
cp ./make "$tools/make"
"$tools/make" --version

cd "$workspace"/nasm-*/
/bin/sh ./configure --build=x86_64-pc-linux-musl --prefix=/usr CC=gcc CFLAGS="$tool_cflags"
"$tools/make" -j2 nasm ndisasm
cp ./nasm ./ndisasm "$tools/"
"$tools/nasm" -v
cd /
umount "$workspace"
echo AXIOM64_BUILD_TOOLS_BUILT
