#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/toolchain/build-tools.sh
#  * @brief   Build GNU Make and NASM inside Axiom64.
#  * @author  frankischilling
#  * @date    2026-11-19
#  *
#  * Checks the supplied source digests and builds native Make, NASM, and NDISASM.
#  * The kernel build runner uses the rebuilt Make and NASM binaries.
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

set -eu
cd /root/kernel-build/tool-sources
sha512sum -c sources.sha512
mkdir /tmp/guest-tools
tar xf make-*.tar.gz -C /tmp/guest-tools
tar xf nasm-*.tar.xz -C /tmp/guest-tools

# GNU config.guess does not recognize the Axiom64 uname string.
cd /tmp/guest-tools/make-*/
/bin/sh ./configure --build=x86_64-pc-linux-musl --prefix=/usr CC=gcc
/usr/bin/make -j2
cp ./make ../make
../make --version

cd /tmp/guest-tools/nasm-*/
/bin/sh ./configure --build=x86_64-pc-linux-musl --prefix=/usr CC=gcc
../make -j2 nasm ndisasm
cp ./nasm ./ndisasm ../
../nasm -v
echo AXIOM64_BUILD_TOOLS_BUILT
