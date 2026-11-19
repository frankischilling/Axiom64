#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file userspace/tests/toolchain/build-tools.sh
# @brief Build GNU Make and NASM natively from locked release archives.
# @author frankischilling
# @date 2026-11-19

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
