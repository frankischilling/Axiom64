#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# @file    userspace/tests/toolchain/build-binutils.sh
# @brief   Build and export GNU binutils inside Axiom64.
# @author  frankischilling
# @date    2026-11-20
#
# Reads verified sources from ext2 and builds out of tree on a RAM mount.
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
set -o pipefail
export LC_ALL=C PATH=/bin:/usr/bin:/sbin:/usr/sbin
source=/mnt/binutils-source
output=/mnt/binutils-export
work=/tmp/binutils-build
mkdir -p "$source" "$output" "$work"
mount -t ext2 -o ro /dev/vda "$source"
mount -t ext2 /dev/vdb "$output"
mount -t ramfs none "$work"
export TMPDIR="$work/tmp"
mkdir "$TMPDIR"

cd "$source"
sha256sum -c /root/binutils-inputs/source.sha256 > "$output/source-check.log"
echo AXIOM64_BINUTILS_SOURCES_VERIFIED
cd "$work"
release="$source/binutils-with-gold-2.44"
target=$(gcc -dumpmachine)
bison --version
flex --version
m4 --version
export CFLAGS='-O2 -g0 -pipe'
export CXXFLAGS="$CFLAGS"
sh "$release/configure" --build="$target" --host="$target" --target="$target" \
    --prefix=/usr --with-sysroot=/ --enable-plugins --disable-nls --disable-werror \
    --enable-default-execstack=no --enable-default-hash-style=gnu \
    --enable-deterministic-archives --enable-new-dtags --enable-relro
echo AXIOM64_BINUTILS_TOP_CONFIGURED
# The verified release already includes the manual pages. Keep the package
# from rebuilding them with Perl and pod2man during the compiler bootstrap.
make -j2 man_MANS= all-binutils all-gas all-ld < /dev/null
stage="$output/stage"
make "DESTDIR=$stage" man_MANS= install-binutils install-gas install-ld < /dev/null
man="$stage/usr/share/man/man1"
mkdir -p "$man"
install -m 644 "$release"/binutils/doc/*.1 "$release/gas/doc/as.1" "$release/ld/ld.1" "$man/"
tools="$stage/usr/bin"
/bin/sh /root/binutils-inputs/check-binutils.sh "$tools"
notice="$stage/usr/share/licenses/binutils"
mkdir -p "$notice"
for name in COPYING COPYING.LIB COPYING3 COPYING3.LIB; do
    cp "$release/$name" "$notice/$name"
done
tar -cf "$output/binutils.tar" -C "$stage" usr
sha256sum "$output/binutils.tar"
cd /
unset TMPDIR
umount "$work"
umount "$source"
sync
umount "$output"
echo AXIOM64_BINUTILS_EXPORTED
echo AXIOM64_TESTS_PASS
