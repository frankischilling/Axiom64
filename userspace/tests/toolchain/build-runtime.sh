#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# @file    userspace/tests/toolchain/build-runtime.sh
# @brief   Build and install the native musl sysroot for the guest image.
# @author  frankischilling
# @date    2026-11-20
#
# Installs musl in the new root and generates compiler specs for building
# against those files before the new image boots.
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
root=$1
project=/root/kernel-build
workspace=/tmp/guest-musl
mkdir "$workspace"
mount -t ramfs none "$workspace"
export TMPDIR="$workspace/tmp"
mkdir "$TMPDIR"
tar xf "$project/musl.tar.gz" -C "$workspace"
cd "$workspace"/musl-*/
while IFS= read -r name; do
    patch -p1 < "$project/musl-patches/$name"
done < "$project/musl-patches/series"
./configure --prefix=/usr --syslibdir=/lib --target=x86_64-linux-musl --enable-debug \
    --enable-wrapper=gcc CC=gcc AR=ar RANLIB=ranlib \
    "CFLAGS=-pipe -ffile-prefix-map=$PWD=/usr/src/musl-runtime" \
    'LDFLAGS=-Wl,-soname,libc.musl-x86_64.so.1'
make -j2 < /dev/null
make "DESTDIR=$root" install < /dev/null
mkdir -p "$root/usr/share/licenses/musl"
cp COPYRIGHT "$root/usr/share/licenses/musl/COPYRIGHT"

# Install a real file at PT_INTERP and use relative aliases for linking.
rm "$root/lib/ld-musl-x86_64.so.1"
mv "$root/usr/lib/libc.so" "$root/lib/ld-musl-x86_64.so.1"
ln -s ../../lib/ld-musl-x86_64.so.1 "$root/usr/lib/libc.so"
ln -s ld-musl-x86_64.so.1 "$root/lib/libc.musl-x86_64.so.1"
cut -d ' ' -f 3 "$project/linux-uapi.sha256" > "$workspace/uapi-files"
tar -C / -T "$workspace/uapi-files" -cf "$workspace/linux-uapi.tar"
tar xf "$workspace/linux-uapi.tar" -C "$root"
(cd "$root"; sha256sum -c "$project/linux-uapi.sha256" > /dev/null)
sed "s@/usr/@$root/usr/@g" "$root/usr/lib/musl-gcc.specs" > "$project/guest-musl.specs"
cat > "$project/guest-musl-gcc" <<'CC'
#!/bin/sh
exec gcc -pipe -specs=/root/kernel-build/guest-musl.specs "$@"
CC
chmod 755 "$project/guest-musl-gcc"
# The Alpine GCC driver expects this archive even when using an explicit sysroot.
# Its failure handler calls libc directly and must not check its own stack.
"$project/guest-musl-gcc" -O2 -fPIC -fno-stack-protector -c "$project/musl-ssp.c" \
    -o "$workspace/__stack_chk_fail_local.o"
ar rcs "$root/usr/lib/libssp_nonshared.a" "$workspace/__stack_chk_fail_local.o"
cd "$project"
unset TMPDIR
umount "$workspace"
echo AXIOM64_GUEST_MUSL_BUILT
