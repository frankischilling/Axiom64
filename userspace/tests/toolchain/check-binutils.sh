#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# @file    userspace/tests/toolchain/check-binutils.sh
# @brief   Assemble, archive, inspect and link with rebuilt binutils.
# @author  frankischilling
# @date    2026-11-20
#
# Checks that the native C compiler selects the supplied assembler and linker.
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
tools=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
test "$(gcc -B "$tools/" -print-prog-name=as)" = "$tools/as"
test "$(gcc -B "$tools/" -print-prog-name=ld)" = "$tools/ld"
cat > answer.s <<'ASM'
.text
.globl answer
.type answer, @function
answer:
    mov $42, %eax
    ret
.section .note.GNU-stack,"",@progbits
ASM
cat > main.c <<'C'
extern int answer(void);
int main(void) { return answer() != 42; }
C
"$tools/as" --64 answer.s -o answer.o
"$tools/ar" rc libanswer.a answer.o
"$tools/ranlib" libanswer.a
"$tools/nm" libanswer.a > symbols
grep ' T answer$' symbols
gcc -B "$tools/" -static main.c libanswer.a -o static-client
gcc -B "$tools/" main.c libanswer.a -o dynamic-client
"$tools/readelf" -Wl static-client > static-elf
"$tools/readelf" -Wl dynamic-client > dynamic-elf
if grep -q INTERP static-elf; then
    exit 1
fi
grep -F 'Requesting program interpreter: /lib/ld-musl-x86_64.so.1]' dynamic-elf
./static-client
./dynamic-client
echo AXIOM64_BINUTILS_LINK_PASS
