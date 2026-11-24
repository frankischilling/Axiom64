#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/tests/toolchain/installed-build-tools.sh
# @brief   Clone, configure, build, and test a native project.
# @author  frankischilling
# @date    2026-11-23
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
test "$(id -u)" = 1000
git --version
cmake --version
ninja --version
rg --version

git init --initial-branch=main source
test -f source/.git/hooks/pre-commit.sample
cat > source/CMakeLists.txt <<'EOF'
cmake_minimum_required(VERSION 3.20)
project(NativeBuild LANGUAGES C CXX)
if(NOT AXIOM64 OR NOT CMAKE_SYSTEM_NAME STREQUAL "Axiom64")
    message(FATAL_ERROR "CMake did not load the Axiom64 platform")
endif()
set(CMAKE_BUILD_RPATH_USE_ORIGIN TRUE)
add_library(native-value SHARED value.c)
add_executable(native-build main.cpp)
target_link_libraries(native-build PRIVATE native-value)
enable_testing()
add_test(NAME native-build COMMAND native-build)
EOF
cat > source/value.c <<'EOF'
int native_value(void) {
    return 42;
}
EOF
cat > source/main.cpp <<'EOF'
#include <iostream>
#include <string>

extern "C" int native_value();

int main() {
    std::cout << "native-" << std::to_string(native_value()) << "-ok\n";
    return native_value() == 42 ? 0 : 1;
}
EOF
git -C source add CMakeLists.txt main.cpp value.c
git -C source -c user.name='Guest Fixture' -c user.email='guest@example.invalid' \
    commit -m 'Seed native build'
git clone --no-local source checkout
test "$(git -C checkout rev-parse HEAD)" = "$(git -C source rev-parse HEAD)"
test "$(git -C checkout show -s --format=%s HEAD)" = 'Seed native build'
test -z "$(git -C checkout status --porcelain)"

cmake -S checkout -B build -G Ninja
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
test "$(build/native-build)" = native-42-ok
readelf -d build/native-build | grep -Fq '[libnative-value.so]'
readelf -d build/native-build | grep -Fq '[$ORIGIN]'
test "$(build/native-build | rg -oP '[[:digit:]]{2}(?=-ok)')" = 42
test "$(rg -l 'return 42;' checkout)" = checkout/value.c
if rg -q 'return 99;' checkout; then
    exit 1
else
    test "$?" = 1
fi

for page in git cmake rg; do
    test -s "/usr/share/man/man1/$page.1.gz"
done
micro -version | grep -q '2[.]0[.]14'
ssh -G localhost | grep -qx 'hostname localhost'
test -x /usr/bin/scp
test -x /usr/bin/sftp
ip -V | grep -q iproute2
ip link show lo | grep -q 'lo:'
ss -V | grep -q iproute2
dig -v | grep -q DiG
gdb -nx -batch -ex 'file /tmp/native-c' -ex 'info functions main' | grep -Eq '[[:space:]]main$'
strace -V | grep -q 'strace -- version'
MANPAGER=cat MANWIDTH=80 /bin/man 2 open | grep -q 'possibly create a file'
MANPAGER=cat MANWIDTH=80 man 1 less | grep -q 'display the contents of a file'
printf '%s\n' NATIVE_BUILD_TOOLS_PASS
