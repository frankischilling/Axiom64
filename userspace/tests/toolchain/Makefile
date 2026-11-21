# SPDX-License-Identifier: GPL-3.0-or-later
## @file    userspace/tests/toolchain/Makefile
# @brief   Builds the native C, C++, and assembly examples inside Axiom64.
# @author  frankischilling
# @date    2026-11-21
#
# Runs executable and shared-library checks and verifies a rejected C input.
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

.PHONY: all test diagnostics
all: /tmp/native-c /tmp/native-cpp /tmp/native-threads /tmp/native-library.so /tmp/native-shared
/tmp/native-arithmetic.o: arithmetic.asm
	nasm -f elf64 $< -o $@
/tmp/native-c: hello.c /tmp/native-arithmetic.o
	gcc -O2 -Wall -Wextra -Werror $^ -o $@
/tmp/native-cpp: hello.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror hello.cpp -o $@
/tmp/native-threads: threads.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror -pthread threads.cpp -o $@
/tmp/native-library.so: library.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs $< -o $@
/tmp/native-shared: shared.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror -pthread $< -o $@ -ldl
diagnostics:
	@if gcc -Wall -Wextra -Werror broken.c -o /tmp/should-not-exist > /tmp/compiler-errors 2>&1; then exit 1; fi
	@grep -q 'error:' /tmp/compiler-errors
	@echo NATIVE_DIAGNOSTICS_PASS
test: all diagnostics
	/tmp/native-c
	/tmp/native-cpp
	/tmp/native-threads
	/tmp/native-shared /tmp/native-library.so
