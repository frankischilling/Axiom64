# SPDX-License-Identifier: GPL-3.0-or-later
# @file    mk/security.mk
# @brief   Build and run security and random-source tests.
# @author  frankischilling
# @date    2026-11-24
#
# Contains credential, file-capability, seccomp and random-source test rules.
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

.PHONY: test-credentials-policy test-credentials-native test-credentials
build/credentials-policy: kernel/tests/security/credentials.cpp kernel/security/credentials.cpp kernel/include/security/credentials.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/security/credentials.cpp kernel/security/credentials.cpp -o $@
test-credentials-policy: build/credentials-policy
	ASAN_OPTIONS=detect_leaks=1 ./build/credentials-policy
.PHONY: test-file-capabilities-policy
.PHONY: test-file-capabilities test-file-capabilities-native
test-file-capabilities:
	$(PYTHON) scripts/file_capabilities/guest.py
	$(PYTHON) scripts/file_capabilities/metadata.py
test-file-capabilities-native: build/file-capabilities-native build/file-capabilities-static build/file-capabilities-dynamic
	$(PYTHON) scripts/file_capabilities/native.py
build/file-capabilities-policy: kernel/tests/security/file_capabilities.cpp kernel/security/file_capabilities.cpp kernel/security/credentials.cpp kernel/include/security/file_capabilities.hpp kernel/include/security/credentials.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/security/file_capabilities.cpp kernel/security/file_capabilities.cpp kernel/security/credentials.cpp -o $@
test-file-capabilities-policy: build/file-capabilities-policy
	ASAN_OPTIONS=detect_leaks=1 ./build/file-capabilities-policy
build/credentials-native: userspace/tests/security/credentials.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DCREDENTIAL_LINKAGE='"native"' $< -o $@
build/file-capabilities-native: userspace/tests/security/file-capabilities.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DFILECAP_LINKAGE='"native"' $< -o $@
build/file-capabilities-static: userspace/tests/security/file-capabilities.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/file-capabilities-dynamic: userspace/tests/security/file-capabilities.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DFILECAP_LINKAGE='"dynamic"' $< -o $@
build/credentials-static: userspace/tests/security/credentials.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -static -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $< -o $@
build/credentials-dynamic: userspace/tests/security/credentials.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DCREDENTIAL_LINKAGE='"dynamic"' -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $< -o $@
test-credentials-native: build/credentials-native build/credentials-static build/credentials-dynamic
	$(PYTHON) scripts/credentials_native.py
test-credentials:
	$(PYTHON) scripts/credentials_test.py
.PHONY: test-seccomp
test-seccomp:
	$(PYTHON) scripts/seccomp_test.py

.PHONY: test-random-native test-random
.PHONY: test-random-generation-exec
test-random-generation-exec:
	$(PYTHON) scripts/random_generation_exec_test.py
build/generation-exec-static: userspace/tests/random/generation_exec.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -Wall -Wextra -Werror -static $< -o $@
build/generation-exec-dynamic: userspace/tests/random/generation_exec.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -Wall -Wextra -Werror $< -o $@
RANDOM_CORE = kernel/core/random/primitives.cpp kernel/core/random/engine.cpp
RANDOM_HEADERS = kernel/include/core/random/primitives.hpp kernel/include/core/random/engine.hpp
build/random-native: kernel/tests/random/generator.cpp $(RANDOM_CORE) $(RANDOM_HEADERS)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/random/generator.cpp $(RANDOM_CORE) -o $@
test-random-native: build/random-native
	ASAN_OPTIONS=detect_leaks=1 ./build/random-native
.PHONY: test-random-virtio-native
build/random-virtio-native: kernel/tests/random/virtio_sample.cpp kernel/drivers/random/sample.cpp kernel/include/drivers/random/sample.hpp $(RANDOM_CORE) $(RANDOM_HEADERS)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/random/virtio_sample.cpp kernel/drivers/random/sample.cpp $(RANDOM_CORE) -o $@
test-random-virtio-native: build/random-virtio-native
	ASAN_OPTIONS=detect_leaks=1 ./build/random-virtio-native
.PHONY: test-random-generation-native
build/random-generation-native: kernel/tests/random/generation.cpp kernel/firmware/generation.cpp kernel/include/firmware/generation.hpp $(RANDOM_CORE) $(RANDOM_HEADERS)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/random/generation.cpp kernel/firmware/generation.cpp $(RANDOM_CORE) -o $@
test-random-generation-native: build/random-generation-native
	ASAN_OPTIONS=detect_leaks=1 ./build/random-generation-native
test-random:
	$(PYTHON) scripts/random_test.py
build/random-static: userspace/tests/random/random.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/random-dynamic: userspace/tests/random/random.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DRANDOM_LINKAGE='"dynamic"' $< -o $@
build/random-snapshot-static: userspace/tests/random/snapshot.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/random-snapshot-dynamic: userspace/tests/random/snapshot.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DRANDOM_LINKAGE='"dynamic"' $< -o $@
build/random-admin-native: userspace/tests/random/administration.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/random-admin-static: userspace/tests/random/administration.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -DRANDOM_LINKAGE='"static"' $< -o $@
build/random-admin-dynamic: userspace/tests/random/administration.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DRANDOM_LINKAGE='"dynamic"' $< -o $@
build/random-seed-native: userspace/services/random_seed.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/random-seed-static: userspace/services/random_seed.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/random-seed-dynamic: userspace/services/random_seed.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/random-seed-probe-native: userspace/tests/random/seed_lifecycle.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/random-seed-probe-static: userspace/tests/random/seed_lifecycle.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -DRANDOM_LINKAGE='"static"' $< -o $@
build/random-seed-probe-dynamic: userspace/tests/random/seed_lifecycle.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DRANDOM_LINKAGE='"dynamic"' $< -o $@
build/random-seed-fault-static: userspace/tests/random/seed_fault.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/random-seed-fault-dynamic: userspace/tests/random/seed_fault.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DRANDOM_LINKAGE='"dynamic"' $< -o $@
build/random-seed-stop-static: userspace/services/random_seed.c userspace/tests/random/seed_crash_stop.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $(filter %.c,$^) -Wl,--wrap=openat,--wrap=write,--wrap=fsync,--wrap=linkat,--wrap=renameat,--wrap=unlinkat -o $@
build/random-seed-stop-dynamic: userspace/services/random_seed.c userspace/tests/random/seed_crash_stop.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror $(filter %.c,$^) -Wl,--wrap=openat,--wrap=write,--wrap=fsync,--wrap=linkat,--wrap=renameat,--wrap=unlinkat -o $@
build/random-seed-crash-static: userspace/tests/random/seed_crash.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/random-seed-crash-dynamic: userspace/tests/random/seed_crash.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DRANDOM_LINKAGE='"dynamic"' $< -o $@
build/random-seed-recovery-static: userspace/tests/random/seed_recovery.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/random-seed-recovery-dynamic: userspace/tests/random/seed_recovery.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DRANDOM_LINKAGE='"dynamic"' $< -o $@
.PHONY: test-random-seed test-random-seed-native test-random-seed-fault test-random-seed-crash test-random-seed-crash-native test-random-seed-recovery
test-random-seed:
	$(PYTHON) scripts/random_seed_test.py
test-random-seed-native:
	$(PYTHON) scripts/random_seed_native.py
test-random-seed-fault:
	$(PYTHON) scripts/random_seed_fault_test.py
test-random-seed-crash:
	$(PYTHON) scripts/random_seed_crash_test.py
test-random-seed-crash-native:
	$(PYTHON) scripts/random_seed_crash_test.py --native
test-random-seed-recovery:
	$(PYTHON) scripts/random_seed_recovery_test.py
.PHONY: test-random-administration test-random-administration-native test-random-virtio
test-random-administration:
	$(PYTHON) scripts/random_administration_test.py
test-random-administration-native:
	$(PYTHON) scripts/random_administration_test.py --native
test-random-virtio:
	$(PYTHON) scripts/random_virtio_test.py
