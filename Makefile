CXX = g++
NASM = nasm
PYTHON = python3
IPV4_WORKERS ?= 2
IPV4_MULTICAST_CORE = $(wildcard kernel/net/ipv4/multicast/*.cpp)
IPV6_CORE = $(wildcard kernel/net/ipv6/*.cpp) kernel/core/random/primitives.cpp
MUSL_CC = gcc -specs="$(CURDIR)/build/musl/build/compiler.specs"
CLANG_FORMAT ?= clang-format-20
CXXFLAGS = -std=c++20 -O2 -g -Wall -Wextra -Werror -ffreestanding -fno-exceptions -fno-rtti -fno-stack-protector -fno-pie -fno-threadsafe-statics -fno-use-cxa-atexit -fno-builtin -m64 -mno-red-zone -mcmodel=kernel -mgeneral-regs-only -Ikernel/include -Ivendor
rwildcard = $(foreach entry,$(wildcard $1*),$(call rwildcard,$(entry)/,$2) $(filter $(subst *,%,$2),$(entry)))
KERNEL_SOURCES = $(filter-out kernel/tests/%,$(call rwildcard,kernel/,*.cpp))
KERNEL_OBJECTS = $(patsubst kernel/%.cpp,build/kernel/%.o,$(KERNEL_SOURCES)) build/kernel/arch/x86_64/entry.o
FORMAT_SOURCES = $(foreach pattern,*.cpp *.hpp,$(call rwildcard,kernel/,$(pattern))) $(foreach pattern,*.c *.h *.cpp *.hpp,$(call rwildcard,userspace/,$(pattern))) scripts/tests/native_icmp_budget.c scripts/tests/native_icmp_stagger_regression.c

.PHONY: all image disk-root test test-storage test-ext2 test-disk-root test-root-io test-network test-ipv4 test-udp test-netlink test-netlink-codec test-address-codec test-configuration test-dhcp-codec test-dhcp-modules test-dhcp-transport test-profiles test-resolver test-resolver-native test-clock-codec test-clock test-file-locks test-file-locks-native test-threads test-thread-io test-virtqueue test-virtio format check-format run run-serial deps busybox sources clean
all: image
.PHONY: test-rtc-codec test-clock-wall test-clock-wall-native
.PHONY: test-random-crypto test-random-crypto-native test-random-crypto-wait test-random-crypto-wait-native
.PHONY: openssl libxcrypt curl ca-bundle test-password-library-native test-password-library test-random-installed
.PHONY: test-pty-security test-pty-security-native
test-pty-security:
	$(PYTHON) scripts/pty_security_test.py
test-pty-security-native:
	$(PYTHON) scripts/pty_security_test.py --native --directory build/pty-security-native
.PHONY: test-account-secret test-account-secret-native
test-account-secret:
	$(PYTHON) scripts/account_secret_test.py
test-account-secret-native:
	$(PYTHON) scripts/account_secret_test.py --native --directory build/account-secret-native
.PHONY: test-parent-death test-parent-death-native test-signal-wait test-signal-wait-native test-account-desktop
.PHONY: test-waitid test-waitid-native test-proc-identity test-proc-identity-native test-proc-identity-policy test-record-lock-lifecycle test-record-lock-lifecycle-native
.PHONY: test-exec-arguments test-exec-arguments-native test-exec-arguments-policy
.PHONY: test-process-limits-policy test-resource-limits test-resource-limits-native test-resource-limits-storage

test-resource-limits:
	$(PYTHON) scripts/resource_limits_test.py

test-resource-limits-native:
	$(PYTHON) scripts/resource_limits_test.py --native --directory build/resource-limits-native

test-resource-limits-storage:
	$(PYTHON) scripts/resource_limits_storage_test.py

build/process-limits-policy: kernel/tests/process/limits.cpp kernel/process/limits.cpp kernel/include/process/limits.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/process/limits.cpp kernel/process/limits.cpp -o $@

test-process-limits-policy: build/process-limits-policy
	ASAN_OPTIONS=detect_leaks=1 ./build/process-limits-policy
test-exec-arguments:
	$(PYTHON) scripts/exec_arguments_test.py --directory build/exec-arguments
test-exec-arguments-native:
	$(PYTHON) scripts/exec_arguments_test.py --native --directory build/exec-arguments-native
build/exec-arguments-policy: kernel/tests/process/exec_arguments.cpp kernel/process/exec_arguments.cpp kernel/include/process/exec_arguments.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/process/exec_arguments.cpp kernel/process/exec_arguments.cpp -o $@
test-exec-arguments-policy: build/exec-arguments-policy
	ASAN_OPTIONS=detect_leaks=1 ./build/exec-arguments-policy
test-waitid:
	$(PYTHON) scripts/waitid_test.py --directory build/waitid
test-waitid-native:
	$(PYTHON) scripts/waitid_test.py --directory build/waitid-native --native
test-proc-identity:
	$(PYTHON) scripts/proc_identity_test.py --directory build/proc-identity
test-proc-identity-native:
	$(PYTHON) scripts/proc_identity_test.py --directory build/proc-identity-native --native
build/proc-identity-policy: kernel/tests/fs/proc_identity.cpp kernel/fs/proc.cpp kernel/process/limits.cpp kernel/include/fs/proc/ipv4.hpp kernel/include/process/limits.hpp kernel/include/fs/proc.hpp kernel/include/process/task.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/fs/proc_identity.cpp kernel/fs/proc.cpp kernel/process/limits.cpp -o $@
test-proc-identity-policy: build/proc-identity-policy
	ASAN_OPTIONS=detect_leaks=1 ./build/proc-identity-policy
test-record-lock-lifecycle:
	$(PYTHON) scripts/record_lock_lifecycle_test.py --directory build/record-lock-lifecycle
test-record-lock-lifecycle-native:
	$(PYTHON) scripts/record_lock_lifecycle_test.py --native --fixtures /tmp/axiom64-record-lock-lifecycle --directory build/record-lock-lifecycle-native
test-parent-death:
	$(PYTHON) scripts/parent_death_test.py --directory build/parent-death
test-parent-death-native:
	$(PYTHON) scripts/parent_death_test.py --directory build/parent-death-native --native
test-signal-wait:
	$(PYTHON) scripts/signal_wait_test.py --directory build/signal-wait
test-signal-wait-native:
	$(PYTHON) scripts/signal_wait_test.py --directory build/signal-wait-native --native
test-account-desktop:
	$(PYTHON) scripts/account_normal_test.py --directory build/account-desktop --graphical
.PHONY: test-account-normal test-vm-state
test-account-normal:
	$(PYTHON) scripts/account_normal_test.py
test-vm-state:
	$(PYTHON) scripts/vm_test.py
openssl:
	$(PYTHON) scripts/build_openssl.py --provider all
libxcrypt:
	$(PYTHON) scripts/build_libxcrypt.py --provider all
curl:
	$(PYTHON) scripts/build_curl.py --provider all
ca-bundle:
	$(PYTHON) scripts/ca_bundle.py
test-password-library-native:
	$(PYTHON) scripts/password_library_test.py
test-password-library:
	$(PYTHON) scripts/password_library_guest.py
test-random-installed:
	$(PYTHON) scripts/random_installed_test.py
test-random-crypto:
	$(PYTHON) scripts/random_crypto_test.py
test-random-crypto-native:
	$(PYTHON) scripts/random_crypto_test.py --native
test-random-crypto-wait:
	$(PYTHON) scripts/random_crypto_wait_test.py
test-random-crypto-wait-native:
	$(PYTHON) scripts/random_crypto_wait_test.py --native
build/crypto-wait-native: userspace/tests/random/crypto_wait.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -Wall -Wextra -Werror $< -o $@
build/crypto-wait-static: userspace/tests/random/crypto_wait.c
	@mkdir -p build
	$(MUSL_CC) -static -std=gnu11 -O2 -Wall -Wextra -Werror $< -o $@
build/crypto-wait-dynamic: userspace/tests/random/crypto_wait.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -Wall -Wextra -Werror $< -o $@
build/rtc-codec: kernel/tests/time/rtc.cpp kernel/firmware/rtc.cpp kernel/include/firmware/rtc.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/time/rtc.cpp kernel/firmware/rtc.cpp -o $@
test-rtc-codec: build/rtc-codec
	ASAN_OPTIONS=detect_leaks=1 ./build/rtc-codec
test-clock-wall:
	$(PYTHON) scripts/clock_wall_test.py
test-clock-wall-native:
	$(PYTHON) scripts/clock_wall_test.py --native
build/clock-wall-native: userspace/tests/time/wall.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/clock-wall-static: userspace/tests/time/wall.c scripts/compile_uapi_client.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -static $<
build/clock-wall-dynamic: userspace/tests/time/wall.c scripts/compile_uapi_client.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $<
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
.PHONY: test-xattr-store
build/xattr-store: kernel/tests/fs/xattr.cpp kernel/fs/xattr_store.cpp kernel/include/fs/xattr.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/fs/xattr.cpp kernel/fs/xattr_store.cpp -o $@
test-xattr-store: build/xattr-store
	ASAN_OPTIONS=detect_leaks=1 ./build/xattr-store
.PHONY: test-ext2-xattr-codec
build/ext2-xattr-codec-test: kernel/tests/fs/ext2_xattr.cpp kernel/fs/ext2/xattr.cpp kernel/fs/xattr_store.cpp kernel/include/fs/ext2/xattr.hpp kernel/include/fs/xattr.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/fs/ext2_xattr.cpp kernel/fs/ext2/xattr.cpp kernel/fs/xattr_store.cpp -o $@
test-ext2-xattr-codec: build/ext2-xattr-codec-test
	ASAN_OPTIONS=detect_leaks=1 $(PYTHON) scripts/tests/ext2_xattr_codec_test.py
.PHONY: test-ext2-journal-native test-ext2-journal test-ext2-journal-lifetime
build/ext2-journal-core-native: kernel/tests/fs/ext2_journal.cpp kernel/fs/ext2/journal.cpp kernel/include/fs/ext2/journal.hpp kernel/include/core/base.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/fs/ext2_journal.cpp kernel/fs/ext2/journal.cpp -o $@
build/ext2-journal-volume-native: kernel/tests/fs/ext2_journal_volume.cpp kernel/fs/ext2/journal.cpp kernel/include/fs/ext2/journal.hpp kernel/include/core/base.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/fs/ext2_journal_volume.cpp kernel/fs/ext2/journal.cpp -o $@
test-ext2-journal-native: build/ext2-journal-core-native build/ext2-journal-volume-native
	ASAN_OPTIONS=detect_leaks=1 ./build/ext2-journal-core-native
	ASAN_OPTIONS=detect_leaks=1 $(PYTHON) scripts/ext2_journal_native_test.py
test-ext2-journal:
	$(PYTHON) scripts/ext2_journal_test.py
test-ext2-journal-lifetime:
	$(PYTHON) scripts/ext2_journal_lifetime_test.py
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
RANDOM_CORE = kernel/core/random/primitives.cpp kernel/core/random/engine.cpp
.PHONY: test-netlink-inventory test-netlink-inventory-native test-netlink-inventory-codec
build/netlink-inventory-codec: kernel/tests/net/inventory.cpp kernel/net/netlink/inventory.cpp kernel/include/net/netlink.hpp kernel/include/net/ipv4.hpp kernel/tests/net/ipv6_disabled.cpp kernel/net/ipv6/wire.cpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
test-netlink-inventory-codec: build/netlink-inventory-codec
	ASAN_OPTIONS=detect_leaks=1 ./build/netlink-inventory-codec
build/netlink-inventory-native: userspace/tests/net/inventory.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/netlink-inventory-static: userspace/tests/net/inventory.c scripts/compile_uapi_client.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -static $<
build/netlink-inventory-dynamic: userspace/tests/net/inventory.c scripts/compile_uapi_client.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $<
test-netlink-inventory:
	$(PYTHON) scripts/netlink_inventory_test.py
test-netlink-inventory-native:
	$(PYTHON) scripts/netlink_inventory_test.py --native
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
.PHONY: test-ownership test-ownership-native
.PHONY: test-normal-manager
.PHONY: test-dns test-dns-native test-dns-tcp test-dns-tcp-native
test-dns:
	$(PYTHON) scripts/dns_test.py
test-dns-native:
	$(PYTHON) scripts/dns_native.py
test-dns-tcp-native:
	$(PYTHON) scripts/tests/musl_dns_tcp_test.py --patched --compare-glibc --output build/dns-tcp-native-sockets-$(shell date +%s%N)
test-dns-tcp:
	$(PYTHON) scripts/dns_tcp_test.py
	$(PYTHON) scripts/dns_tcp_capture.py
	$(PYTHON) scripts/dns_tcp_damaged.py
test-normal-manager:
	$(PYTHON) scripts/normal_manager_test.py
test-ownership:
	$(PYTHON) scripts/ownership_test.py
test-ownership-native:
	$(PYTHON) scripts/ownership_native.py
deps:
	$(PYTHON) scripts/fetch.py
busybox:
	$(PYTHON) scripts/build_busybox.py
build/licenses/.stamp: sources.lock.json ports.lock.json dependencies.json scripts/sources.py scripts/fetch.py
	$(PYTHON) scripts/sources.py prepare
sources: busybox
	$(PYTHON) scripts/sources.py bundle
build/kernel/%.o: kernel/%.cpp vendor/limine.h
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@
build/kernel/arch/x86_64/entry.o: kernel/arch/x86_64/entry.asm
	@mkdir -p $(@D)
	$(NASM) -f elf64 -g -F dwarf $< -o $@
build/axiom64.elf: $(KERNEL_OBJECTS) kernel/arch/x86_64/linker.ld
	ld -nostdlib -static -z max-page-size=0x1000 -T kernel/arch/x86_64/linker.ld $(KERNEL_OBJECTS) -o $@
build/abi-static: userspace/tests/abi/abi.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/file-lock-static: userspace/tests/fs/file-lock.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/file-lock-dynamic: userspace/tests/fs/file-lock.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DLOCK_LINKAGE='"dynamic"' $< -o $@
build/file-lock-native: userspace/tests/fs/file-lock.c Makefile
	@mkdir -p build
	gcc -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -fsanitize=address,undefined -fno-omit-frame-pointer -DLOCK_LINKAGE='"gnu"' $< -o $@
test-file-locks-native:
	$(PYTHON) scripts/file_lock_native.py
test-file-locks:
	$(PYTHON) scripts/file_lock_test.py
build/clock-codec-tests: kernel/tests/time/counter.cpp kernel/core/time.cpp kernel/firmware/acpi.cpp kernel/include/core/time.hpp kernel/include/firmware/acpi.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/time/counter.cpp kernel/core/time.cpp kernel/firmware/acpi.cpp -o $@
test-clock-codec: build/clock-codec-tests
	ASAN_OPTIONS=detect_leaks=1 ./build/clock-codec-tests
build/clock-elapsed-tests: userspace/tests/time/elapsed.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
test-clock:
	$(PYTHON) scripts/clock_test.py
build/abi-dynamic: userspace/tests/abi/abi.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DABI_LINKAGE='"dynamic"' $< -o $@
build/init: userspace/init/main.c userspace/init/console.c userspace/init/console.h userspace/init/seed_records.h
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $(filter %.c,$^) -o $@
build/ipc-tests: userspace/tests/ipc/ipc.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/signal-tests: userspace/tests/process/signals.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/storage-tests: userspace/tests/storage/block.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/vfs-tests: userspace/tests/fs/vfs.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/ext2-tests: userspace/tests/fs/ext2.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/root-tests: userspace/tests/fs/root.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/net-tests: userspace/tests/net/packet.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/ipv4-tests: userspace/tests/net/ipv4.c userspace/tests/net/ipv4_fragments.c userspace/tests/net/ipv4_fragments.h userspace/tests/net/ipv4_path_mtu.c userspace/tests/net/ipv4_path_mtu.h userspace/tests/net/ipv4_query.h userspace/tests/net/ipv4_aliases.c userspace/tests/net/ipv4_aliases.h userspace/tests/net/ipv4_gateways.c userspace/tests/net/ipv4_gateways.h userspace/tests/net/ipv4_unconfigured.c userspace/tests/net/ipv4_unconfigured.h scripts/compile_uapi_client.py scripts/linux_uapi.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $(filter %.c,$^)
build/ipv4-native: userspace/tests/net/ipv4.c userspace/tests/net/ipv4_fragments.c userspace/tests/net/ipv4_fragments.h userspace/tests/net/ipv4_path_mtu.c userspace/tests/net/ipv4_path_mtu.h userspace/tests/net/ipv4_query.h userspace/tests/net/ipv4_aliases.c userspace/tests/net/ipv4_aliases.h userspace/tests/net/ipv4_gateways.c userspace/tests/net/ipv4_gateways.h userspace/tests/net/ipv4_unconfigured.c userspace/tests/net/ipv4_unconfigured.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread $(filter %.c,$^) -o $@
build/ipv4-dynamic: userspace/tests/net/ipv4.c userspace/tests/net/ipv4_fragments.c userspace/tests/net/ipv4_fragments.h userspace/tests/net/ipv4_path_mtu.c userspace/tests/net/ipv4_path_mtu.h userspace/tests/net/ipv4_query.h userspace/tests/net/ipv4_aliases.c userspace/tests/net/ipv4_aliases.h userspace/tests/net/ipv4_gateways.c userspace/tests/net/ipv4_gateways.h userspace/tests/net/ipv4_unconfigured.c userspace/tests/net/ipv4_unconfigured.h scripts/compile_uapi_client.py scripts/linux_uapi.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -pthread $(filter %.c,$^)
build/udp-tests: userspace/tests/net/udp.c scripts/compile_uapi_client.py scripts/linux_uapi.py scripts/build_openssl.py ports.lock.json scripts/build_musl.py sources.lock.json dependencies.json Makefile
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $(filter %.c,$^)
build/dns-static: userspace/tests/net/dns.c userspace/tests/net/dns/contract.h
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/dns-dynamic: userspace/tests/net/dns.c userspace/tests/net/dns/contract.h
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DDNS_LINKAGE='"dynamic"' $< -o $@
build/normal-dns-static: userspace/tests/net/normal-dns.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/normal-dns-dynamic: userspace/tests/net/normal-dns.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DDNS_LINKAGE='"dynamic"' $< -o $@
build/netlink-tests: userspace/tests/net/netlink.cpp userspace/net/config/routing.cpp userspace/net/config/routing.hpp
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -pthread -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu userspace/tests/net/netlink.cpp userspace/net/config/routing.cpp -o $@
build/netlink-native: userspace/tests/net/netlink.cpp userspace/net/config/routing.cpp userspace/net/config/routing.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -pthread -Iuserspace userspace/tests/net/netlink.cpp userspace/net/config/routing.cpp -o $@
PROFILE_SOURCES = userspace/net/config/profile.cpp userspace/net/config/saved.cpp
PROFILE_HEADERS = userspace/net/config/profile.hpp userspace/net/config/saved.hpp userspace/net/dhcp/wire.hpp
PROFILE_FAULTS = -Wl,--wrap=write,--wrap=read,--wrap=close,--wrap=fsync,--wrap=fchmod,--wrap=fchmodat,--wrap=renameat
OWNERSHIP_SOURCES = userspace/tests/net/ownership.cpp userspace/net/manager/ownership.cpp userspace/net/config/saved.cpp
OWNERSHIP_HEADERS = userspace/net/manager/ownership.hpp userspace/net/config/saved.hpp
OWNERSHIP_FAULTS = -Wl,--wrap=flock
MANAGER_SOURCES = userspace/net/manager/main.cpp userspace/net/manager/runtime.cpp userspace/net/manager/static.cpp userspace/net/manager/ownership.cpp userspace/net/config/configuration.cpp userspace/net/config/routing.cpp userspace/net/config/resolver.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/state.cpp userspace/net/dhcp/wire.cpp
MANAGER_HEADERS = userspace/net/manager/runtime.hpp userspace/net/manager/static.hpp userspace/net/manager/ownership.hpp userspace/net/config/configuration.hpp userspace/net/config/routing.hpp userspace/net/config/resolver.hpp $(PROFILE_HEADERS) userspace/net/dhcp/transport.hpp userspace/net/dhcp/state.hpp
MANAGER_NATIVE_SOURCES = $(filter-out userspace/net/manager/main.cpp userspace/net/manager/runtime.cpp,$(MANAGER_SOURCES))
ADDRESS_QUERY_SOURCES = userspace/tests/net/address-query.cpp userspace/net/dhcp/transport.cpp
ADDRESS_QUERY_FLAGS = -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections -Iuserspace -Wl,--gc-sections,--wrap=ioctl
build/address-query-native: $(ADDRESS_QUERY_SOURCES) $(MANAGER_HEADERS)
	@mkdir -p build
	$(CXX) $(ADDRESS_QUERY_FLAGS) $(ADDRESS_QUERY_SOURCES) -o $@
build/address-query-static: $(ADDRESS_QUERY_SOURCES) $(MANAGER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) $(ADDRESS_QUERY_FLAGS) -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu -static $(ADDRESS_QUERY_SOURCES) -o $@
build/address-query-dynamic: $(ADDRESS_QUERY_SOURCES) $(MANAGER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) $(ADDRESS_QUERY_FLAGS) -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $(ADDRESS_QUERY_SOURCES) -o $@
.PHONY: test-manager-runtime-native
build/manager-runtime-native: userspace/tests/net/manager-runtime.cpp userspace/net/manager/runtime.cpp $(MANAGER_NATIVE_SOURCES) $(MANAGER_HEADERS)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iuserspace $< $(MANAGER_NATIVE_SOURCES) -o $@
test-manager-runtime-native: build/manager-runtime-native
	ASAN_OPTIONS=detect_leaks=1 ./build/manager-runtime-native
MANAGER_FAULTS = -Wl,--wrap=renameat,--wrap=fsync,--wrap=rename,--wrap=unlinkat,--wrap=close
build/network-manager-faults: $(MANAGER_SOURCES) $(MANAGER_HEADERS) userspace/tests/net/manager-faults.cpp
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $(MANAGER_SOURCES) userspace/tests/net/manager-faults.cpp $(MANAGER_FAULTS) -o $@
build/network-manager-dynamic-faults: $(MANAGER_SOURCES) $(MANAGER_HEADERS) userspace/tests/net/manager-faults.cpp
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $(MANAGER_SOURCES) userspace/tests/net/manager-faults.cpp $(MANAGER_FAULTS) -o $@
build/network-manager: $(MANAGER_SOURCES) $(MANAGER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $(MANAGER_SOURCES) -o $@
build/network-manager-dynamic: $(MANAGER_SOURCES) $(MANAGER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $(MANAGER_SOURCES) -o $@
build/manager-tests: userspace/tests/net/manager.cpp userspace/tests/net/manager-fixture.hpp userspace/net/config/routing.cpp userspace/net/config/profile.cpp userspace/net/config/saved.cpp userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp $(MANAGER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu userspace/tests/net/manager.cpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp -o $@
build/manager-protocol: userspace/tests/net/manager-protocol.cpp userspace/tests/net/manager-fixture.hpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp $(MANAGER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu userspace/tests/net/manager-protocol.cpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp -o $@
build/manager-link: userspace/tests/net/manager-link.cpp userspace/tests/net/manager-fixture.hpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp $(MANAGER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu userspace/tests/net/manager-link.cpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp -o $@
build/init-supervision: userspace/tests/net/init-supervision.cpp userspace/net/manager/ownership.cpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp $(MANAGER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu userspace/tests/net/init-supervision.cpp userspace/net/manager/ownership.cpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp -o $@
build/static-address-host: userspace/tests/net/static-address.cpp userspace/net/manager/static.cpp userspace/net/manager/static.hpp $(PROFILE_SOURCES) $(PROFILE_HEADERS) userspace/net/dhcp/state.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iuserspace userspace/tests/net/static-address.cpp userspace/net/manager/static.cpp $(PROFILE_SOURCES) -o $@
.PHONY: test-static-address
test-static-address: build/static-address-host
	ASAN_OPTIONS=detect_leaks=1 ./build/static-address-host
.PHONY: test-manager
test-manager:
	$(PYTHON) scripts/manager_test.py
.PHONY: test-manager-protocol
test-manager-protocol:
	$(PYTHON) scripts/manager_protocol_peer_test.py
	$(PYTHON) scripts/manager_protocol_test.py
.PHONY: test-manager-link
test-manager-link:
	$(PYTHON) scripts/manager_link_peer_test.py
	$(PYTHON) scripts/manager_link_test.py
build/ownership-host: $(OWNERSHIP_SOURCES) $(OWNERSHIP_HEADERS)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iuserspace $(OWNERSHIP_SOURCES) $(OWNERSHIP_FAULTS) -o $@
build/ownership-tests: $(OWNERSHIP_SOURCES) $(OWNERSHIP_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace $(OWNERSHIP_SOURCES) $(OWNERSHIP_FAULTS) -o $@
build/ownership-dynamic: $(OWNERSHIP_SOURCES) $(OWNERSHIP_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -Iuserspace $(OWNERSHIP_SOURCES) $(OWNERSHIP_FAULTS) -o $@
CONFIGURATION_SOURCES = userspace/tests/net/configuration.cpp userspace/net/config/configuration.cpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp
CONFIGURATION_HEADERS = userspace/net/config/configuration.hpp userspace/net/config/routing.hpp $(PROFILE_HEADERS) userspace/net/dhcp/transport.hpp userspace/net/dhcp/wire.hpp userspace/net/dhcp/state.hpp
build/configuration-tests: $(CONFIGURATION_SOURCES) $(CONFIGURATION_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $(CONFIGURATION_SOURCES) -o $@
build/configuration-native: $(CONFIGURATION_SOURCES) $(CONFIGURATION_HEADERS)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -Iuserspace $(CONFIGURATION_SOURCES) -o $@
build/dhcp-codec-tests: userspace/tests/net/dhcp.cpp userspace/net/dhcp/wire.cpp userspace/net/dhcp/wire.hpp
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace userspace/tests/net/dhcp.cpp userspace/net/dhcp/wire.cpp -o $@
build/dhcp-codec-host: userspace/tests/net/dhcp.cpp userspace/net/dhcp/wire.cpp userspace/net/dhcp/wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iuserspace userspace/tests/net/dhcp.cpp userspace/net/dhcp/wire.cpp -o $@
build/dhcp-state-tests: userspace/tests/net/dhcp-state.cpp userspace/net/dhcp/state.cpp userspace/net/dhcp/state.hpp userspace/net/dhcp/wire.hpp
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace userspace/tests/net/dhcp-state.cpp userspace/net/dhcp/state.cpp -o $@
build/dhcp-state-host: userspace/tests/net/dhcp-state.cpp userspace/net/dhcp/state.cpp userspace/net/dhcp/state.hpp userspace/net/dhcp/wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iuserspace userspace/tests/net/dhcp-state.cpp userspace/net/dhcp/state.cpp -o $@
build/dhcp-profile-tests: userspace/tests/net/dhcp-profile.cpp $(PROFILE_SOURCES) $(PROFILE_HEADERS) userspace/net/dhcp/wire.hpp
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace userspace/tests/net/dhcp-profile.cpp $(PROFILE_SOURCES) -o $@
build/dhcp-profile-host: userspace/tests/net/dhcp-profile.cpp $(PROFILE_SOURCES) $(PROFILE_HEADERS) userspace/net/dhcp/wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iuserspace userspace/tests/net/dhcp-profile.cpp $(PROFILE_SOURCES) -o $@
build/profile-privacy-host: userspace/tests/net/profile-privacy.cpp $(PROFILE_SOURCES) $(PROFILE_HEADERS)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iuserspace userspace/tests/net/profile-privacy.cpp $(PROFILE_SOURCES) $(PROFILE_FAULTS) -o $@
build/profile-privacy-tests: userspace/tests/net/profile-privacy.cpp $(PROFILE_SOURCES) $(PROFILE_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace userspace/tests/net/profile-privacy.cpp $(PROFILE_SOURCES) $(PROFILE_FAULTS) -o $@
build/profile-privacy-dynamic: userspace/tests/net/profile-privacy.cpp $(PROFILE_SOURCES) $(PROFILE_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -Iuserspace -DPROFILE_LINKAGE='"dynamic"' userspace/tests/net/profile-privacy.cpp $(PROFILE_SOURCES) $(PROFILE_FAULTS) -o $@
DHCP_TRANSPORT_SOURCES = userspace/tests/net/dhcp-transport.cpp userspace/net/config/configuration.cpp userspace/net/config/routing.cpp $(PROFILE_SOURCES) userspace/net/dhcp/transport.cpp userspace/net/dhcp/wire.cpp userspace/net/dhcp/state.cpp
build/dhcp-transport-tests: $(DHCP_TRANSPORT_SOURCES) $(CONFIGURATION_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu $(DHCP_TRANSPORT_SOURCES) -o $@
RESOLVER_SOURCES = userspace/tests/net/resolver.cpp userspace/net/config/resolver.cpp $(PROFILE_SOURCES)
RESOLVER_HEADERS = userspace/net/config/resolver.hpp $(PROFILE_HEADERS) userspace/net/dhcp/wire.hpp
RESOLVER_FAULTS = -Wl,--wrap=rename,--wrap=fsync,--wrap=chmod,--wrap=fchmod
build/resolver-tests: $(RESOLVER_SOURCES) $(RESOLVER_HEADERS)
	@mkdir -p build
	$(MUSL_CC) -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -Iuserspace $(RESOLVER_SOURCES) $(RESOLVER_FAULTS) -o $@
build/resolver-native: $(RESOLVER_SOURCES) $(RESOLVER_HEADERS)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iuserspace $(RESOLVER_SOURCES) $(RESOLVER_FAULTS) -o $@
build/thread-static: userspace/tests/threads/pthreads.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -lm -o $@
build/thread-io-static: userspace/tests/threads/io.c userspace/tests/threads/vectors.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $(filter %.c,$^) -o $@
build/thread-io-dynamic: userspace/tests/threads/io.c userspace/tests/threads/vectors.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DIO_LINKAGE='"dynamic"' $(filter %.c,$^) -o $@
build/io-vectors-native: userspace/tests/threads/vectors.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DIO_VECTORS_MAIN -DIO_LINKAGE='"native"' $< -o $@
build/thread-dynamic: userspace/tests/threads/pthreads.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DTHREAD_LINKAGE='"dynamic"' $< -lm -o $@
build/futex-static: userspace/tests/threads/futex.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/futex-dynamic: userspace/tests/threads/futex.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DFUTEX_LINKAGE='"dynamic"' $< -o $@
build/lifecycle-static: userspace/tests/threads/lifecycle.c userspace/tests/threads/clone.S
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $(filter %.c %.S %.s,$^) -o $@
build/lifecycle-dynamic: userspace/tests/threads/lifecycle.c userspace/tests/threads/clone.S
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DLIFE_LINKAGE='"dynamic"' $(filter %.c %.S %.s,$^) -o $@
build/x11-probe: userspace/tests/desktop/probe.c userspace/desktop/authority.c userspace/desktop/authority.h
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $(filter %.c,$^) -o $@
build/desktop-terminal: userspace/desktop/terminal.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
USERSPACE_DATA = $(foreach pattern,*.sh *.conf *.twmrc,$(call rwildcard,userspace/,$(pattern))) $(wildcard userspace/tests/toolchain/*)
ROOTFS_INPUTS = build/thread-io-static build/thread-io-dynamic build/lifecycle-static build/lifecycle-dynamic build/futex-static build/futex-dynamic build/thread-static build/thread-dynamic build/abi-static build/abi-dynamic build/init build/ipc-tests build/signal-tests build/storage-tests build/vfs-tests build/ext2-tests build/root-tests build/net-tests build/ipv4-tests build/udp-tests build/x11-probe build/licenses/.stamp $(USERSPACE_DATA) ports.lock.json dependencies.json scripts/rootfs.py scripts/ports.py scripts/build_busybox.py scripts/fetch.py
ROOTFS_INPUTS += build/network-manager
ROOTFS_INPUTS += build/random-seed-static
ROOTFS_INPUTS += scripts/build_libcap.py scripts/build_musl.py scripts/build_openssl.py sources.lock.json
ROOTFS_INPUTS += scripts/build_libxcrypt.py scripts/linux_uapi.py
ROOTFS_INPUTS += scripts/build_curl.py scripts/ca_bundle.py
ROOTFS_INPUTS += scripts/build_accounts.py $(wildcard userspace/accounts/*.c userspace/accounts/*.h)
ROOTFS_INPUTS += $(wildcard userspace/desktop/*.c userspace/desktop/*.h)
ROOTFS_INPUTS += build/desktop-terminal
build/rootfs.cpio: $(ROOTFS_INPUTS) | busybox
	$(PYTHON) scripts/rootfs.py
build/rootfs-desktop.cpio: $(ROOTFS_INPUTS) | busybox
	$(PYTHON) scripts/rootfs.py --profile desktop
image: build/axiom64.elf build/rootfs.cpio
	$(PYTHON) scripts/image.py
disk-root: build/axiom64.elf build/rootfs.cpio
	$(PYTHON) scripts/disk_root.py --verify-reproducible
	$(PYTHON) scripts/image.py --root-device /dev/vda --output-name axiom64-disk.iso
test: image
	$(PYTHON) scripts/boot_test.py --firmware both
test-storage:
	$(PYTHON) scripts/storage_test.py
test-ext2:
	$(PYTHON) scripts/ext2_test.py
test-disk-root:
	$(PYTHON) scripts/disk_root_test.py
test-root-io: disk-root
	$(PYTHON) scripts/root_io_test.py
	$(PYTHON) scripts/root_io_test.py --firmware bios --transport modern --delay 35 --expect-timeout
test-network:
	$(PYTHON) scripts/network_matrix.py
test-ipv4:
	$(PYTHON) scripts/ipv4_matrix.py --workers $(IPV4_WORKERS)

.PHONY: test-ipv4-gateways test-ipv4-gateways-native
test-ipv4-gateways:
	$(PYTHON) scripts/tests/compile_uapi_client_test.py
	$(PYTHON) scripts/tests/network_fixture_test.py
	$(PYTHON) scripts/ipv4_gateway_test.py --workers 4
test-ipv4-gateways-native:
	$(PYTHON) scripts/ipv4_alias_native.py --suite gateways
test-udp:
	$(PYTHON) scripts/udp_matrix.py
	$(PYTHON) scripts/tests/udp_capture_test.py
build/netlink-codec-host: kernel/tests/net/netlink.cpp kernel/net/netlink/routes.cpp kernel/include/net/netlink.hpp kernel/include/net/ipv4.hpp kernel/tests/net/ipv6_disabled.cpp kernel/net/ipv6/wire.cpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
test-netlink-codec: build/netlink-codec-host
	./build/netlink-codec-host
.PHONY: test-ipv6-wire test-tcp-wire
build/ipv6-copy-model-native: userspace/tests/net/ipv6_copy_model.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/ipv6-send-model-native: userspace/tests/net/ipv6_send_model.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/ipv6-%-native: userspace/tests/net/ipv6_%.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $(IPV6_FIXTURE_FLAGS) $(filter %.c,$^) -o $@
build/ipv6-%-static: userspace/tests/net/ipv6_%.c scripts/compile_uapi_client.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(IPV6_FIXTURE_FLAGS) -static $(filter %.c,$^)
build/ipv6-%-dynamic: userspace/tests/net/ipv6_%.c scripts/compile_uapi_client.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(IPV6_FIXTURE_FLAGS) $(filter %.c,$^)
build/ipv6-sockets-native build/ipv6-sockets-static build/ipv6-sockets-dynamic build/ipv6-output-native build/ipv6-output-static build/ipv6-output-dynamic: userspace/tests/net/ipv6_fixture.h
build/ipv6-host-native build/ipv6-host-static build/ipv6-host-dynamic: userspace/tests/net/ipv6_address_lifetimes.c userspace/tests/net/ipv6_source_policy.c
build/ipv6-source-policy-native: userspace/tests/net/ipv6_source_policy.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DIPV6_SOURCE_POLICY_STANDALONE $< -o $@
build/ipv6-source-policy-static build/ipv6-source-policy-dynamic: userspace/tests/net/ipv6_source_policy.c scripts/compile_uapi_client.py scripts/build_openssl.py ports.lock.json
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -DIPV6_SOURCE_POLICY_STANDALONE $(if $(filter %-static,$@),-static) $(filter %.c,$^)
build/ipv6-output-native build/ipv6-output-static build/ipv6-output-dynamic: IPV6_FIXTURE_FLAGS = -DIPV6_SEND_CONTROLS_INTEGRATED
build/ipv6-output-native build/ipv6-output-static build/ipv6-output-dynamic: userspace/tests/net/ipv6_send_controls.c userspace/tests/net/ipv6_send_controls_wire.c userspace/tests/net/ipv6_extension_wire.c userspace/tests/net/ipv6_routing_wire.c userspace/tests/net/ipv6_extension_controls.c userspace/tests/net/ipv6_sticky_controls.c userspace/tests/net/ipv6_sticky_wire.c
build/ipv6-pmtu-native build/ipv6-pmtu-static build/ipv6-pmtu-dynamic: userspace/tests/net/ipv6_fixture.h
build/ipv6-errors-native build/ipv6-errors-static build/ipv6-errors-dynamic: userspace/tests/net/ipv6_fixture.h
build/ipv6-errors-native build/ipv6-errors-static build/ipv6-errors-dynamic: IPV6_FIXTURE_FLAGS = -DIPV6_ERROR_CONTROLS_INTEGRATED
build/ipv6-errors-native build/ipv6-errors-static build/ipv6-errors-dynamic: userspace/tests/net/ipv6_error_controls.c
build/ipv6-errors-native build/ipv6-errors-static build/ipv6-errors-dynamic: userspace/tests/net/ipv6_error_metadata.c userspace/tests/net/ipv6_error_record.h userspace/tests/net/ipv6_receive_extensions.c
build/ipv6-cached-native build/ipv6-cached-static build/ipv6-cached-dynamic: userspace/tests/net/ipv6_fixture.h
build/ipv6-expiry-native build/ipv6-expiry-static build/ipv6-expiry-dynamic: userspace/tests/net/ipv6_fixture.h
build/ipv6-controls-native build/ipv6-controls-static build/ipv6-controls-dynamic: userspace/tests/net/ipv6_fixture.h
build/ipv6-controls-native build/ipv6-controls-static build/ipv6-controls-dynamic: IPV6_FIXTURE_FLAGS = -DIPV6_CONTROLS_INTEGRATED
build/ipv6-controls-native build/ipv6-controls-static build/ipv6-controls-dynamic: userspace/tests/net/ipv6_control.c userspace/tests/net/ipv6_control_faults.c userspace/tests/net/ipv6_control_header_faults.c
.PHONY: test-ipv6-copy-model
test-ipv6-copy-model:
	$(PYTHON) scripts/tests/ipv6_copy_model_test.py

test-ipv6-controls-native test-ipv6-errors-native: test-ipv6-copy-model

.PHONY: test-ipv6-send-model
test-ipv6-send-model:
	$(PYTHON) scripts/tests/ipv6_send_model_test.py

test-ipv6-output-native test-ipv6-output-contract: test-ipv6-send-model

.PHONY: test-ipv6-host test-ipv6-host-native test-ipv6-lifetimes-contract
test-ipv6-host:
	$(PYTHON) scripts/ipv6_host_test.py
test-ipv6-host-native:
	$(PYTHON) scripts/ipv6_host_native.py
.PHONY: test-ipv6-configuration test-ipv6-configuration-native
test-ipv6-configuration:
	$(PYTHON) scripts/ipv6_configuration_test.py --directory build/ipv6-configuration-wire
test-ipv6-configuration-native:
	$(PYTHON) scripts/ipv6_configuration_test.py --native --directory build/ipv6-configuration-native
.PHONY: test-ipv6-link-configuration test-ipv6-link-configuration-native
test-ipv6-link-configuration: test-ipv6-configuration-lifetime
	$(PYTHON) scripts/ipv6_configuration_test.py --link-mode --directory build/ipv6-link-configuration-wire
test-ipv6-link-configuration-native: test-ipv6-configuration-lifetime-native
	$(PYTHON) scripts/ipv6_configuration_test.py --link-mode --native --directory build/ipv6-link-configuration-native
.PHONY: test-ipv6-configuration-lifetime test-ipv6-configuration-lifetime-native
test-ipv6-configuration-lifetime:
	$(PYTHON) scripts/ipv6_configuration_test.py --lifetime-mode --directory build/ipv6-configuration-lifetime-wire
test-ipv6-configuration-lifetime-native:
	$(PYTHON) scripts/ipv6_configuration_test.py --lifetime-mode --native --directory build/ipv6-configuration-lifetime-native
.PHONY: test-ipv6-socket-configuration test-ipv6-socket-configuration-native
test-ipv6-socket-configuration:
	$(PYTHON) scripts/ipv6_configuration_test.py --socket-mode --directory build/ipv6-socket-configuration-wire
test-ipv6-socket-configuration-native:
	$(PYTHON) scripts/ipv6_configuration_test.py --socket-mode --native --directory build/ipv6-socket-configuration-native
.PHONY: test-native-address-worker
test-native-address-worker:
	$(PYTHON) scripts/tests/native_address_worker_test.py
.PHONY: test-ipv6-router test-ipv6-router-native
test-ipv6-router:
	$(PYTHON) scripts/ipv6_router_test.py --directory build/ipv6-router-wire
test-ipv6-router-native:
	$(PYTHON) scripts/native_address_worker.py --receipt build/ipv6-router-native-worker.json -- $(PYTHON) scripts/ipv6_router_test.py --native --directory build/ipv6-router-native
.PHONY: test-ipv6-ownership test-ipv6-ownership-native

test-ipv6-ownership:
	$(PYTHON) scripts/ipv6_owner_test.py --group all --directory build/ipv6-owner-wire

test-ipv6-ownership-native:
	$(PYTHON) scripts/ipv6_owner_test.py --native --group all --directory build/ipv6-owner-native

.PHONY: test-ipv6-device test-ipv6-device-native

test-ipv6-device:
	$(PYTHON) scripts/ipv6_device_test.py --directory build/ipv6-device-wire

test-ipv6-device-native:
	$(PYTHON) scripts/ipv6_device_test.py --native --directory build/ipv6-device-native

.PHONY: test-ipv6-device-inventory test-ipv6-device-inventory-native

test-ipv6-device-inventory:
	$(PYTHON) scripts/ipv6_configuration_test.py --device-mode --directory build/ipv6-device-inventory-wire

test-ipv6-device-inventory-native:
	$(PYTHON) scripts/ipv6_configuration_test.py --device-mode --native --directory build/ipv6-device-inventory-native

test-ipv6-lifetimes-contract:
	$(PYTHON) scripts/ipv6_lifetime_contract.py --native-directory build/ipv6-host-native-wire --guest-directory build/ipv6-host-wire --output-directory build/ipv6-lifetime-contract
.PHONY: test-ipv6-sockets test-ipv6-sockets-native
test-ipv6-sockets:
	$(PYTHON) scripts/ipv6_host_test.py --suite sockets
test-ipv6-sockets-native:
	$(PYTHON) scripts/ipv6_host_native.py --suite sockets
.PHONY: test-ipv6-output test-ipv6-output-native
test-ipv6-output: test-ipv6-cached
	$(PYTHON) scripts/ipv6_host_test.py --suite output --workers 2
test-ipv6-output-native: test-ipv6-cached-native
	$(PYTHON) scripts/ipv6_host_native.py --suite output
.PHONY: test-ipv6-output-contract
test-ipv6-output-contract:
	$(PYTHON) scripts/ipv6_send_controls_test.py
	$(PYTHON) scripts/ipv6_extension_contract.py --native-directory build/ipv6-output-native-wire --guest-directory build/ipv6-output-wire --output-directory build/ipv6-extension-contract
	$(PYTHON) scripts/ipv6_sticky_contract.py --native-directory build/ipv6-output-native-wire --guest-directory build/ipv6-output-wire --output-directory build/ipv6-sticky-contract
.PHONY: test-ipv6-pmtu test-ipv6-pmtu-native test-ipv6-pmtu-observation
test-ipv6-pmtu-observation:
	$(PYTHON) scripts/tests/ipv6_pmtu_observation_test.py -v
	$(PYTHON) scripts/tests/packet_observation_test.py -v
test-ipv6-pmtu: test-ipv6-pmtu-observation
	$(PYTHON) scripts/ipv6_host_test.py --suite pmtu --workers 4
test-ipv6-pmtu-native: test-ipv6-pmtu-observation
	$(PYTHON) scripts/ipv6_host_native.py --suite pmtu
.PHONY: test-ipv6-errors test-ipv6-errors-native
.PHONY: test-ipv6-error-record
test-ipv6-error-record:
	$(PYTHON) scripts/tests/ipv6_error_record_test.py -v
test-ipv6-errors:
	$(PYTHON) scripts/ipv6_host_test.py --suite errors --workers 4
test-ipv6-errors-native:
	$(PYTHON) scripts/ipv6_host_native.py --suite errors --workers 3
.PHONY: test-ipv6-errors-contract
test-ipv6-errors-contract:
	$(PYTHON) scripts/ipv6_error_controls_test.py
	$(PYTHON) scripts/ipv6_receive_extensions_contract.py --native-directory build/ipv6-errors-native-wire --guest-directory build/ipv6-errors-wire --output-directory build/ipv6-receive-extensions-contract
.PHONY: test-ipv6-expiry test-ipv6-expiry-native
test-ipv6-expiry:
	$(PYTHON) scripts/ipv6_host_test.py --suite expiry --workers 4
test-ipv6-expiry-native:
	$(PYTHON) scripts/ipv6_host_native.py --suite expiry --workers 3
.PHONY: test-ipv6-controls test-ipv6-controls-native
test-ipv6-controls:
	$(PYTHON) scripts/ipv6_host_test.py --suite controls --workers 4
test-ipv6-controls-native:
	$(PYTHON) scripts/ipv6_host_native.py --suite controls --workers 3
.PHONY: test-ipv6-controls-contract
test-ipv6-controls-contract:
	$(PYTHON) scripts/ipv6_controls_contract_test.py
.PHONY: test-ipv6-fragments test-ipv6-fragments-native
test-ipv6-fragments: test-ipv6-fragment-observation
	$(PYTHON) scripts/ipv6_host_test.py --suite fragments --workers 4
test-ipv6-fragments-native: test-ipv6-fragment-observation
	$(PYTHON) scripts/ipv6_host_native.py --suite fragments
build/ipv6-wire-host: kernel/tests/net/ipv6_wire.cpp kernel/net/ipv6/wire.cpp kernel/include/net/ipv6/wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
build/ipv6-host: kernel/tests/net/ipv6_host.cpp kernel/tests/net/ipv6_output_owner.cpp kernel/tests/net/ipv6_link_configuration.cpp kernel/tests/net/ipv6_router.cpp kernel/tests/net/ipv6_address_lifecycle.cpp $(IPV6_CORE) kernel/fs/proc/ipv6.cpp kernel/fs/proc/integer.cpp kernel/net/ipv6/socket/send_control.cpp kernel/net/ethernet.cpp kernel/net/netlink/ipv6.cpp kernel/net/netlink/addresses.cpp kernel/net/netlink/link.cpp kernel/net/netlink/inventory.cpp kernel/net/netlink/routes.cpp $(call rwildcard,kernel/include/,*.hpp)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections -Ikernel/include $(filter %.cpp,$^) -o $@
build/ipv6-reassembly-host: kernel/tests/net/ipv6_reassembly.cpp kernel/net/ipv6/reassembly.cpp kernel/net/ipv6/wire.cpp kernel/include/net/ipv6/reassembly.hpp kernel/include/net/ipv6/wire.hpp kernel/include/core/base.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv6-reassembly
test-ipv6-reassembly: build/ipv6-reassembly-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/ipv6-reassembly-host
build/ipv6-fragmentation-host: kernel/tests/net/ipv6_fragmentation.cpp kernel/net/ipv6/fragmentation.cpp kernel/net/ipv6/wire.cpp kernel/include/net/ipv6/fragmentation.hpp kernel/include/net/ipv6/wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv6-fragmentation
test-ipv6-fragmentation: build/ipv6-fragmentation-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/ipv6-fragmentation-host
build/ipv6-path-mtu-host: kernel/tests/net/ipv6_path_mtu.cpp kernel/net/ipv6/path_mtu.cpp kernel/net/ipv6/icmp.cpp kernel/net/ipv6/extensions.cpp kernel/net/ipv6/wire.cpp kernel/include/net/ipv6/path_mtu.hpp kernel/include/net/ipv6/icmp.hpp kernel/include/net/ipv6/wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv6-path-mtu
test-ipv6-path-mtu: build/ipv6-path-mtu-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/ipv6-path-mtu-host
.PHONY: test-ipv6-fragment-observation
test-ipv6-fragment-observation:
	$(PYTHON) scripts/tests/ipv6_fragment_observation_test.py -v
.PHONY: test-ipv6-host-maintenance test-ipv6-queued-source-log test-ipv6-queued-source-clock
test-ipv6-queued-source-clock:
	$(PYTHON) scripts/tests/ipv6_queued_sources_clock_test.py

test-ipv6-queued-source-log:
	$(PYTHON) scripts/tests/ipv6_queued_sources_log_test.py

test-ipv6-host-maintenance: test-ipv6-source-policy-contract
	$(PYTHON) scripts/tests/ipv6_host_maintenance_test.py -v

.PHONY: test-ipv6-source-policy-contract
test-ipv6-source-policy-contract:
	$(PYTHON) scripts/tests/ipv6_source_policy_contract_test.py
test-ipv6-wire: test-ipv6-copy-model test-ipv6-send-model test-ipv6-fragment-observation test-ipv6-host-maintenance test-ipv6-queued-source-log test-ipv6-queued-source-clock build/ipv6-wire-host build/ipv6-host build/ipv6-reassembly-host build/ipv6-fragmentation-host build/ipv6-path-mtu-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/ipv6-path-mtu-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/ipv6-fragmentation-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/ipv6-reassembly-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/ipv6-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/ipv6-wire-host
build/ipv4-reassembly-host: kernel/tests/net/ipv4_reassembly.cpp kernel/net/ipv4/reassembly.cpp kernel/include/net/ipv4/reassembly.hpp kernel/include/net/ipv4_wire.hpp kernel/include/core/base.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/ipv4_reassembly.cpp kernel/net/ipv4/reassembly.cpp -o $@
.PHONY: test-ipv4-reassembly
test-ipv4-reassembly: build/ipv4-reassembly-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-reassembly-host
build/ipv4-fragmentation-host: kernel/tests/net/ipv4_fragmentation.cpp kernel/net/ipv4/fragmentation.cpp kernel/include/net/ipv4/fragmentation.hpp kernel/include/net/ipv4_wire.hpp kernel/include/core/base.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/ipv4_fragmentation.cpp kernel/net/ipv4/fragmentation.cpp -o $@
.PHONY: test-ipv4-fragmentation
test-ipv4-fragmentation: build/ipv4-fragmentation-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-fragmentation-host
build/ipv4-path-mtu-host: kernel/tests/net/ipv4_path_mtu.cpp kernel/net/ipv4/path_mtu.cpp kernel/include/net/ipv4/path_mtu.hpp kernel/include/net/ipv4_wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/ipv4_path_mtu.cpp kernel/net/ipv4/path_mtu.cpp -o $@
.PHONY: test-ipv4-path-mtu
test-ipv4-path-mtu: build/ipv4-path-mtu-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-path-mtu-host
build/ipv4-paths-host: kernel/tests/net/ipv4_paths.cpp kernel/net/ipv4/core.cpp kernel/net/ipv4/addresses.cpp kernel/net/ipv4/path_mtu.cpp kernel/net/ipv4/reassembly.cpp kernel/net/ethernet.cpp $(IPV6_CORE) $(call rwildcard,kernel/include/,*.hpp) $(IPV4_MULTICAST_CORE)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv4-paths
build/ipv4-output-host: kernel/tests/net/ipv4_output.cpp kernel/net/ipv4/core.cpp kernel/net/ipv4/addresses.cpp kernel/net/ipv4/path_mtu.cpp kernel/net/ipv4/reassembly.cpp kernel/net/ipv4/fragmentation.cpp kernel/net/ethernet.cpp $(IPV6_CORE) $(call rwildcard,kernel/include/,*.hpp) $(IPV4_MULTICAST_CORE)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections -Ikernel/include $(filter %.cpp,$^) -o $@
build/ipv4-socket-output-host: kernel/tests/net/ipv4_socket_output.cpp kernel/net/ipv4/socket.cpp kernel/net/udp/core.cpp kernel/net/ipv4/core.cpp kernel/net/ipv4/addresses.cpp kernel/net/ipv4/path_mtu.cpp kernel/net/ipv4/reassembly.cpp kernel/net/ipv4/fragmentation.cpp kernel/net/ethernet.cpp $(IPV6_CORE) $(call rwildcard,kernel/include/,*.hpp) kernel/net/ipv4/socket.hpp $(IPV4_MULTICAST_CORE)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections -Ikernel/include $(filter %.cpp,$^) -o $@
test-ipv4-paths: build/ipv4-paths-host build/ipv4-addresses-host build/ipv4-output-host build/ipv4-socket-output-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-paths-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-output-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-socket-output-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-addresses-host
build/ipv4-addresses-host: kernel/tests/net/ipv4_addresses.cpp kernel/net/ipv4/addresses.cpp $(call rwildcard,kernel/include/,*.hpp)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv4-fragments-native
test-ipv4-fragments-native:
	$(PYTHON) scripts/ipv4_fragment_native.py

build/native-icmp-budget: scripts/tests/native_icmp_budget.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
.PHONY: test-native-icmp-budget
test-native-icmp-budget: build/native-icmp-budget
	$(PYTHON) scripts/native_icmp_budget_test.py
	$(PYTHON) scripts/tests/native_icmp_stagger_test.py --directory build/native-icmp-budget-evidence/scheduling-regression

build/tcp-wire-host: kernel/tests/net/tcp_wire.cpp kernel/net/tcp/wire.cpp kernel/net/tcp/wire_detail.hpp kernel/include/net/tcp/wire.hpp kernel/include/net/ipv4_wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/tcp_wire.cpp kernel/net/tcp/wire.cpp -o $@
build/tcp-ipv6-wire-host: kernel/tests/net/tcp_ipv6_wire.cpp kernel/net/tcp/wire.cpp kernel/net/tcp/wire_ipv6.cpp kernel/net/tcp/wire_detail.hpp kernel/net/ipv6/wire.cpp kernel/include/net/tcp/wire.hpp kernel/include/net/ipv6/wire.hpp kernel/include/net/ipv4_wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/tcp_ipv6_wire.cpp kernel/net/tcp/wire.cpp kernel/net/tcp/wire_ipv6.cpp kernel/net/ipv6/wire.cpp -o $@
test-tcp-wire: build/tcp-wire-host build/tcp-ipv6-wire-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/tcp-wire-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/tcp-ipv6-wire-host
.PHONY: test-tcp-sender
build/tcp-sender-host: kernel/tests/net/tcp_sender.cpp kernel/net/tcp/sender.cpp kernel/include/net/tcp/sender.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/tcp_sender.cpp kernel/net/tcp/sender.cpp -o $@
test-tcp-sender: build/tcp-sender-host
	ASAN_OPTIONS=detect_leaks=1 ./build/tcp-sender-host
build/tcp-connection-host: kernel/tests/net/tcp_connection.cpp kernel/net/tcp/connection.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/sender.cpp kernel/net/tcp/wire.cpp kernel/net/tcp/wire_detail.hpp kernel/include/net/tcp/connection.hpp kernel/include/net/tcp/time_wait.hpp kernel/include/net/tcp/sender.hpp kernel/include/net/tcp/wire.hpp kernel/include/net/ipv4_wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/tcp_connection.cpp kernel/net/tcp/connection.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/sender.cpp kernel/net/tcp/wire.cpp -o $@
.PHONY: test-tcp-connection
build/tcp-socket-output-host: kernel/tests/net/tcp_socket_output.cpp kernel/tests/net/tcp_ipv6_socket.cpp kernel/tests/net/tcp_ipv6_error.cpp kernel/tests/net/tcp_ipv6_reset.cpp kernel/net/ipv4/socket.cpp kernel/net/udp/core.cpp kernel/net/ipv4/core.cpp kernel/net/ipv4/addresses.cpp kernel/net/ipv4/path_mtu.cpp kernel/net/ipv4/reassembly.cpp kernel/net/ipv4/fragmentation.cpp kernel/net/ethernet.cpp $(IPV6_CORE) kernel/core/random/primitives.cpp kernel/net/tcp/connection.cpp kernel/net/tcp/icmp.cpp kernel/net/tcp/isn.cpp kernel/net/tcp/sender.cpp kernel/net/tcp/socket.cpp kernel/net/tcp/icmp_ipv6.cpp kernel/net/tcp/wire_ipv6.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/wire.cpp kernel/net/tcp/wire_detail.hpp $(call rwildcard,kernel/include/,*.hpp) kernel/net/ipv4/socket.hpp $(IPV4_MULTICAST_CORE)
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections -Ikernel/include $(filter %.cpp,$^) -o $@
test-tcp-connection: build/tcp-connection-host build/tcp-socket-output-host
	ASAN_OPTIONS=detect_leaks=1 ./build/tcp-connection-host
	ASAN_OPTIONS=detect_leaks=1 ./build/tcp-socket-output-host
build/tcp-icmp-host: kernel/tests/net/tcp_icmp.cpp kernel/net/tcp/icmp.cpp kernel/net/tcp/connection.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/sender.cpp kernel/net/tcp/wire.cpp kernel/net/tcp/wire_detail.hpp kernel/include/net/tcp/icmp.hpp kernel/include/net/tcp/connection.hpp kernel/include/net/tcp/time_wait.hpp kernel/include/net/tcp/sender.hpp kernel/include/net/tcp/wire.hpp kernel/include/net/ipv4_wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/tcp_icmp.cpp kernel/net/tcp/icmp.cpp kernel/net/tcp/connection.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/sender.cpp kernel/net/tcp/wire.cpp -o $@
.PHONY: test-tcp-icmp
test-tcp-icmp: build/tcp-icmp-host
	ASAN_OPTIONS=detect_leaks=1 ./build/tcp-icmp-host

build/tcp-pmtu-host: kernel/tests/net/tcp_pmtu.cpp kernel/net/tcp/icmp.cpp kernel/net/tcp/connection.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/sender.cpp kernel/net/tcp/wire.cpp kernel/net/tcp/wire_detail.hpp kernel/include/net/tcp/icmp.hpp kernel/include/net/tcp/connection.hpp kernel/include/net/tcp/time_wait.hpp kernel/include/net/tcp/sender.hpp kernel/include/net/tcp/wire.hpp kernel/include/net/ipv4_wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/tcp_pmtu.cpp kernel/net/tcp/icmp.cpp kernel/net/tcp/connection.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/sender.cpp kernel/net/tcp/wire.cpp -o $@
.PHONY: test-tcp-pmtu
test-tcp-pmtu: build/tcp-pmtu-host
	ASAN_OPTIONS=detect_leaks=1 ./build/tcp-pmtu-host
build/tcp-time-wait-host: kernel/tests/net/tcp_time_wait.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/wire.cpp kernel/net/tcp/wire_detail.hpp kernel/include/net/tcp/time_wait.hpp kernel/include/net/tcp/wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/tcp_time_wait.cpp kernel/net/tcp/time_wait.cpp kernel/net/tcp/wire.cpp -o $@
.PHONY: test-tcp-time-wait
test-tcp-time-wait: build/tcp-time-wait-host
	ASAN_OPTIONS=detect_leaks=1 ./build/tcp-time-wait-host
build/tcp-isn-host: kernel/tests/net/tcp_isn.cpp kernel/net/tcp/isn.cpp kernel/core/random/primitives.cpp kernel/include/net/tcp/isn.hpp kernel/include/core/random/primitives.hpp kernel/include/net/ipv4_wire.hpp kernel/include/net/ipv6/wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/tcp_isn.cpp kernel/net/tcp/isn.cpp kernel/core/random/primitives.cpp -o $@
.PHONY: test-tcp-isn
test-tcp-isn: build/tcp-isn-host
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/tcp-isn-host
build/tcp6-abi-native: userspace/tests/net/tcp6/abi.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp6-local-native: userspace/tests/net/tcp6/local.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
.PHONY: test-tcp6-native
build/tcp6-fault-native: userspace/tests/net/tcp_fault.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DTCP_IPV6 $< -o $@
build/tcp6-fault-static build/tcp6-fault-dynamic: userspace/tests/net/tcp_fault.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -DTCP_IPV6 $(if $(filter %-static,$@),-static) $(filter %.c,$^)
build/tcp6-scoped-native: userspace/tests/net/tcp_fault.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -DTCP_IPV6 -DTCP_IPV6_LINK_LOCAL $< -o $@
build/tcp6-scoped-static build/tcp6-scoped-dynamic: userspace/tests/net/tcp_fault.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -DTCP_IPV6 -DTCP_IPV6_LINK_LOCAL $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-scoped test-tcp6-scoped-native
test-tcp6-scoped:
	$(PYTHON) scripts/tcp6_test.py --suite scoped
test-tcp6-scoped-native:
	$(PYTHON) scripts/tcp6_test.py --suite scoped --native
build/tcp6-replies-native: userspace/tests/net/tcp6/replies.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp6-replies-static build/tcp6-replies-dynamic: userspace/tests/net/tcp6/replies.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-replies test-tcp6-replies-native
test-tcp6-replies:
	$(PYTHON) scripts/tcp6_test.py --suite replies
test-tcp6-replies-native:
	$(PYTHON) scripts/tcp6_test.py --suite replies --native
build/tcp6-isolation-native: userspace/tests/net/tcp6/isolation.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp6-isolation-static build/tcp6-isolation-dynamic: userspace/tests/net/tcp6/isolation.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-isolation test-tcp6-isolation-native
test-tcp6-isolation:
	$(PYTHON) scripts/tcp6_test.py --suite isolation
test-tcp6-isolation-native:
	$(PYTHON) scripts/tcp6_test.py --suite isolation --native

build/tcp6-zone-source-route-native: userspace/tests/net/tcp6/zone_source_route.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $< -o $@
build/tcp6-zone-source-route-static build/tcp6-zone-source-route-dynamic: userspace/tests/net/tcp6/zone_source_route.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-zone-source-route test-tcp6-zone-source-route-native
test-tcp6-zone-source-route:
	$(PYTHON) scripts/tcp6_test.py --suite zone-source-route
test-tcp6-zone-source-route-native:
	$(PYTHON) scripts/tcp6_test.py --suite zone-source-route --native

build/tcp6-zone-route-native: userspace/tests/net/tcp6/zone_route.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $< -o $@
build/tcp6-zone-route-static build/tcp6-zone-route-dynamic: userspace/tests/net/tcp6/zone_route.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-zone-route test-tcp6-zone-route-native
test-tcp6-zone-route:
	$(PYTHON) scripts/tcp6_test.py --suite zone-route
test-tcp6-zone-route-native:
	$(PYTHON) scripts/tcp6_test.py --suite zone-route --native

build/tcp6-scoped-source-native: userspace/tests/net/tcp6/scoped_source.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $< -o $@
build/tcp6-scoped-source-static build/tcp6-scoped-source-dynamic: userspace/tests/net/tcp6/scoped_source.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-scoped-source test-tcp6-scoped-source-native
test-tcp6-scoped-source:
	$(PYTHON) scripts/tcp6_test.py --suite scoped-source
test-tcp6-scoped-source-native:
	$(PYTHON) scripts/tcp6_test.py --suite scoped-source --native

build/tcp6-source-expiry-native: userspace/tests/net/tcp6/source_expiry.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $< -o $@
build/tcp6-source-expiry-static build/tcp6-source-expiry-dynamic: userspace/tests/net/tcp6/source_expiry.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-source-expiry test-tcp6-source-expiry-native
test-tcp6-source-expiry:
	$(PYTHON) scripts/tcp6_test.py --suite source-expiry
test-tcp6-source-expiry-native:
	$(PYTHON) scripts/tcp6_test.py --suite source-expiry --native

build/tcp6-pending-source-native: userspace/tests/net/tcp6/pending_source.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $< -o $@
build/tcp6-pending-source-static build/tcp6-pending-source-dynamic: userspace/tests/net/tcp6/pending_source.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-pending-source test-tcp6-pending-source-native
test-tcp6-pending-source:
	$(PYTHON) scripts/tcp6_test.py --suite pending-source
test-tcp6-pending-source-native:
	$(PYTHON) scripts/tcp6_test.py --suite pending-source --native

build/tcp6-source-lifetime-native: userspace/tests/net/tcp6/source_lifetime.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $< -o $@
build/tcp6-source-lifetime-static build/tcp6-source-lifetime-dynamic: userspace/tests/net/tcp6/source_lifetime.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-source-lifetime test-tcp6-source-lifetime-native
test-tcp6-source-lifetime:
	$(PYTHON) scripts/tcp6_test.py --suite source-lifetime
test-tcp6-source-lifetime-native:
	$(PYTHON) scripts/tcp6_test.py --suite source-lifetime --native

# All families share one client; each executable fixes its socket family at build time.
define TCP6_CONTROL_CLIENT
build/tcp6-controls-$(1)-native: userspace/tests/net/tcp6/control_wire.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net -DWIRE_FAMILY=$(2) $$< -o $$@
build/tcp6-controls-$(1)-static build/tcp6-controls-$(1)-dynamic: userspace/tests/net/tcp6/control_wire.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$$(PYTHON) scripts/compile_uapi_client.py --output $$@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -Iuserspace/tests/net -DWIRE_FAMILY=$(2) $$(if $$(filter %-static,$$@),-static) $$(filter %.c,$$^)
endef
$(eval $(call TCP6_CONTROL_CLIENT,ipv6,0))
$(eval $(call TCP6_CONTROL_CLIENT,mapped,1))
$(eval $(call TCP6_CONTROL_CLIENT,ipv4,2))

.PHONY: test-tcp6-controls-wire test-tcp6-controls-wire-native
test-tcp6-controls-wire:
	$(PYTHON) scripts/tcp6_test.py --suite controls-ipv6
	$(PYTHON) scripts/tcp6_test.py --suite controls-mapped
	$(PYTHON) scripts/tcp6_test.py --suite controls-ipv4

test-tcp6-controls-wire-native:
	$(PYTHON) scripts/tcp6_test.py --suite controls-ipv6 --native
	$(PYTHON) scripts/tcp6_test.py --suite controls-mapped --native
	$(PYTHON) scripts/tcp6_test.py --suite controls-ipv4 --native

build/tcp6-pmtu-native: userspace/tests/net/tcp6/pmtu.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp6-pmtu-static build/tcp6-pmtu-dynamic: userspace/tests/net/tcp6/pmtu.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-wire test-tcp6-wire-native
build/tcp6-errors-native: userspace/tests/net/tcp6/errors.c userspace/tests/net/ipv6_fixture.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp6-errors-static build/tcp6-errors-dynamic: userspace/tests/net/tcp6/errors.c userspace/tests/net/ipv6_fixture.h scripts/compile_uapi_client.py
	@mkdir -p build
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) $(filter %.c,$^)
.PHONY: test-tcp6-errors test-tcp6-errors-native
test-tcp6-errors:
	$(PYTHON) scripts/tcp6_test.py --suite errors
test-tcp6-errors-native:
	$(PYTHON) scripts/tcp6_test.py --suite errors --native
test-tcp6-wire:
	$(PYTHON) scripts/tcp6_test.py
test-tcp6-wire-native:
	$(PYTHON) scripts/tcp6_test.py --native
.PHONY: test-tcp6-pmtu test-tcp6-pmtu-native
test-tcp6-pmtu:
	$(PYTHON) scripts/tcp6_test.py --suite pmtu
test-tcp6-pmtu-native:
	$(PYTHON) scripts/tcp6_test.py --suite pmtu --native
build/tcp6-mss-native: userspace/tests/net/tcp6/mss.c userspace/tests/net/tcp_maxseg.c userspace/tests/net/tcp_maxseg.h
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $(filter %.c,$^) -o $@
test-tcp6-native: build/tcp6-abi-native build/tcp6-local-native build/tcp6-mss-native
	./build/tcp6-abi-native
	./build/tcp6-local-native
	./build/tcp6-mss-native --native
.PHONY: test-tcp6-abi
test-tcp6-abi: build/axiom64.elf build/init busybox
	$(PYTHON) scripts/tcp6_abi_test.py
.PHONY: test-tcp6-control-state
test-tcp6-control-state: build/axiom64.elf build/init busybox
	$(PYTHON) scripts/tcp6_control_state_test.py
build/tcp-native: userspace/tests/net/tcp.c userspace/tests/net/tcp_maxseg.c userspace/tests/net/tcp_maxseg.h
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread $(filter %.c,$^) -o $@
build/tcp-static: userspace/tests/net/tcp.c userspace/tests/net/tcp_maxseg.c userspace/tests/net/tcp_maxseg.h
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror -pthread $(filter %.c,$^) -o $@
build/tcp-dynamic: userspace/tests/net/tcp.c userspace/tests/net/tcp_maxseg.c userspace/tests/net/tcp_maxseg.h
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread $(filter %.c,$^) -o $@
.PHONY: test-tcp-native test-tcp-sockets test-tcp-native-wire
test-tcp-native:
	$(PYTHON) scripts/tcp_native_test.py
test-tcp-sockets:
	$(PYTHON) scripts/tcp_test.py
test-tcp-native-wire:
	$(PYTHON) scripts/tests/tcp_forward_ports_test.py
	$(PYTHON) scripts/tcp_native_wire.py
build/tcp-fault-native: userspace/tests/net/tcp_fault.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-fault-static: userspace/tests/net/tcp_fault.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-fault-dynamic: userspace/tests/net/tcp_fault.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-timeout-native: userspace/tests/net/tcp_timeout.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-icmp-native: userspace/tests/net/tcp_icmp.c userspace/tests/net/tcp_icmp_cases.h
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
build/tcp-icmp-static: userspace/tests/net/tcp_icmp.c userspace/tests/net/tcp_icmp_cases.h
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
build/tcp-icmp-dynamic: userspace/tests/net/tcp_icmp.c userspace/tests/net/tcp_icmp_cases.h
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
build/tcp-pmtu-native: userspace/tests/net/tcp_pmtu.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
build/tcp-pmtu-static: userspace/tests/net/tcp_pmtu.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
build/tcp-pmtu-dynamic: userspace/tests/net/tcp_pmtu.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
build/tcp-recovery-native: userspace/tests/net/tcp_recovery.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@

build/tcp-recovery-static: userspace/tests/net/tcp_recovery.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@

build/tcp-recovery-dynamic: userspace/tests/net/tcp_recovery.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@

.PHONY: test-tcp-recovery-native test-tcp-recovery-sockets
test-tcp-recovery-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire recovery
test-tcp-recovery-sockets:
	$(PYTHON) scripts/tcp_fault_test.py --wire recovery

build/tcp-reconnect-native: userspace/tests/net/tcp_reconnect.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-reconnect-static: userspace/tests/net/tcp_reconnect.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-reconnect-dynamic: userspace/tests/net/tcp_reconnect.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
.PHONY: test-tcp-reconnect-native test-tcp-reconnect-sockets test-tcp-reconnect-observer
test-tcp-reconnect-observer:
	$(PYTHON) scripts/tests/tcp_reconnect_observer_test.py
test-tcp-reconnect-native: test-tcp-reconnect-observer
	$(PYTHON) scripts/tcp_fault_native.py --wire reconnect
test-tcp-reconnect-sockets: test-tcp-reconnect-observer
	$(PYTHON) scripts/tcp_fault_test.py --wire reconnect --workers 2
build/tcp-pressure-native: userspace/tests/net/tcp_pressure.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
build/tcp-pressure-static: userspace/tests/net/tcp_pressure.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
build/tcp-pressure-dynamic: userspace/tests/net/tcp_pressure.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread $< -o $@
.PHONY: test-tcp-pressure
test-tcp-pressure:
	$(PYTHON) scripts/tcp_pressure_test.py
.PHONY: test-tcp-pmtu-native test-tcp-pmtu-sockets test-tcp-pmtu-observer-retirement
test-tcp-pmtu-observer-retirement:
	$(PYTHON) scripts/tests/tcp_pmtu_observer_retirement_test.py
test-tcp-pmtu-native: test-tcp-pmtu-observer-retirement
	$(PYTHON) scripts/tcp_fault_native.py --wire pmtu
test-tcp-pmtu-sockets:
	$(PYTHON) scripts/tcp_fault_test.py --wire pmtu
.PHONY: test-tcp-icmp-native test-tcp-icmp-sockets test-tcp-icmp-timestamps
test-tcp-icmp-timestamps:
	$(PYTHON) scripts/tests/tcp_icmp_timestamp_test.py -v
test-tcp-icmp-native: test-tcp-icmp-timestamps
	$(PYTHON) scripts/tcp_fault_native.py --wire icmp
test-tcp-icmp-sockets: test-tcp-icmp-timestamps
	$(PYTHON) scripts/tcp_fault_test.py --wire icmp
build/tcp-lifetime-native: userspace/tests/net/tcp_lifetime.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-lifetime-static: userspace/tests/net/tcp_lifetime.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-lifetime-dynamic: userspace/tests/net/tcp_lifetime.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
.PHONY: test-tcp-lifetime test-tcp-lifetime-native
test-tcp-lifetime:
	$(PYTHON) scripts/tcp_lifetime/acceptance.py guest
test-tcp-lifetime-native:
	$(PYTHON) scripts/tcp_lifetime/acceptance.py native
build/tcp-challenge-native: userspace/tests/net/tcp_fault.c
	@mkdir -p build
	$(CC) -DTCP_CHALLENGE -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-challenge-static: userspace/tests/net/tcp_fault.c
	@mkdir -p build
	$(MUSL_CC) -DTCP_CHALLENGE -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-challenge-dynamic: userspace/tests/net/tcp_fault.c
	@mkdir -p build
	$(MUSL_CC) -DTCP_CHALLENGE -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-timeout-static: userspace/tests/net/tcp_timeout.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-timeout-dynamic: userspace/tests/net/tcp_timeout.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
.PHONY: test-tcp-timeout test-tcp-timeout-native
test-tcp-timeout:
	$(PYTHON) scripts/tcp_fault_test.py --wire timeout
test-tcp-timeout-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire timeout
.PHONY: test-tcp-challenge test-tcp-challenge-native
test-tcp-challenge:
	$(PYTHON) scripts/tcp_fault_test.py --wire challenge
test-tcp-challenge-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire challenge
build/tcp-malformed-native: userspace/tests/net/tcp_malformed.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-malformed-static: userspace/tests/net/tcp_malformed.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-malformed-dynamic: userspace/tests/net/tcp_malformed.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
.PHONY: test-tcp-malformed test-tcp-malformed-native
test-tcp-malformed:
	$(PYTHON) scripts/tcp_fault_test.py --wire malformed --workers 2
test-tcp-malformed-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire malformed
build/tcp-device-native: userspace/tests/net/tcp_device.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-device-static: userspace/tests/net/tcp_device.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-device-dynamic: userspace/tests/net/tcp_device.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
.PHONY: test-tcp-device test-tcp-device-native
test-tcp-device:
	$(PYTHON) scripts/tcp_device/run.py guest --workers 2
test-tcp-device-native:
	$(PYTHON) scripts/tcp_device/run.py native
build/tcp-window-native: userspace/tests/net/tcp_window.c
	@mkdir -p build
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-window-static: userspace/tests/net/tcp_window.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -static -O2 -g -Wall -Wextra -Werror $< -o $@
build/tcp-window-dynamic: userspace/tests/net/tcp_window.c
	@mkdir -p build
	$(MUSL_CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror $< -o $@
.PHONY: test-tcp-window test-tcp-window-native test-tcp-fast test-tcp-fast-native
test-tcp-window:
	$(PYTHON) scripts/tcp_fault_test.py --wire window --workers 2
test-tcp-window-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire window
test-tcp-fast:
	$(PYTHON) scripts/tcp_fault_test.py --wire fast --workers 2
test-tcp-fast-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire fast
.PHONY: test-tcp-old-ack test-tcp-old-ack-native
test-tcp-old-ack:
	$(PYTHON) scripts/tcp_fault_test.py --wire old-ack
test-tcp-old-ack-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire old-ack
.PHONY: test-tcp-fault test-tcp-fault-native test-tcp-reordering test-tcp-reordering-native test-tcp-persist test-tcp-persist-native
test-tcp-fault:
	$(PYTHON) scripts/tcp_fault_test.py
test-tcp-fault-native:
	$(PYTHON) scripts/tests/tcp_fault_native_test.py
	$(PYTHON) scripts/tcp_fault_native.py
test-tcp-reordering:
	$(PYTHON) scripts/tcp_fault_test.py --wire reordering
test-tcp-reordering-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire reordering
test-tcp-persist:
	$(PYTHON) scripts/tcp_fault_test.py --wire persist
test-tcp-persist-native:
	$(PYTHON) scripts/tcp_fault_native.py --wire persist
build/address-codec-host: kernel/tests/net/address.cpp kernel/net/netlink/addresses.cpp kernel/net/ipv4/addresses.cpp kernel/include/net/ipv4/addresses.hpp kernel/include/net/netlink.hpp kernel/include/net/ipv4.hpp kernel/include/net/ipv4_wire.hpp kernel/tests/net/ipv6_disabled.cpp kernel/net/ipv6/wire.cpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
test-address-codec: build/address-codec-host
	./build/address-codec-host
test-netlink:
	$(PYTHON) scripts/netlink_test.py
test-configuration: build/configuration-tests
	$(PYTHON) scripts/configuration_test.py
test-dhcp-codec: build/dhcp-codec-host build/dhcp-state-host build/dhcp-profile-host
	./build/dhcp-codec-host
	./build/dhcp-state-host
	./build/dhcp-profile-host
test-dhcp-modules:
	$(PYTHON) scripts/dhcp_modules_test.py
test-profiles:
	$(PYTHON) scripts/profile_test.py
test-dhcp-transport:
	$(PYTHON) scripts/dhcp_transport_test.py
test-resolver: build/resolver-tests
	$(PYTHON) scripts/resolver_test.py
test-resolver-native: build/resolver-native
	$(PYTHON) scripts/resolver_native.py
test-threads:
	$(PYTHON) scripts/boot_test.py --suite threads --firmware both --timeout 170
.PHONY: test-thread-io-native
test-thread-io-native: build/thread-io-static build/thread-io-dynamic build/io-vectors-native
	./build/thread-io-static >build/thread-io-static-native.log
	cat build/thread-io-static-native.log
	./build/thread-io-dynamic >build/thread-io-dynamic-native.log
	cat build/thread-io-dynamic-native.log
	./build/io-vectors-native >build/io-vectors-native.log
	cat build/io-vectors-native.log
test-thread-io:
	$(PYTHON) scripts/boot_test.py --suite threads --phase io --firmware both --timeout 90
build/virtqueue-tests: kernel/tests/drivers/virtio/queue.cpp kernel/drivers/virtio/queue.cpp kernel/include/drivers/virtio/queue.hpp kernel/include/core/base.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/drivers/virtio/queue.cpp kernel/drivers/virtio/queue.cpp -o $@
test-virtqueue: build/virtqueue-tests
	./build/virtqueue-tests
test-virtio:
	$(PYTHON) scripts/virtio_test.py
format:
	$(CLANG_FORMAT) -i $(FORMAT_SOURCES)
check-format:
	$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_SOURCES)
run: build/axiom64.elf build/rootfs.cpio
	$(PYTHON) scripts/vm.py
run-serial: build/axiom64.elf build/rootfs.cpio
	$(PYTHON) scripts/vm.py --serial
clean:
	$(PYTHON) scripts/clean.py

-include $(KERNEL_OBJECTS:.o=.d)

# All guest programs share the checked source-built build provider.
MUSL_INPUTS = sources.lock.json scripts/build_musl.py scripts/musl_cc.py $(wildcard vendor/musl/patches/*.patch)
MUSL_PROGRAMS = build/address-query-static build/address-query-dynamic build/credentials-static build/credentials-dynamic build/random-static build/random-dynamic build/abi-static build/file-lock-static build/file-lock-dynamic build/clock-elapsed-tests build/abi-dynamic build/init build/ipc-tests build/signal-tests build/storage-tests build/vfs-tests build/ext2-tests build/root-tests build/net-tests build/ipv4-tests build/udp-tests build/dns-static build/dns-dynamic build/normal-dns-static build/normal-dns-dynamic build/netlink-tests build/network-manager-faults build/network-manager-dynamic-faults build/network-manager build/network-manager-dynamic build/manager-tests build/manager-protocol build/manager-link build/init-supervision build/ownership-tests build/ownership-dynamic build/configuration-tests build/dhcp-codec-tests build/dhcp-state-tests build/dhcp-profile-tests build/profile-privacy-tests build/profile-privacy-dynamic build/dhcp-transport-tests build/resolver-tests build/thread-static build/thread-io-static build/thread-io-dynamic build/thread-dynamic build/futex-static build/futex-dynamic build/lifecycle-static build/lifecycle-dynamic build/x11-probe build/tcp-static build/tcp-dynamic build/tcp-fault-static build/tcp-fault-dynamic build/tcp-lifetime-static build/tcp-lifetime-dynamic build/tcp-challenge-static build/tcp-challenge-dynamic build/tcp-timeout-static build/tcp-timeout-dynamic build/ipv4-multicast-static build/ipv4-multicast-dynamic
MUSL_PROGRAMS += build/tcp-icmp-static build/tcp-icmp-dynamic
MUSL_PROGRAMS += build/ipv4-dynamic
MUSL_PROGRAMS += build/tcp-pmtu-static build/tcp-pmtu-dynamic
MUSL_PROGRAMS += build/tcp-pressure-static build/tcp-pressure-dynamic
MUSL_PROGRAMS += build/tcp-reconnect-static build/tcp-reconnect-dynamic
MUSL_PROGRAMS += build/tcp-recovery-static build/tcp-recovery-dynamic
MUSL_PROGRAMS += build/tcp-malformed-static build/tcp-malformed-dynamic
MUSL_PROGRAMS += build/tcp-window-static build/tcp-window-dynamic
MUSL_PROGRAMS += build/tcp-device-static build/tcp-device-dynamic
MUSL_PROGRAMS += build/random-admin-static build/random-admin-dynamic
MUSL_PROGRAMS += build/crypto-wait-static build/crypto-wait-dynamic
MUSL_PROGRAMS += build/random-seed-static build/random-seed-dynamic
MUSL_PROGRAMS += build/random-seed-probe-static build/random-seed-probe-dynamic
MUSL_PROGRAMS += build/random-seed-fault-static build/random-seed-fault-dynamic
MUSL_PROGRAMS += build/random-seed-stop-static build/random-seed-stop-dynamic
MUSL_PROGRAMS += build/random-seed-crash-static build/random-seed-crash-dynamic
MUSL_PROGRAMS += build/random-seed-recovery-static build/random-seed-recovery-dynamic
MUSL_PROGRAMS += build/netlink-inventory-static build/netlink-inventory-dynamic
MUSL_PROGRAMS += build/clock-wall-static build/clock-wall-dynamic
MUSL_PROGRAMS += build/random-snapshot-static build/random-snapshot-dynamic
MUSL_PROGRAMS += build/generation-exec-static build/generation-exec-dynamic
MUSL_PROGRAMS += build/ipv4-multicast-source-static build/ipv4-multicast-source-dynamic
MUSL_PROGRAMS += build/ipv4-multicast-source-wire-static build/ipv4-multicast-source-wire-dynamic
MUSL_PROGRAMS += build/ipv4-multicast-source-options-static build/ipv4-multicast-source-options-dynamic
MUSL_PROGRAMS += build/ipv4-multicast-source-policy-static build/ipv4-multicast-source-policy-dynamic
MUSL_PROGRAMS += build/ipv4-multicast-source-capacity-static build/ipv4-multicast-source-capacity-dynamic
MUSL_PROGRAMS += build/ipv4-raw-udp-static build/ipv4-raw-udp-dynamic
$(MUSL_PROGRAMS): $(MUSL_INPUTS) | musl-toolchain
build/rootfs.cpio build/rootfs-desktop.cpio: $(MUSL_INPUTS)
.PHONY: musl-toolchain
musl-toolchain:
	$(PYTHON) scripts/build_musl.py --provider build --compiler-specs

build/dns-static build/dns-dynamic: userspace/tests/net/dns/contract.h
build/dns-tcp-static: userspace/tests/net/dns-tcp.c userspace/tests/net/dns/contract.h $(MUSL_INPUTS) | musl-toolchain
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/dns-tcp-dynamic: userspace/tests/net/dns-tcp.c userspace/tests/net/dns/contract.h $(MUSL_INPUTS) | musl-toolchain
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DDNS_LINKAGE='"dynamic"' $< -o $@

.PHONY: test-ipv6-cached test-ipv6-cached-native
test-ipv6-cached:
	$(PYTHON) scripts/ipv6_host_test.py --suite cached --workers 4
test-ipv6-cached-native:
	$(PYTHON) scripts/ipv6_host_native.py --suite cached

.PHONY: test-ipv4-multicast
build/ipv4-multicast-host: kernel/tests/net/ipv4_multicast.cpp $(filter-out %/runtime.cpp %/source_options.cpp,$(IPV4_MULTICAST_CORE)) kernel/include/net/ipv4/multicast.hpp kernel/include/net/ipv4/source_filter.hpp kernel/include/net/ipv4/source_aggregate.hpp kernel/include/net/ipv4_wire.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
test-ipv4-multicast: build/ipv4-multicast-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-multicast-host
	$(PYTHON) scripts/tests/native_multicast_timers_test.py

build/ipv4-multicast-static: userspace/tests/net/ipv4_multicast.c scripts/compile_uapi_client.py scripts/linux_uapi.py Makefile
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror -static userspace/tests/net/ipv4_multicast.c

build/ipv4-multicast-dynamic: userspace/tests/net/ipv4_multicast.c scripts/compile_uapi_client.py scripts/linux_uapi.py Makefile
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror userspace/tests/net/ipv4_multicast.c

build/ipv4-multicast-source-native: userspace/tests/net/ipv4_multicast_source.c
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@

build/ipv4-multicast-source-static build/ipv4-multicast-source-dynamic: userspace/tests/net/ipv4_multicast_source.c scripts/compile_uapi_client.py scripts/linux_uapi.py Makefile
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) userspace/tests/net/ipv4_multicast_source.c

build/ipv4-source-aggregate-host: kernel/tests/net/ipv4_source_aggregate.cpp kernel/net/ipv4/multicast/source_aggregate.cpp kernel/include/net/ipv4/source_aggregate.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/ipv4_source_aggregate.cpp kernel/net/ipv4/multicast/source_aggregate.cpp -o $@

.PHONY: test-ipv4-source-aggregate
test-ipv4-source-aggregate: build/ipv4-source-aggregate-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-source-aggregate-host

build/ipv4-source-filter-host: kernel/tests/net/ipv4_source_filter.cpp kernel/net/ipv4/multicast/source_filter.cpp kernel/net/ipv4/multicast/source_aggregate.cpp kernel/include/net/ipv4/source_filter.hpp kernel/include/net/ipv4/source_aggregate.hpp
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv4-source-filter
test-ipv4-source-filter: build/ipv4-source-filter-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-source-filter-host

build/ipv4-multicast-source-host: kernel/tests/net/ipv4_multicast_source_host.cpp $(filter-out %/runtime.cpp %/source_options.cpp,$(IPV4_MULTICAST_CORE)) kernel/include/net/ipv4/multicast.hpp kernel/include/net/ipv4/source_filter.hpp kernel/include/net/ipv4/source_aggregate.hpp kernel/include/net/ipv4_wire.hpp
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv4-multicast-source-host
test-ipv4-multicast-source-host: build/ipv4-multicast-source-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-multicast-source-host

build/ipv4-multicast-source-options-native: userspace/tests/net/ipv4_multicast_source_options.c
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/ipv4-multicast-source-options-static build/ipv4-multicast-source-options-dynamic: userspace/tests/net/ipv4_multicast_source_options.c scripts/compile_uapi_client.py scripts/linux_uapi.py Makefile
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) userspace/tests/net/ipv4_multicast_source_options.c

build/ipv4-multicast-source-policy-native: userspace/tests/net/ipv4_multicast_source_policy.c
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/ipv4-multicast-source-policy-static build/ipv4-multicast-source-policy-dynamic: userspace/tests/net/ipv4_multicast_source_policy.c scripts/compile_uapi_client.py scripts/linux_uapi.py Makefile
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) userspace/tests/net/ipv4_multicast_source_policy.c

build/ipv4-multicast-source-capacity-native: userspace/tests/net/ipv4_multicast_source_capacity.c
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/ipv4-multicast-source-capacity-static build/ipv4-multicast-source-capacity-dynamic: userspace/tests/net/ipv4_multicast_source_capacity.c scripts/compile_uapi_client.py scripts/linux_uapi.py Makefile
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) userspace/tests/net/ipv4_multicast_source_capacity.c

build/ipv4-source-reports-host: kernel/tests/net/ipv4_multicast_source_reports.cpp kernel/net/ipv4/multicast/source_reports.cpp kernel/net/ipv4/multicast/source_aggregate.cpp kernel/include/net/ipv4/source_reports.hpp kernel/include/net/ipv4/source_aggregate.hpp kernel/include/net/ipv4/source_filter.hpp
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv4-source-reports
test-ipv4-source-reports: build/ipv4-source-reports-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-source-reports-host

build/ipv4-multicast-source-wire-host: kernel/tests/net/ipv4_multicast_source_wire.cpp $(filter-out %/runtime.cpp %/source_options.cpp,$(IPV4_MULTICAST_CORE)) kernel/include/net/ipv4/multicast.hpp kernel/include/net/ipv4/source_filter.hpp kernel/include/net/ipv4/source_aggregate.hpp kernel/include/net/ipv4_wire.hpp
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include $(filter %.cpp,$^) -o $@
.PHONY: test-ipv4-multicast-source-wire-host
test-ipv4-multicast-source-wire-host: build/ipv4-multicast-source-wire-host
	ASAN_OPTIONS=detect_leaks=1 ./build/ipv4-multicast-source-wire-host

build/ipv4-multicast-source-wire-native: userspace/tests/net/ipv4_multicast_source_wire.c userspace/tests/net/ipv4_multicast_source_delivery.c userspace/tests/net/ipv4_multicast_source_delivery.h
	@mkdir -p build
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $(filter %.c,$^) -o $@

build/ipv4-multicast-source-wire-static build/ipv4-multicast-source-wire-dynamic: userspace/tests/net/ipv4_multicast_source_wire.c userspace/tests/net/ipv4_multicast_source_delivery.c scripts/compile_uapi_client.py scripts/linux_uapi.py Makefile userspace/tests/net/ipv4_multicast_source_delivery.h
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) userspace/tests/net/ipv4_multicast_source_wire.c userspace/tests/net/ipv4_multicast_source_delivery.c

build/ipv4-raw-udp-native: userspace/tests/net/ipv4_raw_udp.c
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@
build/ipv4-raw-udp-static build/ipv4-raw-udp-dynamic: userspace/tests/net/ipv4_raw_udp.c scripts/compile_uapi_client.py scripts/linux_uapi.py Makefile
	$(PYTHON) scripts/compile_uapi_client.py --output $@ -- -std=c11 -O2 -g -Wall -Wextra -Werror $(if $(filter %-static,$@),-static) userspace/tests/net/ipv4_raw_udp.c
