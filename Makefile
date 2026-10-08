CXX = g++
NASM = nasm
PYTHON = python3
CLANG_FORMAT ?= clang-format-20
CXXFLAGS = -std=c++20 -O2 -g -Wall -Wextra -Werror -ffreestanding -fno-exceptions -fno-rtti -fno-stack-protector -fno-pie -fno-threadsafe-statics -fno-use-cxa-atexit -fno-builtin -m64 -mno-red-zone -mcmodel=kernel -mgeneral-regs-only -Ikernel/include -Ivendor
rwildcard = $(foreach entry,$(wildcard $1*),$(call rwildcard,$(entry)/,$2) $(filter $(subst *,%,$2),$(entry)))
KERNEL_SOURCES = $(filter-out kernel/tests/%,$(call rwildcard,kernel/,*.cpp))
KERNEL_OBJECTS = $(patsubst kernel/%.cpp,build/kernel/%.o,$(KERNEL_SOURCES)) build/kernel/arch/x86_64/entry.o
FORMAT_SOURCES = $(foreach pattern,*.cpp *.hpp,$(call rwildcard,kernel/,$(pattern))) $(foreach pattern,*.c *.cpp *.hpp,$(call rwildcard,userspace/,$(pattern)))

.PHONY: all image disk-root test test-storage test-ext2 test-disk-root test-root-io test-network test-ipv4 test-udp test-netlink test-netlink-codec test-threads test-thread-io test-virtqueue test-virtio format check-format run run-serial deps busybox sources clean
all: image
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
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/abi-dynamic: userspace/tests/abi/abi.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -DABI_LINKAGE='"dynamic"' $< -o $@
build/init: userspace/init/main.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/ipc-tests: userspace/tests/ipc/ipc.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/signal-tests: userspace/tests/process/signals.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/storage-tests: userspace/tests/storage/block.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/vfs-tests: userspace/tests/fs/vfs.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/ext2-tests: userspace/tests/fs/ext2.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/root-tests: userspace/tests/fs/root.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/net-tests: userspace/tests/net/packet.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/ipv4-tests: userspace/tests/net/ipv4.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/udp-tests: userspace/tests/net/udp.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/netlink-tests: userspace/tests/net/netlink.cpp userspace/net/config/routing.cpp userspace/net/config/routing.hpp
	@mkdir -p build
	musl-gcc -std=c++20 -O2 -g -Wall -Wextra -Werror -fno-exceptions -fno-rtti -static -pthread -Iuserspace -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu userspace/tests/net/netlink.cpp userspace/net/config/routing.cpp -o $@
build/netlink-native: userspace/tests/net/netlink.cpp userspace/net/config/routing.cpp userspace/net/config/routing.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -pthread -Iuserspace userspace/tests/net/netlink.cpp userspace/net/config/routing.cpp -o $@
build/thread-static: userspace/tests/threads/pthreads.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -lm -o $@
build/thread-io-static: userspace/tests/threads/io.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/thread-io-dynamic: userspace/tests/threads/io.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DIO_LINKAGE='"dynamic"' $< -o $@
build/thread-dynamic: userspace/tests/threads/pthreads.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DTHREAD_LINKAGE='"dynamic"' $< -lm -o $@
build/futex-static: userspace/tests/threads/futex.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $< -o $@
build/futex-dynamic: userspace/tests/threads/futex.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DFUTEX_LINKAGE='"dynamic"' $< -o $@
build/lifecycle-static: userspace/tests/threads/lifecycle.c userspace/tests/threads/clone.S
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread $^ -o $@
build/lifecycle-dynamic: userspace/tests/threads/lifecycle.c userspace/tests/threads/clone.S
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -pthread -DLIFE_LINKAGE='"dynamic"' $^ -o $@
build/x11-probe: userspace/tests/desktop/probe.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
USERSPACE_DATA = $(foreach pattern,*.sh *.conf *.twmrc,$(call rwildcard,userspace/,$(pattern))) $(wildcard userspace/tests/toolchain/*)
ROOTFS_INPUTS = build/thread-io-static build/thread-io-dynamic build/lifecycle-static build/lifecycle-dynamic build/futex-static build/futex-dynamic build/thread-static build/thread-dynamic build/abi-static build/abi-dynamic build/init build/ipc-tests build/signal-tests build/storage-tests build/vfs-tests build/ext2-tests build/root-tests build/net-tests build/ipv4-tests build/udp-tests build/x11-probe build/licenses/.stamp $(USERSPACE_DATA) ports.lock.json dependencies.json scripts/rootfs.py scripts/ports.py scripts/build_busybox.py scripts/fetch.py
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
	$(PYTHON) scripts/ipv4_matrix.py
test-udp:
	$(PYTHON) scripts/udp_matrix.py
build/netlink-codec-host: kernel/tests/net/netlink.cpp kernel/net/netlink/routes.cpp kernel/include/net/netlink.hpp kernel/include/net/ipv4.hpp
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Ikernel/include kernel/tests/net/netlink.cpp kernel/net/netlink/routes.cpp -o $@
test-netlink-codec: build/netlink-codec-host
	./build/netlink-codec-host
test-netlink:
	$(PYTHON) scripts/netlink_test.py
test-threads:
	$(PYTHON) scripts/boot_test.py --suite threads --firmware both --timeout 170
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
run: image
	qemu-system-x86_64 -machine pc -cpu max -m 2G -cdrom build/axiom64.iso -serial stdio -no-reboot
run-serial: image
	qemu-system-x86_64 -machine pc -cpu max -m 2G -cdrom build/axiom64.iso -serial stdio -display none -no-reboot
clean:
	$(PYTHON) scripts/clean.py

-include $(KERNEL_OBJECTS:.o=.d)
