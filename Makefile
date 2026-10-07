CXX = g++
NASM = nasm
PYTHON = python3
CXXFLAGS = -std=c++20 -O2 -g -Wall -Wextra -Werror -ffreestanding -fno-exceptions -fno-rtti -fno-stack-protector -fno-pie -fno-threadsafe-statics -fno-use-cxa-atexit -fno-builtin -m64 -mno-red-zone -mcmodel=kernel -mgeneral-regs-only -Ikernel/include -Ivendor
KERNEL_SOURCES = $(wildcard kernel/*.cpp)
KERNEL_OBJECTS = $(patsubst kernel/%.cpp,build/kernel/%.o,$(KERNEL_SOURCES)) build/kernel/entry.o

.PHONY: all image test run run-serial deps busybox sources clean
all: image
deps:
	$(PYTHON) scripts/fetch.py
busybox:
	$(PYTHON) scripts/build_busybox.py
build/licenses/.stamp: sources.lock.json ports.lock.json dependencies.json scripts/sources.py scripts/fetch.py
	$(PYTHON) scripts/sources.py prepare
sources: busybox
	$(PYTHON) scripts/sources.py bundle
build/kernel/%.o: kernel/%.cpp $(wildcard kernel/include/*.hpp) vendor/limine.h
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@
build/kernel/entry.o: kernel/entry.asm
	@mkdir -p $(@D)
	$(NASM) -f elf64 -g -F dwarf $< -o $@
build/axiom64.elf: $(KERNEL_OBJECTS) kernel/linker.ld
	ld -nostdlib -static -z max-page-size=0x1000 -T kernel/linker.ld $(KERNEL_OBJECTS) -o $@
build/abi-static: userspace/abi-tests.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/abi-dynamic: userspace/abi-tests.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -DABI_LINKAGE='"dynamic"' $< -o $@
build/init: userspace/init.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/ipc-tests: userspace/ipc-tests.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/signal-tests: userspace/signal-tests.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
build/x11-probe: userspace/x11-probe.c
	@mkdir -p build
	musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@
ROOTFS_INPUTS = build/abi-static build/abi-dynamic build/init build/ipc-tests build/signal-tests build/x11-probe build/licenses/.stamp $(wildcard userspace/*.sh userspace/*.conf userspace/*.twmrc) $(wildcard userspace/toolchain-test/*) ports.lock.json dependencies.json scripts/rootfs.py scripts/ports.py scripts/build_busybox.py scripts/fetch.py
build/rootfs.cpio: $(ROOTFS_INPUTS) | busybox
	$(PYTHON) scripts/rootfs.py
build/rootfs-desktop.cpio: $(ROOTFS_INPUTS) | busybox
	$(PYTHON) scripts/rootfs.py --profile desktop
image: build/axiom64.elf build/rootfs.cpio
	$(PYTHON) scripts/image.py
test: image
	$(PYTHON) scripts/boot_test.py --firmware both
run: image
	qemu-system-x86_64 -machine pc -cpu max -m 2G -cdrom build/axiom64.iso -serial stdio -no-reboot
run-serial: image
	qemu-system-x86_64 -machine pc -cpu max -m 2G -cdrom build/axiom64.iso -serial stdio -display none -no-reboot
clean:
	$(PYTHON) scripts/clean.py

-include $(KERNEL_OBJECTS:.o=.d)
