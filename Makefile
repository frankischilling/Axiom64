CXX = g++
NASM = nasm
PYTHON = python3
CXXFLAGS = -std=c++20 -O2 -g -Wall -Wextra -Werror -ffreestanding -fno-exceptions -fno-rtti -fno-stack-protector -fno-pie -fno-threadsafe-statics -fno-use-cxa-atexit -fno-builtin -m64 -mno-red-zone -mcmodel=kernel -mgeneral-regs-only -Ikernel/include -Ivendor
KERNEL_SOURCES = $(wildcard kernel/*.cpp)
KERNEL_OBJECTS = $(patsubst kernel/%.cpp,build/kernel/%.o,$(KERNEL_SOURCES)) build/kernel/entry.o

.PHONY: all image test run deps busybox clean
all: image
deps:
	$(PYTHON) scripts/fetch.py
busybox:
	$(PYTHON) scripts/build_busybox.py
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
build/rootfs.cpio: build/abi-static build/abi-dynamic build/init userspace/boot-test.sh busybox
	$(PYTHON) scripts/rootfs.py
image: build/axiom64.elf build/rootfs.cpio
	$(PYTHON) scripts/image.py
test: image
	$(PYTHON) scripts/boot_test.py --firmware both
run: image
	qemu-system-x86_64 -machine pc -cpu max -m 512M -cdrom build/axiom64.iso -serial stdio -display none -no-reboot
clean:
	$(PYTHON) scripts/clean.py

-include $(KERNEL_OBJECTS:.o=.d)
