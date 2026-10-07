# Build and run

Use Ubuntu 24.04 x86-64, directly or through WSL Ubuntu. Static userspace is built with Ubuntu musl 1.2.4-2; the guest dynamic loader comes from the separately pinned musl port.

```sh
sudo apt-get update
sudo apt-get install -y g++ make musl-tools linux-libc-dev nasm python3 \
    xorriso qemu-system-x86 ovmf xfonts-utils
make -j2 image
make run
```

The first build downloads verified archives, builds BusyBox, assembles the root filesystem, and produces `build/axiom64.iso`. Allow several gigabytes of free disk space. Host Linux provides the build tools and QEMU emulator; the guest runs Axiom64's kernel.

`make run` boots through BIOS with a graphical QEMU window and serial console. The normal image starts Xorg, twm, xeyes, and xterm running interactive Bash. BusyBox ash remains available in the host terminal through the guest serial device. Closing the initial xterm ends the desktop session; run `startx` from ash to start it again.

On WSL, the graphical command requires a working WSLg display. `make run-serial` starts the same image with a hidden framebuffer and exposes the serial console.

To boot the interactive image through UEFI:

```sh
cp /usr/share/OVMF/OVMF_VARS_4M.fd build/OVMF_VARS.fd
qemu-system-x86_64 -machine pc -cpu max -m 2G \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=build/OVMF_VARS.fd \
    -cdrom build/axiom64.iso -serial stdio -no-reboot
```

The full image includes these commands:

```sh
gcc --version
make -C /root/toolchain-test test
zsh -f
```

The example Makefile compiles and runs C and C++ programs, exercises exceptions and the standard library, and checks a rejected C source file. Files are held in RAM and disappear when the guest exits. The initial target is QEMU's emulated PC with PS/2 input and a 1024x768 boot framebuffer.
