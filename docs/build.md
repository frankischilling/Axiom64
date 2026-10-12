# Build and run

Use Ubuntu 24.04 x86-64, directly or through WSL Ubuntu. Static userspace and BusyBox use a source-built Ubuntu musl 1.2.4-2 provider. The installed interpreter and development libraries use the pinned Alpine musl 1.2.5-r12 source and distribution patches. Both providers apply the checked [local DNS transport patch](../vendor/musl/README.md); the host libc and compiler installation stay unchanged.

```sh
sudo apt-get update
sudo apt-get install -y g++ make musl-tools linux-libc-dev nasm python3 \
    xorriso qemu-system-x86 qemu-utils ovmf xfonts-utils e2fsprogs nbdkit nbdkit-plugin-python gdb
make -j2 image
make run
```

The first build downloads verified archives, builds BusyBox, assembles the root filesystem, and produces `build/axiom64.iso`. Allow several gigabytes of free disk space. Host Linux provides the build tools and QEMU emulator; the guest runs Axiom64's kernel.

`make run` boots through BIOS with a graphical QEMU window and an authenticated serial console. First boot asks you to create an administrator and enter its password privately, then requires login. Later boots use the same account and require its password again. The administrator starts Bash with UID/GID 1000 and explicit `sudo` membership; root's password login is locked. Enter passwords in the guest. The [account documentation](accounts.md) describes the current commands and policy.

The VM keeps its ext2 root in `.local/vm/root.ext2`. The launch helper creates that disk once, preserves it across builds and restarts, and prevents two instances from opening the same state directory. It rejects incomplete or damaged creation metadata instead of recreating accounts. Keep this directory to retain your accounts and files. Existing disks retain their installed userspace; to evaluate newly packaged userspace, select a new directory with `python3 scripts/vm.py --state-directory .local/vm-next`. In-guest upgrades remain future work.

Authenticated graphical startup and seat access are still being integrated. The dedicated desktop tests retain Xorg, twm, xeyes and xterm/Bash coverage; the current normal startup enters the serial login session.

On WSL, the graphical command requires a working WSLg display. `make run-serial` starts the same image with a hidden framebuffer and exposes the serial console.

To boot the same persistent VM through UEFI:

```sh
python3 scripts/vm.py --firmware uefi
```

The full image includes these commands:

```sh
gcc --version
getcap /usr/bin/gcc
sudo make -C /root/toolchain-test test
zsh -f
```

The example Makefile compiles and runs C and C++ programs, exercises exceptions, threads, synchronization, and the standard library, and checks a rejected C source file. The standalone `build/axiom64.iso` uses a disposable RAM root: directly booting it starts fresh and does not preserve accounts or files. The normal launch commands use the persistent disk described above. [Mounted ext2 data volumes](ext2.md) and [disk-root fixtures](disk-root.md) provide separate storage tests. The initial target is QEMU's emulated PC with PS/2 input and a 1024x768 boot framebuffer.

On the host, `make test-thread-io` runs the focused BIOS/UEFI [blocking I/O tests](io.md#verification-and-limits). `make test-threads` and `make test` include those tests alongside their broader suites.
