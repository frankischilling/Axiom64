# Build and run

Use Ubuntu 24.04 x86-64, directly or through WSL Ubuntu. Static userspace and BusyBox use a source-built Ubuntu musl 1.2.4-2 provider. The installed interpreter and development libraries use the pinned Alpine musl 1.2.5-r13 source and distribution patches. Both providers apply the checked [local DNS transport patch](../vendor/musl/README.md); the host libc and compiler installation stay unchanged.

```sh
sudo apt-get update
sudo apt-get install -y g++ make musl-tools linux-libc-dev nasm python3 \
    xorriso qemu-system-x86 qemu-utils ovmf xfonts-utils e2fsprogs nbdkit nbdkit-plugin-python gdb
make -j2 image
make run
```

The first build downloads verified archives, builds BusyBox, assembles the root filesystem, and produces `build/axiom64.iso`. Allow several gigabytes of free disk space. Host Linux provides the build tools and QEMU emulator; the guest runs Axiom64's kernel.

BusyBox downloads can use the mirrors listed in `dependencies.json` when upstream is unavailable. Every source must supply the same pinned bytes. A hash mismatch stops the build. The local `prepare` test suite verifies essential boot sources and locked package inputs before compiling providers.

`make run` boots through BIOS with a graphical QEMU window and an authenticated serial console. First boot asks you to create an administrator and enter its password privately, then requires login. Later boots use the same account and require its password again. The administrator starts Bash with UID/GID 1000 and explicit `sudo` membership; root's password login is locked. Enter passwords in the guest. The [account documentation](accounts.md) describes the current commands and policy.

The VM keeps its root in `.local/vm/root.ext2`. New roots use the classic ext3 format with a 32 MiB internal journal. The kernel mounts them through the ext2 driver. Existing state directories keep their original filesystems and installed userspace. The launch helper creates the disk once, locks the state while the VM runs, and refuses incomplete creation metadata. Keep the state directory to retain your accounts and files. To test newly packaged userspace in a separate VM, run `python3 scripts/vm.py --state-directory .local/vm-next`. In-guest upgrades remain future work.

After authentication, normal startup launches Xorg, twm, xeyes and an ordinary-user terminal alongside the private serial shell. A fresh private X11 cookie controls display access. Local BIOS/UEFI RAM/ext2 checks cover input, logout and display/console failure; complete service and crash-recovery integration remains required. See [authenticated desktop sessions](accounts.md#authenticated-desktop).

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

## Raw disk and network boot

After `make image`, use `scripts/boot_media.py` to package the same kernel and
initramfs for a raw virtual disk or a TFTP server. Disk packaging uses
`dosfstools`, `mtools`, and `sfdisk` (`fdisk` on Ubuntu).

```sh
python3 scripts/boot_media.py disk build/axiom64-boot.raw
qemu-system-x86_64 -m 2G -serial stdio -boot order=c \
    -drive file=build/axiom64-boot.raw,format=raw,if=ide,snapshot=on

python3 scripts/boot_media.py pxe build/axiom64-pxe
qemu-system-x86_64 -m 2G -serial stdio -boot order=n \
    -device e1000,netdev=pxe \
    -netdev user,id=pxe,restrict=on,tftp=build/axiom64-pxe,bootfile=limine-bios-pxe.bin
```

The disk uses GPT with a BIOS boot partition and a FAT32 EFI system partition.
For UEFI, add OVMF firmware to the QEMU command. Select `BOOTX64.EFI` as the
network boot file under UEFI. A separate TFTP server must support the `tsize`
option. Both media store a compressed initramfs and expand it at boot. Use the normal VM launcher
to keep accounts and files across boots.

The first Limine module supplies the initramfs. BIOS and UEFI boot logs report
the module count and initramfs size. PID 1 defaults to `/sbin/init`. Pass
`--init-path /absolute/path` to `scripts/image.py` or `scripts/boot_media.py`
to select another executable on the chosen guest root. Duplicate, empty,
relative, or oversized `init=` values fail before userspace starts.

Run `make test-suite SUITE=secondary-boot` to check all three media in fresh
BIOS and UEFI guests. The test uses a small initramfs and retains its serial logs,
boot products, and PXE packet captures under `build/boot-media-test/`. To run it
again alongside existing results, use `python3 scripts/boot_media_test.py --output build/boot-media-next`.

The example Makefile compiles and runs C and C++ programs, exercises exceptions, threads, synchronization, and the standard library, and checks a rejected C source file. The standalone `build/axiom64.iso` uses a disposable RAM root: directly booting it starts fresh and does not preserve accounts or files. The normal launch commands use the persistent disk described above. [Mounted ext2 data volumes](ext2.md) and [disk-root fixtures](disk-root.md) provide separate storage tests. The initial target is QEMU's emulated PC with PS/2 input and a 1024x768 boot framebuffer.

On the host, `make test-thread-io` runs the focused BIOS/UEFI [blocking I/O tests](io.md#verification-and-limits). `make test-threads` and `make test` include those tests alongside their broader suites.

Concurrent builds share one download owner per archive. Its lock covers the
cold-cache check, partial transfer and atomic publication, while unrelated
archives still download in parallel. An interrupted transfer leaves its final
path unpublished and retains partial bytes. Locked packages verify cached and
new bytes under that lock before publication. A declared `vendored_archive`
selects the original checked package from `vendor/ports`; its source must be
present and match the lock even when the download cache is warm. Missing,
changed or redirected local inputs fail verification. Existing source checksum
and signature checks remain mandatory before use.
