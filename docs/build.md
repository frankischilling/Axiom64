# Build and run

Use Ubuntu 24.04 x86-64, directly or through WSL Ubuntu. Static userspace and BusyBox use a source-built Ubuntu musl 1.2.4-2 provider. The installed interpreter and development libraries use the pinned Alpine musl 1.2.5-r13 source and distribution patches. Both providers apply the checked [local DNS transport patch](../vendor/musl/README.md); the host libc and compiler installation stay unchanged.

```sh
sudo apt-get update
sudo apt-get install -y g++ make cmake musl-tools linux-libc-dev nasm python3 \
    xorriso qemu-system-x86 qemu-utils ovmf xfonts-utils e2fsprogs nbdkit nbdkit-plugin-python gdb
make -j2 image
make run
```

The first build downloads verified archives, builds BusyBox, assembles the root filesystem, and produces `build/axiom64.iso`. Allow several gigabytes of free disk space. Host Linux provides the build tools and QEMU emulator; the guest runs Axiom64's kernel.

BusyBox downloads can use the mirrors listed in `dependencies.json` when upstream is unavailable. Every source must supply the same pinned bytes. A hash mismatch stops the build. The local `prepare` test suite verifies essential boot sources and locked package inputs before compiling providers.

`make run` boots through BIOS with a graphical QEMU window and an authenticated serial console. First boot asks you to create an administrator and enter its password privately, then requires login. Later boots use the same account and require its password again. The administrator starts Bash with UID/GID 1000 and explicit `sudo` membership; root's password login is locked. Enter passwords in the guest. The [account documentation](accounts.md) describes the current commands and policy.

The VM keeps its root in `.local/vm/root.ext2`. New roots use the classic ext3 format with a 32 MiB internal journal. The kernel mounts them through the ext2 driver. Existing state directories keep their original filesystems and installed userspace. The launch helper creates the disk once, locks the state while the VM runs, and refuses incomplete creation metadata. Keep the state directory to retain your accounts and files. To test newly packaged userspace in a separate VM, run `python3 scripts/vm.py --state-directory .local/vm-next`. In-guest upgrades remain future work.

After authentication, normal startup launches Xorg, twm, xeyes and an ordinary-user terminal alongside the private serial shell. A fresh private X11 cookie controls display access. Local BIOS/UEFI RAM/ext2 checks cover input, logout and display/console failure; complete service and crash-recovery integration remains required. See [authenticated desktop sessions](accounts.md#authenticated-desktop).

Choose **Weston** from the X11 menu or run `weston-nested` in the graphical terminal to open a Wayland desktop inside Xorg. Open a terminal from the Weston panel and run `wayland-info` or `weston-simple-shm`. To start a Wayland application with the compositor, run `weston-nested -- COMMAND` from the X11 terminal. Close the outer Weston window to end the session.

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

The installed desktop profile also uses `glib-compile-schemas` and
`update-mime-database`. Install `libglib2.0-bin` and `shared-mime-info` on
Ubuntu or Debian before building that profile.

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

See [PXE boot and remote testing](pxe.md) for the direct-Ethernet setup,
firmware boot menu, and SSH, SFTP, and FTP checks on the Blade.

The first Limine module supplies the initramfs. BIOS and UEFI boot logs report
the module count and initramfs size. PID 1 defaults to `/sbin/init`. Pass
`--init-path /absolute/path` to `scripts/image.py` or `scripts/boot_media.py`
to select another executable on the chosen guest root. Duplicate, empty,
relative, or oversized `init=` values fail before userspace starts.

Run `make test-suite SUITE=secondary-boot` to check all three media in fresh
BIOS and UEFI guests. The test uses a small initramfs and retains its serial logs,
boot products, and PXE packet captures under `build/boot-media-test/`. To run it
again alongside existing results, use `python3 scripts/boot_media_test.py --output build/boot-media-next`.

Add `--smp` to test the `smp.probe` boot option with one and twelve logical
processors under BIOS and UEFI. Each application processor switches to its own
kernel stack, loads its processor tables, and checks its APIC ID. The boot
processor then sends two directed wake interrupts to each application
processor and checks both acknowledgements. Each secondary CPU then arms its
local APIC timer twice and verifies that both interrupts arrived. It stops
the timer and checks that its CPU-local task slot is empty. Before parking,
the secondary CPUs load a shared scratch mapping and warm its translation.
The boot CPU verifies that the invalidation code selects only CPUs that have
the target page tables loaded. It replaces the backing page and checks that
each secondary CPU sees the replacement after a directed interrupt. The
scheduler still runs on the bootstrap processor.

Add `--scheduler` to run the separate twelve-CPU userspace test under BIOS and
UEFI. It boots with `smp.scheduler`, forks workers, and checks that they report
execution on all twelve logical CPUs before exiting. For a custom image, pass
`--kernel-option smp.scheduler` to the image builder. The option requires the
Limine processor list, a working shared HPET counter, and successful secondary
CPU checks. Ordinary boots continue to use the boot CPU.

The same invalidation path serves ordinary userspace memory changes. Replaced
and unmapped pages stay allocated until the CPUs using those page tables have
responded. The address-space lock covers CR3 switches and target selection.
Page-table writers still run serially. The implementation flushes non-global
translations with PCID disabled.

Add `--xhci` to the boot-media test to check xHCI firmware ownership, reset,
ring wrap, and USB keyboard configuration under BIOS and UEFI. The test sends a
key press through QEMU and checks the press and release from the keyboard's HID
reports. It also boots without a controller to check that case. For descriptor
and configuration logs, use `usb.xhci=probe`. Use `usb.xhci=keyboard-probe` to
also read key reports on a root-port boot keyboard. Both options halt the
controller before userspace starts.

Mappings of `/dev/fb0` inherit the firmware framebuffer's cache attributes.
On Limine x86-64 boots, this retains write-combining when the CPU supports it.
The boot-media test maps the framebuffer and writes and reads a pixel.

The example Makefile compiles and runs C and C++ programs, exercises exceptions, threads, synchronization, and the standard library, and checks a rejected C source file. The standalone `build/axiom64.iso` uses a disposable RAM root: directly booting it starts fresh and does not preserve accounts or files. The normal launch commands use the persistent disk described above. [Mounted ext2 data volumes](ext2.md) and [disk-root fixtures](disk-root.md) provide separate storage tests. The initial target is QEMU's emulated PC with PS/2 input and a 1024x768 boot framebuffer.

## Multiboot and direct QEMU boot

After `make image`, build the Multiboot wrapper and use the original
uncompressed initramfs. Direct loading uses QEMU's BIOS Multiboot 1 path and
the serial console.

```sh
make build/axiom64-multiboot.elf
qemu-system-x86_64 -m 2G -display none -serial stdio \
    -kernel build/axiom64-multiboot.elf -initrd build/rootfs.cpio
```

Pass kernel arguments with `-append`. The first module supplies the early
filesystem. Use `root=` to switch to a [disk root](disk-root.md) after storage
discovery. Use QEMU's monitor or a guest shutdown command to stop the VM.

GRUB loads the same wrapper through Multiboot 2 under BIOS and UEFI. Copy
`build/axiom64-multiboot.elf` and `build/rootfs.cpio` to the ISO staging tree as
`boot/kernel.elf` and `boot/rootfs.cpio`. Put this entry in `boot/grub/grub.cfg`.

```text
insmod all_video
set gfxmode=auto
menuentry "Axiom64" {
    multiboot2 /boot/kernel.elf
    module2 /boot/rootfs.cpio
}
```

Install `grub-common`, `grub-pc-bin`, and `grub-efi-amd64-bin`, then run
`grub-mkrescue -o build/axiom64-grub.iso path/to/staging-tree`. The wrapper
requests a 1024x768, 32-bit framebuffer for the desktop when available.
BIOS GRUB also accepts `multiboot` and
`module` for a Multiboot 1 boot.

Install `busybox-static` for the test disk. Run `make test-suite SUITE=multiboot`
for fresh i440fx and Q35 boots, framebuffer access from Ring 3, a virtio root, and
missing-module failures.

### BIOS floppy boot

`scripts/floppy_image.py` builds a 1,474,560-byte image using the Multiboot
wrapper and the installed GRUB BIOS files. Install `grub-common`,
`grub-pc-bin`, `dosfstools`, `mtools`, and `fdisk` to build the image. Use
`--initramfs` for a small RAM root. The full userspace fits on a separate disk.
With an existing Axiom64 VM root, use:

```sh
make build/axiom64-multiboot.elf
python3 scripts/floppy_image.py build/axiom64-floppy.raw --root-device /dev/vda
qemu-system-x86_64 -m 2G -serial stdio -boot order=a,strict=on \
    -drive if=floppy,format=raw,readonly=on,file=build/axiom64-floppy.raw \
    -drive if=none,id=root,format=raw,snapshot=on,file=.local/vm/root.ext2 \
    -device virtio-blk-pci,drive=root,disable-legacy=on
```

The Multiboot suite boots both floppy layouts and checks that the builder
rejects oversized payloads and preserves existing images.

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
