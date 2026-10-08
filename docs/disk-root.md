# Ext2 root boot

Axiom64 can start Ring 3 init, shells, the native GNU toolchain, and the Xorg desktop from a whole virtio disk with a classic ext2 filesystem. A small initramfs supplies the initial VFS namespace. The kernel replaces that root before starting any user process. Writable ext2 data mounts use the same backend and can run alongside the disk root.

## Build and boot

On the Ubuntu build host, install the dependencies in [build.md](build.md), including `e2fsprogs`, then run:

```sh
make -j2 disk-root
qemu-system-x86_64 -machine pc -cpu max -m 2G \
    -cdrom build/axiom64-disk.iso -serial stdio -no-reboot \
    -drive if=none,id=root,format=raw,cache=writeback,file=build/root-disk.raw \
    -device virtio-blk-pci,drive=root,disable-legacy=on,addr=5
```

`make disk-root` creates a development fixture at `build/root-disk.raw` and overwrites that generated file. Run the QEMU command again to keep files from the previous guest; rebuild the fixture only when its contents should be replaced. Use `disable-modern=on` for the legacy transport. For UEFI, add the two OVMF drives shown in [build.md](build.md). The ISO supplies Limine and the kernel; this is not a bootloader installation on the ext2 disk.

The fixture contains the same pinned init, libc, shells, tools, desktop, test programs, and licenses as the full initramfs. The builder validates archive paths and types, uses explicit ext2 features, fixes filesystem identifiers, timestamps, and ownership, and compares two independently staged images byte for byte. It runs host `e2fsck` before returning. Generated disks, staging files, and boot evidence stay outside Git. [Port sources and recipes](ports.md) remain part of the corresponding-source bundle.

## Boot selection

Limine's kernel command line selects the root:

| Parameter | Behavior |
| --- | --- |
| No `root`, or `root=ramfs` | Use the supplied initramfs |
| `root=/dev/vda` through `/dev/vdh` | Mount that whole virtio disk as the root |
| `rootfstype=ext2` | Select the supported disk filesystem; omission also selects ext2 |
| `rootflags=rw` | Writable root; also the default for a selected disk |
| `rootflags=ro` | Read-only root; use `readonly=on` on QEMU's drive to enforce it in hardware too |

Empty, duplicate, oversized, and unsupported root options fail with a `BOOT_ROOT_FAIL` diagnostic naming the stage and Linux errno. Filesystem type or flags require a disk selection. A missing disk or rejected ext2 volume also stops boot; the kernel does not silently use the bootstrap as a successful disk root. Device names follow PCI discovery order and are not stable disk identifiers.

The disk must contain executable regular files at `/sbin/init`, `/bin/busybox`, and `/lib/ld-musl-x86_64.so.1`, plus directories at `/dev`, `/proc`, `/sys`, `/tmp`, and `/run`. Required paths are checked through the disk filesystem. The ELF loader and dynamic linker use the selected root. Relative paths, cwd, mount ownership, and `stat.st_dev` follow that root too.

The kernel mounts independent RAM volumes on those five directories. Devices, synthetic process metadata, framebuffer metadata, sockets, and scratch files can therefore work with a read-only root. `/tmp` has mode `01777`. Ordinary files elsewhere use ext2; `/tmp` and `/run` do not persist. These RAM mount points are not complete Linux procfs, sysfs, or devtmpfs implementations.

## Shutdown and errors

Use `/bin/busybox poweroff -f` from the guest serial shell for a clean stop. The kernel synchronizes every active filesystem, reclaims open unlinked ext2 inodes, then marks writable ext2 mounts clean and flushes their devices before exiting. Test boots use the same shutdown path. A sync or finalization error produces `FILESYSTEM_SHUTDOWN_FAIL` and a failure status.

Ordinary boots on QEMU's `pc` machine discover the enabled PIIX4 power-management I/O block through PCI and request soft power off with a 16-bit PM1 control write. The register mapping and sleep type follow [QEMU's PIIX4 implementation](https://github.com/qemu/qemu/blob/v8.2.2/hw/acpi/piix4.c) and [ACPI control implementation](https://github.com/qemu/qemu/blob/v8.2.2/hw/acpi/core.c). This platform path is verified under BIOS and UEFI. General ACPI table discovery, hardware-specific sleep types, restart, and suspend remain planned; an unavailable power block leaves the CPU halted after filesystem shutdown.

The [ext2 validation and error policy](ext2.md) applies to the root. Invalid metadata is rejected before writable mounting. A backend failure can leave a volume marked unclean even when its inode structure remains valid; writable mounting then requires host repair. A failed shutdown is not persistence evidence. Abruptly closing QEMU, losing power, crash recovery, ext4, partitions, stable root identifiers, and a disk installer remain separate roadmap work.

Block requests, including mount-time flushes, have a 30-second deadline. A host flush can cover the copied full image even when the guest changed only a small amount of metadata. Device-reset acknowledgement keeps its separate two-second limit. An expired request is logged with its type, sector, length, and timeout errno, then the device is reset and quarantined.

## Verification

```sh
make test-disk-root
make test-root-io
python3 scripts/disk_root_test.py --checks files --firmware bios --transport modern
python3 scripts/disk_root_test.py --checks errors --firmware uefi --transport legacy
python3 scripts/boot_test.py --disk-root --transport modern --firmware both
python3 scripts/boot_test.py --disk-root --transport legacy --firmware both
python3 scripts/boot_test.py --disk-root --interactive --transport modern --firmware both --timeout 180
python3 scripts/boot_test.py --disk-root --interactive --transport legacy --firmware both --timeout 180
```

The persistence matrix has 16 boots: write, fresh-VM verification, software read-only policy on writable hardware, and read-only hardware for each BIOS/UEFI and modern/legacy pairing. The guest writes files, links, names, modes, and timestamps on both root and a separate data volume. It checks overwrite and truncation visibility through independent descriptions, then powers off with both volumes mounted and deleted files still open. Host `debugfs` compares payloads and metadata, checks the symlink, and runs `e2fsck`. Both disks must be marked clean after writable shutdown and remain byte-identical during both read-only phases.

Another 88 boots reject 22 cases under each pairing: invalid configuration, unavailable devices, writable selection of read-only hardware, a bad superblock, missing or nonexecutable boot files, missing runtime mount points, and injected mount-read, mount-write, and flush failures. Host checks require byte invariance where mounting never wrote, intact filesystem structure after required-file failures, and an unchanged seed fixture. A flush failure may retain the unclean mount marker.

The root I/O regression uses a Unix-socket [nbdkit Python backend](https://libguestfs.org/nbdkit-python-plugin.3.html) behind QEMU's actual virtio disk. It delays successful flushes by three seconds under all four firmware/transport pairings. A separate 35-second backend delay must produce the driver's 30-second timeout and a failed root selection. These mount probes stop before userspace, operate on disposable copies, and check that the seed is unchanged; they do not establish clean shutdown. Their logs, backend timings, and result files use `build/root-io-*`.

The full disk-root boot suite separately requires the complete ABI, thread, IPC, signal, VFS, native C/C++ build, Xorg drawing, window manager, and keyboard-input markers under all four pairings. The normal startup suite checks the interactive desktop under the same pairings, performs a guest shutdown without the test-only exit device, requires QEMU to exit successfully, and checks the disk with host fsck. Each boot uses its own copy of the generated fixture.

Logs and screenshots use `build/disk-root-*`; results are `build/disk-root-results.json`, `disk-root-modern-boot-results.json`, `disk-root-legacy-boot-results.json`, and the corresponding interactive result files. The harness takes no user disk path. Existing RAM-root, data-volume, raw-disk, virtio-transport, sanitizer, formatting, and source-bundle checks remain required.

CI also checks reproduction of the full toolchain fixture and publishes `axiom64-disk-root` with `axiom64-disk.iso` and `root-disk.raw`. Disk-root tests use separate ISO names so the normal RAM-root image remains available in `axiom64-boot`.
