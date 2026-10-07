# Storage

The kernel discovers PCI virtio block devices at boot and exposes whole disks as `/dev/vda` through `/dev/vdh`. Raw disk writes persist when flushed. The root filesystem and ordinary files still live in RAM; writable ext2 is the next storage task.

## Attach a disk

Create a new image and attach it to the normal guest:

```sh
make -j2 image
test ! -e build/data.raw && truncate -s 64M build/data.raw
qemu-system-x86_64 -machine pc -cpu max -m 2G \
    -cdrom build/axiom64.iso -serial stdio -no-reboot \
    -drive if=none,id=data,format=raw,cache=writeback,file=build/data.raw \
    -device virtio-blk-pci,drive=data,disable-legacy=on
```

Use `disable-modern=on` to exercise the legacy PCI transport. To attach a read-only disk, add `readonly=on` to its `-drive` argument. Discovery follows PCI bus, slot, and function order; these names are not persistent identifiers.

## Interfaces

`kernel/include/block.hpp` provides capacity, read-only status, whole-sector reads and writes, and flush. Sector addresses are 64-bit and sectors are 512 bytes. The complete range is checked before a transfer. Calls return zero or a negative Linux error. Multi-sector writes are not atomic and may leave earlier sectors written if a later request fails.

The implementation copies through private, physically contiguous DMA buffers. User addresses never become device descriptors. The PCI module handles configuration mechanism 1, multifunction discovery, and assigned 32/64-bit memory BARs. Modern registers use bounded, uncached supervisor mappings; the legacy transport uses its I/O BAR. Unsupported capabilities, invalid mappings, unavailable queues, and failed feature negotiation prevent a disk from being registered.

Both transports use a split queue with one outstanding request. The driver negotiates read-only and flush features, plus `VIRTIO_F_VERSION_1` for modern devices. It uses memory barriers when publishing descriptors and reading completions, suppresses interrupts, and polls with a calibrated two-second deadline plus a fixed iteration limit. A timeout or invalid completion resets the device and makes subsequent operations fail with `EIO`; DMA pages remain allocated. Backend `IOERR` returns `EIO` while keeping the queue usable. Unsupported requests return `EOPNOTSUPP`.

Block nodes support these Linux x86-64 operations:

| Operation | Behavior |
| --- | --- |
| `read`, `write`, `pread`, `pwrite` | Byte offsets; partial sectors use read-modify-write; offsets advance only for completed bytes |
| `lseek` | Seek from the start, current offset, or disk capacity |
| `stat`, `fstat` | Block-device type, mode `0600`, major 252, minors 0/16/32/...; size comes from ioctls |
| `BLKGETSIZE64`, `BLKGETSIZE` | Byte capacity and 512-byte sector count |
| `BLKSSZGET`, `BLKROGET` | Sector size and read-only flag |
| `fsync`, `fdatasync`, `BLKFLSBUF` | Wait for a virtio flush completion when supported |
| `O_SYNC`, `O_DSYNC` | Flush completed writes before reporting success |

Reads at or beyond capacity return EOF. A write that crosses the end returns the completed prefix; a write starting at the end returns `ENOSPC`. Opening a read-only disk for writing returns `EROFS`. Device truncation and unsupported `O_DIRECT` return `EINVAL`; unsupported ioctls return `ENOTTY`. There is no kernel block cache. If flush was not negotiated, the driver relies on the virtio writethrough contract.

Syscalls currently run on one CPU with interrupts masked, which serializes access to the queue and partial-sector writes. The driver is not ready for concurrent kernel callers or SMP. Limits include eight device initialization attempts, no hotplug or capacity-change handling, and no ECAM, IOMMU, partition parser, disk filesystem mounts, or disk-backed root. [RAM mounts and filesystem dispatch](vfs.md) provide the interface for the next filesystem implementation. Partitioning, caching, and stable root identifiers remain in [the block roadmap](https://github.com/frankischilling/Axiom64/issues/2); writable ext2 remains in [the filesystem roadmap](https://github.com/frankischilling/Axiom64/issues/3).

## Verification

```sh
make test-storage
python3 scripts/storage_test.py --firmware bios --transport modern
```

The default matrix performs four independent boots for each BIOS/UEFI and modern/legacy pairing, for 16 boots total:

1. Write an unaligned pattern spanning several syscall buffers, write across the final sector, flush, and perform 65,540 reads to cross the 16-bit queue-index rollover.
2. Boot a fresh guest using the same disk and recover the pattern and untouched neighboring bytes.
3. Attach that disk read-only and verify both the data and write rejection.
4. Inject one read, write, and flush failure through QEMU `blkdebug`; require `EIO` and successful operations afterward.

Every boot also checks an independent read-only second disk, Linux block metadata, invalid user pointers, descriptor access modes, negative offsets, and disk bounds. After each boot the host compares every byte of both disk images with the expected contents. The failure-injection sectors lie away from firmware's disk probes so boot-time reads do not consume the one-shot errors.

The harness creates its own fixtures under `build/` and takes no user disk path. Evidence is in `build/storage-*.log`, the error-phase QEMU traces, and `build/storage-results.json`, including host-verified SHA-256 hashes. The normal ABI, native toolchain, and desktop tests remain separate regression checks. The timeout and malformed-completion paths have bounded handling in the driver but are not fault-injected by this matrix.

The transport follows the [OASIS virtio 1.2 specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html). The backend failure tests use [QEMU's blkdebug rules](https://www.qemu.org/docs/master/devel/testing/blkdebug.html).
