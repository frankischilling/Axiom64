# Storage

The kernel discovers PCI virtio block devices at boot and exposes whole disks as `/dev/vda` through `/dev/vdh`. Partitions use names such as `/dev/vda1`. [Writable ext2 data mounts](ext2.md) and the optional [ext2 root](disk-root.md) work on whole disks and partitions.

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

## Partitions

Discovery runs once at boot on disks with 512-byte logical sectors. GPT entries keep their table index, including gaps. The scanner checks header and array CRCs, usable ranges, and overlaps. It tries the backup GPT if the primary fails and leaves both copies untouched. See the [UEFI GPT layout](https://uefi.org/specs/UEFI/2.11/05_GUID_Partition_Table_Format.html).

MBR primary slots keep their numbers. Logical partitions start at 5, in extended boot record order. The extended container has no node. The scanner bounds and checks the chain for cycles. It also decodes checksummed 32-bit BSD disklabels at byte 0 or 64 of the label sector, including labels inside FreeBSD, OpenBSD, and NetBSD primary MBR slices. Nested entries follow the MBR logical entries. Unused entries and the full-slice alias are skipped.

Each disk can expose up to 128 numbered partitions. GPT supports up to 128 entries of 128, 256, or 512 bytes each. A failed top-level scan publishes only the whole-disk node. A rejected nested disklabel leaves its parent MBR slice available. Table edits take effect at the next boot. [Select an ext2 root by partition ID or GPT name](disk-root.md#boot-selection) to keep boot independent of disk order.

## Interfaces

`kernel/include/drivers/block/block.hpp` provides capacity, read-only status, whole-sector reads and writes, flush, and exclusive filesystem claims. A claim covers its sector range, including overlapping whole-disk and BSD slice aliases. Disjoint partitions can be mounted independently. Filesystem writes carry their owner. Sector addresses are 64-bit and sectors are 512 bytes. Partition transfers validate their full range before translating to disk sectors. A flush applies to the parent disk. Multi-sector writes can leave earlier sectors written if a later request fails.

The driver copies through private, physically contiguous DMA buffers. The [shared virtio transport and queue modules](virtio.md) handle registers, configuration, queue geometry, descriptor ownership, and reset. PCI discovery reads validated ECAM windows and uses legacy configuration ports for segment-zero buses without a usable window. It enumerates multifunction devices and reads their assigned 32- and 64-bit memory BARs. Unsupported capabilities, invalid mappings, unavailable queues, and failed feature negotiation prevent disk registration.

Both transports use a split queue with one outstanding request. The driver negotiates read-only and flush features, plus `VIRTIO_F_VERSION_1` for modern devices. It uses memory barriers when publishing descriptors and reading completions, suppresses interrupts, and polls with a calibrated 30-second request deadline. Reset acknowledgement retains a separate two-second deadline. A fixed iteration bound is used only if PIT calibration fails. A timeout or invalid completion resets the device and makes subsequent operations fail with `EIO`; DMA pages remain allocated. Backend `IOERR` returns `EIO` while keeping the queue usable. Unsupported requests return `EOPNOTSUPP`.

Block nodes support these Linux x86-64 operations:

| Operation | Behavior |
| --- | --- |
| `read`, `write`, `pread`, `pwrite` | Byte offsets; partial sectors use read-modify-write; offsets advance only for completed bytes |
| `lseek` | Seek from the start, current offset, or disk capacity |
| `stat`, `fstat` | Block-device type and mode `0600`. Whole disks use major 252 and minors 0, 16, 32, and so on. Partitions 1–15 add their number to the disk minor. Higher partitions use major 259. |
| `BLKGETSIZE64`, `BLKGETSIZE` | Byte capacity and 512-byte sector count |
| `BLKSSZGET`, `BLKROGET` | Sector size and read-only flag |
| `fsync`, `fdatasync`, `BLKFLSBUF` | Wait for a virtio flush completion when supported |
| `O_SYNC`, `O_DSYNC` | Flush completed writes before reporting success |

Reads at or beyond capacity return EOF. A write that crosses the end returns the completed prefix. A write starting at the end returns `ENOSPC`. Opening a read-only disk for writing returns `EROFS`. Device truncation and unsupported `O_DIRECT` return `EINVAL`. Unsupported ioctls return `ENOTTY`. If flush was not negotiated, the driver relies on the virtio writethrough contract.

Syscalls run on one CPU with interrupts masked, which serializes queue access and partial-sector writes. Boot attempts to initialize up to eight devices. Concurrent kernel callers, hotplug, capacity changes, and IOMMU support remain in development. See [the filesystem roadmap](ext2.md) for advanced filesystems and recovery.

## Buffer cache

A filesystem can enable a read-through cache after claiming and validating a volume. Each cache holds up to 128 aligned blocks of 512, 1,024, 2,048, or 4,096 bytes, with one block size per claim. Collisions replace an entry. Cache misses go to the device and only successful complete reads fill the cache. Raw reads, mount validation, and journal recovery can read the device directly.

Writes go through to the device. They invalidate all overlapping cached blocks before submission, including writes that later fail. An explicit flush retains its device semantics. Caches hold clean data only. Releasing the claim drops the cache, and `sysinfo.bufferram` accounts for all active cache allocations. Overlapping writable aliases are excluded while the claim is held. Disjoint partitions retain independent caches.

## Format an image inside Axiom64

On a writable guest filesystem with at least 32 MiB free, create a new image with the installed BusyBox applets.

```sh
test ! -e guest.ext2 && busybox truncate -s 32M guest.ext2 &&
    busybox mke2fs -F -b 4096 -I 128 -L GUESTMEDIA guest.ext2
```

After a clean shutdown, export the file and attach it as a virtio disk on the next boot. When it is the first disk, mount it with `mount -t ext2 /dev/vda /mnt/data`. The guest can write through that mount and reopen the same image on a later boot.

## Verification

```sh
make test-storage
make test-partitions
make test-block-cache test-guest-media
python3 scripts/storage_test.py --firmware bios --transport modern
```

The default matrix performs four independent boots for each BIOS/UEFI and modern/legacy pairing, for 16 boots total:

1. Write an unaligned pattern spanning several syscall buffers, write across the final sector, flush, and perform 65,540 reads to cross the 16-bit queue-index rollover.
2. Boot a fresh guest using the same disk and recover the pattern and untouched neighboring bytes.
3. Attach that disk read-only and verify both the data and write rejection.
4. Inject one read, write, and flush failure through QEMU `blkdebug`; require `EIO` and successful operations afterward.

Every boot also checks an independent read-only second disk, Linux block metadata, invalid user pointers, descriptor access modes, negative offsets, and disk bounds. After each boot the host compares every byte of both disk images with the expected contents. The failure-injection sectors lie away from firmware's disk probes so boot-time reads do not consume the one-shot errors.

The harness creates its own fixtures under `build/` and takes no user disk path. Evidence is in `build/storage-*.log`, the error-phase QEMU traces, and `build/storage-results.json`, including host-verified SHA-256 hashes. The normal ABI, native toolchain, and desktop tests remain separate regression checks. The [root I/O tests](disk-root.md#verification) exercise delayed successful flushes and an expired request through actual virtio disks. Malformed completions are not fault-injected by this raw-disk matrix.

`make test-partitions-native` runs the production scanner under ASan and UBSan with valid, malformed, and unreadable tables. `make test-partitions` adds BIOS and UEFI runs with modern and legacy virtio. The guest writes and remounts GPT, MBR logical, and nested BSD partitions, checks overlapping claims and partition boundaries, and verifies files after reboot. The host checks both ext2 volumes with `e2fsck`, reads their files with `debugfs`, and checks the bytes outside those volumes.

`make test-block-cache` checks alignment, replacement, and write invalidation under ASan and UBSan. The partition test also checks that a disjoint mount acquires and releases its cache. `make test-guest-media` formats an image on the guest's scratch filesystem, exports the exact bytes, and boots twice more to write and recover a file. Every BIOS/UEFI and modern/legacy pairing checks the image with host `e2fsck` and confirms the read-only boot leaves it byte-identical.

The transport follows the [OASIS virtio 1.2 specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html). The backend failure tests use [QEMU's blkdebug rules](https://www.qemu.org/docs/master/devel/testing/blkdebug.html).
