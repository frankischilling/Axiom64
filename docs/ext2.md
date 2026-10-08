# Writable ext2 volumes

Axiom64 mounts classic ext2 data volumes and can boot an [ext2 root](disk-root.md) from whole virtio disks. Guest-created files persist after a clean unmount or shutdown and can be read by host filesystem tools. The complete filesystem work remains tracked in [#3](https://github.com/frankischilling/Axiom64/issues/3).

## Create and mount a volume

Install `e2fsprogs` on the build host. Create a new image, format it, and attach it using the [storage instructions](storage.md#attach-a-disk):

```sh
test ! -e build/data.raw && truncate -s 64M build/data.raw
mke2fs -F -t ext2 -b 1024 -I 128 build/data.raw
```

Inside the guest:

```sh
mkdir -p /mnt/data
mount -t ext2 /dev/vda /mnt/data
echo persistent > /mnt/data/example.txt
sync
umount /mnt/data
```

Use `mount -t ext2 -o ro /dev/vda /mnt/data` for inspection without writes. Writable mounting on read-only hardware returns `EROFS`. A mounted filesystem claims its whole disk: another mount and raw writes return `EBUSY`, including writes through an already-open raw descriptor. Raw reads remain available. Unmount releases the claim.

## Supported format and operations

The backend accepts Linux-created revision 0/1 filesystems with 1,024-, 2,048-, or 4,096-byte blocks and 128- or 256-byte inodes. It supports classic direct, single-, double-, and triple-indirect addressing, sparse regular files, typed or original directory records, sparse superblock placement, and the large-file feature. Revision 0 writes above 2 GiB return `EFBIG`; revision 1 sets the large-file flag when needed. File capacity is bounded by the classic pointer tree and the 32-bit count of allocated 512-byte sectors.

Filesystem operations include file and directory creation, short and block-backed symlinks, hard links, unlink/rmdir, rename/replacement, truncation, enumeration, modes, timestamps, `statfs`, `fsync`, and `fdatasync`. Statistics report allocated sectors rather than rounded logical file size. Open descriptions retain unlinked or replaced inodes and directory ancestry needed for traversal; filesystem sync reclaims them after the last reference disappears. A read-only remount returns `EBUSY` while an unlinked inode is still referenced. Timestamps have one-second resolution and signed 32-bit seconds; wider dates and nanosecond storage need later format support.

The kernel preserves reserved descriptor blocks and the resize inode but does not resize a volume. The `ext_attr` and `dir_index` format flags are accepted when no allocated ordinary inode uses an ACL/xattr block or indexed directory. Inode flags, active extended attributes, fragments, bad-block lists, device/FIFO inodes, compression, journals, extents, 64-bit geometry, flexible/meta block groups, and checksum formats return `EOPNOTSUPP`. These features remain planned; the backend does not reinterpret their metadata as classic block pointers.

Before a writable mount changes the disk, validation checks capacity and geometry, group/table placement, bitmap reservations and free counts, inode block ownership, allocation counts, directory records and types, names, link counts, parent relationships, and root reachability. Inconsistent metadata returns `EUCLEAN`; an invalid magic returns `EINVAL`. Writable mounting requires a clean state and no orphan chain. A structurally valid volume without the clean flag can be inspected read-only; it cannot be remounted writable. Use a host filesystem checker for repair.

The layout follows the Linux kernel's [superblock](https://www.kernel.org/doc/html/latest/filesystems/ext4/super.html), [inode](https://www.kernel.org/doc/html/latest/filesystems/ext4/inodes.html), [classic block map](https://www.kernel.org/doc/html/latest/filesystems/ext4/ifork.html), and [directory record](https://www.kernel.org/doc/html/latest/filesystems/ext4/directory.html) documentation. Classic timestamp handling is checked against the [Linux ext2 implementation](https://github.com/torvalds/linux/blob/master/fs/ext2/inode.c).

## Write and error behavior

Each mutation stages its changed blocks in a bounded overlay. Allocation or validation failure discards that operation before disk writes. Successful staging writes data, pointer blocks, inodes, directory records, allocation metadata, and the superblock, then flushes the device. Ordinary writes currently perform this flush too. Read access times are retained until filesystem sync. There is no permanent copy of the disk volume in RAM.

Each mounted volume has a read cache of 128 filesystem blocks, with up to 512 KiB of payload plus tags. Mount validation reads the backend before enabling this cache. Successful reads enter the cache; collisions replace an entry. Staged changes take precedence over cached bytes. Submitting a write invalidates its matching entry before the backend can succeed or fail. Unmount discards the cache, and a new mount reads and validates the disk again. Raw block reads still go directly to the device. The whole-disk claim prevents another guest writer from invalidating filesystem data behind the cache.

Cache misses and commits propagate backend errors to the caller. Failed reads are not cached. After an I/O error during commit, the complete overlay remains available to reads and to a later sync retry. An operation that returned `EIO` may therefore have changed the visible file or completed some disk writes. A successful retry flushes all staged blocks again. Writable mounting clears the clean flag; clean unmount, terminal shutdown, or a successful read-only remount restores it after sync. Terminal shutdown reclaims unlinked inodes even when a task still holds an open description, since those tasks will never resume.

This is a non-journaled development filesystem. The overlay does not make a multi-block write or rename atomic across power loss. There is no recovery implementation, dirty-volume repair, or production release claim. General platform power management, power-loss testing, ext4 journaling/recovery, and repair tooling remain part of the roadmap.

Limits are 4,096 block groups, 8,192 cached directory/inode identities per mount, and 4,096 changed blocks per operation. The mount scan uses temporary memory proportional to filesystem block/inode counts; unavailable memory returns `ENOMEM`. Removed identities remain cached until unmount. Filesystem calls are serialized on one CPU. Partitions, general block caching and writeback, namespaces, permission enforcement, special-file import, broader date support, and advanced ext2/ext4 features remain planned. Private mappings copy file bytes; ext2 shared mappings return `ENODEV`.

## Verification

```sh
make test-ext2
python3 scripts/ext2_test.py --quick --firmware bios --transport modern
python3 scripts/ext2_test.py --checks errors --firmware uefi --transport legacy
```

The complete matrix has 68 boots across BIOS/UEFI and modern/legacy virtio with four layouts: 1 KiB/128-byte inodes, 2 KiB/256-byte inodes, 4 KiB/256-byte inodes, and original revision 0 directory records. Every layout has write, fresh-boot read, and read-only hardware phases. Guest tests cover shell mount/unmount commands, direct/indirect and sparse storage, a triple-indirect sparse file above 4 GiB, truncation/freeing, long names and multi-block enumeration, links, replacement/open lifetime, removed directory traversal, symlinks, signed timestamps, remounts, raw-disk claims, private mappings, and executable loading.

Additional boots reject 22 damaged or unsupported volumes per firmware/transport pairing, exhaust blocks and inodes, test dirty-state policy, and inject mount-read, file-read, file-write, and flush errors. Host checks compare saved file bytes and metadata, inspect the sparse block through `debugfs`, run `e2fsck -fn` after clean unmounts, and require unchanged bytes on rejected/read-only volumes. The harness creates only generated fixtures under `build/`; it accepts no user disk path. Logs and `build/ext2-results.json` record guest results and host verification. Use `--tag` to give an independent development run distinct image and evidence names. The existing full firmware, desktop, VFS, and raw-disk suites remain required.

Failure rules use [QEMU blkdebug](https://www.qemu.org/docs/master/devel/testing/blkdebug.html). Power interruption, sustained failures, interrupted metadata-sector writes, hotplug, and concurrent kernel callers are not covered by this matrix.
