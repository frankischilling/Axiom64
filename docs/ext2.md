# Writable ext2 volumes

Axiom64 mounts classic ext2 data volumes and can boot an [ext2 root](disk-root.md) from whole virtio disks. Guest-created files persist after a clean unmount or shutdown and can be read by host filesystem tools. Checked mounts provide limited recovery after interruption; advanced filesystem support and general metadata repair remain planned.

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

Use `mount -t ext2 -o ro /dev/vda /mnt/data` for read-only access. An interrupted journaled volume can require recovery writes even for a read-only request, as described below. Writable mounting on read-only hardware returns `EROFS`. A mounted filesystem claims its whole disk: another mount and raw writes return `EBUSY`, including writes through an already-open raw descriptor. Raw reads remain available. Unmount releases the claim.

## Supported format and operations

The backend accepts Linux-created revision 0/1 filesystems with 1,024-, 2,048-, or 4,096-byte blocks and 128- or 256-byte inodes. It supports classic direct, single-, double-, and triple-indirect addressing, sparse regular files, typed or original directory records, sparse superblock placement, and the large-file feature. Revision 0 writes above 2 GiB return `EFBIG`; revision 1 sets the large-file flag when needed. File capacity is bounded by the classic pointer tree and the 32-bit count of allocated 512-byte sectors.

Filesystem operations include file and directory creation, short and block-backed symlinks, hard links, unlink/rmdir, rename/replacement, truncation, enumeration, modes, timestamps, `statfs`, `fsync`, and `fdatasync`. Statistics report allocated sectors rather than rounded logical file size. Open descriptions retain unlinked or replaced inodes and directory ancestry needed for traversal; filesystem sync reclaims them after the last reference disappears. A read-only remount returns `EBUSY` while an unlinked inode is still referenced. Timestamps have one-second resolution and signed 32-bit seconds; wider dates and nanosecond storage need later format support.

The kernel preserves reserved descriptor blocks and the resize inode but does not resize a volume. External [xattr and file-capability blocks](file-capabilities.md) support bounded reads/writes, shared-block copy-on-write and clean reboot persistence. The `dir_index` flag is accepted when no allocated directory uses its indexed layout. Classic internal journals have the initial support described below. Stored ACL namespaces, ext4 inode-body attributes, inode flags, fragments, bad-block lists, device/FIFO inodes, compression, extents, 64-bit geometry, flexible/meta block groups, and filesystem checksum formats return `EOPNOTSUPP` before writes. These features remain planned; the backend does not reinterpret their metadata as classic block pointers.

Before a writable mount changes the disk, validation checks capacity and geometry, group/table placement, bitmap reservations and free counts, inode block ownership, allocation counts, directory records and types, names, link counts, parent relationships, and root reachability. Inconsistent metadata returns `EUCLEAN`; an invalid magic returns `EINVAL`. Default writable mounting of an unjournaled volume requires a clean state and no orphan chain. A structurally valid unjournaled volume without the clean flag can be inspected read-only; a default read-only mount cannot be remounted writable.

`mount -t ext2 -o recovery=check /dev/vda /mnt/data` explicitly checks a volume whose clean flag was cleared by an interrupted mount. A writable checked mount can reconcile in-range free-block and free-inode counters from the allocation maps. It can also reclaim an allocated ordinary inode with zero links and a nonzero on-disk deletion time, such as a replaced journal that was still open when the VM stopped. Reclamation requires no live directory reference to that inode. Its block tree and external attributes must have valid ownership; a removed directory must be empty and retain valid, acyclic ancestry. The entire allocation, inode, attribute and directory scan must succeed before correction is staged. A second strict scan checks the proposed result before any disk writes.

A checked writable dirty mount can also preserve a deletion-marked regular file or symlink that still has exactly one directory name. This handles interruption after the old inode's retirement was written but before its name was removed or replaced. Its nonzero deletion time must equal its change time. Every data allocation, external attribute, other inode's link count and directory ancestry must validate first. Recovery restores that inode's single link and clears its deletion time, preserves its name, contents or symlink target, owner and mode, and strictly validates the complete staged result.

An empty retired directory can retain its single parent name under those same checks. Its `.` and `..` records must identify itself and that reachable live parent. Recovery restores its two links and the parent's one missing contribution when the removal already reduced that count. At most one named retired directory per parent is accepted. Nonempty retired directories, multiple names or retirements under one parent, cleared inode bodies, mismatched times, unrelated link errors, unreachable or cyclic ancestry, and overlapping allocations remain errors. Retirement records one timestamp for both change and deletion fields.

On unjournaled volumes, default mounts, clean-state mounts and checked read-only mounts reject these allocated deleted inodes. Default mounts and checked read-only mounts also require consistent counters. Error flags, orphan chains, incorrect directory counts and malformed or unsupported layouts reject mounting. A checked read-only mount of an unjournaled volume preserves disk bytes; a successful clean unmount restores the clean flag. This Axiom64 extension is accepted for an initial ext2 mount; other option values and its use on remounts or other filesystems return `EINVAL`. Use a filesystem checker for other damaged metadata.

The layout follows the Linux kernel's [superblock](https://www.kernel.org/doc/html/latest/filesystems/ext4/super.html), [inode](https://www.kernel.org/doc/html/latest/filesystems/ext4/inodes.html), [classic block map](https://www.kernel.org/doc/html/latest/filesystems/ext4/ifork.html), and [directory record](https://www.kernel.org/doc/html/latest/filesystems/ext4/directory.html) documentation. Free counters use the classic [group descriptor and superblock fields](https://github.com/torvalds/linux/blob/v6.17/fs/ext2/ext2.h). Classic timestamp handling is checked against the [Linux ext2 implementation](https://github.com/torvalds/linux/blob/master/fs/ext2/inode.c).

## Write and error behavior

Each mutation stages its changed blocks in a bounded overlay. Allocation or validation failure discards that operation before disk writes. Successful staging writes data, pointer blocks, inodes, directory records, allocation metadata, and the superblock, then flushes the device. Ordinary writes currently perform this flush too. Read access times are retained until filesystem sync. There is no permanent copy of the disk volume in RAM.

Allocation skips groups whose validated, staged free count is zero and skips fully occupied bitmap words. It retains the same group preference and first-free selection, including after freeing space or discarding a failed operation.

Each mounted volume has a read cache of 128 filesystem blocks, with up to 512 KiB of payload plus tags. Mount validation reads the backend before enabling this cache. Successful reads enter the cache; collisions replace an entry. Staged changes take precedence over cached bytes. Submitting a write invalidates its matching entry before the backend can succeed or fail. Unmount discards the cache, and a new mount reads and validates the disk again. Raw block reads still go directly to the device. The whole-disk claim prevents another guest writer from invalidating filesystem data behind the cache.

Cache misses and commits propagate backend errors to the caller. Failed reads are not cached. After an I/O error during commit, the complete overlay remains available to reads and to a later sync retry. An operation that returned `EIO` may therefore have changed the visible file or completed some disk writes. A successful retry flushes all staged blocks again. Writable mounting clears the clean flag; clean unmount, terminal shutdown, or a successful read-only remount restores it after sync. Terminal shutdown reclaims unlinked inodes even when a task still holds an open description, since those tasks will never resume.

Volumes without a journal use the development write path above. Its overlay does not make a multi-block write or rename atomic across power loss. Checked recovery reconciles redundant free counters, reclaims validated unreferenced deletion-marked inodes and preserves the validated name of a retired file, symlink or empty directory. Directory restoration corrects only its identified parent's bounded link contribution. A cleared inode still referenced by a directory cannot be reconstructed from its name or numeric identity. Repairing other partial file or directory writes, reclaiming orphan chains, general platform power management, broader power-loss testing, advanced ext4 formats and repair tooling remain part of the roadmap.

## Internal journals

Initial journal support accepts a classic internal JBD2 v2 journal in reserved inode 8, with 32-bit block numbers and no journal checksums. Native Linux-created ext3 volumes use this format. They mount through the same `ext2` interface. External journals, checksum variants, asynchronous commits, fast commits, extents and orphan chains remain planned and are rejected before writes.

The journal module stages committed records into the mount overlay. The filesystem then verifies allocation, ownership, namespace, journal identity and unchanged geometry before checkpointing. Journal records cannot overwrite journal storage. Revocations suppress earlier records, escaped magic values are restored, and incomplete transactions leave their home blocks untouched. Writable operations log their complete changed blocks, including data, before committing and writing home locations. A failed operation retains its full overlay for an identical retry. A read-only mount may perform required journal recovery on writable hardware; hardware read-only recovery returns `EROFS`.

After an interrupted journaled mount, validated deletion-marked inodes with no directory references can be reclaimed automatically. This handles files, symlinks and empty directories that were removed while descriptions remained open. Allocation maps, free counters, block and attribute ownership, directory contents and ancestry must all validate first; a strict second scan checks the staged result before it is journaled. Automatic cleanup keeps counter mismatches and named retirement records as errors. The broader `recovery=check` policy remains explicit. A read-only request can complete this cleanup on writable hardware, while hardware read-only recovery fails without writes. Clean-state volumes stay strict. Linux [orphan lists and orphan files](https://docs.kernel.org/filesystems/ext4/orphan.html) remain separate, unsupported formats.

Current focused guest checks recover an inode pointer whose allocation bitmap was not yet written, preserve every preceding file byte, and then exercise append, file creation, rename and clean unmount. Independent native checks compare journal replay with a separate filesystem-checker copy; that repaired copy is never used as guest input. Empty-log startup and recovery advance the transaction ID past abandoned records before reusing journal blocks. Crash controls cover stale records and 32-bit ID wraparound. Broader profile and device-failure acceptance remains in progress. Unjournaled corrupted pointers remain errors; enabling recovery does not allocate blocks by guessing from them.

An operation must fit the available journal and the existing 4,096-block overlay bound. Journal sizing, larger-operation handling and modern journal features remain part of the storage roadmap. The format follows the Linux [journal documentation](https://docs.kernel.org/filesystems/ext4/journal.html) and [v6.17 JBD2 definitions](https://github.com/torvalds/linux/blob/v6.17/include/linux/jbd2.h); this implementation uses Axiom64's synchronous block interface.

Limits are 4,096 block groups, 8,192 cached directory/inode identities per mount, and 4,096 changed blocks per operation. The mount scan uses temporary memory proportional to filesystem block/inode counts; unavailable memory returns `ENOMEM`. Removed identities remain cached until unmount. Filesystem calls are serialized on one CPU. Partitions, general block caching and writeback, namespaces, permission enforcement, special-file import, broader date support, and advanced ext2/ext4 features remain planned. Private mappings copy file bytes; ext2 shared mappings return `ENODEV`.

## Verification

```sh
make test-ext2
python3 scripts/ext2_test.py --quick --firmware bios --transport modern
python3 scripts/ext2_test.py --checks errors --firmware uefi --transport legacy
python3 scripts/ext2_test.py --checks recovery
python3 scripts/ext2_deleted_inode_test.py --directory build/ext2-deleted-recovery
```

The complete matrix has 100 boots across BIOS/UEFI and modern/legacy virtio with four layouts: 1 KiB/128-byte inodes, 2 KiB/256-byte inodes, 4 KiB/256-byte inodes, and original revision 0 directory records. Every layout has write, fresh-boot read, and read-only hardware phases. Guest tests cover shell mount/unmount commands, direct/indirect and sparse storage, a triple-indirect sparse file above 4 GiB, truncation/freeing, long names and multi-block enumeration, links, replacement/open lifetime, removed directory traversal, symlinks, signed timestamps, remounts, raw-disk claims, private mappings, and executable loading.

Thirty-two checked-recovery boots reconcile 96 generated volumes and reject 140 others without changing their bytes. They verify superblock/group counters, multiple descriptors sharing a block, allocation and removal after correction, clean remount, unsupported layouts, allocation ownership, directory/link relationships, orphan chains and counter bounds. Native filesystem checks require a zero exit status and no explicit count-error diagnostics. A separate ordinary checked-mount test of a retained interrupted volume corrected its summaries and preserved all ten regular-file contents and modes. Complete application-level recovery across storage failures remains required.

Additional boots reject 23 damaged or unsupported volumes per firmware/transport pairing, including a valid stored POSIX ACL and a separate corrupt EA pointer. They also exhaust blocks and inodes, test dirty-state policy, and inject mount-read, file-read, file-write, and flush errors. Host checks compare saved file bytes and metadata, inspect the sparse block through `debugfs`, run `e2fsck -fn` after clean unmounts, and require unchanged bytes on rejected/read-only volumes. The harness creates only generated fixtures under `build/`; it accepts no user disk path. Logs and `build/ext2-results.json` record guest results and host verification. CI retains the actual raw storage and ext2 volumes, boot images and fault rules in `axiom64-storage-fixtures`, including on failure. Use `--tag` to give an independent development run distinct image and evidence names. The existing full firmware, desktop, VFS, and raw-disk suites remain required.

The deleted-inode suite starts with six retained 1 KiB/128-byte-inode volumes from actual interrupted journal, account-pointer and generation-directory retirement, including cleared inode bodies as negative controls. It compares every named file, symlink target, directory, inode identity, owner, mode, size and link count before and after guest recovery, requires an independent zero-status filesystem check, and retains the resulting compressed disks. A named retirement permits only its recorded link restoration, deletion-time clearing and the empty directory's one identified parent contribution; file contents and the remaining metadata must match. Controls cover default and read-only denial, missing markers, mismatched times, positive or multiple links, an unrelated unreferenced live inode, clean-state volumes, unsupported inode flags, overlapping allocations, a redirected name, nonempty retired directories, incorrect parent counts, duplicate names or retirements under one parent, cyclic ancestry, block-backed symlinks and shared external attributes. Generated volumes exercise file, symlink and empty-directory recovery across all four layouts, both directory-parent write orders, and 70 retired inodes in one mount. The full matrix has 252 boots across BIOS/UEFI and modern/legacy virtio, retaining all original 172 cases. Its owned result directory must be new and beneath `build/`. These checks establish that specific recovery contract; they do not establish recovery from arbitrary partial metadata writes.

Failure rules use [QEMU blkdebug](https://www.qemu.org/docs/master/devel/testing/blkdebug.html). Power interruption, sustained failures, interrupted metadata-sector writes, hotplug, and concurrent kernel callers are not covered by this matrix.
