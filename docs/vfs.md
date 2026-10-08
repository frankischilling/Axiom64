# Filesystems and mounts

The boot initramfs supplies the initial RAM root; [disk-root selection](disk-root.md) can replace it with ext2 before Ring 3 starts. User programs can mount independent `ramfs` volumes or [classic ext2 disks](ext2.md) on existing directories, remount them read-only or writable, and unmount them when unused.

## Kernel interface

`kernel/include/fs/vfs.hpp` defines `FilesystemOps`, `Mount`, `Node`, and `Path`. The VFS resolves paths and applies mount policy before dispatching lookup, creation, links, removal, rename, file reads/writes, truncation, metadata, enumeration, sync, and shared mapping to the filesystem. `kernel/fs/ramfs.cpp` and `kernel/fs/ext2/ext2.cpp` implement those operations. Filesystems can reject remount and perform final clean-state writes before unmount. Statistics return errors when metadata cannot be read. Initramfs import initializes the boot volume; device operations continue through their drivers.

Each node belongs to one mount. `stat.st_dev` identifies that mount; hard links share an inode within it. A path retains its starting directory node, so relative access through a working directory or directory descriptor keeps its identity when a mount covers that directory. Traversal resolves symlinks before `..`; a mounted root's `..` reaches the covered directory's parent. Names can contain 255 bytes. User paths are bounded to 1,023 bytes and symlink expansion to 2,047 bytes, with at most 40 followed links.

The ELF loader and private file mappings read through the filesystem interface. Shared mappings request backing from the filesystem and return `ENODEV` when it has no shared-mapping operation. RAM shared pages remain referenced after descriptors close and across fork. A mapping created from a read-only descriptor or mount cannot gain write access through `mprotect`.

## Guest operations

| Operation | Supported behavior |
| --- | --- |
| `mount` | `ramfs` and `ext2`, optional `MS_RDONLY`; `MS_REMOUNT` changes policy; the mount utility's `MS_SILENT` flag is accepted |
| `umount2` | Flags zero; sync before detach and restore covered contents |
| `openat`, `mkdirat`, `unlinkat`, `linkat`, `renameat`, `symlinkat`, `readlinkat` | Relative directory identity and filesystem dispatch |
| `rename` | Atomic RAM namespace update, replacement, and retained open descriptions |
| `statfs`, `fstatfs` | Filesystem type, mount identity, name limit, read-only flag, and backend capacity/allocation information |
| `fsync`, `fdatasync`, `sync` | Filesystem sync delegation; raw block descriptors use the disk flush operation |
| `truncate`, `ftruncate` | Filesystem delegation with negative-length, file-type, capacity, and mount checks |

A read-only mount rejects file writes and namespace or metadata mutations with `EROFS`. Read-only remount returns `EBUSY` while writable regular-file descriptions or shared file pages remain. Unmount returns `EBUSY` for open descriptions, live working directories, bound Unix sockets, shared pages, or nested mounts. Cross-filesystem links and renames return `EXDEV`. RAM files removed or replaced remain usable through existing descriptions.

## Verification and limits

`userspace/tests/fs/vfs.c` runs from the ABI and full guest suites under both firmware types. It checks covered and restored contents, pre-existing directory descriptors, symlinks and loops, mount traversal, long names, directory enumeration, hard links, replacement and unlink lifetime, read-only operations, static/dynamic executable loading from a mounted volume, private/shared mappings, socket bindings, nested mounts, inherited working directories, and repeated mount-slot reuse. `VFS_TESTS_PASS` is mandatory. Existing ABI, native toolchain, desktop, and raw disk tests remain required.

There are 16 mount slots including the root, and a shared pool of 16,384 RAM nodes. Unmount frees a volume's owned data and nodes. Removed nodes on an active volume remain allocated, so repeated create/unlink can exhaust that pool. RAM files have a 256 MiB limit; growth that would relocate shared backing returns `EBUSY`. RAM statistics report zero block capacity because there is no fixed block allocation pool.

The namespace is global and kernel filesystem calls are serialized on one CPU. Bind mounts, stacked mounts, root replacement, chroot, mount namespaces, lazy/forced unmount, additional mount flags/options, permission enforcement, disk-backed root, and additional filesystem types remain in [the VFS roadmap](https://github.com/frankischilling/Axiom64/issues/4). Private mappings eagerly copy bytes and do not retain filesystem references; general file-backed virtual-memory lifetime and writeback are still planned. Read-only remount conservatively treats all shared file pages as busy, including read-only mappings. Ext2 also rejects it while an unlinked inode is referenced.

The interface follows the concepts described in the [Linux VFS documentation](https://www.kernel.org/doc/html/latest/filesystems/vfs.html). Supported mount behavior is checked against the Linux [mount](https://man7.org/linux/man-pages/man2/mount.2.html) and [umount](https://man7.org/linux/man-pages/man2/umount.2.html) contracts; the limits above identify the current subset.
