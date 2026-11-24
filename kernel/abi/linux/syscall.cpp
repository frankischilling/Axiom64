// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/abi/linux/syscall.cpp
 * @brief   Linux x86-64 syscall dispatch.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Reads the syscall register frame, checks userspace arguments, and routes
 * requests to kernel subsystems.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "drivers/platform/devices.hpp"
#include "drivers/graphics/drm_scanout.hpp"
#include "boot/boot.hpp"
#include "abi/linux/wall_clock.hpp"
#include "drivers/audio/alsa_pcm.hpp"
#include "drivers/audio/pcm.hpp"
#include "drivers/block/block.hpp"
#include "fs/ext2/ext2.hpp"
#include "ipc/ipc.hpp"
#include "ipc/system_v_semaphores.hpp"
#include "ipc/system_v_message_queues.hpp"
#include "ipc/posix_message_queues.hpp"
#include "ipc/shared_memory.hpp"
#include "process/signals.hpp"
#include "process/clock_sleep.hpp"
#include "process/task.hpp"
#include "security/seccomp.hpp"
#include "process/scheduler.hpp"
#include "process/cpu.hpp"
#include "mm/barrier.hpp"
#include "mm/file_mapping.hpp"
#include "mm/limits.hpp"
#include "mm/remap.hpp"
#include "mm/residency.hpp"
#include "mm/stack.hpp"
#include "process/exec_arguments.hpp"
#include "process/futex.hpp"
#include "process/waitid.hpp"
#include "io/io.hpp"
#include "io/descriptor_wait.hpp"
#include "net/packet.hpp"
#include "net/inet.hpp"
#include "net/inet6.hpp"
#include "net/netlink.hpp"
#include "core/time.hpp"
#include "core/random.hpp"
#include "core/random/primitives.hpp"
#include "abi/linux/credentials.hpp"
#include "abi/linux/resource.hpp"
#include "abi/linux/eventfd.hpp"
#include "abi/linux/timerfd.hpp"
#include "abi/linux/signalfd.hpp"
#include "abi/linux/xattr.hpp"
#include "fs/record_lock.hpp"
#include "fs/proc.hpp"
#include "fs/descriptor_inode.hpp"
#include "fs/descriptor.hpp"
#include "fs/pipe.hpp"
#include "fs/memfd.hpp"
#include "fs/inotify.hpp"

namespace ax {
struct LinuxStat {
    uint64_t dev, ino, nlink;
    uint32_t mode, uid, gid, pad;
    uint64_t rdev;
    int64_t size, blksize, blocks;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns, reserved[3];
};

static_assert(sizeof(LinuxStat) == 144);

struct StatxTimestamp {
    int64_t seconds;
    uint32_t nanoseconds;
    int32_t reserved;
};

struct LinuxStatx {
    uint32_t mask, block_size;
    uint64_t attributes;
    uint32_t links, uid, gid;
    uint16_t mode, reserved;
    uint64_t inode, size, blocks, attributes_mask;
    StatxTimestamp access, birth, change, modification;
    uint32_t rdev_major, rdev_minor, dev_major, dev_minor;
    uint64_t mount_id;
    uint64_t optional_fields[13];
};

static_assert(sizeof(LinuxStatx) == 256);

struct Timespec {
    int64_t sec, nsec;
};

static Handle* fd_handle(int fd, bool path_allowed = false) {
    auto handle =
        fd >= 0 && unsigned(fd) < max_fds ? current_task()->files->entries[fd].handle : nullptr;
    return handle && (!path_allowed && (handle->flags & 010000000)) ? nullptr : handle;
}

static int64_t copy_result(uint64_t to, const void* data, size_t size) {
    return current_task()->memory->space.copy_out(to, data, size) ? 0 : -14;
}

static bool path_at(int fd, uint64_t user, Path& path) {
    if (!current_task()->memory->space.string(user, path.text, sizeof(path.text)))
        return false;
    if (!path.text[0]) {
        path.error = -2;
        return false;
    }
    path.base = current_task()->fs->root_node;
    if (path.text[0] != '/') {
        if (fd == -100)
            path.base = current_task()->fs->cwd_node;
        else {
            auto h = fd_handle(fd, true);
            if (!h) {
                path.error = -9;
                return false;
            }
            if (!h->node || (h->node->mode & 0170000) != directory) {
                path.error = -20;
                return false;
            }
            path.base = h->node;
        }
    }
    path.error = 0;
    return true;
}

static int64_t inotify_call(const Frame& frame) {
    if (frame.rax == 253 || frame.rax == 294) {
        uint32_t flags = frame.rax == 294 ? uint32_t(frame.rdi) : 0;
        if (flags & ~(04000u | 02000000u))
            return -22;
        int fd = reserve_fd(*current_task(), 0, flags & 02000000);
        if (fd < 0)
            return fd;
        int error;
        auto handle =
            open_inotify(current_task()->credentials.user.effective, flags & 04000, error);
        if (!handle) {
            discard_reserved_fd(*current_task()->files, fd);
            return error;
        }
        install_reserved_fd(*current_task()->files, fd, handle);
        return fd;
    }
    uint32_t mask = frame.rdx;
    constexpr uint32_t valid = inotify_events | inotify_flags | inotify_unmount |
                               inotify_queue_overflow | inotify_watch_ignored;
    if (frame.rax == 254 && (!mask || (mask & ~valid)))
        return -22;
    auto handle = fd_handle(frame.rdi);
    if (!handle)
        return -9;
    if (!handle->inotify)
        return -22;
    if (frame.rax == 255)
        return inotify_remove_watch(*handle->inotify, int32_t(frame.rsi));
    if ((mask & inotify_mask_add) && (mask & inotify_mask_create))
        return -22;
    Path path;
    if (!path_at(-100, frame.rsi, path))
        return path.error;
    Node* node = nullptr;
    int error = resolve_path(path, node, !(mask & inotify_dont_follow));
    if (error)
        return error;
    if ((mask & inotify_onlydir) && (node->mode & 0170000) != directory)
        return -20;
    error = node_access(node, 4);
    return error ? error : inotify_add_watch(*handle->inotify, node, mask);
}

static int64_t open_file(int dirfd, uint64_t path, uint32_t flags, uint32_t mode) {
    bool path_only = flags & 010000000;
    if (path_only)
        flags &= 010000000 | 02000000 | 0200000 | 0400000;
    else
        flags |= 0100000; // Native x86-64 opens force O_LARGEFILE.
    Path name;
    if (!path_at(dirfd, path, name))
        return name.error;
    Node* n = nullptr;
    bool created = false;
    int error = resolve_path(name, n, !(flags & 0400000) && !((flags & 0300) == 0300));
    if (!error && (flags & 0300) == 0300)
        return -17;
    if (error == -2 && (flags & 0100)) {
        error = create_node(name, regular_file | ((mode & 07777) & ~current_task()->fs->umask), n);
        created = !error;
    }
    if (error)
        return error;
    if ((flags & 0200000) && (n->mode & 0170000) != directory)
        return -20;
    if ((n->mode & 0170000) == symlink && !path_only)
        return -40;
    if ((n->mode & 0170000) == directory && (flags & 3))
        return -21;
    Node* dentry = n;
    n = file_node(n);
    if (int error = node_validate(n))
        return error;
    unsigned mask = (flags & 3) == 0 ? 4 : (flags & 3) == 1 ? 2 : 6;
    if ((flags & 01000) && (n->mode & 0170000) == regular_file)
        mask |= 2;
    if (!path_only && !created && (error = node_access(n, mask)))
        return error;
    if (!path_only && descriptor_inode_path_only(n))
        return -6;
    if (!path_only && n->mount->nodev &&
        ((n->mode & 0170000) == character || (n->mode & 0170000) == block_device))
        return -13;
    if (((flags & 3) || (flags & 01000)) && (n->mode & 0170000) == regular_file && node_readonly(n))
        return -30;
    if (n->device == Device::block && (flags & 3) && block_info(n->device_id)->readonly)
        return -30;
    if (n->device == Device::block && (flags & 3) && block_claimed(n->device_id))
        return -16;
    if (n->device == Device::block && (flags & 040000)) // O_DIRECT needs alignment semantics.
        return -22;
    if (!path_only && n->device == Device::tty && !current_task()->process->controlling_pty &&
        !current_task()->process->controlling_console)
        return -6;
    if ((flags & 01000) && (n->mode & 0170000) == regular_file) {
        error = node_truncate(n, 0);
        if (error)
            return error;
    }
    if (!path_only && (n->mode & 0170000) == fifo)
        return open_fifo(*current_task(), n, dentry, flags);
    Handle* h = open_handle(n, flags, &error);
    if (!h)
        return error;
    int fd = allocate_fd(current_task(), h, 0, flags & 02000000);
    if (fd < 0) {
        close_handle(h);
    } else {
        h->opened_dentry = dentry;
        if (!path_only) {
            inotify_dentry(dentry, inotify_open);
            if ((flags & 01000) && (n->mode & 0170000) == regular_file)
                inotify_dentry(dentry, inotify_modify);
        }
    }
    return fd;
}

static int path_node_at(int fd, uint64_t user, uint64_t flags, Node*& node, bool real = false) {
    if (flags & ~uint64_t(0x100 | 0x200 | 0x1000))
        return -22;
    Path path;
    if (flags & 0x1000) {
        if (!current_task()->memory->space.string(user, path.text, sizeof(path.text)))
            return -14;
        if (!path.text[0]) {
            auto handle = fd_handle(fd, true);
            node = fd == -100              ? current_task()->fs->cwd_node
                   : !handle               ? nullptr
                   : handle->opened_dentry ? handle->opened_dentry
                                           : handle->node;
            return node ? 0 : -9;
        }
    }
    if (!path_at(fd, user, path))
        return path.error;
    path.real_access = real;
    return resolve_path(path, node, !(flags & 0x100));
}

static int access_file(int fd, uint64_t user, uint32_t mask, uint64_t flags) {
    if (mask & ~7u)
        return -22;
    Node* node = nullptr;
    bool real = !(flags & 0x200);
    int error = path_node_at(fd, user, flags, node, real);
    if (error)
        return error;
    if ((mask & 2) && node_readonly(node))
        return -30;
    if ((mask & 1) && (node->mode & 0170000) == regular_file && node->mount->noexec)
        return -13;
    return node_access(node, mask, real);
}

static int stat_information(Node*& n, LinuxStat& s) {
    if (!n)
        return -2;
    n = file_node(n);
    if (int error = node_validate(n))
        return error;
    if (n->mount->ops->refresh)
        n->mount->ops->refresh(n);
    s.dev = n->mount->id;
    s.ino = n->inode;
    s.nlink = n->links;
    s.mode = n->mode;
    s.size = n->size;
    s.blksize = page_size;
    s.blocks = n->allocated_blocks;
    s.uid = n->uid;
    s.gid = n->gid;
    s.atime = n->atime.sec;
    s.atime_ns = n->atime.nsec;
    s.mtime = n->mtime.sec;
    s.mtime_ns = n->mtime.nsec;
    s.ctime = n->ctime.sec;
    s.ctime_ns = n->ctime.nsec;
    if ((n->mode & 0170000) == character || (n->mode & 0170000) == block_device)
        s.rdev = device_number(n);
    if ((n->mode & 0170000) == block_device)
        s.size = s.blocks = 0;
    return 0;
}

static int64_t stat_node(Node* node, uint64_t dst) {
    LinuxStat information{};
    int error = stat_information(node, information);
    return error ? error : copy_result(dst, &information, sizeof(information));
}

static int64_t stat_descriptor(Handle* handle, uint64_t dst) {
    if (!handle)
        return -9;
    Node* node;
    int error = descriptor_inode(*handle, node);
    return error ? error : stat_node(node, dst);
}

static int stat_path_node(int dirfd, uint64_t path, bool follow, Node*& node) {
    Path name;
    if (!path_at(dirfd, path, name))
        return name.error;
    return resolve_path(name, node, follow);
}

static int64_t stat_path(int dirfd, uint64_t path, uint64_t dst, bool follow) {
    Node* node = nullptr;
    int error = stat_path_node(dirfd, path, follow, node);
    return error ? error : stat_node(node, dst);
}

static int stat_at_node(int dirfd, uint64_t path, uint32_t flags, Node*& node) {
    if (flags & 0x1000) { // AT_EMPTY_PATH
        char first = 0;
        if (path && !current_task()->memory->space.copy_in(&first, path, sizeof(first)))
            return -14;
        if (!first) {
            if (dirfd == -100) { // AT_FDCWD
                node = current_task()->fs->cwd_node;
                return 0;
            }
            auto handle = fd_handle(dirfd, true);
            return handle ? descriptor_inode(*handle, node) : -9;
        }
    }
    return stat_path_node(dirfd, path, !(flags & 0x100), node);
}

static int64_t statx_at(int dirfd, uint64_t path, uint32_t flags, uint32_t mask, uint64_t dst) {
    constexpr uint32_t nofollow = 0x100, no_automount = 0x800, empty_path = 0x1000;
    constexpr uint32_t sync_type = 0x6000, reserved_mask = 0x80000000;
    constexpr uint32_t basic_stats = 0x7ff, mount_id = 0x1000, mount_root = 0x2000;
    if ((flags & ~(nofollow | no_automount | empty_path | sync_type)) ||
        (flags & sync_type) == sync_type || (mask & reserved_mask))
        return -22;
    Node* node = nullptr;
    LinuxStat stat{};
    int error = stat_at_node(dirfd, path, flags, node);
    if (!error)
        error = stat_information(node, stat);
    if (error)
        return error;

    LinuxStatx result{};
    result.mask = basic_stats;
    result.block_size = stat.blksize;
    result.attributes_mask = mount_root;
    if (node == node->mount->root)
        result.attributes = mount_root;
    result.links = stat.nlink;
    result.uid = stat.uid;
    result.gid = stat.gid;
    result.mode = stat.mode;
    result.inode = stat.ino;
    result.size = stat.size;
    result.blocks = stat.blocks;
    result.access = {int64_t(stat.atime), uint32_t(stat.atime_ns), 0};
    result.change = {int64_t(stat.ctime), uint32_t(stat.ctime_ns), 0};
    result.modification = {int64_t(stat.mtime), uint32_t(stat.mtime_ns), 0};
    result.rdev_major = device_major(stat.rdev);
    result.rdev_minor = device_minor(stat.rdev);
    result.dev_major = device_major(stat.dev);
    result.dev_minor = device_minor(stat.dev);
    if (mask & mount_id) {
        result.mask |= mount_id;
        result.mount_id = node->mount->id;
    }
    return copy_result(dst, &result, sizeof(result));
}

static int64_t block(Wait why, int fd = -1, int pid = -1) {
    current_task()->state = State::blocked;
    current_task()->wait = why;
    current_task()->wait_fd = fd;
    current_task()->wait_pid = pid;
    return would_block;
}

static int64_t mmap_call(uint64_t addr, size_t len, uint64_t prot, int flags, int fd,
                         uint64_t off) {
    constexpr int map_fixed = 0x10, map_fixed_noreplace = 0x100000;
    constexpr int map_noreserve = 0x4000;
    bool no_replace = flags & map_fixed_noreplace;
    bool fixed = no_replace || (flags & map_fixed);
    bool replace_existing = fixed && !no_replace;
    // Linux mmap ignores protection bits outside the access permissions.
    prot &= 7;
    bool private_mapping = flags & 2, stack_mapping = flags & 0x100;
    bool reservation =
        (flags & 0x23) == 0x22 && !stack_mapping && (!prot || (flags & map_noreserve));
    size_t limit = reservation ? anonymous_reservation_limit : mmap_length_limit;
    if (!len || len > limit || off % page_size || !(flags & 3) || (flags & 3) == 3)
        return -22;
    len = align_up(len);
    bool advance_map = false;
    auto& space = current_task()->memory->space;
    if (fixed) {
        if (addr % page_size || addr < page_size || addr >= user_limit || len > user_limit - addr)
            return -22;
    } else {
        addr = align_down(addr);
        if (!reservation || addr < 0x10000 || addr >= user_limit || len > user_limit - addr ||
            space.mapped_size(addr, len)) {
            addr = space.find_unmapped(len);
            advance_map = true;
        }
        if (!addr)
            return -12;
    }
    if (addr >= user_limit || len > user_limit - addr)
        return -12;
    Handle* h = nullptr;
    bool framebuffer = false;
    uint64_t drm_address = 0;
    if (!(flags & 0x20)) {
        h = fd_handle(fd);
        if (!h)
            return -9;
    }
    if (no_replace && current_task()->memory->space.mapped_size(addr, len))
        return -17;
    if (h) {
        framebuffer = h->node && h->node->device == Device::framebuffer;
        if (h->node && h->node->device == Device::drm_scanout) {
            if (int error = DrmScanout::mapping(*h, off, len, prot, flags, drm_address))
                return error;
        } else if (!framebuffer && (!h->node || (h->node->mode & 0170000) != regular_file)) {
            return -19;
        }
        if (!framebuffer && h->node->mount->ops == &procfs_ops)
            return -19;
        if (!framebuffer && h->node->mount->ops == &posix_queue_filesystem())
            return -19;
        if (!framebuffer && (h->flags & 3) == 1)
            return -13;
        if (!framebuffer && (prot & 4) && h->node->mount->noexec)
            return -1;
        if (!framebuffer && (flags & 1) && (prot & 2) && (h->flags & 3) != 2)
            return -13;
    }
    if (!memory_growth_allowed(*current_task(), addr, len, replace_existing))
        return -12;
    if (stack_mapping && (!private_mapping || !(flags & 0x20)))
        return -22;
    if (private_mapping && (prot & 2) && !stack_mapping &&
        !data_growth_allowed(*current_task(), addr, len, replace_existing))
        return -12;
    auto complete = [&]() -> int64_t {
        if (advance_map)
            space.next_map = addr + len + page_size;
        return addr;
    };
    auto replace = [&]() -> int {
        return replace_existing ? shared_memory_unmap(*current_task(), addr, len) : 0;
    };
    if (reservation) {
        if (replace_existing && !space.prepare_mapping(addr, len))
            return -12;
        if (int error = replace()) {
            space.trim_page_tables(addr, len);
            return error;
        }
        return space.map_anonymous_reservation(addr, len, prot) ? complete() : -12;
    }
    if (drm_address) {
        if (replace_existing && !space.prepare_mapping(addr, len))
            return -12;
        if (int error = replace()) {
            space.trim_page_tables(addr, len);
            return error;
        }
        return space.map_physical(addr, drm_address, len, prot, false) ? complete() : -12;
    }
    if (framebuffer) {
        int error = replace();
        if (error)
            return error;
        int64_t result = framebuffer_map(current_task()->memory->space, addr, len, prot, off);
        if (result >= 0 && private_mapping)
            for (uint64_t page = addr; page < addr + len; page += page_size)
                *current_task()->memory->space.entry(page) |= page_private;
        return result < 0 ? result : complete();
    }
    if (h && is_memfd(h->node)) {
        int error =
            memfd_map(*current_task(), *h, addr, len, off, prot, flags & 1, replace_existing);
        return error ? error : complete();
    }
    if (h && h->node->mount->ops == &ext2_ops) {
        int error =
            map_disk_file(*current_task(), *h, addr, len, off, prot, flags & 1, replace_existing);
        return error ? error : complete();
    }
    auto file = h ? static_cast<FileMapping*>(alloc(sizeof(FileMapping))) : nullptr;
    if (h && !file)
        return -12;
    auto map_pages = [&]() -> int {
        if (h && (flags & 1)) {
            uint64_t backing;
            if (int error = node_map_shared(h->node, off, len, prot & 2, backing))
                return error;
            if (int error = replace())
                return error;
            if (!space.map_physical(addr, backing, len, prot))
                return -12;
            if ((h->flags & 3) != 2 || node_readonly(h->node))
                for (uint64_t page = addr; page < addr + len; page += page_size)
                    *space.entry(page) |= 0x800; // Shared mapping may never gain write access.
            if (h->node->mount->noexec)
                for (uint64_t page = addr; page < addr + len; page += page_size)
                    *space.entry(page) |= page_no_execute;
            return 0;
        }
        if (int error = replace())
            return error;
        uint64_t mapping_flags = private_mapping ? page_private : 0;
        if (stack_mapping)
            mapping_flags |= page_stack;
        else if (private_mapping && (flags & 0x20))
            mapping_flags |= page_anonymous;
        if (!space.map(addr, len, 3, mapping_flags))
            return -12;
        if ((flags & 0x21) == 0x21)
            for (uint64_t page = addr; page < addr + len; page += page_size) {
                uint64_t& entry = *space.entry(page);
                entry |= 0x400;
                page_account_shared(entry & page_mask);
            }
        if (h && off < h->node->size) {
            uint8_t buffer[4096];
            size_t count = min(len, h->node->size - size_t(off));
            for (size_t done = 0; done < count;) {
                int64_t result =
                    node_read(h->node, off + done, buffer, min(sizeof(buffer), count - done));
                if (result <= 0 || !space.copy_out(addr + done, buffer, size_t(result))) {
                    space.unmap(addr, len);
                    return result < 0 ? int(result) : -5;
                }
                done += result;
            }
        }
        if (h && h->node->mount->noexec)
            for (uint64_t page = addr; page < addr + len; page += page_size)
                *space.entry(page) |= page_no_execute;
        if (!space.protect(addr, len, prot)) {
            space.unmap(addr, len);
            return -12;
        }
        return 0;
    };
    if (int error = map_pages()) {
        release(file);
        return error;
    }
    if (file) {
        *file = {
            .space = &space, .start = addr, .end = addr + len, .offset = off, .description = h};
        attach_file_mapping(*file);
    }
    return complete();
}

static int64_t dup_fd(int old, int target, int flags = 0) {
    if (target < 0 || unsigned(target) >= max_fds)
        return -9;
    if (target != old) {
        if (uint64_t(target) >= current_task()->process->limits.soft(Resource::open_files))
            return -9;
        current_task()->files->expand(target);
    }
    Handle* h = fd_handle(old, true);
    if (!h)
        return -9;
    if (current_task()->files->entries[target].reserved)
        return -16;
    if (target != old) {
        close_descriptor(*current_task()->files, target);
        retain(h);
        current_task()->files->entries[target] = {h, bool(flags & 02000000)};
    }
    return target;
}

static int64_t make_special_node(int dirfd, uint64_t address, uint32_t mode) {
    uint32_t type = mode & 0170000;
    switch (type) {
    case 0:
        type = regular_file;
        break;
    case regular_file:
    case fifo:
        break;
    case directory:
        return -1;
    case character:
    case block_device:
    case 0140000:
        return -95;
    default:
        return -22;
    }
    Path path;
    if (!path_at(dirfd, address, path))
        return path.error;
    Node* node = nullptr;
    size_t length = strlen(path.text);
    if (length && path.text[length - 1] == '/') {
        while (length > 1 && path.text[length - 1] == '/')
            path.text[--length] = 0;
        int error = resolve_path(path, node, false);
        return error ? error : -17;
    }
    return create_node(path, type | ((mode & 07777) & ~current_task()->fs->umask), node);
}

static int64_t create_pipe(uint64_t dst, int flags) {
    if (flags & ~(04000 | pipe_direct | 02000000))
        return -22;
    if (!current_task()->memory->space.valid(dst, 8, true))
        return -14;
    int error;
    auto pipe = create_pipe_buffer(current_task()->credentials, error);
    if (!pipe)
        return error;
    auto reader = pipe_handle(pipe, false);
    auto writer = pipe_handle(pipe, true);
    if (!reader || !writer) {
        if (reader)
            close_handle(reader);
        if (writer)
            close_handle(writer);
        if (!reader && !writer)
            destroy_pipe_buffer(*pipe);
        return -23;
    }
    if (int error = attach_pipe_inode(*pipe, *reader, *writer)) {
        close_handle(reader);
        close_handle(writer);
        return error;
    }
    reader->flags |= flags & 04000;
    writer->flags |= flags & (04000 | pipe_direct);
    int result[2] = {allocate_fd(current_task(), reader, 0, flags & 02000000), -1};
    if (result[0] >= 0)
        result[1] = allocate_fd(current_task(), writer, 0, flags & 02000000);
    if (result[0] < 0 || result[1] < 0) {
        if (result[0] >= 0)
            current_task()->files->entries[result[0]] = {};
        close_handle(reader);
        close_handle(writer);
        return -24;
    }
    current_task()->memory->space.copy_out(dst, result, sizeof(result));
    return 0;
}

static int64_t wait_child(int pid, uint64_t status, int options, uint64_t usage) {
    if (options & ~11)
        return -22;
    if (status && !current_task()->memory->space.valid(status, 4, true))
        return -14;
    bool found = false;
    for (auto& t : tasks) {
        if (t.state == State::empty || t.process->leader != &t ||
            t.process->parent != current_task()->process->pid ||
            (pid > 0 && t.process->pid != pid) ||
            (pid == 0 && t.process->pgid != current_task()->process->pgid) ||
            (pid < -1 && t.process->pgid != -pid))
            continue;
        found = true;
        bool stopped = t.process->stopped && !t.process->stop_reported && (options & 2);
        bool continued = t.process->continued && (options & 8);
        if ((t.state != State::zombie || t.process->live_threads) && !stopped && !continued)
            continue;
        int child = t.process->pid;
        int child_status = !t.process->live_threads ? t.process->exit_status
                           : continued              ? 0xffff
                                                    : (t.process->stop_signal << 8) | 0x7f;
        if (status)
            current_task()->memory->space.copy_out(status, &child_status, 4);
        if (usage) {
            auto report = linux_resource_usage(cpu_waited_usage(*t.process));
            if (copy_result(usage, &report, sizeof(report)))
                return -14;
        }
        if (t.state == State::zombie && !t.process->live_threads)
            reap_task(&t, *current_task()->process);
        else if (continued)
            t.process->continued = false;
        else
            t.process->stop_reported = true;
        return child;
    }
    if (!found)
        return -10;
    if (options & 1)
        return 0;
    return block(Wait::child, -1, pid);
}

static bool read_exec_data(void* context, uint64_t address, void* output, size_t size) {
    return static_cast<AddressSpace*>(context)->copy_in(output, address, size);
}

static int64_t exec_user(uint64_t path, uint64_t argv, uint64_t envp, Frame* frame) {
    if (current_task()->process_limit_exceeded) {
        // Capture filename errors before the deferred quota check; argv/envp follow it.
        char filename[exec_path_limit];
        size_t length = 0;
        for (; length < sizeof(filename); length++) {
            if (!current_task()->memory->space.copy_in(filename + length, path + length, 1))
                return -14;
            if (!filename[length])
                break;
        }
        if (length == sizeof(filename))
            return -36;
        if (!length)
            return -2;
        if (int error = process_exec_limit(*current_task()))
            return error;
    }
    ExecArguments arguments;
    int result = arguments.capture(read_exec_data, &current_task()->memory->space, path, argv, envp,
                                   current_task()->process->limits.soft(Resource::stack));
    if (!result) {
        result = exec_task(current_task(), arguments);
        if (!result)
            *frame = current_task()->frame;
    }
    return result;
}

static void exec_filename_at(int fd, const char* path, char* display) {
    if (fd == -100 || path[0] == '/') {
        memcpy(display, path, strlen(path) + 1);
        return;
    }
    memcpy(display, "/dev/fd/", 8);
    char digits[10];
    size_t count = 0;
    do {
        digits[count++] = '0' + fd % 10;
        fd /= 10;
    } while (fd);
    auto next = display + 8;
    while (count)
        *next++ = digits[--count];
    if (*path)
        *next++ = '/';
    memcpy(next, path, strlen(path) + 1);
}

static int64_t execveat_user(Frame& frame) {
    constexpr uint32_t nofollow = 0x100, empty_path = 0x1000, check_only = 0x10000;
    uint32_t flags = frame.r8;
    int fd = int(frame.rdi);
    Path path;
    auto& task = *current_task();
    auto& space = task.memory->space;
    size_t length = 0;
    while (length < sizeof(path.text)) {
        if (!space.copy_in(path.text + length, frame.rsi + length, 1))
            return -14;
        if (!path.text[length])
            break;
        ++length;
    }
    if (length == sizeof(path.text))
        return -36;
    if (!length && !(flags & empty_path))
        return -2;
    if (int error = process_exec_limit(task))
        return error;
    if (flags & ~(nofollow | empty_path | check_only))
        return -22;

    Node* file = nullptr;
    bool path_inaccessible = false;
    if (path.text[0] == '/') {
        path.base = task.fs->root_node;
    } else if (fd == -100) {
        file = path.base = task.fs->cwd_node;
    } else {
        auto handle = fd_handle(fd, true);
        if (!handle)
            return -9;
        path_inaccessible = task.files->entries[fd].cloexec;
        file = path.base = handle->node;
        if (!length && handle->opened_dentry)
            file = handle->opened_dentry;
        if (length && (!file || (file->mode & 0170000) != directory))
            return -20;
    }
    if (length) {
        if (int error = resolve_path(path, file, !(flags & nofollow)))
            return error;
    }
    if (int error = executable_access(task, file_node(file)))
        return error;

    char display[exec_filename_limit];
    exec_filename_at(fd, path.text, display);
    ExecArguments arguments;
    int result = arguments.capture_named(read_exec_data, &space, display, frame.rdx, frame.r10,
                                         task.process->limits.soft(Resource::stack));
    if (!result && !(flags & check_only)) {
        result = exec_task(&task, arguments, file, path_inaccessible);
        if (!result)
            frame = task.frame;
    }
    return result;
}

static int64_t getdents(int fd, uint64_t buffer, size_t size) {
    auto h = fd_handle(fd);
    if (!h)
        return -9;
    if (!h->node || (h->node->mode & 0170000) != directory)
        return -20;
    size_t done = 0;
    while (true) {
        DirectoryEntry entry{};
        int result = node_readdir(h->node, h->offset, entry);
        if (result <= 0)
            return done ? int64_t(done) : result;
        size_t len = strlen(entry.name) + 1, record = (19 + len + 7) & ~size_t(7);
        if (record > size - done)
            return done ? int64_t(done) : -22;
        uint8_t data[280]{};
        uint16_t reclen = record;
        memcpy(data, &entry.inode, 8);
        memcpy(data + 8, &entry.next, 8);
        memcpy(data + 16, &reclen, 2);
        data[18] = (entry.mode >> 12) & 15;
        memcpy(data + 19, entry.name, len);
        if (!current_task()->memory->space.copy_out(buffer + done, data, record))
            return -14;
        done += record;
        h->offset = entry.next;
    }
}

struct LinuxStatfs {
    uint64_t type, bsize, blocks, bfree, bavail, files, ffree;
    uint32_t fsid[2];
    uint64_t namelen, frsize, flags, spare[4];
};

static_assert(sizeof(LinuxStatfs) == 120);

static int64_t statfs_node(Node* node, uint64_t dst) {
    if (!node)
        return -2;
    FilesystemStats stats;
    int error = node_stats(node, stats);
    if (error)
        return error;
    LinuxStatfs result{};
    result.type = stats.type;
    result.bsize = result.frsize = stats.block_size;
    result.blocks = stats.blocks;
    result.bfree = result.bavail = stats.free_blocks;
    result.files = stats.files;
    result.ffree = stats.free_files;
    result.fsid[0] = node->mount->id;
    result.namelen = 255;
    result.flags = node_readonly(node) ? 1 : 0;
    return copy_result(dst, &result, sizeof(result));
}

static int64_t readlink_path(int fd, uint64_t path, uint64_t buffer, size_t capacity) {
    if (!capacity)
        return -22;
    Node* node = nullptr;
    int error = path_node_at(fd, path, 0x100 | 0x1000, node);
    if (error)
        return error;
    node = file_node(node);
    if ((node->mode & 0170000) != symlink)
        return -22;
    uint8_t data[1024];
    size_t done = 0;
    while (done < capacity) {
        int64_t result = node_read(node, done, data, min(sizeof(data), capacity - done));
        if (result <= 0)
            return result < 0 ? result : int64_t(done);
        if (copy_result(buffer + done, data, result))
            return -14;
        done += result;
    }
    return done;
}

static int64_t ioctl_call(int fd, uint64_t request, uint64_t arg) {
    request = uint32_t(request);
    auto h = fd_handle(fd);
    if (!h)
        return -9;
    if (request == 0x5421) {
        int nonblock;
        if (!current_task()->memory->space.copy_in(&nonblock, arg, 4))
            return -14;
        h->flags = nonblock ? h->flags | 04000 : h->flags & ~04000u;
        return 0;
    }
    if (request == 0x5451 || request == 0x5450) {
        current_task()->files->entries[fd].cloexec = request == 0x5451;
        return 0;
    }
    if (h->timer)
        return timerfd_ioctl(*h->timer, request, arg);
    if (request == 0x541b && h->inotify) {
        int size = inotify_queue(*h->inotify).bytes();
        return copy_result(arg, &size, sizeof(size));
    }
    if (request == 0x541b && (h->socket || h->pipe)) {
        int size = h->socket ? h->socket->uses_record_queue() ? h->socket->datagrams.available()
                                                              : h->socket->stream.size()
                             : h->pipe->size;
        return copy_result(arg, &size, 4);
    }
    if (request == 0x541b && h->packet) {
        int size = packet_available(h->packet);
        return copy_result(arg, &size, 4);
    }
    if (h->packet && (request == 0x8906 || request == 0x8907 || request == 0x80108906 ||
                      request == 0x80108907)) {
        int64_t value[2];
        int error = packet_timestamp(h->packet, value, request == 0x8907 || request == 0x80108907);
        return error ? error : copy_result(arg, value, sizeof(value));
    }
    if (request == 0x541b && h->inet) {
        int size = inet_available(h->inet);
        return copy_result(arg, &size, sizeof(size));
    }
    if (request == 0x541b && h->inet6) {
        int size = inet6_available(h->inet6);
        return copy_result(arg, &size, sizeof(size));
    }
    if ((h->socket || h->packet || h->inet || h->inet6 || h->netlink) && request >= 0x890b &&
        request <= 0x89ff)
        return net_ioctl(*current_task(), request, arg);
    if (!h->node ||
        ((h->node->mode & 0170000) != character && (h->node->mode & 0170000) != block_device))
        return -25;
    const auto result = device_ioctl(h, request, arg);
    if (result == -11) {
        const auto device = h->node->device;
        const bool nonblock = h->flags & 04000;
        if ((device == Device::dsp && request == Pcm::sync_request) ||
            (device == Device::alsa_playback && request == Alsa::drain_request && !nonblock)) {
            current_task()->wait_generation = h->generation;
            return block(Wait::pcm_drain, fd);
        }
        if (device == Device::alsa_playback && request == Alsa::write_frames_request && !nonblock) {
            current_task()->wait_generation = h->generation;
            return block(Wait::alsa_write, fd);
        }
    }
    return result;
}

static int priority_limit(int policy, bool maximum) {
    switch (policy) {
    case 0: // SCHED_OTHER
    case 3: // SCHED_BATCH
    case 5: // SCHED_IDLE
    case 6: // SCHED_DEADLINE
    case 7: // SCHED_EXT
        return 0;
    case 1: // SCHED_FIFO
    case 2: // SCHED_RR
        return maximum ? 99 : 1;
    default:
        return -22;
    }
}

static int64_t scheduler_parameter(unsigned request, int pid, int policy, uint64_t parameter) {
    constexpr unsigned set_param = 142, get_param = 143, set_scheduler = 144, get_scheduler = 145;
    constexpr int reset_on_fork = 0x40000000;
    if (pid < 0 || (request != get_scheduler && !parameter) || policy < 0)
        return -22;
    int priority = 0;
    const bool change = request == set_param || request == set_scheduler;
    if (change && !current_task()->memory->space.copy_in(&priority, parameter, sizeof(priority)))
        return -14;
    auto target = pid ? task(pid) : current_task();
    if (!target)
        return -3;
    if (request == get_scheduler)
        return 0; // Every thread runs under SCHED_OTHER.
    if (request == get_param)
        return copy_result(parameter, &priority, sizeof(priority));
    const int minimum = priority_limit(policy & ~reset_on_fork, false);
    if (minimum < 0 || priority < minimum ||
        priority > priority_limit(policy & ~reset_on_fork, true))
        return -22;
    const auto uid = current_task()->credentials.user.effective;
    if (uid != target->credentials.user.real && uid != target->credentials.user.effective &&
        !capable(current_task()->credentials, Capability::sys_nice))
        return -1;
    return policy ? -95 : 0;
}

int64_t dispatch_linux_syscall(Frame* f, Task* running) {
    uint64_t a = f->rdi, b = f->rsi, c = f->rdx, d = f->r10, e = f->r8, g = f->r9;
    switch (f->rax) {
    case 188:
    case 189:
    case 190:
    case 191:
    case 192:
    case 193:
    case 194:
    case 195:
    case 196:
    case 197:
    case 198:
    case 199:
        return linux_xattr(f->rax, a, b, c, d, e);
    case 0:
    case 1:
    case 17:
    case 18:
    case 19:
    case 20:
    case 40:
    case 43:
    case 44:
    case 45:
    case 46:
    case 47:
    case 73:
    case 275:
    case 276:
    case 278:
    case 288:
        return io_syscall(*running, *f);
    case 2:
        return open_file(-100, a, b, c);
    case 3: {
        auto h = fd_handle(a, true);
        if (!h)
            return -9;
        close_descriptor(*running->files, int(a));
        return 0;
    }
    case 4:
        return stat_path(-100, a, b, true);
    case 5:
        return stat_descriptor(fd_handle(a, true), b);
    case 6:
        return stat_path(-100, a, b, false);
    case 7:
    case 23:
    case 270:
    case 271:
        return descriptor_wait_syscall(*running, *f);
    case 8: {
        auto h = fd_handle(a);
        if (!h || (h->flags & 010000000))
            return -9;
        if (h->epoll || h->event || h->timer || h->signal_descriptor || h->inotify)
            return uint32_t(c) <= 4 ? 0 : -22;
        if (memory_device(*h))
            return uint32_t(c) <= 4 ? 0 : -22;
        if (h->pipe || !h->node || (h->node->mode & 0170000) == character)
            return -29;
        int64_t base = c == 0   ? 0
                       : c == 1 ? int64_t(h->offset)
                       : c == 2 ? int64_t(h->node->size)
                                : -1;
        if (base < 0 || (int64_t(b) < 0 && int64_t(b) < -base) ||
            (int64_t(b) > 0 && b > uint64_t(INT64_MAX - base)))
            return -22;
        int64_t pos = base + int64_t(b);
        if (pos < 0)
            return -22;
        h->offset = pos;
        return pos;
    }
    case 9:
        return mmap_call(a, b, c, d, e, g);
    case 10: {
        int error = memory_protection_range(running->memory->space, a, b, c);
        if (error)
            return error;
        if (!b)
            return 0;
        if (c & (2 | 4)) {
            if (a >= user_limit || b > user_limit - a)
                return -22;
            for (uint64_t p = a; p < a + b; p += page_size) {
                auto entry = running->memory->space.entry(p);
                if (entry &&
                    (((c & 2) && (*entry & 0x800)) || ((c & 4) && (*entry & page_no_execute))))
                    return -13;
            }
        }
        if (a < user_limit && b <= user_limit - a &&
            !memory_protection_allowed(*running, a, align_up(b), int(c)))
            return -12;
        if (a >= user_limit || b > user_limit - a)
            return -12;
        return shared_memory_protect(*running, a, align_up(b), c);
    }
    case 11: {
        if (a % page_size || !b || a >= user_limit || b > user_limit - a)
            return -22;
        int error = shared_memory_unmap(*running, a, align_up(b));
        if (error)
            return error;
        running->memory->space.trim_page_tables(a, align_up(b));
        inotify_reap_inodes();
        return 0;
    }
    case 12: {
        if (!a)
            return running->memory->brk_end;
        if (a < running->memory->brk_base || a > running->memory->brk_base + 128 * 1024 * 1024)
            return running->memory->brk_end;
        if (!heap_change_allowed(*running, a))
            return running->memory->brk_end;
        uint64_t old_end = align_up(running->memory->brk_end), new_end = align_up(a);
        if (new_end > old_end) {
            size_t length = new_end - old_end;
            auto& space = running->memory->space;
            if (space.mapped_size(old_end, length) ||
                !memory_growth_allowed(*running, old_end, length) ||
                !data_growth_allowed(*running, old_end, length) || !space.map(old_end, length, 3))
                return running->memory->brk_end;
        }
        if (new_end < old_end && shared_memory_unmap(*running, new_end, old_end - new_end))
            return running->memory->brk_end;
        running->memory->brk_end = a;
        return a;
    }
    case 13:
        if (a < 1 || a > 64 || a == 9 || a == 19 || d != 8)
            return -22;
        if (c && copy_result(c, running->handlers->signal_actions[a - 1], 32))
            return -14;
        if (b) {
            uint64_t action[4];
            if (!running->memory->space.copy_in(action, b, sizeof(action)))
                return -14;
            memcpy(running->handlers->signal_actions[a - 1], action, sizeof(action));
            signal_discard_ignored(*running, int(a));
        }
        return 0;
    case 14: {
        if (d != 8)
            return -22;
        if (c && copy_result(c, &running->signal_mask, 8))
            return -14;
        if (b) {
            uint64_t mask;
            if (!running->memory->space.copy_in(&mask, b, 8))
                return -14;
            mask &= ~((1ull << 8) | (1ull << 18));
            if (a == 0)
                running->signal_mask |= mask;
            else if (a == 1)
                running->signal_mask &= ~mask;
            else if (a == 2)
                running->signal_mask = mask;
            else
                return -22;
        }
        return 0;
    }
    case 16:
        return ioctl_call(a, b, c);
    case 15:
    case 34:
    case 36:
    case 37:
    case 38:
    case 62:
    case 127:
    case 128:
    case 129:
    case 130:
    case 131:
    case 200:
    case 234:
    case 297:
        return signal_syscall(f);
    case 21: {
        return access_file(-100, a, b, 0);
    }
    case 22:
        return create_pipe(a, 0);
    case 24:
        return 0;
    case 25:
        return remap_memory(*running, a, b, c, d);
    case 26:
        return sync_file_mappings(running->memory->space, a, b, unsigned(c));
    case 27:
        return mapped_residency(*running, a, b, c);
    case 149:
    case 150:
        return set_memory_lock(*running, a, b, f->rax == 149);
    case 28:
        return running->memory->space.valid(a, b) ? 0 : -12;
    case 29:
    case 30:
    case 31:
    case 67:
        return shared_memory_syscall(f);
    case 64:
    case 65:
    case 66:
    case 220:
        return semaphore_syscall(f);
    case 68:
    case 69:
    case 70:
    case 71:
        return message_queue_syscall(f);
    case 240:
    case 241:
    case 242:
    case 243:
    case 244:
    case 245:
        return posix_queue_syscall(f);
    case 32: {
        auto h = fd_handle(a, true);
        if (!h)
            return -9;
        retain(h);
        int fd = allocate_fd(running, h);
        if (fd < 0)
            close_handle(h);
        return fd;
    }
    case 33:
        return dup_fd(a, b);
    case 35:
        return linux_clock_nanosleep(*running, 1, 0, a, b);
    case 39:
        return running->process->pid;
    case 186:
        return running->pid;
    case 41:
    case 42:
    case 48:
    case 49:
    case 50:
    case 51:
    case 52:
    case 53:
    case 54:
    case 55:
    case 213:
    case 232:
    case 233:
    case 281:
    case 291:
    case 441:
        return ipc_syscall(f);
    case 56:
        return clone_task(f, a, b, c, d, e);
    case 57:
        return fork_task(f);
    case 58:
        return fork_task(f, true);
    case 59:
        return exec_user(a, b, c, f);
    case 60:
        exit_thread(running, (a & 255) << 8);
        return 0;
    case 231:
        exit_task(running, (a & 255) << 8);
        return 0;
    case 61:
        return wait_child(a, b, c, d);
    case 63: {
        char name[6][65]{};
        const char* values[] = {"Axiom64",           "axiom64", "0.1",
                                "C++ x86-64 kernel", "x86_64",  "local"};
        for (unsigned i = 0; i < 6; i++)
            memcpy(name[i], values[i], strlen(values[i]) + 1);
        return copy_result(a, name, sizeof(name));
    }
    case 72: {
        if (record_lock_command(b))
            return io_syscall(*running, *f);
        auto h = fd_handle(a, true);
        if (!h)
            return -9;
        if (b == 0 || b == 1030) {
            if (uint32_t(c) >= running->process->limits.soft(Resource::open_files))
                return -22;
            retain(h);
            int fd = allocate_fd(running, h, c, b == 1030);
            if (fd < 0)
                close_handle(h);
            return fd;
        }
        if (b == 1)
            return running->files->entries[int(a)].cloexec;
        if (b == 2) {
            running->files->entries[int(a)].cloexec = c & 1;
            return 0;
        }
        if (b == 3)
            return file_status_flags(*h);
        if (h->flags & 010000000)
            return -9;
        if (b == 1031 || b == 1032)
            return pipe_fcntl(*h, b, c, running->credentials);
        if (b == 1033 || b == 1034)
            return memfd_fcntl(*h, b, c);
        if (b == 4) {
            uint32_t mask = 06000;
            if (h->pipe)
                mask |= pipe_direct;
            h->flags = (h->flags & ~mask) | (c & mask);
            return 0;
        }
        return -22;
    }
    case 74:
    case 75: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        return h->pipe ? -22 : node_sync(h->node, f->rax == 75);
    }
    case 76: {
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        Node* n = nullptr;
        int error = resolve_path(path, n);
        if (error)
            return error;
        if ((error = node_access(n, 2)))
            return error;
        if ((n->mode & 0170000) == block_device)
            return -22;
        error = node_truncate(n, b);
        if (!error)
            inotify_dentry(n, inotify_modify);
        return error;
    }
    case 77: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        if (!h->node || (h->flags & 3) == 0 || (h->node->mode & 0170000) == block_device)
            return -22;
        int error = node_truncate(h->node, b);
        if (!error)
            inotify_dentry(h->opened_dentry, inotify_modify);
        return error;
    }
    case 79: {
        node_path(running->fs->cwd_node, running->fs->cwd, sizeof(running->fs->cwd));
        if (!running->fs->cwd[0])
            return -2;
        size_t n = strlen(running->fs->cwd) + 1;
        if (b < n)
            return -34;
        return copy_result(a, running->fs->cwd, n) ? -14 : int64_t(n);
    }
    case 80: {
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        Node* n = nullptr;
        int error = resolve_path(path, n);
        if (error)
            return error;
        if ((n->mode & 0170000) != directory)
            return -20;
        if ((error = node_access(n, 1)))
            return error;
        auto previous = running->fs->cwd_node;
        running->fs->cwd_node = n;
        node_reference_released(previous);
        inotify_reap_inodes();
        node_path(n, running->fs->cwd, sizeof(running->fs->cwd));
        return 0;
    }
    case 81: {
        auto h = fd_handle(a, true);
        if (!h)
            return -9;
        if (!h->node || (h->node->mode & 0170000) != directory)
            return -20;
        int error = node_access(h->node, 1);
        if (error)
            return error;
        auto previous = running->fs->cwd_node;
        running->fs->cwd_node = h->node;
        node_reference_released(previous);
        inotify_reap_inodes();
        node_path(h->node, running->fs->cwd, sizeof(running->fs->cwd));
        return 0;
    }
    case 83:
    case 258: {
        Path path;
        if (!path_at(f->rax == 83 ? -100 : int(a), f->rax == 83 ? a : b, path))
            return path.error;
        Node* node = nullptr;
        return create_node(
            path, directory | (((f->rax == 83 ? b : c) & 07777) & ~running->fs->umask), node);
    }
    case 85:
        return open_file(-100, a, 01000 | 0100 | 1, b);
    case 86:
    case 265: {
        Path old_path, new_path;
        if (f->rax == 265 && (e & ~0x400ull))
            return -22;
        if (!path_at(f->rax == 86 ? -100 : int(a), f->rax == 86 ? a : b, old_path))
            return old_path.error;
        if (!path_at(f->rax == 86 ? -100 : int(c), f->rax == 86 ? b : d, new_path))
            return new_path.error;
        return link_node(old_path, new_path, f->rax == 265 && (e & 0x400));
    }
    case 82:
    case 264:
    case 316: {
        uint32_t flags = f->rax == 316 ? uint32_t(e) : 0;
        if ((flags & ~7u) || ((flags & 2) && (flags & 5)))
            return -22;
        if (flags & ~1u)
            return -95;
        Path old_path, new_path;
        if (!path_at(f->rax == 82 ? -100 : int(a), f->rax == 82 ? a : b, old_path))
            return old_path.error;
        if (!path_at(f->rax == 82 ? -100 : int(c), f->rax == 82 ? b : d, new_path))
            return new_path.error;
        return rename_node(old_path, new_path, flags & 1);
    }
    case 84:
    case 87:
    case 263: {
        if (f->rax == 263 && (c & ~0x200ull))
            return -22;
        Path path;
        if (!path_at(f->rax == 263 ? int(a) : -100, f->rax == 263 ? b : a, path))
            return path.error;
        return remove_node(path, f->rax == 84 || (f->rax == 263 && (c & 0x200)));
    }
    case 88:
    case 266: {
        char target[1024];
        if (!running->memory->space.string(a, target, sizeof(target)))
            return -14;
        Path path;
        if (!path_at(f->rax == 88 ? -100 : int(b), f->rax == 88 ? b : c, path))
            return path.error;
        Node* node = nullptr;
        return create_node(path, symlink | 0777, node, target);
    }
    case 89:
        return readlink_path(-100, a, b, c);
    case 267:
        return readlink_path(a, b, c, d);
    case 90:
    case 268: {
        Path path;
        if (!path_at(f->rax == 90 ? -100 : int(a), f->rax == 90 ? a : b, path))
            return path.error;
        Node* node = nullptr;
        int error = resolve_path(path, node);
        if (error)
            return error;
        uint32_t mode = f->rax == 90 ? b : c;
        return node_chmod(node, mode);
    }
    case 91: {
        auto h = fd_handle(a);
        if (!h)
            return -9;
        Node* node;
        int error = descriptor_inode(*h, node);
        return error ? error : node_chmod(h->opened_dentry ? h->opened_dentry : node, b);
    }
    case 95: {
        uint32_t old = running->fs->umask;
        running->fs->umask = a & 0777;
        return old;
    }
    case 92:
    case 93:
    case 94: {
        if (f->rax == 93) {
            auto h = fd_handle(a);
            if (!h)
                return -9;
            Node* node;
            int error = descriptor_inode(*h, node);
            return error ? error : node_chown(h->opened_dentry ? h->opened_dentry : node, b, c);
        }
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        Node* node = nullptr;
        int error = resolve_path(path, node, f->rax == 92);
        return error ? error : node_chown(node, b, c);
    }
    case 260: {
        if (e & ~uint64_t(0x100 | 0x1000))
            return -22;
        Node* node = nullptr;
        int error = path_node_at(a, b, e, node);
        return error ? error : node_chown(node, c, d);
    }
    case 96: {
        uint64_t now = clock_realtime_ticks();
        uint64_t time[] = {now / 100, (now % 100) * 10000};
        if (a && copy_result(a, time, sizeof(time)))
            return -14;
        const auto timezone = clock_timezone();
        return b ? copy_result(b, &timezone, sizeof(timezone)) : 0;
    }
    case 97:
    case 160:
    case 302:
        return resource_syscall(f);
    case 98:
        return resource_usage_syscall(int32_t(a), b);
    case 99:
        return system_information_syscall(a);
    case 101: {
        if (!a)
            return -38;
        Task* target = nullptr;
        for (auto& task : tasks)
            if (task.state != State::empty && task.state != State::zombie && task.pid == int(b))
                target = &task;
        if (!target)
            return -3;
        const auto& from = running->credentials;
        const auto& to = target->credentials;
        if (target->process != running->process && !capable(from, Capability::sys_ptrace) &&
            (from.user.real != to.user.real || from.user.real != to.user.effective ||
             from.user.real != to.user.saved || from.group.real != to.group.real ||
             from.group.real != to.group.effective || from.group.real != to.group.saved ||
             !target->memory->dumpable || (to.permitted & ~from.permitted)))
            return -1;
        return -38; // Tracing requests remain unimplemented; permissions precede any future access.
    }
    case 102:
    case 104:
    case 107:
    case 108:
    case 105:
    case 106:
    case 113:
    case 114:
    case 117:
    case 119:
    case 118:
    case 120:
    case 122:
    case 123:
    case 115:
    case 116:
    case 125:
    case 126:
    case 157:
        return credential_syscall(f);
    case 109: {
        if (int32_t(b) < 0)
            return -22;
        Task* target = nullptr;
        for (auto& t : tasks)
            if (t.state != State::empty && t.process->leader == &t &&
                t.process->pid == int(a ? a : running->process->pid))
                target = &t;
        if (!target)
            return -3;
        auto process = target->process;
        if (process != running->process) {
            if (process->parent != running->process->pid)
                return -3;
            if (process->sid != running->process->sid)
                return -1;
            if (process->executed)
                return -13;
        }
        if (process->sid == process->pid)
            return -1;
        int group = b ? b : process->pid;
        if (group != process->pid) {
            bool found = false;
            for (const auto& task : tasks)
                if (task.state != State::empty && task.process->pgid == group &&
                    task.process->sid == running->process->sid)
                    found = true;
            if (!found)
                return -1;
        }
        process->pgid = group;
        return 0;
    }
    case 110:
        return running->process->parent;
    case 111:
        return running->process->pgid;
    case 112:
        if (running->process->pgid == running->process->pid)
            return -1;
        running->process->sid = running->process->pgid = running->process->pid;
        running->process->controlling_pty = nullptr;
        running->process->controlling_console = false;
        return running->process->pid;
    case 124:
        for (auto& t : tasks)
            if (t.state != State::empty && t.process->leader == &t &&
                t.process->pid == int(a ? a : running->process->pid))
                return t.process->sid;
        return -3;
    case 121:
        for (auto& t : tasks)
            if (t.state != State::empty && t.process->leader == &t &&
                t.process->pid == int(a ? a : running->process->pid))
                return t.process->pgid;
        return -3;
    case 158: {
        constexpr uint64_t set_gs = 0x1001, set_fs = 0x1002, get_fs = 0x1003, get_gs = 0x1004;
        if (a == set_fs || a == set_gs) {
            if (b >= user_limit)
                return -1;
            (a == set_fs ? running->fs_base : running->gs_base) = b;
            arch_task(running->fs_base, running->gs_base);
            return 0;
        }
        if (a == get_fs || a == get_gs)
            return copy_result(b, a == get_fs ? &running->fs_base : &running->gs_base,
                               sizeof(uint64_t));
        return -22;
    }
    case 142:
    case 143:
    case 145:
        return scheduler_parameter(f->rax, int32_t(a), 0, b);
    case 144:
        return scheduler_parameter(f->rax, int32_t(a), int32_t(b), c);
    case 146:
    case 147:
        return priority_limit(int32_t(a), f->rax == 146);
    case 169:
        if (!capable(running->credentials, Capability::sys_boot))
            return -1;
        if (a != 0xfee1dead || b != 672274793 || c != 0x4321fedc)
            return -22;
        poweroff(0);
    case 202:
        return futex_syscall(f);
    case 201: {
        int64_t seconds = clock_realtime_ticks() / 100;
        if (a && copy_result(a, &seconds, sizeof(seconds)))
            return -14;
        return seconds;
    }
    case 204: {
        uint64_t mask[(max_boot_processors + 63) / 64]{};
        const unsigned count = scheduler_cpu_count();
        const unsigned bytes = ((count + 63) / 64) * sizeof(mask[0]);
        if (b < bytes)
            return -22;
        for (unsigned cpu = 0; cpu < count; ++cpu)
            mask[cpu / 64] |= 1ull << (cpu % 64);
        return copy_result(c, mask, bytes) ? -14 : bytes;
    }
    case 309: {
        const uint32_t cpu = scheduler_cpu_number(), node = 0;
        return (a && copy_result(a, &cpu, sizeof(cpu))) ||
                       (b && copy_result(b, &node, sizeof(node)))
                   ? -14
                   : 0;
    }
    case 217: {
        int64_t result = getdents(a, b, c);
        if (result >= 0)
            inotify_dentry(fd_handle(a)->opened_dentry, inotify_access);
        return result;
    }
    case 218:
        running->tid_address = a;
        return running->pid;
    case 164:
        return linux_settimeofday(*running, a, b);
    case 227:
        return linux_clock_settime(*running, int32_t(a), b);
    case 228: {
        if (a > 7)
            return -22;
        if (a == 1 || a == 4 || a == 7) {
            uint64_t now = clock_monotonic_ns();
            Timespec ts{int64_t(now / 1000000000), int64_t(now % 1000000000)};
            return copy_result(b, &ts, sizeof(ts));
        }
        uint64_t now = a == 2 || a == 3   ? cpu_ticks(*running, a == 3)
                       : a == 0 || a == 5 ? clock_realtime_ticks()
                                          : ticks;
        Timespec ts{int64_t(now / 100), int64_t(now % 100) * 10000000};
        return copy_result(b, &ts, sizeof(ts));
    }
    case 229: {
        if (a > 7)
            return -22;
        Timespec ts{0, a == 1 || a == 4 || a == 7 ? int64_t(clock_monotonic_resolution_ns())
                                                  : 10000000};
        return b ? copy_result(b, &ts, sizeof(ts)) : 0;
    }
    case 230:
        return linux_clock_nanosleep(*running, int32_t(a), int32_t(b), c, d);
    case 137: {
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        Node* node = nullptr;
        int error = resolve_path(path, node);
        return error ? error : statfs_node(node, b);
    }
    case 138: {
        auto h = fd_handle(a, true);
        if (!h)
            return -9;
        Node* node;
        int error = descriptor_inode(*h, node);
        return error ? error : statfs_node(node, b);
    }
    case 162:
        return sync_filesystems();
    case 165: {
        Path path;
        if (!path_at(-100, b, path))
            return path.error;
        char type[64]{};
        if (c && !running->memory->space.string(c, type, sizeof(type)))
            return -14;
        bool check_dirty = false;
        char options[1024]{};
        if (e) {
            if (!running->memory->space.string(e, options, sizeof(options)))
                return -14;
            if (options[0] && strcmp(type, "tmpfs")) {
                if (!ext_volume_type(type) || (d & 32) || strcmp(options, "recovery=check"))
                    return -22;
                check_dirty = true;
            }
        }
        Path source;
        if (!(d & 32) && ext_volume_type(type) && !path_at(-100, a, source))
            return source.error;
        return mount_filesystem(path, source, type, d, check_dirty, options);
    }
    case 166: {
        Path path;
        if (!path_at(-100, a, path))
            return path.error;
        return unmount(path, b);
    }
    case 247: {
        int selected;
        int error =
            wait_information_selector(*running, unsigned(a), uint32_t(b), unsigned(d), selected);
        if (error)
            return error;
        int64_t result = wait_information(*running, unsigned(a), selected, c, unsigned(d), e);
        return result == would_block ? block(Wait::child, -1, selected) : result;
    }
    case 133:
        return make_special_node(-100, a, b);
    case 257:
        return open_file(a, b, c, d);
    case 259:
        return make_special_node(a, b, c);
    case 262: {
        Node* node = nullptr;
        int error = stat_at_node(a, b, d, node);
        return error ? error : stat_node(node, c);
    }
    case 436:
        return close_task_descriptors(*running, unsigned(a), unsigned(b), unsigned(c));
    case 269:
    case 439: {
        return access_file(a, b, c, f->rax == 439 ? d : 0);
    }
    case 161: {
        if (!capable(running->credentials, Capability::sys_chroot))
            return -1;
        Node* node = nullptr;
        int error = path_node_at(-100, a, 0, node);
        if (error)
            return error;
        if ((node->mode & 0170000) != directory)
            return -20;
        if ((error = node_access(node, 1)))
            return error;
        auto previous = running->fs->root_node;
        running->fs->root_node = node;
        node_reference_released(previous);
        inotify_reap_inodes();
        return 0;
    }
    case 273:
        return -38;
    case 280: {
        if (d & ~uint64_t(0x100))
            return -22;
        Node* node;
        if (b) {
            Path path;
            if (!path_at(a, b, path))
                return path.error;
            int error = resolve_path(path, node, !(d & 0x100));
            if (error)
                return error;
        } else {
            auto h = fd_handle(a);
            if (!h || !h->node)
                return -9;
            node = h->opened_dentry ? h->opened_dentry : h->node;
        }
        auto dentry = node;
        node = file_node(node);
        Timestamp update[] = {node->atime, node->mtime};
        Timespec input[2];
        if (c && !running->memory->space.copy_in(input, c, sizeof(input)))
            return -14;
        unsigned changed = 0;
        for (unsigned i = 0; i < 2; i++) {
            if (c && input[i].nsec == 1073741822)
                continue;
            changed |= 1u << i;
            if (!c || input[i].nsec == 1073741823)
                update[i] = node_now();
            else {
                if (input[i].nsec < 0 || input[i].nsec >= 1000000000)
                    return -22;
                update[i] = {input[i].sec, uint64_t(input[i].nsec)};
            }
        }
        if (changed && running->credentials.user.filesystem != node->uid &&
            !capable(running->credentials, Capability::fowner)) {
            bool now = !c || (input[0].nsec == 1073741823 && input[1].nsec == 1073741823);
            if (!now)
                return -1;
            int error = node_access(node, 2);
            if (error)
                return error;
        }
        uint32_t events = changed == 3   ? inotify_attrib
                          : changed == 1 ? inotify_access
                                         : inotify_modify;
        return changed ? node_setattr(dentry, node->mode, update[0], update[1], events) : 0;
    }
    case 282:
    case 289:
        return signalfd_syscall(*f);
    case 285: {
        auto h = fd_handle(a);
        return h ? allocate_file_range(*running, *h, b, c, d) : -9;
    }
    case 283:
    case 286:
    case 287:
        return timerfd_syscall(*f);
    case 284:
    case 290:
        return eventfd_syscall(*f);
    case 292:
        if (a == b || (c & ~02000000))
            return -22;
        return dup_fd(a, b, c);
    case 293:
        return create_pipe(a, b);
    case 317:
        return seccomp_syscall(*running, uint32_t(a), uint32_t(b), c);
    case 253:
    case 254:
    case 255:
    case 294:
        return inotify_call(*f);
    case 318: {
        unsigned flags = c;
        if ((flags & ~7u) || (flags & 6u) == 6u)
            return -22;
        if (!random_ready() && !(flags & 4u))
            return flags & 1u ? -11 : block(Wait::random);
        uint64_t length = min(b, uint64_t(0x7ffff000)); // Linux MAX_RW_COUNT.
        if (a >= user_limit || length > user_limit - a)
            return -14;
        // Small ready reads complete atomically. Large reads may return a short result.
        if (b > 256 && signal_wakes(*running))
            return -4;
        uint8_t bytes[256];
        size_t done = 0;
        size_t wanted = min(size_t(length), size_t(4096));
        while (done < wanted) {
            size_t n = min(wanted - done, sizeof(bytes));
            if (!running->memory->space.valid(a + done, n, true))
                return done ? int64_t(done) : -14;
            int error = random_read(bytes, n, flags & 4u);
            if (error)
                return done ? int64_t(done) : error;
            bool copied = running->memory->space.copy_out(a + done, bytes, n);
            random::erase(bytes, sizeof(bytes));
            if (!copied)
                return done ? int64_t(done) : -14;
            done += n;
        }
        return done;
    }
    case 319:
        return memfd_create(*running, a, b);
    case 322:
        return execveat_user(*f);
    case 324:
        return memory_barrier(*running->memory, uint32_t(a), uint32_t(b));
    case 326:
        return io_syscall(*running, *f);
    case 332:
        return statx_at(a, b, c, d, e);
    default:
        log("unimplemented syscall %u pid=%u\n", f->rax, uint64_t(running->pid));
        return -38;
    }
}

} // namespace ax
