// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/memfd.cpp
 * @brief   Sparse anonymous memory files and file seals.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Owns anonymous file pages, enforces inode seals, and tracks shared and private mappings.
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

#include "fs/memfd.hpp"
#include "mm/tlb_batch.hpp"
#include "mm/file_mapping.hpp"
#include "fs/descriptor.hpp"
#include "fs/inotify.hpp"
#include "fs/vfs.hpp"
#include "ipc/shared_memory.hpp"
#include "process/task.hpp"
#include "process/signals.hpp"

namespace ax {
namespace {
constexpr unsigned seal_seal = 1, seal_shrink = 2, seal_grow = 4, seal_write = 8,
                   seal_future_write = 16, seal_exec = 32;
constexpr unsigned write_seals = seal_write | seal_future_write;
constexpr unsigned all_seals = seal_seal | seal_shrink | seal_grow | write_seals | seal_exec;
constexpr unsigned close_on_exec = 1, allow_sealing = 2, huge_pages = 4, noexec_seal = 8,
                   executable = 16;
constexpr unsigned radix_bits = 9, radix_size = 1 << radix_bits, root_shift = 45;
constexpr uint64_t shared_page = 0x400;
constexpr uint64_t new_preallocation = 1;

struct MemoryFile {
    Node node;
    FileMapping* mappings;
    uint64_t pages;
    unsigned seals;
    unsigned descriptions;
};

MemoryFile& file(Node* node) {
    return *static_cast<MemoryFile*>(node->filesystem_data);
}

uint64_t* data_slot(MemoryFile& memory, uint64_t index, bool create) {
    auto slot = &memory.pages;
    for (unsigned shift = root_shift;; shift -= radix_bits) {
        if (!*slot) {
            if (!create || !(*slot = page_alloc()))
                return nullptr;
        }
        auto children = static_cast<uint64_t*>(physical(*slot));
        slot = &children[(index >> shift) & (radix_size - 1)];
        if (!shift)
            break;
    }
    return slot;
}

uint64_t data_page(MemoryFile& memory, uint64_t index, bool create) {
    auto slot = data_slot(memory, index, create);
    if (!slot)
        return 0;
    if (!*slot && create) {
        *slot = page_alloc();
        if (*slot) {
            page_account_shared(*slot);
            memory.node.allocated_blocks += page_size / 512;
        }
    }
    return *slot & page_mask;
}

// Drop sparse pages in a range and release tables emptied by the cut.
void discard_pages(MemoryFile& memory, uint64_t& table, unsigned shift, uint64_t base,
                   uint64_t first, uint64_t end, bool rollback = false) {
    if (!table || base >= end || base + (uint64_t(radix_size) << shift) <= first)
        return;
    auto children = static_cast<uint64_t*>(physical(table));
    bool empty = true;
    for (unsigned i = 0; i < radix_size; ++i) {
        auto& child = children[i];
        if (!child)
            continue;
        uint64_t start = base + (uint64_t(i) << shift);
        if (shift)
            discard_pages(memory, child, shift - radix_bits, start, first, end, rollback);
        else if (start >= first && start < end && (!rollback || (child & new_preallocation))) {
            page_free(child & page_mask);
            child = 0;
            memory.node.allocated_blocks -= page_size / 512;
        }
        empty &= !child;
    }
    if (empty) {
        page_free(table);
        table = 0;
    }
}

void collect(MemoryFile& memory) {
    if (memory.descriptions || memory.mappings || memory.node.exec_images)
        return;
    discard_pages(memory, memory.pages, root_shift, 0, 0, UINT64_MAX);
    release(&memory);
}

void invalidate_pages(MemoryFile& memory, uint64_t first, uint64_t end, bool keep_private) {
    for (auto map = memory.mappings; map; map = map->file_next) {
        uint64_t start = max(first, map->offset);
        uint64_t stop = min(end, map->offset + map->end - map->start);
        if (start >= stop)
            continue;
        TlbBatch batch(map->space->root);
        for (uint64_t offset = start; offset < stop; offset += page_size) {
            auto pte = map->space->entry(map->start + offset - map->offset);
            if (!pte || !(*pte & page_mask) ||
                (keep_private && !map->shared && !(*pte & page_file_cow)))
                continue;
            const auto page = *pte & page_mask;
            *pte &= ~(page_mask | shared_page | page_file_cow);
            if (!map->shared)
                *pte |= page_file_cow;
            *pte = file_page_permissions(*pte);
            batch.retire(page);
        }
        batch.finish();
    }
}

bool pinned_pages(const MemoryFile& memory, uint64_t table, unsigned shift, uint64_t base) {
    if (!table)
        return false;
    auto children = static_cast<const uint64_t*>(physical(table));
    for (unsigned i = 0; i < radix_size; ++i) {
        uint64_t page = children[i];
        if (!page)
            continue;
        uint64_t index = base + (uint64_t(i) << shift);
        if (shift) {
            if (pinned_pages(memory, page, shift - radix_bits, index))
                return true;
            continue;
        }
        unsigned actual = page_reference_count(page);
        if (actual <= 1)
            continue;
        unsigned accounted = 1;
        uint64_t offset = index * page_size;
        for (auto map = memory.mappings; map; map = map->file_next) {
            if (offset < map->offset || offset - map->offset >= map->end - map->start)
                continue;
            auto pte = map->space->entry(map->start + offset - map->offset);
            accounted += pte && (*pte & page_mask) == page;
        }
        if (actual > accounted)
            return true;
    }
    return false;
}

int truncate(Node* node, size_t size) {
    auto& memory = file(node);
    size_t old = node->size;
    if ((size > old && (memory.seals & seal_grow)) || (size < old && (memory.seals & seal_shrink)))
        return -1;
    if (size < old) {
        if (size % page_size) {
            if (auto page = data_page(memory, size / page_size, false))
                memset(static_cast<uint8_t*>(physical(page)) + size % page_size, 0,
                       page_size - size % page_size);
        }
        uint64_t end = align_up(size);
        invalidate_pages(memory, end, UINT64_MAX, false);
        discard_pages(memory, memory.pages, root_shift, 0, end / page_size, UINT64_MAX);
    }
    node->size = size;
    node->mtime = node->ctime = node_now();
    return 0;
}

int64_t read(Node* node, uint64_t offset, void* output, size_t length) {
    if (offset >= node->size || !length)
        return 0;
    auto& memory = file(node);
    auto bytes = static_cast<uint8_t*>(output);
    size_t count = min(length, node->size - offset);
    for (size_t done = 0; done < count;) {
        size_t start = offset % page_size;
        size_t part = min(count - done, page_size - start);
        auto page = data_page(memory, offset / page_size, false);
        if (page)
            memcpy(bytes + done, static_cast<const uint8_t*>(physical(page)) + start, part);
        else
            memset(bytes + done, 0, part);
        offset += part;
        done += part;
    }
    node->atime = node_now();
    return count;
}

void zero_fragment(MemoryFile& memory, uint64_t start, uint64_t end) {
    if (auto page = data_page(memory, start / page_size, false))
        memset(static_cast<uint8_t*>(physical(page)) + start % page_size, 0, end - start);
}

void punch_hole(MemoryFile& memory, uint64_t start, uint64_t end) {
    uint64_t first = align_up(start), last = align_down(end);
    if (start < first)
        zero_fragment(memory, start, min(first, end));
    if (last < end && last >= first)
        zero_fragment(memory, last, end);
    if (first < last) {
        // A private page that has already copied its contents no longer
        // shares the backing page removed by a hole punch.
        invalidate_pages(memory, first, last, true);
        discard_pages(memory, memory.pages, root_shift, 0, first / page_size, last / page_size);
    }
}

int preallocate(MemoryFile& memory, uint64_t first, uint64_t end) {
    for (uint64_t index = first; index < end; ++index) {
        auto slot = data_slot(memory, index, true);
        if (slot && *slot)
            continue;
        uint64_t page = slot ? page_alloc() : 0;
        if (!page) {
            discard_pages(memory, memory.pages, root_shift, 0, first, index + 1, true);
            return -28;
        }
        page_account_shared(page);
        *slot = page | new_preallocation;
        memory.node.allocated_blocks += page_size / 512;
    }
    for (uint64_t index = first; index < end; ++index)
        *data_slot(memory, index, false) &= ~new_preallocation;
    return 0;
}

int64_t write(Node* node, uint64_t offset, const void* input, size_t length) {
    if (!length)
        return 0;
    if (offset >= INT64_MAX)
        return -27;
    length = min(length, uint64_t(INT64_MAX) - offset);
    if (int error = memfd_write_limit(node, offset, length))
        return error;
    auto& memory = file(node);
    auto bytes = static_cast<const uint8_t*>(input);
    size_t done = 0;
    while (done < length) {
        auto page = data_page(memory, offset / page_size, true);
        if (!page)
            break;
        size_t start = offset % page_size;
        size_t part = min(length - done, page_size - start);
        memcpy(static_cast<uint8_t*>(physical(page)) + start, bytes + done, part);
        done += part;
        offset += part;
    }
    if (!done)
        return -12;
    node->size = max(node->size, offset);
    node->mtime = node->ctime = node_now();
    return done;
}

int setattr(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime, uint32_t uid,
            uint32_t gid) {
    if (((node->mode ^ mode) & 0111) && (file(node).seals & seal_exec))
        return -1;
    node->mode = mode;
    node->atime = atime;
    node->mtime = mtime;
    node->ctime = node_now();
    node->uid = uid;
    node->gid = gid;
    return 0;
}

int sync(Mount*, Node*, bool) {
    return 0;
}

int stats(Mount*, FilesystemStats& result) {
    result = {0x01021994, page_size, 0, 0, 0, 0};
    return 0;
}

const FilesystemOps operations{
    .lookup = nullptr,
    .create = nullptr,
    .link = nullptr,
    .remove = nullptr,
    .rename = nullptr,
    .read = read,
    .write = write,
    .truncate = truncate,
    .setattr = setattr,
    .readdir = nullptr,
    .sync = sync,
    .map_shared = nullptr,
    .stats = stats,
    .destroy = nullptr,
    .remount = nullptr,
    .prepare_unmount = nullptr,
};
Mount mount{0x7fffffff, nullptr, nullptr, nullptr, &operations, nullptr, true, false};
uint64_t next_inode = 1;

} // namespace

bool is_memfd(const Node* node) {
    return node && node->mount == &mount;
}

int64_t memfd_create(Task& task, uint64_t pointer, uint32_t flags) {
    unsigned valid = close_on_exec | allow_sealing | huge_pages | noexec_seal | executable;
    if (flags & huge_pages)
        valid |= 63u << 26;
    if ((flags & ~valid) || (flags & (noexec_seal | executable)) == (noexec_seal | executable))
        return -22;
    char name[256] = "memfd:";
    bool terminated = false;
    for (unsigned i = 6; i < sizeof(name); ++i) {
        if (!task.memory->space.copy_in(&name[i], pointer + i - 6, 1))
            return -14;
        if (!name[i]) {
            terminated = true;
            break;
        }
    }
    if (!terminated)
        return -22;
    if (flags & huge_pages)
        return -38;

    int fd = reserve_fd(task, 0, flags & close_on_exec);
    if (fd < 0)
        return fd;
    auto memory = static_cast<MemoryFile*>(alloc(sizeof(MemoryFile)));
    if (!memory) {
        discard_reserved_fd(*task.files, fd);
        return -12;
    }
    *memory = {};
    memory->seals = flags & noexec_seal ? seal_exec : (flags & allow_sealing ? 0 : seal_seal);
    auto& node = memory->node;
    node.mount = &mount;
    node.filesystem_data = memory;
    node.inode = next_inode++;
    node.mode = regular_file | (flags & noexec_seal ? 0666 : 0777);
    node.uid = task.credentials.user.filesystem;
    node.gid = task.credentials.group.filesystem;
    node.atime = node.mtime = node.ctime = node_now();
    memcpy(node.name, name, sizeof(name));
    int error;
    auto handle = open_handle(&node, 0100002, &error);
    if (!handle) {
        release(memory);
        discard_reserved_fd(*task.files, fd);
        return error;
    }
    handle->opened_dentry = &node;
    install_reserved_fd(*task.files, fd, handle);
    return fd;
}

int64_t memfd_fcntl(Handle& handle, unsigned command, uint32_t requested) {
    if (command == 1033 && (handle.flags & 3) == 0)
        return -1;
    if (!is_memfd(handle.node))
        return -22;
    auto& memory = file(handle.node);
    if (command == 1034)
        return memory.seals;
    if (requested & ~all_seals)
        return -22;
    if (memory.seals & seal_seal)
        return -1;
    if ((requested & seal_exec) && (handle.node->mode & 0111))
        requested |= seal_shrink | seal_grow | write_seals;
    if ((requested & seal_write) && !(memory.seals & seal_write)) {
        for (auto map = memory.mappings; map; map = map->file_next)
            if (map->may_write)
                return -16;
        if (pinned_pages(memory, memory.pages, root_shift, 0))
            return -16;
    }
    memory.seals |= requested;
    return 0;
}

int memfd_fallocate(Task& task, Handle& handle, unsigned mode, uint64_t offset, uint64_t length) {
    constexpr unsigned keep_size = 1, punch = 2;
    if (offset > INT64_MAX || length > INT64_MAX || !length)
        return -22;
    if (mode & ~(keep_size | punch) || mode == punch)
        return -95;
    if (!(handle.flags & 3))
        return -9;
    if (handle.pipe)
        return -29;
    auto node = handle.node;
    unsigned type = node ? node->mode & 0170000 : 0;
    if (type == directory)
        return -21;
    if (type != regular_file && type != block_device)
        return -19;
    if (length > uint64_t(INT64_MAX) - offset)
        return -27;
    if (!is_memfd(node))
        return -95;
    auto& memory = file(node);
    uint64_t end = offset + length;
    if (mode & punch) {
        if (memory.seals & write_seals)
            return -1;
        punch_hole(memory, offset, end);
    } else {
        if (end > node->size && end > task.process->limits.soft(Resource::file_size)) {
            queue_signal(&task, 25, task.process->pid);
            return -27;
        }
        if ((memory.seals & seal_grow) && end > node->size)
            return -1;
        if (end > uint64_t(INT64_MAX) - (page_size - 1))
            return -27;
        if (int error = preallocate(memory, offset / page_size, align_up(end) / page_size))
            return error;
        if (!(mode & keep_size) && end > node->size)
            node->size = end;
    }
    node->mtime = node->ctime = node_now();
    inotify_dentry(handle.opened_dentry, inotify_modify);
    return 0;
}

int memfd_write_limit(const Node* node, uint64_t offset, size_t& length) {
    if (!length || !is_memfd(node))
        return 0;
    unsigned seals = static_cast<const MemoryFile*>(node->filesystem_data)->seals;
    if (seals & write_seals)
        return -1;
    if ((seals & seal_grow) && (offset >= node->size || length > node->size - offset)) {
        // The write can commit whole page fragments preceding the fragment
        // that would grow the inode.
        uint64_t end = align_down(node->size);
        if (offset >= end)
            return -1;
        length = min(length, end - offset);
    }
    return 0;
}

void memfd_open(Node* node) {
    ++file(node).descriptions;
}

void memfd_close(Node* node) {
    auto& memory = file(node);
    --memory.descriptions;
    collect(memory);
}

void memfd_reap(Node* node) {
    if (is_memfd(node))
        collect(file(node));
}

int memfd_map(Task& task, Handle& handle, uint64_t base, size_t length, uint64_t offset, int prot,
              bool shared, bool replace) {
    if (offset > INT64_MAX || length - 1 > uint64_t(INT64_MAX) - offset)
        return -75;
    auto& memory = file(handle.node);
    bool sealed = memory.seals & write_seals;
    if (shared && (prot & 2) && sealed)
        return -1;
    auto space = &task.memory->space;
    auto map = static_cast<FileMapping*>(alloc(sizeof(FileMapping)));
    if (!map || !space->prepare_mapping(base, length)) {
        release(map);
        return -12;
    }
    if (replace) {
        if (int error = shared_memory_unmap(task, base, length)) {
            release(map);
            return error;
        }
    }
    bool may_write = shared && !sealed && (handle.flags & 3) == 2;
    *map = {.space = space,
            .start = base,
            .end = base + length,
            .offset = offset,
            .memory_file = &memory.node,
            .shared = shared,
            .may_write = may_write};
    uint64_t initial = unpopulated_file_page(*map, prot);
    for (uint64_t va = base; va < base + length; va += page_size)
        *space->entry(va) = initial;
    attach_file_mapping(*map);
    return 0;
}

void memfd_link_mapping(FileMapping& mapping) {
    auto& memory = file(mapping.memory_file);
    mapping.file_next = memory.mappings;
    memory.mappings = &mapping;
}

void memfd_unlink_mapping(FileMapping& mapping) {
    auto& memory = file(mapping.memory_file);
    auto link = &memory.mappings;
    while (*link != &mapping)
        link = &(*link)->file_next;
    *link = mapping.file_next;
    collect(memory);
}

bool memfd_page_resident(Node& node, uint64_t offset) {
    return offset < node.size && data_page(file(&node), offset / page_size, false);
}

FileFault memfd_fault(FileMapping& map, uint64_t offset, uint64_t& pte, bool write) {
    uint64_t state = pte;
    auto& memory = file(map.memory_file);
    if (offset >= memory.node.size)
        return FileFault::bus;

    uint64_t old = state & page_mask;
    bool copy = write && (state & page_file_cow);
    if (old && !copy)
        return FileFault::protection;
    auto page = copy ? page_alloc() : data_page(memory, offset / page_size, true);
    if (!page)
        return FileFault::bus;
    if (copy) {
        auto source = old ? old : data_page(memory, offset / page_size, false);
        if (source)
            memcpy(physical(page), physical(source), page_size);
        state &= ~(page_file_cow | shared_page);
    } else {
        page_retain(page);
        state |= shared_page;
    }
    pte = file_page_permissions((state & ~page_mask) | page);
    sync_user_translations(map.space->root, map.start + offset - map.offset);
    if (old)
        page_free(old);
    return FileFault::resolved;
}
} // namespace ax
