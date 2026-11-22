// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/shared_memory.cpp
 * @brief   System V shared memory.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Tracks segment IDs, attachments, permissions, and removal across process
 * lifetimes.
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
#include "ipc/shared_memory.hpp"
#include "ipc/system_v_permissions.hpp"
#include "core/time.hpp"
#include "mm/file_mapping.hpp"
#include "mm/limits.hpp"

namespace ax {
namespace {
constexpr unsigned max_segments = 4096, slot_mask = 32767;
constexpr size_t max_segment_size = 64 * 1024 * 1024;
constexpr uint64_t max_segment_pages = max_segments * (max_segment_size / page_size);
constexpr unsigned ipc_create = 01000, ipc_exclusive = 02000;
constexpr unsigned shm_readonly = 010000, shm_round = 020000, shm_remap = 040000,
                   shm_exec = 0100000, shm_hugetlb = 04000;
constexpr unsigned marked_for_removal = 01000, locked = 02000;

struct Status {
    SystemVPermission permission;
    uint64_t size, attached, detached, changed;
    int32_t creator_pid, last_pid;
    uint64_t mappings, reserved[2];
};

static_assert(sizeof(Status) == 112 && offsetof(Status, mappings) == 88);

struct Segment {
    Status status;
    uint64_t physical;
    uint32_t lock_uid;
};

// Each shmat creates a distinct identity. Forked and split mappings share it.
struct Attachment {
    Segment* segment;
    uint64_t origin;
    unsigned references;
};
} // namespace

struct SharedMemoryMapping {
    Attachment* attachment;
    SharedMemoryMapping* next;
    uint64_t start, end;
    int protection;
};

namespace {
static Segment segments[max_segments];
static uint16_t generations[max_segments];
static unsigned live_segments;
static uint64_t total_pages;

uint64_t now() {
    return clock_realtime_ticks() / 100;
}

int id_for(unsigned slot) {
    return (unsigned(generations[slot]) << 15) | slot;
}

Segment* find(int id) {
    unsigned slot = unsigned(id) & slot_mask;
    return id >= 0 && slot < max_segments && id == id_for(slot) && segments[slot].physical
               ? &segments[slot]
               : nullptr;
}

void collect(Segment& segment) {
    if (!(segment.status.permission.mode & marked_for_removal) || segment.status.mappings)
        return;
    size_t pages = align_up(segment.status.size) / page_size;
    page_free(segment.physical, pages);
    total_pages -= pages;
    --live_segments;
    ++generations[&segment - segments];
    segment = {};
}

void note_attachment(Segment& segment, int pid) {
    segment.status.attached = now();
    segment.status.last_pid = pid;
}

void retain_mapping(Attachment& attachment, int pid) {
    ++attachment.references;
    ++attachment.segment->status.mappings;
    note_attachment(*attachment.segment, pid);
}

void release_mapping(SharedMemoryMapping* mapping, int pid) {
    auto& attachment = *mapping->attachment;
    auto& segment = *attachment.segment;
    segment.status.detached = now();
    segment.status.last_pid = pid;
    --segment.status.mappings;
    if (!--attachment.references)
        release(&attachment);
    release(mapping);
    collect(segment);
}

SharedMemoryMapping* split_mapping(SharedMemoryMapping& mapping, uint64_t cut,
                                   SharedMemoryMapping* suffix, int pid) {
    *suffix = mapping;
    suffix->start = cut;
    mapping.end = cut;
    mapping.next = suffix;
    retain_mapping(*mapping.attachment, pid);
    return suffix;
}

int open_segment(int key, uint64_t size, unsigned flags) {
    unsigned empty = max_segments;
    for (unsigned slot = 0; slot < max_segments; ++slot) {
        const auto& segment = segments[slot];
        if (!segment.physical) {
            if (empty == max_segments)
                empty = slot;
            if (!key)
                break;
            continue;
        }
        const auto& status = segment.status;
        if (!key || status.permission.key != key)
            continue;
        if ((flags & (ipc_create | ipc_exclusive)) == (ipc_create | ipc_exclusive))
            return -17;
        if (!status.permission.allows(current_task()->credentials, flags | flags >> 3 | flags >> 6))
            return -13;
        return size <= status.size ? id_for(slot) : -22;
    }
    if (key && !(flags & ipc_create))
        return -2;
    if (!size || size > max_segment_size)
        return -22;
    if (flags & shm_hugetlb)
        return -95;
    if (empty == max_segments)
        return -28;
    size_t pages = align_up(size) / page_size;
    auto physical_base = page_alloc(pages);
    if (!physical_base)
        return -12;
    page_account_shared(physical_base, pages);
    auto& segment = segments[empty];
    auto& status = segment.status;
    segment.physical = physical_base;
    const auto& credentials = current_task()->credentials;
    auto& permission = status.permission;
    permission.key = key;
    permission.uid = permission.creator_uid = credentials.user.effective;
    permission.gid = permission.creator_gid = credentials.group.effective;
    permission.mode = flags & 0777;
    permission.sequence = generations[empty];
    status.size = size;
    status.creator_pid = current_task()->process->pid;
    status.changed = now();
    ++live_segments;
    total_pages += pages;
    return id_for(empty);
}

int64_t attach(int id, uint64_t base, unsigned flags) {
    bool replace = flags & shm_remap;
    if (flags & shm_round)
        base = align_down(base);
    if (base % page_size || (replace && !base))
        return -22;
    auto* segment = find(id);
    if (!segment)
        return -22;
    int protection = (flags & shm_readonly ? 1 : 3) | (flags & shm_exec ? 4 : 0);
    unsigned access = 4 | (protection & 2) | (protection & 4 ? 1 : 0);
    if (!segment->status.permission.allows(current_task()->credentials, access))
        return -13;
    auto& memory = *current_task()->memory;
    size_t length = align_up(segment->status.size);
    bool automatic = !base;
    if (automatic) {
        base = memory.space.find_unmapped(length);
        if (!base)
            return -12;
    }
    if (base < page_size || base >= user_limit || length > user_limit - base ||
        (!replace && memory.space.mapped_size(base, length)))
        return -22;
    if (!memory_growth_allowed(*current_task(), base, length, replace))
        return -12;
    auto* identity = static_cast<Attachment*>(alloc(sizeof(Attachment)));
    auto* mapping = static_cast<SharedMemoryMapping*>(alloc(sizeof(SharedMemoryMapping)));
    if (!identity || !mapping || !memory.space.prepare_mapping(base, length)) {
        release(identity);
        release(mapping);
        return -12;
    }
    // A remap of the last fragment of a removed segment still owns its backing.
    ++segment->status.mappings;
    int error = replace ? shared_memory_unmap(*current_task(), base, length) : 0;
    if (error || !memory.space.map_physical(base, segment->physical, length, protection)) {
        --segment->status.mappings;
        collect(*segment);
        release(identity);
        release(mapping);
        return error ? error : -12;
    }
    if (flags & shm_readonly)
        for (uint64_t page = base; page < base + length; page += page_size)
            *memory.space.entry(page) |= 0x800; // Read-only attachment cannot gain write access.
    if (automatic)
        memory.space.next_map = base + length + page_size;
    auto** link = &memory.shared;
    while (*link && (*link)->start < base)
        link = &(*link)->next;
    *identity = {segment, base, 1};
    *mapping = {identity, *link, base, base + length, protection};
    *link = mapping;
    note_attachment(*segment, current_task()->process->pid);
    return base;
}

int detach(uint64_t base) {
    auto& memory = *current_task()->memory;
    auto** link = &memory.shared;
    while (*link && (*link)->attachment->origin != base)
        link = &(*link)->next;
    if (!*link)
        return -22;
    auto* identity = (*link)->attachment;
    unsigned remaining = 0;
    for (auto* mapping = *link; mapping; mapping = mapping->next)
        remaining += mapping->attachment == identity;
    // File identity distinguishes an older surviving fragment from a new shmat
    // that used the same original address with SHM_REMAP.
    while (remaining) {
        auto* mapping = *link;
        if (mapping->attachment != identity) {
            link = &mapping->next;
            continue;
        }
        *link = mapping->next;
        memory.space.unmap(mapping->start, mapping->end - mapping->start);
        release_mapping(mapping, current_task()->process->pid);
        --remaining;
    }
    return 0;
}

int segment_info(int command, uint64_t pointer) {
    auto& memory = current_task()->memory->space;
    if (command == 3) {
        const uint64_t limits[9] = {max_segment_size, 1, max_segments, max_segments,
                                    max_segment_pages};
        if (!memory.copy_out(pointer, limits, sizeof(limits)))
            return -14;
    } else {
        const uint64_t usage[6] = {live_segments, total_pages, total_pages};
        if (!memory.copy_out(pointer, usage, sizeof(usage)))
            return -14;
    }
    for (unsigned slot = max_segments; slot > 0; --slot)
        if (segments[slot - 1].physical)
            return slot - 1;
    return 0;
}

int lock_segment(Segment& segment, bool lock) {
    auto& permission = segment.status.permission;
    const auto& creds = current_task()->credentials;
    bool privileged = capable(creds, Capability::ipc_lock);
    uint64_t limit = current_task()->process->limits.soft(Resource::locked_memory);
    if (!privileged && ((creds.user.effective != permission.uid &&
                         creds.user.effective != permission.creator_uid) ||
                        (lock && !limit)))
        return -1;
    if (!lock) {
        permission.mode &= ~locked;
        return 0;
    }
    if (permission.mode & locked)
        return 0;
    uint32_t uid = creds.user.real;
    if (!privileged) {
        uint64_t charge = align_up(segment.status.size);
        for (const auto& candidate : segments)
            if ((candidate.status.permission.mode & locked) && candidate.lock_uid == uid)
                charge += align_up(candidate.status.size);
        if (charge > align_down(limit))
            return -12;
    }
    segment.lock_uid = uid;
    permission.mode |= locked;
    return 0;
}

int control(int id, int command, uint64_t pointer) {
    if (id < 0)
        return -22;
    if (command == 3 || command == 14)
        return segment_info(command, pointer);
    auto& memory = current_task()->memory->space;
    Status input;
    if (command == 1 && !memory.copy_in(&input, pointer, sizeof(input)))
        return -14;
    bool by_slot = command == 13 || command == 15;
    auto* segment = by_slot ? (unsigned(id) < max_segments ? &segments[id] : nullptr) : find(id);
    if (!segment || !segment->physical)
        return -22;
    auto& status = segment->status;
    const auto& creds = current_task()->credentials;
    if (command == 0 || command == 1) {
        if (!status.permission.controls(creds))
            return -1;
        if (command == 0) {
            status.permission.key = 0;
            status.permission.mode |= marked_for_removal;
            collect(*segment);
            return 0;
        }
        if (input.permission.uid == UINT32_MAX || input.permission.gid == UINT32_MAX)
            return -22;
        status.permission.uid = input.permission.uid;
        status.permission.gid = input.permission.gid;
        status.permission.mode = (status.permission.mode & ~0777u) | (input.permission.mode & 0777);
        status.changed = now();
        return 0;
    }
    if (command == 11 || command == 12)
        return lock_segment(*segment, command == 11);
    if (command != 2 && !by_slot)
        return -22;
    if (command != 15 && !status.permission.allows(creds, 4))
        return -13;
    return memory.copy_out(pointer, &status, sizeof(status)) ? (by_slot ? id_for(id) : 0) : -14;
}
} // namespace

bool shared_memory_fork(Task& child, const Task& parent) {
    auto** tail = &child.memory->shared;
    for (auto* mapping = parent.memory->shared; mapping; mapping = mapping->next) {
        auto* copy = static_cast<SharedMemoryMapping*>(alloc(sizeof(SharedMemoryMapping)));
        if (!copy) {
            while (auto* partial = child.memory->shared) {
                child.memory->shared = partial->next;
                release(partial);
            }
            return false;
        }
        *copy = *mapping;
        copy->next = nullptr;
        *tail = copy;
        tail = &copy->next;
    }
    for (auto* mapping = child.memory->shared; mapping; mapping = mapping->next)
        retain_mapping(*mapping->attachment, parent.process->pid);
    return true;
}

void shared_memory_release(Task& task) {
    while (auto* mapping = task.memory->shared) {
        task.memory->shared = mapping->next;
        release_mapping(mapping, task.process->pid);
    }
}

int shared_memory_unmap(Task& task, uint64_t base, size_t length) {
    if (!length)
        return 0;
    auto& memory = *task.memory;
    uint64_t end = base + length;
    SharedMemoryMapping* suffix = nullptr;
    for (auto* mapping = memory.shared; mapping && mapping->start < end; mapping = mapping->next)
        if (mapping->start < base && end < mapping->end) {
            suffix = static_cast<SharedMemoryMapping*>(alloc(sizeof(SharedMemoryMapping)));
            if (!suffix)
                return -12;
            break;
        }
    if (int error = unmap_file_mappings(memory.space, base, length)) {
        release(suffix);
        return error;
    }
    int pid = task.process->pid;
    auto** link = &memory.shared;
    while (*link && (*link)->start < end) {
        auto* mapping = *link;
        if (mapping->end <= base) {
            link = &mapping->next;
            continue;
        }
        if (base <= mapping->start && mapping->end <= end) {
            *link = mapping->next;
            release_mapping(mapping, pid);
            continue;
        }
        auto& segment = *mapping->attachment->segment;
        if (mapping->start < base && end < mapping->end)
            split_mapping(*mapping, end, suffix, pid);
        else
            note_attachment(segment, pid);
        if (mapping->start < base)
            mapping->end = base;
        else
            mapping->start = end;
        segment.status.detached = now();
        segment.status.last_pid = pid;
        link = &mapping->next;
    }
    return 0;
}

int shared_memory_protect(Task& task, uint64_t base, size_t length, int protection) {
    auto& memory = *task.memory;
    uint64_t end = base + length;
    SharedMemoryMapping* left = nullptr;
    SharedMemoryMapping* right = nullptr;
    protection &= 7;
    for (auto* mapping = memory.shared; mapping && mapping->start < end; mapping = mapping->next) {
        if (mapping->end <= base || mapping->protection == protection)
            continue;
        if (mapping->start < base) {
            left = static_cast<SharedMemoryMapping*>(alloc(sizeof(SharedMemoryMapping)));
            if (!left)
                return -12;
        }
        if (end < mapping->end) {
            right = static_cast<SharedMemoryMapping*>(alloc(sizeof(SharedMemoryMapping)));
            if (!right) {
                release(left);
                return -12;
            }
        }
    }
    if (!memory.space.protect(base, length, protection)) {
        release(left);
        release(right);
        return -12;
    }
    int pid = task.process->pid;
    for (auto* mapping = memory.shared; mapping && mapping->start < end; mapping = mapping->next) {
        if (mapping->end <= base || mapping->protection == protection)
            continue;
        if (mapping->start < base)
            mapping = split_mapping(*mapping, base, left, pid);
        if (end < mapping->end)
            split_mapping(*mapping, end, right, pid);
        mapping->protection = protection;
    }
    return 0;
}

int64_t shared_memory_syscall(Frame* f) {
    switch (f->rax) {
    case 29:
        return open_segment(int32_t(f->rdi), f->rsi, f->rdx);
    case 30:
        return attach(int32_t(f->rdi), f->rsi, f->rdx);
    case 31:
        return control(int32_t(f->rdi), int32_t(f->rsi), f->rdx);
    case 67:
        return detach(f->rdi);
    default:
        return -38;
    }
}
} // namespace ax
