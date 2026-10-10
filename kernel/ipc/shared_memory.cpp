// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/ipc.hpp"

namespace ax {
struct Segment {
    int id, key, creator, last_pid;
    uint64_t physical, size, created, attached, detached;
    unsigned attachments, mode;
    bool removed;
    uint32_t uid = 0, gid = 0, cuid = 0, cgid = 0;
};

static Segment segments[64];
static int next_id = 1;

static int access(const Segment& segment, unsigned requested) {
    const auto& cred = current->credentials;
    unsigned allowed = segment.mode;
    if (cred.user.effective == segment.uid || cred.user.effective == segment.cuid)
        allowed >>= 6;
    else if (credential_group(cred, segment.gid) || credential_group(cred, segment.cgid))
        allowed >>= 3;
    return (requested & ~allowed & 7) && !capable(cred, Capability::ipc_owner) ? -13 : 0;
}

static bool controls(const Segment& segment) {
    const auto& cred = current->credentials;
    return cred.user.effective == segment.uid || cred.user.effective == segment.cuid ||
           capable(cred, Capability::sys_admin);
}

static Segment* find(int id) {
    if (id <= 0)
        return nullptr;
    for (auto& segment : segments)
        if (segment.id == id)
            return &segment;
    return nullptr;
}

static void collect(Segment* segment) {
    if (segment && segment->removed && !segment->attachments) {
        page_free(segment->physical, align_up(segment->size) / page_size);
        *segment = {};
    }
}

void shared_memory_fork(Task* child, const Task* parent) {
    if (child->memory == parent->memory)
        return;
    memcpy(child->memory->shared, parent->memory->shared, sizeof(child->memory->shared));
    for (auto& attachment : child->memory->shared)
        if (attachment.id) {
            auto segment = find(attachment.id);
            if (segment)
                segment->attachments++;
        }
}

void shared_memory_release(Task* task) {
    for (auto& attachment : task->memory->shared)
        if (attachment.id) {
            auto segment = find(attachment.id);
            if (segment) {
                segment->attachments--;
                segment->detached = ticks / 100;
                segment->last_pid = task->process->pid;
                collect(segment);
            }
            attachment = {};
        }
}

struct Permission {
    int32_t key;
    uint32_t uid, gid, cuid, cgid, mode, sequence, pad;
    uint64_t reserved[2];
};

struct Shmid {
    Permission permission;
    uint64_t size, atime, dtime, ctime;
    int32_t creator, last_pid;
    uint64_t attachments, reserved[2];
};

static_assert(sizeof(Permission) == 48 && sizeof(Shmid) == 112);

int64_t shared_memory_syscall(Frame* f) {
    uint64_t a = f->rdi, b = f->rsi, c = f->rdx;
    if (f->rax == 29) {
        for (auto& segment : segments)
            if (segment.id && !segment.removed && a && segment.key == int(a)) {
                if ((c & 0x600) == 0x600)
                    return -17;
                if (b > segment.size)
                    return -22;
                int error = access(segment, (c >> 6) | (c >> 3) | c);
                if (error)
                    return error;
                return segment.id;
            }
        if (a && !(c & 0x200))
            return -2;
        if (!b || b > 64 * 1024 * 1024)
            return -22;
        for (auto& segment : segments)
            if (!segment.id) {
                uint64_t address = page_alloc(align_up(b) / page_size);
                if (!address)
                    return -12;
                segment = {next_id++, int(a), current->process->pid, current->process->pid,
                           address,   b,      ticks / 100,           0,
                           0,         0,      unsigned(c & 0777),    false};
                segment.uid = segment.cuid = current->credentials.user.effective;
                segment.gid = segment.cgid = current->credentials.group.effective;
                return segment.id;
            }
        return -28;
    }
    if (f->rax == 30) {
        auto segment = find(a);
        if (!segment)
            return -22;
        int error = access(*segment, ((c & 0x1000) ? 4 : 6) | ((c & 0x8000) ? 1 : 0));
        if (error)
            return error;
        uint64_t base = b;
        if (c & 0x2000)
            base = align_down(base);
        if (base % page_size)
            return -22;
        SharedAttachment* record = nullptr;
        for (auto& item : current->memory->shared)
            if (!item.id) {
                record = &item;
                break;
            }
        if (!record)
            return -24;
        size_t length = align_up(segment->size);
        if (!base) {
            base = current->memory->space.next_map;
            current->memory->space.next_map += length + page_size;
        }
        if (base < page_size || base >= user_limit || length > user_limit - base)
            return -22;
        for (uint64_t page = base; page < base + length; page += page_size) {
            auto entry = current->memory->space.entry(page);
            if (entry && (*entry & page_mask))
                return -22;
        }
        if (!current->memory->space.map_physical(base, segment->physical, length,
                                                 (c & 0x1000) ? 1 : 3))
            return -12;
        *record = {segment->id, base, length};
        segment->attachments++;
        segment->attached = ticks / 100;
        segment->last_pid = current->process->pid;
        return base;
    }
    if (f->rax == 67) {
        for (auto& record : current->memory->shared)
            if (record.id && record.base == a) {
                auto segment = find(record.id);
                current->memory->space.unmap(record.base, record.length);
                record = {};
                if (segment) {
                    segment->attachments--;
                    segment->detached = ticks / 100;
                    segment->last_pid = current->process->pid;
                    collect(segment);
                }
                return 0;
            }
        return -22;
    }
    if (f->rax == 31) {
        auto segment = find(a);
        if (!segment)
            return -22;
        unsigned command = b & 0xff;
        if (command == 0) {
            if (!controls(*segment))
                return -1;
            segment->removed = true;
            collect(segment);
            return 0;
        }
        if (command == 2) {
            int error = access(*segment, 4);
            if (error)
                return error;
            Shmid info{};
            info.permission.key = segment->key;
            info.permission.uid = segment->uid;
            info.permission.gid = segment->gid;
            info.permission.cuid = segment->cuid;
            info.permission.cgid = segment->cgid;
            info.permission.mode = segment->mode | (segment->removed ? 0x200 : 0);
            info.size = segment->size;
            info.atime = segment->attached;
            info.dtime = segment->detached;
            info.ctime = segment->created;
            info.creator = segment->creator;
            info.last_pid = segment->last_pid;
            info.attachments = segment->attachments;
            return current->memory->space.copy_out(c, &info, sizeof(info)) ? 0 : -14;
        }
        if (command == 1) {
            if (!controls(*segment))
                return -1;
            Shmid info;
            if (!current->memory->space.copy_in(&info, c, sizeof(info)))
                return -14;
            if (info.permission.uid == UINT32_MAX || info.permission.gid == UINT32_MAX)
                return -22;
            segment->uid = info.permission.uid;
            segment->gid = info.permission.gid;
            segment->mode = info.permission.mode & 0777;
            segment->created = ticks / 100;
            return 0;
        }
        return -22;
    }
    return -38;
}
} // namespace ax
