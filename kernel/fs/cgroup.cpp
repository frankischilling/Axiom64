/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * @file    kernel/fs/cgroup.cpp
 * @brief   Manage a unified hierarchy of process groups.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Implements the cgroup v2 core membership and population interfaces
 * described by the Linux cgroup v2 ABI.
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "fs/cgroup.hpp"
#include "fs/inotify.hpp"
#include "fs/vfs.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
enum class File : unsigned { processes, threads, controllers, subtree, type, events };
constexpr const char* names[] = {"cgroup.procs",           "cgroup.threads", "cgroup.controllers",
                                 "cgroup.subtree_control", "cgroup.type",    "cgroup.events"};
Mount* hierarchy;

bool writable(File file) {
    return file == File::processes || file == File::threads || file == File::subtree;
}

bool administrator() {
    return !current_task() || capable(current_task()->credentials, Capability::sys_admin);
}

bool is_directory(const Node* node) {
    return (node->mode & 0170000) == directory;
}

bool in_subtree(const Node* node, const Node* ancestor) {
    for (; node; node = node->parent)
        if (node == ancestor)
            return true;
    return false;
}

bool live_process(const Task& member) {
    return member.state != State::empty && member.process && member.process->leader == &member &&
           member.process->live_threads;
}

bool populated(const Node* group, const Process* exclude = nullptr) {
    for (const auto& member : tasks)
        if (live_process(member) && member.process != exclude &&
            in_subtree(member.process->cgroup, group))
            return true;
    return false;
}

void population_event(Node* group) {
    Node* events = nullptr;
    if (!ramfs_ops.lookup(group, names[unsigned(File::events)], events))
        inotify_inode(events, inotify_modify);
}

// A null membership denotes the root. Common ancestors stay populated.
void move_process(Process& process, Node* next) {
    Node* const origin = process.cgroup;
    process.cgroup = next;
    for (auto previous = origin; previous && !in_subtree(next, previous);
         previous = previous->parent)
        if (!populated(previous))
            population_event(previous);
    for (; next && !in_subtree(origin, next); next = next->parent)
        if (!populated(next, &process))
            population_event(next);
}

int relative_path(const Node* node, char* output, size_t capacity) {
    if (capacity < 2)
        return -36;
    size_t first = capacity - 1;
    output[first] = 0;
    for (; node && node->parent; node = node->parent) {
        const size_t size = strlen(node->name);
        if (size + 1 > first)
            return -36;
        first -= size;
        memcpy(output + first, node->name, size);
        output[--first] = '/';
    }
    if (first == capacity - 1)
        output[--first] = '/';
    memmove(output, output + first, capacity - first);
    return 0;
}

int lookup(Node* parent, const char* name, Node*& node) {
    return ramfs_ops.lookup(parent, name, node);
}

int add_files(Node* group, bool root) {
    for (unsigned index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (root && (index == unsigned(File::type) || index == unsigned(File::events)))
            continue;
        Node* file = nullptr;
        int error =
            ramfs_ops.create(group, names[index],
                             regular_file | (writable(File(index)) ? 0644 : 0444), nullptr, file);
        if (error)
            return error;
        file->uid = 0;
        file->gid = 0;
        file->device_id = index;
    }
    return 0;
}

void retire_files(Node* group) {
    for (auto file = group->first_child; file; file = file->next_sibling) {
        if (file->removed)
            continue;
        ramfs_ops.remove(file);
        inotify_retire_inode(file);
        node_reference_released(file);
    }
}

int create(Node* parent, const char* name, uint32_t mode, const char*, Node*& node) {
    if (!administrator())
        return -1;
    if ((mode & 0170000) != directory)
        return -1;
    size_t size = strlen(name) + 1;
    for (auto ancestor = parent; ancestor->parent; ancestor = ancestor->parent)
        size += strlen(ancestor->name) + 1;
    if (size >= sizeof(Path::text))
        return -36;
    int error = ramfs_ops.create(parent, name, mode, nullptr, node);
    if (error)
        return error;
    error = add_files(node, false);
    if (!error)
        return 0;
    retire_files(node);
    ramfs_ops.remove(node);
    node_reference_released(node);
    return error;
}

int empty(Node* group) {
    for (auto child = group->first_child; child; child = child->next_sibling)
        if (!child->removed && is_directory(child))
            return -16;
    return 0;
}

int remove(Node* node) {
    if (!administrator() || !is_directory(node))
        return -1;
    if (populated(node))
        return -16;
    retire_files(node);
    int error = ramfs_ops.remove(node);
    if (!error)
        node_reference_released(node);
    return error;
}

int attributes(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime, uint32_t uid,
               uint32_t gid) {
    if (!administrator() || uid || gid || (mode & 0022))
        return -1;
    return ramfs_ops.setattr(node, mode, atime, mtime, uid, gid);
}

int readdir(Node* node, uint64_t offset, DirectoryEntry& entry) {
    return ramfs_ops.readdir(node, offset, entry);
}

int stats(Mount*, FilesystemStats& output) {
    output = {0x63677270, page_size, 0, 0, 0, 0};
    return 0;
}

void destroy(Mount* mount) {
    hierarchy = nullptr;
    ramfs_ops.destroy(mount);
}

void reclaim(Mount* mount) {
    for (bool released = true; released;) {
        released = false;
        for (size_t i = 0; i < node_count; ++i) {
            auto& node = nodes[i];
            if (node.mount == mount && node.removed && !node.first_child)
                released |= ramfs_reclaim_unlinked(&node);
        }
    }
}

int sync(Mount* mount, Node*, bool) {
    reclaim(mount);
    return 0;
}

int access(Node* node, unsigned mask, bool) {
    if ((mask & 1) || ((mask & 4) && !(node->mode & 0444)) ||
        ((mask & 2) &&
         (!writable(File(node->device_id)) || !(node->mode & 0200) || !administrator())))
        return -13;
    return 0;
}

struct Reader {
    char* output;
    size_t capacity;
    uint64_t skip;
    size_t length = 0;

    void copy(const char* value, size_t size) {
        const size_t start = min(skip, uint64_t(size));
        skip -= start;
        const size_t count = min(capacity - length, size - start);
        memcpy(output + length, value + start, count);
        length += count;
    }
};

void emit_pid(Reader& reader, unsigned pid) {
    char line[12];
    size_t first = sizeof(line) - 1;
    line[first] = '\n';
    do {
        line[--first] = char('0' + pid % 10);
        pid /= 10;
    } while (pid);
    reader.copy(line + first, sizeof(line) - first);
}

int64_t read(Handle* handle, void* output, size_t size) {
    Reader reader{static_cast<char*>(output), size, handle->offset};
    const auto group = handle->node->parent;
    const auto member_group = group->parent ? group : nullptr;
    const auto kind = File(handle->node->device_id);
    if (kind == File::processes || kind == File::threads) {
        for (const auto& member : tasks) {
            if (reader.length == size)
                break;
            const bool visible = kind == File::processes ? live_process(member)
                                                         : member.state != State::empty &&
                                                               member.state != State::zombie;
            if (visible && member.process && member.process->cgroup == member_group)
                emit_pid(reader, member.pid);
        }
    } else if (kind == File::type) {
        constexpr char type[] = "domain\n";
        reader.copy(type, sizeof(type) - 1);
    } else if (kind == File::events) {
        char events[] = "populated 0\nfrozen 0\n";
        events[10] = populated(group) ? '1' : '0';
        reader.copy(events, sizeof(events) - 1);
    }
    handle->offset += reader.length;
    return int64_t(reader.length);
}

int64_t write(Handle* handle, const void* input, size_t size) {
    if (!size)
        return 0;
    if (File(handle->node->device_id) == File::subtree)
        return -2; // The hierarchy has no registered resource controllers.
    if (size > 32)
        return -22;
    const auto bytes = static_cast<const char*>(input);
    auto space = [](char value) { return value == ' ' || value == '\t' || value == '\n'; };
    size_t at = 0;
    while (at < size && space(bytes[at]))
        ++at;
    const size_t start = at;
    unsigned pid = 0;
    for (; at < size && bytes[at] >= '0' && bytes[at] <= '9'; ++at) {
        const unsigned digit = unsigned(bytes[at] - '0');
        if (pid > (unsigned(INT32_MAX) - digit) / 10)
            return -22;
        pid = pid * 10 + digit;
    }
    if (at == start)
        return -22;
    while (at < size && space(bytes[at]))
        ++at;
    if (at != size)
        return -22;
    auto member = pid ? task(int(pid)) : current_task();
    if (!member || !member->process || !member->process->live_threads)
        return -3;
    auto& process = *member->process;
    Node* group = handle->node->parent;
    if (!group->parent)
        group = nullptr;
    if (File(handle->node->device_id) == File::threads && process.cgroup != group)
        return -95; // Moving a single thread across domain cgroups is unsupported.
    move_process(process, group);
    return int64_t(size);
}

const ControlFileOps interface = {access, read, write,
                                  [](Node*, size_t size) { return size ? -22 : 0; }};

const ControlFileOps* control(Node* node) {
    return is_directory(node) ? nullptr : &interface;
}

int validate(Node* node) {
    return node->removed ? -19 : 0;
}
} // namespace

const FilesystemOps cgroup2_ops = {
    .lookup = lookup,
    .create = create,
    .link = [](Node*, Node*, const char*) { return -1; },
    .remove = remove,
    .rename = [](Node*, Node*, const char*, Node*) { return -95; },
    .read = [](Node*, uint64_t, void*, size_t) -> int64_t { return -22; },
    .write = [](Node*, uint64_t, const void*, size_t) -> int64_t { return -22; },
    .truncate = [](Node*, size_t) { return -22; },
    .setattr = attributes,
    .readdir = readdir,
    .sync = sync,
    .map_shared = nullptr,
    .stats = stats,
    .destroy = destroy,
    .remount = nullptr,
    .prepare_unmount = nullptr,
    .control = control,
    .validate = validate,
    .queue_reclaim = [](Node* node) { return node->removed; },
    .reclaim_queued = reclaim,
    .directory_empty = empty,
};

int cgroup2_mount(Mount* mount) {
    if (hierarchy)
        return -16;
    mount->root = ramfs_root(mount, 0755);
    if (!mount->root)
        return -28;
    if (int error = add_files(mount->root, true)) {
        ramfs_ops.destroy(mount);
        return error;
    }
    hierarchy = mount;
    return 0;
}

int cgroup2_unmount(Mount* mount) {
    return empty(mount->root);
}

int cgroup_path(const Process& process, char* output, size_t capacity) {
    return relative_path(process.cgroup, output, capacity);
}

void cgroup_process_exit(Process& process) {
    move_process(process, nullptr);
}
} // namespace ax
