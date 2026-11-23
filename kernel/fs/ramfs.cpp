// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ramfs.cpp
 * @brief   In-memory filesystem.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Stores nodes and file data in RAM and implements the filesystem operations
 * used by volatile mounts.
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
#include "fs/vfs.hpp"
#include "fs/inotify.hpp"
#include "fs/tmpfs.hpp"
#include "fs/xattr.hpp"
#include "process/task.hpp"

namespace ax {
static uint64_t next_inode = 1;

void ramfs_set_control(Node* node, const ControlFileOps* control) {
    if (node->mount->ops == &ramfs_ops)
        node->filesystem_data = const_cast<ControlFileOps*>(control);
}

static const ControlFileOps* control(Node* node) {
    return static_cast<const ControlFileOps*>(node->filesystem_data);
}

static Node* allocate_node(Mount* mount, uint32_t mode) {
    auto limits = tmpfs_limits(mount);
    if (limits && limits->inodes && limits->used_inodes >= limits->inodes)
        return nullptr;
    Node* node = nullptr;
    for (size_t i = 0; i < node_count; i++)
        if (!nodes[i].mount) {
            node = &nodes[i];
            break;
        }
    if (!node && node_count < sizeof(nodes) / sizeof(nodes[0]))
        node = &nodes[node_count++];
    if (!node)
        return nullptr;
    if (limits)
        ++limits->used_inodes;
    *node = {};
    node->inode = next_inode++;
    node->links = (mode & 0170000) == directory ? 2 : 1;
    node->mode = mode;
    node->mount = mount;
    node->atime = node->mtime = node->ctime = node_now();
    return node;
}

Node* ramfs_root(Mount* mount, uint32_t mode) {
    return allocate_node(mount, directory | (mode & 07777));
}

static int find(Node* parent, const char* name, Node*& result) {
    for (auto n = parent->first_child; n; n = n->next_sibling)
        if (!n->removed && !strcmp(n->name, name)) {
            result = n;
            return 0;
        }
    return -2;
}

static void attach(Node* node, Node* parent, const char* name) {
    node->parent = parent;
    node->next_sibling = parent->first_child;
    parent->first_child = node;
    memcpy(node->name, name, strlen(name) + 1);
    parent->mtime = parent->ctime = node_now();
    if ((node->mode & 0170000) == directory)
        parent->links++;
}

static int create(Node* parent, const char* name, uint32_t mode, const char* target, Node*& node) {
    uint8_t* data = nullptr;
    if (target) {
        data = (uint8_t*)alloc(strlen(target) + 1);
        if (!data)
            return -12;
        memcpy(data, target, strlen(target) + 1);
    }
    node = allocate_node(parent->mount, mode);
    if (!node) {
        release(data);
        return -28;
    }
    node->uid = current_task() ? current_task()->credentials.user.filesystem : 0;
    node->gid = (parent->mode & 02000) ? parent->gid
                : current_task()       ? current_task()->credentials.group.filesystem
                                       : 0;
    attach(node, parent, name);
    if (target) {
        node->data = data;
        node->size = strlen(target);
        node->allocated_blocks = (node->size + 511) / 512;
        node->capacity = node->size + 1;
        node->owned = true;
    }
    return 0;
}

static int link(Node* target, Node* parent, const char* name) {
    Node* alias;
    int error = create(parent, name, target->mode, nullptr, alias);
    if (error)
        return error;
    alias->hardlink = target;
    alias->inode = target->inode;
    target->links++;
    target->ctime = node_now();
    return 0;
}

static int remove(Node* node) {
    node->removed = true;
    if ((node->mode & 0170000) == directory) {
        node->links = 0;
        node->parent->links--;
    } else if (file_node(node)->links)
        file_node(node)->links--;
    file_node(node)->ctime = node_now();
    node->parent->mtime = node->parent->ctime = node_now();
    node_retire_xattrs(node);
    if (tmpfs_limits(node->mount))
        schedule_filesystem_reclaim();
    return 0;
}

void ramfs_reclaim_device(Node* node) {
    if (!node || !node->mount || node->mount->ops != &ramfs_ops || !node->removed || node->links ||
        (node->mode & 0170000) != character)
        return;
    ramfs_reclaim_unlinked(node);
}

static void release_storage(Node& node) {
    if (!node.hardlink && node.owned) {
        if (node.backing_physical)
            page_free(node.backing_physical, node.capacity / page_size);
        else
            release(node.data);
    }
}

static bool reclaim_unlinked(Node* node, TmpfsLimits* limits) {
    if (!node->parent || !node->removed || node->first_child ||
        (!limits && (node->hardlink || node->owned)) ||
        (!node->hardlink && (node->links || node_referenced(node))))
        return false;
    Node** slot = &node->parent->first_child;
    while (*slot && *slot != node)
        slot = &(*slot)->next_sibling;
    if (*slot != node)
        return false;
    *slot = node->next_sibling;
    inotify_retire_inode(node);
    xattr_store_destroy(node->xattrs);
    if (limits) {
        --limits->used_inodes;
        if (node->backing_physical)
            limits->used_pages -= node->capacity / page_size;
        release_storage(*node);
    }
    *node = {};
    return true;
}

bool ramfs_reclaim_unlinked(Node* node) {
    return reclaim_unlinked(node, nullptr);
}

static void reclaim_tmpfs(Mount* mount) {
    auto limits = tmpfs_limits(mount);
    bool released;
    do {
        released = false;
        // Retire removed names before releasing the inode they refer to.
        for (size_t i = 0; i < node_count; ++i)
            if (nodes[i].mount == mount && nodes[i].hardlink)
                released |= reclaim_unlinked(&nodes[i], limits);
        for (size_t i = 0; i < node_count; ++i)
            if (nodes[i].mount == mount && !nodes[i].hardlink)
                released |= reclaim_unlinked(&nodes[i], limits);
    } while (released);
}

static int rename(Node* node, Node* parent, const char* name, Node* replaced) {
    auto old_parent = node->parent;
    Node** slot = &old_parent->first_child;
    while (*slot && *slot != node)
        slot = &(*slot)->next_sibling;
    if (!*slot)
        return -5;
    if (replaced)
        remove(replaced);
    *slot = node->next_sibling;
    if ((node->mode & 0170000) == directory)
        old_parent->links--;
    old_parent->mtime = old_parent->ctime = node_now();
    attach(node, parent, name);
    file_node(node)->ctime = node_now();
    return 0;
}

static int resize_tmpfs(Node& node, size_t size, TmpfsLimits& limits) {
    const size_t old = node.backing_physical ? node.capacity / page_size : 0;
    const size_t next = align_up(size) / page_size;
    if (old == next)
        return 0;
    const bool shared = old && page_shared(node.backing_physical, old);
    if (next < old) {
        // A shared mapping retains its backing and that backing stays charged.
        if (shared)
            return 0;
        page_free(node.backing_physical + next * page_size, old - next);
        limits.used_pages -= old - next;
        node.capacity = next * page_size;
        if (!next) {
            node.backing_physical = 0;
            node.data = nullptr;
            node.owned = false;
        }
        return 0;
    }
    if (shared)
        return -16;
    if (limits.pages && next - old > limits.pages - limits.used_pages)
        return -28;
    auto backing = page_alloc(next);
    if (!backing)
        return -12;
    auto data = static_cast<uint8_t*>(physical(backing));
    if (node.size)
        memcpy(data, node.data, node.size);
    release_storage(node);
    limits.used_pages += next - old;
    node.data = data;
    node.backing_physical = backing;
    node.owned = true;
    node.capacity = next * page_size;
    return 0;
}

static int truncate(Node* node, size_t size) {
    if (size > 256 * 1024 * 1024)
        return -27;
    auto limits = tmpfs_limits(node->mount);
    if (limits) {
        if (int error = resize_tmpfs(*node, size, *limits))
            return error;
    } else if (!node->owned || size > node->capacity) {
        if (node->backing_physical &&
            page_shared(node->backing_physical, node->capacity / page_size))
            return -16;
        size_t cap = align_up(
            max(size, min(size_t(256 * 1024 * 1024), max(size_t(65536), node->capacity * 2))));
        uint64_t backing = page_alloc(cap / page_size);
        if (!backing)
            return -12;
        auto data = (uint8_t*)physical(backing);
        memcpy(data, node->data, min(node->size, size));
        if (node->backing_physical)
            page_free(node->backing_physical, node->capacity / page_size);
        else if (node->owned)
            release(node->data);
        node->data = data;
        node->backing_physical = backing;
        node->owned = true;
        node->capacity = cap;
    }
    if (size > node->size)
        memset(node->data + node->size, 0, size - node->size);
    else if (size < min(node->size, node->capacity))
        memset(node->data + size, 0, min(node->size, node->capacity) - size);
    node->size = size;
    node->allocated_blocks = limits ? node->capacity / 512 : (size + 511) / 512;
    node->mtime = node->ctime = node_now();
    return 0;
}

static int64_t read(Node* node, uint64_t offset, void* buffer, size_t length) {
    if (offset >= node->size)
        return 0;
    size_t count = min(length, node->size - size_t(offset));
    memcpy(buffer, node->data + offset, count);
    if (!node->mount->readonly)
        node->atime = node_now();
    return count;
}

static int64_t write(Node* node, uint64_t offset, const void* buffer, size_t length) {
    if (offset > SIZE_MAX - length)
        return -27;
    if (!node->owned || offset + length > node->size) {
        int error = truncate(node, max(node->size, size_t(offset + length)));
        if (error)
            return error;
    }
    memcpy(node->data + offset, buffer, length);
    node->mtime = node->ctime = node_now();
    return length;
}

static int setattr(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime, uint32_t uid,
                   uint32_t gid) {
    node->mode = mode;
    node->atime = atime;
    node->mtime = mtime;
    node->ctime = node_now();
    node->uid = uid;
    node->gid = gid;
    return 0;
}

static int readdir(Node* parent, uint64_t cookie, DirectoryEntry& entry) {
    for (uint64_t i = cookie; i < node_count + 2; i++) {
        Node* node = i == 0 ? parent : i == 1 ? directory_parent(parent) : &nodes[i - 2];
        if (i >= 2 && (node->parent != parent || node->removed || node->mount != parent->mount))
            continue;
        node = file_node(node);
        entry.inode = node->inode;
        entry.next = i + 1;
        entry.mode = node->mode;
        const char* name = i == 0 ? "." : i == 1 ? ".." : nodes[i - 2].name;
        memcpy(entry.name, name, strlen(name) + 1);
        return 1;
    }
    return 0;
}

static int sync(Mount* mount, Node*, bool) {
    for (size_t i = 0; i < node_count; i++)
        if (nodes[i].mount == mount && !nodes[i].hardlink)
            node_retire_xattrs(&nodes[i]);
    return 0;
}

static int map_shared(Node* node, uint64_t offset, size_t length, uint64_t& physical_address) {
    if (control(node))
        return -19;
    if (offset > SIZE_MAX - length)
        return -27;
    size_t old = node->size;
    uint64_t old_blocks = node->allocated_blocks;
    auto mtime = node->mtime, ctime = node->ctime;
    int error = truncate(node, max(old, size_t(offset + length)));
    if (error)
        return error;
    node->size = old;
    if (!tmpfs_limits(node->mount))
        node->allocated_blocks = old_blocks;
    node->mtime = mtime;
    node->ctime = ctime;
    physical_address = node->backing_physical + offset;
    return 0;
}

static int stats(Mount* mount, FilesystemStats& result) {
    uint64_t files = 0, free = 0;
    for (size_t i = 0; i < node_count; i++) {
        if (!nodes[i].mount)
            free++;
        else if (nodes[i].mount == mount && !nodes[i].removed)
            files++;
    }
    result = {0x858458f6, page_size, 0,
              0,          files,     free + sizeof(nodes) / sizeof(nodes[0]) - node_count};
    return 0;
}

static void destroy(Mount* mount) {
    for (size_t i = 0; i < node_count; i++) {
        auto& node = nodes[i];
        if (node.mount != mount)
            continue;
        if (!node.hardlink)
            xattr_store_destroy(node.xattrs);
        release_storage(node);
        node = {};
    }
}

static int64_t getxattr(Node* node, const XattrName& name, void* buffer, size_t size) {
    return xattr_store_get(node->xattrs, name, buffer, size);
}

static int64_t listxattr(Node* node, void* buffer, size_t size, bool trusted) {
    return xattr_store_list(node->xattrs, buffer, size, trusted);
}

static int setxattr(Node* node, const XattrName& name, const void* value, size_t size,
                    unsigned flags) {
    int error = xattr_store_set(node->xattrs, name, value, size, flags);
    if (!error)
        node->ctime = node_now();
    return error;
}

static int removexattr(Node* node, const XattrName& name) {
    int error = xattr_store_remove(node->xattrs, name);
    if (!error)
        node->ctime = node_now();
    return error;
}

namespace {
constexpr FilesystemOps memory_ops = {
    .lookup = find,
    .create = create,
    .link = link,
    .remove = remove,
    .rename = rename,
    .read = read,
    .write = write,
    .truncate = truncate,
    .setattr = setattr,
    .readdir = readdir,
    .sync = sync,
    .map_shared = map_shared,
    .stats = stats,
    .destroy = destroy,
    .remount = nullptr,
    .prepare_unmount = nullptr,
    .getxattr = getxattr,
    .listxattr = listxattr,
    .setxattr = setxattr,
    .removexattr = removexattr,
    .control = control,
};
} // namespace

const FilesystemOps ramfs_ops = memory_ops;
const FilesystemOps tmpfs_ops = [] {
    auto operations = memory_ops;
    operations.stats = [](Mount* mount, FilesystemStats& result) {
        const auto& limits = *tmpfs_limits(mount);
        result = {0x01021994,    page_size,
                  limits.pages,  limits.pages ? limits.pages - limits.used_pages : 0,
                  limits.inodes, limits.inodes ? limits.inodes - limits.used_inodes : 0};
        return 0;
    };
    operations.destroy = [](Mount* mount) {
        destroy(mount);
        release(mount->data);
        mount->data = nullptr;
    };
    operations.queue_reclaim = [](Node* node) { return node->removed; };
    operations.reclaim_queued = reclaim_tmpfs;
    operations.sync = [](Mount* mount, Node* node, bool data_only) {
        reclaim_tmpfs(mount);
        return sync(mount, node, data_only);
    };
    return operations;
}();
} // namespace ax
