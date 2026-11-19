// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/descriptor_inode.cpp
 * @brief   Metadata for pipes, sockets, and anonymous descriptors.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Keeps stable VFS identities for descriptor-backed objects and preserves
 * their metadata while procfs path handles remain open.
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
#include "fs/descriptor_inode.hpp"
#include "fs/inotify.hpp"
#include "fs/vfs.hpp"

namespace ax {
namespace {
struct DescriptorInode {
    Node node;
    unsigned descriptions;
};

constexpr const char* anonymous_names[] = {"anon_inode:[eventpoll]", "anon_inode:[eventfd]",
                                           "anon_inode:[timerfd]", "anon_inode:[signalfd]",
                                           "anon_inode:inotify"};
Node anonymous_nodes[sizeof(anonymous_names) / sizeof(*anonymous_names)];

void set_attributes(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime, Timestamp ctime,
                    uint32_t uid, uint32_t gid) {
    node->mode = mode;
    node->uid = uid;
    node->gid = gid;
    node->atime = atime;
    node->mtime = mtime;
    node->ctime = ctime;
}

int setattr(Node*, uint32_t mode, Timestamp atime, Timestamp mtime, uint32_t uid, uint32_t gid);
int stats(Mount*, FilesystemStats&);

const FilesystemOps operations{
    .lookup = nullptr,
    .create = nullptr,
    .link = nullptr,
    .remove = nullptr,
    .rename = nullptr,
    .read = nullptr,
    .write = nullptr,
    .truncate = nullptr,
    .setattr = setattr,
    .readdir = nullptr,
    .sync = nullptr,
    .map_shared = nullptr,
    .stats = stats,
    .destroy = nullptr,
    .remount = nullptr,
    .prepare_unmount = nullptr,
};

Mount pipes{0x7ffffffc, nullptr, nullptr, nullptr, &operations, nullptr, true, false};
Mount sockets{0x7ffffffd, nullptr, nullptr, nullptr, &operations, nullptr, true, false};
Mount anonymous{0x7ffffffe, nullptr, nullptr, nullptr, &operations, nullptr, true, false};
uint64_t next_inode = 1;

int setattr(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime, uint32_t uid,
            uint32_t gid) {
    auto now = node_now();
    if (node->mount == &anonymous) {
        for (auto& view : anonymous_nodes)
            set_attributes(&view, mode, atime, mtime, now, uid, gid);
    } else
        set_attributes(node, mode, atime, mtime, now, uid, gid);
    return 0;
}

int stats(Mount* mount, FilesystemStats& result) {
    uint64_t magic = mount == &pipes ? 0x50495045 : mount == &sockets ? 0x534f434b : 0x09041934;
    result = {magic, page_size, 0, 0, 0, 0};
    return 0;
}

DescriptorInode* dynamic_inode(Node* node) {
    if (!node || (node->mount != &pipes && node->mount != &sockets))
        return nullptr;
    return static_cast<DescriptorInode*>(node->filesystem_data);
}

Node* new_inode(Mount& mount, const char* prefix, uint32_t mode, const Handle& handle) {
    auto entry = static_cast<DescriptorInode*>(alloc(sizeof(DescriptorInode)));
    if (!entry)
        return nullptr;
    *entry = {};
    auto& node = entry->node;
    node.mount = &mount;
    node.filesystem_data = entry;
    node.inode = next_inode++;
    node.links = 1;
    node.mode = mode;
    node.uid = handle.opener_uid;
    node.gid = handle.opener_gid;
    node.atime = node.mtime = node.ctime = node_now();
    char* name = node.name;
    while (*prefix)
        *name++ = *prefix++;
    char digits[20];
    unsigned count = 0;
    uint64_t value = node.inode;
    do {
        digits[count++] = '0' + value % 10;
        value /= 10;
    } while (value);
    while (count)
        *name++ = digits[--count];
    *name = ']';
    return &node;
}

Node* anonymous_inode(const Handle& handle) {
    if (!anonymous_nodes[0].mount) {
        auto now = node_now();
        for (unsigned i = 0; i < sizeof(anonymous_nodes) / sizeof(*anonymous_nodes); ++i) {
            auto& node = anonymous_nodes[i];
            node.mount = &anonymous;
            // These classes share inode metadata but supply their own path name.
            node.inode = 1;
            node.links = 1;
            node.mode = 0600;
            node.atime = node.mtime = node.ctime = now;
            memcpy(node.name, anonymous_names[i], strlen(anonymous_names[i]) + 1);
        }
    }
    unsigned kind = handle.epoll               ? 0
                    : handle.event             ? 1
                    : handle.timer             ? 2
                    : handle.signal_descriptor ? 3
                                               : 4;
    return &anonymous_nodes[kind];
}
} // namespace

int attach_pipe_inode(Pipe& pipe, Handle& reader, Handle& writer) {
    auto node = new_inode(pipes, "pipe:[", fifo | 0600, reader);
    if (!node)
        return -12;
    node->named_pipe = &pipe;
    reader.node = writer.node = node;
    retain_descriptor_inode(node);
    retain_descriptor_inode(node);
    return 0;
}

int descriptor_inode(Handle& handle, Node*& node) {
    if (handle.node) {
        node = handle.node;
    } else if (handle.socket || handle.packet || handle.inet || handle.inet6 || handle.netlink) {
        if (!handle.anonymous_path) {
            handle.anonymous_path = new_inode(sockets, "socket:[", 0140777, handle);
            if (!handle.anonymous_path)
                return -12;
            retain_descriptor_inode(handle.anonymous_path);
        }
        node = handle.anonymous_path;
    } else if (handle.epoll || handle.event || handle.timer || handle.signal_descriptor ||
               handle.inotify) {
        node = anonymous_inode(handle);
    } else {
        return -22;
    }
    return 0;
}

const char* descriptor_inode_name(const Node* node) {
    return node && node->mount->ops == &operations ? node->name : nullptr;
}

bool is_anonymous_pipe_inode(const Node* node) {
    return node->mount == &pipes;
}

bool descriptor_inode_path_only(const Node* node) {
    return node->mount == &sockets || node->mount == &anonymous;
}

void retain_descriptor_inode(Node* node) {
    if (auto entry = dynamic_inode(node))
        ++entry->descriptions;
}

void release_descriptor_inode(Node* node) {
    auto entry = dynamic_inode(node);
    if (!entry || --entry->descriptions)
        return;
    node->links = 0;
    inotify_retire_inode(node);
    inotify_reap_inodes();
    release(entry);
}
} // namespace ax
