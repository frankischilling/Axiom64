// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/vfs.hpp"

namespace ax {
static uint64_t next_inode = 1;
static Node* allocate_node(Mount* mount, uint32_t mode) {
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
    return 0;
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
static int truncate(Node* node, size_t size) {
    if (size > 256 * 1024 * 1024)
        return -27;
    if (!node->owned || size > node->capacity) {
        if (node->backing_physical && page_shared(node->backing_physical, node->capacity / page_size))
            return -16;
        size_t cap = align_up(max(size, min(size_t(256 * 1024 * 1024),
                                           max(size_t(65536), node->capacity * 2))));
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
    else if (size < node->size)
        memset(node->data + size, 0, node->size - size);
    node->size = size;
    node->allocated_blocks = (size + 511) / 512;
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
static int setattr(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime) {
    node->mode = mode;
    node->atime = atime;
    node->mtime = mtime;
    node->ctime = node_now();
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
static int sync(Mount*, Node*, bool) {
    return 0;
}
static int map_shared(Node* node, uint64_t offset, size_t length, uint64_t& physical_address) {
    if (offset > SIZE_MAX - length)
        return -27;
    size_t old = node->size;
    uint64_t old_blocks = node->allocated_blocks;
    auto mtime = node->mtime, ctime = node->ctime;
    int error = truncate(node, max(old, size_t(offset + length)));
    if (error)
        return error;
    node->size = old;
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
    result = {0x858458f6, page_size, 0, 0, files,
              free + sizeof(nodes) / sizeof(nodes[0]) - node_count};
    return 0;
}
static void destroy(Mount* mount) {
    for (size_t i = 0; i < node_count; i++) {
        auto& node = nodes[i];
        if (node.mount != mount)
            continue;
        if (!node.hardlink && node.owned) {
            if (node.backing_physical)
                page_free(node.backing_physical, node.capacity / page_size);
            else
                release(node.data);
        }
        node = {};
    }
}
const FilesystemOps ramfs_ops = {find, create, link, remove, rename, read, write, truncate,
                                 setattr, readdir, sync, map_shared, stats, destroy, nullptr, nullptr};
} // namespace ax
