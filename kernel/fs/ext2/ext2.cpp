// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/ext2.cpp
 * @brief   ext2 filesystem operations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Reads and updates ext2 inodes, directories, and block mappings through the
 * block device layer.
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
#include "volume.hpp"

namespace ax {
namespace {
using namespace ext2_detail;

static Volume& volume(Node* node) {
    return *static_cast<Volume*>(node->mount->data);
}

static bool locate(Volume& v, uint32_t parent, const char* name, uint32_t& number,
                   uint64_t* position = nullptr) {
    uint8_t inode[inode_bytes], data[max_block_size];
    if (!v.load_inode(parent, inode))
        return false;
    size_t length = strlen(name);
    for (uint64_t base = 0; base < file_size(inode); base += v.block_size) {
        uint32_t block;
        if (!directory_block(v, inode, base, block, data))
            return false;
        for (unsigned offset = 0; offset < v.block_size;) {
            Record r;
            if (!record(v, data, offset, r))
                return false;
            if (r.inode && r.name_length == length && !memcmp(data + offset + 8, name, length)) {
                number = r.inode;
                if (position)
                    *position = base + offset;
                return true;
            }
            offset += r.length;
        }
    }
    return v.fail(-2);
}

static void put_record(Volume& v, uint8_t* data, unsigned offset, unsigned length, const char* name,
                       uint32_t inode, uint32_t mode) {
    size_t count = strlen(name);
    memset(data + offset, 0, length);
    set32(data + offset, inode);
    set16(data + offset + 4, length);
    set16(data + offset + 6, count);
    if (v.typed_entries)
        data[offset + 7] = file_type(mode);
    memcpy(data + offset + 8, name, count);
}

static bool add_name(Volume& v, uint32_t parent, const char* name, uint32_t number, uint32_t mode) {
    uint8_t inode[inode_bytes], data[max_block_size];
    if (!v.load_inode(parent, inode))
        return false;
    unsigned need = (8 + strlen(name) + 3) & ~3u;
    uint64_t length = file_size(inode);
    for (uint64_t base = 0; base <= length; base += v.block_size) {
        uint32_t block;
        if (base == length) {
            if (length > UINT32_MAX - v.block_size ||
                !v.map_block(inode, base / v.block_size, true, block,
                             (parent - 1) / v.inodes_per_group))
                return v.fail(-27);
            memset(data, 0, v.block_size);
            put_record(v, data, 0, v.block_size, name, number, mode);
            set32(inode + 4, length + v.block_size);
        } else {
            if (!directory_block(v, inode, base, block, data))
                return false;
            bool found = false;
            for (unsigned offset = 0; offset < v.block_size;) {
                Record r;
                if (!record(v, data, offset, r))
                    return false;
                unsigned used = r.inode ? (8 + r.name_length + 3) & ~3u : 0;
                if (r.length - used >= need) {
                    if (used)
                        set16(data + offset + 4, used);
                    put_record(v, data, offset + used, r.length - used, name, number, mode);
                    found = true;
                    break;
                }
                offset += r.length;
            }
            if (!found)
                continue;
        }
        set32(inode + 12, node_now().sec);
        set32(inode + 16, node_now().sec);
        return v.write_block(block, data, 3) && v.save_inode(parent, inode);
    }
    return v.fail(-28);
}

static bool erase_name(Volume& v, uint32_t parent, const char* name, uint32_t expected) {
    uint32_t number, block;
    uint64_t position;
    if (!locate(v, parent, name, number, &position))
        return false;
    if (number != expected)
        return v.fail();
    uint8_t inode[inode_bytes], data[max_block_size];
    if (!v.load_inode(parent, inode) || !directory_block(v, inode, position, block, data))
        return false;
    unsigned target = position % v.block_size, previous = 0;
    for (unsigned offset = 0; offset < target;) {
        Record r;
        if (!record(v, data, offset, r))
            return false;
        previous = offset;
        offset += r.length;
        if (offset > target)
            return v.fail();
    }
    Record r;
    if (!record(v, data, target, r))
        return false;
    if (target)
        set16(data + previous + 4, u16(data + previous + 4) + r.length);
    else {
        set32(data + target, 0);
        set16(data + target + 6, 0);
    }
    set32(inode + 12, node_now().sec);
    set32(inode + 16, node_now().sec);
    return v.write_block(block, data, 3) && v.save_inode(parent, inode);
}

static bool adjust_links(Volume& v, uint32_t number, int delta) {
    uint8_t inode[inode_bytes];
    if (!v.load_inode(number, inode))
        return false;
    int count = int(u16(inode + 26)) + delta;
    if (count < 0)
        return v.fail();
    if (count > UINT16_MAX)
        return v.fail(-31);
    set16(inode + 26, count);
    set32(inode + 12, node_now().sec);
    return v.save_inode(number, inode);
}

static bool drop_inode(Volume& v, Node* node) {
    node = file_node(node);
    uint8_t inode[inode_bytes];
    if (!v.load_inode(node->inode, inode))
        return false;
    bool dir = (u16(inode) & 0170000) == directory;
    unsigned links = u16(inode + 26);
    if (!links)
        return v.fail();
    set16(inode + 26, dir ? 0 : links - 1);
    set32(inode + 12, node_now().sec);
    if (!u16(inode + 26)) {
        if (!node_referenced(node))
            return v.delete_inode(node->inode, inode);
        set32(inode + 20, u32(inode + 12));
    }
    return v.save_inode(node->inode, inode);
}

static int lookup(Node* parent, const char* name, Node*& result) {
    auto& v = volume(parent);
    v.error = 0;
    uint32_t number;
    if (!locate(v, parent->inode, name, number))
        return v.error;
    for (auto entry = v.entries.inode_bucket(number); entry; entry = entry->inode_next)
        if (entry->number == number && entry->node.parent == parent && !entry->node.removed &&
            !strcmp(entry->node.name, name)) {
            result = &entry->node;
            return 0;
        }
    uint8_t inode[inode_bytes];
    if (!v.load_inode(number, inode))
        return v.error;
    auto entry = v.reserve_entry();
    if (!entry)
        return v.error;
    result = v.add_entry(entry, number, parent, name, inode);
    return 0;
}

static int create(Node* parent, const char* name, uint32_t mode, const char* target,
                  Node*& result) {
    auto& v = volume(parent);
    if (target && !*target)
        return -2;
    v.error = 0;
    auto entry = v.reserve_entry();
    if (!entry)
        return v.error;
    if (!v.begin()) {
        v.entries.cancel(entry);
        return v.error;
    }
    bool dir = (mode & 0170000) == directory;
    uint32_t number = v.allocate(true, (parent->inode - 1) / v.inodes_per_group, dir);
    uint8_t inode[inode_bytes]{};
    set16(inode, mode);
    uint32_t uid = current ? current->credentials.user.filesystem : 0;
    uint32_t gid = (parent->mode & 02000) ? parent->gid
                   : current              ? current->credentials.group.filesystem
                                          : 0;
    set16(inode + 2, uid);
    set16(inode + 24, gid);
    set16(inode + 120, uid >> 16);
    set16(inode + 122, gid >> 16);
    set16(inode + 26, dir ? 2 : 1);
    set32(inode + 8, node_now().sec);
    set32(inode + 12, node_now().sec);
    set32(inode + 16, node_now().sec);
    bool success = number != 0;
    if (success && dir) {
        uint32_t block;
        success = v.map_block(inode, 0, true, block, (number - 1) / v.inodes_per_group);
        if (success) {
            uint8_t data[max_block_size]{};
            put_record(v, data, 0, 12, ".", number, directory);
            put_record(v, data, 12, v.block_size - 12, "..", parent->inode, directory);
            set32(inode + 4, v.block_size);
            success = v.write_block(block, data, 3) && adjust_links(v, parent->inode, 1);
        }
    } else if (success && target) {
        size_t length = strlen(target);
        set32(inode + 4, length);
        // The inline target and its terminating NUL must fit in i_block.
        if (length < inode_block_bytes)
            memcpy(inode + 40, target, length);
        else
            for (size_t offset = 0; success && offset < length; offset += v.block_size) {
                uint32_t block;
                success = v.map_block(inode, offset / v.block_size, true, block,
                                      (number - 1) / v.inodes_per_group);
                if (success) {
                    uint8_t data[max_block_size]{};
                    memcpy(data, target + offset, min(length - offset, size_t(v.block_size)));
                    success = v.write_block(block, data, 0);
                }
            }
    }
    success = success && v.save_inode(number, inode, true) &&
              add_name(v, parent->inode, name, number, mode);
    if (!success) {
        v.entries.cancel(entry);
        return v.finish(false);
    }
    result = v.add_entry(entry, number, parent, name, inode);
    return v.finish(true);
}

static int link(Node* target, Node* parent, const char* name) {
    auto& v = volume(parent);
    if (!v.begin())
        return v.error;
    return v.finish(adjust_links(v, target->inode, 1) &&
                    add_name(v, parent->inode, name, target->inode, target->mode));
}

static int remove(Node* node) {
    auto& v = volume(node);
    if (!v.begin())
        return v.error;
    bool dir = (node->mode & 0170000) == directory;
    bool success = erase_name(v, node->parent->inode, node->name, node->inode) &&
                   (!dir || adjust_links(v, node->parent->inode, -1)) && drop_inode(v, node);
    if (success)
        node->removed = true;
    return v.finish(success);
}

static int rename(Node* node, Node* parent, const char* name, Node* replaced) {
    auto& v = volume(node);
    if (!v.begin())
        return v.error;
    bool dir = (node->mode & 0170000) == directory, success = true;
    if (replaced) {
        success = erase_name(v, parent->inode, replaced->name, replaced->inode) &&
                  ((replaced->mode & 0170000) != directory || adjust_links(v, parent->inode, -1)) &&
                  drop_inode(v, replaced);
    }
    success = success && erase_name(v, node->parent->inode, node->name, node->inode) &&
              add_name(v, parent->inode, name, node->inode, node->mode);
    if (success && dir && node->parent != parent) {
        uint32_t number, block;
        uint64_t offset;
        uint8_t inode[inode_bytes], data[max_block_size];
        success = locate(v, node->inode, "..", number, &offset) &&
                  v.load_inode(node->inode, inode) &&
                  directory_block(v, inode, offset, block, data);
        if (success) {
            set32(data + offset % v.block_size, parent->inode);
            success = v.write_block(block, data, 3) && adjust_links(v, node->parent->inode, -1) &&
                      adjust_links(v, parent->inode, 1);
        }
    }
    if (success) {
        uint8_t inode[inode_bytes];
        success = v.load_inode(node->inode, inode);
        if (success) {
            set32(inode + 12, node_now().sec);
            success = v.save_inode(node->inode, inode);
        }
    }
    if (success) {
        if (replaced)
            replaced->removed = true;
        node->parent = parent;
        memcpy(node->name, name, strlen(name) + 1);
    }
    return v.finish(success);
}

static int64_t read(Node* node, uint64_t offset, void* buffer, size_t length) {
    auto& v = volume(node);
    v.error = 0;
    if (offset >= node->size)
        return 0;
    size_t count = min(length, node->size - size_t(offset)), done = 0;
    uint8_t inode[inode_bytes], data[max_block_size];
    if (!v.load_inode(node->inode, inode))
        return v.error;
    auto out = static_cast<uint8_t*>(buffer);
    if (fast_symlink(inode, v.block_size)) {
        if (node->size > inode_block_bytes)
            return -117;
        memcpy(out, inode + 40 + offset, count);
        done = count;
    } else
        while (done < count) {
            uint32_t block;
            size_t start = (offset + done) % v.block_size,
                   bytes = min(count - done, v.block_size - start);
            if (!v.map_block(inode, (offset + done) / v.block_size, false, block, 0) ||
                (block && !v.read_block(block, data)))
                return done ? int64_t(done) : v.error;
            if (block)
                memcpy(out + done, data + start, bytes);
            else
                memset(out + done, 0, bytes);
            done += bytes;
        }
    if (!node->mount->readonly) {
        node->atime = node_now();
        static_cast<Entry*>(node->filesystem_data)->atime_dirty = true;
    }
    return done;
}

static int64_t write(Node* node, uint64_t offset, const void* buffer, size_t length) {
    auto& v = volume(node);
    if (offset > UINT64_MAX - length || offset + length > v.capacity())
        return -27;
    if (!v.begin())
        return v.error;
    uint8_t inode[inode_bytes], data[max_block_size];
    bool success = v.load_inode(node->inode, inode);
    if (success && offset + length > file_size(inode))
        success = v.size(inode, offset + length);
    auto input = static_cast<const uint8_t*>(buffer);
    for (size_t done = 0; success && done < length;) {
        uint32_t block;
        size_t start = (offset + done) % v.block_size,
               bytes = min(length - done, v.block_size - start);
        success = v.map_block(inode, (offset + done) / v.block_size, true, block,
                              (node->inode - 1) / v.inodes_per_group) &&
                  v.read_block(block, data);
        if (success) {
            memcpy(data + start, input + done, bytes);
            success = v.write_block(block, data, 0);
        }
        done += bytes;
    }
    if (success) {
        set32(inode + 12, node_now().sec);
        set32(inode + 16, node_now().sec);
        success = v.save_inode(node->inode, inode);
    }
    int result = v.finish(success);
    return result ? result : int64_t(length);
}

static int truncate(Node* node, size_t length) {
    auto& v = volume(node);
    if (!v.begin())
        return v.error;
    uint8_t inode[inode_bytes];
    bool success = v.load_inode(node->inode, inode) && v.size(inode, length);
    if (success) {
        set32(inode + 12, node_now().sec);
        set32(inode + 16, node_now().sec);
        success = v.save_inode(node->inode, inode);
    }
    return v.finish(success);
}

static int setattr(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime, uint32_t uid,
                   uint32_t gid) {
    if (atime.sec < INT32_MIN || atime.sec > INT32_MAX || mtime.sec < INT32_MIN ||
        mtime.sec > INT32_MAX)
        return -22;
    auto& v = volume(node);
    if (!v.begin())
        return v.error;
    uint8_t inode[inode_bytes];
    bool success = v.load_inode(node->inode, inode);
    if (success) {
        set16(inode, mode);
        set16(inode + 2, uid);
        set16(inode + 24, gid);
        set16(inode + 120, uid >> 16);
        set16(inode + 122, gid >> 16);
        set32(inode + 8, atime.sec);
        set32(inode + 16, mtime.sec);
        set32(inode + 12, node_now().sec);
        success = v.save_inode(node->inode, inode);
    }
    return v.finish(success);
}

static int64_t getxattr(Node* node, const XattrName& name, void* buffer, size_t size) {
    auto& v = volume(node);
    v.error = 0;
    uint8_t inode[inode_bytes], block[max_block_size];
    uint32_t references;
    if (!v.load_inode(node->inode, inode) || !v.xattr_block(inode, block, references))
        return v.error;
    return references ? ext2_xattr_get(block, v.block_size, name, buffer, size) : -61;
}

static int64_t listxattr(Node* node, void* buffer, size_t size, bool trusted) {
    auto& v = volume(node);
    v.error = 0;
    uint8_t inode[inode_bytes], block[max_block_size];
    uint32_t references;
    if (!v.load_inode(node->inode, inode) || !v.xattr_block(inode, block, references))
        return v.error;
    return references ? ext2_xattr_list(block, v.block_size, buffer, size, trusted) : 0;
}

static int change_xattr(Node* node, const XattrName& name, const void* value, size_t size,
                        unsigned flags, bool remove) {
    auto& v = volume(node);
    if (size > v.block_size)
        return -28;
    if (!v.begin())
        return v.error;
    uint8_t inode[inode_bytes], old[max_block_size], replacement[max_block_size];
    uint32_t references;
    if (!v.load_inode(node->inode, inode) || !v.xattr_block(inode, old, references))
        return v.finish(false);
    bool empty;
    int error = ext2_xattr_change(references ? old : nullptr, v.block_size, name, value, size,
                                  flags, remove, replacement, empty);
    if (error) {
        v.fail(error);
        return v.finish(false);
    }
    uint32_t block = u32(inode + 104), target = block;
    bool success = true;
    if (empty) {
        success = v.release_xattr(block, old, references) && v.add_blocks(inode, -1);
        target = 0;
    } else {
        if (references != 1) {
            target = v.allocate(false, (node->inode - 1) / v.inodes_per_group);
            success = target &&
                      (block ? v.release_xattr(block, old, references) : v.add_blocks(inode, 1));
        }
        success = success && v.write_block(target, replacement, 0);
        uint8_t header[1024];
        if (success && !(v.compatible & 8)) {
            success = v.super(header);
            if (success) {
                if (!v.revision) {
                    set32(header + 76, 1);
                    set32(header + 84, v.first_inode);
                    set16(header + 88, v.inode_size);
                }
                set32(header + 92, u32(header + 92) | 8);
                success = v.save_super(header);
            }
        }
    }
    if (success) {
        set32(inode + 104, target);
        set32(inode + 12, node_now().sec);
        success = v.save_inode(node->inode, inode);
    }
    int result = v.finish(success);
    if (success && !empty) {
        v.revision = 1;
        v.compatible |= 8;
    }
    return result;
}

static int setxattr(Node* node, const XattrName& name, const void* value, size_t size,
                    unsigned flags) {
    return change_xattr(node, name, value, size, flags, false);
}

static int removexattr(Node* node, const XattrName& name) {
    return change_xattr(node, name, nullptr, 0, 0, true);
}

static int readdir(Node* node, uint64_t cookie, DirectoryEntry& entry) {
    auto& v = volume(node);
    v.error = 0;
    uint8_t inode[inode_bytes], data[max_block_size], child[inode_bytes];
    if (!v.load_inode(node->inode, inode))
        return v.error;
    if (cookie > file_size(inode))
        return -22;
    while (cookie < file_size(inode)) {
        uint32_t block;
        uint64_t base = cookie - cookie % v.block_size;
        if (!directory_block(v, inode, base, block, data))
            return v.error;
        // Cookies are record offsets. Reject seeks into a record's payload.
        unsigned wanted = cookie % v.block_size, offset = 0;
        while (offset < wanted) {
            Record r;
            if (!record(v, data, offset, r))
                return v.error;
            offset += r.length;
        }
        if (offset != wanted)
            return -22;
        while (offset < v.block_size) {
            Record r;
            if (!record(v, data, offset, r))
                return v.error;
            cookie = base + offset + r.length;
            if (r.inode) {
                if (!v.load_inode(r.inode, child))
                    return v.error;
                entry.inode = r.inode;
                entry.next = cookie;
                entry.mode = u16(child);
                if (r.name_length == 2 && !memcmp(data + offset + 8, "..", 2) &&
                    node == node->mount->root)
                    entry.inode = directory_parent(node)->inode;
                memcpy(entry.name, data + offset + 8, r.name_length);
                entry.name[r.name_length] = 0;
                return 1;
            }
            offset += r.length;
        }
    }
    return 0;
}

static int sync(Mount* mount, Node*, bool) {
    auto& v = *static_cast<Volume*>(mount->data);
    if (!v.begin())
        return v.error;
    if (mount->readonly)
        return 0;
    for (auto entry = v.entries.first(); entry; entry = entry->next) {
        if (!entry->number || entry->node.hardlink)
            continue;
        uint8_t inode[inode_bytes];
        if (!v.load_inode(entry->number, inode))
            return v.error;
        bool orphan = !u16(inode + 26) && !node_referenced(&entry->node);
        if (!orphan && !entry->atime_dirty)
            continue;
        bool success =
            orphan ? v.delete_inode(entry->number, inode) : v.save_inode(entry->number, inode);
        int result = v.finish(success);
        if (result)
            return result;
    }
    return block_flush(v.device);
}

static int stats(Mount* mount, FilesystemStats& result) {
    auto& v = *static_cast<Volume*>(mount->data);
    v.error = 0;
    uint8_t header[1024];
    if (!v.super(header))
        return v.error;
    result = {0xef53, v.block_size, v.blocks, u32(header + 12), v.inodes, u32(header + 16)};
    return 0;
}

static int remount(Mount* mount, bool readonly) {
    auto& v = *static_cast<Volume*>(mount->data);
    if (readonly == mount->readonly)
        return 0;
    if (!readonly && block_info(v.device)->readonly)
        return -30;
    if (!readonly && !v.writable_safe)
        return -117;
    if (readonly)
        for (auto entry = v.entries.first(); entry; entry = entry->next)
            if (entry->number && !entry->node.hardlink && !entry->node.links)
                return -16;
    if (!v.begin())
        return v.error;
    return v.finish(v.state(readonly));
}

static int prepare_unmount(Mount* mount) {
    if (mount->readonly)
        return 0;
    auto& v = *static_cast<Volume*>(mount->data);
    if (!v.begin())
        return v.error;
    // Unmount has no live users; terminal shutdown never resumes the tasks.
    // Reclaim open unlinked inodes before declaring their filesystem clean.
    for (auto entry = v.entries.first(); entry; entry = entry->next) {
        if (!entry->number || entry->node.hardlink)
            continue;
        uint8_t inode[inode_bytes];
        if (!v.load_inode(entry->number, inode))
            return v.error;
        if (!u16(inode + 26)) {
            int result = v.finish(v.delete_inode(entry->number, inode));
            if (result)
                return result;
        }
    }
    return v.finish(v.state(true));
}

static void destroy(Mount* mount) {
    auto v = static_cast<Volume*>(mount->data);
    if (!v)
        return;
    v->discard();
    v->entries.clear();
    if (v->claimed)
        block_unclaim(v->device, v);
    release(v->groups);
    journal_close(v->journal);
    release(v->journal_map);
    release(v);
    mount->root = nullptr;
    mount->data = nullptr;
}

static int journal_read(void* context, uint32_t block, void* data) {
    auto& v = *static_cast<Volume*>(context);
    return block_read(v.device, uint64_t(block) * (v.block_size / sector_size), data,
                      v.block_size / sector_size);
}

static int journal_write(void* context, uint32_t block, const void* data) {
    auto& v = *static_cast<Volume*>(context);
    return block_write(v.device, uint64_t(block) * (v.block_size / sector_size), data,
                       v.block_size / sector_size, &v);
}

static int journal_flush(void* context) {
    return block_flush(static_cast<Volume*>(context)->device);
}

static int journal_overlay(void* context, uint32_t block, const void* data) {
    auto& v = *static_cast<Volume*>(context);
    return v.write_block(block, data, 5) ? 0 : v.error;
}

static bool open_journal(Volume& v, uint8_t* header, const BlockInfo& disk) {
    if (!(v.compatible & 4))
        return (u32(header + 96) & 4) ? v.fail(-95) : true;
    if (u32(header + 224) != 8 || u32(header + 228) || !disk.flush_supported)
        return v.fail(-95);
    uint8_t inode[inode_bytes], original_header[1024];
    memcpy(original_header, header, sizeof(original_header));
    if (!v.load_inode(8, inode))
        return false;
    if ((u16(inode) & 0170000) != regular_file || u16(inode + 26) != 1 || u16(inode + 2) ||
        u16(inode + 24) || u16(inode + 120) || u16(inode + 122) || u32(inode + 20) ||
        u32(inode + 32) || u32(inode + 104) || u32(inode + 108) || !file_size(inode) ||
        file_size(inode) % v.block_size || file_size(inode) / v.block_size < 1024 ||
        file_size(inode) / v.block_size > v.blocks)
        return v.fail(-95);
    v.journal_blocks = file_size(inode) / v.block_size;
    v.journal_map = static_cast<uint32_t*>(alloc(uint64_t(v.journal_blocks) * sizeof(uint32_t)));
    if (!v.journal_map)
        return v.fail(-12);
    for (uint32_t index = 0; index < v.journal_blocks; index++)
        if (!v.map_block(inode, index, false, v.journal_map[index], 0) || !v.journal_map[index])
            return v.fail();
    JournalStorage storage{
        &v,           v.block_size,  v.blocks,     v.journal_map, v.journal_blocks,
        journal_read, journal_write, journal_flush};
    int error;
    v.journal = journal_open(storage, header + 104, error);
    if (!v.journal)
        return v.fail(error);
    if (disk.readonly && (journal_pending(v.journal) || (u32(header + 96) & 4)))
        return v.fail(-30);
    error = journal_stage(v.journal, journal_overlay, &v);
    if (error)
        return v.fail(error);
    if (!v.super(header))
        return false;
    // Replay may update counters and ordinary mount state, but cannot change
    // the geometry, feature interpretation or identity of its own journal.
    uint8_t normalized[1024];
    memcpy(normalized, header, sizeof(normalized));
    constexpr unsigned counters[] = {12, 16, 44, 48}, state_fields[] = {52, 58};
    for (unsigned offset : counters)
        set32(normalized + offset, u32(original_header + offset));
    for (unsigned offset : state_fields)
        set16(normalized + offset, u16(original_header + offset));
    if ((u32(header + 96) & ~4u) != (u32(original_header + 96) & ~4u) ||
        (u32(header + 100) != u32(original_header + 100) &&
         u32(header + 100) != (u32(original_header + 100) | 2)))
        return v.fail();
    set32(normalized + 96, u32(original_header + 96));
    set32(normalized + 100, u32(original_header + 100));
    if (memcmp(normalized, original_header, sizeof(normalized)))
        return v.fail();
    for (unsigned group = 0; group < v.group_count; group++) {
        uint8_t descriptor[32];
        const auto& expected = v.groups[group];
        if (!v.descriptor(group, descriptor) || u32(descriptor) != expected.block_bitmap ||
            u32(descriptor + 4) != expected.inode_bitmap ||
            u32(descriptor + 8) != expected.inode_table)
            return v.fail();
    }
    uint8_t replayed[inode_bytes];
    if (!v.load_inode(8, replayed) || memcmp(inode, replayed, sizeof(inode)))
        return v.fail();
    for (uint32_t index = 0; index < v.journal_blocks; index++) {
        uint32_t block;
        if (!v.map_block(replayed, index, false, block, 0) || block != v.journal_map[index])
            return v.fail();
    }
    v.readonly_features = u32(header + 100);
    return true;
}

static bool layout(Volume& v, uint8_t* header, const BlockInfo& disk, bool check_dirty) {
    if (u16(header + 56) != 0xef53)
        return v.fail(-22);
    v.revision = u32(header + 76);
    if (v.revision > 1 || u32(header + 72) != 0 || u32(header + 24) > 2)
        return v.fail(-95);
    if (!v.revision && (u32(header + 92) || u32(header + 96) || u32(header + 100)))
        return v.fail(-95);
    v.block_size = 1024u << u32(header + 24);
    v.blocks = u32(header + 4);
    v.inodes = u32(header);
    v.first = u32(header + 20);
    v.blocks_per_group = u32(header + 32);
    v.inodes_per_group = u32(header + 40);
    v.inode_size = v.revision ? u16(header + 88) : 128;
    v.first_inode = v.revision ? u32(header + 84) : 11;
    v.compatible = v.revision ? u32(header + 92) : 0;
    uint32_t incompatible = v.revision ? u32(header + 96) : 0;
    v.readonly_features = v.revision ? u32(header + 100) : 0;
    v.typed_entries = incompatible & 2;
    if ((v.compatible & ~0x3cu) || (incompatible & ~6u) || (v.readonly_features & ~3u) ||
        (v.inode_size != 128 && v.inode_size != 256))
        return v.fail(-95);
    v.reserved_gdt = v.compatible & 16 ? u16(header + 206) : 0;
    if (v.first_inode != 11 || ((v.compatible & 16) && !(v.readonly_features & 1)))
        return v.fail(-95);
    if (v.first != (v.block_size == 1024 ? 1u : 0u) || v.blocks <= v.first || v.inodes < 11 ||
        uint64_t(v.blocks) * (v.block_size / sector_size) > disk.sectors || !v.blocks_per_group ||
        v.blocks_per_group > v.block_size * 8 || !v.inodes_per_group ||
        v.inodes_per_group > v.block_size * 8 ||
        v.inodes_per_group % (v.block_size / v.inode_size) ||
        u32(header + 28) != u32(header + 24) || u32(header + 36) != v.blocks_per_group ||
        u32(header + 8) > v.blocks || u32(header + 12) > v.blocks || u32(header + 16) > v.inodes)
        return v.fail();
    v.group_count = (uint64_t(v.blocks) - v.first + v.blocks_per_group - 1) / v.blocks_per_group;
    if (v.group_count > 4096)
        return v.fail(-95);
    if ((uint64_t(v.inodes) + v.inodes_per_group - 1) / v.inodes_per_group != v.group_count)
        return v.fail();
    v.gdt = v.first + 1;
    v.gdt_blocks = (uint64_t(v.group_count) * 32 + v.block_size - 1) / v.block_size;
    uint64_t table_blocks = uint64_t(v.inodes_per_group) * v.inode_size / v.block_size;
    if (v.gdt_blocks + v.reserved_gdt + 1 >= v.blocks_per_group)
        return v.fail();
    v.groups = (Group*)alloc(v.group_count * sizeof(Group));
    if (!v.groups)
        return v.fail(-12);
    uint8_t desc[32];
    for (unsigned group = 0; group < v.group_count; group++) {
        if (!v.descriptor(group, desc))
            return false;
        auto& g = v.groups[group];
        g = {uint32_t(uint64_t(group) * v.blocks_per_group + v.first),
             0,
             0,
             u32(desc),
             u32(desc + 4),
             u32(desc + 8)};
        g.blocks = min(v.blocks - g.first, v.blocks_per_group);
        g.inodes = min(v.inodes - group * v.inodes_per_group, v.inodes_per_group);
        uint64_t start =
            uint64_t(g.first) + (v.has_super(group) ? 1 + v.gdt_blocks + v.reserved_gdt : 0);
        uint64_t end = uint64_t(g.first) + g.blocks;
        if (g.block_bitmap < start || g.block_bitmap >= end || g.inode_bitmap < start ||
            g.inode_bitmap >= end || g.block_bitmap == g.inode_bitmap || g.inode_table < start ||
            g.inode_table + table_blocks > end ||
            (g.block_bitmap >= g.inode_table && g.block_bitmap - g.inode_table < table_blocks) ||
            (g.inode_bitmap >= g.inode_table && g.inode_bitmap - g.inode_table < table_blocks) ||
            u16(desc + 12) > g.blocks || u16(desc + 14) > g.inodes || u16(desc + 16) > g.inodes)
            return v.fail();
    }
    if (!open_journal(v, header, disk))
        return false;
    unsigned state = u16(header + 58);
    v.writable_safe =
        (state == 1 || ((check_dirty || v.journal) && state == 0)) && !u32(header + 232);
    if ((v.journal || check_dirty || !v.mount->readonly) && !v.writable_safe)
        return v.fail();
    auto recovery = Recovery::none;
    if (state == 0) {
        if (check_dirty && !v.mount->readonly)
            recovery = Recovery::checked;
        else if (v.journal && !disk.readonly)
            recovery = Recovery::journal;
    }
    return validate_volume(v, header, recovery);
}

} // namespace

const FilesystemOps ext2_ops = {lookup,   create,     link,    remove,          rename,   read,
                                write,    truncate,   setattr, readdir,         sync,     nullptr,
                                stats,    destroy,    remount, prepare_unmount, getxattr, listxattr,
                                setxattr, removexattr};

int ext2_mount(Mount* mount, Node* device, bool check_dirty) {
    auto info = block_info(device->device_id);
    if (!info)
        return -19;
    if (!mount->readonly && info->readonly)
        return -30;
    auto v = (Volume*)alloc(sizeof(Volume));
    if (!v)
        return -12;
    memset(v, 0, sizeof(Volume));
    v->mount = mount;
    v->device = device->device_id;
    mount->data = v;
    int result = block_claim(v->device, v);
    if (result) {
        destroy(mount);
        return result;
    }
    v->claimed = true;
    uint8_t header[1024], inode[inode_bytes];
    result = block_read(v->device, 2, header, 2);
    if (!result && !layout(*v, header, *info, check_dirty))
        result = v->error;
    if (!result && !v->load_inode(2, inode))
        result = v->error;
    if (!result) {
        auto root = v->reserve_entry();
        if (!root)
            result = v->error;
        else
            mount->root = v->add_entry(root, 2, nullptr, "", inode);
    }
    // Validate the disk through actual backend reads before enabling the cache.
    if (!result)
        result = block_enable_cache(v->device, v->block_size / sector_size, v);
    if (!result && !mount->readonly) {
        set16(header + 58, u16(header + 58) & ~1u);
        if (v->journal)
            set32(header + 96, u32(header + 96) | 4u);
        set32(header + 44, node_now().sec);
        if (u16(header + 52) != UINT16_MAX)
            set16(header + 52, u16(header + 52) + 1);
        result = v->finish(v->save_super(header));
    }
    if (result)
        destroy(mount);
    return result;
}
} // namespace ax
