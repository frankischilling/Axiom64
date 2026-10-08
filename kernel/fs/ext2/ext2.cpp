// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/ext2/ext2.hpp"
#include "drivers/block/block.hpp"
#include "drivers/platform/devices.hpp"

namespace ax {
namespace {
constexpr size_t max_block_size = 4096, inode_bytes = 128;
constexpr unsigned max_changes = 4096, max_entries = 8192, cached_blocks = 128;

static uint16_t u16(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}

static uint32_t u32(const uint8_t* p) {
    return uint32_t(u16(p)) | (uint32_t(u16(p + 2)) << 16);
}

static void set16(uint8_t* p, uint16_t v) {
    p[0] = v;
    p[1] = v >> 8;
}

static void set32(uint8_t* p, uint32_t v) {
    set16(p, v);
    set16(p + 2, v >> 16);
}

static bool bit(const uint8_t* p, uint32_t n) {
    return p[n / 8] & (1u << (n % 8));
}

static void setbit(uint8_t* p, uint32_t n, bool value) {
    if (value)
        p[n / 8] |= 1u << (n % 8);
    else
        p[n / 8] &= ~(1u << (n % 8));
}

static uint64_t file_size(const uint8_t* inode) {
    return u32(inode + 4) |
           ((u16(inode) & 0170000) == regular_file ? uint64_t(u32(inode + 108)) << 32 : 0);
}

static uint8_t file_type(uint32_t mode) {
    switch (mode & 0170000) {
    case regular_file:
        return 1;
    case directory:
        return 2;
    case character:
        return 3;
    case block_device:
        return 4;
    case 0010000:
        return 5;
    case 0140000:
        return 6;
    case symlink:
        return 7;
    default:
        return 0;
    }
}

struct Group {
    uint32_t first, blocks, inodes, block_bitmap, inode_bitmap, inode_table;
};

struct Change {
    Change* next;
    uint32_t block;
    unsigned rank;
    uint8_t data[max_block_size];
};

struct Entry {
    Node node;
    Entry* next;
    uint32_t number;
    bool atime_dirty;
};

struct CachedBlock {
    uint32_t block;
    bool valid;
    uint8_t data[max_block_size];
};

struct Volume {
    Mount* mount;
    unsigned device, block_size, inode_size, group_count, change_count, entry_count;
    uint32_t blocks, inodes, first, blocks_per_group, inodes_per_group, first_inode;
    uint32_t gdt, gdt_blocks, reserved_gdt, revision, compatible, readonly_features;
    bool typed_entries, claimed, writable_safe;
    Group* groups;
    Change* changes;
    Entry* entries;
    CachedBlock* cache;
    uint32_t touched[64];
    unsigned touched_count;
    int error;

    bool fail(int code = -117) {
        if (!error)
            error = code;
        return false;
    }

    bool has_super(unsigned group) const {
        if (!(readonly_features & 1) || group < 2)
            return true;
        constexpr unsigned bases[] = {3, 5, 7};
        for (unsigned base : bases) {
            unsigned n = group;
            while (n % base == 0)
                n /= base;
            if (n == 1)
                return true;
        }
        return false;
    }

    bool metadata(uint32_t block) const {
        if (block < first || block >= blocks)
            return true;
        auto group = unsigned((block - first) / blocks_per_group);
        auto& g = groups[group];
        uint64_t table_blocks =
            (uint64_t(inodes_per_group) * inode_size + block_size - 1) / block_size;
        return block == g.block_bitmap || block == g.inode_bitmap ||
               (block >= g.inode_table && block - g.inode_table < table_blocks) ||
               (has_super(group) && block - g.first < 1 + gdt_blocks + reserved_gdt);
    }

    bool read_block(uint32_t block, void* data) {
        if (block >= blocks)
            return fail();
        for (auto change = changes; change; change = change->next)
            if (change->block == block) {
                memcpy(data, change->data, block_size);
                return true;
            }
        auto cached = cache ? &cache[block % cached_blocks] : nullptr;
        if (cached && cached->valid && cached->block == block) {
            memcpy(data, cached->data, block_size);
            return true;
        }
        int result = block_read(device, uint64_t(block) * (block_size / sector_size), data,
                                block_size / sector_size);
        if (result)
            return fail(result);
        if (cached) {
            cached->block = block;
            cached->valid = true;
            memcpy(cached->data, data, block_size);
        }
        return true;
    }

    bool write_block(uint32_t block, const void* data, unsigned rank) {
        if (block >= blocks)
            return fail();
        for (auto change = changes; change; change = change->next)
            if (change->block == block) {
                memcpy(change->data, data, block_size);
                change->rank = max(change->rank, rank);
                return true;
            }
        if (change_count == max_changes)
            return fail(-12);
        auto change = (Change*)alloc(sizeof(Change));
        if (!change)
            return fail(-12);
        change->next = changes;
        change->block = block;
        change->rank = rank;
        memcpy(change->data, data, block_size);
        changes = change;
        change_count++;
        return true;
    }

    void discard() {
        while (changes) {
            auto next = changes->next;
            release(changes);
            changes = next;
        }
        change_count = touched_count = 0;
    }

    bool super(uint8_t* data) {
        uint8_t block[max_block_size];
        if (!read_block(1024 / block_size, block))
            return false;
        memcpy(data, block + (1024 % block_size), 1024);
        return true;
    }

    bool save_super(const uint8_t* data) {
        uint8_t block[max_block_size];
        if (!read_block(1024 / block_size, block))
            return false;
        memcpy(block + (1024 % block_size), data, 1024);
        return write_block(1024 / block_size, block, 5);
    }

    bool descriptor(unsigned group, uint8_t* data) {
        uint8_t block[max_block_size];
        if (group >= group_count || !read_block(gdt + group * 32 / block_size, block))
            return fail();
        memcpy(data, block + (group * 32 % block_size), 32);
        return true;
    }

    bool save_descriptor(unsigned group, const uint8_t* data) {
        uint8_t block[max_block_size];
        if (group >= group_count || !read_block(gdt + group * 32 / block_size, block))
            return fail();
        memcpy(block + (group * 32 % block_size), data, 32);
        return write_block(gdt + group * 32 / block_size, block, 4);
    }

    bool allocated(uint32_t number, bool inode) {
        if (!number || (inode ? number > inodes : number < first || number >= blocks))
            return fail();
        uint32_t index = inode ? number - 1 : number - first;
        unsigned per_group = inode ? inodes_per_group : blocks_per_group;
        auto& group = groups[index / per_group];
        uint8_t bitmap[max_block_size];
        if (!read_block(inode ? group.inode_bitmap : group.block_bitmap, bitmap))
            return false;
        return bit(bitmap, index % per_group) ? true : fail();
    }

    bool data_block(uint32_t block) {
        return !metadata(block) ? allocated(block, false) : fail();
    }

    Entry* canonical(uint32_t number) {
        for (auto entry = entries; entry; entry = entry->next)
            if (entry->number == number && !entry->node.hardlink)
                return entry;
        return nullptr;
    }

    bool load_inode(uint32_t number, uint8_t* data, bool check = true) {
        if (!number || number > inodes || (check && !allocated(number, true)))
            return fail();
        uint32_t index = number - 1;
        uint64_t offset = uint64_t(index % inodes_per_group) * inode_size;
        uint8_t block[max_block_size];
        if (!read_block(groups[index / inodes_per_group].inode_table + offset / block_size, block))
            return false;
        memcpy(data, block + offset % block_size, inode_bytes);
        if (auto cached = canonical(number); cached && cached->atime_dirty)
            set32(data + 8, cached->node.atime.sec);
        return true;
    }

    bool save_inode(uint32_t number, const uint8_t* data, bool clear = false) {
        uint32_t index = number - 1;
        uint64_t offset = uint64_t(index % inodes_per_group) * inode_size;
        uint8_t block[max_block_size];
        if (!number || number > inodes ||
            !read_block(groups[index / inodes_per_group].inode_table + offset / block_size, block))
            return fail();
        if (clear)
            memset(block + offset % block_size, 0, inode_size);
        memcpy(block + offset % block_size, data, inode_bytes);
        if (!write_block(groups[index / inodes_per_group].inode_table + offset / block_size, block,
                         2))
            return false;
        for (unsigned i = 0; i < touched_count; i++)
            if (touched[i] == number)
                return true;
        if (touched_count == sizeof(touched) / sizeof(touched[0]))
            return fail(-12);
        touched[touched_count++] = number;
        return true;
    }

    void populate(Entry* entry, const uint8_t* data) {
        auto& node = entry->node;
        node.mode = u16(data);
        node.uid = u16(data + 2) | (uint32_t(u16(data + 120)) << 16);
        node.gid = u16(data + 24) | (uint32_t(u16(data + 122)) << 16);
        node.links = u16(data + 26);
        node.size = file_size(data);
        node.allocated_blocks = u32(data + 28);
        node.atime = {int32_t(u32(data + 8)), 0};
        node.ctime = {int32_t(u32(data + 12)), 0};
        node.mtime = {int32_t(u32(data + 16)), 0};
        entry->atime_dirty = false;
        if (!node.mode)
            entry->number = 0;
    }

    bool flush() {
        for (unsigned i = 0; i < touched_count; i++) {
            if (auto entry = canonical(touched[i])) {
                uint8_t inode[inode_bytes];
                if (!load_inode(touched[i], inode, false))
                    return false;
                populate(entry, inode);
                for (auto alias = entries; alias; alias = alias->next)
                    if (alias->node.hardlink == &entry->node)
                        alias->node.mode = entry->node.mode;
            }
        }
        // Keep the complete overlay after an error; a later sync retries every write.
        for (unsigned rank = 0; rank <= 5; rank++)
            for (auto change = changes; change; change = change->next)
                if (change->rank == rank) {
                    // Invalidate before submission, including failed or partial writes.
                    // Pending changes take precedence until their flush completes.
                    if (cache) {
                        auto& cached = cache[change->block % cached_blocks];
                        if (cached.block == change->block)
                            cached.valid = false;
                    }
                    int result =
                        block_write(device, uint64_t(change->block) * (block_size / sector_size),
                                    change->data, block_size / sector_size, this);
                    if (result)
                        return fail(result);
                }
        if (changes) {
            int result = block_flush(device);
            if (result)
                return fail(result);
        }
        discard();
        return true;
    }

    bool begin() {
        error = 0;
        return flush();
    }

    int finish(bool success) {
        if (!success) {
            int result = error ? error : -117;
            discard();
            return result;
        }
        return flush() ? 0 : error;
    }

    Entry* reserve_entry() {
        if (entry_count == max_entries) {
            fail(-12);
            return nullptr;
        }
        auto entry = (Entry*)alloc(sizeof(Entry));
        if (!entry) {
            fail(-12);
            return nullptr;
        }
        memset(entry, 0, sizeof(Entry));
        return entry;
    }

    Node* add_entry(Entry* entry, uint32_t number, Node* parent, const char* name,
                    const uint8_t* inode) {
        entry->number = number;
        entry->node.inode = number;
        entry->node.parent = parent;
        entry->node.mount = mount;
        entry->node.filesystem_data = entry;
        memcpy(entry->node.name, name, strlen(name) + 1);
        if (auto original = canonical(number); original && (u16(inode) & 0170000) != directory) {
            entry->node.hardlink = &original->node;
            entry->node.mode = original->node.mode;
        } else
            populate(entry, inode);
        entry->next = entries;
        entries = entry;
        entry_count++;
        return &entry->node;
    }

    bool counts(unsigned group, bool inode, int delta, int directory_delta = 0) {
        uint8_t desc[32], header[1024];
        if (!descriptor(group, desc) || !super(header))
            return false;
        unsigned field = inode ? 14 : 12, global = inode ? 16 : 12;
        int64_t count = int64_t(u16(desc + field)) + delta;
        int64_t total = int64_t(u32(header + global)) + delta;
        int64_t dirs = int64_t(u16(desc + 16)) + directory_delta;
        if (count < 0 || count > (inode ? groups[group].inodes : groups[group].blocks) ||
            total < 0 || total > (inode ? inodes : blocks) || dirs < 0 ||
            dirs > groups[group].inodes)
            return fail();
        set16(desc + field, count);
        set16(desc + 16, dirs);
        set32(header + global, total);
        set32(header + 48, node_now().sec);
        return save_descriptor(group, desc) && save_super(header);
    }

    uint32_t allocate(bool inode, unsigned preferred, bool dir = false) {
        uint8_t bitmap[max_block_size];
        for (unsigned step = 0; step < group_count; step++) {
            unsigned index = (preferred + step) % group_count;
            auto& group = groups[index];
            uint32_t bitmap_block = inode ? group.inode_bitmap : group.block_bitmap;
            if (!read_block(bitmap_block, bitmap))
                return 0;
            uint32_t count = inode ? group.inodes : group.blocks;
            for (uint32_t i = 0; i < count; i++) {
                uint32_t number = inode ? index * inodes_per_group + i + 1 : group.first + i;
                if (bit(bitmap, i) || (inode && number < first_inode))
                    continue;
                if (!inode && metadata(number)) {
                    fail();
                    return 0;
                }
                setbit(bitmap, i, true);
                if (!write_block(bitmap_block, bitmap, 4) || !counts(index, inode, -1, dir ? 1 : 0))
                    return 0;
                if (!inode) {
                    uint8_t zero[max_block_size]{};
                    if (!write_block(number, zero, 0))
                        return 0;
                }
                return number;
            }
        }
        fail(-28);
        return 0;
    }

    bool free_number(uint32_t number, bool inode, bool dir = false) {
        if ((inode && number < first_inode) || (!inode && metadata(number)) ||
            !allocated(number, inode))
            return fail();
        uint32_t offset = inode ? number - 1 : number - first;
        unsigned per_group = inode ? inodes_per_group : blocks_per_group,
                 index = offset / per_group;
        uint32_t bitmap_block = inode ? groups[index].inode_bitmap : groups[index].block_bitmap;
        uint8_t bitmap[max_block_size];
        if (!read_block(bitmap_block, bitmap))
            return false;
        setbit(bitmap, offset % per_group, false);
        return write_block(bitmap_block, bitmap, 4) && counts(index, inode, 1, dir ? -1 : 0);
    }

    uint64_t capacity() const {
        uint64_t n = block_size / 4;
        return (12 + n + n * n + n * n * n) * block_size;
    }

    bool add_blocks(uint8_t* inode, int delta) {
        int64_t count = int64_t(u32(inode + 28)) + int64_t(delta) * (block_size / sector_size);
        if (count < 0 || count > UINT32_MAX)
            return fail(-27);
        set32(inode + 28, count);
        return true;
    }

    bool map_block(uint8_t* inode, uint64_t logical, bool create, uint32_t& result,
                   unsigned preferred) {
        uint64_t n = block_size / 4, index = logical, span = 1;
        unsigned slot, depth;
        if (index < 12) {
            slot = index;
            depth = 0;
        } else {
            index -= 12;
            if (index < n) {
                slot = 12;
                depth = 1;
            } else {
                index -= n;
                if (index < n * n) {
                    slot = 13;
                    depth = 2;
                    span = n;
                } else {
                    index -= n * n;
                    if (index >= n * n * n)
                        return fail(-27);
                    slot = 14;
                    depth = 3;
                    span = n * n;
                }
            }
        }
        uint32_t pointer = u32(inode + 40 + slot * 4);
        if (!pointer && create) {
            pointer = allocate(false, preferred);
            if (!pointer || !add_blocks(inode, 1))
                return false;
            set32(inode + 40 + slot * 4, pointer);
        }
        if (!pointer) {
            result = 0;
            return true;
        }
        if (!data_block(pointer))
            return false;
        uint8_t block[max_block_size];
        while (depth) {
            if (!read_block(pointer, block))
                return false;
            uint32_t position = index / span;
            uint32_t child = u32(block + position * 4);
            if (!child && create) {
                child = allocate(false, preferred);
                if (!child || !add_blocks(inode, 1))
                    return false;
                set32(block + position * 4, child);
                if (!write_block(pointer, block, 1))
                    return false;
            }
            if (!child) {
                result = 0;
                return true;
            }
            if (!data_block(child))
                return false;
            pointer = child;
            index %= span;
            span /= n;
            depth--;
        }
        result = pointer;
        return true;
    }

    bool prune(uint32_t& pointer, unsigned depth, uint64_t base, uint64_t keep, uint8_t* inode) {
        if (!pointer)
            return true;
        if (!data_block(pointer))
            return false;
        uint64_t span = 1;
        for (unsigned i = 0; i < depth; i++)
            span *= block_size / 4;
        if (base + span <= keep)
            return true;
        if (!depth) {
            if (!free_number(pointer, false) || !add_blocks(inode, -1))
                return false;
            pointer = 0;
            return true;
        }
        uint8_t data[max_block_size];
        if (!read_block(pointer, data))
            return false;
        bool any = false, changed = false;
        for (unsigned i = 0; i < block_size / 4; i++) {
            uint32_t child = u32(data + i * 4), old = child;
            if (!prune(child, depth - 1, base + uint64_t(i) * (span / (block_size / 4)), keep,
                       inode))
                return false;
            if (child != old) {
                set32(data + i * 4, child);
                changed = true;
            }
            any |= child != 0;
        }
        if (!any) {
            if (!free_number(pointer, false) || !add_blocks(inode, -1))
                return false;
            pointer = 0;
            return true;
        }
        return !changed || write_block(pointer, data, 1);
    }

    bool size(uint8_t* inode, uint64_t length) {
        if (length > capacity() || int64_t(length) < 0)
            return fail(-27);
        if (length > INT32_MAX) {
            if (revision == 0)
                return fail(-27);
            uint8_t header[1024];
            if (!super(header))
                return false;
            set32(header + 100, u32(header + 100) | 2);
            if (!save_super(header))
                return false;
        }
        uint64_t old = file_size(inode), keep = (length + block_size - 1) / block_size;
        if (length < old) {
            uint64_t base = 0;
            for (unsigned slot = 0; slot < 15; slot++) {
                unsigned depth = slot < 12 ? 0 : slot - 11;
                uint64_t span = 1;
                for (unsigned i = 0; i < depth; i++)
                    span *= block_size / 4;
                uint32_t pointer = u32(inode + 40 + slot * 4);
                if (!prune(pointer, depth, base, keep, inode))
                    return false;
                set32(inode + 40 + slot * 4, pointer);
                base += span;
            }
        }
        uint64_t tail = min(old, length);
        if (tail % block_size) {
            uint32_t block;
            if (!map_block(inode, tail / block_size, false, block, 0))
                return false;
            if (block) {
                uint8_t data[max_block_size];
                if (!read_block(block, data))
                    return false;
                memset(data + tail % block_size, 0, block_size - tail % block_size);
                if (!write_block(block, data, 0))
                    return false;
            }
        }
        set32(inode + 4, length);
        if ((u16(inode) & 0170000) == regular_file)
            set32(inode + 108, length >> 32);
        return true;
    }

    bool delete_inode(uint32_t number, uint8_t* inode) {
        bool dir = (u16(inode) & 0170000) == directory;
        if (!((u16(inode) & 0170000) == symlink && !u32(inode + 28)) && !size(inode, 0))
            return false;
        memset(inode, 0, inode_bytes);
        return save_inode(number, inode, true) && free_number(number, true, dir);
    }

    bool state(bool clean) {
        uint8_t header[1024];
        if (!super(header))
            return false;
        set16(header + 58, clean ? u16(header + 58) | 1 : u16(header + 58) & ~1u);
        set32(header + 48, node_now().sec);
        return save_super(header);
    }
};

static Volume& volume(Node* node) {
    return *static_cast<Volume*>(node->mount->data);
}

struct Record {
    uint32_t inode;
    unsigned length, name_length;
    uint8_t type;
};

static bool record(Volume& v, const uint8_t* data, unsigned offset, Record& r) {
    if (offset > v.block_size - 8)
        return v.fail();
    r = {u32(data + offset), u16(data + offset + 4),
         unsigned(v.typed_entries ? data[offset + 6] : u16(data + offset + 6)),
         uint8_t(v.typed_entries ? data[offset + 7] : 0)};
    if (r.length < 8 || r.length % 4 || r.length > v.block_size - offset || r.name_length > 255 ||
        r.name_length > r.length - 8 || r.inode > v.inodes || r.type > 7)
        return v.fail();
    if (r.inode)
        for (unsigned i = 0; i < r.name_length; i++)
            if (!data[offset + 8 + i] || data[offset + 8 + i] == '/')
                return v.fail();
    return r.inode && !r.name_length ? v.fail() : true;
}

static bool directory_block(Volume& v, uint8_t* inode, uint64_t offset, uint32_t& block,
                            uint8_t* data) {
    if ((u16(inode) & 0170000) != directory || file_size(inode) % v.block_size)
        return v.fail();
    if (!v.map_block(inode, offset / v.block_size, false, block, 0))
        return false;
    return block ? v.read_block(block, data) : v.fail();
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
        set32(inode + 20, node_now().sec);
    }
    return v.save_inode(node->inode, inode);
}

static int lookup(Node* parent, const char* name, Node*& result) {
    auto& v = volume(parent);
    v.error = 0;
    uint32_t number;
    if (!locate(v, parent->inode, name, number))
        return v.error;
    for (auto entry = v.entries; entry; entry = entry->next)
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
        release(entry);
        return v.error;
    }
    bool dir = (mode & 0170000) == directory;
    uint32_t number = v.allocate(true, (parent->inode - 1) / v.inodes_per_group, dir);
    uint8_t inode[inode_bytes]{};
    set16(inode, mode);
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
        if (length <= 60)
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
        release(entry);
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
    if ((node->mode & 0170000) == symlink && !u32(inode + 28)) {
        if (node->size > 60)
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

static int setattr(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime) {
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
        set32(inode + 8, atime.sec);
        set32(inode + 16, mtime.sec);
        set32(inode + 12, node_now().sec);
        success = v.save_inode(node->inode, inode);
    }
    return v.finish(success);
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
    for (auto entry = v.entries; entry; entry = entry->next) {
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
        for (auto entry = v.entries; entry; entry = entry->next)
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
    for (auto entry = v.entries; entry; entry = entry->next) {
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
    while (v->entries) {
        auto next = v->entries->next;
        release(v->entries);
        v->entries = next;
    }
    if (v->claimed)
        block_unclaim(v->device, v);
    release(v->groups);
    release(v->cache);
    release(v);
    mount->root = nullptr;
    mount->data = nullptr;
}

// The mount scan checks allocation and ownership before any writable I/O. It
// does not repair a damaged volume; recovery remains the filesystem checker's job.
struct Validation {
    Volume& v;
    uint8_t *block_bits = nullptr, *inode_bits = nullptr, *owners = nullptr;
    uint16_t *modes = nullptr, *links = nullptr;
    uint32_t *references = nullptr, *parents = nullptr, *dotdots = nullptr;
    uint8_t inode_table[max_block_size]{};
    uint32_t cached_table = UINT32_MAX;

    explicit Validation(Volume& value) : v(value) {
    }

    ~Validation() {
        release(block_bits);
        release(inode_bits);
        release(owners);
        release(modes);
        release(links);
        release(references);
        release(parents);
        release(dotdots);
    }

    bool allocate() {
        size_t block_bytes = (uint64_t(v.blocks) + 7) / 8;
        size_t inode_count = uint64_t(v.inodes) + 1, inode_bytes = (inode_count + 7) / 8;
        block_bits = (uint8_t*)alloc(block_bytes);
        inode_bits = (uint8_t*)alloc(inode_bytes);
        owners = (uint8_t*)alloc(block_bytes);
        modes = (uint16_t*)alloc(inode_count * sizeof(uint16_t));
        links = (uint16_t*)alloc(inode_count * sizeof(uint16_t));
        references = (uint32_t*)alloc(inode_count * sizeof(uint32_t));
        parents = (uint32_t*)alloc(inode_count * sizeof(uint32_t));
        dotdots = (uint32_t*)alloc(inode_count * sizeof(uint32_t));
        if (!block_bits || !inode_bits || !owners || !modes || !links || !references || !parents ||
            !dotdots)
            return v.fail(-12);
        memset(block_bits, 0, block_bytes);
        memset(owners, 0, block_bytes);
        memset(inode_bits, 0, inode_bytes);
        memset(modes, 0, inode_count * sizeof(uint16_t));
        memset(links, 0, inode_count * sizeof(uint16_t));
        memset(references, 0, inode_count * sizeof(uint32_t));
        memset(parents, 0, inode_count * sizeof(uint32_t));
        memset(dotdots, 0, inode_count * sizeof(uint32_t));
        parents[2] = 2;
        return true;
    }

    bool bitmaps(const uint8_t* header) {
        uint64_t free_blocks = 0, free_inodes = 0;
        uint8_t data[max_block_size], desc[32];
        for (unsigned group = 0; group < v.group_count; group++) {
            auto& g = v.groups[group];
            if (!v.descriptor(group, desc) || !v.read_block(g.block_bitmap, data))
                return false;
            uint32_t free = 0;
            for (unsigned i = 0; i < v.block_size * 8; i++) {
                if (i >= g.blocks) {
                    if (!bit(data, i))
                        return v.fail();
                    continue;
                }
                bool used = bit(data, i);
                setbit(block_bits, g.first + i, used);
                if (v.metadata(g.first + i) && !used)
                    return v.fail();
                if (!used)
                    free++;
            }
            if (free != u16(desc + 12))
                return v.fail();
            free_blocks += free;
            if (!v.read_block(g.inode_bitmap, data))
                return false;
            free = 0;
            for (unsigned i = 0; i < v.block_size * 8; i++) {
                if (i >= g.inodes) {
                    if (!bit(data, i))
                        return v.fail();
                    continue;
                }
                uint32_t number = group * v.inodes_per_group + i + 1;
                bool used = bit(data, i);
                setbit(inode_bits, number, used);
                if (number < v.first_inode && !used)
                    return v.fail();
                if (!used)
                    free++;
            }
            if (free != u16(desc + 14))
                return v.fail();
            free_inodes += free;
        }
        return free_blocks == u32(header + 12) && free_inodes == u32(header + 16) ? true : v.fail();
    }

    bool inode(uint32_t number, uint8_t* data) {
        uint32_t index = number - 1;
        uint64_t offset = uint64_t(index % v.inodes_per_group) * v.inode_size;
        uint32_t block = v.groups[index / v.inodes_per_group].inode_table + offset / v.block_size;
        if (block != cached_table) {
            if (!v.read_block(block, inode_table))
                return false;
            cached_table = block;
        }
        memcpy(data, inode_table + offset % v.block_size, ax::inode_bytes);
        return true;
    }

    bool reserved_descriptor(uint32_t block) {
        auto group = (block - v.first) / v.blocks_per_group;
        uint32_t offset = block - v.groups[group].first;
        return v.has_super(group) && offset >= 1 + v.gdt_blocks &&
               offset < 1 + v.gdt_blocks + v.reserved_gdt;
    }

    bool tree(uint32_t block, unsigned depth, bool resize, uint64_t base, uint64_t limit,
              uint64_t& count, uint64_t& leaves) {
        if (!block)
            return true;
        if (!resize && base >= limit)
            return v.fail();
        if (block < v.first || block >= v.blocks || !bit(block_bits, block) || bit(owners, block))
            return v.fail();
        if (v.metadata(block) && !(resize && reserved_descriptor(block)))
            return v.fail();
        setbit(owners, block, true);
        count++;
        if (!depth) {
            leaves++;
            return true;
        }
        uint8_t data[max_block_size];
        if (!v.read_block(block, data))
            return false;
        uint64_t span = 1;
        for (unsigned i = 1; i < depth; i++)
            span *= v.block_size / 4;
        for (unsigned i = 0; i < v.block_size / 4; i++)
            if (!tree(u32(data + i * 4), depth - 1, resize, base + i * span, limit, count, leaves))
                return false;
        return true;
    }

    bool inode_maps() {
        uint8_t data[ax::inode_bytes], desc[32];
        for (unsigned group = 0; group < v.group_count; group++) {
            unsigned dirs = 0;
            auto& g = v.groups[group];
            for (unsigned i = 0; i < g.inodes; i++) {
                uint32_t number = group * v.inodes_per_group + i + 1;
                if (!bit(inode_bits, number))
                    continue;
                if (!inode(number, data))
                    return false;
                uint32_t mode = u16(data), type = mode & 0170000;
                bool reserved = number < v.first_inode && number != 2;
                bool resize = number == 7 && (v.compatible & 16);
                if (reserved && !resize) {
                    if (mode || file_size(data) || u32(data + 28))
                        return v.fail(-95);
                    for (unsigned slot = 0; slot < 15; slot++)
                        if (u32(data + 40 + slot * 4))
                            return v.fail(-95);
                    continue;
                }
                if (type != regular_file && type != directory && type != symlink && type != 0140000)
                    return v.fail(-95);
                // Inode flags, ACL blocks and fragments need separate policy/layout support.
                if (u32(data + 32) || u32(data + 104) || u32(data + 112) || u16(data + 116) ||
                    (type != regular_file && u32(data + 108)))
                    return v.fail(-95);
                uint64_t length = file_size(data), count = 0, leaves = 0;
                if (length > v.capacity() || (type == regular_file && length > INT32_MAX &&
                                              (v.revision == 0 || !(v.readonly_features & 2))))
                    return v.fail();
                if (type == directory && (!length || length % v.block_size ||
                                          length > uint64_t(v.blocks) * v.block_size))
                    return v.fail();
                if (type == symlink && (!length || length > 4095))
                    return v.fail();
                if (type == 0140000 && (length || u32(data + 28)))
                    return v.fail();
                if (resize) {
                    if (type != regular_file || !u32(data + 92))
                        return v.fail();
                    for (unsigned slot = 0; slot < 15; slot++)
                        if (slot != 13 && u32(data + 40 + slot * 4))
                            return v.fail();
                }
                bool fast_link = type == symlink && !u32(data + 28);
                if (fast_link && length > 60)
                    return v.fail();
                if (!fast_link) {
                    uint64_t base = 0, limit = (length + v.block_size - 1) / v.block_size;
                    for (unsigned slot = 0; slot < 15; slot++) {
                        unsigned depth = slot < 12 ? 0 : slot - 11;
                        if (!tree(u32(data + 40 + slot * 4), depth, resize, base, limit, count,
                                  leaves))
                            return false;
                        uint64_t span = 1;
                        for (unsigned i = 0; i < depth; i++)
                            span *= v.block_size / 4;
                        base += span;
                    }
                }
                if (count * (v.block_size / sector_size) != u32(data + 28))
                    return v.fail();
                if (type == directory && leaves != length / v.block_size)
                    return v.fail();
                if (!reserved) {
                    if (!u16(data + 26) || u32(data + 20))
                        return v.fail();
                    modes[number] = mode;
                    links[number] = u16(data + 26);
                    if (type == directory)
                        dirs++;
                }
            }
            if (!v.descriptor(group, desc))
                return false;
            if (dirs != u16(desc + 16))
                return v.fail();
        }
        for (uint32_t block = v.first; block < v.blocks; block++)
            if (bit(block_bits, block) && !v.metadata(block) && !bit(owners, block))
                return v.fail();
        return (modes[2] & 0170000) == directory ? true : v.fail();
    }

    struct Name {
        uint64_t hash, position;
    };

    bool check_directory(uint32_t number) {
        uint8_t disk_inode[ax::inode_bytes], data[max_block_size];
        if (!inode(number, disk_inode))
            return false;
        size_t slots = 8;
        while (slots < file_size(disk_inode) / 12 * 2)
            slots *= 2;
        auto names = (Name*)alloc(slots * sizeof(Name));
        if (!names)
            return v.fail(-12);
        memset(names, 0, slots * sizeof(Name));
        bool success = true, dot = false, dotdot = false;
        for (uint64_t base = 0; success && base < file_size(disk_inode); base += v.block_size) {
            uint32_t block;
            success = directory_block(v, disk_inode, base, block, data);
            for (unsigned offset = 0; success && offset < v.block_size;) {
                Record r;
                if (!record(v, data, offset, r)) {
                    success = false;
                    break;
                }
                if (r.inode) {
                    if (!bit(inode_bits, r.inode) || !modes[r.inode] ||
                        (r.type && r.type != file_type(modes[r.inode]))) {
                        success = v.fail();
                        break;
                    }
                    bool self = r.name_length == 1 && data[offset + 8] == '.';
                    bool up = r.name_length == 2 && !memcmp(data + offset + 8, "..", 2);
                    if (self) {
                        if (dot || r.inode != number) {
                            success = v.fail();
                            break;
                        }
                        dot = true;
                    } else if (up) {
                        if (dotdot || (modes[r.inode] & 0170000) != ax::directory) {
                            success = v.fail();
                            break;
                        }
                        dotdot = true;
                        dotdots[number] = r.inode;
                    } else if ((modes[r.inode] & 0170000) == ax::directory) {
                        if (parents[r.inode]) {
                            success = v.fail();
                            break;
                        }
                        parents[r.inode] = number;
                    }
                    if (++references[r.inode] > UINT16_MAX) {
                        success = v.fail();
                        break;
                    }
                    uint64_t hash = 14695981039346656037ull;
                    for (unsigned i = 0; i < r.name_length; i++)
                        hash = (hash ^ data[offset + 8 + i]) * 1099511628211ull;
                    size_t slot = hash & (slots - 1);
                    while (names[slot].position) {
                        if (names[slot].hash == hash) {
                            uint8_t previous[max_block_size];
                            uint32_t old_block;
                            uint64_t position = names[slot].position - 1;
                            if (!directory_block(v, disk_inode, position, old_block, previous)) {
                                success = false;
                                break;
                            }
                            Record old;
                            if (!record(v, previous, position % v.block_size, old)) {
                                success = false;
                                break;
                            }
                            if (old.name_length == r.name_length &&
                                !memcmp(previous + position % v.block_size + 8, data + offset + 8,
                                        r.name_length)) {
                                success = v.fail();
                                break;
                            }
                        }
                        slot = (slot + 1) & (slots - 1);
                    }
                    if (!success)
                        break;
                    names[slot] = {hash, base + offset + 1};
                }
                offset += r.length;
            }
        }
        release(names);
        return success && dot && dotdot ? true : v.fail();
    }

    bool directories() {
        for (uint32_t number = 2; number <= v.inodes; number++)
            if ((modes[number] & 0170000) == ax::directory && !check_directory(number))
                return false;
        for (uint32_t number = 2; number <= v.inodes; number++) {
            if (!modes[number])
                continue;
            if (references[number] != links[number])
                return v.fail();
            if ((modes[number] & 0170000) != ax::directory)
                continue;
            if (!parents[number] || dotdots[number] != parents[number])
                return v.fail();
            uint32_t parent = number;
            unsigned depth = 0;
            while (parent != 2) {
                if (++depth > v.inodes || !parents[parent])
                    return v.fail();
                parent = parents[parent];
            }
        }
        return true;
    }
};

static bool layout(Volume& v, const uint8_t* header, const BlockInfo& disk) {
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
    if ((v.compatible & ~0x38u) || (incompatible & ~2u) || (v.readonly_features & ~3u) ||
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
    v.writable_safe = u16(header + 58) == 1 && !u32(header + 232);
    if (!v.mount->readonly && !v.writable_safe)
        return v.fail();
    Validation check{v};
    return check.allocate() && check.bitmaps(header) && check.inode_maps() && check.directories();
}

} // namespace

const FilesystemOps ext2_ops = {lookup, create,   link,    remove,         rename, read,
                                write,  truncate, setattr, readdir,        sync,   nullptr,
                                stats,  destroy,  remount, prepare_unmount};

int ext2_mount(Mount* mount, Node* device) {
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
    if (!result && !layout(*v, header, *info))
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
    if (!result) {
        v->cache = (CachedBlock*)alloc(sizeof(CachedBlock) * cached_blocks);
        if (!v->cache)
            result = -12;
        else
            memset(v->cache, 0, sizeof(CachedBlock) * cached_blocks);
    }
    if (!result && !mount->readonly) {
        set16(header + 58, u16(header + 58) & ~1u);
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
