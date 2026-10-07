// SPDX-License-Identifier: GPL-3.0-or-later
#include "boot.hpp"

namespace ax {
uint64_t direct_map;
static constexpr size_t max_pages = (4ull * 1024 * 1024 * 1024) / page_size;
static uint8_t bitmap[max_pages / 8];
static uint16_t page_references[max_pages];
static size_t search_page = 1;
static uint64_t kernel_root;
static bool used(size_t p) {
    return bitmap[p / 8] & (1u << (p % 8));
}
static void mark(size_t p, bool allocated) {
    if (allocated)
        bitmap[p / 8] |= 1u << (p % 8);
    else
        bitmap[p / 8] &= ~(1u << (p % 8));
}

void memory_init() {
    if (!hhdm_request.response || !memmap_request.response)
        panic("missing memory map");
    direct_map = hhdm_request.response->offset;
    kernel_root = read_cr3() & page_mask;
    memset(bitmap, 0xff, sizeof(bitmap));
    uint64_t available = 0;
    auto map = memmap_request.response;
    for (size_t i = 0; i < map->entry_count; i++) {
        auto e = map->entries[i];
        if (e->type != LIMINE_MEMMAP_USABLE)
            continue;
        uint64_t end = min(align_down(e->base + e->length) / page_size, uint64_t(max_pages));
        for (uint64_t p = max(align_up(e->base) / page_size, uint64_t(1)); p < end; p++) {
            mark(p, false);
            available++;
        }
    }
    log("Memory: %u MiB available, isolated four-level paging\n", available / 256);
}
void* map_mmio(uint64_t address, size_t length) {
    constexpr uint64_t physical_limit = 1ull << 52;
    if (!length || length > 1024 * 1024 || address >= physical_limit ||
        length > physical_limit - address || address > UINT64_MAX - direct_map ||
        length - 1 > UINT64_MAX - direct_map - address ||
        direct_map + address < 0xffff800000000000ull)
        return nullptr;
    for (uint64_t p = align_down(address); p < align_up(address + length); p += page_size) {
        uint64_t va = direct_map + p;
        auto table = (uint64_t*)physical(kernel_root);
        for (int shift = 39; shift > 12; shift -= 9) {
            auto& item = table[(va >> shift) & 511];
            if (item & 128)
                return nullptr; // Never change cache attributes of an existing huge RAM mapping.
            if (!(item & 1)) {
                uint64_t next = page_alloc();
                if (!next)
                    return nullptr;
                item = next | 3;
            }
            table = (uint64_t*)physical(item & page_mask);
        }
        auto& entry = table[(va >> 12) & 511];
        if ((entry & 1) && ((entry & page_mask) != p || !(entry & 16)))
            return nullptr;
        entry = p | 0x1bull | (1ull << 63); // Present, writable, PWT/PCD, supervisor, NX.
        asm volatile("invlpg (%0)" ::"r"(va) : "memory");
    }
    return physical(address);
}
uint64_t page_alloc(size_t count) {
    if (!count || count >= max_pages)
        return 0;
    for (int pass = 0; pass < 2; pass++) {
        size_t first = pass ? 1 : search_page, end = pass ? search_page : max_pages;
        size_t run = 0;
        for (size_t p = first; p < end; p++) {
            run = used(p) ? 0 : run + 1;
            if (run == count) {
                size_t start = p - count + 1;
                for (size_t k = start; k <= p; k++) {
                    mark(k, true);
                    page_references[k] = 1;
                }
                search_page = p + 1;
                memset(physical(start * page_size), 0, count * page_size);
                return start * page_size;
            }
        }
    }
    return 0;
}
void page_free(uint64_t p, size_t count) {
    if (!p || p % page_size || p / page_size + count > max_pages)
        panic("invalid physical free");
    for (size_t i = 0; i < count; i++) {
        auto index = p / page_size + i;
        if (!page_references[index])
            panic("physical page double free");
        if (!--page_references[index])
            mark(index, false);
    }
    search_page = min(search_page, size_t(p / page_size));
}
void page_retain(uint64_t p, size_t count) {
    if (!p || p % page_size || p / page_size + count > max_pages)
        panic("invalid page retain");
    for (size_t i = 0; i < count; i++) {
        auto& refs = page_references[p / page_size + i];
        if (!refs || refs == 65535)
            panic("invalid page reference");
        refs++;
    }
}
bool page_shared(uint64_t p, size_t count) {
    if (!p || p / page_size + count > max_pages)
        return false;
    for (size_t i = 0; i < count; i++)
        if (page_references[p / page_size + i] > 1)
            return true;
    return false;
}
void* alloc(size_t size) {
    if (size > SIZE_MAX - 16 - page_size)
        return nullptr;
    size_t n = align_up(size + 16) / page_size;
    uint64_t p = page_alloc(n);
    if (!p)
        return nullptr;
    auto header = (uint64_t*)physical(p);
    header[0] = n;
    header[1] = 0x4158494f4d484541;
    return header + 2;
}
void release(void* address) {
    if (!address)
        return;
    auto header = (uint64_t*)address - 2;
    if (header[1] != 0x4158494f4d484541)
        panic("invalid heap free");
    page_free(uint64_t(header) - direct_map, header[0]);
}
bool AddressSpace::create() {
    root = page_alloc();
    if (!root)
        return false;
    auto dest = (uint64_t*)physical(root), src = (uint64_t*)physical(kernel_root);
    memcpy(dest + 256, src + 256, 256 * sizeof(uint64_t));
    next_map = 0x100000000;
    return true;
}
uint64_t* AddressSpace::entry(uint64_t va, bool create_table) {
    if (!root || va >= user_limit)
        return nullptr;
    auto table = (uint64_t*)physical(root);
    for (int shift = 39; shift > 12; shift -= 9) {
        auto& item = table[(va >> shift) & 511];
        if (!(item & 1)) {
            if (!create_table)
                return nullptr;
            uint64_t p = page_alloc();
            if (!p)
                return nullptr;
            item = p | 7;
        }
        if (item & 128)
            return nullptr;
        table = (uint64_t*)physical(item & page_mask);
    }
    return &table[(va >> 12) & 511];
}
static uint64_t permissions(int prot) {
    return 4 | ((prot & 3) ? 1 : 0) | ((prot & 2) ? 2 : 0) | ((prot & 4) ? 1 : (1ull << 63));
}
bool AddressSpace::map(uint64_t va, size_t len, int prot) {
    if (va % page_size || va < page_size || va >= user_limit || len > user_limit - va ||
        len > SIZE_MAX - page_size)
        return false;
    for (uint64_t p = va; p < va + align_up(len); p += page_size) {
        auto e = entry(p, true);
        if (!e)
            return false;
        if (!(*e & page_mask)) {
            uint64_t physical_page = page_alloc();
            if (!physical_page)
                return false;
            *e = physical_page;
        }
        *e = (*e & (page_mask | 0x600)) | permissions(prot);
    }
    if (read_cr3() == root)
        write_cr3(root);
    return true;
}
bool AddressSpace::map_physical(uint64_t va, uint64_t pa, size_t len, int prot, bool external) {
    if (va % page_size || pa % page_size || va < page_size || va >= user_limit ||
        len > user_limit - va)
        return false;
    for (uint64_t offset = 0; offset < align_up(len); offset += page_size) {
        auto e = entry(va + offset, true);
        if (!e)
            return false;
        if (*e & page_mask) {
            if (!(*e & 0x200))
                page_free(*e & page_mask);
        }
        if (!external)
            page_retain(pa + offset);
        *e = (pa + offset) | permissions(prot) | (external ? 0x200 : 0x400);
    }
    if (read_cr3() == root)
        write_cr3(root);
    return true;
}
void AddressSpace::unmap(uint64_t va, size_t len) {
    if (va >= user_limit || len > user_limit - va)
        return;
    for (uint64_t p = align_down(va); p < va + len; p += page_size) {
        auto e = entry(p);
        if (e && (*e & page_mask)) {
            if (!(*e & 0x200))
                page_free(*e & page_mask);
            *e = 0;
        }
    }
    if (read_cr3() == root)
        write_cr3(root);
}
bool AddressSpace::protect(uint64_t va, size_t len, int prot) {
    if (va % page_size || va >= user_limit || len > user_limit - va)
        return false;
    for (uint64_t p = va; p < va + len; p += page_size) {
        auto e = entry(p);
        if (!e || !(*e & page_mask))
            return false;
    }
    for (uint64_t p = va; p < va + len; p += page_size) {
        auto e = entry(p);
        *e = (*e & (page_mask | 0x600)) | permissions(prot);
    }
    if (read_cr3() == root)
        write_cr3(root);
    return true;
}
bool AddressSpace::valid(uint64_t va, size_t len, bool write) const {
    if (va >= user_limit || len > user_limit - va)
        return false;
    for (uint64_t p = align_down(va); p < va + len; p += page_size) {
        auto e = const_cast<AddressSpace*>(this)->entry(p);
        if (!e || ((*e & 5) != 5) || (write && !(*e & 2)))
            return false;
    }
    return true;
}
bool AddressSpace::copy_in(void* dst, uint64_t src, size_t len) const {
    if (!valid(src, len))
        return false;
    auto d = (uint8_t*)dst;
    while (len) {
        auto e = const_cast<AddressSpace*>(this)->entry(src);
        size_t n = min(len, size_t(page_size - (src % page_size)));
        memcpy(d, (uint8_t*)physical(*e & page_mask) + src % page_size, n);
        d += n;
        src += n;
        len -= n;
    }
    return true;
}
bool AddressSpace::copy_out(uint64_t dst, const void* src, size_t len) const {
    if (!valid(dst, len, true))
        return false;
    auto s = (const uint8_t*)src;
    while (len) {
        auto e = const_cast<AddressSpace*>(this)->entry(dst);
        size_t n = min(len, size_t(page_size - (dst % page_size)));
        memcpy((uint8_t*)physical(*e & page_mask) + dst % page_size, s, n);
        s += n;
        dst += n;
        len -= n;
    }
    return true;
}
bool AddressSpace::string(uint64_t src, char* dst, size_t cap) const {
    for (size_t i = 0; i < cap; i++) {
        if (!copy_in(dst + i, src + i, 1))
            return false;
        if (!dst[i])
            return true;
    }
    return false;
}
static void destroy_table(uint64_t phys, int level) {
    auto t = (uint64_t*)physical(phys);
    size_t end = level == 4 ? 256 : 512;
    for (size_t i = 0; i < end; i++)
        if (t[i] & page_mask) {
            if (level > 1)
                destroy_table(t[i] & page_mask, level - 1);
            else if (!(t[i] & 0x200))
                page_free(t[i] & page_mask);
        }
    page_free(phys);
}
void AddressSpace::destroy() {
    if (root) {
        destroy_table(root, 4);
        root = 0;
    }
}
static bool clone_table(uint64_t dest, uint64_t src, int level) {
    auto d = (uint64_t*)physical(dest), s = (uint64_t*)physical(src);
    size_t end = level == 4 ? 256 : 512;
    for (size_t i = 0; i < end; i++)
        if (s[i] & page_mask) {
            if (level == 1 && (s[i] & 0x600)) {
                d[i] = s[i];
                if (!(s[i] & 0x200))
                    page_retain(s[i] & page_mask);
                continue;
            }
            uint64_t p = page_alloc();
            if (!p)
                return false;
            d[i] = p | (s[i] & ~page_mask);
            if (level > 1) {
                if (!clone_table(p, s[i] & page_mask, level - 1))
                    return false;
            } else
                memcpy(physical(p), physical(s[i] & page_mask), page_size);
        }
    return true;
}
bool AddressSpace::clone_from(const AddressSpace& src) {
    if (!create())
        return false;
    if (!clone_table(root, src.root, 4)) {
        destroy();
        return false;
    }
    next_map = src.next_map;
    return true;
}
} // namespace ax
