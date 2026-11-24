// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/boot/multiboot.cpp
 * @brief   Normalize Multiboot information for native kernel startup.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Validates loader records, reserves kernel and module memory, and replaces
 * the temporary identity map with the kernel's direct map.
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
#include "boot/boot.hpp"
#include "drivers/platform/legacy_io.hpp"

namespace ax {
namespace {
constexpr uint32_t multiboot1_magic = 0x2badb002;
constexpr uint32_t multiboot2_magic = 0x36d76289;
constexpr uint64_t identity_limit = 1ull << 32;
constexpr uint64_t physical_limit = 1ull << 52;
constexpr uint64_t direct_offset = 0xffff800000000000ull;
constexpr uint64_t image_start = 0x100000;
constexpr uint64_t kernel_start = 0x200000;
constexpr size_t max_modules = 64;
constexpr size_t max_ranges = 256 + max_modules + 5;
constexpr size_t max_info = 1024 * 1024;
constexpr unsigned mapping_slot = (direct_offset >> 39) & 511;

struct Range {
    uint64_t begin, end;
};

struct Candidate {
    Range range;
    BootMemoryKind kind;
    int priority;
};

Candidate candidates[max_ranges];
size_t candidate_count;
BootMemory memory[max_ranges * 2];
uint64_t boundaries[max_ranges * 2];
size_t memory_count;
Range modules[max_modules];
size_t module_count;
char command[4096];
uint64_t framebuffer_address, framebuffer_bytes;
BootFramebuffer framebuffer;
size_t rsdp_size;
bool efi;

template <class T> T read(const uint8_t* data, size_t offset = 0) {
    T value;
    memcpy(&value, data + offset, sizeof(value));
    return value;
}

const uint8_t* identity(uint64_t address, uint64_t size) {
    if (!address || address >= identity_limit || size > identity_limit - address)
        panic("Multiboot information outside the bootstrap address space");
    return reinterpret_cast<const uint8_t*>(address);
}

bool intersects(Range a, Range b) {
    return a.begin < b.end && b.begin < a.end;
}

void add_range(Range range, BootMemoryKind kind, int priority) {
    if (range.begin == range.end)
        return;
    if (candidate_count == max_ranges)
        panic("too many Multiboot memory ranges");
    candidates[candidate_count++] = {range, kind, priority};
}

void add_memory(const uint8_t* entry) {
    uint64_t base = read<uint64_t>(entry);
    uint64_t bytes = read<uint64_t>(entry, 8);
    if (base >= physical_limit || !bytes)
        return;
    Range range{base, base + min(bytes, physical_limit - base)};
    switch (read<uint32_t>(entry, 16)) {
    case 1:
        add_range(range, BootMemoryKind::usable, 1);
        break;
    case 2:
        add_range(range, BootMemoryKind::reserved, 2);
        break;
    case 3:
        add_range(range, BootMemoryKind::firmware, 3);
        break;
    case 4:
        add_range(range, BootMemoryKind::acpi_nvs, 3);
        break;
    default:
        add_range(range, BootMemoryKind::other, 4);
        break;
    }
}

void module(uint32_t start, uint32_t end) {
    if (start < page_size || end <= start || module_count == max_modules)
        panic("invalid Multiboot module range");
    modules[module_count++] = {start, end};
}

void copy_command(const uint8_t* bytes, size_t available) {
    size_t limit = min(available, sizeof(command));
    for (size_t i = 0; i < limit; i++) {
        command[i] = char(bytes[i]);
        if (!command[i])
            return;
    }
    panic("unterminated Multiboot command line");
}

void video(const uint8_t* data, const uint8_t* colors) {
    if (data[21] != 1)
        return;
    uint64_t address = read<uint64_t>(data);
    uint64_t pitch = read<uint32_t>(data, 8);
    uint64_t width = read<uint32_t>(data, 12);
    uint64_t height = read<uint32_t>(data, 16);
    uint8_t bpp = data[20];
    uint64_t bytes = pitch * height;
    if (!address || address % page_size || address >= identity_limit || !width || !height ||
        (bpp != 24 && bpp != 32) || pitch < width * (bpp / 8) || bytes > identity_limit - address)
        return;
    uint32_t channels = 0;
    for (size_t i = 0; i < 6; i += 2) {
        unsigned shift = colors[i], bits = colors[i + 1];
        if (!bits || bits > 8 || shift + bits > bpp)
            return;
        uint32_t mask = ((1u << bits) - 1) << shift;
        if (channels & mask)
            return;
        channels |= mask;
    }
    framebuffer_address = address;
    framebuffer_bytes = bytes;
    framebuffer = {reinterpret_cast<void*>(direct_offset + address),
                   width,
                   height,
                   pitch,
                   bpp,
                   colors[1],
                   colors[0],
                   colors[3],
                   colors[2],
                   colors[5],
                   colors[4]};
}

bool valid_checksum(const uint8_t* data, size_t bytes) {
    uint8_t sum = 0;
    for (size_t i = 0; i < bytes; i++)
        sum += data[i];
    return sum == 0;
}

bool copy_rsdp(const uint8_t* data, size_t available, uint8_t* copy) {
    if (available < 20 || memcmp(data, "RSD PTR ", 8) || !valid_checksum(data, 20))
        return false;
    size_t size = 20;
    if (data[15]) {
        if (data[15] == 1 || available < 36)
            return false;
        size = read<uint32_t>(data, 20);
        if (size < 36 || size > available || size > page_size || !valid_checksum(data, size))
            return false;
    }
    if (size >= rsdp_size) {
        memcpy(copy, data, size);
        rsdp_size = size;
    }
    return true;
}

bool scan_rsdp(uint64_t base, uint64_t end, uint8_t* copy) {
    for (uint64_t location = base; location + 20 <= end; location += 16) {
        if (copy_rsdp(identity(location, end - location), end - location, copy))
            return true;
    }
    return false;
}

void parse_v1(uint32_t address) {
    const auto* data = identity(address, 52);
    uint32_t flags = read<uint32_t>(data);
    if (!(flags & (1u << 6)))
        panic("Multiboot 1 loader supplied no memory map");
    uint32_t length = read<uint32_t>(data, 44);
    if (!length || length > max_info)
        panic("invalid Multiboot 1 memory map size");
    const auto* map = identity(read<uint32_t>(data, 48), length);
    for (size_t offset = 0; offset < length;) {
        size_t remaining = length - offset;
        if (remaining < 24)
            panic("truncated Multiboot 1 memory map");
        size_t size = read<uint32_t>(map, offset);
        if (size < 20 || size > remaining - 4)
            panic("invalid Multiboot 1 memory map record");
        add_memory(map + offset + 4);
        offset += size + 4;
    }
    if (flags & (1u << 2)) {
        uint32_t pointer = read<uint32_t>(data, 16);
        size_t size = min(identity_limit - pointer, uint64_t(sizeof(command)));
        copy_command(identity(pointer, size), size);
    }
    if (flags & (1u << 3)) {
        size_t count = read<uint32_t>(data, 20);
        if (count > max_modules)
            panic("too many Multiboot 1 modules");
        if (count) {
            const auto* entries = identity(read<uint32_t>(data, 24), count * 16);
            for (size_t i = 0; i < count; i++)
                module(read<uint32_t>(entries, i * 16), read<uint32_t>(entries, i * 16 + 4));
        }
    }
    if (flags & (1u << 12)) {
        data = identity(address, 116);
        video(data + 88, data + 110);
    }
}

void parse_v2(uint32_t address, uint8_t* rsdp) {
    const auto* data = identity(address, 8);
    size_t total = read<uint32_t>(data);
    if (address % 8 || total < 16 || total > max_info || total % 8)
        panic("invalid Multiboot 2 information size");
    data = identity(address, total);
    bool have_map = false;
    for (size_t offset = 8; offset < total;) {
        const auto* tag = data + offset;
        uint32_t type = read<uint32_t>(tag);
        size_t size = read<uint32_t>(tag, 4);
        if (size < 8 || size > total - offset)
            panic("invalid Multiboot 2 information tag");
        switch (type) {
        case 0:
            if (size != 8 || offset + 8 != total || !have_map)
                panic("incomplete Multiboot 2 information");
            return;
        case 1:
            copy_command(tag + 8, size - 8);
            break;
        case 3:
            if (size < 17)
                panic("truncated Multiboot 2 module");
            module(read<uint32_t>(tag, 8), read<uint32_t>(tag, 12));
            break;
        case 6: {
            if (size < 40 || have_map)
                panic("invalid Multiboot 2 memory map");
            size_t stride = read<uint32_t>(tag, 8);
            if (stride < 24 || (size - 16) % stride)
                panic("invalid Multiboot 2 memory map record");
            for (size_t entry = 16; entry < size; entry += stride)
                add_memory(tag + entry);
            have_map = true;
            break;
        }
        case 8:
            if (size >= 38)
                video(tag + 8, tag + 32);
            break;
        case 11:
        case 12:
            efi = true;
            break;
        case 14:
        case 15:
            copy_rsdp(tag + 8, size - 8, rsdp);
            break;
        case 18:
            panic("Multiboot 2 EFI boot services still active");
        }
        offset += (size + 7) & ~size_t(7);
    }
    panic("missing Multiboot 2 end tag");
}

void normalize_memory() {
    size_t count = 0;
    for (size_t i = 0; i < candidate_count; i++) {
        uint64_t endpoints[] = {candidates[i].range.begin, candidates[i].range.end};
        for (uint64_t boundary : endpoints) {
            size_t pos = count++;
            while (pos && boundaries[pos - 1] > boundary) {
                boundaries[pos] = boundaries[pos - 1];
                pos--;
            }
            boundaries[pos] = boundary;
        }
    }
    for (size_t i = 1; i < count; i++) {
        uint64_t begin = boundaries[i - 1], end = boundaries[i];
        if (begin == end)
            continue;
        const Candidate* selected = nullptr;
        for (size_t j = 0; j < candidate_count; j++) {
            auto& candidate = candidates[j];
            if (candidate.range.begin <= begin && end <= candidate.range.end &&
                (!selected || candidate.priority > selected->priority))
                selected = &candidate;
        }
        if (!selected)
            continue;
        if (memory_count && memory[memory_count - 1].kind == selected->kind &&
            memory[memory_count - 1].base + memory[memory_count - 1].length == begin) {
            memory[memory_count - 1].length += end - begin;
        } else {
            memory[memory_count++] = {begin, end - begin, selected->kind};
        }
    }
}

class DirectMap {
    uint64_t next, end;
    uint64_t* root;

    uint64_t* table(uint64_t& entry) {
        if (!entry) {
            if (next >= end)
                panic("Multiboot page table area exhausted");
            entry = next | 3;
            next += page_size;
        }
        return reinterpret_cast<uint64_t*>(entry & page_mask);
    }

  public:
    DirectMap(uint64_t begin, uint64_t limit, uint64_t* pml4)
        : next(begin), end(limit), root(pml4) {
    }

    void map(uint64_t begin, uint64_t limit, uint64_t cache_flags = 0) {
        auto* pdpt = table(root[mapping_slot]);
        for (uint64_t page = begin; page < min(limit, identity_limit); page += page_size) {
            auto* pd = table(pdpt[page >> 30]);
            auto* pt = table(pd[(page >> 21) & 511]);
            pt[(page >> 12) & 511] = page | 3 | cache_flags | (1ull << 63);
        }
    }
};

BootMemory memory_at(const void*, size_t index) {
    return memory[index];
}
} // namespace

extern "C" [[noreturn]] void multiboot_main(uint32_t magic, uint32_t information,
                                            uint64_t image_end, uint64_t scratch,
                                            uint64_t bootstrap_end) {
    serial_init();
    uint64_t root_address = read_cr3() & page_mask;
    auto* rsdp = reinterpret_cast<uint8_t*>(scratch);
    if (magic == multiboot1_magic)
        parse_v1(information);
    else if (magic == multiboot2_magic)
        parse_v2(information, rsdp);
    else
        panic("invalid Multiboot loader magic");
    if (!module_count)
        panic("Multiboot requires an initramfs module");
    if (!rsdp_size && !efi) {
        uint64_t ebda = uint64_t(read<uint16_t>(identity(0x40e, 2))) << 4;
        if (ebda < 0x400 || ebda > 0x9fc00 || !scan_rsdp(ebda, ebda + 1024, rsdp))
            scan_rsdp(0xe0000, 0x100000, rsdp);
    }
    add_range({0, image_start}, BootMemoryKind::reserved, 2);
    add_range({image_start, bootstrap_end}, BootMemoryKind::other, 5);
    add_range({kernel_start, root_address}, BootMemoryKind::other, 5);
    add_range({root_address, image_end}, BootMemoryKind::retained, 5);
    for (size_t i = 0; i < module_count; i++) {
        Range range{align_down(modules[i].begin), align_up(modules[i].end)};
        for (size_t j = 0; j < candidate_count; j++) {
            auto& existing = candidates[j];
            if (existing.priority == 5 && intersects(range, existing.range))
                panic("Multiboot module overlaps the kernel or another module");
        }
        add_range(range, BootMemoryKind::retained, 5);
    }
    if (framebuffer_bytes) {
        Range fb{framebuffer_address, align_up(framebuffer_address + framebuffer_bytes)};
        for (size_t i = 0; i < candidate_count; i++) {
            auto& existing = candidates[i];
            if (existing.priority == 5 && intersects(fb, existing.range))
                panic("Multiboot framebuffer overlaps the kernel or a module");
        }
        add_range(fb, BootMemoryKind::other, 5);
    }
    normalize_memory();

    auto* root = reinterpret_cast<uint64_t*>(root_address);
    DirectMap direct(scratch + page_size, image_end, root);
    bool have_usable_memory = false;
    for (size_t i = 0; i < memory_count; i++) {
        auto& entry = memory[i];
        uint64_t begin = align_up(entry.base), end = align_down(entry.base + entry.length);
        if (entry.kind == BootMemoryKind::usable && begin < min(end, identity_limit))
            have_usable_memory = true;
        if (entry.kind == BootMemoryKind::usable || entry.kind == BootMemoryKind::retained)
            direct.map(begin, end);
    }
    if (!have_usable_memory)
        panic("no usable Multiboot memory below 4 GiB");
    if (framebuffer_bytes)
        direct.map(framebuffer_address, align_up(framebuffer_address + framebuffer_bytes), 0x18);

    boot_info = {
        .protocol = magic == multiboot1_magic ? "Multiboot 1" : "Multiboot 2",
        .firmware = efi ? "UEFI" : "BIOS",
        .command = command,
        .direct_offset = direct_offset,
        .rsdp = rsdp_size ? scratch : 0,
        .memory_context = nullptr,
        .memory_count = memory_count,
        .memory_at = memory_at,
        .initramfs = reinterpret_cast<const void*>(direct_offset + modules[0].begin),
        .initramfs_size = modules[0].end - modules[0].begin,
        .module_count = module_count,
        .framebuffer = framebuffer,
    };
    root[0] = 0;
    write_cr3(root_address);
    boot_kernel();
}
} // namespace ax
