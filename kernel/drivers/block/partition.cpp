// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/block/partition.cpp
 * @brief   GPT, MBR, and BSD partition decoding.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Validates disk metadata before exposing bounded sector ranges to block consumers.
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
#include "drivers/block/partition.hpp"

namespace ax {
namespace {
uint16_t le16(const uint8_t* b) {
    return uint16_t(b[0]) | uint16_t(b[1]) << 8;
}

uint32_t le32(const uint8_t* b) {
    return uint32_t(le16(b)) | uint32_t(le16(b + 2)) << 16;
}

uint64_t le64(const uint8_t* b) {
    return uint64_t(le32(b)) | uint64_t(le32(b + 4)) << 32;
}

bool empty(const uint8_t* b, size_t size) {
    for (size_t i = 0; i < size; i++)
        if (b[i])
            return false;
    return true;
}

bool contains(uint64_t start, uint64_t count, uint64_t first, uint64_t limit) {
    return count && start >= first && start < limit && count <= limit - start;
}

bool overlaps(const Partition& a, uint64_t start, uint64_t count) {
    return a.sectors && a.start < start + count && start < a.start + a.sectors;
}

struct Scan {
    uint64_t sectors;
    ReadPartitionSector read;
    void* context;
    PartitionTable& table;

    bool insert(unsigned number, uint64_t start, uint64_t count, unsigned parent = 0) {
        for (unsigned i = 0; i < max_partitions; i++)
            if (i + 1 != parent && overlaps(table.entries[i], start, count))
                return false;
        table.entries[number - 1].start = start;
        table.entries[number - 1].sectors = count;
        return true;
    }
};

void hex(char* out, uint32_t value, unsigned digits) {
    constexpr char alphabet[] = "0123456789abcdef";
    for (unsigned i = 0; i < digits; i++)
        out[i] = alphabet[(value >> ((digits - i - 1) * 4)) & 15];
}

void gpt_id(char* out, const uint8_t* guid) {
    hex(out, le32(guid), 8);
    hex(out + 9, le16(guid + 4), 4);
    hex(out + 14, le16(guid + 6), 4);
    for (unsigned i = 0; i < 2; i++)
        hex(out + 19 + i * 2, guid[8 + i], 2);
    for (unsigned i = 0; i < 6; i++)
        hex(out + 24 + i * 2, guid[10 + i], 2);
    out[8] = out[13] = out[18] = out[23] = '-';
}

void mbr_id(char* out, uint32_t signature, unsigned number) {
    if (!signature)
        return;
    hex(out, signature, 8);
    out[8] = '-';
    hex(out + 9, number, 2);
}

void gpt_label(char* out, const uint8_t* name) {
    for (unsigned i = 0; i < 36; i++) {
        uint32_t point = le16(name + i * 2);
        if (!point)
            break;
        if (point >= 0xd800 && point <= 0xdbff && i + 1 < 36) {
            uint32_t low = le16(name + (i + 1) * 2);
            if (low >= 0xdc00 && low <= 0xdfff) {
                point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
                i++;
            }
        }
        if (point >= 0xd800 && point <= 0xdfff)
            point = 0xfffd;
        if (point < 0x80) {
            *out++ = char(point);
        } else if (point < 0x800) {
            *out++ = char(0xc0 | (point >> 6));
            *out++ = char(0x80 | (point & 63));
        } else {
            if (point >= 0x10000) {
                *out++ = char(0xf0 | (point >> 18));
                *out++ = char(0x80 | ((point >> 12) & 63));
            } else {
                *out++ = char(0xe0 | (point >> 12));
            }
            *out++ = char(0x80 | ((point >> 6) & 63));
            *out++ = char(0x80 | (point & 63));
        }
    }
    *out = 0;
}

uint32_t crc32(uint32_t crc, const uint8_t* bytes, size_t size) {
    for (size_t i = 0; i < size; i++) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320u : 0);
    }
    return crc;
}

int scan_gpt(Scan& scan, bool backup) {
    if (scan.sectors < 4)
        return -22;
    uint8_t sector[sector_size];
    uint64_t last = scan.sectors - 1, header = backup ? last : 1;
    int error = scan.read(scan.context, header, sector);
    if (error)
        return error;

    uint32_t length = le32(sector + 12), header_crc = le32(sector + 16);
    if (memcmp(sector, "EFI PART", 8) || le32(sector + 8) != 0x10000 || length < 92 ||
        length > sector_size || le32(sector + 20) || le64(sector + 24) != header ||
        le64(sector + 32) != (backup ? 1 : last) || empty(sector + 56, 16))
        return -22;
    memset(sector + 16, 0, 4);
    if (~crc32(UINT32_MAX, sector, length) != header_crc)
        return -22;

    uint64_t first = le64(sector + 40), end = le64(sector + 48), array = le64(sector + 72);
    uint32_t entries = le32(sector + 80), stride = le32(sector + 84);
    uint32_t expected = le32(sector + 88);
    constexpr uint64_t min_array_sectors = 16384 / sector_size;
    if (first < 2 + min_array_sectors || end < first || end >= last ||
        last - end - 1 < min_array_sectors || !entries || entries > max_partitions ||
        (stride != 128 && stride != 256 && stride != 512))
        return -22;
    size_t remaining = entries * stride;
    uint64_t array_sectors = (remaining + sector_size - 1) / sector_size;
    if (!contains(array, array_sectors, backup ? end + 1 : 2, backup ? last : first) ||
        first - 2 < array_sectors || last - end - 1 < array_sectors)
        return -22;

    uint32_t crc = UINT32_MAX;
    for (unsigned number = 1; remaining; array++) {
        error = scan.read(scan.context, array, sector);
        if (error)
            return error;
        size_t bytes = min(remaining, sector_size);
        remaining -= bytes;
        crc = crc32(crc, sector, bytes);
        for (size_t offset = 0; offset < bytes; offset += stride, number++) {
            const auto* entry = sector + offset;
            if (empty(entry, 16))
                continue;
            uint64_t start = le64(entry + 32), finish = le64(entry + 40);
            if (start < first || finish < start || finish > end || empty(entry + 16, 16) ||
                !scan.insert(number, start, finish - start + 1))
                return -22;
            auto& partition = scan.table.entries[number - 1];
            gpt_id(partition.id, entry + 16);
            gpt_label(partition.label, entry + 56);
        }
    }
    return ~crc == expected ? 0 : -22;
}

struct MbrEntry {
    unsigned type;
    uint64_t start, sectors;
};

MbrEntry mbr_entry(const uint8_t* sector, unsigned slot) {
    const auto* entry = sector + 446 + slot * 16;
    return {entry[4], le32(entry + 8), le32(entry + 12)};
}

bool extended(unsigned type) {
    return type == 0x05 || type == 0x0f || type == 0x85;
}

bool mbr_signature(const uint8_t* sector) {
    return le16(sector + 510) == 0xaa55;
}

bool mbr_flags(const uint8_t* sector) {
    for (unsigned i = 0; i < 4; i++)
        if (sector[446 + i * 16] & 0x7f)
            return false;
    return true;
}

int scan_extended(Scan& scan, const MbrEntry& container, unsigned& next, uint32_t signature) {
    if (!container.type)
        return 0;
    uint64_t base = container.start, limit = base + container.sectors, current = base;
    uint64_t visited[max_partitions - 4];
    unsigned count = 0;
    uint8_t sector[sector_size];
    for (;;) {
        if (count == sizeof(visited) / sizeof(*visited))
            return -22;
        for (unsigned i = 0; i < count; i++)
            if (visited[i] == current)
                return -22;
        visited[count++] = current;
        for (const auto& partition : scan.table.entries)
            if (overlaps(partition, current, 1))
                return -22;

        int error = scan.read(scan.context, current, sector);
        if (error)
            return error;
        auto data = mbr_entry(sector, 0), link = mbr_entry(sector, 1);
        if (!mbr_signature(sector) || !mbr_flags(sector) || mbr_entry(sector, 2).type ||
            mbr_entry(sector, 3).type)
            return -22;
        if (data.type || data.sectors) {
            uint64_t start = current + data.start;
            if (!data.type || data.type == 0xee || extended(data.type) || !data.start ||
                !contains(start, data.sectors, base, limit) || next > max_partitions)
                return -22;
            for (unsigned i = 0; i < count; i++)
                if (visited[i] >= start && visited[i] - start < data.sectors)
                    return -22;
            if (!scan.insert(next, start, data.sectors))
                return -22;
            mbr_id(scan.table.entries[next - 1].id, signature, next);
            next++;
        }
        if (!link.type && !link.sectors)
            return 0;
        if (!extended(link.type) || !contains(base + link.start, link.sectors, base, limit))
            return -22;
        current = base + link.start;
    }
}

bool bsd_type(unsigned type) {
    return type == 0xa5 || type == 0xa6 || type == 0xa9;
}

int scan_bsd(Scan& scan, unsigned parent, unsigned type, unsigned& next) {
    const auto enclosing =
        parent ? scan.table.entries[parent - 1] : Partition{0, scan.sectors, {}, {}};
    if (enclosing.sectors < 2)
        return 0;
    uint8_t sector[sector_size];
    int error = scan.read(scan.context, enclosing.start + 1, sector);
    if (error)
        return error;
    constexpr uint32_t magic = 0x82564557;
    const auto* label = sector;
    if (le32(label) != magic)
        label += 64;
    if (le32(label) != magic)
        return 0;
    unsigned count = le16(label + 138);
    if (le32(label + 132) != magic || le32(label + 40) != sector_size || !count || count > 16)
        return -22;
    uint16_t checksum = 0;
    for (unsigned i = 0; i < 148 + count * 16; i += 2)
        checksum ^= le16(label + i);
    if (checksum)
        return -22;

    bool relative = type == 0xa5 && count > 2 && !le32(label + 148 + 2 * 16 + 4);
    for (unsigned i = 0; i < count; i++) {
        const auto* entry = label + 148 + i * 16;
        uint64_t size = le32(entry), start = le32(entry + 4);
        if (!entry[12])
            continue;
        if (relative)
            start += enclosing.start;
        if (start == enclosing.start && size == enclosing.sectors)
            continue;
        unsigned number = parent ? next : i + 1;
        if (number > max_partitions ||
            !contains(start, size, enclosing.start, enclosing.start + enclosing.sectors) ||
            !scan.insert(number, start, size, parent))
            return -22;
        if (parent)
            next++;
    }
    return 0;
}

int scan_mbr(Scan& scan, const uint8_t* sector) {
    if (!mbr_flags(sector))
        return -22;
    MbrEntry container{};
    uint32_t signature = le32(sector + 440);
    bool populated = false;
    for (unsigned i = 0; i < 4; i++) {
        auto entry = mbr_entry(sector, i);
        if (!entry.type && !entry.sectors)
            continue;
        if (!entry.type || !contains(entry.start, entry.sectors, 1, scan.sectors))
            return -22;
        populated = true;
        if (extended(entry.type)) {
            if (container.type)
                return -22;
            container = entry;
            continue;
        }
        if (!scan.insert(i + 1, entry.start, entry.sectors))
            return -22;
        mbr_id(scan.table.entries[i].id, signature, i + 1);
    }
    unsigned next = 5;
    if (!populated)
        return scan_bsd(scan, 0, 0, next);
    for (const auto& partition : scan.table.entries)
        if (container.type && overlaps(partition, container.start, container.sectors))
            return -22;
    int error = scan_extended(scan, container, next, signature);
    if (error)
        return error;
    for (unsigned i = 0; i < 4; i++) {
        unsigned type = mbr_entry(sector, i).type;
        if (!bsd_type(type))
            continue;
        unsigned before = next;
        if (scan_bsd(scan, i + 1, type, next)) {
            while (next > before)
                scan.table.entries[--next - 1] = {};
        }
    }
    return 0;
}
} // namespace

int read_partition_table(uint64_t sectors, ReadPartitionSector read, void* context,
                         PartitionTable& table) {
    memset(&table, 0, sizeof(table));
    if (!sectors)
        return 0;
    Scan scan{sectors, read, context, table};
    uint8_t sector[sector_size];
    int error = read(context, 0, sector);
    if (error)
        return error;
    bool protective = false;
    if (mbr_signature(sector))
        for (unsigned i = 0; i < 4; i++) {
            auto entry = mbr_entry(sector, i);
            if (entry.type == 0xee) {
                if (protective || entry.start != 1 ||
                    entry.sectors != min(sectors - 1, uint64_t(UINT32_MAX)))
                    return -22;
                protective = true;
            }
        }
    unsigned unused = 0;
    if (protective) {
        error = scan_gpt(scan, false);
        if (error) {
            memset(&table, 0, sizeof(table));
            error = scan_gpt(scan, true);
        }
    } else if (mbr_signature(sector)) {
        error = scan_mbr(scan, sector);
    } else {
        error = scan_bsd(scan, 0, 0, unused);
    }
    if (error)
        memset(&table, 0, sizeof(table));
    return error;
}
} // namespace ax
