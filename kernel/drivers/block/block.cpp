// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/block/block.cpp
 * @brief   Virtio block device I/O.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Submits sector reads, writes, and flushes through a virtio queue and handles
 * completion.
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
#include "drivers/block/block.hpp"
#include "drivers/block/partition.hpp"
#include "drivers/virtio/pci.hpp"

namespace ax {
namespace {
constexpr unsigned max_disks = 8, transfer_sectors = 32;
constexpr uint64_t feature_ro = 1ull << 5, feature_flush = 1ull << 9;

struct Request {
    uint32_t type, reserved;
    uint64_t sector;
};

static_assert(sizeof(Request) == 16);

struct Volume {
    BlockInfo info{};
    uint64_t start = 0;
    const void* owner = nullptr;
    Volume* next_claim = nullptr;
};

struct Disk {
    VirtioPci pci;
    SplitQueue queue;
    Volume volumes[max_partitions + 1];
    PartitionTable partitions;
    Volume* claims = nullptr;
    bool live = false;
    uint64_t request_physical = 0;
    Request* request = nullptr;
    uint8_t* data = nullptr;
    volatile uint8_t* status = nullptr;
};

// Failed attachments retain their ownership records rather than reusing a slot.
static Disk candidates[max_disks];
static Disk* disks[max_disks];
static unsigned disk_count, attempts;

static bool initialize(Disk& d, const PciFunction& pci) {
    if (!d.pci.open(pci, feature_ro | feature_flush, 8))
        return false;
    auto& info = d.volumes[0].info;
    info.readonly = d.pci.features() & feature_ro;
    info.flush_supported = d.pci.features() & feature_flush;
    if (!d.pci.read_config(0, &info.sectors, sizeof(info.sectors)) || !info.sectors ||
        info.sectors > uint64_t(INT64_MAX) / sector_size)
        return false;
    if (!d.pci.setup_queue(d.queue, 0, 256, 4))
        return false;
    d.request_physical = page_alloc(1 + transfer_sectors * sector_size / page_size);
    if (!d.request_physical)
        return false;
    d.request = (Request*)physical(d.request_physical);
    d.status = (volatile uint8_t*)physical(d.request_physical + sizeof(Request));
    d.data = (uint8_t*)physical(d.request_physical + page_size);
    if (!d.pci.start())
        return false;
    d.live = true;
    return true;
}

static int failed(Disk& d) {
    d.live = false;
    d.pci.stop();
    // Payload and queue allocations stay quarantined after a runtime failure.
    return -5;
}

static int request(Disk& d, uint32_t type, uint64_t sector, size_t length) {
    if (!d.live)
        return -5;
    if (!d.pci.healthy())
        return failed(d);
    *d.request = {type, 0, sector};
    *d.status = 0xff;
    VirtioBuffer buffers[3]{{d.request_physical, sizeof(Request), false}};
    unsigned count = 1;
    if (length)
        buffers[count++] = {d.request_physical + page_size, uint32_t(length), type == 0};
    buffers[count++] = {d.request_physical + sizeof(Request), 1, true};
    int head = d.queue.submit(buffers, count, d.request_physical);
    if (head < 0 || !d.pci.notify(d.queue))
        return failed(d);
    VirtioCompletion completed{};
    // A flush may cover a newly copied full root image. Its backend latency is
    // independent of the transport's short reset acknowledgement deadline.
    int waited = d.pci.wait(d.queue, completed, 30);
    if (waited || completed.head != head || completed.cookie != d.request_physical) {
        log("virtio-blk: completion failed type=%u sector=%u bytes=%u errno=%u\n", uint64_t(type),
            sector, uint64_t(length), uint64_t(waited ? -waited : 5));
        return failed(d);
    }
    // Legacy devices historically report the used length inconsistently.
    uint32_t written = completed.length;
    if (d.pci.modern() && (!written || written > (type == 0 ? length + 1 : 1) ||
                           (*d.status == 0 && written != (type == 0 ? length + 1 : 1))))
        return failed(d);
    if (*d.status == 0)
        return 0;
    if (*d.status == 1)
        return -5;
    if (*d.status == 2)
        return -95;
    return failed(d);
}

static void discover(const PciFunction& p) {
    uint16_t id = p.read16(2);
    if (attempts == max_disks || p.read16(0) != 0x1af4 || (id != 0x1001 && id != 0x1042))
        return;
    auto& d = candidates[attempts++];
    if (!initialize(d, p)) {
        if (d.pci.stop()) {
            d.queue.release();
            if (d.request_physical)
                page_free(d.request_physical, 1 + transfer_sectors * sector_size / page_size);
        }
        log("virtio-blk: initialization failed at %u:%u.%u\n", uint64_t(p.bus), uint64_t(p.slot),
            uint64_t(p.function));
        return;
    }
    disks[disk_count] = &d;
    const auto& info = d.volumes[0].info;
    log("virtio-blk: disk=%u transport=%s sectors=%u readonly=%u flush=%u\n", uint64_t(disk_count),
        d.pci.modern() ? "modern" : "legacy", info.sectors, uint64_t(info.readonly),
        uint64_t(info.flush_supported));
    log("virtio-queue: disk=%u id=0 size=%u\n", uint64_t(disk_count),
        uint64_t(d.queue.layout().size));
    disk_count++;
}

static Disk* disk_for(unsigned device) {
    return disks[device % max_disks];
}

static Volume* volume_for(unsigned device) {
    auto disk = disk_for(device);
    unsigned part = device / max_disks;
    if (!disk || part > max_partitions || !disk->volumes[part].info.sectors)
        return nullptr;
    return &disk->volumes[part];
}

static int transfer(unsigned device, uint64_t sector, void* buffer, size_t count, bool write) {
    auto volume = volume_for(device);
    if (!volume)
        return -19;
    const auto& info = volume->info;
    if (sector > info.sectors || count > info.sectors - sector)
        return -22;
    if (!count)
        return 0;
    if (write && info.readonly)
        return -30;
    auto& d = *disk_for(device);
    if (!d.live)
        return -5;
    sector += volume->start;
    auto bytes = (uint8_t*)buffer;
    while (count) {
        size_t sectors = min(count, size_t(transfer_sectors)), length = sectors * sector_size;
        if (write)
            memcpy(d.data, bytes, length);
        int result = request(d, write ? 1 : 0, sector, length);
        if (result)
            return result;
        if (!write)
            memcpy(bytes, d.data, length);
        bytes += length;
        sector += sectors;
        count -= sectors;
    }
    return 0;
}

static int partition_sector(void* context, uint64_t sector, void* data) {
    return transfer(*static_cast<unsigned*>(context), sector, data, 1, false);
}

static bool conflicts(const Disk& disk, const Volume& volume, const void* owner = nullptr) {
    for (auto other = disk.claims; other; other = other->next_claim)
        if ((other != &volume || other->owner != owner) &&
            volume.start < other->start + other->info.sectors &&
            other->start < volume.start + volume.info.sectors)
            return true;
    return false;
}

static char lowercase_hex(char c) {
    return c >= 'A' && c <= 'F' ? static_cast<char>(c + ('a' - 'A')) : c;
}

static bool same_id(const char* left, const char* right) {
    while (*left && lowercase_hex(*left) == *right) {
        left++;
        right++;
    }
    return !*left && !*right;
}
} // namespace

void block_init() {
    pci_scan(discover);
    for (unsigned i = 0; i < disk_count; i++) {
        auto& disk = *disks[i];
        const auto& info = disk.volumes[0].info;
        int error = read_partition_table(info.sectors, partition_sector, &i, disk.partitions);
        if (error) {
            log("block: partition scan failed disk=%u errno=%d\n", uint64_t(i), int64_t(-error));
            continue;
        }
        for (unsigned p = 0; p < max_partitions; p++) {
            const auto& entry = disk.partitions.entries[p];
            if (entry.sectors)
                disk.volumes[p + 1] = {{entry.sectors, info.readonly, info.flush_supported},
                                       entry.start};
        }
    }
}

const BlockInfo* block_info(unsigned device) {
    auto volume = volume_for(device);
    return volume ? &volume->info : nullptr;
}

unsigned block_device_limit() {
    return max_disks * (max_partitions + 1);
}

void block_device_name(unsigned device, char (&name)[block_name_size]) {
    memcpy(name, "/dev/vda", sizeof("/dev/vda"));
    name[7] += device % max_disks;
    unsigned part = device / max_disks, at = 8;
    if (part >= 100)
        name[at++] = '0' + part / 100;
    if (part >= 10)
        name[at++] = '0' + part / 10 % 10;
    if (part)
        name[at++] = '0' + part % 10;
    name[at] = 0;
}

uint64_t block_device_number(unsigned device) {
    unsigned disk = device % max_disks, part = device / max_disks;
    if (part < 16)
        return 0xfc00 | (disk * 16 + part);
    uint64_t minor = disk * max_partitions + part - 16;
    return (259 << 8) | (minor & 255) | ((minor & ~uint64_t(255)) << 12);
}

int block_find(const char* selection) {
    constexpr char uuid[] = "PARTUUID=", label[] = "PARTLABEL=";
    size_t length = strlen(selection);
    bool by_id = length >= sizeof(uuid) && !memcmp(selection, uuid, sizeof(uuid) - 1);
    bool by_label = length >= sizeof(label) && !memcmp(selection, label, sizeof(label) - 1);
    if (by_id || by_label) {
        const char* value = selection + (by_id ? sizeof(uuid) - 1 : sizeof(label) - 1);
        int found = -19;
        for (unsigned disk = 0; disk < disk_count; disk++) {
            for (unsigned p = 0; p < max_partitions; p++) {
                const auto& part = disks[disk]->partitions.entries[p];
                if (!part.sectors ||
                    !(by_id ? same_id(value, part.id) : !strcmp(value, part.label)))
                    continue;
                if (found >= 0)
                    return -76; // ENOTUNIQ
                found = disk + (p + 1) * max_disks;
            }
        }
        return found;
    }

    if (length < 8 || length >= block_name_size || memcmp(selection, "/dev/vd", 7) ||
        selection[7] < 'a' || selection[7] >= 'a' + int(max_disks) || selection[8] == '0')
        return -19;
    unsigned part = 0;
    for (size_t i = 8; i < length; i++) {
        if (selection[i] < '0' || selection[i] > '9')
            return -19;
        part = part * 10 + unsigned(selection[i] - '0');
    }
    if (part > max_partitions)
        return -19;
    return selection[7] - 'a' + part * max_disks;
}

int block_read(unsigned device, uint64_t sector, void* data, size_t count) {
    return transfer(device, sector, data, count, false);
}

int block_claim(unsigned device, const void* owner) {
    auto volume = volume_for(device);
    if (!volume)
        return -19;
    if (!owner)
        return -22;
    auto& disk = *disk_for(device);
    if (conflicts(disk, *volume))
        return -16;
    volume->owner = owner;
    volume->next_claim = disk.claims;
    disk.claims = volume;
    return 0;
}

void block_unclaim(unsigned device, const void* owner) {
    auto volume = volume_for(device);
    if (!volume || !owner || volume->owner != owner)
        return;
    auto& disk = *disk_for(device);
    auto link = &disk.claims;
    while (*link != volume)
        link = &(*link)->next_claim;
    *link = volume->next_claim;
    volume->owner = nullptr;
    volume->next_claim = nullptr;
}

bool block_claimed(unsigned device) {
    auto volume = volume_for(device);
    return volume && conflicts(*disk_for(device), *volume);
}

int block_write(unsigned device, uint64_t sector, const void* data, size_t count,
                const void* owner) {
    auto volume = volume_for(device);
    if (!volume)
        return -19;
    if (conflicts(*disk_for(device), *volume, owner))
        return -16;
    return transfer(device, sector, const_cast<void*>(data), count, true);
}

int block_flush(unsigned device) {
    auto volume = volume_for(device);
    if (!volume)
        return -19;
    auto& d = *disk_for(device);
    if (!d.live)
        return -5;
    if (volume->info.readonly || !volume->info.flush_supported)
        return 0; // Unnegotiated FLUSH means writethrough.
    return request(d, 4, 0, 0);
}
} // namespace ax
