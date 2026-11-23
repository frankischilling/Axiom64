// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/block/block.cpp
 * @brief   Block device access and volume ownership.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Discovers virtio, ATA, AHCI, NVMe and floppy disks, translates partition I/O, and maintains
 * volume claims and caches.
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
#include "drivers/block/ahci.hpp"
#include "drivers/block/ata.hpp"
#include "drivers/block/cache.hpp"
#include "drivers/block/floppy.hpp"
#include "drivers/block/nvme.hpp"
#include "drivers/block/partition.hpp"
#include "drivers/virtio/pci.hpp"
#include "mm/dma.hpp"

namespace ax {
namespace {
constexpr unsigned virtio_slots = 8, ahci_first = virtio_slots + ata_device_slots;
constexpr unsigned nvme_first = ahci_first + ahci_device_slots;
constexpr unsigned floppy_first = nvme_first + nvme_device_slots;
constexpr unsigned max_disks = floppy_first + floppy_slots;
constexpr unsigned transfer_sectors = 32;
static_assert(transfer_sectors <= ahci_transfer_sectors);
static_assert(ata_device_slots + ahci_device_slots <= 16);
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
    BlockCache* cache = nullptr;
};

struct Disk {
    VirtioPci pci;
    SplitQueue queue;
    Volume volumes[max_partitions + 1];
    PartitionTable partitions;
    Volume* claims = nullptr;
    bool live = false;
    unsigned sd_letter = 0;
    uint64_t request_physical = 0;
    Request* request = nullptr;
    uint8_t* data = nullptr;
    volatile uint8_t* status = nullptr;
};

// Failed attachments retain their ownership records rather than reusing a slot.
static Disk candidates[virtio_slots];
static Disk ata_disks[ata_device_slots];
static Disk ahci_disks[ahci_device_slots];
static Disk nvme_disks[nvme_device_slots];
static Disk floppy_disks[floppy_slots];
static Disk* disks[max_disks];
static unsigned disk_count, attempts;
static uint64_t buffer_bytes;

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
    d.request_physical = Dma::allocate(1 + transfer_sectors * sector_size / page_size, Dma::pci);
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
    if (attempts == virtio_slots || p.read16(0) != 0x1af4 || (id != 0x1001 && id != 0x1042))
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

static bool is_ata(unsigned device) {
    const unsigned slot = device % max_disks;
    return slot >= virtio_slots && slot < ahci_first;
}

static bool is_ahci(unsigned device) {
    const unsigned slot = device % max_disks;
    return slot >= ahci_first && slot < nvme_first;
}

static bool is_nvme(unsigned device) {
    const unsigned slot = device % max_disks;
    return slot >= nvme_first && slot < floppy_first;
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
    if (write && volume->cache)
        volume->cache->invalidate(sector, count);
    auto& d = *disk_for(device);
    if (!d.live)
        return -5;
    sector += volume->start;
    if (device % max_disks >= floppy_first)
        return floppy_transfer(device % max_disks - floppy_first, sector, buffer, count, write);
    if (is_nvme(device))
        return nvme_transfer(device % max_disks - nvme_first, sector, buffer, count, write);
    auto bytes = (uint8_t*)buffer;
    while (count) {
        size_t sectors = min(count, size_t(transfer_sectors)), length = sectors * sector_size;
        if (is_ata(device)) {
            if (int result =
                    ata_transfer(device % max_disks - virtio_slots, sector, bytes, sectors, write))
                return result;
        } else if (is_ahci(device)) {
            if (int result =
                    ahci_transfer(device % max_disks - ahci_first, sector, bytes, sectors, write))
                return result;
        } else {
            if (write)
                memcpy(d.data, bytes, length);
            if (int result = request(d, write ? 1 : 0, sector, length))
                return result;
            if (!write)
                memcpy(bytes, d.data, length);
        }
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

static unsigned decimal(char* name, unsigned value) {
    char digits[10];
    unsigned count = 0;
    do {
        digits[count++] = '0' + value % 10;
        value /= 10;
    } while (value);
    for (unsigned i = 0; i < count; ++i)
        name[i] = digits[count - i - 1];
    return count;
}

static int partition_suffix(const char* text) {
    if (*text == '0')
        return -19;
    unsigned number = 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9')
            return -19;
        number = number * 10 + unsigned(*text - '0');
        if (number > max_partitions)
            return -19;
    }
    return number;
}
} // namespace

void block_init() {
    pci_scan(discover);
    ata_init();
    ahci_init();
    nvme_init();
    floppy_init();
    unsigned assigned = 0;
    for (unsigned slot = 0; slot < ata_device_slots; ++slot) {
        if (const auto* info = ata_info(slot)) {
            auto& disk = ata_disks[slot];
            disk.volumes[0].info = *info;
            disk.live = true;
            disk.sd_letter = slot;
            assigned |= 1u << slot;
            disks[virtio_slots + slot] = &disk;
        }
    }
    unsigned letter = 0;
    for (unsigned slot = 0; slot < ahci_device_slots; ++slot) {
        if (const auto* info = ahci_info(slot)) {
            while (assigned & (1u << letter))
                ++letter;
            auto& disk = ahci_disks[slot];
            disk.volumes[0].info = *info;
            disk.live = true;
            disk.sd_letter = letter++;
            disks[ahci_first + slot] = &disk;
        }
    }
    for (unsigned slot = 0; slot < nvme_device_slots; ++slot) {
        if (const auto* info = nvme_info(slot)) {
            auto& disk = nvme_disks[slot];
            disk.volumes[0].info = *info;
            disk.live = true;
            disks[nvme_first + slot] = &disk;
        }
    }
    for (unsigned i = 0; i < floppy_first; i++) {
        if (!disks[i])
            continue;
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
    for (unsigned slot = 0; slot < floppy_slots; ++slot) {
        if (const auto* info = floppy_info(slot)) {
            auto& disk = floppy_disks[slot];
            disk.volumes[0].info = *info;
            disk.live = true;
            disks[floppy_first + slot] = &disk;
        }
    }
}

int block_shutdown() {
    return nvme_shutdown();
}

const BlockInfo* block_info(unsigned device) {
    auto volume = volume_for(device);
    return volume ? &volume->info : nullptr;
}

unsigned block_device_limit() {
    return max_disks * (max_partitions + 1);
}

void block_device_name(unsigned device, char (&name)[block_name_size]) {
    unsigned disk = device % max_disks;
    if (disk >= floppy_first) {
        memcpy(name, "/dev/fd0", sizeof("/dev/fd0"));
        name[7] += disk - floppy_first;
        return;
    }
    const unsigned part = device / max_disks;
    unsigned at = 8;
    if (is_nvme(device)) {
        const auto address = nvme_address(disk - nvme_first);
        memcpy(name, "/dev/nvme", 9);
        at = 9 + decimal(name + 9, address.controller);
        name[at++] = 'n';
        at += decimal(name + at, address.nsid);
        if (part)
            name[at++] = 'p';
    } else {
        const bool sd = disk >= virtio_slots;
        memcpy(name, sd ? "/dev/sda" : "/dev/vda", sizeof("/dev/vda"));
        name[7] += sd ? disks[disk]->sd_letter : disk;
    }
    if (part)
        at += decimal(name + at, part);
    name[at] = 0;
}

uint64_t block_device_number(unsigned device) {
    unsigned disk = device % max_disks, part = device / max_disks;
    if (disk >= floppy_first)
        return 0x200 | (disk - floppy_first);
    if (disk < nvme_first && part < 16)
        return disk >= virtio_slots ? 0x800 | (disks[disk]->sd_letter * 16 + part)
                                    : 0xfc00 | (disk * 16 + part);
    uint64_t minor =
        disk >= nvme_first ? disk * (max_partitions + 1) + part : disk * max_partitions + part - 16;
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
        for (unsigned disk = 0; disk < max_disks; disk++) {
            if (!disks[disk])
                continue;
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

    if (length < 8 || length >= block_name_size)
        return -19;
    if (length >= 9 && !memcmp(selection, "/dev/nvme", 9)) {
        for (unsigned disk = nvme_first; disk < floppy_first; ++disk) {
            if (!disks[disk])
                continue;
            char name[block_name_size];
            block_device_name(disk, name);
            const size_t stem = strlen(name);
            if (length < stem || memcmp(selection, name, stem))
                continue;
            if (length == stem)
                return disk;
            if (selection[stem] != 'p' || length == stem + 1)
                continue;
            const int part = partition_suffix(selection + stem + 1);
            if (part > 0)
                return disk + unsigned(part) * max_disks;
        }
        return -19;
    }
    bool sd = !memcmp(selection, "/dev/sd", 7);
    if ((!sd && memcmp(selection, "/dev/vd", 7)) || selection[7] < 'a' ||
        selection[7] >= 'a' + int(sd ? ata_device_slots + ahci_device_slots : virtio_slots))
        return -19;
    const int part = partition_suffix(selection + 8);
    if (part < 0)
        return -19;
    const unsigned letter = selection[7] - 'a';
    if (!sd)
        return letter + part * max_disks;
    for (unsigned disk = virtio_slots; disk < nvme_first; ++disk)
        if (disks[disk] && disks[disk]->sd_letter == letter)
            return disk + part * max_disks;
    return -19;
}

int block_read(unsigned device, uint64_t sector, void* data, size_t count) {
    return transfer(device, sector, data, count, false);
}

size_t block_direct_sectors(unsigned device) {
    return is_nvme(device) ? nvme_transfer_limit(device % max_disks - nvme_first) : 1;
}

static uint64_t cache_limit(uint64_t total_memory) {
    constexpr uint64_t maximum = 128 * 1024 * 1024;
    return min(total_memory / 32, maximum);
}

int block_enable_cache(unsigned device, unsigned sectors_per_block, const void* owner) {
    auto volume = volume_for(device);
    if (!volume)
        return -19;
    if (!owner || volume->owner != owner || volume->cache)
        return -16;
    if (!sectors_per_block || sectors_per_block > BlockCache::max_sectors ||
        (sectors_per_block & (sectors_per_block - 1)))
        return -22;
    // A floppy may be ejected, so reads must reach the controller's change check.
    if (device % max_disks >= floppy_first)
        return 0;
    constexpr uint64_t mib = 1024 * 1024;
    const auto ram = physical_memory_stats();
    const auto limit = cache_limit(ram.total);
    if (buffer_bytes >= limit)
        return 0;
    const auto sets =
        BlockCache::sets_for_budget(sectors_per_block, min(limit - buffer_bytes, 64 * mib));
    if (!sets)
        return 0;
    auto cache = static_cast<BlockCache*>(alloc(sizeof(BlockCache)));
    if (!cache)
        return 0;
    if (!cache->initialize(sectors_per_block, sets)) {
        release(cache);
        return 0;
    }
    volume->cache = cache;
    buffer_bytes += cache->allocated_bytes();
    return 0;
}

bool block_read_from_cache(unsigned device, uint64_t sector, void* data, size_t count) {
    auto volume = volume_for(device);
    return volume && volume->cache && volume->cache->read(sector, data, count);
}

size_t block_read_ahead_limit(unsigned device, size_t block_sectors) {
    auto volume = volume_for(device);
    if (!volume || !volume->cache || !block_sectors)
        return 1;
    return max(size_t(1),
               min(block_direct_sectors(device), size_t(transfer_sectors)) / block_sectors);
}

static void remember_read(BlockCache& cache, uint64_t sector, const void* data, size_t count) {
    const auto ram = physical_memory_stats();
    const auto before = cache.allocated_bytes();
    constexpr uint64_t max_growth_floor = 32 * 1024 * 1024;
    const bool allow_growth = buffer_bytes + cache.growth_bytes() <= cache_limit(ram.total) &&
                              ram.free > min(ram.total / 8, max_growth_floor);
    cache.remember(sector, data, count, allow_growth);
    buffer_bytes += cache.allocated_bytes() - before;
}

int block_read_cached(unsigned device, uint64_t sector, void* data, size_t count,
                      size_t contiguous_blocks) {
    auto volume = volume_for(device);
    if (!volume)
        return -19;
    auto cache = volume->cache;
    if (cache && cache->read(sector, data, count))
        return 0;
    if (contiguous_blocks > 1 && cache) {
        const size_t blocks = min(contiguous_blocks, block_read_ahead_limit(device, count));
        // Synchronous block requests are serialized. Keep the shared transfer
        // buffer off the kernel stack and out of the per-volume cache budget.
        static uint8_t buffer[transfer_sectors * sector_size];
        if (blocks > 1 && !block_read(device, sector, buffer, blocks * count)) {
            memcpy(data, buffer, count * sector_size);
            for (size_t i = 0; i < blocks; ++i)
                remember_read(*cache, sector + i * count, buffer + i * count * sector_size, count);
            return 0;
        }
    }
    int result = block_read(device, sector, data, count);
    if (!result && cache)
        remember_read(*cache, sector, data, count);
    return result;
}

uint64_t block_buffer_bytes() {
    return buffer_bytes;
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
    if (volume->cache) {
        buffer_bytes -= volume->cache->allocated_bytes();
        volume->cache->destroy();
        release(volume->cache);
        volume->cache = nullptr;
    }
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
        return 0; // Floppy writes are synchronous. Virtio without FLUSH is writethrough.
    if (is_ata(device))
        return ata_flush(device % max_disks - virtio_slots);
    if (is_ahci(device))
        return ahci_flush(device % max_disks - ahci_first);
    if (is_nvme(device))
        return nvme_flush(device % max_disks - nvme_first);
    return request(d, 4, 0, 0);
}
} // namespace ax
