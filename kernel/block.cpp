// SPDX-License-Identifier: GPL-3.0-or-later
#include "block.hpp"
#include "pci.hpp"

namespace ax {
namespace {
constexpr unsigned max_disks = 8, transfer_sectors = 32;
constexpr uint64_t version_one = 1ull << 32, feature_ro = 1ull << 5, feature_flush = 1ull << 9;
struct Descriptor {
    uint64_t address;
    uint32_t length;
    uint16_t flags, next;
};
struct UsedEntry {
    uint32_t id, length;
};
struct Request {
    uint32_t type, reserved;
    uint64_t sector;
};
static_assert(sizeof(Descriptor) == 16 && sizeof(Request) == 16);
struct Region {
    volatile uint8_t* bytes;
    uint32_t length;
    uint8_t r8(size_t off) const { return bytes[off]; }
    uint16_t r16(size_t off) const { return *(volatile uint16_t*)(bytes + off); }
    uint32_t r32(size_t off) const { return *(volatile uint32_t*)(bytes + off); }
    void w8(size_t off, uint8_t v) { bytes[off] = v; }
    void w16(size_t off, uint16_t v) { *(volatile uint16_t*)(bytes + off) = v; }
    void w32(size_t off, uint32_t v) { *(volatile uint32_t*)(bytes + off) = v; }
    void w64(size_t off, uint64_t v) { w32(off, v); w32(off + 4, v >> 32); }
};
struct Disk {
    PciFunction pci;
    BlockInfo info;
    bool modern, live;
    uint16_t io, size, available, consumed;
    Region common, notify, config, isr;
    uint32_t notify_multiplier, notify_offset;
    uint64_t queue_physical, request_physical;
    size_t queue_pages;
    Descriptor* descriptors;
    volatile uint16_t* avail;
    volatile uint16_t* used;
    volatile UsedEntry* entries;
    Request* request;
    uint8_t* data;
    volatile uint8_t* status;
    void set_status(uint8_t v) { if (modern) common.w8(20, v); else out8(io + 18, v); }
    uint8_t get_status() { return modern ? common.r8(20) : in8(io + 18); }
};
static Disk disks[max_disks];
static unsigned disk_count;
static unsigned attempts;
static uint64_t tsc_frequency;
static uint64_t timestamp() {
    uint32_t low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    return uint64_t(high) << 32 | low;
}
static void dma_barrier() { asm volatile("mfence" ::: "memory"); }
static void calibrate_timeout() {
    // PIT channel 2 is independent of the scheduler's channel 0.
    uint8_t speaker = in8(0x61);
    out8(0x61, speaker & ~3u);
    out8(0x43, 0xb0);
    out8(0x42, uint8_t(11932));
    out8(0x42, uint8_t(11932 >> 8));
    uint64_t started = timestamp();
    out8(0x61, (speaker & ~2u) | 1);
    for (unsigned i = 0; i < 2000000; i++)
        if (in8(0x61) & 32) {
            tsc_frequency = (timestamp() - started) * 100;
            break;
        }
    out8(0x61, speaker);
}
static bool expired(uint64_t started, unsigned spins) {
    return spins >= 20000000 || (tsc_frequency && timestamp() - started >= tsc_frequency * 2);
}
static bool reset(Disk& d) {
    d.set_status(0);
    uint64_t started = timestamp();
    for (unsigned spins = 0; !expired(started, spins); spins++) {
        if (!d.get_status())
            return true;
        asm volatile("pause");
    }
    return false;
}
static bool region(const PciFunction& p, uint8_t capability, Region& out) {
    uint64_t bar;
    uint32_t offset = p.read32(capability + 8), length = p.read32(capability + 12);
    if (!length || !p.memory_bar(p.read8(capability + 4), bar) ||
        bar > (1ull << 52) - offset || length > (1ull << 52) - bar - offset)
        return false;
    void* mapped = map_mmio(bar + offset, length);
    if (!mapped)
        return false;
    out = {(volatile uint8_t*)mapped, length};
    return true;
}
static bool transport(Disk& d) {
    if (d.pci.read16(6) & 16) {
        uint8_t at = d.pci.read8(0x34) & 0xfc;
        bool seen[256]{};
        while (at) {
            if (at < 0x40 || seen[at])
                return false;
            seen[at] = true;
            uint8_t id = d.pci.read8(at), next = d.pci.read8(at + 1) & 0xfc;
            if (id == 0x11) // Use polling with MSI-X disabled on both transports.
                d.pci.write16(at + 2, d.pci.read16(at + 2) & ~0x8000u);
            if (id == 9) {
                uint8_t length = d.pci.read8(at + 2), kind = d.pci.read8(at + 3);
                if (length < 16 || unsigned(at) + length > 256)
                    return false;
                Region mapped{};
                if (kind >= 1 && kind <= 4) {
                    if (!region(d.pci, at, mapped))
                        return false;
                    if (kind == 1) d.common = mapped;
                    if (kind == 2) {
                        if (length < 20)
                            return false;
                        d.notify = mapped;
                        d.notify_multiplier = d.pci.read32(at + 16);
                    }
                    if (kind == 3) d.isr = mapped;
                    if (kind == 4) d.config = mapped;
                }
            }
            at = next;
        }
    }
    if (d.common.bytes && d.common.length >= 56 && d.notify.length >= 2 &&
        d.config.length >= 8 && d.isr.length >= 1) {
        if ((uint64_t(d.common.bytes) & 3) || (uint64_t(d.config.bytes) & 3))
            return false;
        d.modern = true;
        return true;
    }
    if (d.pci.read16(2) != 0x1001)
        return false;
    uint32_t bar = d.pci.read32(0x10);
    if (!(bar & 1) || !(bar & ~3u) || (bar & ~3u) > 0xffc0)
        return false;
    d.io = bar & ~3u;
    return true;
}
static bool initialize(Disk& d) {
    d.pci.write16(4, d.pci.read16(4) | 7 | 0x400); // Decode BARs, bus master, mask INTx.
    if (!transport(d) || !reset(d))
        return false;
    d.set_status(3);
    uint64_t offered;
    if (d.modern) {
        d.common.w32(0, 0);
        offered = d.common.r32(4);
        d.common.w32(0, 1);
        offered |= uint64_t(d.common.r32(4)) << 32;
        if (!(offered & version_one))
            return false;
    } else {
        offered = in32(d.io);
    }
    uint64_t accepted = offered & (feature_ro | feature_flush | (d.modern ? version_one : 0));
    if (d.modern) {
        d.common.w32(8, 0);
        d.common.w32(12, accepted);
        d.common.w32(8, 1);
        d.common.w32(12, accepted >> 32);
        d.set_status(11);
        if (!(d.get_status() & 8))
            return false;
        d.common.w16(22, 0);
        if (d.common.r16(28))
            return false;
        uint16_t offered_size = d.common.r16(24);
        d.size = 256;
        while (d.size > offered_size)
            d.size /= 2;
        d.common.w16(24, d.size);
        uint64_t off = uint64_t(d.common.r16(30)) * d.notify_multiplier;
        if (off > d.notify.length - 2 || (off & 1))
            return false;
        d.notify_offset = off;
    } else {
        out16(d.io + 14, 0);
        out32(d.io + 4, accepted);
        if (in32(d.io + 8))
            return false;
        d.size = in16(d.io + 12);
    }
    if (d.size < 4 || (d.size & (d.size - 1)))
        return false;
    d.info.readonly = accepted & feature_ro;
    d.info.flush_supported = accepted & feature_flush;
    if (d.modern) {
        bool stable = false;
        for (unsigned i = 0; i < 100; i++) {
            uint8_t generation = d.common.r8(21);
            d.info.sectors = d.config.r32(0) | uint64_t(d.config.r32(4)) << 32;
            if (generation == d.common.r8(21)) {
                stable = true;
                break;
            }
        }
        if (!stable)
            return false;
    } else {
        d.info.sectors = in32(d.io + 20) | uint64_t(in32(d.io + 24)) << 32;
    }
    if (!d.info.sectors || d.info.sectors > uint64_t(INT64_MAX) / sector_size)
        return false;
    size_t avail_offset = size_t(d.size) * sizeof(Descriptor);
    size_t used_offset = align_up(avail_offset + 6 + size_t(d.size) * 2);
    size_t pages = align_up(used_offset + 6 + size_t(d.size) * sizeof(UsedEntry)) / page_size;
    d.queue_pages = pages;
    d.queue_physical = page_alloc(pages);
    d.request_physical = page_alloc(1 + transfer_sectors * sector_size / page_size);
    if (!d.queue_physical || !d.request_physical)
        return false;
    d.descriptors = (Descriptor*)physical(d.queue_physical);
    d.avail = (volatile uint16_t*)physical(d.queue_physical + avail_offset);
    d.used = (volatile uint16_t*)physical(d.queue_physical + used_offset);
    d.entries = (volatile UsedEntry*)((volatile uint8_t*)d.used + 4);
    d.request = (Request*)physical(d.request_physical);
    d.status = (volatile uint8_t*)physical(d.request_physical + sizeof(Request));
    d.data = (uint8_t*)physical(d.request_physical + page_size);
    d.avail[0] = 1; // Poll completion; suppress used-buffer interrupts.
    dma_barrier();
    if (d.modern) {
        d.common.w16(16, 0xffff);
        d.common.w16(26, 0xffff);
        d.common.w64(32, d.queue_physical);
        d.common.w64(40, d.queue_physical + avail_offset);
        d.common.w64(48, d.queue_physical + used_offset);
        d.common.w16(28, 1);
        if (d.common.r16(28) != 1)
            return false;
        d.set_status(15);
    } else {
        out32(d.io + 8, d.queue_physical / page_size);
        d.set_status(7);
    }
    if ((d.get_status() & (0x80 | 0x40 | 4)) != 4)
        return false;
    d.live = true;
    return true;
}
static int failed(Disk& d) {
    d.live = false;
    reset(d);
    // DMA allocations stay quarantined even when a broken device refuses reset.
    return -5;
}
static int request(Disk& d, uint32_t type, uint64_t sector, size_t length) {
    if (!d.live)
        return -5;
    if (d.pci.read16(0) != 0x1af4 || (d.get_status() & (0x40 | 0x80)))
        return failed(d);
    *d.request = {type, 0, sector};
    *d.status = 0xff;
    d.descriptors[0] = {d.request_physical, sizeof(Request), 1, uint16_t(length ? 1 : 2)};
    d.descriptors[1] = {d.request_physical + page_size, uint32_t(length), uint16_t(1 | (type == 0 ? 2 : 0)), 2};
    d.descriptors[2] = {d.request_physical + sizeof(Request), 1, 2, 0};
    d.avail[2 + d.available % d.size] = 0;
    dma_barrier();
    d.avail[1] = ++d.available;
    dma_barrier();
    if (d.modern) d.notify.w16(d.notify_offset, 0);
    else out16(d.io + 16, 0);
    uint64_t started = timestamp();
    for (unsigned spins = 0; d.used[1] == d.consumed; spins++) {
        if (expired(started, spins))
            return failed(d);
        asm volatile("pause");
    }
    dma_barrier();
    if (uint16_t(d.used[1] - d.consumed) != 1 ||
        d.entries[d.consumed % d.size].id != 0)
        return failed(d);
    // Legacy devices historically report this field inconsistently.
    uint32_t written = d.entries[d.consumed % d.size].length;
    if (d.modern && (!written || written > (type == 0 ? length + 1 : 1) ||
                    (*d.status == 0 && written != (type == 0 ? length + 1 : 1))))
        return failed(d);
    d.consumed++;
    if (d.modern) d.isr.r8(0);
    else in8(d.io + 19);
    if (*d.status == 0) return 0;
    if (*d.status == 1) return -5;
    if (*d.status == 2) return -95;
    return failed(d);
}
static void discover(const PciFunction& p) {
    uint16_t id = p.read16(2);
    if (attempts == max_disks || p.read16(0) != 0x1af4 || (id != 0x1001 && id != 0x1042))
        return;
    attempts++;
    auto& d = disks[disk_count];
    d = {};
    d.pci = p;
    if (!initialize(d)) {
        if ((d.modern || d.io) && reset(d)) {
            if (d.queue_physical) page_free(d.queue_physical, d.queue_pages);
            if (d.request_physical) page_free(d.request_physical, 1 + transfer_sectors * sector_size / page_size);
        }
        log("virtio-blk: initialization failed at %u:%u.%u\n", uint64_t(p.bus), uint64_t(p.slot), uint64_t(p.function));
        return;
    }
    log("virtio-blk: disk=%u transport=%s sectors=%u readonly=%u flush=%u\n", uint64_t(disk_count),
        d.modern ? "modern" : "legacy", d.info.sectors, uint64_t(d.info.readonly), uint64_t(d.info.flush_supported));
    disk_count++;
}
static int transfer(unsigned device, uint64_t sector, void* buffer, size_t count, bool write) {
    if (device >= disk_count)
        return -19;
    auto& d = disks[device];
    if (sector > d.info.sectors || count > d.info.sectors - sector)
        return -22;
    if (!count)
        return 0;
    if (write && d.info.readonly)
        return -30;
    auto bytes = (uint8_t*)buffer;
    while (count) {
        size_t sectors = min(count, size_t(transfer_sectors)), length = sectors * sector_size;
        if (write) memcpy(d.data, bytes, length);
        int result = request(d, write ? 1 : 0, sector, length);
        if (result) return result;
        if (!write) memcpy(bytes, d.data, length);
        bytes += length;
        sector += sectors;
        count -= sectors;
    }
    return 0;
}
} // namespace
void block_init() {
    calibrate_timeout();
    pci_scan(discover);
}
const BlockInfo* block_info(unsigned device) {
    return device < disk_count ? &disks[device].info : nullptr;
}
int block_read(unsigned device, uint64_t sector, void* data, size_t count) {
    return transfer(device, sector, data, count, false);
}
int block_write(unsigned device, uint64_t sector, const void* data, size_t count) {
    return transfer(device, sector, const_cast<void*>(data), count, true);
}
int block_flush(unsigned device) {
    if (device >= disk_count) return -19;
    auto& d = disks[device];
    if (!d.live) return -5;
    if (d.info.readonly || !d.info.flush_supported) return 0; // Unnegotiated FLUSH means writethrough.
    return request(d, 4, 0, 0);
}
} // namespace ax
