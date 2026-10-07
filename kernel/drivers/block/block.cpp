// SPDX-License-Identifier: GPL-3.0-or-later
#include "drivers/block/block.hpp"
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
struct Disk {
    VirtioPci pci;
    SplitQueue queue;
    BlockInfo info{};
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
    d.info.readonly = d.pci.features() & feature_ro;
    d.info.flush_supported = d.pci.features() & feature_flush;
    if (!d.pci.read_config(0, &d.info.sectors, sizeof(d.info.sectors)) || !d.info.sectors ||
        d.info.sectors > uint64_t(INT64_MAX) / sector_size)
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
    if (d.pci.wait(d.queue, completed) || completed.head != head ||
        completed.cookie != d.request_physical)
        return failed(d);
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
    log("virtio-blk: disk=%u transport=%s sectors=%u readonly=%u flush=%u\n", uint64_t(disk_count),
        d.pci.modern() ? "modern" : "legacy", d.info.sectors, uint64_t(d.info.readonly),
        uint64_t(d.info.flush_supported));
    log("virtio-queue: disk=%u id=0 size=%u\n", uint64_t(disk_count),
        uint64_t(d.queue.layout().size));
    disk_count++;
}
static int transfer(unsigned device, uint64_t sector, void* buffer, size_t count, bool write) {
    if (device >= disk_count)
        return -19;
    auto& d = *disks[device];
    if (sector > d.info.sectors || count > d.info.sectors - sector)
        return -22;
    if (!count)
        return 0;
    if (write && d.info.readonly)
        return -30;
    if (!d.live)
        return -5;
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
} // namespace
void block_init() {
    pci_scan(discover);
}
const BlockInfo* block_info(unsigned device) {
    return device < disk_count ? &disks[device]->info : nullptr;
}
int block_read(unsigned device, uint64_t sector, void* data, size_t count) {
    return transfer(device, sector, data, count, false);
}
static const void* block_owners[8];
int block_claim(unsigned device, const void* owner) {
    if (!block_info(device))
        return -19;
    if (!owner)
        return -22;
    if (block_owners[device])
        return -16;
    block_owners[device] = owner;
    return 0;
}
void block_unclaim(unsigned device, const void* owner) {
    if (device < 8 && block_owners[device] == owner)
        block_owners[device] = nullptr;
}
bool block_claimed(unsigned device) {
    return device < 8 && block_owners[device];
}
int block_write(unsigned device, uint64_t sector, const void* data, size_t count,
                const void* owner) {
    if (device < 8 && block_owners[device] && block_owners[device] != owner)
        return -16;
    return transfer(device, sector, const_cast<void*>(data), count, true);
}
int block_flush(unsigned device) {
    if (device >= disk_count)
        return -19;
    auto& d = *disks[device];
    if (!d.live)
        return -5;
    if (d.info.readonly || !d.info.flush_supported)
        return 0; // Unnegotiated FLUSH means writethrough.
    return request(d, 4, 0, 0);
}
} // namespace ax
