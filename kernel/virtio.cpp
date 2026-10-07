// SPDX-License-Identifier: GPL-3.0-or-later
#include "virtio.hpp"

namespace ax {
namespace {
constexpr uint64_t version_one = 1ull << 32;
static uint64_t tsc_frequency;
static bool calibrated;
static uint64_t timestamp() {
    uint32_t low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    return uint64_t(high) << 32 | low;
}
static void calibrate_timeout() {
    if (calibrated) return;
    calibrated = true;
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
} // namespace
void VirtioPci::set_status(uint8_t value) const {
    if (modern()) common_.w8(20, value);
    else out8(io_ + 18, value);
}
uint8_t VirtioPci::status() const {
    return modern() ? common_.r8(20) : in8(io_ + 18);
}
bool VirtioPci::map_region(uint8_t capability, Region& result) {
    uint64_t bar;
    uint32_t offset = pci_.read32(capability + 8), length = pci_.read32(capability + 12);
    if (!length || !pci_.memory_bar(pci_.read8(capability + 4), bar) ||
        bar > (1ull << 52) - offset || length > (1ull << 52) - bar - offset)
        return false;
    void* mapped = map_mmio(bar + offset, length);
    if (!mapped)
        return false;
    result = {(volatile uint8_t*)mapped, length};
    return true;
}
bool VirtioPci::discover(size_t minimum) {
    if (pci_.read16(6) & 16) {
        uint8_t at = pci_.read8(0x34) & 0xfc;
        bool seen[256]{};
        while (at) {
            if (at < 0x40 || seen[at]) return false;
            seen[at] = true;
            uint8_t id = pci_.read8(at), next = pci_.read8(at + 1) & 0xfc;
            if (id == 0x11) // MSI-X disabled; legacy config begins at offset 20.
                pci_.write16(at + 2, pci_.read16(at + 2) & ~0x8000u);
            if (id == 5)
                pci_.write16(at + 2, pci_.read16(at + 2) & ~1u);
            if (id == 9) {
                uint8_t length = pci_.read8(at + 2), kind = pci_.read8(at + 3);
                if (length < 16 || unsigned(at) + length > 256) return false;
                Region* target = kind == 1 ? &common_ : kind == 2 ? &notify_ :
                                 kind == 3 ? &isr_ : kind == 4 ? &config_ : nullptr;
                if (target && !target->bytes) {
                    if (!map_region(at, *target)) return false;
                    if (kind == 2) {
                        if (length < 20) return false;
                        notify_multiplier_ = pci_.read32(at + 16);
                        if (notify_multiplier_ && ((notify_multiplier_ & 1) ||
                            (notify_multiplier_ & (notify_multiplier_ - 1)))) return false;
                    }
                }
            }
            at = next;
        }
    }
    if (common_.bytes && common_.length >= 56 && notify_.length >= 2 &&
        config_.length >= minimum && isr_.length >= 1) {
        if ((uint64_t(common_.bytes) & 3) || (uint64_t(config_.bytes) & 3) ||
            (uint64_t(notify_.bytes) & 1)) return false;
        mode_ = Mode::modern;
        return true;
    }
    uint16_t id = pci_.read16(2);
    if (id < 0x1000 || id > 0x103f) return false;
    uint32_t bar = pci_.read32(0x10);
    if (!(bar & 1) || !(bar & ~3u) || (bar & ~3u) > 0xffc0) return false;
    io_ = bar & ~3u;
    if (minimum > 0x10000u - io_ - 20) return false;
    mode_ = Mode::legacy;
    return true;
}
bool VirtioPci::open(const PciFunction& pci, uint64_t features, size_t minimum) {
    // Transport features are managed here; no indirect/event-index/packed rings.
    if (opened_ || pci.read16(0) != 0x1af4 || features >> 24 || minimum > 256)
        return false;
    opened_ = true;
    pci_ = pci;
    calibrate_timeout();
    pci_.write16(4, pci_.read16(4) | 7 | 0x400);
    if (!discover(minimum) || !stop()) return false;
    set_status(3);
    uint64_t offered;
    if (modern()) {
        common_.w32(0, 0);
        offered = common_.r32(4);
        common_.w32(0, 1);
        offered |= uint64_t(common_.r32(4)) << 32;
        if (!(offered & version_one)) return false;
    } else {
        offered = in32(io_);
    }
    accepted_ = offered & (features | (modern() ? version_one : 0));
    if (modern()) {
        common_.w32(8, 0);
        common_.w32(12, accepted_);
        common_.w32(8, 1);
        common_.w32(12, accepted_ >> 32);
        set_status(11);
        if (!(status() & 8)) return false;
        common_.w16(16, 0xffff);
    } else {
        out32(io_ + 4, accepted_);
    }
    initialized_ = true;
    return true;
}
bool VirtioPci::setup_queue(SplitQueue& queue, uint16_t id, uint16_t preferred, uint16_t minimum) {
    if (!initialized_ || running_ || !preferred || preferred > 32768 ||
        (preferred & (preferred - 1)) || !minimum || minimum > preferred || queue.layout().size)
        return false;
    Binding* binding = nullptr;
    for (auto& item : queues_) {
        if (item.queue == &queue || (item.queue && item.id == id)) return false;
        if (!item.queue && !binding) binding = &item;
    }
    if (!binding) return false;
    uint16_t size;
    uint32_t notify_offset = 0;
    if (modern()) {
        if (id >= common_.r16(18)) return false;
        common_.w16(22, id);
        if (common_.r16(28)) return false;
        uint16_t offered = common_.r16(24);
        if (!offered || offered > 32768 || (offered & (offered - 1))) return false;
        size = preferred;
        while (size > offered) size /= 2;
        if (size < minimum) return false;
        common_.w16(24, size);
        if (common_.r16(24) != size) return false;
        uint64_t off = uint64_t(common_.r16(30)) * notify_multiplier_;
        if (off > notify_.length - 2 || (off & 1)) return false;
        notify_offset = off;
    } else {
        out16(io_ + 14, id);
        if (in32(io_ + 8)) return false;
        size = in16(io_ + 12); // Read-only size; never clamp a legacy ring.
    }
    if (size < minimum || !queue.create(size)) return false;
    const auto layout = queue.layout();
    if (!modern() && layout.descriptors / page_size > UINT32_MAX) return false;
    *binding = {&queue, id, notify_offset};
    queue.device_owned_ = true; // Before handing any address to the device.
    virtio_dma_barrier();
    if (modern()) {
        common_.w16(26, 0xffff);
        common_.w64(32, layout.descriptors);
        common_.w64(40, layout.available);
        common_.w64(48, layout.used);
        common_.w16(28, 1);
        if (common_.r16(28) != 1) return false;
    } else {
        out32(io_ + 8, layout.descriptors / page_size);
        if (in32(io_ + 8) != layout.descriptors / page_size) return false;
    }
    return true;
}
bool VirtioPci::read_config(size_t offset, void* output, size_t length) const {
    size_t limit = modern() ? config_.length : 0x10000u - io_ - 20;
    if (!initialized_ || !output || offset > limit || length > limit - offset) return false;
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        uint8_t generation = modern() ? common_.r8(21) : 0;
        auto bytes = (uint8_t*)output;
        size_t at = offset, left = length;
        while (left) {
            unsigned width = !(at & 3) && left >= 4 ? 4 : !(at & 1) && left >= 2 ? 2 : 1;
            uint32_t value = modern() ? (width == 4 ? config_.r32(at) : width == 2 ? config_.r16(at) : config_.r8(at)) :
                (width == 4 ? in32(io_ + 20 + at) : width == 2 ? in16(io_ + 20 + at) : in8(io_ + 20 + at));
            memcpy(bytes, &value, width);
            bytes += width;
            at += width;
            left -= width;
        }
        virtio_dma_barrier();
        if (!modern() || generation == common_.r8(21)) return true;
    }
    return false;
}
bool VirtioPci::start() {
    if (!initialized_ || running_) return false;
    bool present = false;
    for (const auto& item : queues_) present |= item.queue != nullptr;
    if (!present) return false;
    set_status(modern() ? 15 : 7);
    running_ = true;
    if (!healthy()) { running_ = false; return false; }
    for (const auto& item : queues_)
        if (item.queue && item.queue->pending_ && !notify(*item.queue)) return false;
    return true;
}
bool VirtioPci::healthy() const {
    return running_ && pci_.read16(0) == 0x1af4 && (status() & (0x80 | 0x40 | 4)) == 4;
}
bool VirtioPci::notify(const SplitQueue& queue) const {
    if (!healthy() || queue.broken_ || !queue.device_owned_) return false;
    for (const auto& item : queues_)
        if (item.queue == &queue) {
            virtio_dma_barrier();
            if (modern()) notify_.w16(item.notify, item.id);
            else out16(io_ + 16, item.id);
            return true;
        }
    return false;
}
int VirtioPci::wait(SplitQueue& queue, VirtioCompletion& completion) const {
    bool bound = false;
    for (const auto& item : queues_) bound |= item.queue == &queue;
    if (!bound || !healthy()) return -5;
    uint64_t started = timestamp();
    for (unsigned spins = 0; !expired(started, spins); spins++) {
        int result = queue.complete(completion);
        if (result < 0 || !healthy()) return -5;
        if (result) {
            if (modern()) isr_.r8(0);
            else in8(io_ + 19);
            return 0;
        }
        asm volatile("pause");
    }
    return -5;
}
bool VirtioPci::stop() {
    running_ = initialized_ = false;
    if (mode_ == Mode::none) return false;
    set_status(0);
    uint64_t started = timestamp();
    for (unsigned spins = 0; !expired(started, spins); spins++) {
        if (!status()) {
            virtio_dma_barrier();
            for (auto& item : queues_)
                if (item.queue) {
                    item.queue->device_owned_ = false;
                    item.queue->broken_ = true;
                    item = {};
                }
            return true;
        }
        asm volatile("pause");
    }
    // Bindings and device-owned allocations remain quarantined after failed reset.
    for (auto& item : queues_)
        if (item.queue) item.queue->broken_ = true;
    return false;
}
} // namespace ax
