// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "drivers/platform/pci.hpp"
#include "drivers/virtio/queue.hpp"

namespace ax {
// Polling modern/legacy adapters; device-specific config/features stay in drivers.
class VirtioPci {
public:
    VirtioPci() = default;
    VirtioPci(const VirtioPci&) = delete;
    VirtioPci& operator=(const VirtioPci&) = delete;
    bool open(const PciFunction&, uint64_t device_features, size_t config_minimum);
    bool setup_queue(SplitQueue&, uint16_t id, uint16_t preferred = 256, uint16_t minimum = 1);
    bool read_config(size_t offset, void* output, size_t length) const;
    bool start();
    bool healthy() const;
    bool notify(const SplitQueue&) const;
    int wait(SplitQueue&, VirtioCompletion&) const;
    bool stop();
    bool modern() const { return mode_ == Mode::modern; }
    uint64_t features() const { return accepted_; }
private:
    enum class Mode { none, modern, legacy };
    struct Region {
        volatile uint8_t* bytes = nullptr;
        uint32_t length = 0;
        uint8_t r8(size_t off) const { return bytes[off]; }
        uint16_t r16(size_t off) const { return *(volatile uint16_t*)(bytes + off); }
        uint32_t r32(size_t off) const { return *(volatile uint32_t*)(bytes + off); }
        void w8(size_t off, uint8_t v) const { bytes[off] = v; }
        void w16(size_t off, uint16_t v) const { *(volatile uint16_t*)(bytes + off) = v; }
        void w32(size_t off, uint32_t v) const { *(volatile uint32_t*)(bytes + off) = v; }
        void w64(size_t off, uint64_t v) const { w32(off, v); w32(off + 4, v >> 32); }
    };
    struct Binding { SplitQueue* queue = nullptr; uint16_t id = 0; uint32_t notify = 0; };
    PciFunction pci_{};
    Mode mode_ = Mode::none;
    Region common_, notify_, config_, isr_;
    Binding queues_[8]{};
    uint16_t io_ = 0;
    uint32_t notify_multiplier_ = 0;
    uint64_t accepted_ = 0;
    bool opened_ = false, initialized_ = false, running_ = false;
    bool map_region(uint8_t capability, Region&);
    bool discover(size_t config_minimum);
    void set_status(uint8_t) const;
    uint8_t status() const;
};
} // namespace ax
