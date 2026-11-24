// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_start.cpp
 * @brief   Start AX201 QuZ firmware, receive ALIVE, and stop DMA.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * The Gen2 sequence follows Linux iwlwifi pcie/trans.c, pcie/trans-gen2.c,
 * pcie/rx.c, iwl-csr.h, and iwl-prph.h. API 77 advertises ALIVE version 6.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_start.hpp"
#include "mm/dma.hpp"

namespace ax::IntelWifi {
namespace {
constexpr unsigned hw_if = 0x00, interrupts = 0x08, interrupt_mask = 0x0c, flow_interrupts = 0x10;
constexpr unsigned reset = 0x20, gp = 0x24, gio = 0x3c, context_base = 0x40, driver_gp_clear = 0x5c;
constexpr unsigned mailbox_set = 0x88, shadow_control = 0xa8, gio_chicken = 0x100;
constexpr unsigned hpet_debug = 0x240, link_power = 0x250;
constexpr unsigned prph_write_address = 0x444, prph_read_address = 0x448;
constexpr unsigned prph_write_data = 0x44c, prph_read_data = 0x450, receive_write_pointer = 0x1c80;
constexpr unsigned hpm_debug = 0xa03440, hpm_power = 0xa03458, hpm_ltr_control = 0xa0348c;
constexpr unsigned hpm_ltr = 0xa03480, peripheral_write_protect = 0xa04d00, cpu_start = 0xa05c44;
constexpr uint32_t pci_owned = 1u << 22, wake_me = 1u << 27, hap_wake = 1u << 19;
constexpr uint32_t init_done = 1u << 2, access_request = 1u << 3, clock_ready = 1u << 0;
constexpr uint32_t sleeping = 1u << 4, rf_enabled = 1u << 27, software_reset = 1u << 7;
constexpr uint32_t stop_master = 1u << 9, master_disabled = 1u << 8;
constexpr uint32_t alive_interrupt = 1u, rx_interrupt = 1u << 31;
constexpr uint32_t error_interrupts = (1u << 29) | (1u << 25);

struct Registers {
    const FirmwareBootIo& io;

    uint32_t read(unsigned offset) const {
        return io.read(io.context, offset);
    }

    void write(unsigned offset, uint32_t value) const {
        io.write(io.context, offset, value);
    }

    bool delay(unsigned microseconds) const {
        return io.delay(io.context, microseconds);
    }

    bool update(unsigned offset, uint32_t set, uint32_t clear = 0) const {
        const auto value = read(offset);
        if (value == UINT32_MAX)
            return false;
        write(offset, (value & ~clear) | set);
        return true;
    }

    bool wait(unsigned offset, uint32_t mask, uint32_t value, unsigned attempts) const {
        for (unsigned i = 0; i < attempts; ++i) {
            const auto current = read(offset);
            if (current == UINT32_MAX)
                return false;
            if ((current & mask) == value)
                return true;
            if (!delay(10))
                return false;
        }
        return false;
    }

    uint32_t read_peripheral(unsigned address) const {
        write(prph_read_address, 0x03000000 | address);
        return read(prph_read_data);
    }

    void write_peripheral(unsigned address, uint32_t value) const {
        write(prph_write_address, 0x03000000 | address);
        write(prph_write_data, value);
    }
};

bool claim(const Registers& reg) {
    if (!reg.update(hw_if, pci_owned) || !reg.wait(hw_if, pci_owned, pci_owned, 5))
        return false;
    return reg.update(mailbox_set, 1u << 5);
}

bool claim_with_wake(const Registers& reg) {
    if (claim(reg))
        return true;
    const auto power = reg.read(link_power);
    if (power == UINT32_MAX)
        return false;
    reg.write(link_power, power | (1u << 31));
    if (!reg.delay(1000) || !reg.update(hw_if, wake_me)) {
        reg.write(link_power, power);
        return false;
    }
    bool owned = false;
    for (unsigned i = 0; i < 150 && !owned; ++i) {
        owned = claim(reg);
        if (!owned && !reg.delay(1000))
            break;
    }
    reg.write(link_power, power);
    return owned;
}

bool acquire_mac(const Registers& reg) {
    return reg.update(gp, init_done | access_request) && reg.delay(2) &&
           reg.wait(gp, clock_ready | sleeping, clock_ready, 2500);
}

bool reset_adapter(const Registers& reg) {
    if (!reg.update(reset, software_reset))
        return false;
    for (unsigned i = 0; i < 5; ++i)
        if (!reg.delay(1000))
            return false;
    return true;
}

const char* prepare_adapter(const Registers& reg, bool& owned) {
    if (!acquire_mac(reg))
        return "MAC clock did not start";
    const auto debug = reg.read_peripheral(hpm_debug);
    constexpr uint32_t persistence = 1u << 12;
    if (debug != UINT32_MAX && (debug & 0xfffffff0u) != 0xa5a5a5a0 && (debug & persistence)) {
        const auto protection = reg.read_peripheral(peripheral_write_protect);
        if (protection & persistence)
            return "firmware persistence is write-protected";
        reg.write_peripheral(hpm_debug, debug & ~persistence);
    }
    owned = reset_adapter(reg) && claim_with_wake(reg);
    if (!owned || !acquire_mac(reg))
        return "MAC did not return after reset";

    // The integrated 22000 MAC needs the power-gating sequence before the final reset.
    const auto power = reg.read_peripheral(hpm_power);
    if (power == UINT32_MAX || (power & 0xfffffff0u) == 0xa5a5a5a0)
        return "MAC power registers unavailable";
    constexpr uint32_t force_active = 1u << 10, enable_gating_and_sleep = 3;
    reg.write_peripheral(hpm_power, power | force_active);
    if (!reg.delay(20))
        return "MAC power wait failed";
    reg.write_peripheral(hpm_power, power | force_active | enable_gating_and_sleep);
    if (!reg.delay(20))
        return "MAC power wait failed";
    reg.write_peripheral(hpm_power, (power | enable_gating_and_sleep) & ~force_active);

    owned = reset_adapter(reg) && claim_with_wake(reg);
    if (!owned)
        return "MAC did not return after power setup";
    reg.write(interrupt_mask, 0);
    reg.write(interrupts, UINT32_MAX);
    reg.write(flow_interrupts, UINT32_MAX);
    if (!reg.update(gio_chicken, 1u << 23) || !reg.update(hpet_debug, 0xffff0000) ||
        !reg.update(hw_if, hap_wake) || !reg.update(gio, 2) || !acquire_mac(reg))
        return "MAC clock did not stabilize";
    const auto control = reg.read(gp);
    if (control == UINT32_MAX)
        return "MAC registers unavailable";
    if (!(control & rf_enabled))
        return "Wi-Fi is blocked by the hardware switch";
    reg.write(driver_gp_clear, (1u << 1) | (1u << 2));
    reg.write(shadow_control, 0x800fffff);
    // Keep the integrated MAC's ROM reads within the PCIe latency budget during boot.
    constexpr uint32_t ltr_250us = 0x80008000 | (2u << 26) | (250u << 16) | (2u << 10) | 250u;
    reg.write_peripheral(hpm_ltr_control, 0xf);
    reg.write_peripheral(hpm_ltr, ltr_250us);
    return nullptr;
}

AlivePacket poll_receive(const FirmwareBootIo& io, const FirmwareBootMemory& memory,
                         unsigned& read) {
    const unsigned closed = memory.receive_status->closed_buffer & rx_buffer_id_mask;
    if (closed >= rx_ring_entries)
        return AlivePacket::malformed;
    // The device completes each buffer before advancing its coherent status pointer.
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    while (read != closed) {
        const unsigned id = memory.used_ring[read] & rx_buffer_id_mask;
        const uint8_t* buffer = io.receive_buffer(io.context, id);
        if (!buffer)
            return AlivePacket::malformed;
        const auto result = read_alive_notification(buffer, page_size);
        if (result != AlivePacket::missing)
            return result;
        read = (read + 1) % rx_ring_entries;
    }
    return AlivePacket::missing;
}

const char* wait_for_alive(const Registers& reg, const FirmwareBootMemory& memory) {
    bool posted = false;
    unsigned read = 0;
    for (unsigned i = 0; i < 2000; ++i) {
        const auto cause = reg.read(interrupts);
        if (cause == UINT32_MAX || (cause & error_interrupts))
            return "firmware startup hardware error";
        if (!posted && (cause & alive_interrupt)) {
            // Firmware programs the RX engine before it raises ALIVE. Publish whole blocks of
            // eight.
            __atomic_thread_fence(__ATOMIC_RELEASE);
            reg.write(receive_write_pointer, (rx_ring_entries - 1) & ~7u);
            posted = true;
        }
        if (cause)
            reg.write(interrupts, cause);
        if (posted) {
            switch (poll_receive(reg.io, memory, read)) {
            case AlivePacket::success:
                return nullptr;
            case AlivePacket::rejected:
                return "firmware rejected startup";
            case AlivePacket::malformed:
                return "invalid firmware notification";
            case AlivePacket::missing:
                break;
            }
        }
        if (!reg.delay(1000))
            return "firmware startup timer unavailable";
    }
    return posted ? "firmware ALIVE message timed out" : "firmware ALIVE interrupt timed out";
}
} // namespace

AlivePacket read_alive_notification(const uint8_t* data, size_t length) {
    constexpr unsigned descriptor_header = 4, command_header = 4, frame_align = 64;
    constexpr unsigned v6_payload = 144;
    if (!data)
        return AlivePacket::malformed;
    for (size_t offset = 0; length - offset >= descriptor_header + command_header;) {
        const auto* p = data + offset;
        const uint32_t flags = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
                               (uint32_t(p[3]) << 24);
        if (!flags || flags == 0x55550000)
            return AlivePacket::missing;
        const auto bytes = (flags & 0x3fff) + descriptor_header;
        if (bytes < descriptor_header + command_header || bytes > length - offset ||
            (flags & 0x3f0000))
            return AlivePacket::malformed;
        if (p[4] == 1 && p[5] == 0) {
            if (bytes < descriptor_header + command_header + v6_payload)
                return AlivePacket::malformed;
            return p[8] == 0xfe && p[9] == 0xca ? AlivePacket::success : AlivePacket::rejected;
        }
        const auto stride = (bytes + frame_align - 1) & ~(frame_align - 1);
        if (stride > length - offset)
            return AlivePacket::malformed;
        offset += stride;
    }
    return AlivePacket::missing;
}

FirmwareBootResult start_and_stop_quz(const FirmwareBootIo& io, const FirmwareBootMemory& memory) {
    if (!memory.context_address || memory.context_address != align_down(memory.context_address) ||
        !Dma::fits(memory.context_address, sizeof(BootContext), Dma::pci) ||
        !memory.receive_status || !memory.used_ring)
        return {"invalid startup DMA addresses", false, true};
    const Registers reg{io};
    if (!claim_with_wake(reg))
        return {"PCI ownership unavailable", false, true};

    bool owned = true;
    const char* error = prepare_adapter(reg, owned);
    if (!owned)
        return {error, false, true};
    const bool request_dma = error == nullptr;
    if (request_dma) {
        if (!io.bus_master(io.context, true)) {
            error = "PCI bus master did not enable";
        } else {
            __atomic_thread_fence(__ATOMIC_RELEASE);
            reg.write(context_base, uint32_t(memory.context_address));
            reg.write(context_base + 4, 0);
            reg.write(interrupt_mask, alive_interrupt | rx_interrupt | error_interrupts);
            reg.write_peripheral(cpu_start, 1);
            error = wait_for_alive(reg, memory);
        }
    }

    reg.write(interrupt_mask, 0);
    bool idle = true;
    if (request_dma) {
        const bool stopped = reg.update(reset, stop_master) &&
                             reg.wait(reset, master_disabled, master_disabled, 200);
        const bool disabled = io.bus_master(io.context, false);
        idle = stopped && disabled;
    }
    const bool reset_done = reset_adapter(reg);
    return {error ? error : "firmware ALIVE received", !error,
            !request_dma || (idle && reset_done)};
}
} // namespace ax::IntelWifi
