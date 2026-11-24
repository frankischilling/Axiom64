// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_context.cpp
 * @brief   Prepare the AX201 QuZ startup context and initial descriptor contents.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Layout and encoding follow Linux iwlwifi's fw/api/ctxt-info.h, iwl-fh.h,
 * pcie/ctxt-info.c and pcie/rx.c. The AX201 queue lengths follow cfg/22000.c.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_context.hpp"
#include "mm/dma.hpp"

namespace ax::IntelWifi {
namespace {
constexpr uint32_t rx_wrap_exponent = 11;
constexpr uint32_t long_tfd = 1 << 8;
constexpr uint32_t rx_size_4k = 4 << 9;
constexpr uint8_t command_wrap_exponent = 5;
static_assert(rx_ring_entries == 1u << rx_wrap_exponent &&
              command_ring_entries == 1u << command_wrap_exponent);

bool valid_dma_page(uint64_t address, size_t bytes) {
    return address && address == align_down(address) && Dma::fits(address, bytes, Dma::pci);
}
} // namespace

bool make_boot_context(const FirmwareImage& image, const FirmwareAddresses& addresses,
                       ReceiveQueues rx, uint64_t command_ring, BootContext& output) {
    if (!valid_dma_page(rx.free_ring, rx_ring_entries * sizeof(uint64_t)) ||
        !valid_dma_page(rx.used_ring, rx_ring_entries * sizeof(uint32_t)) ||
        !valid_dma_page(rx.status, sizeof(ReceiveStatus)) ||
        !valid_dma_page(command_ring, command_ring_entries * sizeof(CommandDescriptor)))
        return false;

    BootContext context{};
    context.mac_id = quz_mac_revision;
    context.dwords = sizeof(BootContext) / sizeof(uint32_t);
    context.control = (rx_wrap_exponent << 4) | long_tfd | rx_size_4k;
    context.rx = rx;
    context.commands = command_ring;
    context.command_size = command_wrap_exponent - 3;

    uint64_t* maps[region_count]{};
    maps[lmac] = context.lmac;
    maps[umac] = context.umac;
    maps[paging] = context.paging;
    for (unsigned region = 0; region < region_count; ++region) {
        const auto& sections = image.regions[region];
        if (!sections.count || sections.count > max_sections)
            return false;
        for (unsigned i = 0; i < sections.count; ++i) {
            const auto bytes = sections.sections[i].size;
            const auto address = addresses[region][i];
            if (!bytes || bytes > max_section_bytes || !valid_dma_page(address, bytes))
                return false;
            maps[region][i] = address;
        }
    }
    output = context;
    return true;
}

bool encode_receive_buffer(uint64_t address, unsigned id, uint64_t& descriptor) {
    if (!id || id > rx_buffer_id_mask || !valid_dma_page(address, page_size))
        return false;
    descriptor = address | id;
    return true;
}

bool initialize_transmit_ring(uint64_t invalid_command, CommandDescriptor* ring, unsigned entries) {
    if (!valid_dma_page(invalid_command, invalid_command_size))
        return false;
    for (unsigned i = 0; i < entries; ++i) {
        auto& descriptor = ring[i];
        descriptor = {};
        descriptor.buffer_count = 1;
        descriptor.buffers[0] = {invalid_command_size, invalid_command};
    }
    return true;
}

bool prepare_command_ring(uint64_t invalid_command, uint8_t (&payload)[invalid_command_size],
                          CommandDescriptor (&ring)[command_ring_entries]) {
    if (!initialize_transmit_ring(invalid_command, ring, command_ring_entries))
        return false;
    // A debug command with an invalid sequence protects unused slots from stray fetches.
    const uint8_t invalid_header[invalid_command_size] = {6, 15, 0xff, 0xff, 0, 0, 0, 0};
    memcpy(payload, invalid_header, sizeof(payload));
    return true;
}
} // namespace ax::IntelWifi
