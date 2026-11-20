// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/e1000.cpp
 * @brief   Drives Intel-compatible Ethernet rings on supported PCI devices.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Initializes the MAC and exchanges frames through legacy descriptors.
 * The 82574L supports PCI MSI. Both adapters can use firmware-routed INTx.
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
#include "net/ethernet.hpp"
#include "drivers/platform/pci.hpp"
#include "drivers/virtio/queue.hpp"
#include "ipc/ipc.hpp"

namespace ax {
namespace {
constexpr unsigned ring_size = 64, buffer_size = 2048;
constexpr uint32_t model_82540em = 0x100e8086, model_82574l = 0x10d38086;
constexpr unsigned ctrl = 0, status = 8, icr = 0xc0, ics = 0xc8, ims = 0xd0, imc = 0xd8,
                   rctl = 0x100;
constexpr uint32_t tx_writeback = 1u << 0, link_change = 1u << 2, rx_timer = 1u << 7;
constexpr uint32_t interrupt_sources = tx_writeback | link_change | rx_timer;
constexpr unsigned tctl = 0x400, tipg = 0x410, rx_base = 0x2800, tx_base = 0x3800;
constexpr unsigned rx_checksum = 0x5000;
constexpr uint32_t disable_packet_checksum = 1u << 13;
constexpr unsigned mac_low = 0x5400, mac_high = 0x5404, multicast = 0x5200;

struct RxDescriptor {
    uint64_t address;
    uint16_t length, checksum;
    uint8_t status, errors;
    uint16_t special;
};

struct TxDescriptor {
    uint64_t address;
    uint16_t length;
    uint8_t checksum_offset, command, status, checksum_start;
    uint16_t special;
};

static_assert(sizeof(RxDescriptor) == 16 && sizeof(TxDescriptor) == 16);

struct Controller {
    NetAdapter adapter{};
    PciFunction pci{};
    PciMsi msi;
    PciIntx intx;
    uint32_t model = 0;
    volatile uint32_t* registers = nullptr;
    uint64_t rings = 0, receive = 0, transmit = 0;
    volatile RxDescriptor* rx = nullptr;
    volatile TxDescriptor* tx = nullptr;
    unsigned rx_next = 0, tx_next = 0, tx_oldest = 0, pending = 0;
    bool fragment = false;
    bool irq_rx_reported = false, irq_tx_reported = false;
    bool probing_intx = false;
    volatile bool intx_observed = false;

    uint32_t read(unsigned offset) const {
        return registers[offset / 4];
    }

    void write(unsigned offset, uint32_t value) const {
        registers[offset / 4] = value;
        read(status); // Drain posted register writes.
    }
};

static Controller controllers[max_net_devices];
static unsigned attempts;

static void stop(NetAdapter& adapter) {
    auto& device = *static_cast<Controller*>(adapter.data);
    adapter.info.live = adapter.info.writable = adapter.info.carrier = false;
    if (device.registers) {
        device.write(imc, UINT32_MAX);
        device.write(rctl, 0);
        device.write(tctl, 0);
        device.read(icr);
    }
    device.msi.stop(device.pci);
    device.intx.stop(device.pci);
    device.pci.write16(4, (device.pci.read16(4) | 0x400) & ~uint16_t(4));
    // DMA pages remain owned for the controller's entire lifetime, even on failure.
}

static void poll(NetAdapter& adapter) {
    auto& device = *static_cast<Controller*>(adapter.data);
    if (!adapter.info.live)
        return;
    uint32_t state = device.read(status);
    if (state == UINT32_MAX || device.pci.read32(0) != device.model) {
        while (device.pending) {
            net_tx_complete(adapter, device.tx[device.tx_oldest].length, true);
            device.tx_oldest = (device.tx_oldest + 1) % ring_size;
            device.pending--;
        }
        stop(adapter);
        return;
    }
    adapter.info.carrier = state & 2;
    if (device.intx.delivery_failed()) {
        device.write(imc, UINT32_MAX);
        device.intx.stop(device.pci);
    }
    if (!device.msi.active() && !device.intx.active())
        device.read(icr); // Discard causes for polling devices.
    while (device.pending && (device.tx[device.tx_oldest].status & 1)) {
        virtio_dma_barrier();
        const auto& descriptor = device.tx[device.tx_oldest];
        net_tx_complete(adapter, descriptor.length, descriptor.status & 0x0e);
        device.tx_oldest = (device.tx_oldest + 1) % ring_size;
        device.pending--;
    }
    for (unsigned budget = 0; budget < ring_size; budget++) {
        auto& descriptor = device.rx[device.rx_next];
        if (!(descriptor.status & 1))
            break;
        virtio_dma_barrier();
        bool end = descriptor.status & 2;
        if (!end || device.fragment || descriptor.errors || descriptor.length < ethernet_header ||
            descriptor.length > 1518)
            net_rx_error(adapter);
        else
            net_receive(adapter, physical(device.receive + device.rx_next * buffer_size),
                        descriptor.length);
        device.fragment = !end;
        descriptor.status = 0;
        descriptor.errors = 0;
        descriptor.length = 0;
        virtio_dma_barrier();
        device.write(rx_base + 0x18, device.rx_next);
        device.rx_next = (device.rx_next + 1) % ring_size;
    }
    adapter.info.writable = device.pending < ring_size - 1;
}

static int send(NetAdapter& adapter, const void* frame, size_t length) {
    auto& device = *static_cast<Controller*>(adapter.data);
    if (!adapter.info.live)
        return -5;
    if (device.pending == ring_size - 1)
        return -11;
    unsigned index = device.tx_next;
    auto& descriptor = device.tx[index];
    memcpy(physical(device.transmit + index * buffer_size), frame, length);
    descriptor.address = device.transmit + index * buffer_size;
    descriptor.length = length;
    descriptor.checksum_offset = 0;
    descriptor.checksum_start = 0;
    descriptor.special = 0;
    descriptor.status = 0;
    descriptor.command = 1 | 2 | 8; // End of packet, FCS insertion, completion writeback.
    virtio_dma_barrier();
    device.pending++;
    device.tx_next = (index + 1) % ring_size;
    device.write(tx_base + 0x18, device.tx_next);
    adapter.info.writable = device.pending < ring_size - 1;
    return 0;
}

static bool interrupt(void* context) {
    auto& device = *static_cast<Controller*>(context);
    uint32_t cause = device.read(icr);
    if (!(cause & interrupt_sources))
        return false;
    if (device.probing_intx && cause != UINT32_MAX && (cause & tx_writeback))
        device.intx_observed = true;
    const char* mode = device.msi.active() ? "MSI" : "INTx";
    const auto& info = device.adapter.info;
    uint64_t rx_before = info.stats.rx_packets, tx_before = info.stats.tx_packets;
    bool previous_carrier = info.carrier, previous_live = info.live;
    poll(device.adapter);
    if (info.stats.rx_packets != rx_before && !device.irq_rx_reported) {
        device.irq_rx_reported = true;
        log("e1000: %s RX completion index=%u\n", mode, uint64_t(info.index));
    }
    if (info.stats.tx_packets != tx_before && !device.irq_tx_reported) {
        device.irq_tx_reported = true;
        log("e1000: %s TX completion index=%u\n", mode, uint64_t(info.index));
    }
    if (info.stats.rx_packets != rx_before || info.stats.tx_packets != tx_before ||
        previous_carrier != info.carrier || previous_live != info.live)
        epoll_notify();
    return true;
}

static void message_interrupt(void* context) {
    interrupt(context);
}

static void configure_interrupt(Controller& device) {
    const auto& pci = device.pci;
    if (device.model == model_82574l && device.msi.start(pci, message_interrupt, &device)) {
        device.read(icr);
        device.write(ims, interrupt_sources);
        if ((device.read(ims) & interrupt_sources) == interrupt_sources)
            return;
        device.write(imc, UINT32_MAX);
        device.msi.stop(pci);
    }
    if (!device.intx.start(pci, interrupt, &device))
        return;
    device.read(icr);
    device.probing_intx = true;
    device.write(ims, interrupt_sources);
    device.write(ics, tx_writeback); // Assert a real device cause before relying on the pin.
    bool delivered = interrupt_wait_for(device.intx_observed);
    device.probing_intx = false;
    if (delivered) {
        log("e1000: INTx verified index=%u gsi=%u\n", uint64_t(device.adapter.info.index),
            uint64_t(device.intx.gsi()));
        return;
    }
    device.write(imc, UINT32_MAX);
    device.intx.stop(pci);
    device.read(icr);
    log("e1000: INTx probe failed index=%u, polling\n", uint64_t(device.adapter.info.index));
}

static bool initialize(Controller& device, const PciFunction& pci, uint32_t model) {
    device.pci = pci;
    device.model = model;
    device.adapter = {{}, poll, send, stop, &device};
    uint64_t address;
    if (pci.read8(0x0b) != 2 || pci.read8(0x0a) != 0 || !pci.memory_bar(0, address))
        return false;
    device.registers = static_cast<volatile uint32_t*>(map_mmio(address, 0x20000));
    if (!device.registers)
        return false;
    pci.write16(4, pci.read16(4) | 0x406);
    if ((pci.read16(4) & 0x406) != 0x406)
        return false;
    device.write(imc, UINT32_MAX);
    device.write(rctl, 0);
    device.write(tctl, 0);
    device.write(ctrl, device.read(ctrl) | (1u << 26));
    unsigned spins = 0;
    while (device.read(ctrl) & (1u << 26)) {
        if (++spins == 1000000)
            return false;
        asm volatile("pause");
    }
    device.write(imc, UINT32_MAX);
    device.read(icr);
    device.write(ctrl, device.read(ctrl) | (1u << 6) | (1u << 5));
    uint32_t low = device.read(mac_low), high = device.read(mac_high);
    if (!(high & (1u << 31)))
        return false;
    memcpy(device.adapter.info.mac, &low, 4);
    memcpy(device.adapter.info.mac + 4, &high, 2);
    for (unsigned i = 0; i < 128; i++)
        device.write(multicast + i * 4, 0);
    device.rings = page_alloc(2);
    device.receive = page_alloc(ring_size * buffer_size / page_size);
    device.transmit = page_alloc(ring_size * buffer_size / page_size);
    if (!device.rings || !device.receive || !device.transmit)
        return false;
    memset(physical(device.rings), 0, 2 * page_size);
    device.rx = static_cast<volatile RxDescriptor*>(physical(device.rings));
    device.tx = static_cast<volatile TxDescriptor*>(physical(device.rings + page_size));
    for (unsigned i = 0; i < ring_size; i++)
        device.rx[i].address = device.receive + i * buffer_size;
    device.write(rx_base, device.rings);
    device.write(rx_base + 4, device.rings >> 32);
    device.write(rx_base + 8, ring_size * sizeof(RxDescriptor));
    device.write(rx_base + 0x10, 0);
    device.write(rx_base + 0x18, ring_size - 1);
    device.write(tx_base, device.rings + page_size);
    device.write(tx_base + 4, (device.rings + page_size) >> 32);
    device.write(tx_base + 8, ring_size * sizeof(TxDescriptor));
    device.write(tx_base + 0x10, 0);
    device.write(tx_base + 0x18, 0);
    device.write(tipg, 10 | (8 << 10) | (6 << 20));
    // Hand complete frames to the network stack for checksum validation.
    if (model == model_82574l)
        device.write(rx_checksum, disable_packet_checksum);
    virtio_dma_barrier();
    device.write(tctl, 2 | 8 | (15 << 4) | (64 << 12));
    device.write(rctl, 2 | (1u << 4) | (1u << 15) | (1u << 26));
    device.adapter.info.live = true;
    poll(device.adapter);
    if (!device.adapter.info.live || !net_register(device.adapter))
        return false;
    configure_interrupt(device);
    uint64_t index = device.adapter.info.index;
    log("e1000: index=%u model=%s rx=%u tx=%u\n", index,
        model == model_82574l ? "82574L" : "82540EM", uint64_t(ring_size), uint64_t(ring_size));
    const char* mode = device.msi.active() ? "msi" : device.intx.active() ? "intx" : "poll";
    log("e1000 IRQ: index=%u mode=%s\n", index, mode);
    return true;
}
} // namespace

void e1000_attach(const PciFunction& pci) {
    uint32_t model = pci.read32(0);
    if (attempts == max_net_devices || (model != model_82540em && model != model_82574l))
        return;
    auto& device = controllers[attempts++];
    if (initialize(device, pci, model))
        return;
    stop(device.adapter);
    log("e1000: initialization failed at %u:%u.%u\n", uint64_t(pci.bus), uint64_t(pci.slot),
        uint64_t(pci.function));
}
} // namespace ax
