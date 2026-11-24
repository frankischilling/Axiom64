// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/rtl8168g.cpp
 * @brief   Drives the Realtek RTL8168G and RTL8111G Ethernet MAC.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Uses polling and descriptor DMA after a firmware-initialized PHY handoff.
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
#include "core/time.hpp"
#include "drivers/platform/pci.hpp"
#include "drivers/virtio/queue.hpp"
#include "mm/dma.hpp"

namespace ax {
namespace {
constexpr uint32_t pci_id = 0x816810ec;
constexpr uint16_t pci_command = 4;
constexpr uint16_t memory_enable = 2, bus_master = 4, intx_disable = 1 << 10;
constexpr unsigned aperture = 0x100;
constexpr unsigned station_address = 0x00, multicast_filter = 0x08, tx_ring = 0x20;
constexpr unsigned chip_command = 0x37, tx_poll = 0x38, irq_mask = 0x3c, irq_status = 0x3e;
constexpr unsigned tx_config = 0x40, rx_config = 0x44, config_lock = 0x50;
constexpr unsigned config2 = 0x53, config3 = 0x54, config5 = 0x56, phy_status = 0x6c;
constexpr unsigned eri_data = 0x70, eri_access = 0x74, ephy_access = 0x80;
constexpr unsigned mac_ocp = 0xb0, phy_ocp = 0xb8, mcu = 0xd3;
constexpr unsigned rx_max_size = 0xda, cplus = 0xe0, moderation = 0xe2, rx_ring = 0xe4;
constexpr unsigned early_tx_size = 0xec, misc = 0xf0;
constexpr uint8_t reset = 1 << 4, engines = (1 << 3) | (1 << 2), tx_kick = 1 << 6;
constexpr uint8_t link_up = 1 << 1, fifo_empty = (1 << 5) | (1 << 4), link_list_ready = 1 << 1;
constexpr uint32_t rx_gate = 1 << 19, tx_fifo_empty = 1 << 11, access_flag = 1u << 31;
constexpr uint32_t rx_dma_config = (1 << 15) | (1 << 14) | (1 << 11) | (7 << 8);
constexpr uint32_t tx_dma_config = (3 << 24) | (7 << 8) | (1 << 7);
constexpr uint32_t accept_own_multicast_broadcast = (1 << 1) | (1 << 2) | (1 << 3);
constexpr uint16_t rx_overrun = (1 << 6) | (1 << 4);
constexpr uint64_t tx_retry_ticks = 10, tx_timeout_ticks = 200;
constexpr unsigned max_tx_restarts = 2;

constexpr unsigned slots = 64, buffer_size = 2048, buffer_pages = slots * buffer_size / page_size;
constexpr size_t minimum_wire_frame = 60, maximum_frame = 1518, fcs_bytes = 4;
constexpr uint32_t own = 1u << 31, end_of_ring = 1u << 30;
constexpr uint32_t first = 1u << 29, last = 1u << 28;
constexpr uint32_t rx_errors = (1 << 22) | (1 << 21) | (1 << 20) | (1 << 19);
constexpr uint32_t rx_length = 0x3fff;

struct Descriptor {
    uint32_t status, options;
    uint64_t address;
};

static_assert(sizeof(Descriptor) == 16 && 2 * slots * sizeof(Descriptor) <= page_size);
static_assert(slots * buffer_size % page_size == 0 && maximum_frame + fcs_bytes <= buffer_size);

constexpr uint32_t ring_flag(unsigned index) {
    return index == slots - 1 ? end_of_ring : 0;
}

constexpr size_t receive_size(uint32_t status, bool discard_tail) {
    const size_t bytes = status & rx_length;
    return !discard_tail && (status & (own | first | last | rx_errors)) == (first | last) &&
                   bytes >= ethernet_header + fcs_bytes && bytes <= maximum_frame + fcs_bytes
               ? bytes - fcs_bytes
               : 0;
}

static_assert(ring_flag(0) == 0 && ring_flag(slots - 1) == end_of_ring);
static_assert(receive_size(first | last | end_of_ring | 64, false) == 60);
static_assert(receive_size(first | last | (maximum_frame + fcs_bytes), false) == maximum_frame);
static_assert(receive_size(first | last | (maximum_frame + fcs_bytes + 1), false) == 0);
static_assert(receive_size(first | last | (ethernet_header + fcs_bytes - 1), false) == 0);
static_assert(receive_size(own | first | last | 64, false) == 0);
static_assert(receive_size(first | last | rx_errors | 64, false) == 0);
static_assert(receive_size(last | 64, false) == 0);
static_assert(receive_size(first | last | 64, true) == 0);

struct Controller {
    PciFunction pci{};
    NetAdapter adapter{};
    volatile uint8_t* registers = nullptr;
    volatile Descriptor* rx = nullptr;
    volatile Descriptor* tx = nullptr;
    uint64_t descriptors = 0, receive = 0, transmit = 0;
    unsigned rx_next = 0, tx_next = 0, tx_oldest = 0, pending = 0;
    uint16_t lengths[slots]{};
    uint16_t dma_command = 0;
    unsigned tx_restarts = 0;
    uint64_t tx_kick_tick = 0, tx_progress_tick = 0;
    bool polling = false;
    bool discard_tail = false;

    template <typename T> T read(unsigned offset) const {
        return *reinterpret_cast<volatile T*>(registers + offset);
    }

    template <typename T> void write(unsigned offset, T value) const {
        *reinterpret_cast<volatile T*>(registers + offset) = value;
    }

    template <typename T>
    bool wait(unsigned offset, T mask, T expected, unsigned interval, unsigned attempts) const {
        for (unsigned i = 0; i < attempts; ++i) {
            const T value = read<T>(offset);
            if (value == T(~T(0)))
                return false;
            if ((value & mask) == expected)
                return true;
            if (!clock_delay_us(interval))
                return false;
        }
        return false;
    }

    bool write_extended(unsigned address, unsigned lanes, uint32_t value) const {
        write(eri_data, value);
        write(eri_access, access_flag | (lanes << 12) | address);
        return wait<uint32_t>(eri_access, access_flag, 0, 100, 100);
    }

    bool read_extended(unsigned address, uint32_t& value) const {
        write<uint32_t>(eri_access, (0xf << 12) | address);
        if (!wait<uint32_t>(eri_access, access_flag, access_flag, 100, 100))
            return false;
        value = read<uint32_t>(eri_data);
        return true;
    }

    bool update_extended(unsigned address, uint32_t clear, uint32_t set) const {
        uint32_t value;
        return read_extended(address, value) &&
               write_extended(address, 0xf, (value & ~clear) | set);
    }

    void update_mac_ocp(uint16_t address, uint16_t clear, uint16_t set) const {
        const uint32_t selector = uint32_t(address) << 15;
        write(mac_ocp, selector);
        const uint16_t current = read<uint32_t>(mac_ocp);
        write(mac_ocp, access_flag | selector | ((current & ~clear) | set));
    }

    bool quiesce(bool restarting) const;
    bool configure_mac() const;
    bool wake_phy() const;
    bool allocate_rings();
    void rearm_rx(unsigned index);

    void kick_tx() {
        write<uint8_t>(tx_poll, tx_kick);
        tx_kick_tick = ticks;
    }
};

static Controller controllers[max_net_devices];
static unsigned attached;

bool Controller::quiesce(bool restarting) const {
    write<uint16_t>(irq_mask, 0);
    write<uint32_t>(rx_config, read<uint32_t>(rx_config) & ~uint32_t(0x3f));
    write<uint32_t>(misc, read<uint32_t>(misc) | rx_gate);
    if (!clock_delay_us(2000))
        return false;
    const bool fifo_idle = wait<uint32_t>(tx_config, tx_fifo_empty, tx_fifo_empty, 100, 42) &&
                           wait<uint8_t>(mcu, fifo_empty, fifo_empty, 100, 42);
    if (!fifo_idle && !restarting)
        return false;

    write<uint8_t>(chip_command, 0);
    if (!clock_delay_us(1000))
        return false;
    write<uint8_t>(mcu, read<uint8_t>(mcu) & ~(1 << 7)); // Leave out-of-band receive mode.
    update_mac_ocp(0xe8de, 1 << 14, 0);
    if (!wait<uint8_t>(mcu, link_list_ready, link_list_ready, 100, 42))
        return false;
    update_mac_ocp(0xe8de, 0, 1 << 15);
    if (!wait<uint8_t>(mcu, link_list_ready, link_list_ready, 100, 42))
        return false;

    write<uint8_t>(chip_command, reset);
    if (!wait<uint8_t>(chip_command, reset, 0, 100, 100))
        return false;
    write<uint16_t>(irq_mask, 0);
    write<uint16_t>(irq_status, UINT16_MAX);
    return true;
}

bool Controller::configure_mac() const {
    // Use the G MAC's FIFO sizing and embedded PHY settings. Keep clock
    // requests and device-managed ASPM disabled during and after programming.
    write<uint8_t>(config2, read<uint8_t>(config2) & ~(1 << 7));
    write<uint8_t>(config3, read<uint8_t>(config3) & ~(1 << 1));
    write<uint8_t>(config5, read<uint8_t>(config5) & ~1u);
    write<uint16_t>(cplus, read<uint16_t>(cplus) & (1 << 13));
    write<uint8_t>(early_tx_size, 0x27);
    write<uint16_t>(moderation, 0);

    if (!write_extended(0xc8, 0xf, 0x00080002) || !write_extended(0xe8, 0xf, 0x00100006) ||
        !write_extended(0xcc, 1, 0x38) || !write_extended(0xd0, 1, 0x48) ||
        !update_extended(0xdc, 1, 0) || !update_extended(0xdc, 0, 1) ||
        !write_extended(0x2f8, 3, 0x1d8f) || !write_extended(0xc0, 3, 0) ||
        !write_extended(0xb8, 3, 0) || !update_extended(0x2fc, 0x06, 0x01) ||
        !update_extended(0x1b0, 1 << 12, 0))
        return false;

    constexpr struct {
        unsigned index;
        uint16_t clear, set;
    } ephy_settings[] = {
        {0x00, 0x0008, 0},
        {0x0c, 0x3ff0, 0x0820},
        {0x1e, 0, 1},
        {0x19, 0x8000, 0},
    };

    for (const auto& setting : ephy_settings) {
        const uint32_t selector = setting.index << 16;
        write(ephy_access, selector);
        if (!wait<uint32_t>(ephy_access, access_flag, access_flag, 10, 100))
            return false;
        uint16_t value = read<uint32_t>(ephy_access);
        write(ephy_access, access_flag | selector | ((value & ~setting.clear) | setting.set));
        if (!wait<uint32_t>(ephy_access, access_flag, 0, 10, 100) || !clock_delay_us(10))
            return false;
    }
    return true;
}

bool Controller::wake_phy() const {
    // Preserve PHY firmware and advertisements installed by firmware. Wake
    // the transceiver if PXE powered it down while releasing the controller.
    constexpr uint32_t basic_mode_control = uint32_t(0xa400) << 15;
    constexpr uint16_t power_down_or_isolate = (1 << 11) | (1 << 10);
    constexpr uint16_t autoneg = 1 << 12, renegotiate = 1 << 9;
    write(phy_ocp, basic_mode_control);
    if (!wait<uint32_t>(phy_ocp, access_flag, access_flag, 25, 10))
        return false;
    uint16_t control = read<uint32_t>(phy_ocp);
    if (control == UINT16_MAX || !update_extended(0x1a8, 0, 0xfc000000))
        return false;
    if (!(control & power_down_or_isolate))
        return true;
    control &= ~power_down_or_isolate;
    if (control & autoneg)
        control |= renegotiate;
    write(phy_ocp, access_flag | basic_mode_control | control);
    return wait<uint32_t>(phy_ocp, access_flag, 0, 25, 10);
}

void Controller::rearm_rx(unsigned index) {
    rx[index].options = 0;
    rx[index].address = receive + index * buffer_size;
    virtio_dma_barrier();
    rx[index].status = own | ring_flag(index) | buffer_size;
}

bool Controller::allocate_rings() {
    const uint64_t new_descriptors = Dma::allocate(1, Dma::pci);
    const uint64_t new_receive = Dma::allocate(buffer_pages, Dma::pci);
    const uint64_t new_transmit = Dma::allocate(buffer_pages, Dma::pci);
    if (!new_descriptors || !new_receive || !new_transmit) {
        if (new_descriptors)
            page_free(new_descriptors);
        if (new_receive)
            page_free(new_receive, buffer_pages);
        if (new_transmit)
            page_free(new_transmit, buffer_pages);
        return false;
    }
    // A restart uses fresh pages. A late DMA completion can only reach the
    // retired allocation, which stays reserved until power-off.
    descriptors = new_descriptors;
    receive = new_receive;
    transmit = new_transmit;
    constexpr unsigned tx_offset = slots * sizeof(Descriptor);
    rx = static_cast<volatile Descriptor*>(physical(descriptors));
    tx = static_cast<volatile Descriptor*>(physical(descriptors + tx_offset));
    for (unsigned i = 0; i < slots; ++i) {
        rearm_rx(i);
        tx[i].status = ring_flag(i);
        tx[i].address = transmit + i * buffer_size;
    }
    rx_next = tx_next = tx_oldest = pending = 0;
    discard_tail = false;
    return true;
}

static void stop(NetAdapter& adapter) {
    auto& device = *static_cast<Controller*>(adapter.data);
    adapter.info.live = adapter.info.carrier = adapter.info.writable = false;
    if (device.pci.read32(0) == pci_id) {
        device.write<uint16_t>(irq_mask, 0);
        device.write<uint32_t>(misc, device.read<uint32_t>(misc) | rx_gate);
        device.write<uint8_t>(chip_command, 0);
        device.read<uint8_t>(chip_command); // Drain posted writes before stopping PCI DMA.
        const uint16_t command = device.pci.read16(pci_command);
        device.pci.write16(pci_command, command & ~bus_master);
        device.pci.read16(pci_command);
        device.write<uint16_t>(irq_status, UINT16_MAX);
    }
    while (device.pending) {
        net_tx_complete(adapter, device.lengths[device.tx_oldest], true);
        device.tx_oldest = (device.tx_oldest + 1) % slots;
        --device.pending;
    }
    // A device that disappeared or did not stop may still own DMA pages.
}

static void restart(Controller& device);

static void poll(NetAdapter& adapter) {
    auto& device = *static_cast<Controller*>(adapter.data);
    if (!adapter.info.live || device.polling)
        return;
    const uint16_t cause = device.read<uint16_t>(irq_status);
    const uint8_t phy = device.read<uint8_t>(phy_status);
    // The legacy PCI system-error bit is not a fatal status on this MAC.
    if (cause == UINT16_MAX || phy == UINT8_MAX) {
        log("rtl8168g: adapter %u lost register access\n", uint64_t(adapter.info.index));
        stop(adapter);
        return;
    }
    device.write(irq_status, cause);
    adapter.info.carrier = (phy & link_up) != 0;
    if (cause & rx_overrun)
        net_rx_error(adapter);
    const unsigned pending_before = device.pending;
    while (device.pending && !(device.tx[device.tx_oldest].status & own)) {
        virtio_dma_barrier();
        net_tx_complete(adapter, device.lengths[device.tx_oldest]);
        device.tx_oldest = (device.tx_oldest + 1) % slots;
        --device.pending;
    }
    if (device.pending != pending_before || !adapter.info.carrier)
        device.tx_progress_tick = ticks;
    if (device.pending && adapter.info.carrier &&
        ticks - device.tx_progress_tick >= tx_timeout_ticks) {
        restart(device);
        return;
    }
    // The controller can miss a second doorbell while fetching a burst.
    // If completion left more frames queued, prompt it to fetch again.
    if (device.pending && adapter.info.carrier &&
        (device.pending != pending_before || ticks - device.tx_kick_tick >= tx_retry_ticks))
        device.kick_tx();
    adapter.info.writable = device.pending < slots - 1;

    // RX can cause a synchronous reply via net_send(), which polls this adapter.
    device.polling = true;
    for (unsigned budget = 0; budget < slots; ++budget) {
        const unsigned index = device.rx_next;
        const uint32_t status = device.rx[index].status;
        if (status & own)
            break;
        virtio_dma_barrier();
        if (const size_t bytes = receive_size(status, device.discard_tail))
            net_receive(adapter, physical(device.receive + index * buffer_size), bytes);
        else
            net_rx_error(adapter);
        device.discard_tail = !(status & last);
        device.rearm_rx(index);
        device.rx_next = (index + 1) % slots;
    }
    device.polling = false;
}

static int send(NetAdapter& adapter, const void* frame, size_t bytes) {
    auto& device = *static_cast<Controller*>(adapter.data);
    if (bytes > maximum_frame)
        return -90;
    if (device.pending == slots - 1)
        return -11;
    const unsigned index = device.tx_next;
    auto* buffer = static_cast<uint8_t*>(physical(device.transmit + index * buffer_size));
    memcpy(buffer, frame, bytes);
    const size_t wire_bytes = max(bytes, minimum_wire_frame);
    memset(buffer + bytes, 0, wire_bytes - bytes);
    device.lengths[index] = bytes;
    virtio_dma_barrier();
    device.tx[index].status = own | ring_flag(index) | first | last | uint32_t(wire_bytes);
    virtio_dma_barrier();
    device.kick_tx();
    device.tx_next = (index + 1) % slots;
    if (!device.pending)
        device.tx_progress_tick = ticks;
    ++device.pending;
    adapter.info.writable = device.pending < slots - 1;
    return 0;
}

static const char* start(Controller& device, bool restarting) {
    const uint16_t command = device.dma_command;
    if (device.pci.read32(0) != pci_id || device.pci.read16(pci_command) != command)
        return "PCI DMA disable";
    if (!device.quiesce(restarting))
        return "reset";

    auto& adapter = device.adapter;
    device.write<uint8_t>(config_lock, 0xc0);
    if (!device.configure_mac() || !device.wake_phy()) {
        device.write<uint8_t>(config_lock, 0);
        return "MAC/PHY";
    }
    uint8_t mac[6];
    bool nonzero = false;
    for (unsigned i = 0; i < sizeof(mac); ++i) {
        mac[i] = device.read<uint8_t>(station_address + i);
        nonzero |= mac[i] != 0;
    }
    if (!nonzero || (mac[0] & 1) || (restarting && memcmp(mac, adapter.info.mac, sizeof(mac))) ||
        !device.allocate_rings()) {
        device.write<uint8_t>(config_lock, 0);
        return "MAC address/DMA";
    }
    memcpy(adapter.info.mac, mac, sizeof(mac));
    device.write<uint32_t>(multicast_filter, UINT32_MAX);
    device.write<uint32_t>(multicast_filter + 4, UINT32_MAX);
    device.write<uint16_t>(rx_max_size, maximum_frame + fcs_bytes);
    device.write<uint32_t>(tx_ring + 4, 0);
    device.write<uint32_t>(tx_ring, device.descriptors + slots * sizeof(Descriptor));
    device.write<uint32_t>(rx_ring + 4, 0);
    device.write<uint32_t>(rx_ring, device.descriptors);
    device.write<uint8_t>(config_lock, 0);
    virtio_dma_barrier();
    device.pci.write16(pci_command, command | bus_master);
    if (device.pci.read16(pci_command) != (command | bus_master))
        return "PCI DMA";

    device.write<uint32_t>(misc, device.read<uint32_t>(misc) & ~rx_gate);
    device.write<uint8_t>(chip_command, engines);
    device.write<uint32_t>(tx_config, tx_dma_config);
    device.write<uint32_t>(rx_config, rx_dma_config | accept_own_multicast_broadcast);
    if ((device.read<uint8_t>(chip_command) & (engines | reset)) != engines)
        return "engine enable";
    const uint8_t phy = device.read<uint8_t>(phy_status);
    if (phy == UINT8_MAX)
        return "PHY status";
    adapter.info.live = true;
    adapter.info.carrier = (phy & link_up) != 0;
    adapter.info.writable = true;
    return nullptr;
}

static void restart(Controller& device) {
    auto& adapter = device.adapter;
    const uint64_t index = adapter.info.index;
    log("rtl8168g: TX stalled index=%u pending=%u oldest=%u rx=%u\n", index,
        uint64_t(device.pending), uint64_t(device.tx_oldest), uint64_t(device.rx_next));
    stop(adapter);
    if (device.tx_restarts == max_tx_restarts)
        return;
    ++device.tx_restarts;
    if (const char* failure = start(device, true)) {
        stop(adapter);
        log("rtl8168g: index=%u recovery failed at %s\n", index, failure);
        return;
    }
    log("rtl8168g: index=%u restarted DMA queues attempt=%u\n", index,
        uint64_t(device.tx_restarts));
}
} // namespace

void rtl8168g_attach(const PciFunction& pci) {
    if (attached == max_net_devices || pci.read32(0) != pci_id || pci.read16(0x0a) != 0x0200)
        return;

    // The first memory BAR is the MAC aperture. Probe the assigned resource
    // with firmware DMA disabled and restore the command on a foreign XID.
    const uint16_t original = pci.read16(pci_command);
    const uint16_t command = (original | memory_enable | intx_disable) & ~bus_master;
    pci.write16(pci_command, command);
    if (pci.read16(pci_command) != command) {
        pci.write16(pci_command, original);
        return;
    }
    uint64_t address = 0;
    for (unsigned i = 0; i < 6; ++i) {
        PciBar bar;
        auto result = pci.probe_bar(i, PciBarSpace::memory, bar);
        if (result == PciBarStatus::restore_failed)
            return;
        if (result == PciBarStatus::valid && bar.range(0, aperture, address))
            break;
    }
    auto* registers =
        address ? static_cast<volatile uint8_t*>(map_mmio(address, aperture)) : nullptr;
    if (!registers) {
        pci.write16(pci_command, original);
        log("rtl8168g: no validated MAC aperture\n");
        return;
    }

    const uint32_t xid =
        (reinterpret_cast<volatile uint32_t*>(registers + tx_config)[0] >> 20) & 0xfcf;
    if ((xid & 0x7cf) != 0x4c0) {
        pci.write16(pci_command, original);
        log("rtl8168g: unknown MAC XID=%x\n", uint64_t(xid));
        return;
    }
    auto& device = controllers[attached++];
    device.pci = pci;
    device.registers = registers;
    device.dma_command = command;
    device.adapter = {{}, poll, send, stop, &device};
    if (const char* stage = start(device, false)) {
        stop(device.adapter);
        log("rtl8168g: XID=%x initialization failed at %s\n", uint64_t(xid), stage);
        return;
    }
    if (!net_register(device.adapter, "rtl8168g", &pci)) {
        stop(device.adapter);
        log("rtl8168g: XID=%x network registration failed\n", uint64_t(xid));
        return;
    }
    log("rtl8168g: index=%u XID=%x rx=%u tx=%u mode=poll\n", uint64_t(device.adapter.info.index),
        uint64_t(xid), uint64_t(slots), uint64_t(slots));
}
} // namespace ax
