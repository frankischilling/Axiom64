// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/block/ahci.cpp
 * @brief   Polled AHCI SATA disk driver.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Owns command DMA, controller handoff, bounded I/O, and SATA link recovery.
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
#include "drivers/block/ahci.hpp"
#include "core/time.hpp"
#include "drivers/block/ahci_command.hpp"
#include "drivers/block/ata_identity.hpp"
#include "drivers/platform/poll.hpp"
#include "drivers/platform/pci.hpp"
#include "mm/dma.hpp"

namespace ax {
namespace {
using DevicePoll::wait;
constexpr unsigned host_control = 1, host_status = 2, implemented = 3, version = 4;
constexpr unsigned capabilities2 = 9, ownership = 10;
constexpr uint32_t ahci_enable = 1u << 31, host_reset = 1;
constexpr size_t ports_offset = 0x100, port_stride = 0x80, maximum_mmio = 0x1100;
constexpr unsigned clb = 0, fb = 2, interrupt_status = 4, interrupt_enable = 5, command = 6;
constexpr unsigned task_file = 8, signature = 9, link_status = 10, link_control = 11;
constexpr unsigned link_error = 12, active = 13, issue = 14, fis_switch = 16;
constexpr uint32_t start_engine = 1, receive_fis = 1u << 4;
constexpr uint32_t fis_running = 1u << 14, engine_running = 1u << 15;
constexpr uint32_t task_busy = 0x88, task_error = 0x21;
constexpr uint32_t command_error = 0x7d000000; // Fatal host, interface, or task-file status.
constexpr uint32_t sata_disk = 0x00000101;
constexpr size_t dma_pages = 1 + ahci_transfer_sectors * sector_size / page_size;
static_assert(ahci_transfer_sectors * sector_size % page_size == 0);

struct Port {
    volatile uint32_t* registers = nullptr;
    uint64_t dma = 0;
    BlockInfo info{};
    AtaIdentity identity{};
    uint16_t serial[10]{}, model[20]{};
    unsigned number = 0;
    bool identifiable = false;
    bool live = false;

    uint32_t read(unsigned reg) const {
        return registers[reg];
    }

    void write(unsigned reg, uint32_t value) const {
        registers[reg] = value;
    }

    auto& memory() const {
        return *static_cast<Ahci::CommandMemory*>(physical(dma));
    }

    void* buffer() const {
        return physical(dma + page_size);
    }
};

Port devices[ahci_device_slots]{};
unsigned count_devices;

bool connected(const Port& port) {
    return (port.read(link_status) & 0xf0f) == 0x103;
}

bool stop(const Port& port) {
    port.write(command, port.read(command) & ~start_engine);
    if (!wait([&] { return !(port.read(command) & (start_engine | engine_running)); }, 50))
        return false;
    port.write(command, port.read(command) & ~receive_fis);
    return wait([&] { return !(port.read(command) & (receive_fis | fis_running)); }, 50);
}

void clear_status(const Port& port) {
    port.write(link_error, UINT32_MAX);
    port.write(interrupt_status, UINT32_MAX);
}

bool reset_port(const Port& port) {
    if (!stop(port))
        return false;
    port.write(interrupt_enable, 0);
    port.write(fis_switch, 0);
    port.write(clb, port.dma);
    port.write(clb + 1, 0);
    port.write(fb, port.dma + offsetof(Ahci::CommandMemory, received));
    port.write(fb + 1, 0);
    clear_status(port);
    constexpr uint32_t disable_lpm = (1u << 26) | (1u << 27);
    port.write(command,
               (port.read(command) & ~(0xf0000000u | disable_lpm)) | receive_fis | 6 | (1u << 28));
    if (!wait(
            [&] {
                return (port.read(command) & (receive_fis | fis_running)) ==
                       (receive_fis | fis_running);
            },
            50))
        return false;
    const uint32_t control = (port.read(link_control) & 0xf0) | 0x300;
    port.write(link_control, control | 1);
    if (!clock_delay_us(2000)) {
        if (!wait([start = ticks] { return ticks - start >= 2; }, 5)) {
            port.write(link_control, control);
            return false;
        }
    }
    port.write(link_control, control);
    if (!wait([&] { return connected(port) && !(port.read(task_file) & task_busy); }, 200) ||
        port.read(signature) != sata_disk || port.read(issue) || port.read(active))
        return false;
    clear_status(port);
    port.write(command, port.read(command) | start_engine);
    return port.read(command) & start_engine;
}

int execute(const Port& port, uint8_t opcode, uint64_t sector, uint16_t sectors, uint32_t bytes,
            bool extended = false, bool write = false) {
    if (!connected(port) || port.read(issue) || port.read(active))
        return -5;
    if (!wait([&] { return !(port.read(task_file) & task_busy); }, 500))
        return -110;
    clear_status(port);
    auto& memory = port.memory();
    Ahci::prepare(memory, port.dma, opcode, sector, sectors, bytes, extended, write);
    asm volatile("mfence" ::: "memory");
    port.write(issue, 1); // PxCI is write-one-to-set. This port uses slot zero.
    if (!wait(
            [&] {
                return !port.read(issue) || (port.read(interrupt_status) & command_error) ||
                       !connected(port);
            },
            3000))
        return -110;
    asm volatile("mfence" ::: "memory");
    const auto transferred = *static_cast<volatile uint32_t*>(&memory.list[1]);
    if (!connected(port) || port.read(issue) || (port.read(interrupt_status) & command_error) ||
        (port.read(task_file) & (task_busy | task_error)) || transferred != bytes)
        return -5;
    return 0;
}

bool identify(const Port& port, AtaIdentity& identity) {
    if (execute(port, 0xec, 0, 0, sector_size))
        return false;
    const auto* words = static_cast<const uint16_t*>(port.buffer());
    return (words[49] & 0x100) && ata_identity(words, identity);
}

void release_port(Port& port) {
    if (!stop(port)) {
        log("ahci: port=%u DMA retained after stop failure\n", uint64_t(port.number));
        return;
    }
    port.write(clb, 0);
    port.write(clb + 1, 0);
    port.write(fb, 0);
    port.write(fb + 1, 0);
    page_free(port.dma, dma_pages);
    port.dma = 0;
}

int recover(Port& port, int error) {
    // A failed write is never replayed. Verify the same disk before accepting new I/O.
    AtaIdentity found{};
    port.live = port.identifiable && connected(port) && reset_port(port) && identify(port, found);
    if (port.live) {
        const auto* words = static_cast<const uint16_t*>(port.buffer());
        port.live = found.sectors == port.identity.sectors &&
                    found.flush_command == port.identity.flush_command &&
                    found.extended == port.identity.extended &&
                    !memcmp(port.serial, words + 10, sizeof(port.serial)) &&
                    !memcmp(port.model, words + 27, sizeof(port.model));
    }
    if (!port.live)
        stop(port); // Retain DMA storage even if the port cannot be stopped.
    log("ahci: port=%u command errno=%u recovery=%s\n", uint64_t(port.number), uint64_t(-error),
        port.live ? "ready" : "offline");
    return error;
}

void attach_port(volatile uint32_t* registers, unsigned number) {
    Port port{registers};
    port.number = number;
    const auto detection = port.read(link_status) & 15;
    if (detection != 1 && detection != 3)
        return;
    port.dma = Dma::allocate(dma_pages, Dma::pci);
    if (!port.dma)
        return;
    if (!reset_port(port) || !identify(port, port.identity)) {
        release_port(port);
        return;
    }
    const auto* words = static_cast<const uint16_t*>(port.buffer());
    memcpy(port.serial, words + 10, sizeof(port.serial));
    memcpy(port.model, words + 27, sizeof(port.model));
    for (uint16_t word : port.serial)
        port.identifiable |= word && word != 0x2020 && word != UINT16_MAX;
    bool flush = port.identity.flush_command != 0;
    port.info = {port.identity.sectors, !flush, flush};
    port.live = true;
    devices[count_devices++] = port;
    log("ahci: port=%u sectors=%u lba48=%u flush=%u\n", uint64_t(number), port.identity.sectors,
        uint64_t(port.identity.extended), uint64_t(flush));
}

bool handoff(volatile uint32_t* registers) {
    if (registers[version] < 0x00010200 || !(registers[capabilities2] & 1))
        return true;
    constexpr uint32_t firmware_owned = 1, os_owned = 2, firmware_busy = 16;
    registers[ownership] = (registers[ownership] & ~(4u | 8u)) | os_owned;
    return wait(
        [&] {
            return (registers[ownership] & (firmware_owned | os_owned | firmware_busy)) == os_owned;
        },
        200);
}

void attach(const PciFunction& pci) {
    if (count_devices == ahci_device_slots || pci.read16(0x0a) != 0x0106 || pci.read8(9) != 1)
        return;
    PciBar bar;
    uint64_t address;
    if (pci.probe_bar(5, PciBarSpace::memory, bar) != PciBarStatus::valid)
        return;
    const size_t length = min(bar.size, uint64_t(maximum_mmio));
    if (length < ports_offset + port_stride || !bar.range(0, length, address))
        return;
    auto* registers = static_cast<volatile uint32_t*>(map_mmio(address, length));
    if (!registers)
        return;
    const uint16_t saved = pci.read16(4);
    constexpr uint16_t memory_decode = 2, bus_master = 4, disable_intx = 0x400;
    pci.write16(4, saved | memory_decode);
    if (!(pci.read16(4) & memory_decode) || registers[version] == UINT32_MAX ||
        !handoff(registers)) {
        pci.write16(4, saved);
        return;
    }
    pci.write16(4, (saved & ~7u) | memory_decode | disable_intx);
    if ((pci.read16(4) & 0x407) != (memory_decode | disable_intx))
        return;
    registers[host_control] = ahci_enable;
    if (!(registers[host_control] & ahci_enable))
        return;
    registers[host_control] = ahci_enable | host_reset;
    if (!wait([&] { return !(registers[host_control] & host_reset); }, 100)) {
        log("ahci: controller reset timed out\n");
        return;
    }
    registers[host_control] = ahci_enable;
    registers[host_status] = UINT32_MAX;
    pci.write16(4, (saved & ~7u) | memory_decode | bus_master | disable_intx);
    if ((pci.read16(4) & 0x407) != (memory_decode | bus_master | disable_intx))
        return;
    const uint32_t ports = registers[implemented];
    const unsigned available = (length - ports_offset) / port_stride;
    log("ahci: controller reset complete ports=%x\n", uint64_t(ports));
    for (unsigned port = 0; port < available && count_devices < ahci_device_slots; ++port)
        if (ports & (1u << port))
            attach_port(registers + (ports_offset + port * port_stride) / sizeof(uint32_t), port);
}
} // namespace

void ahci_init() {
    pci_scan(attach);
}

const BlockInfo* ahci_info(unsigned slot) {
    return slot < count_devices ? &devices[slot].info : nullptr;
}

int ahci_transfer(unsigned slot, uint64_t sector, void* data, size_t count, bool write) {
    const auto* info = ahci_info(slot);
    if (!info)
        return -19;
    if (sector > info->sectors || count > info->sectors - sector || count > ahci_transfer_sectors)
        return -22;
    if (!count)
        return 0;
    if (write && info->readonly)
        return -30;
    auto& port = devices[slot];
    if (!port.live)
        return -5;

    const auto bytes = count * sector_size;
    const bool extended = sector + count > lba28_limit;
    const uint8_t opcode = extended ? (write ? 0x35 : 0x25) : (write ? 0xca : 0xc8);
    if (write)
        memcpy(port.buffer(), data, bytes);
    if (const int error = execute(port, opcode, sector, count, bytes, extended, write))
        return recover(port, error);
    if (!write)
        memcpy(data, port.buffer(), bytes);
    return 0;
}

int ahci_flush(unsigned slot) {
    if (!ahci_info(slot))
        return -19;
    auto& port = devices[slot];
    if (!port.live)
        return -5;
    if (const auto opcode = port.identity.flush_command) {
        if (const int error = execute(port, opcode, 0, 0, 0, opcode == 0xea))
            return recover(port, error);
    }
    return 0;
}
} // namespace ax
