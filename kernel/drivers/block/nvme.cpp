// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/block/nvme.cpp
 * @brief   Polled PCI NVMe controller and namespace driver.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Owns admin and I/O queues, reset recovery, and bounded DMA for NVM commands.
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
#include "drivers/block/nvme.hpp"
#include "drivers/block/nvme_command.hpp"
#include "drivers/platform/poll.hpp"
#include "drivers/platform/pci.hpp"
#include "mm/dma.hpp"

namespace ax {
namespace {
using namespace Nvme;
using DevicePoll::wait;
constexpr unsigned cap_low = 0, cap_high = 1, version_reg = 2, interrupt_mask = 3;
constexpr unsigned configuration = 5, status_reg = 7, attributes = 9, admin_sq = 10, admin_cq = 12;
constexpr size_t doorbells = 0x1000;
constexpr uint32_t enabled = 1, ready = 1, fatal = 2;
constexpr uint32_t cq_entry_size = 4u << 20, sq_entry_size = 6u << 16;
constexpr uint32_t request_shutdown = 1u << 14, shutdown_mask = 3u << 2,
                   shutdown_complete = 2u << 2;
constexpr unsigned timeout_ticks = 3000;
constexpr unsigned max_depth = 16;
constexpr unsigned bounce_page = 4, prp_page = bounce_page + bounce_pages;
constexpr unsigned list_page = prp_page + 1, dma_pages = list_page + 1;
constexpr uint16_t admin_identify = 6, admin_features = 9;
constexpr uint16_t admin_create_cq = 5, admin_create_sq = 1;

struct Queue {
    unsigned tail = 0, head = 0;
    uint16_t next_cid = 0;
    unsigned phase = 1;
};

struct Controller {
    volatile uint32_t* registers = nullptr;
    uint64_t dma = 0;
    unsigned stride = 0, depth = 0, ready_timeout = 0, limit = 0;
    unsigned number = 0;
    uint32_t version = 0, namespaces = 0;
    uint8_t identity[60]{};
    uint8_t firmware[8]{};
    Queue queues[2]{};
    bool live = false;

    uint32_t read(unsigned reg) const {
        return registers[reg];
    }

    void write(unsigned reg, uint32_t value) const {
        registers[reg] = value;
    }

    void address(unsigned reg, uint64_t value) const {
        write(reg, uint32_t(value));
        write(reg + 1, value >> 32);
    }

    uint64_t page(unsigned index) const {
        return dma + index * page_size;
    }

    void* bytes(unsigned index) const {
        return physical(page(index));
    }

    void ring(unsigned index, unsigned value) const {
        write(doorbells / sizeof(uint32_t) + index * stride, value);
    }
};

struct Namespace {
    Controller* controller = nullptr;
    uint32_t id = 0;
    BlockInfo info{};
    uint8_t identifiers[24]{};
    uint8_t uuid[16]{};
};

Controller controllers[nvme_controller_slots]{};
Namespace disks[nvme_device_slots]{};
unsigned controller_count, disk_count;

int lose_queue(Controller& controller, int error) {
    controller.live = false;
    return error;
}

int submit(Controller& controller, unsigned qid, Command command) {
    if ((controller.read(status_reg) & (ready | fatal)) != ready)
        return lose_queue(controller, -5);
    auto& queue = controller.queues[qid];
    auto* submissions = static_cast<Command*>(controller.bytes(qid * 2));
    auto* completions = static_cast<volatile Completion*>(controller.bytes(qid * 2 + 1));
    const uint16_t cid = queue.next_cid++;
    command.cid = cid;
    submissions[queue.tail] = command;
    queue.tail = (queue.tail + 1) % controller.depth;
    asm volatile("mfence" ::: "memory");
    controller.ring(qid * 2, queue.tail);

    auto& completion = completions[queue.head];
    if (!wait(
            [&] {
                return (completion.status & 1) == queue.phase ||
                       (controller.read(status_reg) & (ready | fatal)) != ready;
            },
            timeout_ticks))
        return lose_queue(controller, -110);
    asm volatile("mfence" ::: "memory");
    const uint16_t status = completion.status;
    if ((controller.read(status_reg) & (ready | fatal)) != ready || (status & 1) != queue.phase ||
        completion.queue != qid || completion.cid != cid || completion.head != queue.tail)
        return lose_queue(controller, -5);
    if (++queue.head == controller.depth) {
        queue.head = 0;
        queue.phase ^= 1;
    }
    controller.ring(qid * 2 + 1, queue.head);
    return status >> 1 ? -5 : 0;
}

bool disable(const Controller& controller) {
    controller.write(configuration, 0);
    return wait([&] { return !(controller.read(status_reg) & ready); }, controller.ready_timeout);
}

int identify(Controller& controller, uint32_t id, unsigned selector, unsigned page_index) {
    memset(controller.bytes(page_index), 0, page_size);
    Command command{};
    command.opcode = admin_identify;
    command.nsid = id;
    command.prp1 = controller.page(page_index);
    command.cdw10 = selector;
    return submit(controller, 0, command);
}

bool initialize(Controller& controller) {
    controller.live = false;
    if (!disable(controller))
        return false;
    memset(controller.bytes(0), 0, dma_pages * page_size);
    for (auto& queue : controller.queues)
        queue = {};
    controller.write(interrupt_mask, UINT32_MAX);
    const unsigned size = controller.depth - 1;
    controller.write(attributes, size | (size << 16));
    controller.address(admin_sq, controller.page(0));
    controller.address(admin_cq, controller.page(1));
    controller.write(configuration, enabled | sq_entry_size | cq_entry_size);
    if (!wait([&] { return controller.read(status_reg) & (ready | fatal); },
              controller.ready_timeout) ||
        (controller.read(status_reg) & (ready | fatal)) != ready)
        return false;

    controller.live = true;
    Command command{};
    command.opcode = admin_features;
    command.cdw10 = 7; // Request one I/O submission and one completion queue.
    if (submit(controller, 0, command))
        return false;
    command = {};
    command.opcode = admin_create_cq;
    command.prp1 = controller.page(3);
    command.cdw10 = (size << 16) | 1;
    command.cdw11 = 1; // Physically contiguous CQ, interrupt disabled.
    if (submit(controller, 0, command))
        return false;
    command = {};
    command.opcode = admin_create_sq;
    command.prp1 = controller.page(2);
    command.cdw10 = (size << 16) | 1;
    command.cdw11 = (1u << 16) | 1; // Physically contiguous SQ associated with CQ 1.
    return !submit(controller, 0, command);
}

bool read_controller(Controller& controller, bool recovery) {
    if (identify(controller, 0, 1, bounce_page))
        return false;
    const auto* data = static_cast<const uint8_t*>(controller.bytes(bounce_page));
    if (recovery) {
        bool serial = false;
        for (unsigned i = 0; i < 20; ++i)
            serial |= data[4 + i] && data[4 + i] != ' ' && data[4 + i] != 0xff;
        if (!serial || memcmp(controller.identity, data + 4, sizeof(controller.identity)))
            return false;
    }
    memcpy(controller.identity, data + 4, sizeof(controller.identity));
    memcpy(controller.firmware, data + 64, sizeof(controller.firmware));
    memcpy(&controller.namespaces, data + 516, sizeof(controller.namespaces));
    controller.limit = transfer_sectors(data[77]);
    return true;
}

bool read_namespace(Controller& controller, uint32_t id, Namespace& disk) {
    if (identify(controller, id, 0, bounce_page))
        return false;
    const auto* data = static_cast<const uint8_t*>(controller.bytes(bounce_page));
    if (!namespace_info(data, disk.info))
        return false;
    disk.controller = &controller;
    disk.id = id;
    memcpy(disk.identifiers, data + 104, sizeof(disk.identifiers));
    return controller.version < 0x00010300 ||
           (!identify(controller, id, 3, bounce_page) && namespace_descriptors(data, disk.uuid));
}

void add_namespace(Controller& controller, uint32_t id) {
    Namespace probe{};
    if (read_namespace(controller, id, probe)) {
        disks[disk_count++] = probe;
        log("nvme: controller=%u nsid=%u sectors=%u readonly=%u\n", uint64_t(controller.number),
            uint64_t(id), probe.info.sectors, uint64_t(probe.info.readonly));
    }
}

bool discover_namespaces(Controller& controller) {
    if (controller.version < 0x00010100) {
        for (uint32_t id = 1;
             id <= min(controller.namespaces, 1024u) && disk_count < nvme_device_slots; ++id) {
            add_namespace(controller, id);
            if (!controller.live)
                return false;
        }
        return true;
    }
    uint32_t cursor = 0;
    // Bound scans of controllers with large numbers of unsupported namespaces.
    for (unsigned batch = 0; batch < 16 && disk_count < nvme_device_slots; ++batch) {
        if (identify(controller, cursor, 2, list_page))
            return false;
        const auto* ids = static_cast<const uint32_t*>(controller.bytes(list_page));
        for (unsigned i = 0; i < page_size / sizeof(*ids) && disk_count < nvme_device_slots; ++i) {
            const uint32_t id = ids[i];
            if (!id)
                return true;
            if (id <= cursor || id == UINT32_MAX)
                return false;
            cursor = id;
            add_namespace(controller, id);
            if (!controller.live)
                return false;
        }
    }
    return true;
}

void recover(Controller& controller) {
    // The command may already have reached the device. Recovery never replays it.
    bool success = initialize(controller) && read_controller(controller, true);
    for (unsigned i = 0; success && i < disk_count; ++i) {
        const auto& disk = disks[i];
        if (disk.controller != &controller)
            continue;
        Namespace current{};
        success = read_namespace(controller, disk.id, current) &&
                  current.info.sectors == disk.info.sectors &&
                  current.info.readonly == disk.info.readonly &&
                  !memcmp(current.identifiers, disk.identifiers, sizeof(disk.identifiers)) &&
                  !memcmp(current.uuid, disk.uuid, sizeof(disk.uuid));
    }
    controller.live = success;
    if (!success)
        disable(controller); // Keep the allocation pinned even if reset never acknowledges.
    log("nvme: controller=%u queue recovery=%s\n", uint64_t(controller.number),
        success ? "ready" : "offline");
}

bool mask_messages(const PciFunction& pci) {
    if (const auto msi = pci.find_capability(5)) {
        pci.write16(msi + 2, pci.read16(msi + 2) & ~1u);
        if (pci.read16(msi + 2) & 1)
            return false;
    }
    if (const auto msix = pci.find_capability(0x11)) {
        pci.write16(msix + 2, (pci.read16(msix + 2) & ~0x8000u) | 0x4000);
        if (pci.read16(msix + 2) & 0x8000)
            return false;
    }
    return true;
}

void attach(const PciFunction& pci) {
    if (controller_count == nvme_controller_slots || disk_count == nvme_device_slots ||
        pci.read16(0x0a) != 0x0108 || pci.read8(9) != 2)
        return;
    PciBar bar;
    uint64_t address;
    if (pci.probe_bar(0, PciBarSpace::memory, bar) != PciBarStatus::valid ||
        !bar.range(0, page_size, address))
        return;
    auto* registers = static_cast<volatile uint32_t*>(map_mmio(address, page_size));
    if (!registers)
        return;
    constexpr uint16_t memory = 2, master = 4, no_intx = 0x400;
    const uint16_t original = pci.read16(4);
    const uint16_t command = (original & ~7u) | memory | master | no_intx;
    pci.write16(4, command);
    if ((pci.read16(4) & 0x407) != (memory | master | no_intx) || !mask_messages(pci)) {
        pci.write16(4, original);
        return;
    }

    const auto cap0 = registers[cap_low], cap1 = registers[cap_high];
    const unsigned version = registers[version_reg], stride = 1u << (cap1 & 15);
    const size_t span = doorbells + (3 * stride + 1) * sizeof(uint32_t);
    const unsigned depth = min((cap0 & 0xffffu) + 1, max_depth);
    if (!version || version == UINT32_MAX || !(cap1 & (1u << 5)) || (cap1 & (15u << 16)) ||
        depth < 2 || !bar.range(0, span, address) || !map_mmio(address, span)) {
        pci.write16(4, original);
        return;
    }
    const auto dma = Dma::allocate(dma_pages, Dma::pci);
    if (!dma) {
        pci.write16(4, original);
        return;
    }

    auto& controller = controllers[controller_count];
    controller = {};
    controller.registers = registers;
    controller.dma = dma;
    controller.stride = stride;
    controller.depth = depth;
    controller.ready_timeout = max(1u, cap0 >> 24) * 50;
    controller.number = controller_count++;
    controller.version = version;
    const unsigned previous_count = disk_count;
    if (!initialize(controller) || !read_controller(controller, false) ||
        !discover_namespaces(controller)) {
        controller.live = false;
        disk_count = previous_count;
        if (disable(controller)) {
            page_free(dma, dma_pages);
            controller.dma = 0;
            pci.write16(4, original & ~master);
        }
        log("nvme: controller=%u initialization failed\n", uint64_t(controller.number));
        return;
    }
    log("nvme: controller=%u reset complete depth=%u transfer_sectors=%u\n",
        uint64_t(controller.number), uint64_t(controller.depth), uint64_t(controller.limit));
}

int run_io(Controller& controller, Command command) {
    if (!controller.live)
        return -5;
    const int result = submit(controller, 1, command);
    if (result && !controller.live)
        recover(controller);
    return result;
}

template <size_t N> void identity_field(char (&output)[N], const uint8_t* source) {
    size_t length = N - 1;
    while (length &&
           (!source[length - 1] || source[length - 1] == ' ' || source[length - 1] == 0xff))
        --length;
    for (size_t i = 0; i < length; ++i)
        output[i] = source[i] >= ' ' && source[i] <= '~' ? char(source[i]) : '?';
    output[length] = 0;
}
} // namespace

void nvme_init() {
    pci_scan(attach);
}

const BlockInfo* nvme_info(unsigned slot) {
    return slot < disk_count ? &disks[slot].info : nullptr;
}

NvmeAddress nvme_address(unsigned slot) {
    const auto& disk = disks[slot];
    return {disk.controller->number, disk.id};
}

bool nvme_identity(unsigned number, NvmeIdentity& identity) {
    if (number >= controller_count || !controllers[number].live)
        return false;
    const auto& controller = controllers[number];
    identity_field(identity.serial, controller.identity);
    identity_field(identity.model, controller.identity + sizeof(identity.serial) - 1);
    identity_field(identity.firmware, controller.firmware);
    return true;
}

int nvme_transfer(unsigned slot, uint64_t sector, void* data, size_t count, bool write) {
    if (!nvme_info(slot))
        return -19;
    const auto& disk = disks[slot];
    if (sector > disk.info.sectors || count > disk.info.sectors - sector)
        return -22;
    if (write && disk.info.readonly)
        return -30;
    auto& controller = *disk.controller;
    auto* bytes = static_cast<uint8_t*>(data);
    while (count) {
        if (!controller.live)
            return -5;
        const size_t sectors = min(count, size_t(controller.limit));
        const size_t length = sectors * sector_size;
        auto* bounce = controller.bytes(bounce_page);
        if (write)
            memcpy(bounce, bytes, length);
        Command command{};
        command.opcode = write ? 1 : 2;
        command.nsid = disk.id;
        command.cdw10 = uint32_t(sector);
        command.cdw11 = sector >> 32;
        command.cdw12 = sectors - 1;
        if (!data_pages(command, controller.page(bounce_page), controller.page(prp_page),
                        static_cast<uint64_t*>(controller.bytes(prp_page)), length))
            return -22;
        if (int result = run_io(controller, command))
            return result;
        if (!write)
            memcpy(bytes, bounce, length);
        bytes += length;
        sector += sectors;
        count -= sectors;
    }
    return 0;
}

int nvme_flush(unsigned slot) {
    if (!nvme_info(slot))
        return -19;
    Command command{}; // NVM Flush.
    command.nsid = disks[slot].id;
    return run_io(*disks[slot].controller, command);
}

int nvme_shutdown() {
    int result = 0;
    for (unsigned i = 0; i < controller_count; ++i) {
        auto& controller = controllers[i];
        if (!controller.live)
            continue;
        controller.live = false;
        controller.write(configuration, controller.read(configuration) | request_shutdown);
        if (wait([&] { return (controller.read(status_reg) & shutdown_mask) == shutdown_complete; },
                 max(controller.ready_timeout, 500u))) {
            log("nvme: controller=%u shutdown complete\n", uint64_t(controller.number));
        } else {
            log("nvme: controller=%u shutdown timed out\n", uint64_t(controller.number));
            result = -110;
        }
    }
    return result;
}
} // namespace ax
