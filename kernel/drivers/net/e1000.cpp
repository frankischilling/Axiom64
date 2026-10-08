// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ethernet.hpp"
#include "drivers/platform/pci.hpp"
#include "drivers/virtio/queue.hpp"

namespace ax {
namespace {
constexpr unsigned ring_size = 64, buffer_size = 2048;
constexpr unsigned ctrl = 0, status = 8, icr = 0xc0, imc = 0xd8, rctl = 0x100;
constexpr unsigned tctl = 0x400, tipg = 0x410, rx_base = 0x2800, tx_base = 0x3800;
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
    volatile uint32_t* registers = nullptr;
    uint64_t rings = 0, receive = 0, transmit = 0;
    volatile RxDescriptor* rx = nullptr;
    volatile TxDescriptor* tx = nullptr;
    unsigned rx_next = 0, tx_next = 0, tx_oldest = 0, pending = 0;
    bool fragment = false;

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
    device.pci.write16(4, (device.pci.read16(4) | 0x400) & ~uint16_t(4));
    // DMA pages remain owned for the controller's entire lifetime, even on failure.
}

static void poll(NetAdapter& adapter) {
    auto& device = *static_cast<Controller*>(adapter.data);
    if (!adapter.info.live)
        return;
    uint32_t state = device.read(status);
    if (state == UINT32_MAX || device.pci.read32(0) != 0x100e8086) {
        while (device.pending) {
            net_tx_complete(adapter, device.tx[device.tx_oldest].length, true);
            device.tx_oldest = (device.tx_oldest + 1) % ring_size;
            device.pending--;
        }
        stop(adapter);
        return;
    }
    adapter.info.carrier = state & 2;
    device.read(icr); // All NIC interrupts remain masked; discard stale causes.
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

static bool initialize(Controller& device, const PciFunction& pci) {
    device.pci = pci;
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
    virtio_dma_barrier();
    device.write(tctl, 2 | 8 | (15 << 4) | (64 << 12));
    device.write(rctl, 2 | (1u << 4) | (1u << 15) | (1u << 26));
    device.adapter.info.live = true;
    poll(device.adapter);
    if (!device.adapter.info.live || !net_register(device.adapter))
        return false;
    log("e1000: index=%u model=82540EM rx=%u tx=%u\n", uint64_t(device.adapter.info.index),
        uint64_t(ring_size), uint64_t(ring_size));
    return true;
}
} // namespace

void e1000_attach(const PciFunction& pci) {
    if (attempts == max_net_devices || pci.read32(0) != 0x100e8086)
        return;
    auto& device = controllers[attempts++];
    if (initialize(device, pci))
        return;
    stop(device.adapter);
    log("e1000: initialization failed at %u:%u.%u\n", uint64_t(pci.bus), uint64_t(pci.slot),
        uint64_t(pci.function));
}
} // namespace ax
