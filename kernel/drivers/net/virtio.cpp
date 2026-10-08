// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ethernet.hpp"
#include "drivers/virtio/pci.hpp"

namespace ax {
namespace {
constexpr unsigned slots = 64;
constexpr uint64_t feature_mtu = 1ull << 3, feature_mac = 1ull << 5, feature_status = 1ull << 16;

struct Header {
    uint8_t flags, segmentation;
    uint16_t header_length, segment_size, checksum_start, checksum_offset, buffers;
};

static_assert(sizeof(Header) == 12);

struct Buffer {
    uint64_t physical = 0;
    size_t length = 0;
    bool pending = false;
};

struct Controller {
    VirtioPci pci;
    SplitQueue rx, tx;
    NetAdapter adapter{};
    Buffer receive[slots], transmit[slots];
    unsigned rx_count = 0, tx_count = 0;
    size_t header = 0, capacity = 0, pages = 0;
};

static Controller controllers[max_net_devices];
static unsigned attempts;

static void stop(NetAdapter& adapter) {
    auto& device = *static_cast<Controller*>(adapter.data);
    adapter.info.live = adapter.info.writable = adapter.info.carrier = false;
    device.pci.stop();
    // No hot removal yet. Keep payloads and ownership records quarantined.
}

static int failed(Controller& device) {
    for (unsigned i = 0; i < device.tx_count; i++)
        if (device.transmit[i].pending) {
            net_tx_complete(device.adapter, device.transmit[i].length, true);
            device.transmit[i].pending = false;
        }
    stop(device.adapter);
    return -5;
}

static bool supply(Controller& device, unsigned index) {
    auto& buffer = device.receive[index];
    memset(physical(buffer.physical), 0, device.header);
    VirtioBuffer area{buffer.physical, uint32_t(device.capacity), true};
    if (device.rx.submit(&area, 1, index) < 0)
        return false;
    buffer.pending = true;
    return true;
}

static void poll(NetAdapter& adapter) {
    auto& device = *static_cast<Controller*>(adapter.data);
    if (!adapter.info.live)
        return;
    if (!device.pci.healthy()) {
        failed(device);
        return;
    }
    uint16_t status = 1;
    if ((device.pci.features() & feature_status) &&
        !device.pci.read_config(6, &status, sizeof(status))) {
        failed(device);
        return;
    }
    adapter.info.carrier = status & 1;
    VirtioCompletion completed{};
    for (unsigned budget = 0; budget < device.tx_count; budget++) {
        int result = device.tx.complete(completed);
        if (!result)
            break;
        if (result < 0 || completed.cookie >= device.tx_count ||
            !device.transmit[completed.cookie].pending ||
            (device.pci.modern() && completed.length)) {
            failed(device);
            return;
        }
        auto& buffer = device.transmit[completed.cookie];
        net_tx_complete(adapter, buffer.length);
        buffer.pending = false;
    }
    bool recycled = false;
    for (unsigned budget = 0; budget < device.rx_count; budget++) {
        int result = device.rx.complete(completed);
        if (!result)
            break;
        if (result < 0 || completed.cookie >= device.rx_count ||
            !device.receive[completed.cookie].pending) {
            net_rx_error(adapter);
            failed(device);
            return;
        }
        unsigned index = completed.cookie;
        auto& buffer = device.receive[index];
        buffer.pending = false;
        const auto header = static_cast<const Header*>(physical(buffer.physical));
        if (completed.length < device.header + ethernet_header ||
            completed.length > device.capacity || header->flags || header->segmentation ||
            // QEMU leaves num_buffers zero without mergeable RX buffers.
            // Accept either single-buffer encoding, never a chained payload.
            (device.pci.modern() && header->buffers > 1))
            net_rx_error(adapter);
        else
            net_receive(adapter,
                        static_cast<const uint8_t*>(physical(buffer.physical)) + device.header,
                        completed.length - device.header);
        if (!supply(device, index)) {
            failed(device);
            return;
        }
        recycled = true;
    }
    if (recycled && !device.pci.notify(device.rx)) {
        failed(device);
        return;
    }
    adapter.info.writable = false;
    for (unsigned i = 0; i < device.tx_count; i++)
        adapter.info.writable |= !device.transmit[i].pending;
}

static int send(NetAdapter& adapter, const void* frame, size_t length) {
    auto& device = *static_cast<Controller*>(adapter.data);
    if (!adapter.info.live)
        return -5;
    for (unsigned i = 0; i < device.tx_count; i++) {
        auto& buffer = device.transmit[i];
        if (buffer.pending)
            continue;
        auto bytes = static_cast<uint8_t*>(physical(buffer.physical));
        memset(bytes, 0, device.header);
        memcpy(bytes + device.header, frame, length);
        VirtioBuffer area{buffer.physical, uint32_t(device.header + length), false};
        int result = device.tx.submit(&area, 1, i);
        if (result < 0)
            return result == -11 ? -11 : failed(device);
        buffer.pending = true;
        buffer.length = length;
        if (!device.pci.notify(device.tx))
            return failed(device);
        adapter.info.writable = false;
        for (unsigned n = 0; n < device.tx_count; n++)
            adapter.info.writable |= !device.transmit[n].pending;
        return 0;
    }
    return -11;
}

static bool initialize(Controller& device, const PciFunction& pci) {
    device.adapter = {{}, poll, send, stop, &device};
    if (!device.pci.open(pci, feature_mtu | feature_mac | feature_status, 6))
        return false;
    if (!(device.pci.features() & feature_mac) ||
        !device.pci.read_config(0, device.adapter.info.mac, 6))
        return false;
    uint16_t mtu = 1500;
    if ((device.pci.features() & feature_mtu) && (!device.pci.read_config(10, &mtu, 2) || mtu < 68))
        return false;
    device.adapter.info.maximum_mtu = mtu;
    device.header = device.pci.modern() ? sizeof(Header) : sizeof(Header) - 2;
    device.capacity = device.header + mtu + 18;
    device.pages = align_up(device.capacity) / page_size;
    if (!device.pci.setup_queue(device.rx, 0, 1024, 2) ||
        !device.pci.setup_queue(device.tx, 1, 1024, 2))
        return false;
    device.rx_count = min(unsigned(device.rx.layout().size), slots);
    device.tx_count = min(unsigned(device.tx.layout().size), slots);
    for (unsigned i = 0; i < device.rx_count; i++) {
        device.receive[i].physical = page_alloc(device.pages);
        if (!device.receive[i].physical || !supply(device, i))
            return false;
    }
    for (unsigned i = 0; i < device.tx_count; i++) {
        device.transmit[i].physical = page_alloc(device.pages);
        if (!device.transmit[i].physical)
            return false;
    }
    if (!device.pci.start())
        return false;
    device.adapter.info.live = true;
    poll(device.adapter);
    if (!device.adapter.info.live || !net_register(device.adapter))
        return false;
    log("virtio-net: index=%u transport=%s rx=%u tx=%u features=%x\n",
        uint64_t(device.adapter.info.index), device.pci.modern() ? "modern" : "legacy",
        uint64_t(device.rx.layout().size), uint64_t(device.tx.layout().size),
        device.pci.features());
    return true;
}
} // namespace

void virtio_net_attach(const PciFunction& pci) {
    uint16_t id = pci.read16(2);
    if (attempts == max_net_devices || pci.read16(0) != 0x1af4 || (id != 0x1000 && id != 0x1041))
        return;
    auto& device = controllers[attempts++];
    if (initialize(device, pci))
        return;
    if (device.pci.stop()) {
        device.rx.release();
        device.tx.release();
        for (auto& buffer : device.receive)
            if (buffer.physical)
                page_free(buffer.physical, device.pages);
        for (auto& buffer : device.transmit)
            if (buffer.physical)
                page_free(buffer.physical, device.pages);
    }
    log("virtio-net: initialization failed at %u:%u.%u\n", uint64_t(pci.bus), uint64_t(pci.slot),
        uint64_t(pci.function));
}
} // namespace ax
