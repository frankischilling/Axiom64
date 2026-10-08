// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ethernet.hpp"
#include "net/packet.hpp"
#include "drivers/platform/pci.hpp"

namespace ax {
void virtio_net_attach(const PciFunction&);

void e1000_attach(const PciFunction&);

static NetAdapter* devices[max_net_devices];
static unsigned count;

static void discover(const PciFunction& pci) {
    virtio_net_attach(pci);
    e1000_attach(pci);
}

void net_init() {
    pci_scan(discover);
}

unsigned net_register(NetAdapter& adapter) {
    bool nonzero = false;
    for (auto byte : adapter.info.mac)
        nonzero |= byte != 0;
    if (count == max_net_devices || !nonzero || (adapter.info.mac[0] & 1) || !adapter.poll ||
        !adapter.send || !adapter.stop || !adapter.info.live || adapter.info.maximum_mtu < 68 ||
        adapter.info.maximum_mtu > 65535)
        return 0;
    auto& info = adapter.info;
    info.index = count + 1;
    memcpy(info.name, "eth0", 5);
    info.name[3] += count;
    info.mtu = min(info.maximum_mtu, uint32_t(1500));
    devices[count++] = &adapter;
    log("NET_DEVICE index=%u name=%s mtu=%u carrier=%u mac=%x:%x:%x:%x:%x:%x\n",
        uint64_t(info.index), info.name, uint64_t(info.mtu), uint64_t(info.carrier),
        uint64_t(info.mac[0]), uint64_t(info.mac[1]), uint64_t(info.mac[2]), uint64_t(info.mac[3]),
        uint64_t(info.mac[4]), uint64_t(info.mac[5]));
    return info.index;
}

const NetInfo* net_info(unsigned index) {
    return index && index <= count ? &devices[index - 1]->info : nullptr;
}

void net_poll() {
    for (unsigned i = 0; i < count; i++)
        if (devices[i]->info.live)
            devices[i]->poll(*devices[i]);
}

void net_shutdown() {
    for (unsigned i = 0; i < count; i++) {
        devices[i]->stop(*devices[i]);
        devices[i]->info.live = devices[i]->info.carrier = false;
    }
}

int net_configure(unsigned index, bool administrative, uint32_t mtu) {
    auto info = net_info(index);
    if (!info)
        return -19;
    if (mtu < 68 || mtu > info->maximum_mtu)
        return -22;
    auto& writable = devices[index - 1]->info;
    writable.administrative = administrative;
    writable.mtu = mtu;
    return 0;
}

bool net_writable(unsigned index) {
    auto info = net_info(index);
    // Errors are ready, so an already blocked operation can report them.
    return !info || !info->live || !info->administrative || !info->carrier || info->writable;
}

int net_send(unsigned index, const void* frame, size_t length, const void* sender) {
    auto info = net_info(index);
    if (!info)
        return -19;
    auto& adapter = *devices[index - 1];
    adapter.poll(adapter);
    if (!info->live)
        return -5;
    if (!info->administrative || !info->carrier)
        return -100;
    if (length < ethernet_header)
        return -22;
    const auto bytes = static_cast<const uint8_t*>(frame);
    size_t header = bytes[12] == 0x81 && bytes[13] == 0 ? 18 : ethernet_header;
    if (length < header)
        return -22;
    if (length > info->mtu + header)
        return -90;
    int result = adapter.send(adapter, frame, length);
    if (!result)
        packet_deliver(adapter.info, frame, length, 4, sender);
    else if (result != -11)
        adapter.info.stats.tx_errors++;
    return result;
}

void net_receive(NetAdapter& adapter, const void* frame, size_t length) {
    auto& info = adapter.info;
    if (length < ethernet_header || length > info.maximum_mtu + 18) {
        net_rx_error(adapter);
        return;
    }
    info.stats.rx_packets++;
    info.stats.rx_bytes += length;
    if (!info.administrative) {
        info.stats.rx_dropped++;
        return;
    }
    const auto bytes = static_cast<const uint8_t*>(frame);
    bool broadcast = true;
    for (unsigned i = 0; i < 6; i++)
        broadcast &= bytes[i] == 0xff;
    unsigned type = broadcast ? 1 : (bytes[0] & 1) ? 2 : !memcmp(bytes, info.mac, 6) ? 0 : 3;
    packet_deliver(info, frame, length, type, nullptr);
}

void net_tx_complete(NetAdapter& adapter, size_t length, bool error) {
    if (error) {
        adapter.info.stats.tx_errors++;
        adapter.info.stats.tx_dropped++;
    } else {
        adapter.info.stats.tx_packets++;
        adapter.info.stats.tx_bytes += length;
    }
}

void net_rx_error(NetAdapter& adapter) {
    adapter.info.stats.rx_errors++;
    adapter.info.stats.rx_dropped++;
}
} // namespace ax
